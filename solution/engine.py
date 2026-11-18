"""Recovery decisions: validation, pair selection and the atomic commit.

Rules (all re-checked while holding the SQLite write lock; a preview is only
advisory):

* the attempt belongs to the account, is open, and request time ``at`` lies in
  ``[created_at, expires_at]`` inclusive;
* the attempt was opened at the account's *current* generation, and no
  recovery has already advanced that generation;
* both proofs are unconsumed, properly signed, inside their own
  ``[not_before, not_after]`` window, and bound to the same attempt, account,
  account generation and pending-profile digest;
* both proofs use channels that are live at the request time at their current
  generation; the pair covers two different channel types with at least one
  human/admin channel, two different channels and two different verifiers;
* among all valid pairs the lexicographically smallest one, ordered by
  ``(proof id, proof id)``, is chosen, so storage or enumeration order can never
  change the outcome.

The commit is one transaction: consume both proofs, advance the account
generation, close every open attempt of the consumed generation, insert the
recovery row and persist the request receipt.  Either all of it is durable or
none of it is.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field

from . import db
from .errors import (
    BUSINESS_ERRORS,
    E_ACCOUNT_FROZEN,
    E_ACCOUNT_GEN_STALE,
    E_ATTEMPT_ACCOUNT,
    E_ATTEMPT_CLOSED,
    E_ATTEMPT_EXPIRED,
    E_ATTEMPT_NOT_YET_ACTIVE,
    E_ATTEMPT_SUPERSEDED,
    E_BAD_REQUEST,
    E_BAD_SIGNATURE,
    E_BINDING,
    E_BUSY,
    E_CHANNEL_GEN_STALE,
    E_CHANNEL_GEN_UNKNOWN,
    E_CHANNEL_REVOKED,
    E_CHANNEL_TIME,
    E_NO_STRONG_CHANNEL,
    E_NO_VALID_PAIR,
    E_PROOF_CONSUMED,
    E_PROOF_EXPIRED,
    E_PROOF_NOT_YET_VALID,
    E_REQUEST_CONFLICT,
    E_SAME_CHANNEL,
    E_SAME_CHANNEL_TYPE,
    E_INTERNAL,
    E_SAME_SIGNER,
    E_TIMEOUT,
    E_UNKNOWN_CHANNEL,
    E_UNKNOWN_ID,
    E_UNKNOWN_OP,
    RecoveryError,
)
from .model import (
    STRONG_CHANNEL_TYPES,
    attempt_digest,
    event_signature_ok,
    is_int,
    proof_signature_ok,
    recovery_digest,
    request_hash,
)

#: Attempts closed by a committed recovery carry this prefix in ``closed_by``,
#: which distinguishes them from administratively closed attempts.
RECOVERY_CLOSED_PREFIX = "recovery:"

MUTATING_OPS = ("request_recovery", "rotate_channel", "revoke_channel")
READ_ONLY_OPS = ("preview", "get_account", "get_attempt", "get_recovery", "get_state")
ALL_OPS = MUTATING_OPS + READ_ONLY_OPS

#: field name -> expected kind, per operation (structural validation only).
REQUIRED = {
    "request_recovery": (("account_id", str), ("attempt_id", str)),
    "preview": (("account_id", str), ("attempt_id", str)),
    "rotate_channel": (("channel_id", str), ("channel_gen", int), ("signature", str)),
    "revoke_channel": (("channel_id", str), ("channel_gen", int), ("signature", str)),
    "get_account": (("account_id", str),),
    "get_attempt": (("attempt_id", str),),
    "get_recovery": (("account_id", str),),
    "get_state": (),
}


class NullSync:
    """Production sink: no synchronisation points."""

    def hit(self, point: str) -> None:
        return None


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@dataclass
class Diagnosis:
    proof: db.ProofView
    code: str | None = None
    message: str | None = None

    def as_dict(self) -> dict:
        return {"proof_id": self.proof.id, "code": self.code, "message": self.message}


@dataclass
class Evaluation:
    account: db.AccountView | None = None
    attempt: db.AttemptView | None = None
    blocker: RecoveryError | None = None
    diagnoses: list[Diagnosis] = field(default_factory=list)
    pair: tuple[db.ProofView, db.ProofView] | None = None


def _proof_diagnosis(state: db.State, proof: db.ProofView, attempt: db.AttemptView, at: int, key: bytes) -> Diagnosis:
    diagnosis = Diagnosis(proof=proof)
    if proof.status != "available":
        diagnosis.code = E_PROOF_CONSUMED
        diagnosis.message = f"proof {proof.id} is {proof.status}"
        return diagnosis
    if not proof_signature_ok(key, proof.as_signature_input()):
        diagnosis.code = E_BAD_SIGNATURE
        diagnosis.message = f"proof {proof.id} signature does not verify"
        return diagnosis
    if proof.attempt_id != attempt.id:
        diagnosis.code = E_BINDING
        diagnosis.message = f"proof {proof.id} is bound to attempt {proof.attempt_id}"
        return diagnosis
    if proof.account_id != attempt.account_id:
        diagnosis.code = E_BINDING
        diagnosis.message = f"proof {proof.id} is bound to account {proof.account_id}"
        return diagnosis
    if proof.account_gen != attempt.account_gen:
        diagnosis.code = E_BINDING
        diagnosis.message = f"proof {proof.id} carries account_gen {proof.account_gen}"
        return diagnosis
    if proof.profile_digest != attempt.profile_digest:
        diagnosis.code = E_BINDING
        diagnosis.message = f"proof {proof.id} carries a different pending-profile digest"
        return diagnosis
    channel = state.channels.get(proof.channel_id)
    if channel is None:
        diagnosis.code = E_UNKNOWN_CHANNEL
        diagnosis.message = f"channel {proof.channel_id} is unknown"
        return diagnosis
    if at < proof.not_before:
        diagnosis.code = E_PROOF_NOT_YET_VALID
        diagnosis.message = f"proof {proof.id} is valid from {proof.not_before}"
        return diagnosis
    if at > proof.not_after:
        diagnosis.code = E_PROOF_EXPIRED
        diagnosis.message = f"proof {proof.id} expired at {proof.not_after}"
        return diagnosis
    generation, revoked_at = state.channel_state(proof.channel_id)
    if proof.channel_gen > generation:
        diagnosis.code = E_CHANNEL_GEN_UNKNOWN
        diagnosis.message = f"channel {proof.channel_id} is at generation {generation}, proof claims {proof.channel_gen}"
        return diagnosis
    if revoked_at is not None:
        diagnosis.code = E_CHANNEL_REVOKED
        diagnosis.message = f"channel {proof.channel_id} was revoked at {revoked_at}"
        return diagnosis
    if proof.channel_gen < generation:
        diagnosis.code = E_CHANNEL_GEN_STALE
        diagnosis.message = f"channel {proof.channel_id} moved to generation {generation}, proof at {proof.channel_gen}"
        return diagnosis
    return diagnosis


#: Fixed priority for the *reported* reason.  Every rule is evaluated, so
#: the full violation set is observable even where rules happen to overlap
#: (two proofs from one channel necessarily share a channel type; two device
#: proofs necessarily lack a human/admin proof).
PAIR_RULE_ORDER = (
    E_SAME_CHANNEL,
    E_SAME_CHANNEL_TYPE,
    E_SAME_SIGNER,
    E_NO_STRONG_CHANNEL,
)


def pair_violations(first: db.ProofView, second: db.ProofView) -> list[str]:
    """Every two-channel rule the pair breaks, in priority order."""
    violations: list[str] = []
    if first.channel_id == second.channel_id:
        violations.append(E_SAME_CHANNEL)
    if first.channel_type == second.channel_type:
        violations.append(E_SAME_CHANNEL_TYPE)
    if first.issuer == second.issuer:
        violations.append(E_SAME_SIGNER)
    if first.channel_type not in STRONG_CHANNEL_TYPES and second.channel_type not in STRONG_CHANNEL_TYPES:
        violations.append(E_NO_STRONG_CHANNEL)
    return violations


def pair_rule(first: db.ProofView, second: db.ProofView) -> str | None:
    """The single reported reason a pair is refused, or None when it is legal."""
    violations = pair_violations(first, second)
    return violations[0] if violations else None


def select_pair(diagnoses: list[Diagnosis]) -> tuple[db.ProofView, db.ProofView] | None:
    usable = sorted((item.proof for item in diagnoses if item.code is None), key=lambda proof: proof.id)
    for index, first in enumerate(usable):
        for second in usable[index + 1 :]:
            if pair_rule(first, second) is None:
                return first, second
    return None


def evaluate(state: db.State, *, account_id: str, attempt_id: str, at: int, key: bytes) -> Evaluation:
    result = Evaluation()
    account = state.accounts.get(account_id)
    if account is None:
        result.blocker = RecoveryError(E_UNKNOWN_ID, f"account {account_id!r} does not exist")
        return result
    result.account = account
    attempt = state.attempts.get(attempt_id)
    if attempt is None:
        result.blocker = RecoveryError(E_UNKNOWN_ID, f"attempt {attempt_id!r} does not exist")
        return result
    result.attempt = attempt
    if attempt.account_id != account_id:
        result.blocker = RecoveryError(
            E_ATTEMPT_ACCOUNT, f"attempt {attempt_id!r} belongs to account {attempt.account_id!r}"
        )
        return result
    if account.status != "active":
        result.blocker = RecoveryError(E_ACCOUNT_FROZEN, f"account {account_id!r} is {account.status}")
        return result
    if attempt.status != "open":
        if (attempt.closed_by or "").startswith(RECOVERY_CLOSED_PREFIX):
            result.blocker = RecoveryError(
                E_ATTEMPT_SUPERSEDED, f"attempt {attempt_id!r} was closed by a committed recovery"
            )
        else:
            result.blocker = RecoveryError(E_ATTEMPT_CLOSED, f"attempt {attempt_id!r} is closed")
        return result
    if any(
        row.account_id == attempt.account_id and row.account_gen == attempt.account_gen + 1
        for row in state.recoveries.values()
    ):
        result.blocker = RecoveryError(
            E_ATTEMPT_SUPERSEDED, f"a recovery already consumed generation {attempt.account_gen} of this account"
        )
        return result
    if attempt.account_gen != account.account_gen:
        result.blocker = RecoveryError(
            E_ACCOUNT_GEN_STALE,
            f"attempt {attempt_id!r} was opened at generation {attempt.account_gen}, "
            f"account is at {account.account_gen}",
        )
        return result
    if at < attempt.created_at:
        result.blocker = RecoveryError(
            E_ATTEMPT_NOT_YET_ACTIVE, f"attempt {attempt_id!r} starts at {attempt.created_at}"
        )
        return result
    if at > attempt.expires_at:
        result.blocker = RecoveryError(E_ATTEMPT_EXPIRED, f"attempt {attempt_id!r} expired at {attempt.expires_at}")
        return result

    for proof in sorted(
        (proof for proof in state.proofs.values() if proof.attempt_id == attempt_id),
        key=lambda proof: proof.id,
    ):
        result.diagnoses.append(_proof_diagnosis(state, proof, attempt, at, key))
    result.pair = select_pair(result.diagnoses)
    return result


def no_pair_error(evaluation: Evaluation) -> RecoveryError:
    usable = [item.proof.id for item in evaluation.diagnoses if item.code is None]
    error = RecoveryError(
        E_NO_VALID_PAIR,
        f"no valid proof pair for attempt {evaluation.attempt.id if evaluation.attempt else '?'}: "
        f"{len(usable)} usable of {len(evaluation.diagnoses)} proofs",
    )
    details: dict = {"reasons": [item.as_dict() for item in evaluation.diagnoses]}
    if usable:
        proofs = sorted((item.proof for item in evaluation.diagnoses if item.code is None), key=lambda p: p.id)
        seen: set[str] = set()
        for index, first in enumerate(proofs):
            for second in proofs[index + 1 :]:
                seen.update(pair_violations(first, second))
        details["usable_proofs"] = usable
        details["pair_codes"] = [code for code in PAIR_RULE_ORDER if code in seen]
        details["pairing"] = "no combination of the usable proofs satisfies the two-channel rules"
    error.details = details  # type: ignore[attr-defined]
    return error


# ---------------------------------------------------------------------------
# Request parsing
# ---------------------------------------------------------------------------


def request_error(message: str) -> RecoveryError:
    return RecoveryError(E_BAD_REQUEST, message)


def parse_request(operation: dict) -> dict:
    """Structural validation only; semantics are checked against the state."""
    if not isinstance(operation, dict):
        raise request_error("operation must be an object")
    kind = operation.get("op")
    if kind not in ALL_OPS:
        raise RecoveryError(E_UNKNOWN_OP, f"unknown operation {kind!r}")
    remote_id = operation.get("remote_id")
    if not isinstance(remote_id, str) or not remote_id:
        raise request_error("field 'remote_id' must be a non-empty string")
    for name, wanted in REQUIRED[kind]:
        value = operation.get(name)
        if wanted is str:
            if not isinstance(value, str) or not value:
                raise request_error(f"field {name!r} must be a non-empty string")
        elif not is_int(value):
            raise request_error(f"field {name!r} must be an integer")
    at = operation.get("at")
    if at is not None and (not is_int(at) or at < 0):
        raise request_error("field 'at' must be a non-negative integer")
    if kind in ("rotate_channel", "revoke_channel"):
        if operation["channel_gen"] < 1:
            raise request_error("field 'channel_gen' must be a positive integer")
        if at is None:
            raise request_error("lifecycle operations must carry an explicit 'at'")
    return {
        "kind": kind,
        "at": at,
        "account_id": operation.get("account_id"),
        "attempt_id": operation.get("attempt_id"),
        "channel_id": operation.get("channel_id"),
        "channel_gen": operation.get("channel_gen"),
        "signature": operation.get("signature"),
        "remote_id": remote_id,
    }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class Engine:
    """Executes operations for exactly one tenant.

    Every operation is idempotent under ``remote_id``: the first execution's
    receipt is persisted in the same transaction as its effects, and a repeat
    with identical parameters returns that receipt with ``replayed: true``.
    A repeat with different parameters is refused with ``E501`` and leaves the
    stored receipt untouched.
    """

    def __init__(self, conn, *, tenant: str, key: bytes, now: int, sync=None):
        self.conn = conn
        self.tenant = tenant
        self.key = key
        self.now = now
        self.sync = sync or NullSync()

    # -- helpers -------------------------------------------------------------
    def read_state(self) -> db.State:
        return db.read_state(self.conn, self.tenant)

    def _at(self, request: dict) -> int:
        if request["at"] is not None:
            return request["at"]
        stored = db.read_now(self.conn, self.tenant)
        return self.now if stored is None else stored

    @staticmethod
    def _envelope(request: dict, tenant: str, receipt: dict, *, replayed: bool = False) -> dict:
        return {
            "remote_id": request["remote_id"],
            "op": request["kind"],
            "tenant": tenant,
            "status": receipt["status"],
            "code": receipt["code"],
            "replayed": replayed,
            "receipt": receipt,
        }

    def _replay_or_conflict(self, state: db.State, remote_id: str, req_hash: str) -> dict | None:
        stored = state.ops.get(remote_id)
        if stored is None:
            return None
        if stored.request_hash != req_hash:
            raise RecoveryError(
                E_REQUEST_CONFLICT,
                f"request id {remote_id!r} was already used with different parameters",
            )
        return stored.result_dict()

    # -- operation builders --------------------------------------------------
    def _preview_receipt(self, request: dict) -> dict:
        at = self._at(request)
        state = self.read_state()
        evaluation = evaluate(
            state, account_id=request["account_id"], attempt_id=request["attempt_id"], at=at, key=self.key
        )
        receipt: dict = {
            "status": "ok",
            "code": None,
            "message": None,
            "at": at,
            "account_id": request["account_id"],
            "attempt_id": request["attempt_id"],
            "account_gen": evaluation.account.account_gen if evaluation.account else None,
            "attempt_open": bool(evaluation.attempt and evaluation.attempt.status == "open"),
            "available_proofs": [],
            "candidate": None,
            "reasons": [item.as_dict() for item in evaluation.diagnoses],
        }
        if evaluation.blocker is not None:
            receipt["status"] = "unavailable"
            receipt["code"] = evaluation.blocker.code
            receipt["message"] = evaluation.blocker.message
            receipt["reasons"] = []
            return receipt
        receipt["available_proofs"] = [
            {
                "proof_id": item.proof.id,
                "channel_id": item.proof.channel_id,
                "channel_type": item.proof.channel_type,
                "channel_gen": item.proof.channel_gen,
                "issuer": item.proof.issuer,
            }
            for item in evaluation.diagnoses
            if item.code is None
        ]
        if evaluation.pair is not None:
            receipt["candidate"] = {
                "proofs": [evaluation.pair[0].id, evaluation.pair[1].id],
                "channels": [evaluation.pair[0].channel_id, evaluation.pair[1].channel_id],
                "types": [evaluation.pair[0].channel_type, evaluation.pair[1].channel_type],
                "issuers": [evaluation.pair[0].issuer, evaluation.pair[1].issuer],
            }
        else:
            receipt["status"] = "none"
            receipt["code"] = E_NO_VALID_PAIR
            error = no_pair_error(evaluation)
            details = getattr(error, "details", {})
            receipt["pair_codes"] = details.get("pair_codes", [])
            receipt["pairing"] = details.get("pairing")
        return receipt

    def _account_receipt(self, request: dict) -> dict:
        state = self.read_state()
        account = state.accounts.get(request["account_id"])
        if account is None:
            raise RecoveryError(E_UNKNOWN_ID, f"account {request['account_id']!r} does not exist")
        return {
            "status": "read",
            "code": None,
            "account": account.as_dict(),
            "attempts": [
                attempt.as_dict()
                for _, attempt in sorted(state.attempts.items())
                if attempt.account_id == account.id
            ],
            "recoveries": [
                row.as_dict() for _, row in sorted(state.recoveries.items()) if row.account_id == account.id
            ],
        }

    def _attempt_receipt(self, request: dict) -> dict:
        state = self.read_state()
        attempt = state.attempts.get(request["attempt_id"])
        if attempt is None:
            raise RecoveryError(E_UNKNOWN_ID, f"attempt {request['attempt_id']!r} does not exist")
        return {
            "status": "read",
            "code": None,
            "attempt": attempt.as_dict(),
            "proofs": [
                proof.as_dict() for _, proof in sorted(state.proofs.items()) if proof.attempt_id == attempt.id
            ],
        }

    def _recovery_receipt(self, request: dict) -> dict:
        state = self.read_state()
        return {
            "status": "read",
            "code": None,
            "account_id": request["account_id"],
            "recoveries": [
                row.as_dict()
                for _, row in sorted(state.recoveries.items())
                if row.account_id == request["account_id"]
            ],
        }

    def _state_receipt(self, request: dict) -> dict:
        return {"status": "read", "code": None, "state": self.read_state().snapshot()}

    # -- recovery ------------------------------------------------------------
    def _recovery_receipt_or_error(self, tx: db.WriteTx, state: db.State, request: dict, at: int) -> dict:
        remote_id = request["remote_id"]
        evaluation = evaluate(
            state, account_id=request["account_id"], attempt_id=request["attempt_id"], at=at, key=self.key
        )
        if evaluation.blocker is not None:
            return self._rejection(request, at, evaluation.blocker)
        attempt = evaluation.attempt
        assert attempt is not None
        if evaluation.pair is None:
            return self._rejection(request, at, no_pair_error(evaluation))
        first, second = evaluation.pair

        attempt_sha = attempt_digest(
            tenant=self.tenant,
            account_id=attempt.account_id,
            attempt_id=attempt.id,
            account_gen=attempt.account_gen,
            profile_digest_=attempt.profile_digest,
        )
        recovery_sha = recovery_digest(
            tenant=self.tenant,
            account_id=attempt.account_id,
            account_gen=attempt.account_gen + 1,
            attempt_id=attempt.id,
            attempt_digest_=attempt_sha,
            proof_a=first.id,
            proof_b=second.id,
            profile_digest_=attempt.profile_digest,
        )
        closed_by = RECOVERY_CLOSED_PREFIX + recovery_sha
        row = db.RecoveryView(
            account_gen=attempt.account_gen + 1,
            account_id=attempt.account_id,
            attempt_id=attempt.id,
            proof_a=first.id,
            proof_b=second.id,
            attempt_digest=attempt_sha,
            profile_digest=attempt.profile_digest,
            recovery_digest=recovery_sha,
            at=at,
            request_tenant=self.tenant,
            request_id=remote_id,
            request_at=at,
        )

        tx.touch()
        tx.consume_proof(first, attempt.id, at)
        tx.consume_proof(second, attempt.id, at)
        new_generation = tx.bump_account(attempt.account_id)
        if new_generation != attempt.account_gen + 1:
            raise RuntimeError("account generation changed inside the write lock")
        closed = tx.close_attempts_of_generation(attempt.account_id, attempt.account_gen, closed_by)
        tx.insert_recovery(row)
        self.sync.hit("recovery.after_consume")
        return {
            "status": "committed",
            "code": None,
            "message": None,
            "at": at,
            "account_id": attempt.account_id,
            "attempt_id": attempt.id,
            "recovery": row.as_dict(),
            "closed_attempts": closed,
            "reasons": [],
        }

    def _rejection(self, request: dict, at: int, error: RecoveryError) -> dict:
        details = getattr(error, "details", {}) or {}
        receipt = {
            "status": "rejected",
            "code": error.code,
            "message": error.message,
            "at": at,
            "account_id": request["account_id"],
            "attempt_id": request["attempt_id"],
            "recovery": None,
            "reasons": details.get("reasons", []),
        }
        for key in ("pairing", "usable_proofs", "pair_codes"):
            if key in details:
                receipt[key] = details[key]
        return receipt

    # -- channel lifecycle ---------------------------------------------------
    def _channel_receipt_or_error(self, tx: db.WriteTx, state: db.State, request: dict, at: int) -> dict:
        remote_id = request["remote_id"]
        kind = "rotate" if request["kind"] == "rotate_channel" else "revoke"
        channel_id = request["channel_id"]
        error = self._channel_problem(state, request, at, kind)
        if error is not None:
            return {
                "status": "rejected",
                "code": error.code,
                "message": error.message,
                "at": at,
                "channel_id": channel_id,
                "channel_gen": request["channel_gen"],
                "kind": kind,
                "reasons": [],
            }
        tx.touch()
        tx.insert_event(
            event_id=remote_id,
            channel_id=channel_id,
            kind=kind,
            channel_gen=request["channel_gen"],
            at=at,
            signature=request["signature"],
        )
        return {
            "status": "committed",
            "code": None,
            "message": None,
            "at": at,
            "channel_id": channel_id,
            "channel_gen": request["channel_gen"],
            "kind": kind,
            "reasons": [],
        }

    def _channel_problem(self, state: db.State, request: dict, at: int, kind: str) -> RecoveryError | None:
        channel_id = request["channel_id"]
        if channel_id not in state.channels:
            return RecoveryError(E_UNKNOWN_CHANNEL, f"channel {channel_id!r} is unknown in this tenant")
        payload = {
            "id": request["remote_id"],
            "channel_id": channel_id,
            "kind": kind,
            "channel_gen": request["channel_gen"],
            "at": at,
            "signature": request["signature"],
        }
        if not event_signature_ok(self.key, payload):
            return RecoveryError(E_BAD_SIGNATURE, f"lifecycle signature for {request['remote_id']!r} does not verify")
        generation, revoked_at = state.channel_state(channel_id)
        if revoked_at is not None:
            return RecoveryError(E_CHANNEL_REVOKED, f"channel {channel_id!r} was revoked at {revoked_at}")
        latest = max((event.at for event in state.events.values() if event.channel_id == channel_id), default=-1)
        if at < latest:
            return RecoveryError(
                E_CHANNEL_TIME,
                f"channel {channel_id!r} already has a lifecycle event at {latest}; {at} is in its past",
            )
        if kind == "rotate" and request["channel_gen"] != generation + 1:
            return RecoveryError(
                E_CHANNEL_GEN_UNKNOWN,
                f"channel {channel_id!r} is at generation {generation}, cannot rotate to {request['channel_gen']}",
            )
        if kind == "revoke" and request["channel_gen"] != generation:
            return RecoveryError(
                E_CHANNEL_GEN_UNKNOWN,
                f"channel {channel_id!r} is at generation {generation}, cannot revoke generation "
                f"{request['channel_gen']}",
            )
        return None

    # -- dispatch ------------------------------------------------------------
    def execute(self, operation: dict) -> dict:
        """Execute one operation, translating infrastructure failures.

        ``sqlite3.OperationalError`` for a lock timeout becomes ``E602`` and a
        sync-point timeout becomes ``E701``.  Neither is a business outcome:
        they propagate to the caller and are never written to a receipt.
        """
        try:
            return self._execute(operation)
        except sqlite3.OperationalError as error:
            if "locked" in str(error).lower() or "busy" in str(error).lower():
                raise RecoveryError(E_BUSY, f"database stayed locked: {error}") from error
            raise
        except TimeoutError as error:
            raise RecoveryError(E_TIMEOUT, str(error)) from error
        except (sqlite3.DatabaseError, OSError) as error:
            raise RecoveryError(E_INTERNAL, f"{type(error).__name__}: {error}") from error

    def _execute(self, operation: dict) -> dict:
        """Execute one operation and return its result envelope.

        Only mutating operations own a request receipt; read-only operations
        are answered from a consistent snapshot and can be repeated freely.
        Structural malformations (``E100``, ``E102``) are answered without
        touching the database because they cannot be attributed to a request
        id reliably; every other outcome is persisted and replayable.
        """
        request = parse_request(operation)
        kind = request["kind"]
        if kind in READ_ONLY_OPS:
            receipt = self._read_receipt(request)
            return self._envelope(request, self.tenant, receipt)
        req_hash = request_hash(operation)
        if kind in ("rotate_channel", "revoke_channel"):
            self.sync.hit("channel.before_lock")
        else:
            self.sync.hit("recovery.before_lock")
        with db.WriteTx(self.conn, self.tenant) as tx:
            state = tx.state
            assert state is not None
            stored = self._replay_or_conflict(state, request["remote_id"], req_hash)
            if stored is not None:
                tx.rollback()
                return self._envelope(request, self.tenant, stored, replayed=True)
            if kind == "request_recovery":
                receipt = self._recovery_receipt_or_error(tx, state, request, self._at(request))
                after_write = "recovery.after_write"
                after_commit = "recovery.after_commit"
            elif kind in ("rotate_channel", "revoke_channel"):
                receipt = self._channel_receipt_or_error(tx, state, request, self._at(request))
                after_write = "channel.after_write"
                after_commit = "channel.after_commit"
            else:  # pragma: no cover - parse_request already filtered
                raise RecoveryError(E_UNKNOWN_OP, f"unknown operation {kind!r}")
            tx.touch()
            tx.insert_op(request["remote_id"], kind, req_hash, receipt["status"], receipt["code"], receipt)
            self.sync.hit(after_write)
        self.sync.hit(after_commit)
        return self._envelope(request, self.tenant, receipt)

    def _read_receipt(self, request: dict) -> dict:
        if request["kind"] == "preview":
            return self._preview_receipt(request)
        if request["kind"] == "get_account":
            return self._account_receipt(request)
        if request["kind"] == "get_attempt":
            return self._attempt_receipt(request)
        if request["kind"] == "get_recovery":
            return self._recovery_receipt(request)
        if request["kind"] == "get_state":
            return self._state_receipt(request)
        raise RecoveryError(E_UNKNOWN_OP, f"unknown operation {request['kind']!r}")  # pragma: no cover

    def execute_caught(self, operation: dict) -> dict:
        """Like :meth:`execute` but converts protocol errors into envelopes."""
        try:
            return self.execute(operation)
        except RecoveryError as error:
            return {
                "remote_id": operation.get("remote_id"),
                "op": operation.get("op"),
                "tenant": self.tenant,
                "status": "error",
                "code": error.code,
                "replayed": False,
                "receipt": {
                    "status": "error",
                    "code": error.code,
                    "message": error.message,
                },
            }


# ---------------------------------------------------------------------------
# Case runner
# ---------------------------------------------------------------------------


def run_case(conn, seed, *, sync=None) -> dict:
    """Seed one tenant (if new) and execute its operations in order."""
    inserted = db.seed_tenant(conn, seed, now=seed.now)
    engine = Engine(conn, tenant=seed.tenant, key=seed.key, now=seed.now, sync=sync)
    results = [engine.execute_caught(operation) for operation in seed.operations]
    return {
        "case_id": seed.case_id,
        "tenant": seed.tenant,
        "seeded": inserted,
        "results": results,
        "snapshot": db.read_state(conn, seed.tenant).snapshot(),
    }
