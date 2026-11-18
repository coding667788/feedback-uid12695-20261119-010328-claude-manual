"""Input validation, canonical encoding, digests and signatures.

All records are synthetic and supplied by the case file.  Signatures are
HMAC-SHA256 under a demo key that is embedded in the cases file; they exist so
that proofs and channel lifecycle events are authenticated the way a real
coordinator would authenticate them.  They make no claim of real-world
security.

Canonical encoding (shared by profile digests, attempt digests, recovery
digests and every signature):

* UTF-8, object keys sorted, no whitespace.
* Array order is preserved.
* Optional fields that are absent are omitted from the encoding.
* ``signature`` itself is excluded from the payload it signs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .errors import (
    E_BAD_CASE,
    E_BAD_RECORD,
    E_BAD_SIGNATURE,
    E_CHANNEL_TIME,
    E_DUPLICATE_ID,
    E_UNKNOWN_ID,
    RecoveryError,
)

CHANNEL_TYPES = ("human", "device", "admin")
#: A recovery pair must contain at least one proof of one of these types.
STRONG_CHANNEL_TYPES = ("human", "admin")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_hex64(value: Any) -> bool:
    return isinstance(value, str) and bool(_HEX64.match(value))


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# Digests
# ---------------------------------------------------------------------------


def profile_digest(profile: Any) -> str:
    """Digest of the pending profile.  The raw profile is never persisted."""
    return sha256_hex(canonical_json(profile))


def attempt_digest(
    *, tenant: str, account_id: str, attempt_id: str, account_gen: int, profile_digest_: str
) -> str:
    return sha256_hex(
        canonical_json(
            {
                "tenant": tenant,
                "account_id": account_id,
                "attempt_id": attempt_id,
                "account_gen": account_gen,
                "profile_digest": profile_digest_,
            }
        )
    )


def recovery_digest(
    *,
    tenant: str,
    account_id: str,
    account_gen: int,
    attempt_id: str,
    attempt_digest_: str,
    proof_a: str,
    proof_b: str,
    profile_digest_: str,
) -> str:
    return sha256_hex(
        canonical_json(
            {
                "tenant": tenant,
                "account_id": account_id,
                "account_gen": account_gen,
                "attempt_id": attempt_id,
                "attempt_digest": attempt_digest_,
                "proofs": [proof_a, proof_b],
                "profile_digest": profile_digest_,
            }
        )
    )


def request_hash(operation: dict) -> str:
    """Digest of everything about a request except its idempotency key."""
    payload = {name: value for name, value in operation.items() if name != "remote_id"}
    return sha256_hex(canonical_json(payload))


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------


def _sign(key: bytes, payload: dict) -> str:
    return hmac.new(key, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def proof_payload(proof: dict) -> dict:
    return {
        "id": proof["id"],
        "attempt_id": proof["attempt_id"],
        "account_id": proof["account_id"],
        "account_gen": proof["account_gen"],
        "profile_digest": proof["profile_digest"],
        "channel_id": proof["channel_id"],
        "channel_type": proof["channel_type"],
        "channel_gen": proof["channel_gen"],
        "not_before": proof["not_before"],
        "not_after": proof["not_after"],
        "issuer": proof["issuer"],
    }


def proof_signature(key: bytes, proof: dict) -> str:
    return _sign(key, proof_payload(proof))


def proof_signature_ok(key: bytes, proof: dict) -> bool:
    signature = proof.get("signature")
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(proof_signature(key, proof), signature)


def event_payload(event: dict) -> dict:
    return {
        "id": event["id"],
        "channel_id": event["channel_id"],
        "kind": event["kind"],
        "channel_gen": event["channel_gen"],
        "at": event["at"],
    }


def event_signature(key: bytes, event: dict) -> str:
    return _sign(key, event_payload(event))


def event_signature_ok(key: bytes, event: dict) -> bool:
    signature = event.get("signature")
    if not isinstance(signature, str):
        return False
    return hmac.compare_digest(event_signature(key, event), signature)


# ---------------------------------------------------------------------------
# Case file seeds
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelSeed:
    id: str
    type: str


@dataclass(frozen=True)
class AccountSeed:
    id: str
    account_gen: int
    status: str


@dataclass(frozen=True)
class AttemptSeed:
    id: str
    account_id: str
    account_gen: int
    profile: dict
    profile_digest: str
    created_at: int
    expires_at: int
    status: str


@dataclass(frozen=True)
class ProofSeed:
    id: str
    attempt_id: str
    account_id: str
    account_gen: int
    profile_digest: str
    channel_id: str
    channel_type: str
    channel_gen: int
    not_before: int
    not_after: int
    issuer: str
    signature: str
    status: str = "available"
    consumed_by: str | None = None
    consumed_at: int | None = None


@dataclass(frozen=True)
class EventSeed:
    id: str
    channel_id: str
    kind: str
    channel_gen: int
    at: int
    signature: str


@dataclass
class CaseSeed:
    case_id: str
    tenant: str
    account_id: str
    now: int
    key: bytes
    channels: list[ChannelSeed] = field(default_factory=list)
    accounts: list[AccountSeed] = field(default_factory=list)
    attempts: list[AttemptSeed] = field(default_factory=list)
    proofs: list[ProofSeed] = field(default_factory=list)
    events: list[EventSeed] = field(default_factory=list)
    operations: list[dict] = field(default_factory=list)
    expectation: dict | None = None


def load_cases(path: str) -> dict:
    """Read a cases file and validate its top-level structure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise RecoveryError(E_BAD_CASE, f"cannot read cases file: {exc}") from exc
    except ValueError as exc:
        raise RecoveryError(E_BAD_CASE, f"cases file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise RecoveryError(E_BAD_CASE, "top level must be an object")
    if not isinstance(data.get("cases", []), list):
        raise RecoveryError(E_BAD_CASE, "'cases' must be an array")
    if not isinstance(data.get("races", []), list):
        raise RecoveryError(E_BAD_CASE, "'races' must be an array")
    # A tenant owns its records, so one tenant may be described only once in
    # the whole file.  This is a file-level property: it is checked before any
    # scenario runs so a duplicated tenant cannot silently share a database.
    declared: dict[str, str] = {}
    for index, entry in enumerate(data.get("cases", [])):
        if not isinstance(entry, dict):
            raise RecoveryError(E_BAD_CASE, f"case #{index} is not an object")
        tenant = entry.get("tenant")
        if not isinstance(tenant, str) or not tenant:
            raise RecoveryError(E_BAD_CASE, f"case #{index} needs a non-empty 'tenant'")
        case_id = entry.get("case_id", f"case#{index}")
        if tenant in declared:
            raise RecoveryError(
                E_DUPLICATE_ID, f"tenant {tenant!r} is described by both {declared[tenant]!r} and {case_id!r}"
            )
        declared[tenant] = f"case {case_id!r}"
    for index, entry in enumerate(data.get("races", [])):
        if not isinstance(entry, dict) or not isinstance(entry.get("case"), dict):
            raise RecoveryError(E_BAD_CASE, f"race #{index} needs a 'case' object")
        case_entry = entry["case"]
        tenant = case_entry.get("tenant")
        if not isinstance(tenant, str) or not tenant:
            raise RecoveryError(E_BAD_CASE, f"race #{index} case needs a non-empty 'tenant'")
        race_id = entry.get("race_id", f"race#{index}")
        if tenant in declared:
            raise RecoveryError(
                E_DUPLICATE_ID, f"tenant {tenant!r} is described by both {declared[tenant]!r} and race {race_id!r}"
            )
        declared[tenant] = f"race {race_id!r}"
    return data


def _req_str(record: dict, name: str, where: str) -> str:
    value = record.get(name)
    if not isinstance(value, str) or not value:
        raise RecoveryError(E_BAD_RECORD, f"{where}: field {name!r} must be a non-empty string")
    return value


def _req_int(record: dict, name: str, where: str, *, minimum: int | None = None) -> int:
    value = record.get(name)
    if not is_int(value):
        raise RecoveryError(E_BAD_RECORD, f"{where}: field {name!r} must be an integer")
    if minimum is not None and value < minimum:
        raise RecoveryError(E_BAD_RECORD, f"{where}: field {name!r} must be >= {minimum}")
    return value


def _unique(records: list[dict], where: str) -> dict[str, dict]:
    by_id: dict[str, dict] = {}
    for record in records:
        if not isinstance(record, dict):
            raise RecoveryError(E_BAD_RECORD, f"{where}: every record must be an object")
        record_id = _req_str(record, "id", where)
        if record_id in by_id:
            raise RecoveryError(E_DUPLICATE_ID, f"{where}: duplicate id {record_id!r}")
        by_id[record_id] = record
    return by_id


def proof_dict(seed: ProofSeed) -> dict:
    return {
        "id": seed.id,
        "attempt_id": seed.attempt_id,
        "account_id": seed.account_id,
        "account_gen": seed.account_gen,
        "profile_digest": seed.profile_digest,
        "channel_id": seed.channel_id,
        "channel_type": seed.channel_type,
        "channel_gen": seed.channel_gen,
        "not_before": seed.not_before,
        "not_after": seed.not_after,
        "issuer": seed.issuer,
        "signature": seed.signature,
    }


def event_dict(seed: EventSeed) -> dict:
    return {
        "id": seed.id,
        "channel_id": seed.channel_id,
        "kind": seed.kind,
        "channel_gen": seed.channel_gen,
        "at": seed.at,
        "signature": seed.signature,
    }


def parse_case(case: dict, index: int) -> CaseSeed:
    """Validate one case and return seeds ready for insertion."""
    if not isinstance(case, dict):
        raise RecoveryError(E_BAD_CASE, f"case #{index} is not an object")
    case_id = _req_str(case, "case_id", f"case #{index}")
    tenant = _req_str(case, "tenant", f"case {case_id}")
    account_id = _req_str(case, "account_id", f"case {case_id}")
    key_text = case.get("signing_key")
    if not isinstance(key_text, str) or not key_text:
        raise RecoveryError(E_BAD_CASE, f"case {case_id}: signing_key must be a non-empty string")
    key = key_text.encode("utf-8")
    load = case.get("load", {})
    if not isinstance(load, dict):
        raise RecoveryError(E_BAD_CASE, f"case {case_id}: load must be an object")
    now = load.get("now", 0)
    if not is_int(now) or now < 0:
        raise RecoveryError(E_BAD_CASE, f"case {case_id}: load.now must be a non-negative integer")
    operations = case.get("operations", [])
    if not isinstance(operations, list):
        raise RecoveryError(E_BAD_CASE, f"case {case_id}: operations must be an array")
    for op_index, op in enumerate(operations):
        if not isinstance(op, dict):
            raise RecoveryError(E_BAD_CASE, f"case {case_id}: operation #{op_index} is not an object")
        _req_str(op, "remote_id", f"case {case_id} operation #{op_index}")

    names = ("accounts", "channels", "attempts", "proofs", "channel_events")
    for name in names:
        if not isinstance(load.get(name, []), list):
            raise RecoveryError(E_BAD_CASE, f"case {case_id}: load.{name} must be an array")
    where = f"case {case_id}"
    channels_raw = _unique(load.get("channels", []), f"{where} channels")
    accounts_raw = _unique(load.get("accounts", []), f"{where} accounts")
    attempts_raw = _unique(load.get("attempts", []), f"{where} attempts")
    proofs_raw = _unique(load.get("proofs", []), f"{where} proofs")
    events_raw = _unique(load.get("channel_events", []), f"{where} channel events")

    # -- channels ------------------------------------------------------------
    channels: dict[str, ChannelSeed] = {}
    for record in channels_raw.values():
        cid = _req_str(record, "id", f"{where} channel")
        ctype = record.get("type")
        if ctype not in CHANNEL_TYPES:
            raise RecoveryError(E_BAD_RECORD, f"{where} channel {cid}: type must be one of {CHANNEL_TYPES}")
        channels[cid] = ChannelSeed(id=cid, type=ctype)

    # -- accounts ------------------------------------------------------------
    accounts: list[AccountSeed] = []
    for record in accounts_raw.values():
        aid = _req_str(record, "id", f"{where} account")
        gen = _req_int(record, "account_gen", f"{where} account {aid}", minimum=0)
        status = record.get("status", "active")
        if status not in ("active", "frozen"):
            raise RecoveryError(E_BAD_RECORD, f"{where} account {aid}: status must be active or frozen")
        accounts.append(AccountSeed(id=aid, account_gen=gen, status=status))
    accounts_by_id = {account.id: account for account in accounts}
    if account_id not in accounts_by_id:
        raise RecoveryError(E_UNKNOWN_ID, f"{where}: account {account_id!r} is missing from load.accounts")

    # -- attempts ------------------------------------------------------------
    attempts: list[AttemptSeed] = []
    for record in attempts_raw.values():
        att_id = _req_str(record, "id", f"{where} attempt")
        att_account = _req_str(record, "account_id", f"{where} attempt {att_id}")
        if att_account not in accounts_by_id:
            raise RecoveryError(E_UNKNOWN_ID, f"{where} attempt {att_id}: unknown account {att_account!r}")
        att_gen = _req_int(record, "account_gen", f"{where} attempt {att_id}", minimum=1)
        profile = record.get("profile")
        if not isinstance(profile, dict):
            raise RecoveryError(E_BAD_RECORD, f"{where} attempt {att_id}: profile must be an object")
        created_at = _req_int(record, "created_at", f"{where} attempt {att_id}", minimum=0)
        expires_at = _req_int(record, "expires_at", f"{where} attempt {att_id}", minimum=0)
        if expires_at <= created_at:
            raise RecoveryError(E_BAD_RECORD, f"{where} attempt {att_id}: expires_at must be after created_at")
        status = record.get("status", "open")
        if status not in ("open", "closed"):
            raise RecoveryError(E_BAD_RECORD, f"{where} attempt {att_id}: status must be open or closed")
        attempts.append(
            AttemptSeed(
                id=att_id,
                account_id=att_account,
                account_gen=att_gen,
                profile=profile,
                profile_digest=profile_digest(profile),
                created_at=created_at,
                expires_at=expires_at,
                status=status,
            )
        )
    attempts_by_id = {attempt.id: attempt for attempt in attempts}

    # -- proofs --------------------------------------------------------------
    proofs: list[ProofSeed] = []
    for record in proofs_raw.values():
        proof_id = _req_str(record, "id", f"{where} proof")
        attempt_id = _req_str(record, "attempt_id", f"{where} proof {proof_id}")
        if attempt_id not in attempts_by_id:
            raise RecoveryError(E_UNKNOWN_ID, f"{where} proof {proof_id}: unknown attempt {attempt_id!r}")
        proof_account = _req_str(record, "account_id", f"{where} proof {proof_id}")
        if proof_account not in accounts_by_id:
            raise RecoveryError(E_UNKNOWN_ID, f"{where} proof {proof_id}: unknown account {proof_account!r}")
        digest = record.get("profile_digest")
        if not is_hex64(digest):
            raise RecoveryError(
                E_BAD_RECORD, f"{where} proof {proof_id}: profile_digest must be 64 lowercase hex characters"
            )
        channel_id = _req_str(record, "channel_id", f"{where} proof {proof_id}")
        channel_type = record.get("channel_type")
        if channel_type not in CHANNEL_TYPES:
            raise RecoveryError(E_BAD_RECORD, f"{where} proof {proof_id}: bad channel_type")
        if channel_id in channels and channels[channel_id].type != channel_type:
            raise RecoveryError(
                E_BAD_RECORD,
                f"{where} proof {proof_id}: channel {channel_id!r} is declared as "
                f"{channels[channel_id].type!r}, proof says {channel_type!r}",
            )
        channels.setdefault(channel_id, ChannelSeed(id=channel_id, type=channel_type))
        seed = ProofSeed(
            id=proof_id,
            attempt_id=attempt_id,
            account_id=proof_account,
            account_gen=_req_int(record, "account_gen", f"{where} proof {proof_id}", minimum=1),
            profile_digest=digest,
            channel_id=channel_id,
            channel_type=channel_type,
            channel_gen=_req_int(record, "channel_gen", f"{where} proof {proof_id}", minimum=1),
            not_before=_req_int(record, "not_before", f"{where} proof {proof_id}", minimum=0),
            not_after=_req_int(record, "not_after", f"{where} proof {proof_id}", minimum=0),
            issuer=_req_str(record, "issuer", f"{where} proof {proof_id}"),
            signature=_req_str(record, "signature", f"{where} proof {proof_id}"),
            status=record.get("status", "available"),
            consumed_by=record.get("consumed_by"),
            consumed_at=record.get("consumed_at"),
        )
        if seed.not_after < seed.not_before:
            raise RecoveryError(E_BAD_RECORD, f"{where} proof {proof_id}: not_after is before not_before")
        if seed.status not in ("available", "consumed"):
            raise RecoveryError(E_BAD_RECORD, f"{where} proof {proof_id}: status must be available or consumed")
        if seed.status == "consumed":
            if not isinstance(seed.consumed_by, str) or not seed.consumed_by:
                raise RecoveryError(
                    E_BAD_RECORD, f"{where} proof {proof_id}: a consumed proof needs consumed_by"
                )
            if not is_int(seed.consumed_at):
                raise RecoveryError(
                    E_BAD_RECORD, f"{where} proof {proof_id}: a consumed proof needs consumed_at"
                )
        if not proof_signature_ok(key, proof_dict(seed)):
            raise RecoveryError(E_BAD_SIGNATURE, f"{where} proof {proof_id}: signature does not verify")
        proofs.append(seed)

    # -- channel lifecycle events --------------------------------------------
    events: list[EventSeed] = []
    for record in events_raw.values():
        event_id = _req_str(record, "id", f"{where} channel event")
        channel_id = _req_str(record, "channel_id", f"{where} channel event {event_id}")
        if channel_id not in channels:
            raise RecoveryError(
                E_UNKNOWN_ID, f"{where} channel event {event_id}: unknown channel {channel_id!r}"
            )
        kind = record.get("kind")
        if kind not in ("rotate", "revoke"):
            raise RecoveryError(E_BAD_RECORD, f"{where} channel event {event_id}: kind must be rotate or revoke")
        seed = EventSeed(
            id=event_id,
            channel_id=channel_id,
            kind=kind,
            channel_gen=_req_int(record, "channel_gen", f"{where} channel event {event_id}", minimum=1),
            at=_req_int(record, "at", f"{where} channel event {event_id}", minimum=0),
            signature=_req_str(record, "signature", f"{where} channel event {event_id}"),
        )
        if not event_signature_ok(key, event_dict(seed)):
            raise RecoveryError(E_BAD_SIGNATURE, f"{where} channel event {event_id}: signature does not verify")
        events.append(seed)

    _check_channel_chain(channels, events, where)

    expectation = case.get("expect")
    if expectation is not None and not isinstance(expectation, dict):
        raise RecoveryError(E_BAD_CASE, f"case {case_id}: expect must be an object")

    return CaseSeed(
        case_id=case_id,
        tenant=tenant,
        account_id=account_id,
        now=now,
        key=key,
        channels=list(channels.values()),
        accounts=accounts,
        attempts=attempts,
        proofs=proofs,
        events=events,
        operations=operations,
        expectation=expectation,
    )


def _check_channel_chain(channels: dict[str, ChannelSeed], events: list[EventSeed], where: str) -> None:
    """Seeded lifecycle events must form one valid chain per channel.

    Generation 1 exists implicitly.  ``rotate`` to N+1 requires the channel to
    be alive at N; ``revoke`` at N kills generation N and everything after it.
    Events of one channel must be non-decreasing in ``at``.
    """
    by_channel: dict[str, list[EventSeed]] = {cid: [] for cid in channels}
    for event in events:
        by_channel[event.channel_id].append(event)
    for channel_id, chain in by_channel.items():
        gen = 1
        alive = True
        last_at = -1
        for event in sorted(chain, key=lambda item: (item.at, item.id)):
            if event.at < last_at:
                raise RecoveryError(
                    E_CHANNEL_TIME, f"{where} channel {channel_id}: lifecycle time moved backwards"
                )
            last_at = event.at
            if not alive:
                raise RecoveryError(
                    E_BAD_RECORD, f"{where} channel {channel_id}: event {event.id!r} after the channel was revoked"
                )
            if event.kind == "rotate":
                if event.channel_gen != gen + 1:
                    raise RecoveryError(
                        E_BAD_RECORD,
                        f"{where} channel {channel_id}: event {event.id!r} rotates to generation "
                        f"{event.channel_gen}, expected {gen + 1}",
                    )
                gen = event.channel_gen
            else:
                if event.channel_gen != gen:
                    raise RecoveryError(
                        E_BAD_RECORD,
                        f"{where} channel {channel_id}: event {event.id!r} revokes generation "
                        f"{event.channel_gen}, current is {gen}",
                    )
                alive = False
