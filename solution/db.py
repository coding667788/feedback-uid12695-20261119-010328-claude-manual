"""SQLite persistence shared by independent processes.

Design notes
------------
* WAL journal and a busy timeout let two processes read while one writes.
* Every mutation happens inside ``BEGIN IMMEDIATE``.  A commit therefore always
  holds the database write lock, and every read used for the decision is made
  *inside* that transaction: previews are advisory, decisions are not.
* Concurrent writers are serialised by SQLite itself.  The loser of a race
  re-reads the committed state and rejects rather than overwriting it.
* ``meta.rev`` is a monotonic revision bumped by every committed write
  transaction.  It is used as the first statement of a write transaction to
  take the lock unambiguously, and as a cheap way to tell "did anything
  commit?" during debugging; it is deliberately excluded from the business
  snapshot.
* State is exposed as frozen dataclasses: a preview can be compared with a
  later snapshot by value without aliasing.

Every table is keyed by ``tenant``; records of one tenant are invisible to
another (a proof id from tenant B is "unknown" in tenant A).
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tenants (
    tenant TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    now INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
    tenant TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    PRIMARY KEY (tenant, channel_id)
);
CREATE TABLE IF NOT EXISTS accounts (
    tenant TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_gen INTEGER NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (tenant, account_id)
);
CREATE TABLE IF NOT EXISTS attempts (
    tenant TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_gen INTEGER NOT NULL,
    profile TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    closed_by TEXT,
    PRIMARY KEY (tenant, attempt_id)
);
CREATE TABLE IF NOT EXISTS proofs (
    tenant TEXT NOT NULL,
    proof_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    account_gen INTEGER NOT NULL,
    profile_digest TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    channel_gen INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    issuer TEXT NOT NULL,
    signature TEXT NOT NULL,
    status TEXT NOT NULL,
    consumed_by TEXT,
    consumed_at INTEGER,
    PRIMARY KEY (tenant, proof_id)
);
CREATE TABLE IF NOT EXISTS channel_events (
    tenant TEXT NOT NULL,
    event_id TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    channel_gen INTEGER NOT NULL,
    at INTEGER NOT NULL,
    signature TEXT NOT NULL,
    PRIMARY KEY (tenant, event_id)
);
CREATE TABLE IF NOT EXISTS recoveries (
    tenant TEXT NOT NULL,
    account_gen INTEGER NOT NULL,
    account_id TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    proof_a TEXT NOT NULL,
    proof_b TEXT NOT NULL,
    attempt_digest TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    recovery_digest TEXT NOT NULL,
    at INTEGER NOT NULL,
    request_tenant TEXT NOT NULL,
    request_id TEXT NOT NULL,
    request_at INTEGER NOT NULL,
    PRIMARY KEY (tenant, account_gen)
);
CREATE TABLE IF NOT EXISTS ops (
    tenant TEXT NOT NULL,
    remote_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    code TEXT,
    result TEXT NOT NULL,
    PRIMARY KEY (tenant, remote_id)
);
"""


def connect(path: str, *, busy_timeout: float = 30.0) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=busy_timeout, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout * 1000)}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        conn.execute("INSERT OR IGNORE INTO meta(k, v) VALUES ('rev', '0')")
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise


# ---------------------------------------------------------------------------
# Immutable views
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChannelView:
    id: str
    type: str


@dataclass(frozen=True)
class AccountView:
    id: str
    account_gen: int
    status: str

    def as_dict(self) -> dict:
        return {"account_id": self.id, "account_gen": self.account_gen, "status": self.status}


@dataclass(frozen=True)
class AttemptView:
    id: str
    account_id: str
    account_gen: int
    profile: str
    profile_digest: str
    created_at: int
    expires_at: int
    status: str
    closed_by: str | None

    def as_dict(self) -> dict:
        return {
            "attempt_id": self.id,
            "account_id": self.account_id,
            "account_gen": self.account_gen,
            "profile_digest": self.profile_digest,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status,
            "closed_by": self.closed_by,
        }


@dataclass(frozen=True)
class ProofView:
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
    status: str
    consumed_by: str | None
    consumed_at: int | None

    def as_dict(self) -> dict:
        return {
            "proof_id": self.id,
            "attempt_id": self.attempt_id,
            "account_id": self.account_id,
            "account_gen": self.account_gen,
            "profile_digest": self.profile_digest,
            "channel_id": self.channel_id,
            "channel_type": self.channel_type,
            "channel_gen": self.channel_gen,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "issuer": self.issuer,
            "status": self.status,
            "consumed_by": self.consumed_by,
            "consumed_at": self.consumed_at,
        }

    def as_signature_input(self) -> dict:
        return {
            "id": self.id,
            "attempt_id": self.attempt_id,
            "account_id": self.account_id,
            "account_gen": self.account_gen,
            "profile_digest": self.profile_digest,
            "channel_id": self.channel_id,
            "channel_type": self.channel_type,
            "channel_gen": self.channel_gen,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "issuer": self.issuer,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class EventView:
    id: str
    channel_id: str
    kind: str
    channel_gen: int
    at: int
    signature: str = ""

    def as_dict(self) -> dict:
        return {
            "event_id": self.id,
            "channel_id": self.channel_id,
            "kind": self.kind,
            "channel_gen": self.channel_gen,
            "at": self.at,
        }

    def as_signature_input(self) -> dict:
        return {
            "id": self.id,
            "channel_id": self.channel_id,
            "kind": self.kind,
            "channel_gen": self.channel_gen,
            "at": self.at,
            "signature": self.signature,
        }


@dataclass(frozen=True)
class RecoveryView:
    account_gen: int
    account_id: str
    attempt_id: str
    proof_a: str
    proof_b: str
    attempt_digest: str
    profile_digest: str
    recovery_digest: str
    at: int
    request_tenant: str
    request_id: str
    request_at: int

    def as_dict(self) -> dict:
        return {
            "account_gen": self.account_gen,
            "account_id": self.account_id,
            "attempt_id": self.attempt_id,
            "proofs": [self.proof_a, self.proof_b],
            "attempt_digest": self.attempt_digest,
            "profile_digest": self.profile_digest,
            "recovery_digest": self.recovery_digest,
            "at": self.at,
            "request_tenant": self.request_tenant,
            "request_id": self.request_id,
            "request_at": self.request_at,
        }


@dataclass(frozen=True)
class OpView:
    remote_id: str
    kind: str
    request_hash: str
    status: str
    code: str | None
    result: str

    def result_dict(self) -> dict:
        return json.loads(self.result)


@dataclass
class State:
    """One consistent snapshot of a tenant."""

    rev: int
    channels: dict[str, ChannelView] = field(default_factory=dict)
    accounts: dict[str, AccountView] = field(default_factory=dict)
    attempts: dict[str, AttemptView] = field(default_factory=dict)
    proofs: dict[str, ProofView] = field(default_factory=dict)
    events: dict[str, EventView] = field(default_factory=dict)
    recoveries: dict[int, RecoveryView] = field(default_factory=dict)
    ops: dict[str, OpView] = field(default_factory=dict)

    # -- channel generation maths -------------------------------------------
    def channel_state(self, channel_id: str) -> tuple[int, int | None]:
        """Current generation and revocation time of a channel.

        Lifecycle state is whatever has been *committed*: a recovery
        submission re-reads it, so a rotation or revocation that lands first
        invalidates proofs already issued at an older generation.  The ``at``
        field of an event only orders events against each other; it is not a
        time gate for recovery, because a submission is always decided against
        the latest committed state.
        """
        generation = 1
        events = sorted(
            (event for event in self.events.values() if event.channel_id == channel_id),
            key=lambda event: (event.at, event.id),
        )
        for event in events:
            if event.kind == "revoke" and event.channel_gen == generation:
                return generation, event.at
            if event.kind == "rotate" and event.channel_gen == generation + 1:
                generation = event.channel_gen
        return generation, None

    def snapshot(self) -> dict:
        """Deterministic picture of the persisted business state.

        ``rev`` is excluded: it counts write transactions and would differ for
        reasons that are not part of the business outcome.
        """
        return {
            "channels": {key: {"channel_id": ch.id, "type": ch.type} for key, ch in sorted(self.channels.items())},
            "accounts": {key: value.as_dict() for key, value in sorted(self.accounts.items())},
            "attempts": {key: value.as_dict() for key, value in sorted(self.attempts.items())},
            "proofs": {key: value.as_dict() for key, value in sorted(self.proofs.items())},
            "events": {key: value.as_dict() for key, value in sorted(self.events.items())},
            "recoveries": [self.recoveries[key].as_dict() for key in sorted(self.recoveries)],
            "ops": [
                {
                    "remote_id": op.remote_id,
                    "kind": op.kind,
                    "status": op.status,
                    "code": op.code,
                    "result": op.result_dict(),
                }
                for _, op in sorted(self.ops.items())
            ],
        }


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def _read_state(conn: sqlite3.Connection, tenant: str) -> State:
    """Read a whole tenant; the caller owns the transaction."""
    meta = {row["k"]: row["v"] for row in conn.execute("SELECT k, v FROM meta")}
    rev = int(meta.get("rev", "0"))
    channels = {
        row["channel_id"]: ChannelView(id=row["channel_id"], type=row["channel_type"])
        for row in conn.execute("SELECT channel_id, channel_type FROM channels WHERE tenant = ?", (tenant,))
    }
    accounts = {
        row["account_id"]: AccountView(
            id=row["account_id"], account_gen=row["account_gen"], status=row["status"]
        )
        for row in conn.execute(
            "SELECT account_id, account_gen, status FROM accounts WHERE tenant = ?", (tenant,)
        )
    }
    attempts = {
        row["attempt_id"]: AttemptView(
            id=row["attempt_id"],
            account_id=row["account_id"],
            account_gen=row["account_gen"],
            profile=row["profile"],
            profile_digest=row["profile_digest"],
            created_at=row["created_at"],
            expires_at=row["expires_at"],
            status=row["status"],
            closed_by=row["closed_by"],
        )
        for row in conn.execute(
            "SELECT attempt_id, account_id, account_gen, profile, profile_digest, created_at, "
            "expires_at, status, closed_by FROM attempts WHERE tenant = ?",
            (tenant,),
        )
    }
    proofs = {
        row["proof_id"]: ProofView(
            id=row["proof_id"],
            attempt_id=row["attempt_id"],
            account_id=row["account_id"],
            account_gen=row["account_gen"],
            profile_digest=row["profile_digest"],
            channel_id=row["channel_id"],
            channel_type=row["channel_type"],
            channel_gen=row["channel_gen"],
            not_before=row["not_before"],
            not_after=row["not_after"],
            issuer=row["issuer"],
            signature=row["signature"],
            status=row["status"],
            consumed_by=row["consumed_by"],
            consumed_at=row["consumed_at"],
        )
        for row in conn.execute(
            "SELECT proof_id, attempt_id, account_id, account_gen, profile_digest, channel_id, "
            "channel_type, channel_gen, not_before, not_after, issuer, signature, status, "
            "consumed_by, consumed_at FROM proofs WHERE tenant = ?",
            (tenant,),
        )
    }
    events = {
        row["event_id"]: EventView(
            id=row["event_id"],
            channel_id=row["channel_id"],
            kind=row["kind"],
            channel_gen=row["channel_gen"],
            at=row["at"],
            signature=row["signature"],
        )
        for row in conn.execute(
            "SELECT event_id, channel_id, kind, channel_gen, at, signature "
            "FROM channel_events WHERE tenant = ?",
            (tenant,),
        )
    }
    recoveries = {
        row["account_gen"]: RecoveryView(
            account_gen=row["account_gen"],
            account_id=row["account_id"],
            attempt_id=row["attempt_id"],
            proof_a=row["proof_a"],
            proof_b=row["proof_b"],
            attempt_digest=row["attempt_digest"],
            profile_digest=row["profile_digest"],
            recovery_digest=row["recovery_digest"],
            at=row["at"],
            request_tenant=row["request_tenant"],
            request_id=row["request_id"],
            request_at=row["request_at"],
        )
        for row in conn.execute(
            "SELECT account_gen, account_id, attempt_id, proof_a, proof_b, attempt_digest, "
            "profile_digest, recovery_digest, at, request_tenant, request_id, request_at "
            "FROM recoveries WHERE tenant = ?",
            (tenant,),
        )
    }
    ops = {
        row["remote_id"]: OpView(
            remote_id=row["remote_id"],
            kind=row["kind"],
            request_hash=row["request_hash"],
            status=row["status"],
            code=row["code"],
            result=row["result"],
        )
        for row in conn.execute(
            "SELECT remote_id, kind, request_hash, status, code, result FROM ops WHERE tenant = ?",
            (tenant,),
        )
    }
    return State(
        rev=rev,
        channels=channels,
        accounts=accounts,
        attempts=attempts,
        proofs=proofs,
        events=events,
        recoveries=recoveries,
        ops=ops,
    )


def read_state(conn: sqlite3.Connection, tenant: str) -> State:
    """Consistent read snapshot (advisory; may be stale by the next statement)."""
    conn.execute("BEGIN")
    try:
        state = _read_state(conn, tenant)
    finally:
        conn.execute("COMMIT")
    return state


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


class WriteTx:
    """One ``BEGIN IMMEDIATE`` transaction.

    The transaction starts by reading the tenant inside the write lock, so a
    decision taken after :meth:`state` cannot be overtaken by another process.
    """

    def __init__(self, conn: sqlite3.Connection, tenant: str):
        self.conn = conn
        self.tenant = tenant
        self.state: State | None = None
        self.rev = 0
        self._open = False

    def __enter__(self) -> "WriteTx":
        self.conn.execute("BEGIN IMMEDIATE")
        self._open = True
        self.bump_rev()
        self.state = _read_state(self.conn, self.tenant)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if not self._open:
            return
        try:
            if exc_type is None:
                self.conn.execute("COMMIT")
            else:
                self.conn.execute("ROLLBACK")
        finally:
            self._open = False

    def bump_rev(self) -> None:
        row = self.conn.execute("SELECT v FROM meta WHERE k = 'rev'").fetchone()
        self.rev = int(row["v"]) + 1
        self.conn.execute("UPDATE meta SET v = ? WHERE k = 'rev'", (str(self.rev),))

    def touch(self) -> None:
        """Re-assert that this transaction holds the write lock."""
        self.conn.execute("UPDATE meta SET v = v WHERE k = 'rev'")

    def commit(self) -> None:
        self.conn.execute("COMMIT")
        self._open = False

    def rollback(self) -> None:
        self.conn.execute("ROLLBACK")
        self._open = False

    # -- statements ---------------------------------------------------------
    def consume_proof(self, proof: ProofView, by_attempt: str, at: int) -> None:
        cursor = self.conn.execute(
            "UPDATE proofs SET status = 'consumed', consumed_by = ?, consumed_at = ? "
            "WHERE tenant = ? AND proof_id = ? AND status = 'available'",
            (by_attempt, at, self.tenant, proof.id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError(f"proof {proof.id!r} was not consumable inside the write lock")

    def bump_account(self, account_id: str) -> int:
        row = self.conn.execute(
            "SELECT account_gen FROM accounts WHERE tenant = ? AND account_id = ?", (self.tenant, account_id)
        ).fetchone()
        new_gen = int(row["account_gen"]) + 1
        self.conn.execute(
            "UPDATE accounts SET account_gen = ? WHERE tenant = ? AND account_id = ?",
            (new_gen, self.tenant, account_id),
        )
        return new_gen

    def close_attempts_of_generation(self, account_id: str, account_gen: int, closed_by: str) -> list[str]:
        rows = list(
            self.conn.execute(
                "SELECT attempt_id FROM attempts WHERE tenant = ? AND account_id = ? AND account_gen = ? "
                "AND status = 'open' ORDER BY attempt_id",
                (self.tenant, account_id, account_gen),
            )
        )
        self.conn.execute(
            "UPDATE attempts SET status = 'closed', closed_by = ? WHERE tenant = ? AND account_id = ? "
            "AND account_gen = ? AND status = 'open'",
            (closed_by, self.tenant, account_id, account_gen),
        )
        return [row["attempt_id"] for row in rows]

    def insert_recovery(self, recovery: RecoveryView) -> None:
        self.conn.execute(
            "INSERT INTO recoveries(tenant, account_gen, account_id, attempt_id, proof_a, proof_b, "
            "attempt_digest, profile_digest, recovery_digest, at, request_tenant, request_id, request_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self.tenant,
                recovery.account_gen,
                recovery.account_id,
                recovery.attempt_id,
                recovery.proof_a,
                recovery.proof_b,
                recovery.attempt_digest,
                recovery.profile_digest,
                recovery.recovery_digest,
                recovery.at,
                recovery.request_tenant,
                recovery.request_id,
                recovery.request_at,
            ),
        )

    def insert_op(self, remote_id: str, kind: str, req_hash: str, status: str, code: str | None, receipt: dict) -> None:
        """Persist a receipt (the ``receipt`` member of an envelope).

        Replay must return exactly what the first execution returned, so this
        is the only document stored; the envelope's ``replayed`` flag is
        computed per call and never persisted.
        """
        self.conn.execute(
            "INSERT INTO ops(tenant, remote_id, kind, request_hash, status, code, result) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self.tenant, remote_id, kind, req_hash, status, code, json.dumps(receipt, sort_keys=True)),
        )

    def insert_event(self, *, event_id: str, channel_id: str, kind: str, channel_gen: int, at: int, signature: str) -> None:
        self.conn.execute(
            "INSERT INTO channel_events(tenant, event_id, channel_id, kind, channel_gen, at, signature) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self.tenant, event_id, channel_id, kind, channel_gen, at, signature),
        )


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def seed_tenant(conn: sqlite3.Connection, seed, *, now: int = 0) -> bool:
    """Insert a case's records for its tenant once.  Returns True if inserted."""
    tenant = seed.tenant
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT 1 FROM tenants WHERE tenant = ?", (tenant,)).fetchone()
        if row is not None:
            conn.execute("COMMIT")
            return False
        conn.execute(
            "INSERT INTO tenants(tenant, case_id, now) VALUES (?, ?, ?)", (tenant, seed.case_id, now)
        )
        for channel in seed.channels:
            conn.execute(
                "INSERT INTO channels(tenant, channel_id, channel_type) VALUES (?, ?, ?)",
                (tenant, channel.id, channel.type),
            )
        for account in seed.accounts:
            conn.execute(
                "INSERT INTO accounts(tenant, account_id, account_gen, status) VALUES (?, ?, ?, ?)",
                (tenant, account.id, account.account_gen, account.status),
            )
        for attempt in seed.attempts:
            conn.execute(
                "INSERT INTO attempts(tenant, attempt_id, account_id, account_gen, profile, profile_digest, "
                "created_at, expires_at, status, closed_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    attempt.id,
                    attempt.account_id,
                    attempt.account_gen,
                    json.dumps(attempt.profile, sort_keys=True),
                    attempt.profile_digest,
                    attempt.created_at,
                    attempt.expires_at,
                    attempt.status,
                    None,
                ),
            )
        for proof in seed.proofs:
            conn.execute(
                "INSERT INTO proofs(tenant, proof_id, attempt_id, account_id, account_gen, profile_digest, "
                "channel_id, channel_type, channel_gen, not_before, not_after, issuer, signature, status, "
                "consumed_by, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    proof.id,
                    proof.attempt_id,
                    proof.account_id,
                    proof.account_gen,
                    proof.profile_digest,
                    proof.channel_id,
                    proof.channel_type,
                    proof.channel_gen,
                    proof.not_before,
                    proof.not_after,
                    proof.issuer,
                    proof.signature,
                    proof.status,
                    proof.consumed_by,
                    proof.consumed_at,
                ),
            )
        for event in seed.events:
            conn.execute(
                "INSERT INTO channel_events(tenant, event_id, channel_id, kind, channel_gen, at, signature) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (tenant, event.id, event.channel_id, event.kind, event.channel_gen, event.at, event.signature),
            )
        row = conn.execute("SELECT v FROM meta WHERE k = 'rev'").fetchone()
        conn.execute("UPDATE meta SET v = ? WHERE k = 'rev'", (str(int(row["v"]) + 1),))
        conn.execute("COMMIT")
        return True
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def read_now(conn: sqlite3.Connection, tenant: str) -> int | None:
    row = conn.execute("SELECT now FROM tenants WHERE tenant = ?", (tenant,)).fetchone()
    return None if row is None else int(row["now"])


