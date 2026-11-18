"""Independent synthesis of case files.

This module deliberately does **not** import ``solution``.  It re-implements
the documented canonical encoding and HMAC rules from the README so that a
case file is an independent statement of the protocol: the solution has to
agree with it, not the other way round.

Everything here is synthetic: the signing key, ids, channels and profiles are
made up by :func:`build_document`.
"""

from __future__ import annotations

import hashlib
import hmac
import json

KEY = b"synthetic-recovery-key-2026"


def canon(value) -> bytes:
    """README canonical form: UTF-8, sorted keys, no whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha(value) -> str:
    return hashlib.sha256(canon(value)).hexdigest()


def hmac_hex(value) -> str:
    return hmac.new(KEY, canon(value), hashlib.sha256).hexdigest()


def profile_digest(profile: dict) -> str:
    return sha(profile)


def proof(
    proof_id,
    attempt_id,
    account_id,
    account_gen,
    profile,
    channel_id,
    channel_type,
    channel_gen,
    not_before,
    not_after,
    issuer,
    status=None,
    consumed_by=None,
    consumed_at=None,
):
    payload = {
        "id": proof_id,
        "attempt_id": attempt_id,
        "account_id": account_id,
        "account_gen": account_gen,
        "profile_digest": profile_digest(profile),
        "channel_id": channel_id,
        "channel_type": channel_type,
        "channel_gen": channel_gen,
        "not_before": not_before,
        "not_after": not_after,
        "issuer": issuer,
    }
    record = {**payload, "signature": hmac_hex(payload)}
    if status is not None:
        record["status"] = status
        record["consumed_by"] = consumed_by
        record["consumed_at"] = consumed_at
    return record


def proof_signature_for(record: dict) -> str:
    """Signature over the seven proof fields named by the README."""
    payload = {
        "id": record["id"],
        "attempt_id": record["attempt_id"],
        "account_id": record["account_id"],
        "account_gen": record["account_gen"],
        "profile_digest": record["profile_digest"],
        "channel_id": record["channel_id"],
        "channel_type": record["channel_type"],
        "channel_gen": record["channel_gen"],
        "not_before": record["not_before"],
        "not_after": record["not_after"],
        "issuer": record["issuer"],
    }
    return hmac_hex(payload)


def event(event_id, channel_id, kind, channel_gen, at):
    payload = {"id": event_id, "channel_id": channel_id, "kind": kind, "channel_gen": channel_gen, "at": at}
    return {**payload, "signature": hmac_hex(payload)}


def lifecycle_request(remote_id, op, channel_id, channel_gen, at):
    """Signed channel-lifecycle request.

    The signature covers the lifecycle effect, not the request bookkeeping:
    ``id`` (the remote id), ``channel_id``, ``kind``, ``channel_gen`` and
    ``at``.  This matches the canonical form used for seeded events, so the
    same key and rule authenticate both.
    """
    payload = {
        "id": remote_id,
        "channel_id": channel_id,
        "kind": "rotate" if op == "rotate_channel" else "revoke",
        "channel_gen": channel_gen,
        "at": at,
    }
    return {**payload, "remote_id": remote_id, "op": op, "signature": hmac_hex(payload)}


def attempt(attempt_id, account_id, account_gen, profile, created_at, expires_at, status="open"):
    return {
        "id": attempt_id,
        "account_id": account_id,
        "account_gen": account_gen,
        "profile": profile,
        "created_at": created_at,
        "expires_at": expires_at,
        "status": status,
    }


def recovery_request(remote_id, account_id, attempt_id, at=None, **extra):
    request = {"remote_id": remote_id, "op": "request_recovery", "account_id": account_id, "attempt_id": attempt_id}
    if at is not None:
        request["at"] = at
    request.update(extra)
    return request


def case(case_id, tenant, account_id, now, channels, accounts, attempts, proofs, events, operations, expect):
    return {
        "case_id": case_id,
        "tenant": tenant,
        "account_id": account_id,
        "signing_key": KEY.decode("ascii"),
        "load": {
            "now": now,
            "channels": channels,
            "accounts": accounts,
            "attempts": attempts,
            "proofs": proofs,
            "channel_events": events,
        },
        "operations": operations,
        "expect": expect,
    }


def channel(channel_id, channel_type):
    return {"id": channel_id, "type": channel_type}


def account(account_id, account_gen, status="active"):
    return {"id": account_id, "account_gen": account_gen, "status": status}


def write_document(path: str, document: dict) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2, sort_keys=False)
        handle.write("\n")
