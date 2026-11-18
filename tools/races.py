"""Race scenarios for ``cases.json``.

Each race is a small script of process actions; sync points fix the order, so
the outcome is deterministic on any machine.  The expectations are written
from the protocol rules, not from a previous run.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import synth  # noqa: E402
from tools.gen_cases import PROFILE, base_account, channels, proof  # noqa: E402


def race_case(case_id, tenant, proof_list, attempt_list, channel_list, events=None, accounts=None):
    return {
        "case_id": case_id,
        "tenant": tenant,
        "account_id": "acct-1",
        "signing_key": synth.KEY.decode("ascii"),
        "load": {
            "now": 0,
            "channels": channel_list,
            "accounts": accounts or [base_account()],
            "attempts": attempt_list,
            "proofs": proof_list,
            "channel_events": events or [],
        },
        "operations": [],
        "expect": {},
    }


def two_channel_case(tag, prof=None):
    """One attempt with a current human proof and a current device proof."""
    prof = prof or PROFILE
    proofs = [
        proof(f"{tag}-h", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof(f"{tag}-d", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d"),
    ]
    return race_case(
        tag,
        f"tenant-{tag}",
        proofs,
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        channels(tag),
    )


# ---------------------------------------------------------------------------
# A. Revocation wins the race
# ---------------------------------------------------------------------------


def race_revoke_first():
    tag = "race-revoke"
    prof = PROFILE
    case_dict = two_channel_case(tag, prof)
    steps = [
        # W1 previews a currently valid state, but parks before taking the lock
        {"start": "W1", "request": synth.recovery_request("req-w1", "acct-1", "att-1", at=500), "park": ["recovery.before_lock"]},
        {"at": "W1", "point": "recovery.before_lock"},
        # W2 revokes the device channel at t=450 (in the past relative to the
        # request time, so the revocation applies) and is allowed to finish
        {"start": "W2", "request": synth.lifecycle_request("lif-w2", "revoke_channel", f"{tag}-d", 1, 450)},
        {"exit": "W2"},
        {"snapshot": "after-revoke"},
        # now W1 is released and must re-read the proofs: its device proof is dead
        {"release": "W1", "point": "recovery.before_lock"},
        {"exit": "W1"},
        {"snapshot": "final"},
        # the failure receipt is itself a persisted business outcome, so the
        # snapshot legitimately changes by exactly that receipt
        {"snapshot_change": ["after-revoke", "final"]},
    ]
    expect = {
        "workers": [
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.receipt.code": None},
            {"name": "W1", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506", "envelope.replayed": False},
        ],
        "snapshots": {
            "after-revoke": {
                "accounts.acct-1.account_gen": 1,
                "events.lif-w2": {"kind": "revoke", "channel_gen": 1, "at": 450},
            },
        },
        "final": {
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
            "proofs." + f"{tag}-h": {"status": "available"},
            "proofs." + f"{tag}-d": {"status": "available"},
        },
    }
    return {"race_id": "race-revoke-first", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# B. Two attempts of the same account race
# ---------------------------------------------------------------------------


def race_two_attempts():
    tag = "race-two"
    prof = PROFILE
    proofs = [
        proof("r2-h", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof("r2-d", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d"),
        proof("r2-a", "att-2", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 3000, "v-a"),
        proof("r2-d2", "att-2", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 3000, "v-d2"),
    ]
    case_dict = race_case(
        tag,
        f"tenant-{tag}",
        proofs,
        [
            synth.attempt("att-1", "acct-1", 1, prof, 100, 3000),
            synth.attempt("att-2", "acct-1", 1, prof, 100, 3000),
        ],
        channels(tag),
    )
    steps = [
        {"start": "W1", "request": synth.recovery_request("req-1", "acct-1", "att-1", at=500), "park": ["recovery.before_lock"]},
        {"start": "W2", "request": synth.recovery_request("req-2", "acct-1", "att-2", at=500), "park": ["recovery.before_lock"]},
        # both have seen the same (valid) state before either locks
        {"at": "W1", "point": "recovery.before_lock"},
        {"at": "W2", "point": "recovery.before_lock"},
        {"release": "W1", "point": "recovery.before_lock"},
        {"exit": "W1"},
        {"snapshot": "after-first"},
        {"release": "W2", "point": "recovery.before_lock"},
        {"exit": "W2"},
        {"snapshot": "final"},
        {"snapshot_change": ["after-first", "final"]},
    ]
    expect = {
        "workers": [
            # pair order is lexicographic by proof id, not channel type order
            {"name": "W1", "envelope.receipt.status": "committed", "envelope.receipt.recovery.proofs": ["r2-d", "r2-h"]},
            {"name": "W2", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E505"},
        ],
        "snapshots": {
            "after-first": {"accounts.acct-1.account_gen": 2, "attempts.att-1.status": "closed"},
        },
        "final": {
            "accounts.acct-1.account_gen": 2,
            "attempts.att-1.status": "closed",
            "attempts.att-2.status": "closed",
            "proofs.r2-h.status": "consumed",
            "proofs.r2-d.status": "consumed",
            "proofs.r2-a.status": "available",
            "proofs.r2-d2.status": "available",
        },
    }
    return {"race_id": "race-two-attempts", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# C. Expiry boundary races
# ---------------------------------------------------------------------------


def race_expiry_boundary():
    """One step past a proof's not_after fails; exactly at it succeeds."""
    tag = "race-expiry"
    prof = PROFILE
    base = two_channel_case(tag, prof)
    # the device proof is valid through t=500 inclusive
    base["load"]["proofs"][1] = proof(
        f"{tag}-d", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 500, "v-d"
    )
    steps = [
        # W1 is one tick past the boundary and must fail, even though it runs
        # before the successful worker
        {"start": "W1", "request": synth.recovery_request("req-too-late", "acct-1", "att-1", at=501), "park": ["recovery.before_lock"]},
        {"at": "W1", "point": "recovery.before_lock"},
        {"release": "W1", "point": "recovery.before_lock"},
        {"exit": "W1"},
        {"snapshot": "after-late"},
        # W2 runs exactly at the boundary and is allowed to commit
        {"start": "W2", "request": synth.recovery_request("req-at-boundary", "acct-1", "att-1", at=500), "park": ["recovery.before_lock"]},
        {"at": "W2", "point": "recovery.before_lock"},
        {"release": "W2", "point": "recovery.before_lock"},
        {"exit": "W2"},
        {"snapshot": "final"},
        {"snapshot_change": ["after-late", "final"]},
    ]
    expect = {
        "workers": [
            {"name": "W1", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506"},
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.receipt.recovery.proofs": [f"{tag}-d", f"{tag}-h"]},
        ],
        "snapshots": {
            "after-late": {"accounts.acct-1.account_gen": 1, "attempts.att-1.status": "open"},
            "final": {"accounts.acct-1.account_gen": 2, "attempts.att-1.status": "closed"},
        },
        "final": {
            "accounts.acct-1.account_gen": 2,
            "proofs." + f"{tag}-d": {"status": "consumed", "consumed_at": 500},
        },
    }
    return {"race_id": "race-expiry-boundary", "case": base, "steps": steps, "expect": expect}


def race_expiry_after_commit():
    """The same boundary, but the extra attempt is a fresh one at generation 2."""
    tag = "race-expiry2"
    prof = PROFILE
    proofs = [
        proof(f"{tag}-h", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof(f"{tag}-d", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 500, "v-d"),
        proof(f"{tag}-h2", "att-2", "acct-1", 2, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h2"),
        proof(f"{tag}-a2", "att-2", "acct-1", 2, prof, f"{tag}-a", "admin", 1, 100, 3000, "v-a2"),
    ]
    case_dict = race_case(
        tag,
        f"tenant-{tag}",
        proofs,
        [
            synth.attempt("att-1", "acct-1", 1, prof, 100, 3000),
            synth.attempt("att-2", "acct-1", 2, prof, 100, 3000),
        ],
        channels(tag),
    )
    steps = [
        {"start": "W1", "request": synth.recovery_request("req-1", "acct-1", "att-1", at=500)},
        {"exit": "W1"},
        {"snapshot": "after-first"},
        # at 501 the device proof of att-1 (and att-1 itself) is superseded;
        # the fresh attempt at generation 2 is unaffected.
        {"start": "W2", "request": synth.recovery_request("req-2", "acct-1", "att-2", at=501)},
        {"exit": "W2"},
        {"snapshot": "final"},
        {"snapshot_change": ["after-first", "final"]},
    ]
    expect = {
        "workers": [
            {"name": "W1", "envelope.receipt.status": "committed", "envelope.receipt.recovery.proofs": [f"{tag}-d", f"{tag}-h"]},
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.receipt.recovery.proofs": [f"{tag}-a2", f"{tag}-h2"]},
        ],
        "snapshots": {
            "after-first": {"accounts.acct-1.account_gen": 2, "proofs." + f"{tag}-d": {"status": "consumed"}},
        },
        "final": {"accounts.acct-1.account_gen": 3},
    }
    return {"race_id": "race-expiry-after-commit", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# D. Crash between consuming the proofs and committing
# ---------------------------------------------------------------------------


def race_kill_before_commit():
    tag = "race-kill-before"
    prof = PROFILE
    case_dict = two_channel_case(tag, prof)
    steps = [
        {"snapshot": "before"},
        {"start": "W1", "request": synth.recovery_request("req-kill", "acct-1", "att-1", at=500), "park": ["recovery.after_write"]},
        {"at": "W1", "point": "recovery.after_write"},
        # inside the uncommitted transaction the proofs are already consumed
        # in W1's own view; an independent reader must still see the old state
        {"snapshot": "during"},
        {"kill": "W1"},
        {"expect_dead": "W1"},
        {"snapshot": "after-kill"},
        {"no_snapshot_change": ["before", "during"]},
        {"no_snapshot_change": ["before", "after-kill"]},
        # a fresh process with the same request succeeds; the killed
        # transaction left no receipt behind, so this is not a replay
        {"start": "W2", "request": synth.recovery_request("req-kill", "acct-1", "att-1", at=500)},
        {"exit": "W2"},
        {"snapshot": "final"},
        # and the retry is durable
        {"start": "W3", "request": synth.recovery_request("req-kill", "acct-1", "att-1", at=500)},
        {"exit": "W3"},
    ]
    expect = {
        "workers": [
            {"name": "W1", "killed": True},
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.replayed": False},
            {"name": "W3", "envelope.receipt.status": "committed", "envelope.replayed": True},
        ],
        "snapshots": {
            "during": {
                "accounts.acct-1.account_gen": 1,
                "proofs." + f"{tag}-h": {"status": "available"},
                "attempts.att-1.status": "open",
            },
            "after-kill": {
                "accounts.acct-1.account_gen": 1,
                "attempts.att-1.status": "open",
                "proofs." + f"{tag}-h": {"status": "available"},
                "proofs." + f"{tag}-d": {"status": "available"},
            },
        },
        "final": {"accounts.acct-1.account_gen": 2, "attempts.att-1.status": "closed"},
    }
    return {"race_id": "race-kill-before-commit", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# E. Crash after the commit but before the reply is returned
# ---------------------------------------------------------------------------


def race_kill_before_reply():
    tag = "race-kill-reply"
    prof = PROFILE
    case_dict = two_channel_case(tag, prof)
    steps = [
        {"start": "W1", "request": synth.recovery_request("req-kill", "acct-1", "att-1", at=500), "park": ["recovery.after_commit"]},
        {"at": "W1", "point": "recovery.after_commit"},
        {"snapshot": "committed"},
        {"kill": "W1"},
        {"expect_dead": "W1"},
        {"snapshot": "after-kill"},
        {"no_snapshot_change": ["committed", "after-kill"]},
        # the retry must return the persisted first result, not redo anything
        {"start": "W2", "request": synth.recovery_request("req-kill", "acct-1", "att-1", at=500)},
        {"exit": "W2"},
        {"snapshot": "final"},
        {"no_snapshot_change": ["after-kill", "final"]},
    ]
    expect = {
        "workers": [
            {"name": "W1", "killed": True},
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.replayed": True},
        ],
        "snapshots": {
            "committed": {
                "accounts.acct-1.account_gen": 2,
                "attempts.att-1.status": "closed",
                "proofs." + f"{tag}-h": {"status": "consumed", "consumed_by": "att-1"},
            },
            "after-kill": {"accounts.acct-1.account_gen": 2},
        },
        "final": {
            "accounts.acct-1.account_gen": 2,
            "attempts.att-1.status": "closed",
            "proofs." + f"{tag}-d": {"status": "consumed"},
        },
    }
    return {"race_id": "race-kill-before-reply", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# F. A failed pair does not poison a retry after a revocation
# ---------------------------------------------------------------------------


def race_failed_then_revoke():
    tag = "race-fail-revoke"
    prof = PROFILE
    # All three proofs come from verifier "v-x": any human/device or
    # human/admin pair therefore violates the "different verifier" rule, and
    # device/device violates the "different channel type" rule.  No legal pair
    # exists, whatever order they are enumerated in.
    proofs = [
        proof("rf-h", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-x"),
        proof("rf-d1", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-x"),
        proof("rf-d2", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 3000, "v-x"),
    ]
    case_dict = race_case(
        tag,
        f"tenant-{tag}",
        proofs,
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        channels(tag),
    )
    steps = [
        {"start": "W1", "request": synth.recovery_request("req-fail", "acct-1", "att-1", at=500)},
        {"exit": "W1"},
        {"snapshot": "after-failure"},
        # revoke the human channel, then replay the same request: the stored
        # failure must be returned, not a fresh evaluation
        {"start": "W2", "request": synth.lifecycle_request("lif-2", "revoke_channel", f"{tag}-h", 1, 600)},
        {"exit": "W2"},
        {"start": "W3", "request": synth.recovery_request("req-fail", "acct-1", "att-1", at=500)},
        {"exit": "W3"},
        # a different request id sees the new state and still fails
        {"start": "W4", "request": synth.recovery_request("req-fresh", "acct-1", "att-1", at=500)},
        {"exit": "W4"},
    ]
    expect = {
        "workers": [
            {"name": "W1", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506"},
            {"name": "W3", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506", "envelope.replayed": True},
            {"name": "W4", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506", "envelope.replayed": False},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
        },
    }
    return {"race_id": "race-failed-then-revoke", "case": case_dict, "steps": steps, "expect": expect}


# ---------------------------------------------------------------------------
# G. Two workers use the same request id concurrently
# ---------------------------------------------------------------------------


def race_same_request_id():
    tag = "race-same-id"
    prof = PROFILE
    case_dict = two_channel_case(tag, prof)
    steps = [
        {"start": "W1", "request": synth.recovery_request("req-same", "acct-1", "att-1", at=500), "park": ["recovery.before_lock"]},
        {"start": "W2", "request": synth.recovery_request("req-same", "acct-1", "att-1", at=500), "park": ["recovery.before_lock"]},
        {"at": "W1", "point": "recovery.before_lock"},
        {"at": "W2", "point": "recovery.before_lock"},
        {"release": "W1", "point": "recovery.before_lock"},
        {"exit": "W1"},
        {"release": "W2", "point": "recovery.before_lock"},
        {"exit": "W2"},
    ]
    expect = {
        "workers": [
            {"name": "W1", "envelope.receipt.status": "committed", "envelope.replayed": False},
            {"name": "W2", "envelope.receipt.status": "committed", "envelope.replayed": True},
        ],
        "final": {"accounts.acct-1.account_gen": 2},
    }
    return {"race_id": "race-same-request-id", "case": case_dict, "steps": steps, "expect": expect}


def build_races():
    return [
        race_revoke_first(),
        race_two_attempts(),
        race_expiry_boundary(),
        race_expiry_after_commit(),
        race_kill_before_commit(),
        race_kill_before_reply(),
        race_failed_then_revoke(),
        race_same_request_id(),
    ]


if __name__ == "__main__":  # pragma: no cover
    import json

    print(json.dumps(build_races(), indent=2)[:2000])
