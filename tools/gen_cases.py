"""Synthesise ``cases.json``: single-process cases plus two-process races.

Every expected value in the file is written down by hand (or derived from the
protocol rules restated in this module); nothing is read back from the
implementation.  Run with::

    python tools/gen_cases.py cases.json

The generator only depends on :mod:`tools.synth`, which re-implements the
documented canonical encoding/HMAC rules independently of ``solution``.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools import synth  # noqa: E402

PROFILE = {"display_name": "alice", "email": "alice@example.test", "locale": "en-GB"}
PROFILE_ALT = {"display_name": "alice", "email": "alice@example.test", "locale": "fr-FR"}
PROFILE_OTHER = {"display_name": "mallory", "email": "mallory@example.test"}


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


def channels(tag, human="h", device="d", admin="a", spare_device="d2"):
    """Four channels with stable types; ids carry the case tag."""
    return [
        synth.channel(f"{tag}-{human}", "human"),
        synth.channel(f"{tag}-{device}", "device"),
        synth.channel(f"{tag}-{admin}", "admin"),
        synth.channel(f"{tag}-{spare_device}", "device"),
    ]


def base_account(account_id="acct-1", gen=1, status="active"):
    return synth.account(account_id, gen, status)


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
    **extra,
):
    return synth.proof(
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
        **extra,
    )


def recovery(remote_id, attempt_id="att-1", at=500, account_id="acct-1", **extra):
    return synth.recovery_request(remote_id, account_id, attempt_id, at=at, **extra)


# ---------------------------------------------------------------------------
# Case 1: happy path, idempotency, conflict, tenant isolation
# ---------------------------------------------------------------------------


def case_protocol_errors():
    """Structural and protocol-level refusals are visible in the results.

    ``E100`` (malformed request) and ``E102`` (unknown operation) are not
    business outcomes, so they are reported in the result document but never
    persisted: the request has no trustworthy receipt identity.
    """
    tag = "protocol"
    prof = PROFILE
    proofs = [
        proof("p-00-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-01-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    operations = [
        # unknown operation name
        {"remote_id": "proto-unknown", "op": "explode", "account_id": "acct-1"},
        # missing required field
        {"remote_id": "proto-missing", "op": "request_recovery", "account_id": "acct-1"},
        # wrong field type
        {"remote_id": "proto-type", "op": "request_recovery", "account_id": "acct-1", "attempt_id": 7},
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "error", "code": "E102"},
            {"op": 1, "status": "error", "code": "E100"},
            {"op": 2, "status": "error", "code": "E100"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_happy():
    tag = "happy"
    prof = PROFILE
    proofs = [
        proof("p-01-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-human"),
        proof("p-02-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-device"),
        proof("p-03-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-admin"),
        # another tenant's proof id, same attempt id, must be invisible here
        proof("p-04-human", "att-1", "acct-1", 1, prof, f"{tag}-spare", "device", 1, 100, 900, "v-spare"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        recovery("req-1", at=500),
        recovery("req-1", at=500),  # identical -> replay
        synth.recovery_request("req-1", "acct-1", "att-1", at=501),  # different params -> E501
        {"remote_id": "op-account", "op": "get_account", "account_id": "acct-1"},
        {"remote_id": "op-attempt", "op": "get_attempt", "attempt_id": "att-1"},
    ]
    expect = {
        "outcomes": [
            # Lexicographic pair: p-01(admin? no, human) + p-02(device) are the two
            # smallest ids, different channels and types, human present -> chosen.
            {"op": 0, "status": "ok", "candidate": ["p-01-human", "p-02-device"]},
            {"op": 1, "status": "committed", "code": None, "proofs": ["p-01-human", "p-02-device"], "account_gen": 2},
            {"op": 2, "status": "committed", "replayed": True, "proofs": ["p-01-human", "p-02-device"]},
            {"op": 3, "status": "error", "code": "E501"},
            {"op": 4, "status": "read"},
            {"op": 5, "status": "read"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 2,
            "attempts.att-1.status": "closed",
            "proofs.p-01-human.status": "consumed",
            "proofs.p-02-device.status": "consumed",
            "proofs.p-03-admin.status": "available",
            "proofs.p-04-human.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 2: pair selection rules (same signer, same type, device-only, etc.)
# ---------------------------------------------------------------------------


def case_pair_rules():
    tag = "pairs"
    prof = PROFILE
    proofs = [
        # a valid human proof, but its signer is reused by the admin proof
        proof("p-10-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-shared"),
        proof("p-11-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-shared"),
        # two devices: both are usable alone, cannot pair with each other
        proof("p-12-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d1"),
        proof("p-13-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 900, "v-d2"),
    ]
    # only p-10..p-13 are present, so the only legal pair is (p-10, p-12):
    # p-10/p-11 share a signer, p-10/p-13 are device+human but p-12 has the
    # smaller id than p-13 so (p-10, p-12) wins.
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        recovery("req-1", at=500),
        recovery("req-2", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "ok", "candidate": ["p-10-human", "p-12-device"]},
            {"op": 1, "status": "committed", "proofs": ["p-10-human", "p-12-device"]},
            # E505 because the attempt was closed by the first recovery.
            {"op": 2, "status": "rejected", "code": "E505"},
        ],
        "final": {
            "proofs.p-10-human.status": "consumed",
            "proofs.p-12-device.status": "consumed",
            "proofs.p-11-admin.status": "available",
            "proofs.p-13-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_device_only_pair():
    tag = "deviceonly"
    prof = PROFILE
    proofs = [
        proof("p-20-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d1"),
        proof("p-21-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 900, "v-d2"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        recovery("req-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "none", "code": "E506"},
            {"op": 1, "status": "rejected", "code": "E506"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
            "proofs.p-20-device.status": "available",
            "proofs.p-21-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_same_signer_only():
    tag = "signer"
    prof = PROFILE
    proofs = [
        proof("p-30-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-same"),
        proof("p-31-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-same"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "none", "code": "E506"},
            {"op": 1, "status": "rejected", "code": "E506"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "proofs.p-30-human.status": "available",
            "proofs.p-31-admin.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 3: window and expiry boundaries (inclusive at both ends)
# ---------------------------------------------------------------------------


def case_boundaries():
    tag = "bounds"
    prof = PROFILE
    proofs = [
        # att-1 exercises the attempt window: both proofs stay valid well past
        # the attempt's own expires_at (900)
        proof("p-50-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 200, 2000, "v-h"),
        proof("p-51-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 2000, "v-d"),
    ]
    operations = [
        # at == not_before boundary is valid (inclusive)
        {"remote_id": "op-preview-at-nb", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 200},
        # one nanosecond early is not
        {"remote_id": "op-preview-early", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 199},
        # attempt expires at 900, exactly 900 is valid
        {"remote_id": "op-preview-exp", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 900},
        # but 901 is not
        {"remote_id": "op-preview-after", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 901},
        # the attempt's own expires_at (900) is inclusive
        {"remote_id": "op-preview-attempt-exp", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 900},
        # 901 is past the attempt window
        {"remote_id": "op-preview-attempt-late", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 901},
        # a proof's not_after (800) is inclusive too
        {"remote_id": "op-preview-proof-exp", "op": "preview", "account_id": "acct-1", "attempt_id": "att-2", "at": 800},
        # at 801 the human proof of att-2 is expired while its device proof is
        # live; one live proof is not a pair -> E506, reasons in proof-id order
        {"remote_id": "op-preview-proof-late", "op": "preview", "account_id": "acct-1", "attempt_id": "att-2", "at": 801},
        # a single proof whose window ended at 800 is unusable at 801, even
        # though its attempt stays open until 2000
        {"remote_id": "op-preview-att3", "op": "preview", "account_id": "acct-1", "attempt_id": "att-3", "at": 801},
        # submission at the attempt boundary commits
        synth.recovery_request("req-1", "acct-1", "att-1", at=900),
        # the attempt is now closed by recovery
        synth.recovery_request("req-2", "acct-1", "att-1", at=900),
    ]
    # every channel stays at generation 1 in this case: the boundary under
    # test is the time window, not the channel generation
    proofs.append(proof("p-52-human", "att-2", "acct-1", 1, prof, f"{tag}-h", "human", 1, 200, 800, "v-h2"))
    proofs.append(proof("p-53-device", "att-2", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 2000, "v-d2"))
    proofs.append(proof("p-54-human", "att-3", "acct-1", 1, prof, f"{tag}-h", "human", 1, 200, 800, "v-h3"))
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 900),
        synth.attempt("att-2", "acct-1", 1, prof, 100, 2000),
        synth.attempt("att-3", "acct-1", 1, prof, 100, 2000),
    ]
    expect = {
        "outcomes": [
            # at == p-50's not_before (200) both proofs are inside their windows
            {"op": 0, "status": "ok", "candidate": ["p-50-human", "p-51-device"]},
            # 199 is before p-50's not_before; p-51 alone cannot make a pair
            {"op": 1, "status": "none", "code": "E506", "reasons": ["E210", None]},
            # the attempt's last instant (900) is inside its inclusive window
            {"op": 2, "status": "ok", "candidate": ["p-50-human", "p-51-device"]},
            # 901 is past the attempt window: the attempt itself is the blocker
            {"op": 3, "status": "unavailable", "code": "E211"},
            # the same boundary, seen again (attempt still open at 900)
            {"op": 4, "status": "ok", "candidate": ["p-50-human", "p-51-device"]},
            {"op": 5, "status": "unavailable", "code": "E211"},
            # p-52's not_after (800) is inclusive
            {"op": 6, "status": "ok", "candidate": ["p-52-human", "p-53-device"]},
            # one past not_after the human proof expires; device alone is no pair
            {"op": 7, "status": "none", "code": "E506", "reasons": ["E204", None]},
            # a single expired proof cannot recover either
            {"op": 8, "status": "none", "code": "E506", "reasons": ["E204"]},
            {"op": 9, "status": "committed", "proofs": ["p-50-human", "p-51-device"]},
            {"op": 10, "status": "rejected", "code": "E505"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 2,
            "attempts.att-1.status": "closed",
            # the recovery closes every open attempt of the consumed generation
            "attempts.att-2.status": "closed",
            "attempts.att-3.status": "closed",
            "proofs.p-50-human.status": "consumed",
            "proofs.p-51-device.status": "consumed",
            "proofs.p-52-human.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 4: channel rotation, stale generations, revocation
# ---------------------------------------------------------------------------


def case_channel_lifecycle():
    tag = "chanlife"
    prof = PROFILE
    proofs = [
        proof("p-60-human-g1", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 2000, "v-h"),
        proof("p-61-device-g1", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 2000, "v-d"),
        proof("p-62-human-g1", "att-2", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 2000, "v-h2"),
        proof("p-63-admin-g1", "att-2", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 2000, "v-a"),
    ]
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 2000),
        synth.attempt("att-2", "acct-1", 1, prof, 100, 2000),
    ]
    # seeded history: the human channel rotated 1 -> 2, the device channel was
    # revoked.  Lifecycle state is committed state, so both apply to every
    # subsequent submission regardless of the ``at`` of the request.
    events = [
        synth.event("ev-h-rot1", f"{tag}-h", "rotate", 2, 300),
        synth.event("ev-d-rev1", f"{tag}-d", "revoke", 1, 250),
    ]
    operations = [
        # p-60 (gen 1) is stale, p-61's channel is revoked -> no pair; the
        # per-proof reasons are reported in proof-id order
        {"remote_id": "op-preview-stale", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 400},
        # a request time before the events does not resurrect them
        {"remote_id": "op-preview-revoked", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 299},
        # att-2 pairs a stale generation-1 human proof with a live admin proof:
        # the stale one is unusable and one proof alone cannot recover
        {"remote_id": "op-preview-att2", "op": "preview", "account_id": "acct-1", "attempt_id": "att-2", "at": 400},
        # rotating a revoked channel must fail
        synth.lifecycle_request("lif-1", "rotate_channel", f"{tag}-d", 2, 500),
        # rotating to an already-used generation must fail
        synth.lifecycle_request("lif-2", "rotate_channel", f"{tag}-h", 2, 600),
        # the correct next generation works
        synth.lifecycle_request("lif-3", "rotate_channel", f"{tag}-h", 3, 700),
        # a lifecycle event cannot be inserted before an existing one
        synth.lifecycle_request("lif-time", "rotate_channel", f"{tag}-h", 4, 650),
        # a lifecycle request for a channel this tenant does not know
        synth.lifecycle_request("lif-unknown", "revoke_channel", "no-such-channel", 1, 760),
        # an unauthenticated lifecycle request is refused
        {**synth.lifecycle_request("lif-4", "revoke_channel", f"{tag}-a", 1, 750), "signature": "0" * 64},
        # att-1 still has one stale proof, so recovery stays impossible
        recovery("req-1", attempt_id="att-1", at=800),
        recovery("req-2", attempt_id="att-1", at=900),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "none", "code": "E506", "reasons": ["E403", "E402"]},
            {"op": 1, "status": "none", "code": "E506", "reasons": ["E403", "E402"]},
            {"op": 2, "status": "none", "code": "E506", "reasons": ["E403", None]},
            # the admin proof is healthy on its own; it has no E402/E405
            {"op": 3, "status": "rejected", "code": "E402"},
            {"op": 4, "status": "rejected", "code": "E404"},
            {"op": 5, "status": "committed", "code": None},
            {"op": 6, "status": "rejected", "code": "E214"},
            {"op": 7, "status": "rejected", "code": "E401"},
            {"op": 8, "status": "rejected", "code": "E301"},
            {"op": 9, "status": "rejected", "code": "E506", "reasons": ["E403", "E402"]},
            {"op": 10, "status": "rejected", "code": "E506"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
            "proofs.p-60-human-g1.status": "available",
            "proofs.p-61-device-g1.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        events,
        operations,
        expect,
    )


def case_new_generation_proof():
    """A proof minted at the *new* channel generation is accepted."""
    tag = "newgen"
    prof = PROFILE
    proofs = [
        proof("p-70-human-g1", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof("p-71-human-g2", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 2, 400, 3000, "v-h2"),
        proof("p-72-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d"),
    ]
    events = [synth.event("ev-h-rot", f"{tag}-h", "rotate", 2, 300)]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "ok", "candidate": ["p-71-human-g2", "p-72-device"]},
            {"op": 1, "status": "committed", "proofs": ["p-71-human-g2", "p-72-device"]},
        ],
        "final": {
            "proofs.p-70-human-g1.status": "available",
            "proofs.p-71-human-g2.status": "consumed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        proofs,
        events,
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 5: binding failures (profile, attempt, account, generation)
# ---------------------------------------------------------------------------


def case_binding():
    tag = "binding"
    prof = PROFILE
    proofs = [
        # digest of a *different* pending profile
        proof("p-80-human", "att-1", "acct-1", 1, PROFILE_ALT, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-81-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        # account_gen two while the account is at generation one
        proof("p-82-admin", "att-1", "acct-1", 2, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a"),
        # proof bound to a different attempt
        proof("p-83-admin", "att-2", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a2"),
    ]
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 900),
        synth.attempt("att-2", "acct-1", 1, prof, 100, 900),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        # wrong profile digest on p-80, stale generation on p-82, and p-83 is
        # not part of att-1 at all -> E506 with per-proof reasons
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "none", "code": "E506", "reasons": ["E205", None, "E205"]},
            {"op": 1, "status": "rejected", "code": "E506", "reasons": ["E205", None, "E205"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "proofs.p-80-human.status": "available",
            "proofs.p-81-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


def case_routing_errors():
    """Attempt/account routing and frozen accounts are rejected up front."""
    tag = "route"
    prof = PROFILE
    proofs = [
        proof("p-90-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-91-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    operations = [
        # att-1 belongs to acct-2, not acct-1
        synth.recovery_request("req-wrong-account", "acct-1", "att-1", at=500),
        # frozen account
        synth.recovery_request("req-frozen", "acct-3", "att-3", at=500),
        # unknown attempt
        synth.recovery_request("req-unknown", "acct-1", "att-missing", at=500),
        # preview of unknown account
        {"remote_id": "op-preview-unknown", "op": "preview", "account_id": "acct-missing", "attempt_id": "att-1", "at": 500},
    ]
    accounts = [base_account("acct-1"), base_account("acct-2"), base_account("acct-3", status="frozen")]
    attempts = [
        synth.attempt("att-1", "acct-2", 1, prof, 100, 900),
        synth.attempt("att-3", "acct-3", 1, prof, 100, 900),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E502"},
            {"op": 1, "status": "rejected", "code": "E212"},
            {"op": 2, "status": "rejected", "code": "E201"},
            {"op": 3, "status": "unavailable", "code": "E201"},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        accounts,
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 6: generation bump invalidates a sibling attempt, second recovery works
# ---------------------------------------------------------------------------


def case_second_recovery():
    """After a recovery, a fresh attempt at the new generation recovers."""
    tag = "second"
    prof = PROFILE
    proofs = [
        proof("p-100-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof("p-101-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d"),
        # a sibling attempt at generation 1 that was never cured
        proof("p-102-admin", "att-sibling", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 3000, "v-a"),
        proof("p-103-device", "att-sibling", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 3000, "v-d2"),
        # a fresh attempt at generation 2
        proof("p-104-human", "att-2", "acct-1", 2, prof, f"{tag}-h", "human", 1, 100, 4000, "v-h3"),
        proof("p-105-admin", "att-2", "acct-1", 2, prof, f"{tag}-a", "admin", 1, 100, 4000, "v-a3"),
    ]
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 3000),
        synth.attempt("att-sibling", "acct-1", 1, prof, 100, 3000),
        synth.attempt("att-2", "acct-1", 2, prof, 100, 4000),
    ]
    operations = [
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
        # the sibling attempt at generation 1 is now stale and closed
        synth.recovery_request("req-sibling", "acct-1", "att-sibling", at=600),
        # a fresh attempt at the new generation succeeds
        synth.recovery_request("req-2", "acct-1", "att-2", at=700),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "committed", "account_gen": 2, "proofs": ["p-100-human", "p-101-device"]},
            {"op": 1, "status": "rejected", "code": "E505"},
            {"op": 2, "status": "committed", "account_gen": 3, "proofs": ["p-104-human", "p-105-admin"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 3,
            "attempts.att-1.status": "closed",
            "attempts.att-sibling.status": "closed",
            "attempts.att-2.status": "closed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 7: failure receipt is fixed even if the state later becomes recoverable
# ---------------------------------------------------------------------------


def case_fixed_failure():
    """A business failure is persisted; a later, now-valid repeat still replays it."""
    tag = "fixedfail"
    prof = PROFILE
    proofs = [
        # before t=400 only the human proof is inside its window
        proof("p-110-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof("p-111-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 400, 3000, "v-d"),
    ]
    operations = [
        synth.recovery_request("req-early", "acct-1", "att-1", at=200),
        # same id, same parameters, later execution time: must replay the failure
        synth.recovery_request("req-early", "acct-1", "att-1", at=200),
        # a different id at t=500 would have succeeded, proving the state is fine
        synth.recovery_request("req-late", "acct-1", "att-1", at=500),
        # and a third repeat of the early id still replays
        synth.recovery_request("req-early", "acct-1", "att-1", at=200),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E506", "replayed": False},
            {"op": 1, "status": "rejected", "code": "E506", "replayed": True},
            {"op": 2, "status": "committed", "proofs": ["p-110-human", "p-111-device"]},
            {"op": 3, "status": "rejected", "code": "E506", "replayed": True},
        ],
        "final": {
            "accounts.acct-1.account_gen": 2,
            "proofs.p-110-human.status": "consumed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 8: idempotency key is tenant-scoped
# ---------------------------------------------------------------------------


def case_tenant_scope():
    """The same remote id in two tenants is two independent receipts."""
    tag = "scope"
    prof = PROFILE
    proofs = [
        proof("p-120-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-121-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    operations = [
        synth.recovery_request("req-shared", "acct-1", "att-1", at=500),
    ]
    # one case = one tenant, so we build a second tenant as its own case below
    return synth.case(
        tag,
        f"tenant-{tag}-a",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        {
            "outcomes": [{"op": 0, "status": "committed"}],
            "final": {"accounts.acct-1.account_gen": 2},
        },
    )


def case_tenant_scope_b():
    tag = "scopeb"
    prof = PROFILE
    proofs = [
        proof("p-130-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-131-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    return synth.case(
        tag,
        "tenant-scope-b",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        [synth.recovery_request("req-shared", "acct-1", "att-1", at=500)],
        {
            "outcomes": [{"op": 0, "status": "committed", "replayed": False}],
            "final": {"accounts.acct-1.account_gen": 2},
        },
    )


# ---------------------------------------------------------------------------
# Case 9: administrator pair (admin + device) is legal
# ---------------------------------------------------------------------------


def case_admin_device():
    tag = "adminde"
    prof = PROFILE
    proofs = [
        proof("p-140-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        proof("p-141-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a"),
        # a third proof that is individually unusable (same channel as p-140),
        # proving that ineligible proofs cannot block a valid pair
        proof("p-139-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d-dup"),
    ]
    operations = [
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            # p-139 < p-140 but shares the channel with p-140, so it cannot pair
            # with admin p-141? it can: distinct channel from p-141, admin+device.
            # Lexicographically the smallest pair is (p-139, p-141).
            {"op": 0, "status": "committed", "proofs": ["p-139-device", "p-141-admin"]},
        ],
        "final": {
            "proofs.p-139-device.status": "consumed",
            "proofs.p-141-admin.status": "consumed",
            "proofs.p-140-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 10: unusable pairs do not poison a later legal attempt
# ---------------------------------------------------------------------------


def case_recovery_after_failed_pair():
    """A failed pair leaves proofs available; a second attempt still recovers."""
    tag = "afterfail"
    prof = PROFILE
    proofs = [
        # att-1 has only two devices -> E506, both proofs stay available
        proof("p-150-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d1"),
        proof("p-151-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 3000, "v-d2"),
        # att-2 has a legal human+device pair
        proof("p-152-human", "att-2", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h"),
        proof("p-153-device", "att-2", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d3"),
    ]
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 3000),
        synth.attempt("att-2", "acct-1", 1, prof, 100, 3000),
    ]
    operations = [
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
        synth.recovery_request("req-2", "acct-1", "att-2", at=600),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E506"},
            {"op": 1, "status": "committed", "proofs": ["p-152-human", "p-153-device"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 2,
            "attempts.att-1.status": "closed",
            "proofs.p-150-device.status": "available",
            "proofs.p-151-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Races
# ---------------------------------------------------------------------------




def case_same_type_rule():
    """Two *distinct* channels of the same type are still rejected.

    ``h1-human`` and ``h2-human`` are human proofs from two different channels
    with two different verifiers, both live and both in-window.  Nothing else
    is wrong with them (different ids, different channels, different issuers),
    so the only reason they cannot recover is the distinct-channel-type rule.
    The admin proof joins later (its window starts at 600); once it is valid
    the smallest legal pair is ``(h1-human, z-admin)``, which also shows the
    human proofs were otherwise eligible.
    """
    tag = "sametype"
    prof = PROFILE
    proofs = [
        proof("h1-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h1"),
        proof("h2-human", "att-1", "acct-1", 1, prof, f"{tag}-h2", "human", 1, 100, 900, "v-h2"),
        proof("z-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 600, 900, "v-a"),
    ]
    operations = [
        # at 500 only the two human proofs are usable -> no pair (E506)
        {"remote_id": "op-preview-early", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        # at 700 the admin proof is live; the smallest legal pair skips h2
        {"remote_id": "op-preview-late", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 700},
        synth.recovery_request("req-1", "acct-1", "att-1", at=700),
    ]
    expect = {
        "outcomes": [
            # two human proofs from two channels and two verifiers: same type
            {"op": 0, "status": "none", "code": "E506", "reasons": [None, None, "E210"], "pair_codes": ["E208"]},
            {"op": 1, "status": "ok", "candidate": ["h1-human", "z-admin"]},
            {"op": 2, "status": "committed", "proofs": ["h1-human", "z-admin"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 2,
            "proofs.h1-human.status": "consumed",
            "proofs.h2-human.status": "available",
            "proofs.z-admin.status": "consumed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag) + [synth.channel(f"{tag}-h2", "human")],
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_preconsumed_proof():
    """A proof already consumed by an earlier recovery is not reusable.

    ``old-human`` and ``old-device`` were consumed by a previous recovery of a
    *closed* attempt; a new attempt at the current generation presents them as
    a seemingly valid pair.  Both must be rejected as consumed (E206), and the
    attempt's own fresh proofs must be the ones chosen.
    """
    tag = "preconsumed"
    prof = PROFILE
    proofs = [
        proof(
            "a-old-human",
            "att-old",
            "acct-1",
            1,
            prof,
            f"{tag}-h",
            "human",
            1,
            100,
            3000,
            "v-h",
            status="consumed",
            consumed_by="att-old",
            consumed_at=150,
        ),
        proof(
            "b-old-device",
            "att-old",
            "acct-1",
            1,
            prof,
            f"{tag}-d",
            "device",
            1,
            100,
            3000,
            "v-d",
            status="consumed",
            consumed_by="att-old",
            consumed_at=150,
        ),
        proof("c-new-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 3000, "v-h2"),
        proof("d-new-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d2"),
    ]
    operations = [
        {"remote_id": "op-preview-old", "op": "preview", "account_id": "acct-1", "attempt_id": "att-old", "at": 500},
        {"remote_id": "op-preview-new", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    attempts = [
        synth.attempt("att-old", "acct-1", 1, prof, 100, 3000, status="closed"),
        synth.attempt("att-1", "acct-1", 1, prof, 100, 3000),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "unavailable", "code": "E504"},
            {"op": 1, "status": "ok", "candidate": ["c-new-human", "d-new-device"]},
            {"op": 2, "status": "committed", "proofs": ["c-new-human", "d-new-device"]},
        ],
        "final": {
            "proofs.a-old-human": {"status": "consumed", "consumed_by": "att-old"},
            "proofs.b-old-device": {"status": "consumed", "consumed_by": "att-old"},
            "proofs.c-new-human.status": "consumed",
            "proofs.d-new-device.status": "consumed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


def case_consumed_proofs_block_pair():
    """The only candidate pair is consumed, so the attempt cannot recover."""
    tag = "blockedpair"
    prof = PROFILE
    proofs = [
        proof(
            "e-human",
            "att-1",
            "acct-1",
            1,
            prof,
            f"{tag}-h",
            "human",
            1,
            100,
            3000,
            "v-h",
            status="consumed",
            consumed_by="att-other",
            consumed_at=120,
        ),
        proof("f-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d"),
    ]
    operations = [
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E506", "reasons": ["E206", None]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
            "proofs.f-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        proofs,
        [],
        operations,
        expect,
    )


def case_two_devices_only_rule():
    """A device + admin pair is legal; device + device is not, even with
    different channels, different issuers and both live."""
    tag = "twodevices"
    prof = PROFILE
    proofs = [
        proof("d1-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 3000, "v-d1"),
        proof("d2-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 3000, "v-d2"),
        proof("z-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 900, 950, "v-a"),
    ]
    operations = [
        {"remote_id": "op-preview-early", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        {"remote_id": "op-preview-late", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 910},
        synth.recovery_request("req-1", "acct-1", "att-1", at=910),
    ]
    expect = {
        "outcomes": [
            # two devices break two rules at once: same type and no
            # human/admin proof.  Both are reported, in priority order.
            {"op": 0, "status": "none", "code": "E506", "pair_codes": ["E208", "E209"]},
            {"op": 1, "status": "ok", "candidate": ["d1-device", "z-admin"]},
            {"op": 2, "status": "committed", "proofs": ["d1-device", "z-admin"]},
        ],
        "final": {
            "proofs.d2-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 3000)],
        proofs,
        [],
        operations,
        expect,
    )


def case_pair_level_violations():
    """Read-only probe of every pair-level rule through ``pair_codes``.

    All three proofs are devices, so every possible pair lacks a human/admin
    proof (E209) and every pair is same-type (E208); additionally two of the
    three share one channel (E207) and one pair shares one verifier (E203), so
    the union of all violated rules across all pairs is reported.
    """
    tag = "paircodes"
    prof = PROFILE
    proofs = [
        proof("a-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-a"),
        proof("b-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-b"),
        proof("c-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 900, "v-a"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
    ]
    expect = {
        "outcomes": [
            # a/b share the channel, a/c share the verifier, all are devices
            {
                "op": 0,
                "status": "none",
                "code": "E506",
                "pair_codes": ["E207", "E208", "E203", "E209"],
            },
        ],
        "final": {
            # a preview is read-only: nothing is consumed and no receipt exists
            "accounts.acct-1.account_gen": 1,
            "proofs.a-device.status": "available",
            "proofs.b-device.status": "available",
            "proofs.c-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_attempt_start_boundary():
    """The attempt's ``created_at`` is inclusive."""
    tag = "startbound"
    prof = PROFILE
    proofs = [
        proof("s1-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("s2-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    operations = [
        {"remote_id": "op-before", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 299},
        {"remote_id": "op-at", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 300},
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "unavailable", "code": "E213"},
            {"op": 1, "status": "ok", "candidate": ["s1-human", "s2-device"]},
        ],
        "final": {
            # both operations are previews, so nothing was consumed
            "accounts.acct-1.account_gen": 1,
            "attempts.att-1.status": "open",
            "proofs.s1-human.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 300, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_attempt_other_account():
    """A proof naming another account is refused by the binding rule."""
    tag = "otheracct"
    prof = PROFILE
    proofs = [
        proof("o1-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("o2-device", "att-1", "acct-2", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
    ]
    operations = [
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E506", "reasons": [None, "E205"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 1,
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account("acct-1"), base_account("acct-2")],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_wrong_attempt_binding():
    """A proof bound to another attempt never enters this attempt's pool.

    ``orphan`` lives in the seed (the tenant knows it) but is bound to
    ``att-2``.  A recovery of ``att-1`` must not see it at all: the pool is
    selected by binding, not by id.  Only ``att-2`` can use it, and there the
    human/device pair is complete.
    """
    tag = "wrongatt"
    prof = PROFILE
    proofs = [
        proof("k1-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("k2-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        proof("orphan-admin", "att-2", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a"),
        proof("k3-device", "att-2", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 900, "v-d2"),
    ]
    attempts = [
        synth.attempt("att-1", "acct-1", 1, prof, 100, 900),
        synth.attempt("att-2", "acct-1", 1, prof, 100, 900),
    ]
    operations = [
        {"remote_id": "op-att1-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
        {"remote_id": "op-att2-preview", "op": "preview", "account_id": "acct-2", "attempt_id": "att-2", "at": 500},
    ]
    expect = {
        "outcomes": [
            # the orphan admin proof is not part of att-1's pool
            {"op": 0, "status": "ok", "candidate": ["k1-human", "k2-device"]},
            {"op": 1, "status": "committed", "proofs": ["k1-human", "k2-device"]},
            # a wrong account id makes the preview refuse (routing, not binding)
            {"op": 2, "status": "unavailable", "code": "E201"},
        ],
        "final": {
            "proofs.orphan-admin.status": "available",
            "attempts.att-2.status": "closed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        attempts,
        proofs,
        [],
        operations,
        expect,
    )


def case_stale_generation_attempt():
    """An attempt opened at an older account generation cannot recover."""
    tag = "stalegen"
    prof = PROFILE
    proofs = [
        proof("g1-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("g2-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        # a live attempt at the current generation, used as a control
        proof("g3-human", "att-2", "acct-1", 3, prof, f"{tag}-h", "human", 1, 100, 900, "v-h2"),
        proof("g4-admin", "att-2", "acct-1", 3, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a2"),
    ]
    operations = [
        synth.recovery_request("req-stale", "acct-1", "att-1", at=500),
        synth.recovery_request("req-live", "acct-1", "att-2", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "rejected", "code": "E503"},
            {"op": 1, "status": "committed", "account_gen": 4, "proofs": ["g3-human", "g4-admin"]},
        ],
        "final": {
            "accounts.acct-1.account_gen": 4,
            "attempts.att-1.status": "open",
            "attempts.att-2.status": "closed",
            # the stale attempt's proofs are untouched
            "proofs.g1-human.status": "available",
            "proofs.g2-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account("acct-1", gen=3)],
        [
            synth.attempt("att-1", "acct-1", 1, prof, 100, 900),
            synth.attempt("att-2", "acct-1", 3, prof, 100, 900),
        ],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Case 11/12: the lexicographically smallest valid pair wins
# ---------------------------------------------------------------------------


def case_lexicographic():
    """The smallest valid pair is not the first two usable proofs.

    Sorted by proof id the usable proofs are

        a-human   (human,  issuer v-h)
        b-device  (device, issuer v-h)   <- same signer as a-human
        k-admin   (admin,  issuer v-a)
        m-device  (device, issuer v-d)

    ``(a-human, b-device)`` is forbidden (same verifier), so the smallest
    legal pair is ``(a-human, k-admin)`` -- not the admin/device pair that a
    greedy "pair the first acceptable channel types" strategy would choose.
    The proofs are also loaded in scrambled order to prove that storage order
    is irrelevant.
    """
    tag = "lexi"
    prof = PROFILE
    proofs = [
        proof("m-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        proof("k-admin", "att-1", "acct-1", 1, prof, f"{tag}-a", "admin", 1, 100, 900, "v-a"),
        proof("a-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("b-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 900, "v-h"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {"op": 0, "status": "ok", "candidate": ["a-human", "k-admin"]},
            {"op": 1, "status": "committed", "proofs": ["a-human", "k-admin"]},
        ],
        "final": {
            "proofs.a-human.status": "consumed",
            "proofs.k-admin.status": "consumed",
            "proofs.b-device.status": "available",
            "proofs.m-device.status": "available",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


def case_numeric_ids():
    """Proof ids compare as strings, not as numbers.

    ``"p-10-device"`` sorts before ``"p-9-human"`` because ``"1" < "9"``, so
    the reported pair is ``["p-10-device", "p-9-human"]`` even though a
    numeric reading of the ids would reverse it.  The third proof ``p-1-device``
    is expired, which also pins the order of the per-proof reasons list.
    """
    tag = "numids"
    prof = PROFILE
    proofs = [
        proof("p-9-human", "att-1", "acct-1", 1, prof, f"{tag}-h", "human", 1, 100, 900, "v-h"),
        proof("p-10-device", "att-1", "acct-1", 1, prof, f"{tag}-d", "device", 1, 100, 900, "v-d"),
        proof("p-1-device", "att-1", "acct-1", 1, prof, f"{tag}-d2", "device", 1, 100, 400, "v-d2"),
    ]
    operations = [
        {"remote_id": "op-preview", "op": "preview", "account_id": "acct-1", "attempt_id": "att-1", "at": 500},
        synth.recovery_request("req-1", "acct-1", "att-1", at=500),
    ]
    expect = {
        "outcomes": [
            {
                "op": 0,
                "status": "ok",
                "candidate": ["p-10-device", "p-9-human"],
                "reasons": ["E204", None, None],
            },
            {"op": 1, "status": "committed", "proofs": ["p-10-device", "p-9-human"]},
        ],
        "final": {
            "proofs.p-1-device.status": "available",
            "proofs.p-10-device.status": "consumed",
            "proofs.p-9-human.status": "consumed",
        },
    }
    return synth.case(
        tag,
        f"tenant-{tag}",
        "acct-1",
        0,
        channels(tag),
        [base_account()],
        [synth.attempt("att-1", "acct-1", 1, prof, 100, 900)],
        proofs,
        [],
        operations,
        expect,
    )


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------


def build_cases() -> list:
    """All single-process cases, in a stable order."""
    return [
        case_happy(),
        case_protocol_errors(),
        case_pair_rules(),
        case_device_only_pair(),
        case_same_signer_only(),
        case_boundaries(),
        case_channel_lifecycle(),
        case_new_generation_proof(),
        case_binding(),
        case_routing_errors(),
        case_second_recovery(),
        case_fixed_failure(),
        case_tenant_scope(),
        case_tenant_scope_b(),
        case_admin_device(),
        case_recovery_after_failed_pair(),
        case_same_type_rule(),
        case_lexicographic(),
        case_numeric_ids(),
        case_preconsumed_proof(),
        case_consumed_proofs_block_pair(),
        case_two_devices_only_rule(),
        case_pair_level_violations(),
        case_attempt_start_boundary(),
        case_attempt_other_account(),
        case_stale_generation_attempt(),
        case_wrong_attempt_binding(),
    ]


def build_document() -> dict:
    from tools.races import build_races

    return {
        "schema": "recovery-cases/1",
        "description": (
            "Synthetic-credential account recovery: single-process cases and "
            "sync-point-ordered two-process races. All ids, keys and profiles "
            "are invented; no real credential is used anywhere."
        ),
        "cases": build_cases(),
        "races": build_races(),
    }



def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write("usage: python tools/gen_cases.py cases.json\n")
        return 2
    document = build_document()
    with open(argv[0], "w", encoding="utf-8", newline="\n") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")
    print(f"wrote {argv[0]}: {len(document['cases'])} cases, {len(document['races'])} races")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
