"""Unit tests: pure rules, with expectations stated directly.

These tests do not go through a case file, and each expected value is spelled
out in the assertion rather than read from the implementation.
"""

from __future__ import annotations

import unittest

from tests.helpers import PROFILE, DatabaseCase

from solution import db
from solution.engine import (
    Diagnosis,
    Evaluation,
    evaluate,
    pair_rule,
    select_pair,
)
from solution.errors import (
    E_ACCOUNT_FROZEN,
    E_ACCOUNT_GEN_STALE,
    E_ATTEMPT_CLOSED,
    E_ATTEMPT_EXPIRED,
    E_ATTEMPT_NOT_YET_ACTIVE,
    E_ATTEMPT_SUPERSEDED,
    E_BAD_SIGNATURE,
    E_BINDING,
    E_CHANNEL_GEN_STALE,
    E_CHANNEL_GEN_UNKNOWN,
    E_CHANNEL_REVOKED,
    E_NO_STRONG_CHANNEL,
    E_PROOF_CONSUMED,
    E_PROOF_EXPIRED,
    E_PROOF_NOT_YET_VALID,
    E_SAME_CHANNEL,
    E_SAME_CHANNEL_TYPE,
    E_SAME_SIGNER,
    E_UNKNOWN_CHANNEL,
)
from solution.model import (
    attempt_digest,
    canonical_json,
    profile_digest,
    recovery_digest,
)
from tools import synth


def _state(**kwargs) -> db.State:
    return db.State(rev=0, **kwargs)


def _channel(channel_id: str, kind: str) -> db.ChannelView:
    return db.ChannelView(id=channel_id, type=kind)


def _proof(proof_id: str, **overrides) -> db.ProofView:
    values = {
        "id": proof_id,
        "attempt_id": "att-1",
        "account_id": "acct-1",
        "account_gen": 1,
        "profile_digest": profile_digest(PROFILE),
        "channel_id": "ch-human",
        "channel_type": "human",
        "channel_gen": 1,
        "not_before": 100,
        "not_after": 900,
        "issuer": "verifier-1",
        "signature": "",
        "status": "available",
        "consumed_by": None,
        "consumed_at": None,
    }
    values.update(overrides)
    return db.ProofView(**values)


def _attempt(**overrides) -> db.AttemptView:
    values = {
        "id": "att-1",
        "account_id": "acct-1",
        "account_gen": 1,
        "profile": canonical_json(PROFILE),
        "profile_digest": profile_digest(PROFILE),
        "created_at": 100,
        "expires_at": 900,
        "status": "open",
        "closed_by": None,
    }
    values.update(overrides)
    return db.AttemptView(**values)


def _account(**overrides) -> db.AccountView:
    values = {"id": "acct-1", "account_gen": 1, "status": "active"}
    values.update(overrides)
    return db.AccountView(**values)


class CanonicalEncodingTests(unittest.TestCase):
    def test_sorted_keys_without_whitespace(self):
        self.assertEqual(canonical_json({"b": 1, "a": [1, 2]}), '{"a":[1,2],"b":1}')

    def test_utf8_is_not_escaped(self):
        self.assertEqual(canonical_json({"k": "é"}), '{"k":"é"}')

    def test_profile_digest_is_sha256_of_canonical_form(self):
        import hashlib

        expected = hashlib.sha256(b'{"a":1,"b":"x"}').hexdigest()
        self.assertEqual(profile_digest({"b": "x", "a": 1}), expected)

    def test_attempt_digest_covers_every_field(self):
        base = dict(tenant="t", account_id="a", attempt_id="at", account_gen=1, profile_digest_="00")
        self.assertNotEqual(attempt_digest(**base), attempt_digest(**{**base, "account_gen": 2}))
        self.assertNotEqual(attempt_digest(**base), attempt_digest(**{**base, "tenant": "t2"}))

    def test_recovery_digest_is_order_sensitive(self):
        base = dict(
            tenant="t",
            account_id="a",
            account_gen=2,
            attempt_id="at",
            attempt_digest_="d",
            proof_a="p1",
            proof_b="p2",
            profile_digest_="f",
        )
        self.assertNotEqual(recovery_digest(**base), recovery_digest(**{**base, "proof_a": "p2", "proof_b": "p1"}))

    def test_hmac_rule_matches_independent_synth(self):
        payload = {"id": "x", "channel_id": "c", "kind": "rotate", "channel_gen": 2, "at": 5}
        import hashlib
        import hmac

        expected = hmac.new(synth.KEY, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(synth.hmac_hex(payload), expected)


class ChannelGenerationTests(unittest.TestCase):
    def test_default_generation_is_one(self):
        state = _state(channels={"c": _channel("c", "human")})
        self.assertEqual(state.channel_state("c"), (1, None))

    def test_rotation_advances_the_generation(self):
        state = _state(
            channels={"c": _channel("c", "human")},
            events={"e": db.EventView(id="e", channel_id="c", kind="rotate", channel_gen=2, at=10)},
        )
        self.assertEqual(state.channel_state("c"), (2, None))

    def test_revocation_reports_the_generation_and_time(self):
        state = _state(
            channels={"c": _channel("c", "human")},
            events={"e": db.EventView(id="e", channel_id="c", kind="revoke", channel_gen=1, at=7)},
        )
        self.assertEqual(state.channel_state("c"), (1, 7))

    def test_events_are_applied_in_time_order_not_id_order(self):
        state = _state(
            channels={"c": _channel("c", "human")},
            events={
                "z-first": db.EventView(id="z-first", channel_id="c", kind="rotate", channel_gen=2, at=10),
                "a-second": db.EventView(id="a-second", channel_id="c", kind="rotate", channel_gen=3, at=20),
                "m-last": db.EventView(id="m-last", channel_id="c", kind="revoke", channel_gen=3, at=30),
            },
        )
        self.assertEqual(state.channel_state("c"), (3, 30))


class PairRuleTests(unittest.TestCase):
    def test_human_and_device_pair(self):
        self.assertIsNone(pair_rule(_proof("a", channel_id="c1"), _proof("b", **{"channel_id": "c2", "channel_type": "device", "issuer": "v2"})))

    def test_admin_and_device_pair(self):
        admin = _proof("a", channel_id="c1", channel_type="admin")
        device = _proof("b", channel_id="c2", channel_type="device", issuer="v2")
        self.assertIsNone(pair_rule(admin, device))

    def test_two_devices_are_rejected(self):
        first = _proof("a", channel_id="c1", channel_type="device")
        second = _proof("b", channel_id="c2", channel_type="device", issuer="v2")
        # same type is reported first; both rules independently forbid the pair
        self.assertEqual(pair_rule(first, second), E_SAME_CHANNEL_TYPE)

    def test_human_and_admin_are_allowed(self):
        first = _proof("a", channel_id="c1", channel_type="human")
        second = _proof("b", channel_id="c2", channel_type="admin", issuer="v2")
        self.assertIsNone(pair_rule(first, second))

    def test_same_type_is_rejected_even_for_different_channels(self):
        first = _proof("a", channel_id="c1", channel_type="human")
        second = _proof("b", channel_id="c2", channel_type="human", issuer="v2")
        self.assertEqual(pair_rule(first, second), E_SAME_CHANNEL_TYPE)

    def test_same_channel_is_rejected(self):
        first = _proof("a", channel_id="c1")
        second = _proof("b", channel_id="c1", channel_type="device", issuer="v2")
        self.assertEqual(pair_rule(first, second), E_SAME_CHANNEL)

    def test_same_verifier_is_rejected(self):
        first = _proof("a", channel_id="c1")
        second = _proof("b", channel_id="c2", channel_type="device")
        self.assertEqual(pair_rule(first, second), E_SAME_SIGNER)


class PairSelectionTests(unittest.TestCase):
    def _diagnoses(self, *proofs):
        return [Diagnosis(proof=proof) for proof in proofs]

    def test_smallest_pair_by_id_is_chosen(self):
        proofs = [
            _proof("a-human"),
            _proof("m-device", channel_id="c2", channel_type="device", issuer="v2"),
            _proof("z-admin", channel_id="c3", channel_type="admin", issuer="v3"),
        ]
        pair = select_pair(self._diagnoses(*proofs))
        self.assertEqual([item.id for item in pair], ["a-human", "m-device"])

    def test_input_order_is_irrelevant(self):
        proofs = [
            _proof("z-admin", channel_id="c3", channel_type="admin", issuer="v3"),
            _proof("m-device", channel_id="c2", channel_type="device", issuer="v2"),
            _proof("a-human"),
        ]
        pair = select_pair(self._diagnoses(*proofs))
        self.assertEqual([item.id for item in pair], ["a-human", "m-device"])

    def test_ids_compare_as_strings(self):
        proofs = [
            _proof("p-9-human"),
            _proof("p-10-device", channel_id="c2", channel_type="device", issuer="v2"),
        ]
        pair = select_pair(self._diagnoses(*proofs))
        self.assertEqual([item.id for item in pair], ["p-10-device", "p-9-human"])

    def test_ineligible_proofs_are_skipped_not_fatal(self):
        proofs = [
            _proof("a-human", channel_id="c1"),
            _proof("b-device", channel_id="c2", channel_type="device", issuer="v2"),
            _proof("c-device-dead", channel_id="c3", channel_type="device", issuer="v3"),
        ]
        diagnoses = self._diagnoses(*proofs)
        diagnoses[2].code = E_PROOF_EXPIRED
        pair = select_pair(diagnoses)
        self.assertEqual([item.id for item in pair], ["a-human", "b-device"])

    def test_no_pair_returns_none(self):
        proofs = [
            _proof("a-device", channel_id="c1", channel_type="device"),
            _proof("b-device", channel_id="c2", channel_type="device", issuer="v2"),
        ]
        self.assertIsNone(select_pair(self._diagnoses(*proofs)))


class ProofEligibilityTests(DatabaseCase):
    """Each rule is exercised through ``evaluate`` with a hand-built state."""

    def setUp(self):
        super().setUp()
        self.key = synth.KEY

    def _state_with(self, proof, **state_kwargs):
        # ``signature`` is honoured when the caller supplies one, so a bad
        # signature can be exercised; otherwise the record is signed here.
        signature = proof.get("signature") or synth.proof_signature_for(proof)
        proof = {**proof, "signature": signature}
        view = db.ProofView(
            id=proof["id"],
            attempt_id=proof["attempt_id"],
            account_id=proof["account_id"],
            account_gen=proof["account_gen"],
            profile_digest=proof["profile_digest"],
            channel_id=proof["channel_id"],
            channel_type=proof["channel_type"],
            channel_gen=proof["channel_gen"],
            not_before=proof["not_before"],
            not_after=proof["not_after"],
            issuer=proof["issuer"],
            signature=signature,
            status=proof.get("status", "available"),
            consumed_by=proof.get("consumed_by"),
            consumed_at=proof.get("consumed_at"),
        )
        channels = {"ch-human": _channel("ch-human", "human"), "ch-device": _channel("ch-device", "device")}
        return _state(
            channels={**channels, **state_kwargs.pop("channels", {})},
            accounts=state_kwargs.pop("accounts", {"acct-1": _account()}),
            attempts=state_kwargs.pop("attempts", {"att-1": _attempt()}),
            proofs={view.id: view},
            events=state_kwargs.pop("events", {}),
        )

    def _signed(self, **overrides):
        base = dict(
            id="p-1",
            attempt_id="att-1",
            account_id="acct-1",
            account_gen=1,
            profile_digest=profile_digest(PROFILE),
            channel_id="ch-human",
            channel_type="human",
            channel_gen=1,
            not_before=100,
            not_after=900,
            issuer="verifier-1",
        )
        base.update(overrides)
        return {**base, "signature": synth.proof_signature_for(base)}

    def _diagnose(self, proof_dict, at=500, **state_kwargs):
        state = self._state_with(proof_dict, **state_kwargs)
        view = next(iter(state.proofs.values()))
        from solution.engine import _proof_diagnosis

        attempt = state.attempts["att-1"]
        return _proof_diagnosis(state, view, attempt, at, self.key)

    def test_clean_proof_has_no_problem(self):
        self.assertIsNone(self._diagnose(self._signed()).code)

    def test_consumed_proof(self):
        proof = self._signed()
        proof["status"] = "consumed"
        proof["consumed_by"] = "att-0"
        proof["consumed_at"] = 120
        self.assertEqual(self._diagnose(proof).code, E_PROOF_CONSUMED)

    def test_bad_signature(self):
        proof = self._signed()
        proof["signature"] = "0" * 64
        self.assertEqual(self._diagnose(proof).code, E_BAD_SIGNATURE)

    def test_wrong_attempt_binding(self):
        # pool selection normally hides such a proof; the check is defence in
        # depth for callers that hand a proof over directly
        self.assertEqual(self._diagnose(self._signed(attempt_id="att-2")).code, E_BINDING)

    def test_wrong_account_binding(self):
        self.assertEqual(self._diagnose(self._signed(account_id="acct-2")).code, E_BINDING)

    def test_wrong_generation_binding(self):
        self.assertEqual(self._diagnose(self._signed(account_gen=2)).code, E_BINDING)

    def test_wrong_profile_digest(self):
        self.assertEqual(
            self._diagnose(self._signed(profile_digest=profile_digest({"x": 1}))).code, E_BINDING
        )

    def test_unknown_channel(self):
        self.assertEqual(self._diagnose(self._signed(channel_id="ch-missing")).code, E_UNKNOWN_CHANNEL)

    def test_not_yet_valid_boundary(self):
        self.assertIsNone(self._diagnose(self._signed(), at=100).code)
        self.assertEqual(self._diagnose(self._signed(), at=99).code, E_PROOF_NOT_YET_VALID)

    def test_expiry_boundary(self):
        self.assertIsNone(self._diagnose(self._signed(), at=900).code)
        self.assertEqual(self._diagnose(self._signed(), at=901).code, E_PROOF_EXPIRED)

    def test_generation_ahead_of_channel(self):
        self.assertEqual(self._diagnose(self._signed(channel_gen=2)).code, E_CHANNEL_GEN_UNKNOWN)

    def test_stale_channel_generation(self):
        rotated = db.EventView(id="e", channel_id="ch-human", kind="rotate", channel_gen=2, at=10)
        self.assertEqual(self._diagnose(self._signed(), events={"e": rotated}).code, E_CHANNEL_GEN_STALE)

    def test_revoked_channel(self):
        revoked = db.EventView(id="e", channel_id="ch-human", kind="revoke", channel_gen=1, at=10)
        self.assertEqual(self._diagnose(self._signed(), events={"e": revoked}).code, E_CHANNEL_REVOKED)

    def test_revocation_beats_generation_staleness(self):
        events = {
            "r": db.EventView(id="r", channel_id="ch-human", kind="rotate", channel_gen=2, at=10),
            "v": db.EventView(id="v", channel_id="ch-human", kind="revoke", channel_gen=2, at=20),
        }
        self.assertEqual(self._diagnose(self._signed(channel_gen=1), events=events).code, E_CHANNEL_REVOKED)


class AttemptBlockerTests(unittest.TestCase):
    def test_attempt_window_is_inclusive(self):
        attempt = _attempt(created_at=100, expires_at=900)
        state = _state(accounts={"acct-1": _account()}, attempts={"att-1": attempt})
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=99, key=b"k").blocker.code, E_ATTEMPT_NOT_YET_ACTIVE)
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=901, key=b"k").blocker.code, E_ATTEMPT_EXPIRED)

    def test_frozen_account(self):
        state = _state(accounts={"acct-1": _account(status="frozen")}, attempts={"att-1": _attempt()})
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k").blocker.code, E_ACCOUNT_FROZEN)

    def test_stale_account_generation(self):
        state = _state(
            accounts={"acct-1": _account(account_gen=2)},
            attempts={"att-1": _attempt(account_gen=1)},
        )
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k").blocker.code, E_ACCOUNT_GEN_STALE)

    def test_closed_attempt(self):
        state = _state(
            accounts={"acct-1": _account()},
            attempts={"att-1": _attempt(status="closed", closed_by="admin")},
        )
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k").blocker.code, E_ATTEMPT_CLOSED)

    def test_attempt_at_an_older_generation_is_blocked(self):
        state = _state(
            accounts={"acct-1": _account(account_gen=3)},
            attempts={"att-1": _attempt(account_gen=1)},
        )
        result = evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k")
        self.assertEqual(result.blocker.code, E_ACCOUNT_GEN_STALE)

    def test_attempt_closed_by_recovery_is_superseded(self):
        state = _state(
            accounts={"acct-1": _account()},
            attempts={"att-1": _attempt(status="closed", closed_by="recovery:abc")},
        )
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k").blocker.code, E_ATTEMPT_SUPERSEDED)

    def test_recovery_at_this_generation_supersedes(self):
        row = db.RecoveryView(
            account_gen=2,
            account_id="acct-1",
            attempt_id="att-1",
            proof_a="p1",
            proof_b="p2",
            attempt_digest="d",
            profile_digest="f",
            recovery_digest="r",
            at=400,
            request_tenant="t",
            request_id="req",
            request_at=400,
        )
        state = _state(
            accounts={"acct-1": _account()},
            attempts={"att-1": _attempt()},
            recoveries={2: row},
        )
        self.assertEqual(evaluate(state, account_id="acct-1", attempt_id="att-1", at=500, key=b"k").blocker.code, E_ATTEMPT_SUPERSEDED)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
