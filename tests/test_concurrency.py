"""Tests for the multi-process harness itself.

These tests start *real* independent Python processes through
``solution.worker``, order them with sync points and, where required, kill the
processes that this test started.  No other process is ever signalled.

They deliberately assert on the harness mechanism (arrival markers, kill
semantics, WAL isolation) as well as on the protocol outcome, because a
harness that silently degrades into "run them one after another" would make
the race scenarios meaningless.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest

from tests.helpers import (
    PROFILE,
    ROOT,
    DatabaseCase,
    case,
    recovery,
    standard_attempt,
    standard_proofs,
)
from tools import synth

from solution import db
from solution.model import parse_case
from solution.runner import execute_race
from solution.syncpoints import SyncDir


def race_case(case_id, tenant, proof_list, attempt_list, channel_list, events=None):
    return synth.case(case_id, tenant, "acct-1", 0, channel_list, [synth.account("acct-1", 1)], attempt_list, proof_list, events or [], [], {})


def two_channel_race_case(tenant: str) -> dict:
    return race_case(
        tenant,
        tenant,
        standard_proofs(tenant),
        [standard_attempt()],
        [synth.channel(f"{tenant}-h", "human"), synth.channel(f"{tenant}-d", "device")],
    )


class SyncPointTests(DatabaseCase):
    def test_arrival_and_release_are_observed(self):
        from solution.syncpoints import FileSync

        directory = self.path("sync")
        os.makedirs(directory)
        token = "tok"
        sink = FileSync(directory, token, timeout=5.0, park=["p1"])
        controller = SyncDir(directory, timeout=5.0)
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import sys; sys.path.insert(0, r'%s');"
                    "from solution.syncpoints import FileSync;"
                    "FileSync(r'%s', %r, timeout=5.0, park=['p1']).hit('p1');"
                    "print('resumed')"
                )
                % (ROOT, directory, token)
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            controller.wait("p1", token, timeout=10)
            out, err = process.communicate(timeout=0.1) if False else ("", "")
            self.assertIsNone(process.poll(), "the worker must still be parked before release")
            controller.release("p1", token)
            out, err = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, err)
            self.assertIn("resumed", out)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_parking_is_opt_in(self):
        from solution.syncpoints import FileSync

        directory = self.path("sync2")
        os.makedirs(directory)
        # park=["other"] means a hit on "p1" must not block
        sink = FileSync(directory, "tok2", timeout=0.2, park=["other"])
        started = time.monotonic()
        sink.hit("p1")
        self.assertLess(time.monotonic() - started, 0.15)
        self.assertIn("p1", sink.hits)
        self.assertEqual(sink.parked, [])

    def test_unreleased_park_times_out(self):
        from solution.syncpoints import FileSync

        directory = self.path("sync3")
        os.makedirs(directory)
        sink = FileSync(directory, "tok3", timeout=0.1, park=["p1"])
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            sink.hit("p1")
        self.assertLess(time.monotonic() - started, 5.0)


class RaceExecutionTests(DatabaseCase):
    def test_revocation_wins_and_the_loser_re_reads(self):
        tenant = "race-inline-revoke"
        race = {
            "race_id": "inline-revoke",
            "case": two_channel_race_case(tenant),
            "steps": [
                {"start": "W1", "request": recovery("req-w1", at=500), "park": ["recovery.before_lock"]},
                {"at": "W1", "point": "recovery.before_lock"},
                {"start": "W2", "request": synth.lifecycle_request("lif-w2", "revoke_channel", f"{tenant}-d", 1, 450)},
                {"exit": "W2"},
                {"release": "W1", "point": "recovery.before_lock"},
                {"exit": "W1"},
            ],
            "expect": {
                "workers": [
                    {"name": "W2", "envelope.receipt.status": "committed"},
                    {"name": "W1", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E506"},
                ],
                "final": {"accounts.acct-1.account_gen": 1, "attempts.att-1.status": "open"},
            },
        }
        outcome = execute_race(race, 0, self.workdir)
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(outcome["problems"], [])

    def test_kill_after_consume_rolls_everything_back(self):
        tenant = "race-inline-kill"
        race = {
            "race_id": "inline-kill",
            "case": two_channel_race_case(tenant),
            "steps": [
                {"snapshot": "before"},
                {"start": "W1", "request": recovery("req-kill", at=500), "park": ["recovery.after_write"]},
                {"at": "W1", "point": "recovery.after_write"},
                {"kill": "W1"},
                {"expect_dead": "W1"},
                {"snapshot": "after-kill"},
                {"no_snapshot_change": ["before", "after-kill"]},
                {"start": "W2", "request": recovery("req-kill", at=500)},
                {"exit": "W2"},
            ],
            "expect": {
                "workers": [
                    {"name": "W1", "killed": True},
                    {"name": "W2", "envelope.receipt.status": "committed", "envelope.replayed": False},
                ],
                "final": {"accounts.acct-1.account_gen": 2},
            },
        }
        outcome = execute_race(race, 0, self.workdir)
        self.assertEqual(outcome["problems"], [])

    def test_kill_after_commit_keeps_the_receipt(self):
        tenant = "race-inline-kill2"
        race = {
            "race_id": "inline-kill2",
            "case": two_channel_race_case(tenant),
            "steps": [
                {"start": "W1", "request": recovery("req-kill", at=500), "park": ["recovery.after_commit"]},
                {"at": "W1", "point": "recovery.after_commit"},
                {"kill": "W1"},
                {"expect_dead": "W1"},
                {"snapshot": "after-kill"},
                {"start": "W2", "request": recovery("req-kill", at=500)},
                {"exit": "W2"},
                {"snapshot": "final"},
                {"no_snapshot_change": ["after-kill", "final"]},
            ],
            "expect": {
                "workers": [
                    {"name": "W1", "killed": True},
                    {"name": "W2", "envelope.receipt.status": "committed", "envelope.replayed": True},
                ],
                "final": {"accounts.acct-1.account_gen": 2},
            },
        }
        outcome = execute_race(race, 0, self.workdir)
        self.assertEqual(outcome["problems"], [])

    def test_only_the_started_process_is_killed(self):
        """A decoy process owned by the test must survive a race's kill step."""
        tenant = "race-inline-bystander"
        decoy = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            race = {
                "race_id": "inline-bystander",
                "case": two_channel_race_case(tenant),
                "steps": [
                    {"start": "W1", "request": recovery("req-1", at=500), "park": ["recovery.before_lock"]},
                    {"at": "W1", "point": "recovery.before_lock"},
                    {"kill": "W1"},
                    {"expect_dead": "W1"},
                ],
                "expect": {"workers": [{"name": "W1", "killed": True}]},
            }
            outcome = execute_race(race, 0, self.workdir)
            self.assertEqual(outcome["problems"], [])
            self.assertIsNone(decoy.poll(), "an unrelated process must never be signalled")
        finally:
            if decoy.poll() is None:
                decoy.kill()
            decoy.communicate()

    def test_killing_a_worker_twice_is_harmless(self):
        tenant = "race-inline-twokill"
        race = {
            "race_id": "inline-twokill",
            "case": two_channel_race_case(tenant),
            "steps": [
                {"start": "W1", "request": recovery("req-1", at=500), "park": ["recovery.before_lock"]},
                {"at": "W1", "point": "recovery.before_lock"},
                {"kill": "W1"},
                {"kill": "W1"},
                {"expect_dead": "W1"},
            ],
            "expect": {"workers": [{"name": "W1", "killed": True}]},
        }
        outcome = execute_race(race, 0, self.workdir)
        self.assertEqual(outcome["problems"], [])

    def test_waiting_on_a_dead_worker_fails_fast(self):
        """A worker that dies before parking must not burn the full timeout."""
        race = {
            "race_id": "dead-worker",
            "case": two_channel_race_case("race-inline-dead"),
            "steps": [
                # a non-object request makes the worker fail before it can
                # reach any engine sync point
                {"start": "W1", "request": ["not", "an", "operation"], "park": ["recovery.before_lock"]},
                {"at": "W1", "point": "recovery.before_lock"},
            ],
            "expect": {},
        }
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            execute_race(race, 0, self.workdir, timeout=30)
        self.assertLess(time.monotonic() - started, 10, "the wait should abort as soon as the worker is gone")

    def test_unknown_verb_is_a_harness_error(self):
        race = {
            "race_id": "bad",
            "case": two_channel_race_case("race-inline-bad"),
            "steps": [{"teleport": "W1"}],
            "expect": {},
        }
        with self.assertRaises(Exception):
            execute_race(race, 0, self.workdir)

    def test_missing_case_is_a_harness_error(self):
        from solution.runner import ScenarioError

        with self.assertRaises(ScenarioError):
            execute_race({"race_id": "nocase", "steps": [{"snapshot": "x"}]}, 0, self.workdir)


class RaceOutcomeTests(DatabaseCase):
    """Semantic checks on what the race leaves behind in the database."""

    def _run(self, race):
        outcome = execute_race(race, 0, self.workdir, timeout=60)
        self.assertEqual(outcome["status"], "ok", outcome.get("message"))
        return outcome

    def test_snapshot_of_the_loser_reflects_no_partial_work(self):
        tenant = "race-loser"
        race = {
            "race_id": "loser",
            "case": two_channel_race_case(tenant),
            "steps": [
                {"start": "W1", "request": recovery("req-1", at=500), "park": ["recovery.before_lock"]},
                {"start": "W2", "request": recovery("req-2", at=500), "park": ["recovery.before_lock"]},
                {"at": "W1", "point": "recovery.before_lock"},
                {"at": "W2", "point": "recovery.before_lock"},
                {"release": "W1", "point": "recovery.before_lock"},
                {"exit": "W1"},
                {"release": "W2", "point": "recovery.before_lock"},
                {"exit": "W2"},
            ],
            "expect": {
                "workers": [
                    {"name": "W1", "envelope.receipt.status": "committed"},
                    # same attempt and same request time: the second worker must
                    # re-read the attempt, find it closed, and reject
                    {"name": "W2", "envelope.receipt.status": "rejected", "envelope.receipt.code": "E505"},
                ],
                "final": {"accounts.acct-1.account_gen": 2},
            },
        }
        outcome = self._run(race)
        self.assertEqual(outcome["problems"], [])
        proofs = outcome["snapshot"]["proofs"]
        self.assertEqual({proof["status"] for proof in proofs.values()}, {"consumed"})
        self.assertEqual({proof["consumed_by"] for proof in proofs.values()}, {"att-1"})

    def test_worker_output_is_one_envelope_per_request(self):
        tenant = "race-envelopes"
        requests = [recovery("req-a", at=500), recovery("req-b", at=600)]
        race = {
            "race_id": "envelopes",
            "case": two_channel_race_case(tenant),
            "steps": [{"start": "W1", "request": requests}, {"exit": "W1"}],
            "expect": {"workers": [{"name": "W1", "envelope_count": 2}]},
        }
        outcome = self._run(race)
        worker = outcome["workers"][0]
        self.assertEqual(len(worker["envelopes"]), 2)
        self.assertEqual(worker["envelopes"][0]["receipt"]["status"], "committed")
        self.assertEqual(worker["envelopes"][1]["receipt"]["status"], "rejected")
        self.assertEqual(outcome["problems"], [])

    def test_worker_crash_is_reported_as_fatal_not_silent(self):
        tenant = "race-fatal"
        race = {
            "race_id": "fatal",
            "case": two_channel_race_case(tenant),
            "steps": [
                # a malformed request makes parse_request raise before any receipt
                {"start": "W1", "request": {"op": "request_recovery", "remote_id": "x"}},
                {"exit": "W1"},
            ],
            "expect": {"workers": [{"name": "W1", "envelope.receipt.code": "E100"}]},
        }
        outcome = self._run(race)
        self.assertEqual(outcome["problems"], [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
