"""Integration tests for the coordinator, run in-process against SQLite."""

from __future__ import annotations

import shutil
import unittest

from tests.helpers import (
    PROFILE,
    DatabaseCase,
    case,
    recovery,
    run_single_case,
    standard_attempt,
    standard_proofs,
)
from tools import synth

from solution import db
from solution.engine import Engine
from solution.errors import (
    E_BAD_RECORD,
    E_BAD_REQUEST,
    E_CHANNEL_REVOKED,
    E_DUPLICATE_ID,
    E_NO_VALID_PAIR,
    E_REQUEST_CONFLICT,
    E_UNKNOWN_ID,
    E_UNKNOWN_OP,
    RecoveryError,
)


def fresh_engine(workdir: str, tenant: str = "tenant-t", now: int = 0) -> Engine:
    conn = db.connect(f"{workdir}/engine.db")
    db.init_db(conn)
    engine = Engine(conn, tenant=tenant, key=synth.KEY, now=now)
    engine.conn = conn
    return engine


class DatabasePersistenceTests(DatabaseCase):
    def test_schema_is_idempotent(self):
        path = self.path("a.db")
        first = db.connect(path)
        db.init_db(first)
        first.close()
        second = db.connect(path)
        db.init_db(second)
        self.assertEqual(db.read_state(second, "t").rev, 0)
        second.close()

    def test_rotation_wal_updates_survive_reopen(self):
        path = self.path("b.db")
        conn = db.connect(path)
        db.init_db(conn)
        conn.close()
        conn = db.connect(path)
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        conn.close()

    def test_seed_tenant_is_idempotent(self):
        from solution.model import parse_case

        case_dict = case(
            "seed",
            "tenant-seed",
            [recovery("req-1")],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-seed"),
        )
        seed = parse_case(case_dict, 0)
        conn = db.connect(self.path("seed.db"))
        db.init_db(conn)
        self.assertTrue(db.seed_tenant(conn, seed, now=0))
        self.assertFalse(db.seed_tenant(conn, seed, now=0))
        state = db.read_state(conn, "tenant-seed")
        self.assertEqual(sorted(state.proofs), ["att-1-device", "att-1-human"])
        conn.close()


class IdempotencyTests(DatabaseCase):
    def test_same_parameters_replay_the_stored_receipt(self):
        engine = fresh_engine(self.workdir)
        engine.conn.close()
        case_dict = case(
            "replay",
            "tenant-replay",
            [recovery("req-1", at=500), recovery("req-1", at=500)],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-replay"),
        )
        result = run_single_case(case_dict, self.workdir)
        self.assertEqual(result["results"][0]["receipt"]["status"], "committed")
        self.assertEqual(result["results"][1]["receipt"], result["results"][0]["receipt"])
        self.assertFalse(result["results"][0]["replayed"])
        self.assertTrue(result["results"][1]["replayed"])

    def test_different_parameters_conflict(self):
        case_dict = case(
            "conflict",
            "tenant-conflict",
            [recovery("req-1", at=500), recovery("req-1", at=501)],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-conflict"),
        )
        result = run_single_case(case_dict, self.workdir)
        self.assertEqual(result["results"][1]["code"], E_REQUEST_CONFLICT)
        self.assertEqual(result["results"][1]["status"], "error")

    def test_business_failure_is_replayed_verbatim(self):
        proofs = standard_proofs("tenant-fail")
        # remove the device proof so the failure has a single cause
        proofs = [proofs[0]]
        case_dict = case(
            "fail-replay",
            "tenant-fail",
            [recovery("req-1", at=500), recovery("req-1", at=500)],
            attempts=[standard_attempt()],
            proofs=proofs,
        )
        result = run_single_case(case_dict, self.workdir)
        first, second = result["results"]
        self.assertEqual(first["status"], "rejected")
        self.assertEqual(first["code"], E_NO_VALID_PAIR)
        self.assertEqual(second["receipt"], first["receipt"])
        self.assertTrue(second["replayed"])

    def test_replay_returns_the_first_result_even_after_the_world_changed(self):
        proofs = standard_proofs("tenant-late")
        # the device proof only becomes valid at t=400
        proofs[1]["not_before"] = 400
        proofs[1]["signature"] = synth.proof_signature_for(proofs[1])
        case_dict = case(
            "late",
            "tenant-late",
            [
                recovery("req-early", at=200),
                recovery("req-late", at=500),
                recovery("req-early", at=200),
            ],
            attempts=[standard_attempt()],
            proofs=proofs,
        )
        result = run_single_case(case_dict, self.workdir)
        early, late, again = result["results"]
        self.assertEqual((early["status"], early["code"]), ("rejected", E_NO_VALID_PAIR))
        self.assertEqual(late["status"], "committed")
        self.assertEqual((again["status"], again["code"]), ("rejected", E_NO_VALID_PAIR))
        self.assertTrue(again["replayed"])

    def test_conflict_leaves_the_stored_receipt_intact(self):
        case_dict = case(
            "conflict-keeps",
            "tenant-conflict-keeps",
            [recovery("req-1", at=500), recovery("req-1", at=600), recovery("req-1", at=500)],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-conflict-keeps"),
        )
        result = run_single_case(case_dict, self.workdir)
        self.assertEqual(result["results"][2]["status"], "committed")
        self.assertTrue(result["results"][2]["replayed"])

    def test_request_ids_are_tenant_scoped(self):
        """The same remote id in two tenants yields two independent receipts."""
        for suffix in ("a", "b"):
            tenant = f"tenant-scope-{suffix}"
            history = self.path(f"tenant-{suffix}.sqlite")
            conn = db.connect(history)
            db.init_db(conn)
            from solution.model import parse_case

            seed = parse_case(
                case(
                    f"scope-{suffix}",
                    tenant,
                    [],
                    attempts=[standard_attempt()],
                    proofs=standard_proofs(tenant),
                ),
                0,
            )
            db.seed_tenant(conn, seed, now=0)
            first = Engine(conn, tenant=tenant, key=synth.KEY, now=0).execute(recovery("req-shared"))
            self.assertEqual(first["receipt"]["status"], "committed")
            self.assertFalse(first["replayed"])
            # a *second* engine on the same tenant sees the stored receipt
            second = Engine(conn, tenant=tenant, key=synth.KEY, now=0).execute(recovery("req-shared"))
            self.assertTrue(second["replayed"])
            conn.close()

    def test_structural_errors_are_not_persisted(self):
        case_dict = case(
            "structural",
            "tenant-structural",
            [{"remote_id": "r1", "op": "request_recovery", "account_id": "acct-1"}],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-structural"),
        )
        result = run_single_case(case_dict, self.workdir)
        self.assertEqual(result["results"][0]["code"], E_BAD_REQUEST)
        self.assertEqual(result["snapshot"]["ops"], [])


class AtomicityTests(DatabaseCase):
    def _seeded(self, tenant: str, proofs=None):
        from solution.model import parse_case

        conn = db.connect(self.path(f"{tenant}.db"))
        db.init_db(conn)
        seed = parse_case(
            case(
                tenant,
                tenant,
                [],
                attempts=[
                    standard_attempt(),
                    standard_attempt("att-sibling"),
                ],
                proofs=(proofs or standard_proofs(tenant))
                + [
                    synth.proof(
                        "sibling-admin",
                        "att-sibling",
                        "acct-1",
                        1,
                        PROFILE,
                        f"{tenant}-a",
                        "admin",
                        1,
                        100,
                        900,
                        "verifier-admin",
                    )
                ],
            ),
            0,
        )
        db.seed_tenant(conn, seed, now=0)
        return conn

    def test_all_five_effects_commit_together(self):
        conn = self._seeded("tenant-atomic")
        result = Engine(conn, tenant="tenant-atomic", key=synth.KEY, now=0).execute(recovery("req-1"))
        self.assertEqual(result["receipt"]["status"], "committed")
        state = db.read_state(conn, "tenant-atomic")
        self.assertEqual(state.accounts["acct-1"].account_gen, 2)
        self.assertEqual(state.proofs["att-1-human"].status, "consumed")
        self.assertEqual(state.proofs["att-1-device"].status, "consumed")
        self.assertEqual(state.proofs["att-1-human"].consumed_by, "att-1")
        self.assertEqual(state.attempts["att-1"].status, "closed")
        self.assertEqual(state.attempts["att-sibling"].status, "closed")
        self.assertTrue(state.attempts["att-sibling"].closed_by.startswith("recovery:"))
        self.assertIn(2, state.recoveries)
        self.assertEqual(state.recoveries[2].proof_a, "att-1-device")
        self.assertEqual(state.recoveries[2].proof_b, "att-1-human")
        self.assertIn("req-1", state.ops)
        conn.close()

    def test_a_commit_that_raises_leaves_no_trace(self):
        from solution.model import parse_case

        conn = self._seeded("tenant-rollback")
        engine = Engine(conn, tenant="tenant-rollback", key=synth.KEY, now=0)
        original = db.WriteTx.consume_proof

        def explode(self, proof, by_attempt, at):
            raise RuntimeError("simulated failure between consume and commit")

        db.WriteTx.consume_proof = explode
        try:
            with self.assertRaises(RuntimeError):
                engine.execute(recovery("req-1"))
        finally:
            db.WriteTx.consume_proof = original
        state = db.read_state(conn, "tenant-rollback")
        self.assertEqual(state.accounts["acct-1"].account_gen, 1)
        self.assertEqual(state.proofs["att-1-human"].status, "available")
        self.assertEqual(state.attempts["att-1"].status, "open")
        self.assertNotIn(2, state.recoveries)
        self.assertNotIn("req-1", state.ops)
        conn.close()

    def test_a_failed_pair_does_not_consume_anything(self):
        proofs = [p for p in standard_proofs("tenant-nopair") if p["channel_type"] == "device"]
        proofs.append(
            synth.proof(
                "second-device",
                "att-1",
                "acct-1",
                1,
                PROFILE,
                "tenant-nopair-d",
                "device",
                1,
                100,
                900,
                "another-verifier",
            )
        )
        from solution.model import parse_case

        conn = db.connect(self.path("nopair.db"))
        db.init_db(conn)
        seed = parse_case(
            case("nopair", "tenant-nopair", [], attempts=[standard_attempt()], proofs=proofs, channel_types={"d": "device"}), 0
        )
        db.seed_tenant(conn, seed, now=0)
        result = Engine(conn, tenant="tenant-nopair", key=synth.KEY, now=0).execute(recovery("req-1"))
        self.assertEqual(result["receipt"]["code"], E_NO_VALID_PAIR)
        state = db.read_state(conn, "tenant-nopair")
        self.assertEqual({p.status for p in state.proofs.values()}, {"available"})
        self.assertEqual(state.accounts["acct-1"].account_gen, 1)
        self.assertIn("req-1", state.ops, "the business failure itself is persisted")
        conn.close()


class LifecycleOperationTests(DatabaseCase):
    def _engine(self, tenant: str):
        from solution.model import parse_case

        conn = db.connect(self.path(f"{tenant}.db"))
        db.init_db(conn)
        seed = parse_case(
            case(tenant, tenant, [], attempts=[standard_attempt()], proofs=standard_proofs(tenant)),
            0,
        )
        db.seed_tenant(conn, seed, now=0)
        return conn, Engine(conn, tenant=tenant, key=synth.KEY, now=0)

    def test_rotation_changes_the_current_generation(self):
        conn, engine = self._engine("tenant-rot")
        request = synth.lifecycle_request("lif-1", "rotate_channel", "tenant-rot-h", 2, 400)
        self.assertEqual(engine.execute(request)["receipt"]["status"], "committed")
        state = db.read_state(conn, "tenant-rot")
        self.assertEqual(state.channel_state("tenant-rot-h"), (2, None))
        conn.close()

    def test_revocation_kills_the_channel(self):
        conn, engine = self._engine("tenant-rev")
        engine.execute(synth.lifecycle_request("lif-1", "revoke_channel", "tenant-rev-h", 1, 400))
        state = db.read_state(conn, "tenant-rev")
        self.assertEqual(state.channel_state("tenant-rev-h"), (1, 400))
        self.assertIsNotNone(state.channel_state("tenant-rev-h")[1])
        conn.close()

    def test_wrong_generation_is_refused(self):
        conn, engine = self._engine("tenant-gen")
        result = engine.execute(synth.lifecycle_request("lif-1", "rotate_channel", "tenant-gen-h", 3, 400))
        self.assertEqual(result["receipt"]["status"], "rejected")
        self.assertEqual(result["receipt"]["code"], "E404")
        conn.close()

    def test_unknown_channel_is_refused(self):
        conn, engine = self._engine("tenant-unk")
        result = engine.execute(synth.lifecycle_request("lif-1", "rotate_channel", "nope", 2, 400))
        self.assertEqual(result["receipt"]["code"], "E401")
        conn.close()

    def test_unsigned_lifecycle_request_is_refused(self):
        conn, engine = self._engine("tenant-sig")
        request = synth.lifecycle_request("lif-1", "rotate_channel", "tenant-sig-h", 2, 400)
        request["signature"] = "f" * 64
        result = engine.execute(request)
        self.assertEqual(result["receipt"]["code"], "E301")
        self.assertEqual(db.read_state(conn, "tenant-sig").channel_state("tenant-sig-h"), (1, None))
        conn.close()

    def test_time_travel_is_refused(self):
        conn, engine = self._engine("tenant-time")
        engine.execute(synth.lifecycle_request("lif-1", "rotate_channel", "tenant-time-h", 2, 400))
        result = engine.execute(synth.lifecycle_request("lif-2", "rotate_channel", "tenant-time-h", 3, 300))
        self.assertEqual(result["receipt"]["code"], "E214")
        conn.close()

    def test_revoked_channel_cannot_be_rotated(self):
        conn, engine = self._engine("tenant-rev2")
        engine.execute(synth.lifecycle_request("lif-1", "revoke_channel", "tenant-rev2-h", 1, 400))
        result = engine.execute(synth.lifecycle_request("lif-2", "rotate_channel", "tenant-rev2-h", 2, 500))
        self.assertEqual(result["receipt"]["code"], E_CHANNEL_REVOKED)
        conn.close()


class IsolationTests(DatabaseCase):
    def test_two_databases_do_not_share_state(self):
        from solution.model import parse_case

        conn_a = db.connect(self.path("a.db"))
        conn_b = db.connect(self.path("b.db"))
        for conn in (conn_a, conn_b):
            db.init_db(conn)
        seed_a = parse_case(case("a", "tenant-a", [], attempts=[standard_attempt()], proofs=standard_proofs("tenant-a")), 0)
        seed_b = parse_case(case("b", "tenant-b", [], attempts=[standard_attempt()], proofs=standard_proofs("tenant-b")), 0)
        db.seed_tenant(conn_a, seed_a, now=0)
        db.seed_tenant(conn_b, seed_b, now=0)
        Engine(conn_a, tenant="tenant-a", key=synth.KEY, now=0).execute(recovery("req-1"))
        state_b = db.read_state(conn_b, "tenant-b")
        self.assertEqual(state_b.accounts["acct-1"].account_gen, 1)
        self.assertEqual(state_b.ops, {})
        self.assertEqual(state_a_gen(conn_a), 2)
        conn_a.close()
        conn_b.close()

    def test_records_of_another_tenant_are_unknown(self):
        from solution.model import parse_case

        conn = db.connect(self.path("mix.db"))
        db.init_db(conn)
        seed = parse_case(
            case("mix", "tenant-mix", [], attempts=[standard_attempt()], proofs=standard_proofs("tenant-mix")), 0
        )
        db.seed_tenant(conn, seed, now=0)
        engine = Engine(conn, tenant="tenant-other", key=synth.KEY, now=0)
        with self.assertRaises(RecoveryError) as caught:
            engine.execute({"remote_id": "r", "op": "get_attempt", "attempt_id": "att-1"})
        self.assertEqual(caught.exception.code, E_UNKNOWN_ID)
        conn.close()


def state_a_gen(conn) -> int:
    return db.read_state(conn, "tenant-a").accounts["acct-1"].account_gen


class DocumentTests(DatabaseCase):
    def test_load_errors_abort_only_their_case(self):
        good = case("good", "tenant-good", [recovery("req-1")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-good"))
        bad = case("bad", "tenant-bad", [recovery("req-1")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-bad"))
        bad["load"]["proofs"][0]["signature"] = "0" * 64
        document = {"cases": [bad, good], "races": []}
        self.write_json("doc.json", document)
        from solution.runner import execute_document

        result = execute_document(document, workroot=self.workdir)
        self.assertEqual(result["cases"][0]["status"], "load_error")
        self.assertEqual(result["cases"][0]["code"], "E301")
        self.assertEqual(result["cases"][1]["status"], "ok")
        self.assertEqual(result["cases"][1]["problems"], [])

    def test_a_malformed_record_is_a_load_error_for_its_case(self):
        """E104: a record that parses but cannot be loaded fails only its case."""
        from solution.runner import execute_document

        broken = case(
            "broken-record",
            "tenant-broken-record",
            [recovery("req-1")],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-broken-record"),
        )
        del broken["load"]["attempts"][0]["profile"]
        good = case(
            "survivor",
            "tenant-survivor",
            [recovery("req-2")],
            attempts=[standard_attempt()],
            proofs=standard_proofs("tenant-survivor"),
        )
        result = execute_document({"cases": [broken, good], "races": []}, workroot=self.workdir)
        self.assertEqual(result["cases"][0]["status"], "load_error")
        self.assertEqual(result["cases"][0]["code"], E_BAD_RECORD)
        self.assertEqual(result["cases"][1]["status"], "ok")

    def test_duplicate_tenant_is_rejected_before_anything_runs(self):
        from solution.model import load_cases

        first = case("one", "tenant-dup", [recovery("req-1")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-dup"))
        second = case("two", "tenant-dup", [recovery("req-2")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-dup"))
        path = self.write_json("dup.json", {"cases": [first, second], "races": []})
        with self.assertRaises(RecoveryError) as caught:
            load_cases(path)
        self.assertEqual(caught.exception.code, E_DUPLICATE_ID)

    def test_a_race_may_not_reuse_a_case_tenant(self):
        from solution.model import load_cases

        first = case("one", "tenant-dup2", [recovery("req-1")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-dup2"))
        race_case = case("race", "tenant-dup2", [], attempts=[standard_attempt()], proofs=standard_proofs("tenant-dup2"))
        path = self.write_json(
            "dup-race.json",
            {"cases": [first], "races": [{"race_id": "r", "case": race_case, "steps": [], "expect": {}}]},
        )
        with self.assertRaises(RecoveryError) as caught:
            load_cases(path)
        self.assertEqual(caught.exception.code, E_DUPLICATE_ID)

    def test_unknown_operation_is_a_protocol_error(self):
        result = run_single_case(
            case("weird", "tenant-weird", [{"remote_id": "r", "op": "explode"}]), self.workdir
        )
        self.assertEqual(result["results"][0]["code"], E_UNKNOWN_OP)


class CliTests(DatabaseCase):
    def test_cli_writes_results_and_returns_zero_on_success(self):
        import json
        import subprocess
        import sys

        from tests.helpers import ROOT

        document = {
            "cases": [
                case("cli", "tenant-cli", [recovery("req-1")], attempts=[standard_attempt()], proofs=standard_proofs("tenant-cli"))
            ],
            "races": [],
        }
        input_path = self.write_json("in.json", document)
        output_path = self.path("out.json")
        process = subprocess.run(
            [sys.executable, "-m", "solution", "--input", input_path, "--output", output_path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        with open(output_path, encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["summary"]["cases_failed"], 0)

    def test_cli_reports_a_broken_input_file(self):
        import json
        import subprocess
        import sys

        from tests.helpers import ROOT

        input_path = self.path("broken.json")
        with open(input_path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        output_path = self.path("out.json")
        process = subprocess.run(
            [sys.executable, "-m", "solution", "--input", input_path, "--output", output_path],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(process.returncode, 2)
        with open(output_path, encoding="utf-8") as handle:
            self.assertEqual(json.load(handle)["error"], "E101")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
