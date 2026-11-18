"""Tests over the checked-in corpus (``cases.json``).

The corpus is the reproducible part of the delivery: the same file drives
``python -m solution`` and these tests.  Expectations inside it were written
from the protocol rules in ``tools/gen_cases.py`` / ``tools/races.py``; the
tests here check that the file is well-formed, fully executed, deterministic,
and sensitive to protocol violations (via ``tools/mutation_check.py``).
"""

from __future__ import annotations

import json
import os
import unittest

from tests.helpers import ROOT

CORPUS = os.path.join(ROOT, "cases.json")

REQUIRED_CASES = {
    "happy",
    "pairs",
    "deviceonly",
    "signer",
    "bounds",
    "chanlife",
    "newgen",
    "binding",
    "route",
    "second",
    "fixedfail",
    "scope",
    "scopeb",
    "adminde",
    "afterfail",
    "sametype",
    "lexi",
    "numids",
    "preconsumed",
    "blockedpair",
    "twodevices",
    "protocol",
    "paircodes",
    "startbound",
    "otheracct",
    "stalegen",
    "wrongatt",
}

REQUIRED_RACES = {
    "race-revoke-first",
    "race-two-attempts",
    "race-expiry-boundary",
    "race-expiry-after-commit",
    "race-kill-before-commit",
    "race-kill-before-reply",
    "race-failed-then-revoke",
    "race-same-request-id",
}


def load_corpus() -> dict:
    with open(CORPUS, "r", encoding="utf-8") as handle:
        return json.load(handle)


class CorpusShapeTests(unittest.TestCase):
    def test_corpus_file_exists_and_is_valid_json(self):
        self.assertTrue(os.path.exists(CORPUS), "cases.json must be part of the delivery")
        document = load_corpus()
        self.assertEqual(document["schema"], "recovery-cases/1")

    def test_every_required_case_is_present(self):
        document = load_corpus()
        found = {entry["case_id"] for entry in document["cases"]}
        self.assertEqual(REQUIRED_CASES - found, set())

    def test_every_required_race_is_present(self):
        document = load_corpus()
        found = {entry["race_id"] for entry in document["races"]}
        self.assertEqual(REQUIRED_RACES - found, set())

    def test_tenants_are_unique_across_the_whole_file(self):
        document = load_corpus()
        tenants = [entry["tenant"] for entry in document["cases"]]
        tenants += [entry["case"]["tenant"] for entry in document["races"]]
        self.assertEqual(len(tenants), len(set(tenants)))

    def test_every_case_and_race_has_expectations(self):
        document = load_corpus()
        for entry in document["cases"]:
            expect = entry["expect"]
            self.assertTrue(expect.get("outcomes"), f"{entry['case_id']} has no outcome assertions")
            self.assertTrue(expect.get("final"), f"{entry['case_id']} has no final assertions")
        for entry in document["races"]:
            expect = entry["expect"]
            self.assertTrue(expect.get("workers"), f"{entry['race_id']} has no worker assertions")

    def test_the_corpus_exercises_the_business_error_codes(self):
        """Every business code is either asserted in the corpus or tested elsewhere.

        The corpus itself asserts the codes that describe a recovery outcome.
        Codes that describe a *document* problem (`E101`, `E103`, `E104`) are
        covered by the CLI and load tests; this test names them explicitly so
        that adding a new business code without coverage fails here.
        """
        from solution.errors import BUSINESS_ERRORS

        document = load_corpus()
        facts = json.dumps(document)

        asserted_in_corpus = {
            "E100", "E102", "E201", "E203", "E204", "E205", "E206", "E207",
            "E208", "E209", "E210", "E211", "E212", "E213", "E214", "E301",
            "E401", "E402", "E403", "E404", "E501", "E502", "E503", "E504",
            "E505", "E506",
        }
        covered_elsewhere = {
            "E101": "tests/test_integration.py::CliTests.test_cli_reports_a_broken_input_file",
            "E103": "tests/test_integration.py::DocumentTests.test_duplicate_tenant_is_rejected_before_anything_runs",
            "E104": "tests/test_integration.py::DocumentTests.test_a_malformed_record_is_a_load_error_for_its_case",
        }
        for code in sorted(BUSINESS_ERRORS):
            if code in covered_elsewhere:
                continue
            self.assertIn(code, asserted_in_corpus, f"{code} is not asserted by any corpus expectation")
            self.assertIn(code, facts, f"{code} is not mentioned by cases.json")

    def test_no_real_looking_secrets(self):
        document = load_corpus()
        self.assertEqual(document["cases"][0]["signing_key"], "synthetic-recovery-key-2026")
        self.assertIn("synthetic", document["description"].lower())


class CorpusExecutionTests(unittest.TestCase):
    """The whole file, executed twice, must be identical and pass."""

    @classmethod
    def setUpClass(cls):
        import tempfile

        from solution.model import load_cases
        from solution.runner import execute_document

        cls.document = load_cases(CORPUS)
        cls.tmp = tempfile.TemporaryDirectory(prefix="corpus-")
        try:
            cls.first = execute_document(cls.document, timeout=120)
            cls.second = execute_document(cls.document, timeout=120)
        finally:
            cls.tmp.cleanup()

    def test_no_case_or_race_fails(self):
        self.assertEqual(self.first["summary"]["cases_failed"], 0, self._problems())
        self.assertEqual(self.first["summary"]["races_failed"], 0, self._problems())

    def _problems(self) -> str:
        lines = []
        for case in self.first["cases"]:
            if case["problems"]:
                lines.append(f"{case['case_id']}: {case['problems']}")
        for race in self.first["races"]:
            if race["problems"]:
                lines.append(f"{race['race_id']}: {race['problems']}")
        return "\n".join(lines)

    def test_execution_is_deterministic(self):
        strip = {
            "stdout",
            "stderr",
            "returncode",
            "workers",
            "paths",
        }
        first = [{key: value for key, value in case.items() if key not in strip} for case in self.first["cases"]]
        second = [{key: value for key, value in case.items() if key not in strip} for case in self.second["cases"]]
        self.assertEqual(first, second)
        self.assertEqual(
            self.first["summary"],
            self.second["summary"],
            "the same corpus must produce the same summary twice",
        )

    def test_every_case_reports_the_expected_number_of_operations(self):
        for entry, result in zip(self.document["cases"], self.first["cases"]):
            self.assertEqual(len(result["results"]), len(entry["operations"]), entry["case_id"])

    def test_committed_receipts_carry_a_full_recovery_row(self):
        committed = 0
        for result in self.first["cases"]:
            for operation in result["results"]:
                receipt = operation.get("receipt") or {}
                if receipt.get("status") != "committed" or "recovery" not in receipt:
                    continue
                committed += 1
                recovery = receipt["recovery"]
                self.assertEqual(len(recovery["proofs"]), 2)
                self.assertEqual(
                    recovery["proofs"], sorted(recovery["proofs"]), "pair must be stored in proof-id order"
                )
                for key in (
                    "account_gen",
                    "account_id",
                    "attempt_id",
                    "attempt_digest",
                    "profile_digest",
                    "recovery_digest",
                    "request_tenant",
                    "request_id",
                    "request_at",
                    "at",
                ):
                    self.assertIn(key, recovery)
        self.assertGreater(committed, 10, "the corpus should commit many recoveries")

    def test_replayed_receipts_are_byte_identical_to_the_first(self):
        checked = 0
        for result in self.first["cases"]:
            seen: dict[str, dict] = {}
            for operation in result["results"]:
                remote_id = operation.get("remote_id")
                if operation.get("replayed"):
                    original = seen.get(remote_id)
                    self.assertIsNotNone(original, f"{remote_id} replayed without a first execution")
                    self.assertEqual(operation["receipt"], original, f"{remote_id} replay drifted")
                    checked += 1
                else:
                    seen.setdefault(remote_id, operation.get("receipt") or {})
        self.assertGreater(checked, 0, "at least one case must exercise replay")

    def test_no_race_worker_reports_a_fatal_error(self):
        for race in self.first["races"]:
            for worker in race["workers"]:
                for envelope in worker["envelopes"]:
                    self.assertNotEqual(
                        envelope.get("status"), "fatal", f"{race['race_id']}/{worker['name']}: {envelope}"
                    )
                    self.assertNotEqual(envelope.get("status"), "unparsed", f"{race['race_id']}/{worker['name']}")


class MutationSensitivityTests(unittest.TestCase):
    """The corpus must reject protocol violations (see tools/mutation_check.py)."""

    def test_every_mutant_is_caught(self):
        import subprocess
        import sys

        process = subprocess.run(
            [sys.executable, os.path.join(ROOT, "tools", "mutation_check.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=900,
        )
        self.assertEqual(
            process.returncode,
            0,
            "some mutants survived, so a protocol rule is not pinned by any expectation:\n"
            + process.stdout
            + process.stderr,
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
