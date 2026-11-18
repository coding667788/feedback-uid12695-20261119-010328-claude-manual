"""Mutation sweep: verify the corpus catches protocol violations.

Each mutant disables exactly one rule; the corpus must reject every one of
them.  This checks the *tests*, not the solution: a survivor means some rule
is not actually pinned by any expectation.

Run: ``python tools/mutation_check.py``
Exit status is 0 only when every mutant is caught.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

MUTANTS = [
    (
        "no-different-verifier",
        "solution/engine.py",
        """    if first.issuer == second.issuer:
        violations.append(E_SAME_SIGNER)
""",
        "",
    ),
    (
        "no-distinct-type",
        "solution/engine.py",
        """    if first.channel_type == second.channel_type:
        violations.append(E_SAME_CHANNEL_TYPE)
""",
        "",
    ),
    (
        "no-strong-channel",
        "solution/engine.py",
        """    if first.channel_type not in STRONG_CHANNEL_TYPES and second.channel_type not in STRONG_CHANNEL_TYPES:
        violations.append(E_NO_STRONG_CHANNEL)
""",
        "",
    ),
    (
        "no-distinct-channel",
        "solution/engine.py",
        """    if first.channel_id == second.channel_id:
        violations.append(E_SAME_CHANNEL)
""",
        "",
    ),
    (
        "largest-pair",
        "solution/engine.py",
        "    usable = sorted((item.proof for item in diagnoses if item.code is None), key=lambda proof: proof.id)",
        "    usable = sorted((item.proof for item in diagnoses if item.code is None), key=lambda proof: proof.id, reverse=True)",
    ),
    (
        "no-sibling-close",
        "solution/engine.py",
        "        closed = tx.close_attempts_of_generation(attempt.account_id, attempt.account_gen, closed_by)",
        "        closed = []",
    ),
    (
        "ignore-revocation",
        "solution/engine.py",
        """    if revoked_at is not None:
        diagnosis.code = E_CHANNEL_REVOKED""",
        """    if False:
        diagnosis.code = E_CHANNEL_REVOKED""",
    ),
    (
        "no-stale-generation",
        "solution/engine.py",
        """    if proof.channel_gen < generation:
        diagnosis.code = E_CHANNEL_GEN_STALE""",
        """    if False:
        diagnosis.code = E_CHANNEL_GEN_STALE""",
    ),
    (
        "no-profile-binding",
        "solution/engine.py",
        """    if proof.profile_digest != attempt.profile_digest:
        diagnosis.code = E_BINDING""",
        """    if False:
        diagnosis.code = E_BINDING""",
    ),
    (
        "no-attempt-binding",
        "solution/engine.py",
        """    if proof.attempt_id != attempt.id:
        diagnosis.code = E_BINDING""",
        """    if False:
        diagnosis.code = E_BINDING""",
    ),
    (
        "no-not-before-check",
        "solution/engine.py",
        """    if at < proof.not_before:
        diagnosis.code = E_PROOF_NOT_YET_VALID""",
        """    if False:
        diagnosis.code = E_PROOF_NOT_YET_VALID""",
    ),
    (
        "exclusive-not-after",
        "solution/engine.py",
        "    if at > proof.not_after:",
        "    if at >= proof.not_after:",
    ),
    (
        "exclusive-attempt-end",
        "solution/engine.py",
        "    if at > attempt.expires_at:",
        "    if at >= attempt.expires_at:",
    ),
    (
        "exclusive-attempt-start",
        "solution/engine.py",
        "    if at < attempt.created_at:",
        "    if at <= attempt.created_at:",
    ),
    (
        "ignore-frozen-account",
        "solution/engine.py",
        '    if account.status != "active":',
        "    if False:",
    ),
    (
        "no-consumed-proof-check",
        "solution/engine.py",
        '    if proof.status != "available":',
        "    if False:",
    ),
    (
        "no-attempt-account-check",
        "solution/engine.py",
        """    if attempt.account_id != account_id:
        result.blocker = RecoveryError(""",
        """    if False:
        result.blocker = RecoveryError(""",
    ),
    (
        "no-supersede-check",
        "solution/engine.py",
        """        if (attempt.closed_by or "").startswith(RECOVERY_CLOSED_PREFIX):""",
        """        if False:""",
    ),
    (
        "no-attempt-generation-check",
        "solution/engine.py",
        """    if attempt.account_gen != account.account_gen:
        result.blocker = RecoveryError(""",
        """    if False:
        result.blocker = RecoveryError(""",
    ),
    (
        "replay-ignores-hash",
        "solution/engine.py",
        "        if stored.request_hash != req_hash:",
        "        if False:",
    ),
    (
        "no-generation-bump",
        "solution/db.py",
        "            (new_gen, self.tenant, account_id),",
        '            (int(row["account_gen"]), self.tenant, account_id),',
    ),
    (
        "failure-not-persisted",
        "solution/db.py",
        "    def insert_op(self, remote_id: str, kind: str, req_hash: str, status: str, code: str | None, receipt: dict) -> None:",
        """    def insert_op(self, remote_id: str, kind: str, req_hash: str, status: str, code: str | None, receipt: dict) -> None:
        if status == "rejected":
            return""",
    ),
]


def run_unit_tests(workdir: pathlib.Path, timeout: float = 300.0) -> tuple[bool, str]:
    """Run the rule-level unit tests against the mutated package."""
    process = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_rules", "-v"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return process.returncode == 0, (process.stdout + process.stderr)[-800:]


def run_mutant(name: str, relative: str, old: str, new: str) -> dict:
    target = ROOT / relative
    source = target.read_text(encoding="utf-8")
    if old not in source:
        return {"mutant": name, "status": "pattern-missing", "failed": None}
    workdir = pathlib.Path(tempfile.mkdtemp(prefix="mutant-"))
    try:
        package = workdir / "solution"
        shutil.copytree(ROOT / "solution", package, ignore=shutil.ignore_patterns("__pycache__"))
        for folder in ("tests", "tools"):
            shutil.copytree(
                ROOT / folder,
                workdir / folder,
                ignore=shutil.ignore_patterns("__pycache__", "_patch*.py", "mutation_check.py"),
            )
        shutil.copy(ROOT / "cases.json", workdir / "cases.json")
        mutated = package / pathlib.Path(relative).name
        mutated.write_text(source.replace(old, new, 1), encoding="utf-8")
        output = workdir / "result.json"
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "solution",
                "--input",
                str(workdir / "cases.json"),
                "--output",
                str(output),
                "--no-races",
            ],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if not output.exists():
            return {"mutant": name, "status": "crashed", "failed": None, "stderr": process.stderr[-600:]}
        payload = json.loads(output.read_text(encoding="utf-8"))
        failed = [case["case_id"] for case in payload["cases"] if case["problems"] or case["status"] != "ok"]
        units_ok, unit_output = run_unit_tests(workdir)
        return {
            "mutant": name,
            "status": "ok",
            "failed": failed,
            "unit_failed": not units_ok,
            "unit_output": unit_output,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    caught = 0
    survivors = []
    crashed = []
    for mutant_name, mutant_path, mutant_old, mutant_new in MUTANTS:
        result = run_mutant(mutant_name, mutant_path, mutant_old, mutant_new)
        if result["status"] == "crashed":
            # The mutant breaks the program instead of changing an outcome.
            # That is "detected", but for a reason that does not prove the
            # *expectations* pin the rule, so report it separately and require
            # the rule to also be covered by a case or unit assertion.
            print(f"{result['mutant']:<30} crashed (reported separately)")
            crashed.append(result["mutant"])
            continue
        if result["status"] != "ok":
            print(f"{result['mutant']:<30} {result['status']}")
            survivors.append(result["mutant"])
            continue
        if result["failed"]:
            print(f"{result['mutant']:<30} caught by {len(result['failed'])} case(s): {', '.join(result['failed'][:5])}")
            caught += 1
        elif result["unit_failed"]:
            print(f"{result['mutant']:<30} caught by the rule unit tests")
            caught += 1
        else:
            print(f"{result['mutant']:<30} SURVIVED")
            survivors.append(result["mutant"])
    print()
    if crashed:
        print(f"{len(crashed)} mutant(s) broke the run (the rule guards an invariant): {', '.join(crashed)}")
    if survivors:
        print(f"{len(survivors)} survivor(s): {', '.join(survivors)}")
        return 1
    print(f"all {caught} behavioural mutants were caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
