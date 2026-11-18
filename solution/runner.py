"""Case and race execution shared by the CLI and the test suite.

Isolation
---------
Every scenario runs against its **own** fresh SQLite database in a private
temporary directory.  Scenarios cannot observe one another, and a crash
scenario can be re-run from the same ``cases.json`` without cleanup.

Races
-----
A race is a scripted interleaving of processes that the harness itself starts
with :class:`subprocess.Popen`.  Ordering is fixed by file-based sync points,
never by sleeping or by hoping a process wins.  The harness kills only the
processes it started; it never looks for or touches any other process.

Expectations
------------
All expected values are written in the case/race document by hand or derived
from the protocol rules in ``tools/gen_cases.py``.  Nothing is read back from
the implementation to decide what to expect.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import db
from .engine import run_case
from .errors import RecoveryError
from .model import parse_case
from .syncpoints import SyncDir

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ScenarioError(Exception):
    """The scenario could not be executed as specified (harness problem)."""


# ---------------------------------------------------------------------------
# Dotted-path assertions
# ---------------------------------------------------------------------------


class _Missing:
    def __repr__(self):
        return "<missing>"


_MISSING = _Missing()


def lookup(mapping, path: str):
    current = mapping
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return _MISSING
        else:
            return _MISSING
    return current


def matches(actual, expected) -> bool:
    """Compare, allowing a dict expectation to name a subset of keys."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        return all(key in actual and matches(actual[key], value) for key, value in expected.items())
    return actual == expected


def check_assertions(payload: dict, assertions: dict) -> list[str]:
    problems: list[str] = []
    for path, expected in assertions.items():
        actual = lookup(payload, path)
        if isinstance(actual, _Missing) or not matches(actual, expected):
            problems.append(f"expected {path}={expected!r}, got {actual!r}")
    return problems


def check_expectation(results: list[dict], snapshot: dict, expect: dict) -> list[str]:
    """Check a single-process case's expectations.

    ``expect.outcomes`` addresses operations by ``"op": <index>`` (0-based
    position in ``operations``) or by ``"remote_id"`` (last result with that
    id).  Supported assertions:

    ``status``, ``code``, ``replayed``
        fields of the result envelope itself;
    ``proofs``, ``account_gen``, ``reasons``, ``candidate``
        paths inside ``receipt``: ``recovery.proofs``, ``recovery.account_gen``,
        ``reasons[].code``, ``candidate.proofs``.

    ``expect.final`` is a dotted-path map checked against the persisted
    snapshot after the case ran.
    """
    problems: list[str] = []
    last_by_remote: dict[str, dict] = {}
    for result in results:
        last_by_remote[result.get("remote_id")] = result
    for assertion in expect.get("outcomes", []):
        if "op" in assertion:
            index = assertion["op"]
            if not isinstance(index, int) or not 0 <= index < len(results):
                problems.append(f"outcome {index}: no such operation result")
                continue
            label = f"op {index}"
            result = results[index]
        else:
            remote_id = assertion.get("remote_id")
            label = f"remote_id {remote_id!r}"
            result = last_by_remote.get(remote_id)
            if result is None:
                problems.append(f"no result for {label}")
                continue
        receipt = result.get("receipt") or {}
        for field in ("status", "code", "replayed"):
            if field in assertion and result.get(field) != assertion[field]:
                problems.append(f"{label}: expected {field}={assertion[field]!r}, got {result.get(field)!r}")
        if "proofs" in assertion:
            actual = (receipt.get("recovery") or {}).get("proofs")
            if actual != assertion["proofs"]:
                problems.append(f"{label}: expected proofs {assertion['proofs']!r}, got {actual!r}")
        if "account_gen" in assertion:
            actual = (receipt.get("recovery") or {}).get("account_gen")
            if actual != assertion["account_gen"]:
                problems.append(f"{label}: expected account_gen {assertion['account_gen']!r}, got {actual!r}")
        if "reasons" in assertion:
            actual = [item.get("code") for item in receipt.get("reasons", [])]
            if actual != assertion["reasons"]:
                problems.append(f"{label}: expected reasons {assertion['reasons']!r}, got {actual!r}")
        if "candidate" in assertion:
            actual = (receipt.get("candidate") or {}).get("proofs")
            if actual != assertion["candidate"]:
                problems.append(f"{label}: expected candidate {assertion['candidate']!r}, got {actual!r}")
        if "pair_codes" in assertion:
            actual = receipt.get("pair_codes")
            if actual != assertion["pair_codes"]:
                problems.append(f"{label}: expected pair_codes {assertion['pair_codes']!r}, got {actual!r}")
    problems.extend(check_assertions(snapshot, expect.get("final", {})))
    return problems


# ---------------------------------------------------------------------------
# Single-process cases
# ---------------------------------------------------------------------------


def execute_case(case_dict: dict, index: int, workdir: str, *, sync=None) -> dict:
    case_id = case_dict.get("case_id") if isinstance(case_dict, dict) else f"#{index}"
    conn = db.connect(os.path.join(workdir, "case.db"))
    try:
        db.init_db(conn)
        try:
            seed = parse_case(case_dict, index)
        except RecoveryError as error:
            return {
                "case_id": case_id,
                "status": "load_error",
                "code": error.code,
                "message": error.message,
                "results": [],
                "snapshot": None,
                "problems": [],
            }
        outcome = run_case(conn, seed, sync=sync)
        return {
            "case_id": outcome["case_id"],
            "status": "ok",
            "code": None,
            "message": None,
            "results": outcome["results"],
            "snapshot": outcome["snapshot"],
            "problems": check_expectation(outcome["results"], outcome["snapshot"], seed.expectation or {}),
        }
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Multi-process races
# ---------------------------------------------------------------------------


class Worker:
    def __init__(self, name: str, process, sync_dir: str, token: str):
        self.name = name
        self.process = process
        self.sync_dir = sync_dir
        self.token = token
        self.stdout = ""
        self.stderr = ""
        self.returncode: int | None = None
        self.killed = False

    def envelopes(self) -> list[dict]:
        parsed = []
        for line in self.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except ValueError:
                parsed.append({"status": "unparsed", "line": line})
        return parsed

    def last_envelope(self) -> dict | None:
        envelopes = self.envelopes()
        return envelopes[-1] if envelopes else None


def execute_race(race: dict, index: int, workdir: str, *, timeout: float = 60.0) -> dict:
    """Execute one scripted race.

    Step verbs (each step is data, never code):

    ``{"start": "W", "request": <op or [ops]>, "park": ["point", ...]}``
        Start a new process.  ``request`` is a JSON document handed to the
        worker; ``park`` lists the sync points it must stop at.  An empty or
        missing list means it never parks.
    ``{"at": "W", "point": "p"}``            wait for W to arrive at p
    ``{"release": "W", "point": "p"}``       wait, then let W continue
    ``{"exit": "W"}``                        wait for W to finish; record its output
    ``{"kill": "W"}``                        kill W (only if this race started it)
    ``{"expect_dead": "W"}``                 assert W has already exited
    ``{"snapshot": "name"}``                 take a named snapshot of the database
    ``{"no_snapshot_change": ["a", "b"]}``   assert snapshots a and b are identical
    ``{"snapshot_change": ["a", "b"]}``      assert snapshots a and b differ

    ``race.expect.workers`` asserts on worker fields: ``envelope.receipt.code``,
    ``envelope.status``, ``returncode``, ``killed``, ``envelope_count``.
    ``race.expect.final`` asserts dotted paths on the final snapshot.
    ``race.expect.snapshots`` asserts dotted paths on the named snapshots.
    """
    race_id = race.get("race_id", f"race#{index}")
    case_dict = race.get("case")
    steps = race.get("steps")
    if not isinstance(case_dict, dict):
        raise ScenarioError(f"{race_id}: 'case' must be an object")
    if not isinstance(steps, list) or not steps:
        raise ScenarioError(f"{race_id}: 'steps' must be a non-empty array")

    db_path = os.path.join(workdir, "race.db")
    sync_dir = os.path.join(workdir, "sync")
    os.makedirs(sync_dir, exist_ok=True)
    conn = db.connect(db_path)
    try:
        db.init_db(conn)
        try:
            seed = parse_case(case_dict, 0)
        except RecoveryError as error:
            return {
                "race_id": race_id,
                "status": "load_error",
                "code": error.code,
                "message": error.message,
                "workers": [],
                "steps": [],
                "problems": [],
            }
        db.seed_tenant(conn, seed, now=seed.now)
    finally:
        conn.close()

    controller = SyncDir(sync_dir, timeout=timeout)
    workers: dict[str, Worker] = {}
    snapshots: dict[str, dict] = {}
    problems: list[str] = []
    log: list[dict] = []
    env = dict(os.environ)
    env["PYTHONPATH"] = PROJECT_ROOT + os.pathsep + env.get("PYTHONPATH", "") if env.get("PYTHONPATH") else PROJECT_ROOT

    def snapshot_now() -> dict:
        reader = db.connect(db_path)
        try:
            return db.read_state(reader, seed.tenant).snapshot()
        finally:
            reader.close()

    def drain(worker: Worker, *, timeout_s: float) -> None:
        out, err = worker.process.communicate(timeout=timeout_s)
        worker.stdout = out or ""
        worker.stderr = err or ""
        worker.returncode = worker.process.returncode

    try:
        for step_index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ScenarioError(f"{race_id}: step #{step_index} is not an object")
            entry: dict = {"step": step_index}
            if "start" in step:
                name = step["start"]
                if name in workers:
                    raise ScenarioError(f"{race_id}: worker {name!r} started twice")
                request = step.get("request")
                if not isinstance(request, (dict, list)):
                    raise ScenarioError(f"{race_id}: worker {name!r} needs a request")
                request_path = os.path.join(workdir, f"request-{name}.json")
                with open(request_path, "w", encoding="utf-8") as handle:
                    json.dump(request, handle, sort_keys=True)
                park = list(step.get("park", []))
                token = controller.new_token()
                argv = [
                    sys.executable,
                    "-m",
                    "solution.worker",
                    "--db",
                    db_path,
                    "--tenant",
                    seed.tenant,
                    "--key",
                    seed.key.decode("utf-8"),
                    "--now",
                    str(seed.now),
                    "--request",
                    request_path,
                    "--sync-dir",
                    sync_dir,
                    "--sync-token",
                    token,
                    "--park",
                    ",".join(park),
                ]
                process = subprocess.Popen(
                    argv,
                    cwd=PROJECT_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                )
                workers[name] = Worker(name, process, sync_dir, token)
                entry.update({"start": name, "park": park})
            elif "at" in step or "release" in step:
                name = step.get("at") or step.get("release")
                worker = workers.get(name)
                if worker is None:
                    raise ScenarioError(f"{race_id}: unknown worker {name!r}")
                point = step.get("point")
                if not isinstance(point, str):
                    raise ScenarioError(f"{race_id}: step #{step_index} needs a point")
                controller.wait(
                    point, worker.token, timeout=timeout, alive=lambda: worker.process.poll() is None
                )
                if "release" in step:
                    controller.release(point, worker.token)
                entry.update({"worker": name, "point": point, "released": "release" in step})
            elif "kill" in step:
                name = step["kill"]
                worker = workers.get(name)
                if worker is None:
                    raise ScenarioError(f"{race_id}: unknown worker {name!r}")
                if worker.process.poll() is None:
                    worker.process.kill()
                    worker.killed = True
                try:
                    worker.stdout, worker.stderr = worker.process.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:  # pragma: no cover - kill should be immediate
                    pass
                worker.returncode = worker.process.returncode
                entry.update({"kill": name})
            elif "expect_dead" in step:
                name = step["expect_dead"]
                worker = workers.get(name)
                if worker is None:
                    raise ScenarioError(f"{race_id}: unknown worker {name!r}")
                if worker.process.poll() is None:
                    problems.append(f"{race_id}: worker {name} was expected to be dead but is alive")
                entry.update({"expect_dead": name})
            elif "exit" in step:
                name = step["exit"]
                worker = workers.get(name)
                if worker is None:
                    raise ScenarioError(f"{race_id}: unknown worker {name!r}")
                try:
                    drain(worker, timeout_s=timeout)
                except subprocess.TimeoutExpired:
                    worker.process.kill()
                    worker.killed = True
                    worker.stdout, worker.stderr = worker.process.communicate()
                    worker.returncode = worker.process.returncode
                    problems.append(f"{race_id}: worker {name} timed out")
                entry.update({"exit": name, "returncode": worker.returncode})
            elif "snapshot" in step:
                label = step["snapshot"]
                if not isinstance(label, str):
                    raise ScenarioError(f"{race_id}: snapshot needs a name")
                snapshots[label] = snapshot_now()
                entry.update({"snapshot": label})
            elif "no_snapshot_change" in step or "snapshot_change" in step:
                want_change = "snapshot_change" in step
                names = step.get("snapshot_change" if want_change else "no_snapshot_change")
                if not isinstance(names, list) or len(names) != 2:
                    raise ScenarioError(f"{race_id}: step #{step_index} needs two snapshot names")
                first, second = names
                if first not in snapshots or second not in snapshots:
                    raise ScenarioError(f"{race_id}: unknown snapshot in {names!r}")
                same = snapshots[first] == snapshots[second]
                if same == want_change:
                    problems.append(
                        f"{race_id}: snapshots {first!r} and {second!r} "
                        f"{'differ' if want_change else 'are identical'} unexpectedly"
                    )
                entry.update({"compared": names, "equal": same})
            else:
                raise ScenarioError(f"{race_id}: step #{step_index} has no recognised verb")
            log.append(entry)
    finally:
        for worker in workers.values():
            if worker.process.poll() is None:
                worker.process.kill()
                worker.killed = True
            try:
                if worker.process.stdout is not None and not worker.stdout:
                    out, err = worker.process.communicate(timeout=10)
                    worker.stdout = worker.stdout or (out or "")
                    worker.stderr = worker.stderr or (err or "")
                worker.returncode = worker.process.returncode
            except Exception:  # noqa: BLE001 - cleanup is best effort
                pass
            for stream in (worker.process.stdout, worker.process.stderr):
                try:
                    if stream is not None and not stream.closed:
                        stream.close()
                except Exception:  # noqa: BLE001
                    pass

    final_snapshot = snapshot_now()
    outcome = {
        "race_id": race_id,
        "status": "ok",
        "code": None,
        "message": None,
        "workers": [
            {
                "name": worker.name,
                "returncode": worker.returncode,
                "killed": worker.killed,
                "stdout": worker.stdout,
                "stderr": worker.stderr,
                "envelopes": worker.envelopes(),
                "envelope": worker.last_envelope(),
                "envelope_count": len(worker.envelopes()),
            }
            for worker in workers.values()
        ],
        "steps": log,
        "snapshots": snapshots,
        "snapshot": final_snapshot,
        "problems": problems,
    }
    expect = race.get("expect")
    if isinstance(expect, dict):
        outcome["problems"] = problems + check_race_expectation(outcome, expect)
    return outcome


def check_race_expectation(outcome: dict, expect: dict) -> list[str]:
    problems: list[str] = []
    by_name = {worker["name"]: worker for worker in outcome["workers"]}
    for assertion in expect.get("workers", []):
        name = assertion.get("name")
        worker = by_name.get(name)
        if worker is None:
            problems.append(f"race: no worker {name!r} was started")
            continue
        flat = {
            "returncode": worker["returncode"],
            "killed": worker["killed"],
            "envelope_count": worker["envelope_count"],
            "envelope.status": (worker["envelope"] or {}).get("status"),
            "envelope.code": (worker["envelope"] or {}).get("code"),
            "envelope.replayed": (worker["envelope"] or {}).get("replayed"),
            "envelope.receipt.status": ((worker["envelope"] or {}).get("receipt") or {}).get("status"),
            "envelope.receipt.code": ((worker["envelope"] or {}).get("receipt") or {}).get("code"),
            "envelope.receipt.recovery.proofs": (
                ((worker["envelope"] or {}).get("receipt") or {}).get("recovery") or {}
            ).get("proofs"),
        }
        for field, expected in assertion.items():
            if field == "name":
                continue
            if flat.get(field) != expected:
                problems.append(f"worker {name}: expected {field}={expected!r}, got {flat.get(field)!r}")
    problems.extend(check_assertions(outcome["snapshot"], expect.get("final", {})))
    for label, assertions in expect.get("snapshots", {}).items():
        snap = outcome["snapshots"].get(label)
        if snap is None:
            problems.append(f"race: no snapshot named {label!r}")
            continue
        for path, expected in assertions.items():
            actual = lookup(snap, path)
            if isinstance(actual, _Missing) or not matches(actual, expected):
                problems.append(f"snapshot {label}: expected {path}={expected!r}, got {actual!r}")
    return problems


# ---------------------------------------------------------------------------
# Whole-document execution
# ---------------------------------------------------------------------------


def execute_document(document: dict, *, workroot: str | None = None, timeout: float = 60.0) -> dict:
    owner = workroot is None
    root = workroot or tempfile.mkdtemp(prefix="recovery-cases-")
    cases_out: list[dict] = []
    races_out: list[dict] = []
    try:
        for index, case_dict in enumerate(document.get("cases", [])):
            workdir = os.path.join(root, f"case-{index:03d}")
            os.makedirs(workdir, exist_ok=True)
            cases_out.append(execute_case(case_dict, index, workdir))
        for index, race in enumerate(document.get("races", [])):
            workdir = os.path.join(root, f"race-{index:03d}")
            os.makedirs(workdir, exist_ok=True)
            try:
                races_out.append(execute_race(race, index, workdir, timeout=timeout))
            except ScenarioError as error:
                races_out.append(
                    {
                        "race_id": race.get("race_id", f"race#{index}") if isinstance(race, dict) else f"race#{index}",
                        "status": "harness_error",
                        "message": str(error),
                        "workers": [],
                        "steps": [],
                        "snapshots": {},
                        "snapshot": None,
                        "problems": [str(error)],
                    }
                )
        summary = {
            "cases": len(cases_out),
            "cases_ok": sum(1 for case in cases_out if case["status"] == "ok" and not case["problems"]),
            "cases_failed": sum(1 for case in cases_out if case["status"] != "ok" or case["problems"]),
            "races": len(races_out),
            "races_ok": sum(1 for race in races_out if race["status"] == "ok" and not race["problems"]),
            "races_failed": sum(1 for race in races_out if race["status"] != "ok" or race["problems"]),
        }
        return {"cases": cases_out, "races": races_out, "summary": summary}
    finally:
        if owner:
            shutil.rmtree(root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    import argparse

    from .model import load_cases

    parser = argparse.ArgumentParser(prog="python -m solution")
    parser.add_argument("--input", required=True, help="cases.json to execute")
    parser.add_argument("--output", required=True, help="where to write result.json")
    parser.add_argument("--workdir", default=None, help="keep intermediate databases here")
    parser.add_argument("--no-races", action="store_true", help="skip multi-process races")
    parser.add_argument("--timeout", type=float, default=60.0, help="per-wait timeout for races")
    args = parser.parse_args(argv)

    try:
        document = load_cases(args.input)
    except RecoveryError as error:
        write_json(args.output, {"error": error.code, "message": error.message, "cases": [], "races": [], "summary": {}})
        sys.stderr.write(f"{error.code}: {error.message}\n")
        return 2
    if args.no_races:
        document = {"cases": document.get("cases", []), "races": []}
    if args.workdir:
        os.makedirs(args.workdir, exist_ok=True)
    payload = execute_document(document, workroot=args.workdir, timeout=args.timeout)
    write_json(args.output, payload)
    summary = payload["summary"]
    ok = summary.get("cases_failed", 0) == 0 and summary.get("races_failed", 0) == 0
    return 0 if ok else 1


def write_json(path: str, payload: dict) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)
        handle.write("\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
