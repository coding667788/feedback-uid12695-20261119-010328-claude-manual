"""Shared test helpers: independent record synthesis and isolated databases.

The helpers here re-implement the documented canonical encoding and HMAC rule
instead of importing it from ``solution``, so tests state expectations
independently.  See ``tools/synth.py``; this module only adds fixtures.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from tools import synth  # noqa: E402

PROFILE = {"display_name": "alice", "email": "alice@example.test", "locale": "en-GB"}
PROFILE_ALT = {"display_name": "alice", "email": "alice@example.test", "locale": "fr-FR"}


class DatabaseCase(unittest.TestCase):
    """A test case with a private temporary directory per test method."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="recovery-test-")
        self.addCleanup(self._tmp.cleanup)
        self.workdir = self._tmp.name

    def path(self, name: str) -> str:
        return os.path.join(self.workdir, name)

    def write_json(self, name: str, payload) -> str:
        target = self.path(name)
        with open(target, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return target


def case(
    case_id,
    tenant,
    operations,
    *,
    channel_types=None,
    accounts=None,
    attempts=None,
    proofs=None,
    events=None,
    now=0,
    account_id="acct-1",
    expect=None,
):
    channel_types = channel_types or {"h": "human", "d": "device", "a": "admin"}
    return synth.case(
        case_id,
        tenant,
        account_id,
        now,
        [synth.channel(f"{tenant}-{name}", kind) for name, kind in channel_types.items()],
        accounts if accounts is not None else [synth.account(account_id, 1)],
        attempts or [],
        proofs or [],
        events or [],
        operations,
        expect or {},
    )


def standard_proofs(tenant, attempt_id="att-1", account_id="acct-1", account_gen=1, profile=None):
    profile = profile or PROFILE
    return [
        synth.proof(
            f"{attempt_id}-human",
            attempt_id,
            account_id,
            account_gen,
            profile,
            f"{tenant}-h",
            "human",
            1,
            100,
            900,
            "verifier-human",
        ),
        synth.proof(
            f"{attempt_id}-device",
            attempt_id,
            account_id,
            account_gen,
            profile,
            f"{tenant}-d",
            "device",
            1,
            100,
            900,
            "verifier-device",
        ),
    ]


def standard_attempt(attempt_id="att-1", account_id="acct-1", account_gen=1, profile=None):
    profile = profile or PROFILE
    return synth.attempt(attempt_id, account_id, account_gen, profile, 100, 900)


def recovery(remote_id, attempt_id="att-1", account_id="acct-1", at=500, **extra):
    return synth.recovery_request(remote_id, account_id, attempt_id, at=at, **extra)


def run_single_case(case_dict, workdir):
    """Execute one case in ``workdir`` and return its result document."""
    from solution.runner import execute_case

    return execute_case(case_dict, 0, workdir)
