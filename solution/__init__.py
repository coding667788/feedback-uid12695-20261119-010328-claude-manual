"""Synthetic-credential account-recovery coordinator.

Entry points
------------
``python -m solution --input cases.json --output result.json``
    Execute every case (and every two-process race) and write the results.

``python -m solution.worker ...``
    Internal: one independent process executing one request (used by races).

``python -m unittest discover -s tests -v``
    Automated test suite.
"""

from .errors import DESCRIPTIONS, RecoveryError
from .model import canonical_json, load_cases, parse_case, profile_digest
from .syncpoints import FileSync, SyncSink

__all__ = [
    "DESCRIPTIONS",
    "FileSync",
    "RecoveryError",
    "SyncSink",
    "canonical_json",
    "load_cases",
    "parse_case",
    "profile_digest",
]
__version__ = "1.0.0"
