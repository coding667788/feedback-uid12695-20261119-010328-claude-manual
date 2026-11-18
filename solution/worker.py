"""Run operations in a separate process (used by the concurrency tests).

This is the "second independent process": it opens its own SQLite connection,
executes the operations of one request file in order and prints one JSON
envelope per line on stdout.  ``--sync-dir`` makes the engine park at sync
points so the test can order it against another process or kill it mid-flight.

The parent only ever kills processes it started itself through this module.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import db
from .engine import Engine
from .errors import RecoveryError
from .syncpoints import FileSync


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="solution.worker")
    parser.add_argument("--db", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--key", required=True, help="HMAC key for synthetic records")
    parser.add_argument("--now", type=int, default=0)
    parser.add_argument("--request", required=True, help="JSON file: one operation or a list of them")
    parser.add_argument("--sync-dir", default=None)
    parser.add_argument("--sync-token", default=None)
    parser.add_argument("--sync-timeout", type=float, default=120.0)
    parser.add_argument("--park", default="", help="comma separated points, or ALL")
    args = parser.parse_args(argv)

    with open(args.request, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    operations = payload if isinstance(payload, list) else [payload]

    conn = db.connect(args.db)
    db.init_db(conn)
    sink = None
    if args.sync_dir:
        raw = (args.park or "").strip()
        park = None if raw == "ALL" else [point for point in raw.split(",") if point]
        sink = FileSync(args.sync_dir, args.sync_token, timeout=args.sync_timeout, park=park)
    engine = Engine(conn, tenant=args.tenant, key=args.key.encode("utf-8"), now=args.now, sync=sink)

    for operation in operations:
        try:
            envelope = engine.execute(operation)
        except RecoveryError as error:
            envelope = {
                "remote_id": operation.get("remote_id") if isinstance(operation, dict) else None,
                "op": operation.get("op") if isinstance(operation, dict) else None,
                "tenant": args.tenant,
                "status": "error",
                "code": error.code,
                "replayed": False,
                "receipt": {"status": "error", "code": error.code, "message": error.message},
            }
        except Exception as error:  # noqa: BLE001 - reported to the parent, never swallowed
            envelope = {
                "remote_id": operation.get("remote_id") if isinstance(operation, dict) else None,
                "op": operation.get("op") if isinstance(operation, dict) else None,
                "tenant": args.tenant,
                "status": "fatal",
                "code": "E799",
                "replayed": False,
                "receipt": {"status": "fatal", "code": "E799", "message": f"{type(error).__name__}: {error}"},
            }
        sys.stdout.write(json.dumps(envelope, sort_keys=True))
        sys.stdout.write("\n")
        sys.stdout.flush()
    conn.close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
