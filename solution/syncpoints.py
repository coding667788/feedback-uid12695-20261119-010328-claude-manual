"""Synchronisation points used by the concurrency tests.

A **sync point** is a named place in the engine where a process parks until
the test releases it.  Points are implemented as files in a shared directory
so that they work between independent processes on Windows without extra
services:

* the parked process creates ``<point>__<token>.arrived`` (flushed to disk)
  and then polls for ``<point>__<token>.released``;
* the controller waits for the ``arrived`` marker and later creates the
  ``released`` marker.

This makes the interleaving explicit: a test never relies on ``sleep`` to
guess an order.  The markers are the only channel between the processes; no
business state is exchanged through them.

The engine only ever calls :meth:`SyncSink.hit`; it has no other knowledge of
the harness.
"""

from __future__ import annotations

import os
import time
import uuid

POLL_INTERVAL = 0.002


def _arrived_path(directory: str, point: str, token: str) -> str:
    return os.path.join(directory, f"{point}__{token}.arrived")


def _released_path(directory: str, point: str, token: str) -> str:
    return os.path.join(directory, f"{point}__{token}.released")


class SyncSink:
    """No-op sink used whenever no harness directory is configured."""

    def hit(self, point: str) -> None:  # pragma: no cover - trivial
        return None


class FileSync(SyncSink):
    """Worker side of a file-based rendezvous.

    ``park`` names the points this worker should stop at.  An empty list means
    "park at every point", which is convenient for ad-hoc debugging; the tests
    always pass an explicit list so an unexpected point cannot silently hang a
    worker.
    """

    def __init__(
        self,
        directory: str,
        token: str | None = None,
        *,
        timeout: float = 120.0,
        park: list[str] | None = None,
    ):
        self.directory = directory
        self.token = token or uuid.uuid4().hex
        self.timeout = timeout
        self.park = park
        os.makedirs(directory, exist_ok=True)
        self.hits: list[str] = []
        self.parked: list[str] = []

    def hit(self, point: str) -> None:
        self.hits.append(point)
        if self.park is not None and point not in self.park:
            return
        self.parked.append(point)
        arrived = _arrived_path(self.directory, point, self.token)
        released = _released_path(self.directory, point, self.token)
        with open(arrived, "w", encoding="ascii") as handle:
            handle.write("1")
            handle.flush()
            os.fsync(handle.fileno())
        deadline = time.monotonic() + self.timeout
        while not os.path.exists(released):
            if time.monotonic() > deadline:
                raise TimeoutError(f"sync point {point!r} was never released")
            time.sleep(POLL_INTERVAL)


class SyncDir:
    """Controller side: observe arrivals and release parked workers."""

    def __init__(self, directory: str, *, timeout: float = 60.0):
        self.directory = directory
        self.timeout = timeout
        os.makedirs(directory, exist_ok=True)

    def new_token(self) -> str:
        return uuid.uuid4().hex

    def wait(self, point: str, token: str, *, timeout: float | None = None, alive=None) -> None:
        """Block until the worker arrives at ``point``.

        ``alive`` is an optional zero-argument callable; when it returns False
        the wait fails immediately instead of burning the whole timeout, which
        turns "the worker died before parking" into a clear harness error.
        """
        path = _arrived_path(self.directory, point, token)
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while not os.path.exists(path):
            if alive is not None and not alive():
                raise TimeoutError(f"process exited before reaching sync point {point!r}")
            if time.monotonic() > deadline:
                raise TimeoutError(f"process never reached sync point {point!r}")
            time.sleep(POLL_INTERVAL)

    def release(self, point: str, token: str) -> None:
        path = _released_path(self.directory, point, token)
        with open(path, "w", encoding="ascii") as handle:
            handle.write("1")
            handle.flush()
            os.fsync(handle.fileno())

