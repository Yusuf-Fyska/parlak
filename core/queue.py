"""
Minimal in-memory queue placeholder kept for compatibility.
In single-node mode this is unused but available for future extension.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)


@dataclass
class Job:
    id: str
    payload: dict
    attempts: int = 0
    max_attempts: int = 3


class JobQueue:
    def __init__(self):
        self._backend = _InMemoryBackend()

    def enqueue(self, job: Job):
        log.debug("enqueue job %s", job.id)
        self._backend.enqueue(job)

    def consume(self, handler: Callable[[Job], None], stop_event: threading.Event):
        self._backend.consume(handler, stop_event)


class _InMemoryBackend:
    def __init__(self):
        self.q: "queue.Queue[Job]" = queue.Queue()

    def enqueue(self, job: Job):
        self.q.put(job)

    def consume(self, handler: Callable[[Job], None], stop_event: threading.Event):
        while not stop_event.is_set():
            try:
                job = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                handler(job)
            except Exception:  # noqa: BLE001
                job.attempts += 1
                if job.attempts < job.max_attempts:
                    time.sleep(1)
                    self.q.put(job)
            finally:
                self.q.task_done()
