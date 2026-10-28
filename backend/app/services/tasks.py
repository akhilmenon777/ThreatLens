"""Tiny in-process background task registry for long operations (bulk dataset import).

Tasks run in a daemon thread and report progress; the UI polls ``GET /api/tasks/{id}``.
State is in memory only: a backend restart forgets running tasks (the data that was
already committed stays in the database).
"""
from __future__ import annotations

import threading
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Task:
    id: str
    kind: str
    status: str = "running"            # running | completed | failed
    progress: float = 0.0              # 0..1
    message: str = "Starting…"
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None

    def update(self, progress: float | None = None, message: str | None = None) -> None:
        if progress is not None:
            self.progress = max(0.0, min(1.0, progress))
        if message is not None:
            self.message = message

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "status": self.status, "progress": round(self.progress, 3),
                "message": self.message, "result": self.result, "error": self.error,
                "elapsed_s": round((self.finished_at or time.time()) - self.started_at, 1)}


_tasks: dict[str, Task] = {}
_lock = threading.Lock()


def start(kind: str, fn: Callable[[Task], dict[str, Any]]) -> Task:
    with _lock:
        for t in _tasks.values():
            if t.kind == kind and t.status == "running":
                return t  # one import at a time: return the running one
        task = Task(id=uuid.uuid4().hex[:12], kind=kind)
        _tasks[task.id] = task

    def run():
        try:
            task.result = fn(task)
            task.status = "completed"
            task.progress = 1.0
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            task.status = "failed"
            task.error = f"{type(exc).__name__}: {exc}"[:1000]
            task.message = "Failed"
            traceback.print_exc()
        finally:
            task.finished_at = time.time()

    threading.Thread(target=run, daemon=True, name=f"task-{kind}").start()
    return task


def get(task_id: str) -> Task | None:
    return _tasks.get(task_id)


def running(kind: str) -> Task | None:
    return next((t for t in _tasks.values() if t.kind == kind and t.status == "running"), None)
