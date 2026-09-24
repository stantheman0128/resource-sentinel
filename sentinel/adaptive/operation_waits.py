"""One lexical wait budget; it grants no admission or native authority.

Only callers that explicitly enter bounded_waits change existing timeouts.
Timeouts are recalculated before each SQLite statement/native mutex wait. An
expired budget permits zero-wait cleanup: rollback, release and close are never
forbidden by this helper. Filesystem/native calls cannot be forcibly preempted;
new-work consumers must also require the deadline before committing effects.
"""
from contextlib import contextmanager
import math
import os
import re
import sqlite3
import threading
import time


_LOCAL = threading.local()
_BUSY = re.compile(r"\s*PRAGMA\s+busy_timeout\s*(?:=\s*(\d+)|\(\s*(\d+)\s*\))\s*;?\s*", re.I)


class OperationWaitExpired(RuntimeError):
    pass


class _Budget:
    def __init__(self, milliseconds):
        self.pid, self.thread = os.getpid(), threading.current_thread()
        self.deadline = time.monotonic() + milliseconds / 1000

    def remaining_ms(self):
        if os.getpid() != self.pid or threading.current_thread() is not self.thread:
            raise OperationWaitExpired("operation_wait_owner_changed")
        return max(0, math.floor((self.deadline - time.monotonic()) * 1000))

    def require(self):
        if self.remaining_ms() <= 0:
            raise OperationWaitExpired("operation_wait_deadline_exceeded")


@contextmanager
def bounded_waits(*, milliseconds=250):
    if type(milliseconds) is not int or not 0 < milliseconds <= 250:
        raise ValueError("invalid_operation_wait_budget")
    previous = getattr(_LOCAL, "budget", None)
    budget = previous if previous is not None else _Budget(milliseconds)
    if previous is not None:
        previous.remaining_ms()
        previous.deadline = min(previous.deadline, time.monotonic() + milliseconds / 1000)
    _LOCAL.budget = budget
    try:
        yield budget
    finally:
        _LOCAL.budget = previous


def remaining_timeout_ms(maximum):
    if type(maximum) is not int or maximum < 0:
        raise ValueError("invalid_wait_timeout")
    budget = getattr(_LOCAL, "budget", None)
    return maximum if budget is None else min(maximum, budget.remaining_ms())


class _Cursor(sqlite3.Cursor):
    def execute(self, sql, parameters=()):
        return super().execute(self.connection._bounded_statement(sql), parameters)

    def executemany(self, *args, **kwargs):
        raise OperationWaitExpired("operation_wait_batch_unsupported")

    def executescript(self, *args, **kwargs):
        raise OperationWaitExpired("operation_wait_batch_unsupported")


class _Connection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        self._operation_budget = getattr(_LOCAL, "budget", None)
        if self._operation_budget is None:
            raise OperationWaitExpired("operation_wait_scope_required")
        self._operation_timeout_ms = max(0, int(kwargs.get("timeout", 5) * 1000))
        super().__init__(*args, **kwargs)

    def _bounded_statement(self, sql):
        timeout = min(self._operation_timeout_ms, self._operation_budget.remaining_ms())
        # Respect the existing SQLite authorizer. This only requests a smaller
        # busy timeout; it never removes or replaces a database guard.
        super().execute("PRAGMA busy_timeout=" + str(timeout))
        match = _BUSY.fullmatch(sql) if type(sql) is str else None
        if match is not None:
            timeout = min(timeout, int(match.group(1) or match.group(2)))
            self._operation_timeout_ms = timeout
            return "PRAGMA busy_timeout=" + str(timeout)
        return sql

    def execute(self, sql, parameters=()):
        return super().execute(self._bounded_statement(sql), parameters)

    def cursor(self, factory=None):
        if factory is not None and factory is not _Cursor:
            raise OperationWaitExpired("operation_wait_cursor_unsupported")
        return super().cursor(factory=_Cursor)

    def executemany(self, *args, **kwargs):
        raise OperationWaitExpired("operation_wait_batch_unsupported")

    def executescript(self, *args, **kwargs):
        raise OperationWaitExpired("operation_wait_batch_unsupported")

    def commit(self):
        self._bounded_statement("COMMIT")
        return super().commit()

    def rollback(self):
        self._bounded_statement("ROLLBACK")
        return super().rollback()


def sqlite_options(*, timeout):
    """Connection kwargs which can only tighten the caller's normal timeout."""
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0:
        raise ValueError("invalid_sqlite_timeout")
    if getattr(_LOCAL, "budget", None) is None:
        return {"timeout": timeout}
    return {"timeout": remaining_timeout_ms(math.floor(timeout * 1000)) / 1000,
            "factory": _Connection}
