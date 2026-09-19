"""Explicit L1 fixture adapter; it does not retain native handles or fences.

Only unit tests use this callback adapter. A real provider must implement its
own acquisition, native verification, lifetime and cleanup in a context scope.
"""
from contextlib import contextmanager
import threading

from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease


class FixturePolicyProvider:
    """Explicit in-process L1 mutex model; no native ownership or Job proof."""
    def __init__(self, logon_id="S-1-5-5-1-2"):
        self.logon_id = logon_id
        self.active = False
        self._lock = threading.Lock()

    def current_logon(self):
        return self.logon_id

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        if not self._lock.acquire(timeout=timeout_ms / 1000):
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.active = True
        try:
            yield PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, False)
        finally:
            self.active = False
            self._lock.release()


def fixture_evidence_provider(verifier):
    @contextmanager
    def fixture_scope(operation, record, caller):
        yield verifier(operation, record, caller)
    return fixture_scope
