"""Explicit L1 fixture adapter; it does not retain native handles or fences.

Only unit tests use this callback adapter. A real provider must implement its
own acquisition, native verification, lifetime and cleanup in a context scope.
"""
from contextlib import contextmanager


def fixture_evidence_provider(verifier):
    @contextmanager
    def fixture_scope(operation, record, caller):
        yield verifier(operation, record, caller)
    return fixture_scope
