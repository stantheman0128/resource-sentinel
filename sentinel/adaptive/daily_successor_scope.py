"""Lightweight lookup of an already retained original successor invocation."""
from pathlib import Path
import threading


CURRENT = threading.local()
SQL_CURRENT = threading.local()


def current_operation(db_path=None):
    operation = getattr(CURRENT, "operation", None)
    if operation is None:
        return None
    from .daily_successor import DailySuccessorError, DailySuccessorOperation
    if type(operation) is not DailySuccessorOperation:
        raise DailySuccessorError("original_operation_required")
    operation._original()
    if db_path is not None and Path(db_path).resolve() != operation.ledger_path:
        raise DailySuccessorError("ledger_changed", operation)
    return operation


def current_startup_operation(db_path=None):
    """SQL custody only; this grants no generation mutation/readiness scope."""
    operation = getattr(SQL_CURRENT, "operation", None)
    if operation is None:
        return None
    from .daily_successor import DailySuccessorError, DailySuccessorOperation
    if type(operation) is not DailySuccessorOperation:
        raise DailySuccessorError("original_operation_required")
    operation._original()
    if db_path is not None and Path(db_path).resolve() != operation.ledger_path:
        raise DailySuccessorError("ledger_changed", operation)
    return operation
