"""Persistent compatibility fences for cooperative, older capacity writers.

These markers identify audited SQL paths, not callers or native authority. A
writer that knows this protocol must still perform shared admission accounting.
Read-only legacy approval paths cannot be fenced by SQLite DML triggers.
"""
from __future__ import annotations

import sqlite3


WRITER_PROTOCOL = 1
MAX_WRITER_REVISION = (1 << 63) - 1
_CAPACITY = {"reservations": "direct", "worker_reservations": "routed"}
_REQUIRED_TABLES = {"adaptive_runtime", "managed_executions", "reservations", "worker_reservations", "workers"}
_TERMINAL = "('FINISHED','CANCELLED_BEFORE_START','START_FAILED')"


def _tables(conn):
    return {row[0] for row in conn.execute("""SELECT name FROM sqlite_master WHERE type='table'
        AND name IN ('reservations','worker_reservations','workers','adaptive_runtime','managed_executions')""")}


def _tagged(alias, table):
    expressions = [f"{alias}.lifecycle_managed IS NOT 0", f"{alias}.execution_id IS NOT NULL"]
    if table == "reservations":
        expressions.extend((f"{alias}.managed_spec_hash IS NOT NULL",
                            f"substr({alias}.tool_use_id,1,11) IS 'managed-v1:'"))
    return "(" + " OR ".join(expressions) + ")"


def _registry_backref(alias, table):
    kind = _CAPACITY[table]
    # A valid opposite-kind reservation ID is a separate namespace. An invalid
    # kind (including a parent illegally carrying an allocation ID) cannot
    # discard the only remaining reference after capacity tags were stripped.
    return (f"(m.reservation_id={alias}.id AND (m.allocation_kind IS '{kind}' OR "
            "(typeof(m.allocation_kind)='text' AND m.allocation_kind IN ('direct','routed')) IS NOT 1))")


def _bound(alias, table):
    return (f"({_tagged(alias, table)} OR EXISTS(SELECT 1 FROM managed_executions m "
            f"WHERE {_registry_backref(alias, table)}))")


def _protected(tables):
    # NULL and malformed values must not make a WHEN expression evaluate NULL.
    terms = ["""NOT ((SELECT count(*) FROM adaptive_runtime)=1 AND EXISTS(
        SELECT 1 FROM adaptive_runtime WHERE typeof(singleton)='integer' AND singleton IS 1
        AND typeof(schema_version)='integer' AND schema_version IS 1
        AND typeof(protocol_version)='integer' AND protocol_version IS 1 AND typeof(registry_revision)='integer'
        AND registry_revision>=0 AND typeof(mode)='text'
        AND mode IN ('off','shadow','canary','limited')
        AND admission_barrier IS 'NONE'))""",
        f"""EXISTS(SELECT 1 FROM managed_executions m WHERE (
            typeof(m.state)='text' AND m.state IN {_TERMINAL}
            AND m.launch_sealed IS 1 AND m.launch_in_flight IS 0
            AND ((m.allocation_kind IN ('direct','routed')
                  AND typeof(m.reservation_id)='text' AND length(m.reservation_id)>0
                  AND m.parent_execution_id IS NULL)
                 OR (m.allocation_kind IS 'parent' AND m.reservation_id IS NULL
                     AND typeof(m.parent_execution_id)='text' AND length(m.parent_execution_id)>0))) IS NOT 1)"""]
    for table in _CAPACITY:
        if table in tables:
            terms.append(f"EXISTS(SELECT 1 FROM {table} a WHERE {_bound('a', table)})")
    return "(" + " OR ".join(terms) + ")"


def _valid_new(*, insert):
    revision = ("NEW.writer_revision IS 0" if insert else
                f"typeof(OLD.writer_revision)='integer' AND OLD.writer_revision>=0 "
                f"AND OLD.writer_revision<{MAX_WRITER_REVISION} "
                "AND NEW.writer_revision IS OLD.writer_revision+1")
    return ("(NEW.writer_protocol IS 1 AND typeof(NEW.writer_protocol)='integer' "
            "AND typeof(NEW.writer_revision)='integer' AND " + revision + ")")


def _terminal_binding(table):
    kind = _CAPACITY[table]
    spec = ("CASE WHEN OLD.managed_spec_hash IS NULL THEN OLD.spec_hash "
            "ELSE OLD.managed_spec_hash END" if table == "reservations" else "OLD.spec_hash")
    return f"""(OLD.lifecycle_managed IS 1 AND typeof(OLD.lifecycle_managed)='integer'
        AND typeof(OLD.execution_id)='text' AND length(OLD.execution_id)>0
        AND EXISTS(SELECT 1 FROM managed_executions m
            WHERE m.execution_id=OLD.execution_id AND m.allocation_kind='{kind}'
            AND m.reservation_id=OLD.id AND m.parent_execution_id IS NULL
            AND typeof(m.state)='text' AND m.state IN {_TERMINAL}
            AND m.launch_sealed IS 1 AND m.launch_in_flight IS 0
            AND typeof(m.spec_hash)='text' AND length(m.spec_hash)=64
            AND m.spec_hash IS ({spec}))
        AND NOT EXISTS(SELECT 1 FROM managed_executions m WHERE {_registry_backref('OLD', table)}
            AND (m.execution_id IS NOT OLD.execution_id OR m.allocation_kind IS NOT '{kind}')))"""


def _install(conn, name, event, table, predicate, reason):
    # Rebuild, including cross-table predicates, instead of retaining any older
    # partial-schema fence that was installed before the peer ledger existed.
    conn.execute(f"DROP TRIGGER IF EXISTS {name}")
    conn.execute(f"""CREATE TRIGGER {name} BEFORE {event} ON {table}
        WHEN {predicate}
        BEGIN SELECT RAISE(ABORT,'{reason}'); END""")


def writer_obligations_present(conn: sqlite3.Connection) -> bool:
    """Inspect the exact trigger predicate under the caller's writer lock.

    A constructor uses this after migration to avoid changing legacy locality
    metadata underneath surviving or malformed managed allocations.
    """
    if not conn.in_transaction:
        raise ValueError("writer_fence_requires_transaction")
    tables = _tables(conn)
    if not {"adaptive_runtime", "managed_executions"} <= tables:
        raise ValueError("writer_fence_requires_lifecycle_schema")
    if not _REQUIRED_TABLES <= tables:
        raise ValueError("writer_fence_requires_capacity_schema")
    return conn.execute("SELECT " + _protected(tables)).fetchone()[0] == 1


def migrate_writer_fence(conn: sqlite3.Connection) -> None:
    """Add metadata and refresh persistent guards in the caller's transaction.

    The lifecycle migration calls this only after its runtime/registry tables
    exist. This function does not commit, open another connection, or install
    UDFs. Both real ledgers and the worker registry must already exist; never
    return a weaker fence that an older opposite constructor could bypass.
    """
    if not conn.in_transaction:
        raise ValueError("writer_fence_requires_transaction")
    tables = _tables(conn)
    if not {"adaptive_runtime", "managed_executions"} <= tables:
        raise ValueError("writer_fence_requires_lifecycle_schema")
    if not _REQUIRED_TABLES <= tables:
        raise ValueError("writer_fence_requires_capacity_schema")
    for table in (*_CAPACITY, "workers"):
        if table not in tables:
            continue
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        additions = {
            "writer_protocol": "INTEGER NOT NULL DEFAULT 0 CHECK(typeof(writer_protocol)='integer' AND writer_protocol BETWEEN 0 AND 2147483647)",
            "writer_revision": f"INTEGER NOT NULL DEFAULT 0 CHECK(typeof(writer_revision)='integer' AND writer_revision BETWEEN 0 AND {MAX_WRITER_REVISION})",
        }
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    protected = _protected(tables)
    for table in (*_CAPACITY, "workers"):
        if table not in tables:
            continue
        incoming = f" OR {_tagged('NEW', table)}" if table in _CAPACITY else ""
        for event, insert in (("INSERT", True), ("UPDATE", False)):
            _install(conn, f"adaptive_writer_{table}_{event.lower()}", event, table,
                     f"({protected}{incoming}) AND NOT {_valid_new(insert=insert)}",
                     "capacity_writer_protocol_required")
        if table in _CAPACITY:
            _install(conn, f"adaptive_writer_{table}_delete", "DELETE", table,
                     f"{_bound('OLD', table)} AND NOT {_terminal_binding(table)}",
                     "managed_allocation_release_requires_terminal")
            unique = "request_key" if table == "reservations" else "task_id"
            # REPLACE can implicitly delete a conflicting row without running
            # DELETE triggers when recursive_triggers is off. Block the INSERT
            # itself, including execution-index and explicit rowid collisions.
            # Implicit NEW.rowid is undefined in BEFORE INSERT: a coincident
            # value may conservatively deny an insert, never authorize release.
            collision = f"""EXISTS(SELECT 1 FROM {table} a WHERE {_bound('a', table)}
                AND (a.rowid=NEW.rowid OR a.id=NEW.id OR a.{unique}=NEW.{unique}
                     OR (NEW.execution_id IS NOT NULL AND a.execution_id=NEW.execution_id)))"""
            _install(conn, f"adaptive_writer_{table}_replace", "INSERT", table,
                     collision, "managed_allocation_replace_forbidden")
            update_collision = f"""EXISTS(SELECT 1 FROM {table} a
                WHERE a.rowid != OLD.rowid AND {_bound('a', table)}
                AND (a.rowid=NEW.rowid OR a.id=NEW.id OR a.{unique}=NEW.{unique}
                     OR (NEW.execution_id IS NOT NULL AND a.execution_id=NEW.execution_id)))"""
            _install(conn, f"adaptive_writer_{table}_update_replace", "UPDATE", table,
                     update_collision, "managed_allocation_replace_forbidden")
        else:
            # Registry refreshes use audited UPDATE-if-present/INSERT-if-absent
            # transactions. An UPSERT's INSERT event cannot be distinguished
            # from REPLACE here, so neither may replace a referenced worker.
            # While obligations survive, all old worker changes are held, even
            # for remote workers: SQL does not duplicate Python locality rules.
            referenced = ("EXISTS(SELECT 1 FROM worker_reservations a WHERE a.worker_id=OLD.id)"
                          if "worker_reservations" in tables else "0")
            _install(conn, "adaptive_writer_workers_delete", "DELETE", table,
                     f"{protected} AND ({referenced})", "worker_release_requires_unreferenced")
            collision = ("EXISTS(SELECT 1 FROM workers w JOIN worker_reservations a ON a.worker_id=w.id "
                         "WHERE w.id=NEW.id OR w.rowid=NEW.rowid)" if "worker_reservations" in tables else "0")
            _install(conn, "adaptive_writer_workers_replace", "INSERT", table,
                     f"{protected} AND ({collision})", "worker_replace_forbidden")
            collision = ("EXISTS(SELECT 1 FROM workers w JOIN worker_reservations a ON a.worker_id=w.id "
                         "WHERE w.rowid != OLD.rowid AND (w.id=NEW.id OR w.rowid=NEW.rowid))"
                         if "worker_reservations" in tables else "0")
            _install(conn, "adaptive_writer_workers_update_replace", "UPDATE", table,
                     f"{protected} AND ({collision})", "worker_replace_forbidden")
