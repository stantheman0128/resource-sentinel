"""The existing direct/routed capacity schemas, prepared as one transaction.

Both ledgers must exist before persistent writer guards are installed. Otherwise
an older opposite entrypoint can CREATE its absent table without those guards.
This adds no reservation ledger and performs no locality or allocation backfill.
"""
from __future__ import annotations

import sqlite3


_CREATE = """
CREATE TABLE IF NOT EXISTS reservations (
    id TEXT PRIMARY KEY,
    request_key TEXT NOT NULL UNIQUE,
    owner_pid INTEGER NOT NULL,
    owner_started REAL NOT NULL,
    tool_use_id TEXT,
    repo TEXT NOT NULL,
    command_signature TEXT NOT NULL,
    command_text TEXT NOT NULL,
    resource_class TEXT NOT NULL,
    priority TEXT NOT NULL,
    priority_rank INTEGER NOT NULL,
    cpu_units REAL NOT NULL,
    ram_gib REAL NOT NULL,
    io_slots INTEGER NOT NULL,
    created_at REAL NOT NULL,
    heartbeat_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    spec_hash TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    owner_pid INTEGER NOT NULL,
    repo TEXT NOT NULL,
    command_signature TEXT NOT NULL,
    resource_class TEXT NOT NULL,
    priority TEXT NOT NULL,
    cpu_units REAL NOT NULL,
    ram_gib REAL NOT NULL,
    io_slots INTEGER NOT NULL,
    started_at REAL NOT NULL,
    ended_at REAL NOT NULL,
    outcome TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    failure_domain TEXT NOT NULL,
    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
    capacity_pool TEXT NOT NULL DEFAULT '',
    max_concurrency INTEGER NOT NULL DEFAULT 1,
    quota_domain TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL,
    automation_level TEXT NOT NULL,
    os TEXT NOT NULL,
    capacity_ram_gib REAL NOT NULL,
    allocatable_ram_gib REAL NOT NULL,
    visible_cpu REAL,
    allocatable_cpu REAL,
    disk_free_gib REAL,
    allocatable_disk_gib REAL,
    capabilities_json TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    source TEXT NOT NULL,
    observed_at REAL NOT NULL,
    probe_expires_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS worker_reservations (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL UNIQUE,
    worker_id TEXT NOT NULL,
    failure_domain TEXT NOT NULL,
    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
    capacity_pool TEXT NOT NULL DEFAULT '',
    spec_hash TEXT NOT NULL DEFAULT '',
    ram_gib REAL NOT NULL,
    cpu_units REAL NOT NULL,
    disk_gib REAL NOT NULL,
    created_at REAL NOT NULL,
    heartbeat_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    metadata_json TEXT NOT NULL,
    FOREIGN KEY(worker_id) REFERENCES workers(id)
);
CREATE TABLE IF NOT EXISTS routed_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reservation_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    failure_domain TEXT NOT NULL,
    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
    capacity_pool TEXT NOT NULL DEFAULT '',
    spec_hash TEXT NOT NULL DEFAULT '',
    ram_gib REAL NOT NULL,
    cpu_units REAL NOT NULL,
    disk_gib REAL NOT NULL,
    started_at REAL NOT NULL,
    ended_at REAL NOT NULL,
    outcome TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
"""

_ADDITIONS = {
    "reservations": {"spec_hash": "TEXT NOT NULL DEFAULT ''"},
    "workers": {
        "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
        "capacity_pool": "TEXT NOT NULL DEFAULT ''",
        "max_concurrency": "INTEGER NOT NULL DEFAULT 1",
        "quota_domain": "TEXT NOT NULL DEFAULT ''",
    },
    "worker_reservations": {
        "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
        "capacity_pool": "TEXT NOT NULL DEFAULT ''",
        "spec_hash": "TEXT NOT NULL DEFAULT ''",
    },
    "routed_executions": {
        "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
        "capacity_pool": "TEXT NOT NULL DEFAULT ''",
        "spec_hash": "TEXT NOT NULL DEFAULT ''",
    },
}

_REQUIRED = {
    "reservations": "id request_key owner_pid owner_started tool_use_id repo command_signature command_text resource_class priority priority_rank cpu_units ram_gib io_slots created_at heartbeat_at expires_at spec_hash",
    "executions": "id reservation_id request_key owner_pid repo command_signature resource_class priority cpu_units ram_gib io_slots started_at ended_at outcome",
    "workers": "id provider failure_domain capacity_scope capacity_pool max_concurrency quota_domain state automation_level os capacity_ram_gib allocatable_ram_gib visible_cpu allocatable_cpu disk_free_gib allocatable_disk_gib capabilities_json trust_domain source observed_at probe_expires_at updated_at",
    "worker_reservations": "id task_id worker_id failure_domain capacity_scope capacity_pool spec_hash ram_gib cpu_units disk_gib created_at heartbeat_at expires_at metadata_json",
    "routed_executions": "id reservation_id task_id worker_id failure_domain capacity_scope capacity_pool spec_hash ram_gib cpu_units disk_gib started_at ended_at outcome metadata_json",
}

_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_exec_signature ON executions(command_signature, ended_at)",
    "CREATE INDEX IF NOT EXISTS idx_workers_domain ON workers(failure_domain)",
    "CREATE INDEX IF NOT EXISTS idx_worker_res_domain ON worker_reservations(failure_domain, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_worker_res_pool ON worker_reservations(capacity_pool, expires_at)",
    "CREATE INDEX IF NOT EXISTS idx_worker_res_worker ON worker_reservations(worker_id)",
)


def prepare_capacity_schema(conn: sqlite3.Connection) -> None:
    """Prepare both real ledgers after version checks, under the writer lock.

    Only the documented historical additive columns receive defaults. An
    existing table missing other required columns is an unsupported shape;
    migration must roll back rather than invent identities or resource values.
    The caller owns commit/rollback and installs adaptive columns/guards before
    releasing its transaction. No executescript implicit commit is permitted.
    """
    if not conn.in_transaction:
        raise ValueError("capacity_schema_requires_transaction")
    for statement in _CREATE.split(";"):
        if statement.strip():
            conn.execute(statement)
    for table, additions in _ADDITIONS.items():
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, declaration in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")
    for table, required in _REQUIRED.items():
        columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not set(required.split()) <= columns:
            raise ValueError("capacity_schema_incomplete")
    for statement in _INDEXES:
        conn.execute(statement)
