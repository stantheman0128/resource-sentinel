"""Durable acknowledgement of an original guardian's completed native custody.

This receipt is historical retirement evidence, never launch, restore or release
authority. Only the retained post-proof cleanup owner can publish it, after all
four original native owners closed positively. Retrying uses its original POLICY
operation; observing FINISHED or a missing allocation cannot manufacture one.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from .contracts import CpuControl, CpuControlMode, RecoveryManifest
from .policy import PolicyBinding, PolicyError
from .store import LifecycleError, _coverage_read_transaction
from .supervisor_reconcile import RetainedPolicyOperation


_TABLE = "adaptive_terminal_custody_receipts"
_OWNERS = ("root", "wrapper", "job", "mutex")
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_COLUMNS = ("execution_id", "schema_version", "state_revision", "manifest_seq",
            "manifest_hash", "policy_instance_id", "policy_logon_id", "guardian_epoch",
            "registry_revision", "receipt_json", "receipt_hash")
_SCHEMA = """CREATE TABLE adaptive_terminal_custody_receipts (
    execution_id TEXT PRIMARY KEY NOT NULL,
    schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
    state_revision INTEGER NOT NULL CHECK(typeof(state_revision)='integer' AND state_revision>=0),
    manifest_seq INTEGER NOT NULL CHECK(typeof(manifest_seq)='integer' AND manifest_seq>=0),
    manifest_hash TEXT NOT NULL, policy_instance_id TEXT NOT NULL,
    policy_logon_id TEXT NOT NULL, guardian_epoch TEXT NOT NULL,
    registry_revision INTEGER NOT NULL CHECK(typeof(registry_revision)='integer' AND registry_revision>=0),
    receipt_json TEXT NOT NULL, receipt_hash TEXT NOT NULL,
    FOREIGN KEY(execution_id) REFERENCES managed_executions(execution_id))"""


def _canonical(value):
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise LifecycleError("terminal_receipt_invalid") from None
    if len(encoded) > 65536:
        raise LifecycleError("terminal_receipt_invalid")
    return encoded


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _schema(conn, *, create=False):
    found = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    if found is None:
        if not create:
            return False
        conn.execute(_SCHEMA)
        found = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    # Do not accept a lookalike table missing the primary-key or CHECK rules.
    if (found[0] != "table" or type(found[1]) is not str or
            " ".join(found[1].split()) != " ".join(_SCHEMA.split()) or
            tuple(row[1] for row in conn.execute(f"PRAGMA table_info({_TABLE})")) != _COLUMNS):
        raise LifecycleError("terminal_receipt_schema_invalid")
    return True


def _ledger_path(store):
    try:
        return getattr(store, "_existing_ledger_path", None) or Path(store.db_path).resolve()
    except (OSError, TypeError, ValueError, RuntimeError):
        raise LifecycleError("coverage_registry_unavailable") from None


def _terminal_proof(conn, store, row, manifest):
    """Exact terminal/archive validation in the caller's one SQLite snapshot."""
    _, manifest = store._retained_inputs(row, manifest)
    current = store._public(store._get(conn, manifest.execution_id))
    if current != dict(row):
        raise LifecycleError("terminal_receipt_row_changed")
    finished = row.get("finished_at")
    if (row["state"] != "FINISHED" or row["launch_sealed"] != 1 or
            row["launch_in_flight"] != 0 or row["claim_consumed"] != 1 or
            row["parent_execution_id"] is not None or manifest.root_identity is None or
            manifest.original != _DISABLED or manifest.pending_intent is not None or
            manifest.last_applied not in (None, _DISABLED) or
            type(finished) not in (int, float) or not math.isfinite(finished) or finished < 0):
        raise LifecycleError("terminal_receipt_terminal_unverified")
    kind = row["allocation_kind"]
    if kind not in {"direct", "routed"}:
        raise LifecycleError("terminal_receipt_terminal_unverified")
    own = "reservations" if kind == "direct" else "worker_reservations"
    other = "worker_reservations" if kind == "direct" else "reservations"
    if (conn.execute(f"SELECT count(*) FROM {own} WHERE execution_id=? OR id=?",
            (manifest.execution_id, row["reservation_id"])).fetchone()[0] != 0 or
            conn.execute(f"SELECT count(*) FROM {other} WHERE execution_id=?",
                (manifest.execution_id,)).fetchone()[0] != 0 or
            conn.execute("""SELECT count(*) FROM managed_executions WHERE execution_id=? OR
                (reservation_id=? AND (allocation_kind=? OR allocation_kind IS NULL OR
                                      allocation_kind NOT IN ('direct','routed')))""",
                (manifest.execution_id, row["reservation_id"], kind)).fetchone()[0] != 1):
        raise LifecycleError("terminal_receipt_terminal_unverified")
    table = "executions" if kind == "direct" else "routed_executions"
    columns = "outcome,ended_at,cpu_units,started_at,ram_gib," + (
        "io_slots" if kind == "direct" else "task_id,spec_hash")
    archives = conn.execute(f"SELECT {columns} FROM {table} WHERE reservation_id=? LIMIT 2",
                            (row["reservation_id"],)).fetchall()
    if len(archives) != 1:
        raise LifecycleError("terminal_receipt_archive_unverified")
    archive = dict(archives[0])
    if (archive["outcome"] != "managed_finished" or archive["ended_at"] != finished or
            archive["cpu_units"] != row["requested_cpu_units"] or
            (kind == "direct" and archive["io_slots"] != row["requested_io_slots"]) or
            (kind == "routed" and (archive["task_id"] != row["task_id"] or
                                   archive["spec_hash"] != row["spec_hash"]))):
        raise LifecycleError("terminal_receipt_archive_unverified")
    for name in ("started_at", "ram_gib"):
        value = archive[name]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise LifecycleError("terminal_receipt_archive_unverified")
    if archive["started_at"] > finished:
        raise LifecycleError("terminal_receipt_archive_unverified")
    return archive


def _body(row, manifest, binding, registry_revision, archive):
    if (type(binding) is not PolicyBinding or binding.logon_id != manifest.guardian_identity.logon_id or
            type(registry_revision) is not int or registry_revision < 0):
        raise LifecycleError("terminal_receipt_binding_invalid")
    return {
        "schema_version": 1, "evidence_kind": "guardian_terminal_custody_closed",
        "execution_id": row["execution_id"], "state": "FINISHED",
        "state_revision": row["state_revision"], "terminal_row_hash": _digest(dict(row)),
        "manifest_seq": manifest.manifest_seq, "manifest_hash": manifest.manifest_hash,
        "policy_instance_id": binding.instance_id, "policy_logon_id": binding.logon_id,
        "guardian_epoch": manifest.guardian_epoch, "registry_revision": registry_revision,
        "guardian_identity": manifest.guardian_identity.to_dict(),
        "wrapper_identity": manifest.wrapper_identity.to_dict(),
        "root_identity": manifest.root_identity.to_dict(),
        "job_name": manifest.job_name, "job_nonce": manifest.creation_nonce,
        "reservation": manifest.reservation.to_dict(), "spec_hash": manifest.spec_hash,
        "allocated_floor": manifest.allocated_floor.to_dict(),
        "closed_owners": list(_OWNERS), "archive_hash": _digest(archive),
    }


def _values(body):
    encoded = _canonical(body)
    return (body["execution_id"], 1, body["state_revision"], body["manifest_seq"],
            body["manifest_hash"], body["policy_instance_id"], body["policy_logon_id"],
            body["guardian_epoch"], body["registry_revision"], encoded,
            hashlib.sha256(encoded.encode("utf-8")).hexdigest())


def _verified_record(conn, store, row, manifest):
    if not _schema(conn):
        raise LifecycleError("terminal_receipt_missing")
    record = conn.execute(f"SELECT * FROM {_TABLE} WHERE execution_id=?",
                          (row["execution_id"],)).fetchone()
    if record is None:
        raise LifecycleError("terminal_receipt_missing")
    try:
        binding = PolicyBinding(record["policy_instance_id"], record["policy_logon_id"])
        runtime = store._policy._runtime(conn)
        if store._policy._binding(runtime, binding.logon_id) != binding:
            raise LifecycleError("terminal_receipt_binding_changed")
        archive = _terminal_proof(conn, store, row, manifest)
        expected = _body(row, manifest, binding, record["registry_revision"], archive)
        if tuple(record) != _values(expected):
            raise LifecycleError("terminal_receipt_changed")
    except (TypeError, ValueError, KeyError, OverflowError, PolicyError):
        raise LifecycleError("terminal_receipt_invalid") from None
    return expected


def assert_terminal_custody_receipt(store, journal, row):
    """Read historical closure proof without acquiring native mutation authority.

    Uses a read-only connection, never a migration-owning service. A later
    runtime epoch is permitted: the receipt binds the original manifest epoch.
    This proves no current native observation and cannot clear any barrier.
    """
    if not isinstance(row, dict) or row.get("state") != "FINISHED":
        raise LifecycleError("terminal_receipt_terminal_unverified")
    manifest = journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
    if type(manifest) is not RecoveryManifest:
        raise LifecycleError("terminal_receipt_manifest_invalid")
    with _coverage_read_transaction(_ledger_path(store)) as conn:
        return _verified_record(conn, store, row, manifest)


class TerminalReceiptOperation:
    """One retained acknowledgement, after positive closure of original owners."""

    def __init__(self, lifecycle, custody):
        from .terminal_custody import TerminalCustody
        if (type(custody) is not TerminalCustody or getattr(custody, "proof_published", False) is not True or
                custody.native_complete is not True or custody.closed_owners != _OWNERS or
                custody.quarantined or getattr(lifecycle.store, "existing_path", False) is not True):
            raise LifecycleError("terminal_receipt_original_custody_required")
        self.lifecycle, self.custody = lifecycle, custody
        self.store = lifecycle.store
        self._operation = RetainedPolicyOperation(self.store)
        self._candidate = None
        self._entry = None

    @property
    def guard(self):
        return self._operation.guard

    @property
    def pending(self):
        return self._operation.pending

    @property
    def _error(self):
        return self._operation._error

    def _authority(self):
        custody, entry = self.custody, self._entry
        if (entry is None or self.lifecycle._entries.get(custody.execution_id) is not entry or
                entry.terminal_cleanup is not custody or
                custody.proof_published is not True or custody.native_complete is not True or
                custody.closed_owners != _OWNERS or custody.quarantined):
            raise LifecycleError("terminal_receipt_original_custody_required")
        # The retained owner verifies the alive original guardian, immutable
        # proof, and row/archive; it never touches already closed native owners.
        custody.verify(self.lifecycle, entry)

    def _runtime(self, conn, guard=None):
        policy = self.store._policy
        runtime = policy._runtime(conn) if guard is None else policy.revalidate(conn, guard)
        if (policy._binding(runtime, self.custody.binding.logon_id) != self.custody.binding or
                runtime["guardian_epoch"] != self.custody.manifest.guardian_epoch or
                runtime["active_logon_id"] != self.custody.binding.logon_id):
            raise LifecycleError("terminal_receipt_binding_changed")
        return runtime

    def _reconciled(self):
        self._authority()
        if self._candidate is None:
            return False
        with _coverage_read_transaction(_ledger_path(self.store)) as conn:
            self._runtime(conn)
            if not _schema(conn):
                return False
            record = conn.execute(f"SELECT * FROM {_TABLE} WHERE execution_id=?",
                                  (self.custody.execution_id,)).fetchone()
            if record is None:
                return False
            actual = _verified_record(conn, self.store, self.custody.row, self.custody.manifest)
            if actual != self._candidate:
                raise LifecycleError("terminal_receipt_attempt_changed")
        self._operation._changed = True
        return True

    def _write(self, guard):
        self._authority()
        policy = self.store._policy
        policy.assert_held(guard)
        if self._reconciled():
            return True
        if self._candidate is None:
            with _coverage_read_transaction(_ledger_path(self.store)) as conn:
                runtime = self._runtime(conn, guard)
                archive = _terminal_proof(conn, self.store, self.custody.row, self.custody.manifest)
                # Publish before the write/commit cutpoint. A lost ACK must
                # reconcile this exact body, never a newly sampled revision.
                self._candidate = _body(self.custody.row, self.custody.manifest,
                    self.custody.binding, runtime["registry_revision"], archive)
        with self.store._transaction() as conn:
            runtime = self._runtime(conn, guard)
            archive = _terminal_proof(conn, self.store, self.custody.row, self.custody.manifest)
            if _body(self.custody.row, self.custody.manifest, self.custody.binding,
                     runtime["registry_revision"], archive) != self._candidate:
                raise LifecycleError("terminal_receipt_attempt_changed")
            _schema(conn, create=True)
            previous = conn.execute(f"SELECT * FROM {_TABLE} WHERE execution_id=?",
                                    (self.custody.execution_id,)).fetchone()
            values = _values(self._candidate)
            if previous is not None:
                if tuple(previous) != values:
                    raise LifecycleError("terminal_receipt_attempt_changed")
                return True
            inserted = conn.execute(f"""INSERT INTO {_TABLE}
                SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (
                    SELECT 1 FROM adaptive_runtime WHERE singleton=1
                    AND policy_instance_id=? AND policy_logon_id=? AND policy_entry_nonce=?
                    AND guardian_epoch=? AND registry_revision=?)
                AND EXISTS (SELECT 1 FROM managed_executions WHERE execution_id=?
                    AND state='FINISHED' AND state_revision=? AND job_nonce=?)""",
                values + (self.custody.binding.instance_id, self.custody.binding.logon_id,
                          guard.nonce, self.custody.manifest.guardian_epoch,
                          self._candidate["registry_revision"], self.custody.execution_id,
                          self.custody.row["state_revision"], self.custody.manifest.creation_nonce))
            if inserted.rowcount != 1:
                raise LifecycleError("terminal_receipt_attempt_changed")
            if _verified_record(conn, self.store, self.custody.row, self.custody.manifest) != self._candidate:
                raise LifecycleError("terminal_receipt_attempt_changed")
        return True

    def tick(self, entry):
        """One bounded POLICY attempt; removal requires its clean completion."""
        with self.lifecycle._lock:
            if self._entry is None:
                self._entry = entry
            elif self._entry is not entry:
                return self._operation._pending("terminal_receipt_custody_changed", quarantine=True)
            if self._operation._quarantine:
                return self._operation._pending(self._operation._quarantine, quarantine=True)
            try:
                self._authority()
                if self._operation._complete and not self._reconciled():
                    return self._operation._pending("terminal_receipt_missing", quarantine=True)
            except BaseException as error:
                return self._operation._failure(error)
            return self._operation._run(self.custody.binding.logon_id,
                lambda: self._write(self.guard), self._reconciled)
