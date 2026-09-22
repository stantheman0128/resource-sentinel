"""Historical C2 post-close custody proof, never new retirement authority.

Capture only the original live pending owner after clean native proof. Publish
after its actual handles close positively; no missing handle is called closed.
FINISHED keeps the independent four-owner terminal custody contract.
"""
from __future__ import annotations

import math

from .contracts import RecoveryManifest
from .policy import PolicyBinding, PolicyError
from .store import LifecycleError, _coverage_read_transaction, _RETIREMENT_FIELDS
from .supervisor_reconcile import RetainedPolicyOperation
from . import terminal_receipt as terminal


_TABLE = "adaptive_prelaunch_custody_receipts"
_STATES = frozenset({"CANCELLED_BEFORE_START", "START_FAILED"})
_OWNERS = ("job", "wrapper", "mutex")
_SCHEMA = terminal._SCHEMA.replace(terminal._TABLE, _TABLE)


def _schema(conn, *, create=False):
    found = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    if found is None:
        if not create:
            return False
        conn.execute(_SCHEMA)
        found = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    if (found[0] != "table" or type(found[1]) is not str or
            " ".join(found[1].split()) != " ".join(_SCHEMA.split()) or
            tuple(row[1] for row in conn.execute(f"PRAGMA table_info({_TABLE})")) != terminal._COLUMNS):
        raise LifecycleError("prelaunch_custody_schema_invalid")
    return True


def _proof(conn, store, expected, manifest):
    _, manifest = store._retained_inputs(expected, manifest)
    row = store._get(conn, manifest.execution_id)
    if store._public(row) != dict(expected):
        raise LifecycleError("prelaunch_custody_row_changed")
    finished = row["finished_at"]
    if (row["state"] not in _STATES or row["allocation_kind"] != "direct" or
            row["parent_execution_id"] is not None or row["launch_sealed"] != 1 or
            row["launch_in_flight"] != 0 or type(finished) not in (int, float) or
            not math.isfinite(finished) or finished < 0):
        raise LifecycleError("prelaunch_custody_terminal_unverified")
    # Includes rootlessness, last_applied=None, zero lifetime/fence semantics,
    # exact original guardian/epoch/nonce and destroyed one-use credential.
    store._assert_prelaunch_receipt(conn, row, manifest)
    retirement = dict(conn.execute("SELECT " + ",".join(_RETIREMENT_FIELDS) +
        " FROM adaptive_prelaunch_retirements WHERE execution_id=?", (row["execution_id"],)).fetchone())
    if (conn.execute("SELECT count(*) FROM reservations WHERE execution_id=? OR id=?",
            (row["execution_id"], row["reservation_id"])).fetchone()[0] != 0 or
            conn.execute("SELECT count(*) FROM worker_reservations WHERE execution_id=?",
                (row["execution_id"],)).fetchone()[0] != 0 or
            conn.execute("""SELECT count(*) FROM managed_executions WHERE execution_id=? OR
                (reservation_id=? AND (allocation_kind='direct' OR allocation_kind IS NULL OR
                                      allocation_kind NOT IN ('direct','routed')))""",
                (row["execution_id"], row["reservation_id"])).fetchone()[0] != 1):
        raise LifecycleError("prelaunch_custody_allocation_unverified")
    archives = conn.execute("SELECT * FROM executions WHERE reservation_id=? LIMIT 2",
                            (row["reservation_id"],)).fetchall()
    if len(archives) != 1:
        raise LifecycleError("prelaunch_custody_archive_unverified")
    archive = dict(archives[0])
    if (archive["outcome"] != "managed_" + row["state"].lower() or
            archive["ended_at"] != finished or archive["cpu_units"] != row["requested_cpu_units"] or
            archive["io_slots"] != row["requested_io_slots"]):
        raise LifecycleError("prelaunch_custody_archive_unverified")
    for field in ("started_at", "ram_gib"):
        value = archive[field]
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            raise LifecycleError("prelaunch_custody_archive_unverified")
    if archive["started_at"] > finished or conn.execute("""SELECT 1 FROM queue
            WHERE managed_execution_id=? OR request_key=? LIMIT 1""",
            (row["execution_id"], archive["request_key"])).fetchone() is not None:
        raise LifecycleError("prelaunch_custody_archive_unverified")
    return archive, retirement


def _body(row, manifest, binding, registry_revision, archive, retirement):
    if (type(binding) is not PolicyBinding or binding.logon_id != manifest.guardian_identity.logon_id or
            type(registry_revision) is not int or registry_revision < 0):
        raise LifecycleError("prelaunch_custody_binding_invalid")
    never_created = retirement["evidence_kind"] == "never-created"
    return {
        "schema_version": 1, "evidence_kind": "guardian_prelaunch_custody_closed",
        "execution_id": row["execution_id"], "state": row["state"],
        "state_revision": row["state_revision"], "terminal_row_hash": terminal._digest(dict(row)),
        "manifest_seq": manifest.manifest_seq, "manifest_hash": manifest.manifest_hash,
        "policy_instance_id": binding.instance_id, "policy_logon_id": binding.logon_id,
        "guardian_epoch": manifest.guardian_epoch, "registry_revision": registry_revision,
        "guardian_identity": manifest.guardian_identity.to_dict(),
        "wrapper_identity": manifest.wrapper_identity.to_dict(),
        "root_identity": None, "root_disposition": "never-created",
        "job_name": manifest.job_name, "job_nonce": manifest.creation_nonce,
        "job_disposition": "never-created" if never_created else "closed",
        "reservation": manifest.reservation.to_dict(), "spec_hash": manifest.spec_hash,
        "allocated_floor": manifest.allocated_floor.to_dict(),
        "closed_owners": [name for name in _OWNERS if name != "job" or not never_created],
        "retirement_hash": terminal._digest(retirement), "archive_hash": terminal._digest(archive),
    }


def _verified_record(conn, store, row, manifest):
    if not _schema(conn):
        raise LifecycleError("prelaunch_custody_receipt_missing")
    record = conn.execute(f"SELECT * FROM {_TABLE} WHERE execution_id=?", (row["execution_id"],)).fetchone()
    if record is None:
        raise LifecycleError("prelaunch_custody_receipt_missing")
    try:
        binding = PolicyBinding(record["policy_instance_id"], record["policy_logon_id"])
        if store._policy._binding(store._policy._runtime(conn), binding.logon_id) != binding:
            raise LifecycleError("prelaunch_custody_binding_changed")
        archive, retirement = _proof(conn, store, row, manifest)
        expected = _body(row, manifest, binding, record["registry_revision"], archive, retirement)
        if tuple(record) != terminal._values(expected):
            raise LifecycleError("prelaunch_custody_receipt_changed")
    except (TypeError, ValueError, KeyError, OverflowError, PolicyError):
        raise LifecycleError("prelaunch_custody_receipt_invalid") from None
    return expected


def assert_prelaunch_custody_receipt(store, journal, row):
    """Read exact historical C2 closure, allowing later runtime epochs only."""
    if type(row) is not dict or row.get("state") not in _STATES:
        raise LifecycleError("prelaunch_custody_terminal_unverified")
    manifest = journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
    if type(manifest) is not RecoveryManifest:
        raise LifecycleError("prelaunch_custody_manifest_invalid")
    with _coverage_read_transaction(terminal._ledger_path(store)) as conn:
        return _verified_record(conn, store, row, manifest)


def assert_closed_custody_receipt(store, journal, row):
    """Select the original terminal-state proof without coercing C2 to FINISHED."""
    if isinstance(row, dict) and row.get("state") in _STATES:
        return assert_prelaunch_custody_receipt(store, journal, row)
    return terminal.assert_terminal_custody_receipt(store, journal, row)


class PrelaunchReceiptOperation(terminal.TerminalReceiptOperation):
    """Capture before cleanup; inherited POLICY retry runs only after closure."""

    def __init__(self, owner, entry, row, manifest, binding):
        from .guardian import _PendingExecution
        if (type(entry) is not _PendingExecution or owner._pending.get(entry.execution_id) is not entry or
                owner.lifecycle._scope_entry is not None or entry.root is not None or
                not entry.retirement_sealed or entry.closed_handles or
                type(binding) is not PolicyBinding or getattr(owner.store, "existing_path", False) is not True):
            raise LifecycleError("prelaunch_custody_original_owner_required")
        self.owner, self.lifecycle, self.store = owner, owner.lifecycle, owner.store
        self.custody = self
        self.execution_id = entry.execution_id
        self.row, self.manifest, self.binding = dict(row), manifest, binding
        self.owners = {name: getattr(entry, name) for name in _OWNERS}
        self._entry = entry
        self._operation = RetainedPolicyOperation(self.store)
        self._candidate = None
        self._proof_hashes = None
        owner._check_entry(entry, self.row)
        if entry.record != manifest or manifest.guardian_identity != owner.guardian.identity:
            raise LifecycleError("prelaunch_custody_original_owner_required")
        if self.owners["wrapper"] is None or self.owners["mutex"] is None:
            raise LifecycleError("prelaunch_custody_original_owner_required")

    def verify(self, entry):
        # The operation is already attached before any I/O or native probe.
        # Keep interrupted/uncertain verification evidence on that same owner.
        if self._operation._quarantine:
            # A refusal must not replace the original exception that may retain
            # the only connection or native cleanup owner.
            raise LifecycleError("prelaunch_custody_cleanup_unverified")
        try:
            self._verify(entry)
        except BaseException as error:
            self._operation._error = error
            if (not isinstance(error, Exception) or hasattr(error, "_journal_cleanup_owner") or
                    "coverage_reader_cleanup_failed" in getattr(error, "__notes__", ())):
                self._operation._quarantine = "prelaunch_custody_cleanup_unverified"
            raise

    def _verify(self, entry):
        self.lifecycle._validate_guardian()
        if (entry is not self._entry or self.owner._pending.get(self.execution_id) is not entry or
                getattr(entry, "retirement_receipt_operation", None) is not self or
                not entry.retirement_cleanup_started or not entry.retirement_sealed or entry.root is not None or
                self.owner.guardian.identity != self.manifest.guardian_identity or
                entry.wrapper.identity != self.manifest.wrapper_identity or
                any(getattr(entry, name) is not original for name, original in self.owners.items())):
            raise LifecycleError("prelaunch_custody_original_owner_required")
        if entry.journal_cleanup_error is not None or entry.retirement_mutex_close_unknown:
            raise LifecycleError("prelaunch_custody_cleanup_unverified")
        try:
            manifest = self.owner.journal.read(self.execution_id, creation_nonce=self.manifest.creation_nonce)
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise
        if manifest != self.manifest or entry.record != self.manifest:
            raise LifecycleError("prelaunch_custody_manifest_changed")
        with _coverage_read_transaction(terminal._ledger_path(self.store)) as conn:
            self._runtime(conn)
            archive, retirement = _proof(conn, self.store, self.row, manifest)
        hashes = (terminal._digest(archive), terminal._digest(retirement))
        if self._proof_hashes is None:
            never_created = retirement["evidence_kind"] == "never-created"
            if (entry.closed_handles or
                    (never_created and (entry.create_attempted or self.owners["job"] is not None)) or
                    (not never_created and (not entry.create_attempted or self.owners["job"] is None))):
                raise LifecycleError("prelaunch_custody_original_owner_required")
            self._proof_hashes = hashes
        if hashes != self._proof_hashes:
            raise LifecycleError("prelaunch_custody_proof_changed")

    def _authority(self):
        self.verify(self._entry)
        required = {name for name, original in self.owners.items() if original is not None}
        if self._entry.closed_handles != required:
            raise LifecycleError("prelaunch_custody_close_incomplete")

    def _reconciled(self):
        self._authority()
        if self._candidate is None:
            return False
        with _coverage_read_transaction(terminal._ledger_path(self.store)) as conn:
            self._runtime(conn)
            if not _schema(conn) or conn.execute(f"SELECT 1 FROM {_TABLE} WHERE execution_id=?",
                    (self.execution_id,)).fetchone() is None:
                return False
            if _verified_record(conn, self.store, self.row, self.manifest) != self._candidate:
                raise LifecycleError("prelaunch_custody_attempt_changed")
        self._operation._changed = True
        return True

    def _write(self, guard):
        self._authority()
        self.store._policy.assert_held(guard)
        if self._reconciled():
            return True
        if self._candidate is None:
            with _coverage_read_transaction(terminal._ledger_path(self.store)) as conn:
                runtime = self._runtime(conn, guard)
                archive, retirement = _proof(conn, self.store, self.row, self.manifest)
                self._candidate = _body(self.row, self.manifest, self.binding,
                    runtime["registry_revision"], archive, retirement)
        with self.store._transaction() as conn:
            runtime = self._runtime(conn, guard)
            archive, retirement = _proof(conn, self.store, self.row, self.manifest)
            if _body(self.row, self.manifest, self.binding, runtime["registry_revision"],
                     archive, retirement) != self._candidate:
                raise LifecycleError("prelaunch_custody_attempt_changed")
            _schema(conn, create=True)
            values = terminal._values(self._candidate)
            previous = conn.execute(f"SELECT * FROM {_TABLE} WHERE execution_id=?", (self.execution_id,)).fetchone()
            if previous is not None:
                if tuple(previous) != values:
                    raise LifecycleError("prelaunch_custody_attempt_changed")
                return True
            inserted = conn.execute(f"""INSERT INTO {_TABLE}
                SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (
                    SELECT 1 FROM adaptive_runtime WHERE singleton=1 AND policy_instance_id=?
                    AND policy_logon_id=? AND policy_entry_nonce=? AND guardian_epoch=? AND registry_revision=?)
                AND EXISTS (SELECT 1 FROM managed_executions WHERE execution_id=?
                    AND state=? AND state_revision=? AND job_nonce=?)""",
                values + (self.binding.instance_id, self.binding.logon_id, guard.nonce,
                          self.manifest.guardian_epoch, self._candidate["registry_revision"],
                          self.execution_id, self.row["state"], self.row["state_revision"], self.manifest.creation_nonce))
            if inserted.rowcount != 1 or _verified_record(conn, self.store, self.row, self.manifest) != self._candidate:
                raise LifecycleError("prelaunch_custody_attempt_changed")
        return True
