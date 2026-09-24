"""Explicit installed-source activation and a resident daily generation keeper.

This is called only after the separately reviewed canonical-source installation.
It uses the real daily ledger, starts its SupervisorHost in off mode, and never
enables control, changes configuration, creates a Scheduled Task, or kills a
process. A source manifest is a comparison input, not activation authority.
Original cohort, process, POLICY and SQL custody supply that authority.

One non-daemon thread serves read-only readiness in this same process so a child
can authenticate its original keeper during supervisor startup. Its one-resource
pipe registry is strongly owned independently of the supervisor's pipe registry.
Draining CPU control alone cannot retire daily accounting obligations. Only an
explicit retirement request on this original host, its acknowledged freeze and
seal, and positive cleanup of every retained owner permit a clean process exit.
Retirement leaves daily admission fenced; it is not an automatic restart path.
"""
from __future__ import annotations

import argparse
import importlib
from pathlib import Path
import sqlite3
import sys
import threading
import time

from . import daily_generation as generation
from .daily_cohort import CohortUnavailable
from .daily_readiness_transport import DailyReadinessService, LedgerFileIdentity
from .host_authority import read_host_capability
from .ipc import _hex
from .pipe_windows import NativePipeListener, NativePipeRegistry
from .store import LifecycleStore, migrate_schema
from .supervisor_host import SupervisorHost, emit


_MODULE_ROOT = Path(__file__).resolve().parents[2]
_BASE_PYTHON = Path("C:/Python313/python.exe")
_PRELOAD = (
    "recovery_journal", "supervisor_reconcile", "supervisor_startup",
    "host_discovery", "operator_transport", "supervisor_operations",
    "recovery_owner", "supervisor", "supervisor_epoch",
    "daily_retirement",
)
_EMPTY_TABLES = ("reservations", "worker_reservations", "queue", "managed_executions")


class DailyActivationError(RuntimeError):
    def __init__(self, reason, host=None):
        self.reason, self.host = reason, host
        super().__init__(reason)


def _reason(error):
    return _reason_text(getattr(error, "reason", None))


def _reason_text(reason):
    if type(reason) is str and 0 < len(reason) <= 128 and all(
            char in "abcdefghijklmnopqrstuvwxyz0123456789_" for char in reason):
        return reason
    return "daily_activation_unverified"


class _ConnectionCustody:
    """Own the exact SQL object; a failed close is never retried as proof."""

    def __init__(self, connection):
        self.connection = connection
        self.closed = self.close_unknown = False

    def close(self):
        if self.closed:
            return
        if self.close_unknown:
            raise DailyActivationError("daily_activation_connection_close_unknown")
        self.close_unknown = True
        self.connection.close()
        self.closed, self.close_unknown = True, False


class DailyActivationHost:
    """Single original keeper; no authority callbacks or alternate locations."""

    def __init__(self, manifest, expected_config_digest, expected_ledger_identity, *, retire_after_drain=False):
        if type(manifest) is not generation.SourceManifest:
            raise DailyActivationError("daily_activation_manifest_required")
        _hex(expected_config_digest)
        if type(expected_ledger_identity) is not LedgerFileIdentity:
            raise DailyActivationError("daily_activation_ledger_identity_required")
        if type(retire_after_drain) is not bool:
            raise DailyActivationError("daily_activation_retirement_intent_invalid")
        self.manifest = manifest
        self.expected_config_digest = expected_config_digest
        self.expected_ledger_identity = expected_ledger_identity
        self.source_root, self.data_dir = generation.daily_locations()
        self.source_root, self.data_dir = Path(self.source_root), Path(self.data_dir)
        self.ledger_path = self.data_dir / "sentinel.db"
        self.journal_dir = self.data_dir / "adaptive-journal"
        self.owner = self.store = self.guard = self.supervisor = None
        self._connections = []
        self._migration_attempted = self._install_attempted = False
        self._start_attempted = self._supervisor_attempted = False
        self._failure = self._readiness_failure = None
        self._thread = self._listener = self._service = self._registry = None
        self._readiness_original_thread = self._readiness_original_listener = None
        self._readiness_original_registry = None
        self._listener_ready = threading.Event()
        self._thread_stopped = threading.Event()
        self._readiness_start_attempted = False
        self._readiness_stop = threading.Event()
        self._readiness_joined = self._readiness_listener_closed = False
        self._readiness_close_unknown = self._readiness_cleanup_complete = False
        self._readiness_close_attempted = False
        self._retirement_cleanup_error = None
        self._retirement = None
        self._retirement_creation_attempted = False
        self._retire_after_drain = retire_after_drain
        self._native_custody_possible = False
        self._supervisor_closed = False
        self._generation_settled = False
        self._waiting_for_cohort = False
        self._waiting_owner = self._waiting_cohort = None
        self._supervisor_state = self._supervisor_reason = None
        self._draining = False
        self._phase = "unstarted"

    def _retain_failure(self, error):
        self._waiting_for_cohort = False
        if self._failure is None:
            self._failure = error
        error.daily_activation_host = self
        self._phase = "custody_retained"

    def _defer_known_live_cohort(self, error):
        """Only a positive pre-SQL live observation permits the same-owner retry."""
        if (type(error) is not CohortUnavailable or
                error.reason != "cohort_ambiguous_consumers_still_alive" or
                self.owner is None or error.cohort is not self.owner.cohort or
                self._migration_attempted or self._install_attempted or
                any(not item.closed or item.close_unknown for item in self._connections) or
                self._failure is not None):
            return False
        if self._waiting_owner is not None and (
                self.owner is not self._waiting_owner or self.owner.cohort is not self._waiting_cohort):
            return False
        self._waiting_owner, self._waiting_cohort = self.owner, self.owner.cohort
        self._waiting_for_cohort = True
        self._phase = "waiting_for_old_cohort"
        return True

    def _continue_startup(self):
        # _migrate_once revalidates the pinned source/config/file identity and
        # refreshes the very same retained cohort before opening any SQL handle.
        self._migrate_once()
        self._waiting_for_cohort = False
        self._install_once()
        self._start_readiness()
        self._listener_ready.wait(1.0)

    def _observe_supervisor_record(self, record):
        record = record if type(record) is dict else {}
        cold_reason = getattr(self.supervisor, "cold_reason", None)
        if record.get("state") == "COLD_RECOVERY_HOLD" or type(cold_reason) is str:
            self._supervisor_state = "supervisor_cold_recovery_hold"
            reason = cold_reason if type(cold_reason) is str else record.get("reason")
            self._supervisor_reason = _reason_text(reason)
        elif record.get("attached") is False or record.get("guardian_status") == "unattached":
            self._supervisor_state = "supervisor_attach_pending"
            self._supervisor_reason = "supervisor_host_attach_pending"
        else:
            self._supervisor_state, self._supervisor_reason = "resident", None
        if not self._draining and self._failure is None and self._readiness_failure is None:
            self._phase = self._supervisor_state

    def _assert_prepared_binding(self):
        if self.source_root.resolve(strict=True) != _MODULE_ROOT.resolve(strict=True):
            raise DailyActivationError("daily_activation_installed_source_required", self)
        if Path(sys.executable).resolve() != _BASE_PYTHON.resolve():
            raise DailyActivationError("daily_activation_base_python_required", self)
        generation._assert_daily_locations(self.source_root, self.ledger_path)
        if LedgerFileIdentity.capture(self.ledger_path) != self.expected_ledger_identity:
            raise DailyActivationError("daily_activation_ledger_binding_changed", self)
        if generation._fixed_policy_digest(self.ledger_path) != self.expected_config_digest:
            raise DailyActivationError("daily_activation_config_binding_changed", self)
        generation.verify_import_provenance(self.manifest, self.source_root)

    def _open(self, *, readonly=False):
        connection = sqlite3.connect(self.ledger_path.resolve(strict=True).as_uri() +
            ("?mode=ro" if readonly else "?mode=rw"), uri=True,
            timeout=.25, isolation_level=None)
        custody = _ConnectionCustody(connection)
        self._connections.append(custody)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=250")
        return custody

    def _empty_preflight(self, connection):
        names = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "adaptive_daily_generation" in names:
            # Even an empty/damaged/retired old generation is not cold adoption.
            raise DailyActivationError("daily_activation_existing_generation", self)
        if "reservations" not in names or "queue" not in names:
            raise DailyActivationError("daily_activation_legacy_schema_unverified", self)
        for table in _EMPTY_TABLES:
            if table in names and connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                raise DailyActivationError("daily_activation_allocations_not_empty", self)
        if "adaptive_runtime" in names:
            rows = connection.execute("SELECT * FROM adaptive_runtime LIMIT 2").fetchall()
            if len(rows) != 1:
                raise DailyActivationError("daily_activation_runtime_unverified", self)
            runtime = dict(rows[0])
            if (runtime.get("mode") != "off" or runtime.get("admission_barrier") != "NONE" or
                    runtime.get("policy_entry_nonce") is not None):
                raise DailyActivationError("daily_activation_requires_empty_off", self)

    def _migrate_once(self):
        if self._migration_attempted:
            raise DailyActivationError("daily_activation_migration_already_attempted", self)
        self._assert_prepared_binding()
        self.owner.cohort.assert_retired()
        observed = self._open(readonly=True)
        self._empty_preflight(observed.connection)
        observed.close()
        # Recheck under the original writer transaction before any DDL. The
        # separately retained source cutover must exclude new old-code writers.
        current = self._open()
        self._migration_attempted = True
        self._phase = "schema_migration"
        current.connection.execute("BEGIN IMMEDIATE")
        self._empty_preflight(current.connection)
        migrate_schema(current.connection, in_transaction=True)
        current.connection.commit()
        current.close()

    def _install_once(self):
        if self._install_attempted:
            raise DailyActivationError("daily_activation_install_already_attempted", self)
        self.store = LifecycleStore(self.ledger_path, existing_path=True)
        policy = self.store._policy
        # Mark before prepare: an exception may leave a committed nonce without
        # returning its guard. No reconstruction or fresh prepare is attempted.
        self._install_attempted = True
        self._phase = "generation_install"
        self.guard = policy.prepare(self.owner.process.identity.logon_id)
        with policy.hold(self.guard):
            self.owner.prepare_install(policy=policy, guard=self.guard)
            current = self._open()
            current.connection.execute("BEGIN IMMEDIATE")
            self.owner.install_locked(current.connection, policy=policy, guard=self.guard)
            current.connection.commit()
        # Generation readiness requires the original POLICY scope and original
        # install connection to have positively completed their cleanup.
        self.owner.settle_install_connection()
        current.closed = True
        acknowledged = self._open(readonly=True)
        self.owner.acknowledge_install(conn=acknowledged.connection)
        acknowledged.close()
        self._generation_settled = True
        self._phase = "generation_ready"

    def start(self):
        if self._start_attempted:
            raise DailyActivationError("daily_activation_start_already_attempted", self)
        self._start_attempted = True
        try:
            # Resolve the fixed host collaborators before readiness callbacks
            # inspect executed modules. Later import churn still fails closed.
            for name in _PRELOAD:
                importlib.import_module("sentinel.adaptive." + name)
            self._assert_prepared_binding()
            self._native_custody_possible = True
            read_host_capability()  # Fail before migration inside a foreign Job.
            self.owner = generation.DailyGenerationOwner.capture(manifest=self.manifest,
                source_root=self.source_root, ledger_path=self.ledger_path)
            # Bounded observer wait only. A late thread stays owned and a later
            # run_once can start the supervisor after its listener is ready.
            self._continue_startup()
            return self.run_once()
        except BaseException as error:
            captured = getattr(error, "daily_generation_owner", None)
            if self.owner is None and captured is not None:
                self.owner = captured
            if self._defer_known_live_cohort(error):
                return self.status()
            self._retain_failure(error)
            raise

    def _start_readiness(self):
        if self._readiness_start_attempted:
            raise DailyActivationError("daily_activation_readiness_start_already_attempted", self)
        self.owner.assert_ready()
        self._registry = NativePipeRegistry(max_resources=1)
        self._readiness_original_registry = self._registry
        self._service = DailyReadinessService(self.owner.readiness_endpoint, self.owner)
        self._thread = threading.Thread(target=self._serve_readiness,
            name="sentinel-daily-readiness", daemon=False)
        self._readiness_original_thread = self._thread
        self._readiness_start_attempted = True
        self._thread.start()

    def _serve_readiness(self):
        """Same original process, read-only service, no automatic retirement."""
        try:
            self._listener = NativePipeListener(self.owner.readiness_endpoint, registry=self._registry)
            self._readiness_original_listener = self._listener
            self._listener_ready.set()
            while not self._readiness_stop.is_set():
                try:
                    self._service.serve_once(self._listener, timeout_ms=1000)
                except Exception as error:
                    status = self._registry.status()
                    if status.pending or status.quarantined or status.resources != 1:
                        # Preserve unknown native cleanup. Do not replace the
                        # original listener or reinterpret a poisoned endpoint.
                        self._readiness_failure = error
                        return
                    # A completed timeout, invalid peer, or refused readiness
                    # changed no state. The original listener remains owned.
        except BaseException as error:
            self._readiness_failure = error
            error.daily_activation_host = self
        finally:
            # This records thread termination, never native listener cleanup.
            self._thread_stopped.set()

    def request_drain(self):
        self._draining = True
        if self.supervisor is not None and not self._supervisor_closed:
            self.supervisor.begin_drain()
            try:
                self.supervisor.request_local_drain()
            except BaseException as error:
                self._retain_failure(error)

    def request_retirement(self):
        """Explicit intent on this original host, distinct from ordinary drain."""
        from .daily_retirement import DailyRetirementOperation
        if (self._generation_settled is not True or self.owner is None or
                self.supervisor is None or self._supervisor_attempted is not True):
            raise DailyActivationError("daily_retirement_host_not_ready", self)
        if self._retirement is not None:
            if type(self._retirement) is not DailyRetirementOperation or self._retirement.host is not self:
                raise DailyActivationError("daily_retirement_operation_changed", self)
            return self._retirement
        if self._retirement_creation_attempted:
            raise DailyActivationError("daily_retirement_creation_unverified", self)
        self._retirement_creation_attempted = True
        self._retirement = DailyRetirementOperation(self)
        return self._retirement

    def _original_retirement(self, operation):
        from .daily_retirement import DailyRetirementOperation
        if (operation is not self._retirement or type(operation) is not DailyRetirementOperation or
                operation.host is not self):
            raise DailyActivationError("daily_retirement_original_operation_required", self)
        return operation

    def _retirement_complete(self):
        if self._retirement is None:
            return False
        operation = self._original_retirement(self._retirement)
        return (operation.complete is True and self._readiness_cleanup_complete is True and
                self._readiness_close_unknown is False)

    def _tick_retirement(self):
        operation = self._original_retirement(self._retirement)
        try:
            operation.tick()
        except BaseException as error:
            # Its original operation owns failed SQL/POLICY work. Independent
            # supervisor recovery still gets its tick while that work settles.
            self._retain_failure(error)
        if operation.freeze_acknowledged is True:
            self.request_drain()
        if operation.sealed is True:
            self.shutdown_native_retirement(operation)

    def shutdown_native_retirement(self, operation):
        """Close only this exact sealed operation's original native keeper."""
        operation = self._original_retirement(operation)
        if operation.sealed is not True or operation.freeze_acknowledged is not True:
            raise DailyActivationError("daily_retirement_seal_unacknowledged", self)
        if operation.complete is True:
            if not self._retirement_complete():
                raise DailyActivationError("daily_retirement_cleanup_unverified", self)
            return True
        self._phase = "generation_keeper_retiring"
        self._readiness_stop.set()
        if self._readiness_close_unknown:
            return False
        if self._thread is None or not self._thread_stopped.is_set():
            return False
        try:
            if (self._thread is not self._readiness_original_thread or
                    self._listener is not self._readiness_original_listener or
                    self._registry is not self._readiness_original_registry):
                raise DailyActivationError("daily_retirement_keeper_owner_changed", self)
            if not self._readiness_joined:
                # The worker's finally signal alone is not a join receipt. The
                # original Thread must also complete its own bounded join.
                self._thread.join(timeout=0)
                if self._thread.is_alive() is not False:
                    return False
                self._readiness_joined = True
            if any(item.closed is not True or item.close_unknown is not False for item in self._connections):
                return False
            if self._listener is None or self._registry is None:
                return False
            if not self._readiness_listener_closed:
                if self._readiness_close_attempted:
                    return False
                self._readiness_close_attempted = True
                # Set before the native boundary. An exception can never
                # become authority to retry the same numeric handle as fresh.
                self._readiness_close_unknown = True
                self._listener.close()
                self._readiness_listener_closed = True
                self._readiness_close_unknown = False
            status = self._registry.status()
            if (type(status.resources) is not int or status.resources != 0 or
                    type(status.pending) is not int or status.pending != 0 or
                    type(status.quarantined) is not int or status.quarantined != 0):
                return False
            self._readiness_cleanup_complete = True
            operation.close_owner()
            if self._retirement_complete():
                self._phase = "generation_retired"
                return True
            return False
        except BaseException as error:
            if self._retirement_cleanup_error is None:
                self._retirement_cleanup_error = error
            self._retain_failure(error)
            return False

    def run_once(self):
        if not self._start_attempted:
            raise DailyActivationError("daily_activation_not_started", self)
        if self._retirement_complete():
            return self.status()
        supervisor_closed_before = self._supervisor_closed
        if self._failure is not None and self.supervisor is None:
            return self.status()
        if self._waiting_for_cohort:
            if self._draining:
                return self.status()
            try:
                if self.owner is not self._waiting_owner or self.owner.cohort is not self._waiting_cohort:
                    raise DailyActivationError("daily_activation_wait_owner_changed", self)
                self._continue_startup()
            except BaseException as error:
                if self._defer_known_live_cohort(error):
                    return self.status()
                self._retain_failure(error)
                raise
        retirement_ticked = False
        if self._retirement is not None:
            self._tick_retirement()
            retirement_ticked = True
            if self._retirement_complete() or self._retirement.sealed is True:
                return self.status()
        if self._readiness_failure is not None or self._thread_stopped.is_set():
            self._phase = "readiness_custody_retained"
            # Stop new managed launches while preserving existing guardian
            # recovery. The generation itself is not silently retired.
            self.request_drain()
        if (not self._supervisor_attempted and self._listener_ready.is_set() and
                not self._thread_stopped.is_set() and not self._draining):
            self._supervisor_attempted = True
            self.supervisor = SupervisorHost(data_dir=self.data_dir,
                journal_dir=self.journal_dir, child_cwd=self.source_root,
                python_executable=str(_BASE_PYTHON), max_guardians=1,
                guardian_iterations=0, helper_profile_path=None)
            try:
                self._observe_supervisor_record(self.supervisor.start())
            except BaseException as error:
                self._retain_failure(error)
                # Preserve any child creation witnesses on this exact host.
                self.request_drain()
                raise
        if self._retire_after_drain and self._retirement is None and self.supervisor is not None:
            self.request_retirement()
        if self._retirement is not None and not retirement_ticked:
            self._tick_retirement()
            retirement_ticked = True
            if self._retirement_complete() or self._retirement.sealed is True:
                return self.status()
        if self.supervisor is not None and not self._supervisor_closed:
            try:
                if self._draining:
                    self.request_drain()
                self._observe_supervisor_record(self.supervisor.run_once())
                if self._draining and self.supervisor._custody_snapshot()["settled"]:
                    result = self.supervisor.close()
                    if (result.get("cleanup_errors") or result.get("guardian_left_running") or
                            result.get("helper_left_running") or result.get("unverified") or
                            result.get("unsettled_captures")):
                        raise DailyActivationError("daily_activation_supervisor_cleanup_unverified", self)
                    self._supervisor_closed = True
                    self._phase = "generation_keeper_resident"
            except BaseException as error:
                self._retain_failure(error)
                self._draining = True
                self.supervisor.begin_drain()
                raise
        if self._retirement is not None and self._supervisor_closed and not supervisor_closed_before:
            self._tick_retirement()
        return self.status()

    def status(self):
        complete = self._retirement_complete()
        return {"event": "daily_activation_host", "phase": self._phase,
                "generation_activation_acknowledged": self._generation_settled,
                "readiness_listener_started": self._listener_ready.is_set(),
                "readiness_listener_closed": self._readiness_listener_closed,
                "supervisor_state": self._supervisor_state,
                "supervisor_closed": self._supervisor_closed, "drain_requested": self._draining,
                "retirement_requested": self._retirement is not None,
                "retirement_phase": None if self._retirement is None else self._retirement.phase,
                "retirement_reason": None if self._retirement is None or self._retirement.reason is None else
                    _reason_text(self._retirement.reason),
                "clean_exit_allowed": complete,
                "reason": (None if complete else _reason(self._failure) if self._failure is not None else
                    _reason(self._readiness_failure) if self._readiness_failure is not None else
                    "daily_generation_retirement_required" if self._supervisor_closed and self._retirement is None else
                    "cohort_ambiguous_consumers_still_alive" if self._waiting_for_cohort else
                    self._supervisor_reason)}

    def run_forever(self):
        """Keep original custody on startup failure, interrupt, and drained CPU."""
        if not self._start_attempted:
            try:
                self.start()
            except BaseException as error:
                self._retain_failure(error)
                if (not self._native_custody_possible and self.owner is None and
                        not self._connections):
                    # An invalid comparison input before the first native call
                    # owns no generation or handles and need not stay resident.
                    raise
        previous = None
        while True:
            previous = self._retained_tick(previous)
            if self._retirement_complete():
                return self.status()

    def _retain_interruption(self, error):
        if not isinstance(error, KeyboardInterrupt):
            self._retain_failure(error)
        try:
            self.request_drain()
        except BaseException as failure:
            self._retain_failure(failure)

    def _retained_tick(self, previous=None):
        """One resident iteration, including fallible diagnostics and pacing.

        This bounded orchestration seam grants no shutdown or adoption right.
        Every interruption leaves original recovery owners reachable and the
        following iteration still services them. Neither diagnostics nor the
        pacing handler may turn a protective drain into process termination.
        """
        try:
            record = self.run_once()
        except BaseException as error:
            self._retain_interruption(error)
            record = self.status()
        published = previous
        if record != previous:
            try:
                if emit(record) is True:
                    published = record
            except BaseException as error:
                self._retain_interruption(error)
        try:
            time.sleep(1.0)
        except BaseException as error:
            self._retain_interruption(error)
        return published


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--config-digest", required=True)
    parser.add_argument("--ledger-device", required=True)
    parser.add_argument("--ledger-inode", required=True)
    parser.add_argument("--retire-generation-after-drain", action="store_true",
        help="explicitly request freeze, supervisor drain and generation retirement after activation")
    options = parser.parse_args(argv)
    # A manifest file is bounded public comparison data. It never substitutes
    # for canonical provenance, exact file binding, or native original owners.
    with Path(options.manifest).open("rb") as stream:
        payload = stream.read(1024 * 1024 + 1)
    if len(payload) > 1024 * 1024:
        raise DailyActivationError("daily_activation_manifest_too_large")
    from .contracts import strict_json_loads
    manifest = generation.SourceManifest.from_dict(strict_json_loads(payload))
    ledger = LedgerFileIdentity.from_dict({"st_dev": options.ledger_device, "st_ino": options.ledger_inode})
    host = DailyActivationHost(manifest, options.config_digest, ledger,
                               retire_after_drain=options.retire_generation_after_drain)
    result = host.run_forever()
    if not host._retirement_complete():
        raise DailyActivationError("daily_activation_unexpected_return", host)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
