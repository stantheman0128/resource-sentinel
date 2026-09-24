"""Production host authority for the guardian and wrapper launch contracts.

Every method here is a live read of an authoritative source. None of them
consults a configuration flag, a cached receipt or a serialized readiness
field, and none of them returns success from a constant. Anything that cannot
be read right now refuses with a typed reason.

The guardian surface is assert_ready, assert_covered and assert_excluded, which
GuardianLaunchOwner._authority treats as satisfied only when they return None.
The wrapper surface is assert_launch_ready, which ManagedLauncher._ready calls
before each lifecycle step and before native creation.

Refusals use two error types so that each caller keeps its own stable reason
channel. Guardian refusals are LifecycleError, which the control consumer turns
into a rejected acknowledgement instead of an unwind. Wrapper refusals are
ManagedLaunchError, which the launcher already reports without leaking command
text.

This module never mutates the ledger, never takes POLICY on its own and never
performs a native Set. The legacy exclusion check requires the caller to be
holding POLICY already, because the registry it reads is only stable inside
that scope.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import math
import os
from pathlib import Path
import sqlite3
import sys
import time

from ..accounting import AccountingError, validate_active_allocation
from .contracts import IdentityStatus, ProcessIdentity
from .identity import IdentityUnavailable, VerifiedProcess
from .launcher import ManagedLaunchError
from .store import LifecycleError, LifecycleStore, _coverage_read_transaction


ACTIVE_STATES = frozenset({"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING",
                           "START_UNKNOWN", "UNCERTAIN_HOLD"})
# States the guardian may still reconcile but must never treat as covered work
# with a healthy lease behind it.
HELD_STATES = frozenset({"START_UNKNOWN", "UNCERTAIN_HOLD"})
_BOOL = C.c_int
_DWORD = C.c_uint32
_WORD = C.c_uint16
_HANDLE = C.c_void_p
_ALL_GROUPS = 0xFFFF


class HostAuthorityError(LifecycleError):
    """Guardian-side refusal with a stable machine readable reason."""

    def __init__(self, reason, win32_error=None):
        self.reason = reason
        self.win32_error = win32_error
        super().__init__(reason)


class HostReadinessError(ManagedLaunchError):
    """Wrapper-side refusal carrying the same stable reason vocabulary."""

    def __init__(self, reason, win32_error=None):
        self.win32_error = win32_error
        super().__init__(reason)


class HostCapabilityUnsupported(RuntimeError):
    """This host cannot support managed control, or the answer is unknown."""

    def __init__(self, reason, win32_error=None):
        self.reason = reason
        self.win32_error = win32_error
        super().__init__(reason)


@dataclass(frozen=True)
class HostCapability:
    """One read-only capability record, never persisted as a readiness flag."""
    platform: str
    os_major: int
    os_minor: int
    os_build: int
    logical_processors: int
    processor_groups: int
    process_affinity: str
    pid: int

    def to_dict(self):
        return {"platform": self.platform, "os_major": self.os_major, "os_minor": self.os_minor,
                "os_build": self.os_build, "logical_processors": self.logical_processors,
                "processor_groups": self.processor_groups, "process_affinity": self.process_affinity,
                "in_parent_job": False, "python_bits": 64, "pid": self.pid}


def _bind(dll, name, result, *arguments):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, arguments
    return function


class _CapabilityBackend:
    """Fixed size native reads only. No handle is opened or retained here."""

    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise HostCapabilityUnsupported("host_platform_unsupported")
        try:
            self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
            _bind(k, "GetCurrentProcess", _HANDLE)
            _bind(k, "IsProcessInJob", _BOOL, _HANDLE, _HANDLE, C.POINTER(_BOOL))
            _bind(k, "GetActiveProcessorGroupCount", _WORD)
            _bind(k, "GetActiveProcessorCount", _DWORD, _WORD)
            _bind(k, "GetProcessAffinityMask", _BOOL, _HANDLE,
                  C.POINTER(C.c_size_t), C.POINTER(C.c_size_t))
        except (AttributeError, OSError):
            raise HostCapabilityUnsupported("host_native_api_unavailable") from None


def read_host_capability() -> HostCapability:
    """Read-only capability preflight. Unknown and any parent Job fail closed.

    This is the production counterpart of the read-only preflight the Windows
    test helpers use. It reimplements the checks rather than importing them,
    so that shipped code never depends on a test package.

    A process inside a Job it does not own cannot be given an independent CPU
    rate denominator, so that case is refused rather than approximated.
    """
    backend = _CapabilityBackend()
    kernel = backend.kernel
    current = kernel.GetCurrentProcess()
    member = _BOOL()
    if not kernel.IsProcessInJob(current, None, C.byref(member)):
        raise HostCapabilityUnsupported("host_parent_job_membership_unknown", C.get_last_error())
    if member.value:
        raise HostCapabilityUnsupported("host_foreign_parent_job")
    groups = int(kernel.GetActiveProcessorGroupCount())
    processors = int(kernel.GetActiveProcessorCount(_ALL_GROUPS))
    if groups != 1 or not 1 <= processors <= 64:
        raise HostCapabilityUnsupported("host_processor_topology_unsupported")
    process_mask, system_mask = C.c_size_t(), C.c_size_t()
    if not kernel.GetProcessAffinityMask(current, C.byref(process_mask), C.byref(system_mask)):
        raise HostCapabilityUnsupported("host_processor_affinity_unknown", C.get_last_error())
    if process_mask.value != system_mask.value or system_mask.value.bit_count() != processors:
        raise HostCapabilityUnsupported("host_processor_affinity_restricted")
    try:
        version = sys.getwindowsversion()
        record = HostCapability(sys.platform, int(version.major), int(version.minor),
                                int(version.build), processors, groups,
                                str(process_mask.value), os.getpid())
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise HostCapabilityUnsupported("host_os_version_unavailable") from None
    return record


def _finite(value, *, minimum=None):
    try:
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            return False
    except (TypeError, OverflowError):
        return False
    return minimum is None or value >= minimum


def _ledger_path(store):
    try:
        return store._existing_ledger_path or Path(store.db_path).resolve()
    except (OSError, TypeError, ValueError, RuntimeError):
        raise HostAuthorityError("host_coverage_registry_unavailable") from None


class HostAuthority:
    """One live authority shared by a guardian host and a wrapper host.

    ``store`` is the lifecycle store bound to the real ledger. ``guardian`` is
    the retained VerifiedProcess of the process that owns the launch scopes;
    the guardian host passes its own current process. Without it the legacy
    exclusion check has no identity to look for in the infrastructure registry
    and refuses.

    ``clock`` supplies the wall clock used for lease freshness. It is a unit
    test seam for a clock, not a source of readiness.
    """

    def __init__(self, store, *, guardian=None, clock=time.time):
        if not isinstance(store, LifecycleStore):
            raise HostAuthorityError("host_store_required")
        if guardian is not None and not isinstance(guardian, VerifiedProcess):
            raise HostAuthorityError("host_guardian_identity_invalid")
        self.store = store
        self.guardian = guardian
        self._clock = clock

    # Guardian surface -----------------------------------------------------

    def assert_ready(self) -> None:
        """Re-read host capability on every call. There is no cached answer."""
        try:
            read_host_capability()
        except HostCapabilityUnsupported as error:
            raise HostAuthorityError(error.reason, error.win32_error) from None

    def assert_covered(self, row) -> None:
        """Prove that this execution still holds a fresh authoritative lease.

        The supplied row is a consistency input. The ledger snapshot read here
        is the authority: the execution must still exist at the same revision,
        still be active, still be a direct allocation bound to exactly one
        reservation, and that reservation's lease must not have elapsed.

        An elapsed lease refuses. It is never reported as released capacity and
        nothing here writes a state change.
        """
        execution_id = self._execution_id(row, HostAuthorityError, "host_coverage_row_invalid")
        now = self._now(HostAuthorityError, "host_coverage_clock_unavailable")
        path = _ledger_path(self.store)
        try:
            with _coverage_read_transaction(path) as conn:
                self._ordinary_execution(conn, execution_id, HostAuthorityError)
                live = self._live_row(conn, execution_id, HostAuthorityError,
                                      "host_coverage_execution_missing")
                self._match(row, live, HostAuthorityError, "host_coverage_row_mismatch")
                self._active(live, HostAuthorityError)
                source = self._allocation(conn, execution_id)
        except LifecycleError as error:
            raise self._translate(error, HostAuthorityError, "host_coverage_registry_unavailable") from None
        self._lease(source["allocation"], now)

    def assert_excluded(self, row) -> None:
        """Prove the legacy writer batch is currently excluding this scope.

        The authority is the same registry read the guarded legacy writer
        performs, taken under the POLICY scope this caller already holds. It
        yields the live protected identity set and the live managed Job name
        list that the batch opens and skips on membership.

        Proving all of the following refuses anything weaker:

        1. the infrastructure registry exists with its exact schema,
        2. the persistent writer fence triggers are installed,
        3. this guardian is registered infrastructure, so the batch skips it,
        4. this execution's wrapper is in the protected identity set,
        5. this execution's Job name is in the live managed Job scope.
        """
        from .legacy_writer import LegacyMutationError, _registry_locked
        from .policy import PolicyError
        from .writers import writer_obligations_present

        if not isinstance(row, dict) and not hasattr(row, "keys"):
            raise HostAuthorityError("host_exclusion_row_invalid")
        execution_id = self._execution_id(row, HostAuthorityError, "host_exclusion_row_invalid")
        self._ordinary_execution_at_path(_ledger_path(self.store), execution_id, HostAuthorityError)
        job_name = row["job_name"] if "job_name" in row else None
        job_nonce = row["job_nonce"] if "job_nonce" in row else None
        if (type(job_name) is not str or type(job_nonce) is not str or
                job_name != f"Local\\ResourceSentinel.Job.{execution_id}.{job_nonce}"):
            raise HostAuthorityError("host_exclusion_scope_unknown")
        wrapper = self._wrapper_identity(row)
        guardian = self._live_guardian()
        try:
            guard = self.store._policy.assert_held()
        except PolicyError:
            raise HostAuthorityError("host_exclusion_policy_not_held") from None
        if guard.binding.logon_id != guardian.logon_id:
            raise HostAuthorityError("host_exclusion_policy_logon_mismatch")
        self._writer_fence(writer_obligations_present)
        deadline = time.monotonic() + .25
        try:
            revision, protected, jobs = _registry_locked(self.store, guard, deadline, time.monotonic)
        except (LegacyMutationError, PolicyError, sqlite3.Error, OSError):
            raise HostAuthorityError("host_exclusion_registry_unavailable") from None
        if type(revision) is not int or revision < 0:
            raise HostAuthorityError("host_exclusion_registry_unavailable")
        if guardian not in protected:
            raise HostAuthorityError("host_exclusion_guardian_unregistered")
        if wrapper not in protected:
            raise HostAuthorityError("host_exclusion_wrapper_unprotected")
        if job_name not in jobs:
            raise HostAuthorityError("host_exclusion_scope_unknown")

    # Wrapper surface ------------------------------------------------------

    def assert_launch_ready(self, admission, row, endpoint) -> None:
        """Prove host capability, live ledger coverage and endpoint binding.

        The wrapper cannot prove legacy writer exclusion. That proof needs the
        POLICY scope the guardian holds for the whole launch, and a wrapper
        that took POLICY would deadlock against the guardian it is calling.
        The guardian asserts exclusion at prepare, at claim and at bind through
        assert_excluded, so a launch whose scope is not excluded still cannot
        complete. This method refuses to claim that fact itself.
        """
        from .admission import ManagedAdmission

        try:
            read_host_capability()
        except HostCapabilityUnsupported as error:
            raise HostReadinessError(error.reason, error.win32_error) from None
        if type(admission) is not ManagedAdmission:
            raise HostReadinessError("host_readiness_admission_required")
        try:
            snapshot = admission.snapshot()
        except Exception:
            raise HostReadinessError("host_readiness_admission_unavailable") from None
        execution_id = self._execution_id(row, HostReadinessError, "host_readiness_row_invalid")
        if execution_id != snapshot.execution_id:
            raise HostReadinessError("host_readiness_row_mismatch")
        self._endpoint(endpoint, snapshot)
        self._ordinary_execution_at_path(_ledger_path(self.store), execution_id, HostReadinessError)
        try:
            live = self.store.query(execution_id, existing_path=True)
        except LifecycleError as error:
            raise self._translate(error, HostReadinessError,
                                  "host_readiness_registry_unavailable") from None
        self._match(row, live, HostReadinessError, "host_readiness_row_mismatch")
        try:
            self._active(live, HostReadinessError)
            self.store.assert_admission_covered(admission, live)
        except LifecycleError as error:
            raise self._translate(error, HostReadinessError,
                                  "host_readiness_coverage_unverified") from None

    # Shared helpers -------------------------------------------------------

    @staticmethod
    def _ordinary_execution_at_path(path, execution_id, error_type):
        try:
            with _coverage_read_transaction(path) as conn:
                HostAuthority._ordinary_execution(conn, execution_id, error_type)
        except error_type:
            raise
        except (LifecycleError, sqlite3.Error, OSError, ValueError):
            raise error_type("host_experiment_link_unavailable") from None

    @staticmethod
    def _ordinary_execution(conn, execution_id, error_type):
        from .experiment_local_backing import LocalBackingError, assert_ordinary_execution
        try:
            assert_ordinary_execution(conn, execution_id)
        except LocalBackingError as error:
            raise error_type(error.reason) from None
        except (sqlite3.Error, ValueError, TypeError):
            raise error_type("host_experiment_link_unavailable") from None

    @staticmethod
    def _execution_id(row, error_type, reason):
        try:
            execution_id = row["execution_id"]
            revision = row["state_revision"]
        except (TypeError, KeyError, IndexError):
            raise error_type(reason) from None
        if (type(execution_id) is not str or not execution_id or
                type(revision) is not int or isinstance(revision, bool) or revision < 0):
            raise error_type(reason)
        return execution_id

    def _now(self, error_type, reason):
        try:
            now = self._clock()
        except Exception:
            raise error_type(reason) from None
        if not _finite(now, minimum=0):
            raise error_type(reason)
        return now

    @staticmethod
    def _live_row(conn, execution_id, error_type, reason):
        row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?",
                           (execution_id,)).fetchone()
        if row is None:
            raise error_type(reason)
        return LifecycleStore._public(row)

    @staticmethod
    def _match(supplied, live, error_type, reason):
        """Compare every field the caller supplied against the live snapshot.

        Extra keys a caller carries, such as a transport's launch flags, have
        no ledger column and are skipped. A key the ledger does have must be
        identical, including the revision.
        """
        try:
            keys = list(supplied.keys())
        except AttributeError:
            raise error_type(reason) from None
        if "state_revision" not in keys or supplied["state_revision"] != live["state_revision"]:
            raise error_type(reason)
        for key in keys:
            if key in live and supplied[key] != live[key]:
                raise error_type(reason)

    @staticmethod
    def _active(live, error_type):
        """Shared activity rules for both surfaces, with a per-surface prefix.

        A registered Job scope legitimately still reads coverage 'unmanaged'
        between scope registration and the prepared commit, so only the two
        impossible combinations are refused.
        """
        prefix = "host_coverage_" if error_type is HostAuthorityError else "host_readiness_"
        state = live.get("state")
        if state not in ACTIVE_STATES:
            raise error_type(prefix + "state_inactive")
        if state in HELD_STATES or live.get("hold_reason") is not None:
            raise error_type(prefix + "hold_active")
        if live.get("allocation_kind") != "direct" or live.get("parent_execution_id") is not None:
            raise error_type(prefix + "allocation_unsupported")
        job_name, coverage = live.get("job_name"), live.get("coverage")
        if coverage not in {"unmanaged", "job_contained"}:
            raise error_type(prefix + "scope_inconsistent")
        if job_name is None and coverage != "unmanaged":
            raise error_type(prefix + "scope_inconsistent")
        if coverage == "job_contained" and job_name is None:
            raise error_type(prefix + "scope_inconsistent")

    def _allocation(self, conn, execution_id):
        try:
            return validate_active_allocation(conn, execution_id,
                                              local_context=self.store._local_context)
        except AccountingError:
            raise HostAuthorityError("host_coverage_allocation_unverified") from None

    @staticmethod
    def _lease(allocation, now):
        """Lease freshness, read from the bound reservation row.

        The accounting validator deliberately ignores allocation TTL because a
        managed floor outlives it. Coverage freshness is exactly the fact it
        leaves out, so it is read here and only ever used to refuse.
        """
        expires_at = allocation.get("expires_at")
        heartbeat_at = allocation.get("heartbeat_at")
        duration = allocation.get("lease_duration_sec")
        if not _finite(expires_at, minimum=0) or not _finite(heartbeat_at, minimum=0):
            raise HostAuthorityError("host_coverage_lease_invalid")
        if duration is not None and not _finite(duration, minimum=0):
            raise HostAuthorityError("host_coverage_lease_invalid")
        if duration is not None and duration <= 0:
            raise HostAuthorityError("host_coverage_lease_invalid")
        if expires_at < heartbeat_at:
            raise HostAuthorityError("host_coverage_lease_invalid")
        if heartbeat_at > now:
            raise HostAuthorityError("host_coverage_clock_regression")
        if expires_at <= now:
            raise HostAuthorityError("host_coverage_lease_expired")

    @staticmethod
    def _wrapper_identity(row):
        try:
            identity = ProcessIdentity.from_dict({
                "pid": row["wrapper_pid"],
                "created_filetime_100ns": row["wrapper_created_filetime_100ns"],
                "logon_id": row["logon_id"]})
        except (TypeError, KeyError, ValueError, IndexError):
            raise HostAuthorityError("host_exclusion_row_invalid") from None
        return identity

    def _live_guardian(self):
        if self.guardian is None:
            raise HostAuthorityError("host_exclusion_guardian_unavailable")
        try:
            observed = self.guardian.observe()
        except IdentityUnavailable:
            raise HostAuthorityError("host_exclusion_guardian_unavailable") from None
        if (observed.status is not IdentityStatus.ALIVE or
                observed.identity != self.guardian.identity):
            raise HostAuthorityError("host_exclusion_guardian_unavailable")
        return self.guardian.identity

    def _writer_fence(self, present):
        try:
            with self.store._connection() as conn:
                conn.execute("PRAGMA busy_timeout=25")
                conn.execute("BEGIN")
                installed = present(conn)
        except (sqlite3.Error, ValueError, LifecycleError, OSError):
            raise HostAuthorityError("host_exclusion_writer_fence_unknown") from None
        if installed is not True:
            raise HostAuthorityError("host_exclusion_writer_fence_absent")

    @staticmethod
    def _endpoint(endpoint, snapshot):
        from .pipe_windows import NativePipeEndpoint

        if type(endpoint) is not NativePipeEndpoint:
            raise HostReadinessError("host_readiness_endpoint_invalid")
        if endpoint.logon_id != snapshot.logon_id:
            raise HostReadinessError("host_readiness_endpoint_logon_mismatch")
        if endpoint.server_identity == snapshot.wrapper_identity:
            raise HostReadinessError("host_readiness_endpoint_self_bound")

    @staticmethod
    def _translate(error, error_type, fallback):
        reason = getattr(error, "reason", None)
        if type(reason) is not str or not reason:
            reason = str(error) or fallback
        return error_type(reason)
