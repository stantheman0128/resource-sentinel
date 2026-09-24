"""Failure-atomic policy ownership for cooperating lifecycle writers.

The durable entry nonce is bookkeeping, not launch authority. It is committed
before a native wait and retains uncertainty before confirmed release. Only
this scope's positively completed release may clear its exact nonce; a final
clear acknowledgment failure can follow an already committed cleanup. There is
no takeover, TTL cleanup, barrier-clear operation, or fixture fallback here.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import re
import threading
from uuid import UUID, uuid4

from .contracts import IdentityStatus
from .identity import IdentityUnavailable, VerifiedProcess
from .windows import NativePolicyMutex, NativePolicyMutexError, PolicyMutexLease


class PolicyError(RuntimeError):
    pass


class PolicyBusy(PolicyError):
    pass


def _uuid(value):
    try:
        parsed = UUID(value) if isinstance(value, str) else None
        return parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        return False


def _logon(value):
    match = re.fullmatch(r"S-1-5-5-([0-9]{1,10})-([0-9]{1,10})", value) if isinstance(value, str) else None
    return match is not None and all(int(part) <= 0xFFFFFFFF for part in match.groups())


@dataclass(frozen=True)
class PolicyBinding:
    instance_id: str
    logon_id: str

    def __post_init__(self):
        if not _uuid(self.instance_id) or not _logon(self.logon_id):
            raise PolicyError("policy_binding_invalid")

    @property
    def name(self):
        return f"Local\\ResourceSentinel.Policy.{self.logon_id}.{self.instance_id}"


class NativePolicyProvider:
    def current_logon(self):
        try:
            with VerifiedProcess.current() as current:
                observed = current.observe()
                if (current.identity.pid != os.getpid() or observed.identity != current.identity or
                        observed.status is not IdentityStatus.ALIVE):
                    raise PolicyError("policy_current_identity_unavailable")
                return current.identity.logon_id
        except IdentityUnavailable as error:
            raise PolicyError("policy_current_identity_unavailable") from error

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        with NativePolicyMutex(binding.logon_id, binding.instance_id) as mutex:
            with mutex.acquire(timeout_ms=timeout_ms) as lease:
                yield lease


@dataclass
class PolicyGuard:
    binding: PolicyBinding
    nonce: str
    # Set only after a known transaction rejection has rolled back and closed.
    clean_rejection: bool = False


class PolicyCoordinator:
    def __init__(self, store, provider=None):
        self.store = store
        self.provider = NativePolicyProvider() if provider is None else provider
        self._held = threading.local()

    def current_guard(self):
        """Return only this coordinator's current-thread validated ownership.

        This is a trusted in-process borrowing seam, not a serialized lease or
        a native query. An abandoned, released or uncertain scope confers no
        authority; callers must still revalidate this nonce in their DB CAS.
        """
        return getattr(self._held, "guard", None)

    def current_cleanup_guard(self):
        """Exact current-thread nonce cleanup, after native scope release.

        This grants no POLICY borrowing or capacity authority. Daily retirement
        uses it only to recognize the original _clear connection opener.
        """
        return getattr(self._held, "cleanup_guard", None)

    def assert_held(self, guard=None):
        current = self.current_guard()
        if current is None or (guard is not None and current is not guard):
            raise PolicyError("policy_scope_not_held")
        return current

    def current_logon(self):
        value = self.provider.current_logon()
        if not _logon(value):
            raise PolicyError("policy_current_logon_invalid")
        return value

    @staticmethod
    def _runtime(conn):
        row = conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
        if row is None:
            raise PolicyError("policy_runtime_unavailable")
        row = dict(row)
        if (row.get("schema_version") != 1 or row.get("protocol_version") != 1 or
                row.get("mode") not in {"off", "shadow", "canary", "limited"} or
                row.get("admission_barrier") not in {"NONE", "CONTROLLING", "RECOVERY_HOLD"} or
                type(row.get("registry_revision")) is not int or row["registry_revision"] < 0):
            raise PolicyError("policy_runtime_invalid")
        return row

    @staticmethod
    def _binding(row, logon_id):
        instance, logon = row["policy_instance_id"], row["policy_logon_id"]
        initialized = row["policy_binding_initialized"]
        if type(initialized) is not int or initialized not in {0, 1}:
            raise PolicyError("policy_binding_invalid")
        if initialized == 0:
            if instance is None and logon is None and row["policy_entry_nonce"] is None:
                return None
            raise PolicyError("policy_binding_invalid")
        binding = PolicyBinding(instance, logon)
        if binding.logon_id != logon_id:
            raise PolicyError("policy_logon_mismatch")
        return binding

    def prepare(self, logon_id):
        from .experiment_cleanup import current_operation
        operation = current_operation()
        if operation is not None:
            current_operation(self.store.db_path)
            return operation.prepare_policy(self, logon_id)
        # Randomness and identity collection happen before the short DB lock.
        candidate, nonce = str(uuid4()), str(uuid4())
        with self.store._transaction() as conn:
            row = self._runtime(conn)
            pending = row["policy_entry_nonce"]
            if pending is not None and not _uuid(pending):
                raise PolicyError("policy_entry_invalid")
            binding = self._binding(row, logon_id)
            if row["active_logon_id"] not in {"", logon_id}:
                raise PolicyError("policy_logon_mismatch")
            if pending is not None:
                # Never turn contention with a live operation into recovery.
                # A lost binding with an extant nonce also cannot be recreated.
                if binding is None:
                    raise PolicyError("policy_binding_invalid")
                raise PolicyBusy("policy_scope_busy")
            if binding is None:
                binding = PolicyBinding(candidate, logon_id)
            changed = conn.execute("""UPDATE adaptive_runtime
                SET policy_instance_id=?,policy_logon_id=?,policy_entry_nonce=?,policy_binding_initialized=1
                WHERE singleton=1 AND policy_entry_nonce IS NULL""",
                (binding.instance_id, binding.logon_id, nonce)).rowcount
            if changed != 1:
                raise PolicyError("policy_entry_conflict")
        # Returning requires commit and connection cleanup to have succeeded.
        return PolicyGuard(binding, nonce)

    def revalidate(self, conn, guard):
        row = self._runtime(conn)
        binding = self._binding(row, guard.binding.logon_id)
        if (binding != guard.binding or row["policy_entry_nonce"] != guard.nonce or
                row["active_logon_id"] not in {"", guard.binding.logon_id}):
            raise PolicyError("policy_entry_changed")
        return row

    def _clear(self, guard):
        from .daily_generation import readiness_nonce_cleanup
        with readiness_nonce_cleanup(self, guard):
            self._clear_owned(guard)

    def _clear_owned(self, guard):
        if self.current_guard() is not None or self.current_cleanup_guard() is not None:
            raise PolicyError("policy_cleanup_scope_nested")
        self._held.cleanup_guard = guard
        try:
            with self.store._transaction() as conn:
                self.revalidate(conn, guard)
                if conn.execute("""UPDATE adaptive_runtime SET policy_entry_nonce=NULL
                    WHERE singleton=1 AND policy_instance_id=? AND policy_logon_id=? AND policy_entry_nonce=?""",
                    (guard.binding.instance_id, guard.binding.logon_id, guard.nonce)).rowcount != 1:
                    raise PolicyError("policy_entry_changed")
        finally:
            self._held.cleanup_guard = None

    def record_recovery_hold(self, guard):
        with self.store._transaction() as conn:
            row = self.revalidate(conn, guard)
            if row["admission_barrier"] != "RECOVERY_HOLD":
                conn.execute("""UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD',
                    registry_revision=registry_revision+1 WHERE singleton=1""")
            return self._runtime(conn)

    @contextmanager
    def hold(self, guard):
        from .daily_generation import readiness_scope
        with readiness_scope(self.store.db_path):
            with self._hold_owned(guard) as held:
                yield held

    @contextmanager
    def _hold_owned(self, guard):
        if self.current_guard() is not None:
            raise PolicyError("policy_scope_nested")
        scope = self.provider.hold(guard.binding, timeout_ms=250)
        enter, leave = getattr(type(scope), "__enter__", None), getattr(type(scope), "__exit__", None)
        if not callable(enter) or not callable(leave):
            raise PolicyError("invalid_policy_scope")
        try:
            lease = enter(scope)
        except NativePolicyMutexError as error:
            # A timeout is a positive no-ownership result. All other entry
            # failures leave the nonce, including unknown native wait outcomes.
            if error.reason == "policy_mutex_timeout" and not getattr(error, "__notes__", ()):
                try:
                    self._clear(guard)
                except BaseException:
                    error.add_note("policy_entry_cleanup_failed")
            raise
        safe_to_clear = False
        try:
            if (type(lease) is not PolicyMutexLease or lease.name != guard.binding.name or
                    lease.instance_id != guard.binding.instance_id or lease.logon_id != guard.binding.logon_id or
                    type(lease.abandoned) is not bool):
                raise PolicyError("invalid_policy_lease")
            if lease.abandoned:
                # A failed hold commit must retain the pre-Wait nonce, even if
                # releasing this mutex destroys the kernel object afterward.
                self.record_recovery_hold(guard)
                safe_to_clear = True
                raise PolicyError("policy_mutex_abandoned")
            # prepare() commits before the native wait. A delayed waiter must
            # not expose a stale guard after another fenced owner has changed
            # its durable nonce/binding. Verify while the acquired mutex is
            # retained, before any consumer can borrow it or touch native Jobs.
            # Read/connection cleanup failure leaves the nonce uncertain, using
            # the same release/error path as every other pre-yield rejection.
            with self.store._connection() as conn:
                # Bound SQLite lock waiting while native POLICY is held.
                conn.execute("PRAGMA busy_timeout=250")
                self.revalidate(conn, guard)
            self._held.guard = guard
            yield guard
            safe_to_clear = True
        except BaseException as primary:
            notes = tuple(getattr(primary, "__notes__", ()))
            # The yield body (including nested evidence cleanup) is over.
            # Never expose borrowing authority during native release/cleanup.
            self._held.guard = None
            try:
                suppressed = leave(scope, type(primary), primary, primary.__traceback__)
            except BaseException:
                primary.add_note("policy_scope_cleanup_failed")
                raise primary
            finally:
                self._held.guard = None
            if suppressed or tuple(getattr(primary, "__notes__", ())) != notes:
                primary.add_note("policy_scope_cleanup_unverified")
            elif safe_to_clear or (guard.clean_rejection and not notes):
                try:
                    self._clear(guard)
                except BaseException:
                    primary.add_note("policy_entry_cleanup_failed")
            raise
        else:
            # The production provider returns only after ReleaseMutex and
            # handle cleanup succeeded. Cleanup failure retains the exact nonce.
            self._held.guard = None
            try:
                leave(scope, None, None, None)
            except BaseException as primary:
                # Distinguish native provider cleanup from the later SQLite
                # nonce clear. A generic cleanup error is still uncertain
                # ownership and must never authorize emergency reacquisition.
                primary.add_note("policy_scope_cleanup_failed")
                raise
            finally:
                self._held.guard = None
            self._clear(guard)
