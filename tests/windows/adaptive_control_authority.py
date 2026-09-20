"""P1 control coordination over real exemption and lifecycle stores.

This supplies the missing transaction work at the S1 owner's authority seam.
The host collaborator must still prove its actual running cohort, exclusion,
measurements and recovery availability. Construction is not a native gate unlock.
There is no environment/CLI/receipt constructor or production actuator here.
"""
from enum import Enum
from pathlib import Path
import time
import uuid

from sentinel.adaptive.contracts import CpuControlMode, ProcessIdentity
from sentinel.adaptive.exemption_sync import snapshot_locked
from sentinel.adaptive.store import ControlSlotRejected, LifecycleError


class GrantRelation(Enum):
    APPLICABLE = "applicable"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class NativeGrantScope:
    """Bounded exact-handle check for the existing test-only Job launcher.

    A grant inside the Job protects the entire Job. A grant on the wrapper or
    its live verified ancestors protects the wrapper's newly created command.
    A legacy float birth cannot establish an exact identity. Missing processes,
    inaccessible ancestry and PID reuse all remain UNKNOWN, never unrelated.
    """

    def relation(self, owner, lease):
        retained = []
        result = GrantRelation.UNKNOWN
        deadline = min(owner.observation_deadline, time.monotonic() + 1.0)

        def timely():
            if time.monotonic() >= deadline:
                raise LifecycleError("exemption_scope_deadline")

        try:
            birth = lease.get("root_created_filetime_100ns")
            logon = lease.get("root_logon_id")
            if birth is None or logon is None:
                return result
            # These are internal authority rows, not a caller's attestation.
            expected = ProcessIdentity(lease["root_pid"], int(birth), logon)
            timely()
            root = owner.native.ProcessHandle.open(expected.pid, expected.created_filetime_100ns)
            retained.append(root)
            if root.wait(0) or root.full_identity(expected_logon_id=expected.logon_id) != expected:
                return result
            member = root.is_in_job(owner.job)
            timely()
            if member:
                return GrantRelation.APPLICABLE

            current = owner.native.ProcessHandle.open(owner.caller.pid,
                                                     owner.caller.created_filetime_100ns)
            retained.append(current)
            child = current.full_identity(expected_logon_id=owner.caller.logon_id)
            seen = set()
            for _ in range(32):
                timely()
                if current.wait(0) or child.pid in seen:
                    return result
                seen.add(child.pid)
                if child == expected:
                    return GrantRelation.APPLICABLE
                parent_pid = current.parent_pid()
                if parent_pid == 0:
                    return GrantRelation.UNRELATED
                parent = owner.native.ProcessHandle.open(parent_pid)
                retained.append(parent)
                parent_identity = parent.full_identity(expected_logon_id=child.logon_id)
                timely()
                if parent_identity.created_filetime_100ns > child.created_filetime_100ns:
                    return result
                current, child = parent, parent_identity
            return result
        except Exception:
            return GrantRelation.UNKNOWN
        finally:
            # A close failure is not successful scope proof. Preserve every
            # uncertain native reference with the owning execution for retry.
            failed = []
            for handle in reversed(retained):
                try:
                    handle.close()
                except BaseException:
                    failed.append(handle)
            if failed:
                owner._grant_scope_handles.extend(failed)
                owner._retain()
                raise LifecycleError("exemption_scope_cleanup_unverified")


class S1ControlAuthority:
    """Join actual fresh grants and the single durable control slot for S1.

    The collaborator is still required for real host readiness and old writer
    handoff. It cannot replace the two stores' reads/transactions in this class.
    Synthetic collaborators are used only by explicitly labelled L1 tests.
    """

    def __init__(self, *, data_dir, exemptions, host, scope=None):
        self.ledger_path = (Path(data_dir) / "sentinel.db").resolve()
        if Path(exemptions.path).resolve() != self.ledger_path.with_name("exemptions.sqlite3"):
            raise LifecycleError("control_authority_ledger_mismatch")
        self.exemptions, self.host = exemptions, host
        self.scope = NativeGrantScope() if scope is None else scope
        self._episodes = {}

    @property
    def guardian_epoch(self):
        return self.host.guardian_epoch

    def assert_ready(self):
        self.host.assert_ready()

    def capacity(self):
        return self.host.capacity()

    def assert_covered(self, admission, row):
        self.host.assert_covered(admission, row)

    def assert_excluded(self, row):
        self.host.assert_excluded(row)

    def retain(self, owner):
        self.host.retain(owner)

    def _assert_owner(self, owner):
        owner.assert_held()
        if (Path(owner.store.db_path).resolve() != self.ledger_path or
                owner.guardian_epoch != self.guardian_epoch):
            raise LifecycleError("control_authority_ledger_mismatch")

    def authorize_control(self, owner, target):
        self._assert_owner(owner)
        if target.mode is not CpuControlMode.HARD_CAP:
            raise LifecycleError("control_target_invalid")
        self.host.assert_ready()
        row = owner.store.query(owner.execution_id)
        owner._assert_row(row)
        owner._assert_covered(row)
        self.host.assert_excluded(row)
        # The read closes its transaction before native scope queries and the
        # subsequent sentinel.db transaction. POLICY stays held throughout.
        try:
            snapshot = snapshot_locked(self.exemptions, lifecycle_store=owner.store,
                                       now=time.time())
            for lease in snapshot.leases:
                relation = self.scope.relation(owner, lease)
                if relation is not GrantRelation.UNRELATED:
                    reason = ("execution_exempt" if relation is GrantRelation.APPLICABLE
                              else "exemption_scope_unknown")
                    raise LifecycleError(reason)
        except Exception:
            # No new grant/DB acknowledgement is required to try withdrawing
            # our own previous restriction. restore retains unresolved custody.
            owner.restore()
            raise

        episode = self._episodes.get(owner.execution_id)
        if episode is not None and episode["owner"] is not owner:
            raise LifecycleError("control_episode_owner_changed")
        if episode is None:
            episode = {"owner": owner, "slot_id": str(uuid.uuid4()),
                       "attempted": False, "acquired": False,
                       "never_acquired": False, "restored": False}
            self._episodes[owner.execution_id] = episode
        if episode["attempted"]:
            # S1 needs one Set per case. A lost slot ACK never authorizes a
            # second Set. The production two-level controller is separate.
            raise LifecycleError("control_episode_requires_reconciliation")
        episode["attempted"] = True
        try:
            result = owner.store.begin_control_slot_locked(owner.execution_id,
                caller=owner.caller, expected_revision=row["state_revision"],
                slot_id=episode["slot_id"], exemption_revision=snapshot.revision)
        except ControlSlotRejected:
            # Only the store can establish completed rollback/cleanup. A
            # timeout, lost ACK or generic failure is not this positive result.
            episode["never_acquired"] = True
            raise
        episode["acquired"] = result["slot_state"] == "HELD"
        if result["duplicate"] or result["slot_state"] != "HELD":
            raise LifecycleError("control_slot_ack_unverified")

    def control_restored(self, owner):
        self._assert_owner(owner)
        episode = self._episodes.get(owner.execution_id)
        if episode is not None:
            if episode["owner"] is not owner:
                raise LifecycleError("control_episode_owner_changed")
            slot = owner.store.query_control_slot_locked()
            if slot is not None and slot["execution_id"] == owner.execution_id:
                if slot["slot_id"] != episode["slot_id"]:
                    raise LifecycleError("control_episode_owner_changed")
                row = owner.store.query(owner.execution_id)
                owner.store.release_control_slot_locked(owner.execution_id,
                    caller=owner.caller, expected_revision=row["state_revision"],
                    slot_id=episode["slot_id"])
            elif not episode["never_acquired"]:
                raise LifecycleError("control_slot_recovery_unverified")
            # Absence/foreign ownership only settles a verified rolled-back
            # begin. Losing an acquired/uncertain slot is never successful ACK.
            episode["restored"] = True
        # This notification cannot clear RECOVERY_HOLD; native restoration and
        # release of a control slot do not supply five fresh uncapped samples.
        self.host.control_restored(owner)

    def observe_control(self, owner):
        """Fresh check consumed by every bounded wait while S1 is capped.

        This never renews a control slot or performs a restrictive Set. A new
        grant, unreadable grant state or lost authority withdraws our cap and
        invalidates the measurement window. Native restore remains independent
        of grant DB availability and of admission/coverage success.
        """
        self._assert_owner(owner)
        try:
            self.host.assert_ready()
            row = owner.store.query(owner.execution_id)
            owner._assert_row(row)
            owner._assert_covered(row)
            self.host.assert_excluded(row)
            episode = self._episodes.get(owner.execution_id)
            slot = owner.store.query_control_slot_locked()
            if (episode is None or episode["owner"] is not owner or
                    not episode["acquired"] or episode["restored"] or
                    slot is None or slot["slot_state"] != "HELD" or
                    slot["slot_id"] != episode["slot_id"] or
                    slot["execution_id"] != owner.execution_id):
                raise LifecycleError("control_slot_recovery_unverified")
            snapshot = snapshot_locked(self.exemptions, lifecycle_store=owner.store,
                                       now=time.time())
            for lease in snapshot.leases:
                relation = self.scope.relation(owner, lease)
                if relation is not GrantRelation.UNRELATED:
                    raise LifecycleError("execution_exempt" if relation is GrantRelation.APPLICABLE
                                         else "exemption_scope_unknown")
            manifest = owner._read_manifest()
            if (manifest.pending_intent is not None or
                    manifest.last_applied is None or
                    manifest.last_applied.mode is not CpuControlMode.HARD_CAP or
                    owner.query_cpu_control() != manifest.last_applied):
                raise LifecycleError("external_control_conflict")
        except Exception as primary:
            try:
                owner.restore()
            except BaseException:
                primary.add_note("control_observer_restore_unverified")
            raise
