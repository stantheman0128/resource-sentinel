"""S1's consumed, in-process recovery warmup; never a host readiness provider.

The serial S1 runtime retains each exact owner until this consumer has observed
its sealed terminal Job empty, disabled and journal-settled. Five new machine
windows are collected outside POLICY/Job locks. The final accounting projection
and barrier CAS share a short transaction under those locks. Missing inventory,
an observed power event, or any uncertain proof leaves recovery closed.

This is test-host source, not production sleep/recovery acceptance. The host
authority still owns actual cohort/legacy-exclusion/capacity readiness. No file,
environment flag, serialized proof or boolean callback can clear the barrier.

The successful barrier CAS is the recovery linearization point. Power observer
unregistration happens afterwards without locks; its failure retains custody
and re-enters HOLD, but does not mean NONE was never briefly observable. A real
host collaborator must bind its readiness/config generation to the same POLICY
scope; the unavailable host authority remains a separate native entry gate.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import threading
import time

from sentinel.accounting import frame_from_fast_frame, project_local_capacity
from sentinel.adaptive.contracts import CpuControlMode, FastFrame, Validity
from sentinel.adaptive.control_slot import query_locked
from sentinel.adaptive.machine_sampler import MachineSampler, MachineSample
from sentinel.adaptive.store import LifecycleError, TERMINAL_STATES


_MAX_OWNERS = 64  # Ten S1 effect rounds plus the fixed prerequisite cases.
_WINDOWS = 5
_DEADLINE_SECONDS = 12.0
_TICKS = 10_000_000


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def _fail(reason):
    raise LifecycleError("s1_recovery_" + reason)


@dataclass(frozen=True)
class _SettledOwner:
    # A private, process-local witness created only while original custody is
    # still held. Closing a handle or reading a terminal row cannot create one.
    owner: object
    row_digest: str
    manifest_hash: str | None


class S1Recovery:
    def __init__(self, runtime, *, sampler_factory=MachineSampler,
                 power_factory=None, tick=None, sleep=time.sleep,
                 monotonic=time.monotonic):
        self.runtime = runtime
        self._sampler_factory = sampler_factory
        self._power_factory = power_factory
        self._tick = tick
        self._sleep, self._monotonic = sleep, monotonic
        self._settled = {}
        self._pending_power = []
        self._lock = threading.Lock()

    def _now(self):
        if self._tick is None:
            from tests.windows.adaptive_win32 import interrupt_time_100ns
            return interrupt_time_100ns()
        return self._tick()

    def _power(self):
        from tests.windows.adaptive_power import NativePowerWitness
        witness = (NativePowerWitness.open() if self._power_factory is None
                   else self._power_factory())
        if type(witness) is not NativePowerWitness:
            _fail("power_witness_invalid")
        return witness

    def assert_entry(self):
        """A failed close/recovery cannot silently become a fresh S1 case."""
        if self._pending_power:
            _fail("power_cleanup_unverified")
        for owner in self.runtime.owners:
            if not owner._closed or self._settled.get(owner.execution_id, None) is None:
                _fail("previous_owner_unsettled")

    def _members(self, owner):
        members = tuple(self.runtime.owners)
        if (not members or len(members) > _MAX_OWNERS or
                len({item.execution_id for item in members}) != len(members) or
                not any(item is owner for item in members) or
                self.runtime.pending_admissions):
            _fail("inventory_unknown")
        if any(item is not owner and not item._closed for item in members):
            _fail("other_owner_unsettled")
        ledger = Path(owner.store.db_path).resolve()
        if (ledger != Path(self.runtime.coordinator.db_path).resolve() or
                any(Path(item.store.db_path).resolve() != ledger for item in members)):
            _fail("ledger_mismatch")
        return members

    @staticmethod
    def _read_locked(owner, members, conn):
        guard = owner.store._policy.assert_held()
        runtime = owner.store._policy.revalidate(conn, guard)
        slot = query_locked(conn, runtime, guard)
        rows = conn.execute("SELECT * FROM managed_executions LIMIT ?",
                            (_MAX_OWNERS + 1,)).fetchall()
        rows = {row["execution_id"]: owner.store._public(row) for row in rows}
        if set(rows) != {item.execution_id for item in members}:
            _fail("inventory_unknown")
        named = slot is not None or any(row["job_name"] is not None for row in rows.values())
        initial = not named and runtime["admission_barrier"] == "NONE"
        if (runtime["guardian_epoch"] not in ({"", owner.guardian_epoch} if initial else {owner.guardian_epoch}) or
                runtime["active_logon_id"] not in ({"", owner.caller.logon_id} if initial else {owner.caller.logon_id}) or
                runtime["mode"] not in {"off", "shadow", "canary", "limited"}):
            _fail("runtime_changed")
        if slot is not None:
            row = rows.get(slot["execution_id"])
            if row is None or slot["slot_state"] != "RESTORED":
                _fail("slot_unsettled")
            expected = {"job_name": row["job_name"], "job_nonce": row["job_nonce"],
                        "guardian_epoch": row["guardian_epoch"], "logon_id": row["logon_id"],
                        "owner_pid": row["wrapper_pid"],
                        "owner_created_filetime_100ns": row["wrapper_created_filetime_100ns"]}
            if any(slot[key] != value for key, value in expected.items()):
                _fail("slot_binding_changed")
        if runtime["admission_barrier"] == "CONTROLLING":
            _fail("slot_unsettled")
        # The complete row set includes historical terminal scopes. An empty
        # active-row query or a RESTORED slot is never an all-caps proof.
        signature = _digest({"rows": rows, "slot": slot,
            "runtime": {key: runtime[key] for key in (
                "registry_revision", "mode", "guardian_epoch", "active_logon_id",
                "admission_barrier", "policy_instance_id", "policy_logon_id")}})
        return runtime, rows, signature

    def _prove_owner(self, owner, row):
        if (not owner._terminal or not owner._sealed or owner._control_pending or
                row["state"] not in TERMINAL_STATES or not row["launch_sealed"] or
                row["launch_in_flight"]):
            _fail("owner_unsettled")
        digest = _digest(row)
        previous = self._settled.get(owner.execution_id)
        if previous is not None:
            if previous.owner is not owner or previous.row_digest != digest:
                _fail("terminal_witness_changed")
            if previous.manifest_hash is not None:
                record = owner.journal.read(owner.execution_id, creation_nonce=owner.creation_nonce)
                if record.manifest_hash != previous.manifest_hash:
                    _fail("terminal_manifest_changed")
            if owner._closed or owner._recovery_job_released:
                return previous
        if owner._closed:
            _fail("terminal_witness_missing")
        owner._assert_row(row)
        record = owner._read_manifest() if row["job_name"] is not None else None
        if record is not None and (record.pending_intent is not None or
                record.original.mode is not CpuControlMode.DISABLED or
                record.last_applied is not None and record.last_applied.mode is not CpuControlMode.DISABLED):
            _fail("manifest_unsettled")
        if owner._create_attempted:
            if (owner.job is None or owner.job.name != owner.job_name or
                    owner.job.logon_sid != owner.caller.logon_id or record is None):
                _fail("job_custody_unknown")
            if owner.query_cpu_control().mode is not CpuControlMode.DISABLED:
                _fail("cap_not_restored")
            count, pids = owner.job.accounting()["active_processes"], tuple(owner.job.active_pids())
            if type(count) is not int or count != 0 or pids != ():
                _fail("job_not_empty")
            if owner.process is not None:
                if (owner._root is None or record.root_identity != owner._root or
                        owner.process.full_identity(expected_logon_id=owner.caller.logon_id) != owner._root or
                        owner.process.wait(0) is not True):
                    _fail("root_unsettled")
            elif owner._root is not None or row["root_pid"] is not None:
                _fail("root_custody_unknown")
        elif (owner.job is not None or owner.process is not None or owner._launch_attempted or
                owner._root is not None or row["root_pid"] is not None):
            _fail("creation_unsettled")
        return _SettledOwner(owner, digest, None if record is None else record.manifest_hash)

    def _observe(self, owner, members, *, expected=None):
        with owner.mutation_scope():
            with owner.store._connection() as conn:
                conn.execute("PRAGMA busy_timeout=250")
                conn.execute("BEGIN")
                runtime, rows, signature = self._read_locked(owner, members, conn)
            witnesses = [self._prove_owner(item, rows[item.execution_id]) for item in members]
            signature = self._inventory_signature(signature, witnesses)
            if expected is not None and signature != expected:
                _fail("registry_changed")
            return runtime, signature, witnesses

    @staticmethod
    def _inventory_signature(ledger_signature, witnesses):
        return _digest([ledger_signature, [(value.owner.execution_id, value.row_digest,
                                           value.manifest_hash) for value in witnesses]])

    def _capacity(self):
        self.runtime.authority.assert_ready()
        _, config = self.runtime.authority.capacity()
        # Retain a value snapshot; no mutable host callback result is consumed
        # from inside SQLite or treated as native measurement authority.
        return json.loads(json.dumps(config, sort_keys=True, allow_nan=False))

    def _retry_cleanup(self, owner):
        """Retry only post-proof handle cleanup, without querying closed handles.

        The original consumer already observed disabled + sealed empty under
        original custody and completed warmup/CAS/power cleanup. No barrier or
        capacity change occurs here; close itself is never the witness.
        """
        proof = self._settled.get(owner.execution_id)
        if (proof is None or proof.owner is not owner or not owner._terminal or
                not owner._sealed or owner._control_pending or self._pending_power):
            _fail("terminal_witness_missing")
        row = owner.store.query(owner.execution_id)
        if _digest(row) != proof.row_digest:
            _fail("terminal_witness_changed")
        if proof.manifest_hash is not None:
            record = owner.journal.read(owner.execution_id, creation_nonce=owner.creation_nonce)
            if record.manifest_hash != proof.manifest_hash:
                _fail("terminal_manifest_changed")

    @staticmethod
    def _frame(sample, runtime, config, now):
        frame = FastFrame(sampler_epoch=sample.sampler_epoch, clock_epoch=sample.clock_epoch,
            sample_seq=sample.sample_seq, window_start_tick_100ns=sample.window_start_tick_100ns,
            window_end_tick_100ns=sample.window_end_tick_100ns, published_tick_100ns=now,
            sampled_at_utc=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            config_revision=_digest(config), registry_revision=runtime["registry_revision"],
            machine=sample.machine, jobs=(), validity=Validity.VALID, errors=(),
            collection_cost_ms=sample.collection_cost_ms, collection_skew_ms=sample.collection_cost_ms)
        # Empty attribution intentionally gives no measured-usage subtraction.
        return frame_from_fast_frame(frame, now_tick_100ns=now, clock_epoch=sample.clock_epoch)

    @contextmanager
    def _transaction(self, store):
        with store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.commit()
            except BaseException as primary:
                try:
                    conn.rollback()
                except BaseException:
                    primary.add_note("s1_recovery_rollback_unverified")
                raise

    def _commit(self, owner, members, signature, sample, config, witness, token):
        # Native queries precede SQLite, with original Job/owner custody and the
        # shared mutation fences retained through the following transaction.
        with owner.mutation_scope():
            with owner.store._connection() as conn:
                conn.execute("BEGIN")
                runtime, rows, ledger_signature = self._read_locked(owner, members, conn)
            witnessed = [self._prove_owner(item, rows[item.execution_id]) for item in members]
            if self._inventory_signature(ledger_signature, witnessed) != signature:
                _fail("registry_changed")
            # Revalidate after the last sample and all native owner reads. The
            # actual host must serialize readiness/config changes with POLICY;
            # no fixture callback or this method supplies that missing host.
            if self._capacity() != config:
                _fail("config_changed")
            witness.assert_current(token)
            now, before = self._now(), self._monotonic()
            if not sample.is_fresh(now, clock_epoch=sample.clock_epoch):
                _fail("sample_stale")
            frame = self._frame(sample, runtime, config, now)
            with self._transaction(owner.store) as conn:
                checked, _, current = self._read_locked(owner, members, conn)
                if current != ledger_signature or checked["admission_barrier"] != "RECOVERY_HOLD":
                    _fail("registry_changed")
                def fresh():
                    # No native telemetry or host callbacks inside SQLite.
                    witness.assert_current(token)
                    elapsed = self._monotonic() - before
                    if not 0 <= elapsed < .25 or not sample.is_fresh(
                            now + int(elapsed * _TICKS), clock_epoch=sample.clock_epoch):
                        _fail("sample_stale")
                fresh()
                projection = project_local_capacity(conn, frame, config)
                if (projection["errors"] or projection["registry_revision"] != checked["registry_revision"] or
                        projection["barrier"] != "RECOVERY_HOLD"):
                    _fail("accounting_unreconciled")
                fresh()
                if conn.execute("""UPDATE adaptive_runtime SET admission_barrier='NONE',
                    registry_revision=registry_revision+1 WHERE singleton=1
                    AND registry_revision=? AND admission_barrier='RECOVERY_HOLD'""",
                    (checked["registry_revision"],)).rowcount != 1:
                    _fail("registry_changed")
                fresh()
            witness.assert_current(token)

    @staticmethod
    def _retain_hold(owner):
        """A late commit/cleanup failure cannot turn uncertainty into readiness."""
        with owner.mutation_scope():
            guard = owner.store._policy.assert_held()
            with owner.store._transaction() as conn:
                runtime = owner.store._policy.revalidate(conn, guard)
                if runtime["admission_barrier"] == "NONE":
                    conn.execute("""UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD',
                        registry_revision=registry_revision+1 WHERE singleton=1
                        AND registry_revision=? AND admission_barrier='NONE'""",
                        (runtime["registry_revision"],))

    def before_close(self, owner):
        """Called by actual S1 owner.close, before closing any native handle."""
        if not self._lock.acquire(blocking=False):
            _fail("busy")
        power = sampler = None
        recovery_attempt = False
        primary = None
        completed = False
        settled = ()
        try:
            members = self._members(owner)
            if owner._cleanup_started:
                self._retry_cleanup(owner)
                return
            if self._pending_power:
                # Exact cleanup retry, never a new registration over uncertainty.
                for pending in self._pending_power:
                    pending.close()
                self._pending_power.clear()
            runtime, signature, settled = self._observe(owner, members)
            barrier = runtime["admission_barrier"]
            if barrier == "NONE":
                completed = True
                return
            if barrier != "RECOVERY_HOLD":
                _fail("barrier_unknown")
            recovery_attempt = True
            config = self._capacity()
            power = self._power()
            token = power.snapshot()
            sampler = self._sampler_factory()
            if type(sampler) is not MachineSampler:
                _fail("sampler_invalid")
            sampler.invalidate_clock()
            deadline = self._monotonic() + _DEADLINE_SECONDS
            power.assert_current(token)
            baseline = sampler.sample()
            if (type(baseline) is not MachineSample or baseline.validity is not Validity.UNKNOWN or
                    baseline.machine is None or baseline.window_start_tick_100ns is not None or
                    tuple((error.code, error.stage) for error in baseline.errors) !=
                    (("sample_window_invalid", "machine_warmup"),)):
                _fail("baseline_unavailable")
            epochs = baseline.sampler_epoch, baseline.clock_epoch, baseline.counter_epoch
            previous = baseline
            for _ in range(_WINDOWS):
                self._sleep(1.0)  # No POLICY, Job mutex, or SQLite transaction.
                if self._monotonic() >= deadline:
                    _fail("deadline_expired")
                power.assert_current(token)
                self._observe(owner, members, expected=signature)
                if self._capacity() != config:
                    _fail("config_changed")
                sample = sampler.sample()
                now = self._now()
                if (type(sample) is not MachineSample or sample.reset_required or sample.errors or
                        (sample.sampler_epoch, sample.clock_epoch, sample.counter_epoch) != epochs or
                        sample.sample_seq != previous.sample_seq + 1 or
                        sample.window_start_tick_100ns != previous.window_end_tick_100ns or
                        not sample.is_fresh(now, clock_epoch=baseline.clock_epoch)):
                    _fail("sample_invalid")
                power.assert_current(token)
                self._observe(owner, members, expected=signature)
                previous = sample
            if self._monotonic() >= deadline:
                _fail("deadline_expired")
            self._commit(owner, members, signature, sample, config, power, token)
            completed = True
        except BaseException as error:
            primary = error
            # open() may have acquired native ownership before failing its
            # cleanup. An exception-attached witness is still our obligation.
            from tests.windows.adaptive_power import NativePowerWitness
            failed_power = getattr(error, "power_witness", None)
            if (type(failed_power) is NativePowerWitness and
                    not any(failed_power is item for item in self._pending_power)):
                self._pending_power.append(failed_power)
            if sampler is not None:
                try:
                    sampler.invalidate_clock()
                except BaseException:
                    error.add_note("s1_recovery_sampler_reset_unverified")
            if recovery_attempt:
                try:
                    self._retain_hold(owner)
                except BaseException:
                    error.add_note("s1_recovery_hold_unverified")
            owner._retain()
            raise
        finally:
            # Unregister may wait for callbacks: do it after all mutation/DB
            # scopes have exited. Keep the actual owner on any cleanup failure.
            try:
                if power is not None:
                    try:
                        power.close()
                    except BaseException as cleanup:
                        self._pending_power.append(power)
                        owner._retain()
                        try:
                            self._retain_hold(owner)
                        except BaseException:
                            cleanup.add_note("s1_recovery_hold_unverified")
                        if primary is None:
                            raise
                        primary.add_note("s1_recovery_power_cleanup_unverified")
                if completed and primary is None:
                    # Only completed power cleanup commits a reusable witness.
                    # Until owner.close releases Job custody, _prove_owner still
                    # re-queries the actual retained handle on every retry.
                    self._settled.update((value.owner.execution_id, value) for value in settled)
            finally:
                self._lock.release()
