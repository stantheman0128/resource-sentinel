"""Explicit drain observations, without restrictive decisions or proposals.

The observer samples retained query handles and authoritative frame bindings.
It owns no actuator or release authority. Guardian consumes consecutive fresh
uncapped frames and decides whether its admission barrier may clear; five
helper ticks, five Query flags, or a transport ACK alone prove no such release.

Construction and ordinary off/shadow ticks send nothing. Only request_drain()
enables the frame-only sender. A pending frame retains its exact request ID,
payload and endpoint across uncertainty; a retry never mints a fresh sample.
"""
from dataclasses import dataclass
from uuid import uuid4

from .contracts import FastFrame, TICKS_PER_SECOND, Validity
from .control_messages import ControlFrameAck, ControlObservation
from .helper_control import ControlBindingSnapshot, HelperControlError
from .sampler import FrameSampler, profile_revision

TICKS_PER_MS = TICKS_PER_SECOND // 1000


@dataclass(frozen=True)
class PendingDrainFrame:
    request_id: str
    binding: ControlBindingSnapshot
    frame: FastFrame


@dataclass(frozen=True)
class DrainObservationResult:
    reason: str
    sampled: bool = False
    operation: str | None = None
    acknowledged: bool = False
    uncertain: bool = False
    complete: bool = False


def _same_endpoint(left, right):
    return all(getattr(left, name) == getattr(right, name) for name in (
        "endpoint", "helper_identity", "guardian_epoch", "policy_epoch", "config_revision"))


def _scope_rows(binding):
    return tuple((row["execution_id"], row["job_name"], row["job_nonce"],
                  row["logon_id"], row["counter_epoch"]) for row in binding.executions)


def _cleanup_unknown(error):
    """Recognize retained native custody without closing/retrying its owners."""
    seen = set()
    for _ in range(8):
        if error is None or id(error) in seen:
            return False
        seen.add(id(error))
        if (getattr(error, "io_pending", False) is True
                or getattr(error, "_identity_handle_cleanup", ())
                or getattr(error, "_policy_mutex_cleanup", ())
                or getattr(error, "__notes__", ())
                or getattr(error, "reason", "") in {
                    "pipe_quarantined", "pipe_peer_close_failed", "pipe_identity_close_failed",
                    "pipe_handle_close_failed", "pipe_event_close_failed", "pipe_io_pending"}):
            return True
        error = getattr(error, "_control_cause", None)
    return error is not None  # An unexpectedly deep chain is unknown.


class HelperDrainObserver:
    """One explicit drain, one outstanding immutable observation at a time.

    restore_pending is a required live host callback. Only exactly False means
    there is no active sender restoration obligation; missing/unknown/error
    cannot turn into completion. It does not authorize this observer to restore.
    client_factory must return a frame-only client, never an active control
    client. All production observations still traverse authenticated transport.
    """
    def __init__(self, *, profile, sampler, binding_source, client_factory, clock,
                 restore_pending):
        if (not isinstance(sampler, FrameSampler) or not callable(clock)
                or not callable(client_factory) or not callable(restore_pending)
                or not callable(getattr(binding_source, "read", None))
                or not callable(getattr(binding_source, "confirm_unchanged", None))):
            raise HelperControlError("helper_drain_sources_invalid")
        if profile_revision(profile) != sampler.config_revision:
            raise HelperControlError("helper_drain_profile_mismatch")
        self.profile, self.sampler, self.source = profile, sampler, binding_source
        self.clock, self.restore_pending = clock, restore_pending
        self._factory, self._client, self._binding = client_factory, None, None
        self.pending = None
        self._requested = self._complete = self._uncertain = False
        self._last_sequence = None
        self._failure = None
        self._cleanup_failure = None

    @property
    def complete(self):
        return self._complete

    @property
    def drain_pending(self):
        return self._requested and not self._complete

    @property
    def cleanup_pending(self):
        return self._cleanup_failure is not None

    def _result(self, reason, *, sampled=False, acknowledged=False):
        return DrainObservationResult(reason, sampled, "frame" if sampled or acknowledged or self.pending else None,
                                      acknowledged, self._uncertain, self._complete)

    def request_drain(self):
        self._requested = True
        return self._result("helper_drain_requested")

    def _read(self, ids):
        binding = self.source.read(ids)
        if (type(binding) is not ControlBindingSnapshot
                or binding.config_revision != self.sampler.config_revision
                or set(binding.execution_ids) != set(ids)):
            raise HelperControlError("helper_drain_binding_invalid")
        if self._binding is not None and not _same_endpoint(binding, self._binding):
            raise HelperControlError("helper_drain_epoch_changed")
        return binding

    def _can_complete(self, binding):
        # No cached ACK or local sample count can clear this host's obligation.
        # Recheck the exact binding around the host's restoration-state read.
        return (not self.cleanup_pending and binding.mode == "off"
                and binding.admission_barrier == "NONE"
                and self.restore_pending() is False
                and self.source.confirm_unchanged(binding) is True)

    def _ensure_client(self, binding):
        if self._client is None:
            client = self._factory(binding.endpoint, binding.helper_identity)
            self._client = client  # retain a partially unsuitable owner too.
        if (not callable(getattr(self._client, "observe_uncapped", None))
                or hasattr(self._client, "propose") or hasattr(self._client, "request_restore")):
            raise HelperControlError("helper_drain_frame_only_client_required")
        return self._client

    def _fresh_frame(self, frame, binding):
        now = self.clock()
        if (type(now) is not int or type(frame) is not FastFrame
                or frame.validity is not Validity.VALID
                or frame.config_revision != binding.config_revision
                or frame.registry_revision != binding.registry_revision
                or not frame.window_start_tick_100ns < frame.window_end_tick_100ns <= frame.published_tick_100ns <= now
                or now - frame.window_end_tick_100ns > self.profile.sample_max_age_ms * TICKS_PER_MS
                or {job.execution_id: job.counter_epoch for job in frame.jobs} !=
                   {row["execution_id"]: row["counter_epoch"] for row in binding.executions}
                or any(not job.membership_complete or job.cpu_units is None for job in frame.jobs)):
            raise HelperControlError("helper_drain_frame_unavailable")
        sequence = (frame.sampler_epoch, frame.clock_epoch, frame.sample_seq)
        if self._last_sequence is not None and sequence[:2] == self._last_sequence[:2] and sequence[2] <= self._last_sequence[2]:
            raise HelperControlError("helper_drain_frame_replayed")

    def _validate_ack(self, operation, ack):
        frame, binding = operation.frame, operation.binding
        if (type(ack) is not ControlFrameAck or ack.request_id != operation.request_id
                or ack.guardian_epoch != binding.guardian_epoch or ack.policy_epoch != binding.policy_epoch
                or ack.sampler_epoch != frame.sampler_epoch or ack.clock_epoch != frame.clock_epoch
                or ack.sample_seq != frame.sample_seq or ack.config_revision != binding.config_revision
                or {result.execution_id for result in ack.results} != {job.execution_id for job in frame.jobs}
                or ack.registry_revision < binding.registry_revision):
            raise HelperControlError("helper_drain_ack_mismatch")
        now = self.clock()
        if type(now) is not int or now < frame.window_end_tick_100ns:
            raise HelperControlError("helper_drain_ack_clock_invalid")
        for result in ack.results:
            if (result.observation in (ControlObservation.UNCAPPED, ControlObservation.CAPPED)
                    and not frame.window_end_tick_100ns <= result.queried_tick_100ns <= now):
                raise HelperControlError("helper_drain_ack_query_invalid")
        # A definitive REJECTED/UNVERIFIED response consumes this request but
        # proves no uncapped sample. The next tick obtains a new actual frame.
        return all(result.observation is ControlObservation.UNCAPPED for result in ack.results)

    def _send_pending(self, *, sampled):
        operation = self.pending
        # Replays are acknowledgements of the OLD immutable observation, never
        # fresh samples. Endpoint/Job identity changes cannot adopt that request.
        # A naturally retired execution is no longer RUNNING/DRAINING and the
        # live source correctly refuses its old row. Reconcile the old request
        # against the current exact endpoint and currently retained enrollment;
        # guardian alone recognizes its immutable cached ACK/stale rejection.
        current = self._read(self.sampler.enrolled)
        original_rows = {row[0]: row for row in _scope_rows(operation.binding)}
        if (not _same_endpoint(current, operation.binding) or any(
                row[0] in original_rows and row != original_rows[row[0]]
                for row in _scope_rows(current))):
            raise HelperControlError("helper_drain_pending_scope_changed")
        client = self._ensure_client(operation.binding)
        try:
            ack = client.observe_uncapped(operation.frame, request_id=operation.request_id,
                guardian_epoch=operation.binding.guardian_epoch,
                policy_epoch=operation.binding.policy_epoch, timeout_ms=500)
            uncapped = self._validate_ack(operation, ack)
        except BaseException as error:
            self._uncertain = True
            if _cleanup_unknown(error):
                self._cleanup_failure = error
            raise
        self.pending = None
        self._uncertain = False
        self._last_sequence = (operation.frame.sampler_epoch, operation.frame.clock_epoch,
                               operation.frame.sample_seq)
        fresh = self._read(self.sampler.enrolled)
        self._binding = fresh
        self._complete = self._can_complete(fresh)
        return self._result("helper_drain_complete" if self._complete else
            "helper_drain_observing" if uncapped else "helper_drain_observation_rejected",
            sampled=sampled, acknowledged=True)

    def tick(self):
        if not self._requested:
            return self._result("helper_drain_not_requested")
        self._complete = False
        if self.cleanup_pending:
            return self._result("helper_drain_cleanup_pending")
        try:
            if self.pending is not None:
                return self._send_pending(sampled=False)
            binding = self._read(self.sampler.enrolled)
            self._binding = binding
            if self._can_complete(binding):
                self._complete = True
                return self._result("helper_drain_complete")
            result = self.sampler.sample(binding=binding.frame_binding())
            if result.frame is None or result.reset_required:
                return self._result("helper_drain_frame_unavailable")
            self._fresh_frame(result.frame, binding)
            if self.source.confirm_unchanged(binding) is not True:
                return self._result("helper_drain_binding_changed_during_capture")
            self._ensure_client(binding)
            self.pending = PendingDrainFrame(str(uuid4()), binding, result.frame)
            return self._send_pending(sampled=True)
        except Exception as error:
            self._failure = error
            reason = getattr(error, "reason", "helper_drain_observation_unavailable")
            if self.pending is not None:
                self._uncertain = True
            return self._result(reason)
