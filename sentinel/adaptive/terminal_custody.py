"""Retained terminal cleanup; no native query after a close attempt begins.

The lifecycle creates this owner only after exact terminal/native proof and a
clean proof-fence exit. Close failures do not recreate handles or grant release
authority. Durable history is revalidated before each bounded cleanup attempt.
"""
from __future__ import annotations

from dataclasses import dataclass

from .contracts import CpuControl, CpuControlMode
from .control_slot import read_slot, _barrier_consistent
from .identity import VerifiedProcess, _known_close_failure
from .native_job import NativeJobError
from .store import LifecycleError
from .windows import NativePolicyMutexError


_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_OWNER_NAMES = ("root", "wrapper", "job", "mutex")


@dataclass(frozen=True)
class TerminalCleanupResult:
    execution_id: str
    complete: bool
    pending: bool
    quarantined: bool
    reason: str
    closed_owners: tuple[str, ...]


class TerminalCustody:
    """Original owners and immutable proof, published before the first close."""

    def __init__(self, entry, row, manifest, binding, *, slot_proof=None):
        self.execution_id = entry.execution_id
        self.row, self.manifest, self.binding = dict(row), manifest, binding
        self.slot_proof = None if slot_proof is None else dict(slot_proof)
        self.owners = {name: getattr(entry, name) for name in _OWNER_NAMES}
        self.states = {name: "absent" if owner is None else "owned"
                       for name, owner in self.owners.items()}
        self.error = None
        self.quarantined = False
        self.proof_published = False
        self.receipt_operation = None

    @property
    def closed_owners(self):
        return tuple(name for name in _OWNER_NAMES if self.states[name] == "closed")

    @property
    def native_complete(self):
        return all(state in {"absent", "closed"} for state in self.states.values())

    def result(self, *, complete=False, reason="guardian_terminal_cleanup_pending"):
        return TerminalCleanupResult(self.execution_id, complete, not complete,
                                     self.quarantined, reason, self.closed_owners)

    def verify(self, lifecycle, entry):
        """Read durable exact proof only; never use a possibly closed owner."""
        lifecycle._validate_guardian()
        if (entry.terminal_cleanup is not self or entry.manifest != self.manifest or
                any(getattr(entry, name) is not owner for name, owner in self.owners.items())):
            raise LifecycleError("guardian_terminal_custody_changed")
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("guardian_journal_cleanup_unverified")
        try:
            manifest = lifecycle.journal.read(self.execution_id,
                creation_nonce=self.manifest.creation_nonce)
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
                self.quarantined = True
            raise
        if manifest != self.manifest:
            raise LifecycleError("guardian_terminal_manifest_changed")
        row = lifecycle.store.query(self.execution_id, existing_path=True)
        if dict(row) != self.row:
            raise LifecycleError("guardian_terminal_row_changed")
        lifecycle.store.assert_retained_terminal(row, manifest)
        if (row["state"] != "FINISHED" or manifest.original != _DISABLED or
                manifest.pending_intent is not None or manifest.last_applied not in (None, _DISABLED)):
            raise LifecycleError("guardian_terminal_unverified")
        with lifecycle.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = lifecycle.store._policy._runtime(conn)
            binding = lifecycle.store._policy._binding(runtime, self.binding.logon_id)
            if binding != self.binding or runtime["guardian_epoch"] != manifest.guardian_epoch:
                raise LifecycleError("guardian_terminal_policy_changed")
            slot = read_slot(conn)
            _barrier_consistent(slot, runtime)
            if slot is not None:
                if (slot["policy_instance_id"] != binding.instance_id or
                        slot["policy_logon_id"] != binding.logon_id):
                    raise LifecycleError("control_slot_binding_mismatch")
                if slot["execution_id"] == self.execution_id and (
                        slot["slot_state"] != "RESTORED" or slot != self.slot_proof):
                    raise LifecycleError("guardian_terminal_slot_changed")
                # A later conservative off generation may raise a new global
                # HOLD after this exact terminal proof/cleanup was published.
                # It cannot authorize querying closed owners or erase their
                # completed proof. Continue cleanup, preserving the new HOLD.

    @staticmethod
    def _retryable(name, owner, error):
        if not isinstance(error, Exception) or getattr(error, "_native_close_outcome_unknown", False):
            return False
        if isinstance(owner, VerifiedProcess):
            return _known_close_failure(error) and owner._close_outcome_unknown is False
        if name == "job":
            return (isinstance(error, NativeJobError) and
                    getattr(error, "_known_native_close_failed", False) is True and
                    not getattr(error, "__notes__", ()))
        if name == "mutex":
            return (isinstance(error, NativePolicyMutexError) and
                    error.reason == "policy_mutex_handle_close_failed" and
                    type(error.win32_error) is int and error.win32_error > 0 and
                    not getattr(error, "__notes__", ()))
        return False

    def close_remaining(self):
        if self.quarantined:
            raise LifecycleError("guardian_terminal_cleanup_quarantined")
        for name in _OWNER_NAMES:
            if self.states[name] in {"absent", "closed"}:
                continue
            if self.states[name] != "owned":
                self.quarantined = True
                raise LifecycleError("guardian_terminal_cleanup_quarantined")
            owner = self.owners[name]
            # This marker precedes native entry, including process interrupts
            # between successful CloseHandle and its Python acknowledgement.
            self.states[name] = "close_unknown"
            try:
                owner.close()
            except BaseException as error:
                self.error = error
                if self._retryable(name, owner, error):
                    self.states[name] = "owned"
                else:
                    self.quarantined = True
                raise
            self.states[name] = "closed"
