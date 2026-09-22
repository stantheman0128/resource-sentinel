"""Match retained original launches to the exact validated S2 observations.

Both collaborators are trusted in-process owners. No wire field, database flag,
or caller-supplied digest can populate a positive measured scope. The authority
loads and validates its pinned bundle outside POLICY; this callable only reads
immutable prepared data and original guardian custody, without native probes.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from .launch_topology import LaunchTopology, OriginalLaunchProvenance, _digest
from .store import LifecycleError


class LaunchScopeUnavailable(LifecycleError):
    """A known absent/mismatched observation, carrying no native custody."""
    def __init__(self):
        super().__init__("capability_launch_scope_unverified")


def _deny():
    raise LaunchScopeUnavailable()


@dataclass(frozen=True)
class RetainedLaunchProvenance:
    execution_id: str
    job_nonce: str
    provenance: OriginalLaunchProvenance

    def __post_init__(self):
        try:
            valid_id = type(self.execution_id) is str and str(UUID(self.execution_id)) == self.execution_id
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        if (not valid_id or type(self.job_nonce) is not str or len(self.job_nonce) != 32 or
                any(char not in "0123456789abcdef" for char in self.job_nonce) or
                type(self.provenance) is not OriginalLaunchProvenance):
            _deny()


@dataclass(frozen=True)
class MeasuredLaunchTopologies:
    config_revision: str
    host_fingerprint: str
    bundle_sha256: str
    topologies: tuple[LaunchTopology, ...]

    def __post_init__(self):
        if (not all(_digest(value) for value in
                    (self.config_revision, self.host_fingerprint, self.bundle_sha256)) or
                type(self.topologies) is not tuple or not 1 <= len(self.topologies) <= 32 or
                any(type(value) is not LaunchTopology or value.shell_kind not in {"powershell51", "pwsh"}
                    for value in self.topologies) or len(set(self.topologies)) != len(self.topologies)):
            _deny()


class RetainedLaunchScopeSource:
    """Only the original guardian custody can provide actual launch scope.

    ``owner.launch_provenance_for`` rechecks its retained execution, original
    wrapper/root and Job nonce. A replacement guardian without that custody
    fails closed. This restriction never gates owned restoration.
    """
    def __init__(self, *, owner, authority):
        self.owner, self.authority = owner, authority

    def __call__(self, *, execution_id, config_revision, host_fingerprint, bundle_sha256):
        measured = self.authority.prepared_launch_topologies()
        if (type(measured) is not MeasuredLaunchTopologies or
                measured.config_revision != config_revision or
                measured.host_fingerprint != host_fingerprint or
                measured.bundle_sha256 != bundle_sha256):
            _deny()
        retained = self.owner.launch_provenance_for(execution_id)
        if type(retained) is not RetainedLaunchProvenance or retained.execution_id != execution_id:
            _deny()
        topology = retained.provenance.topology
        if topology not in measured.topologies:
            _deny()
        from .capability_evidence import VerifiedLaunchScope
        # Hashes are computed here from equal typed observations, not accepted
        # from the wrapper, caller or producer as independent permission.
        matched = next(item for item in measured.topologies if item == topology)
        return VerifiedLaunchScope(execution_id, config_revision, host_fingerprint,
            bundle_sha256, matched.sha256, topology.sha256)
