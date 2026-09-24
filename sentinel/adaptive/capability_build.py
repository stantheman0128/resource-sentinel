"""Read actual canonical runtime and separate reviewed fixture inventories.

These frozen locators are evidence data, not execution or admission authority.
No test code is imported, no native API is called, and no runtime data is written.
The producer separately attests the bytes actually executed before publication.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path

from . import capability_evidence as evidence
from .daily_generation import SourceManifest, daily_locations, verify_import_provenance


_KIND = "canonical_runtime_fixture_inventory"


def _root(value):
    if type(value) is not str or not 0 < len(value) <= 32768 or "\0" in value:
        evidence._reject("capability_source_root_invalid")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        evidence._reject("capability_source_root_invalid")
    evidence._safe_directory(path)
    if path.resolve(strict=True) != path:
        evidence._reject("capability_source_root_invalid")
    return path


def _identity(path):
    info = os.lstat(path)
    if not info.st_ino:
        evidence._reject("capability_source_root_invalid")
    return info.st_dev, info.st_ino


def _namespace_layout(root):
    # tests/__init__.py is outside the three hashed inventories. The reviewed
    # bootstrap uses only restricted namespaces, never arbitrary package code.
    for directory in (root / "tests", *(root / "tests" / name for name in
            ("windows", "benchmarks", "fixtures"))):
        evidence._safe_directory(directory)
        if os.path.lexists(directory / "__init__.py"):
            evidence._reject("capability_fixture_layout_changed")


@dataclass(frozen=True)
class SourceBinding:
    schema_version: int
    kind: str
    runtime_root: str
    producer_root: str
    source_digest: str

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != 1 or
                type(self.kind) is not str or self.kind != _KIND or
                not evidence._digest(self.source_digest)):
            evidence._reject("capability_source_binding_invalid")
        runtime, _ = _root(self.runtime_root), _root(self.producer_root)
        canonical, _ = daily_locations()
        if runtime != canonical.resolve(strict=True) or runtime != evidence._ROOT.resolve(strict=True):
            evidence._reject("capability_canonical_source_required")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        evidence._object(value, ("schema_version", "kind", "runtime_root", "producer_root", "source_digest"))
        return cls(**value)


class SourceBoundBuildSource:
    """One original binding; changed generations/roots never become a refresh.

    Consumer construction verifies source data. It does not certify that a
    producer executed those bytes; only the concrete bootstrap can do that.
    """
    def __init__(self, binding):
        if type(binding) is not SourceBinding:
            evidence._reject("capability_source_binding_invalid")
        self.binding = binding
        self._original = binding.to_dict()
        self.runtime = _root(binding.runtime_root)
        self.producer = _root(binding.producer_root)
        _namespace_layout(self.producer)
        self._roots = (_identity(self.runtime), _identity(self.producer))
        self._manifest = SourceManifest.capture(self.runtime)
        if self._manifest.digest != binding.source_digest:
            evidence._reject("capability_source_generation_changed")
        self._runtime_source = evidence.CurrentBuildSource()
        self._producer_source = evidence.CurrentBuildSource()
        self._build = None

    def _verify(self):
        if type(self.binding) is not SourceBinding or self.binding.to_dict() != self._original:
            evidence._reject("capability_source_binding_changed")
        checked = SourceBinding.from_dict(self._original)
        _namespace_layout(self.producer)
        if (self.runtime != Path(checked.runtime_root) or self.producer != Path(checked.producer_root) or
                (_identity(self.runtime), _identity(self.producer)) != self._roots):
            evidence._reject("capability_source_root_changed")
        self._manifest.verify(self.runtime)
        # Matching files cannot certify an older consumer still loaded in this
        # process. This attests only canonical production modules, never tests.
        verify_import_provenance(self._manifest, self.runtime)

    def _read_build(self):
        return evidence.BuildIdentity(
            self._runtime_source._inventory((self.runtime / "sentinel",),
                (self.runtime / "scripts" / "invoke-sentinel.ps1",), relative_root=self.runtime),
            self._producer_source._inventory(tuple(self.producer / "tests" / name
                for name in ("windows", "benchmarks", "fixtures")), relative_root=self.producer),
        )

    def __call__(self):
        self._verify()
        build = self._read_build()
        # Recheck the original inventory/file fingerprints after both reads;
        # roots and the full daily closure must still be the same generation.
        self._verify()
        if self._read_build() != build or self._build is not None and self._build != build:
            evidence._reject("capability_build_changed")
        self._build = build
        return build
