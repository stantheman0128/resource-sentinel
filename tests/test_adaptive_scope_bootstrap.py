"""Portable import provenance regressions; no native scope or capacity is used.

Each bootstrap runs in a fresh isolated Python process so the real execution
audit hook cannot alter the unittest process or inherit its Sentinel imports.
The small canonical tree is an explicit source fixture, never activated code.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import time
import unittest
from uuid import uuid4

from sentinel.adaptive.daily_generation import REQUIRED_PATHS, SourceManifest
from tests.windows import adaptive_scope_launch as scope
from tests.windows import adaptive_scope_wrapper as wrapper


_RUNNER = r'''
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType

wrapper_path, bootstrap_path, checksum, home, mode = sys.argv[1:]
Path.home = classmethod(lambda cls: Path(home))
spec = importlib.util.spec_from_file_location("scope_bootstrap_fixture", wrapper_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
exec(compile(Path(wrapper_path).read_bytes(), wrapper_path, "exec", dont_inherit=True), module.__dict__)
probe = None
if mode == "fixture_stale":
    # Prove the cache really is timestamp-valid: the ordinary loader executes
    # OLD even though the source pinned in the bootstrap now contains NEW.
    path = str(Path(wrapper_path).with_name("adaptive_scope_launch.py"))
    cached_spec = importlib.util.spec_from_file_location("scope_cached_probe", path)
    cached = importlib.util.module_from_spec(cached_spec)
    sys.modules[cached_spec.name] = cached
    cached_spec.loader.exec_module(cached)
    probe = cached.FIXTURE_INITIALIZER
elif mode == "preloaded":
    sys.modules["sentinel"] = ModuleType("sentinel")
elif mode == "ambient":
    sys.path.append(str(Path(home) / "ambient"))
try:
    payload, launch, command, manifest = module.load_bootstrap(bootstrap_path, checksum)
    outcome = {"accepted": True, "command_sha256": command.sha256,
               "fixture_initializer": getattr(launch, "FIXTURE_INITIALIZER", None)}
except Exception as error:
    outcome = {"accepted": False, "reason": str(error)}
observer = sys.modules.get("sentinel_daily_bootstrap")
adaptive = sys.modules.get("sentinel.adaptive")
outcome.update(cached_fixture_initializer=probe,
               production_initializer=getattr(adaptive, "PRODUCTION_INITIALIZER", None),
               observer_installed=getattr(observer, "_OBSERVER", None) is not None,
               wrapper_owners=len(module._RETAINED))
print(json.dumps(outcome, sort_keys=True))
'''


class ScopeBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.root = self.home / "Projects" / "resource-sentinel"
        self.fixtures = self.home / "fixtures"
        self.fixtures.mkdir()
        self.original_root = Path(scope.__file__).resolve().parents[2]
        # Keep the SourceManifest's actual closed source/schema rules. Only the
        # imports exercised by bootstrap need executable production contents.
        for relative in REQUIRED_PATHS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# portable source fixture\n")
        for relative in ("sentinel_daily_bootstrap.py", "sentinel/adaptive/__init__.py",
                         "sentinel/adaptive/daily_generation.py", "sentinel/adaptive/contracts.py",
                         "sentinel/adaptive/identity.py", "sentinel/adaptive/pipe_windows.py",
                         "sentinel/adaptive/windows.py"):
            (self.root / relative).write_bytes((self.original_root / relative).read_bytes())
        # The production package installs its original observer at this exact
        # entry boundary. Other coordinator imports are irrelevant to this test.
        (self.root / "sentinel/__init__.py").write_bytes(
            b"import sentinel_daily_bootstrap as _daily_bootstrap\n"
            b"_daily_bootstrap.observe_package_import()\n")
        self.wrapper_path = self.fixtures / "adaptive_scope_wrapper.py"
        self.launch_path = self.fixtures / "adaptive_scope_launch.py"
        self.wrapper_path.write_bytes(Path(wrapper.__file__).read_bytes())
        self.launch_path.write_bytes(Path(scope.__file__).read_bytes())
        self.workload = self.fixtures / "workload.py"
        self.workload.write_bytes(b"# source pin only; never executed\n")
        self.executable = str(Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True))
        self.command = scope.ScopeCommand.capture(application=self.executable,
            arguments=("-I", str(self.workload)), cwd=self.home, fixture_paths=(self.workload,))
        self.scope_id = str(uuid4())
        self.bootstrap_path = self.home / ("scope-wrapper-" + self.scope_id + ".json")

    def payload(self):
        manifest = SourceManifest.capture(self.root)
        nonce = uuid4().hex
        generation = dict(singleton=1, schema_version=1, generation=str(uuid4()), state="ACTIVE",
            source_digest=manifest.digest, config_digest="a" * 64,
            source_manifest_json=json.dumps(manifest.to_dict()), source_root=str(self.root),
            ledger_path=str(self.home / "fixture-ledger.sqlite3"),
            owner_identity_json=json.dumps(dict(pid=101, created_filetime_100ns=123456, logon_id="S-1-5-5-1-2")),
            ledger_identity_json=json.dumps(["1", "2"]), readiness_instance_id=str(uuid4()))
        return dict(schema_version=2, scope_id=self.scope_id, job_nonce=nonce,
            job_name="Local\\ResourceSentinel.Test.Job." + nonce,
            guardian_identity=dict(pid=101, created_filetime_100ns=123456, logon_id="S-1-5-5-1-2"),
            endpoint_instance=str(uuid4()), deadline_monotonic=time.monotonic() + 120,
            command=self.command.to_dict(), command_sha256=self.command.sha256,
            canonical_source=str(self.root), generation=generation,
            reservation_id="r" * 32, binding_sha256="b" * 64,
            request_marker=str(self.home / ("scope-request-" + self.scope_id + ".json")),
            fixture_sources=[scope.FixtureSource.capture(path).to_dict()
                             for path in (self.launch_path, self.wrapper_path)],
            python_sha256=hashlib.sha256(Path(self.executable).read_bytes()).hexdigest())

    def bootstrap(self, payload=None, *, mode="normal"):
        data = scope.canonical(self.payload() if payload is None else payload)
        self.bootstrap_path.write_bytes(data)
        result = subprocess.run([self.executable, "-I", "-c", _RUNNER,
            str(self.wrapper_path), str(self.bootstrap_path), hashlib.sha256(data).hexdigest(),
            str(self.home), mode], capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(outcome["wrapper_owners"], 0, "bootstrap must acquire no native owner")
        return outcome

    def timestamp_valid_stale_cache(self, path, name):
        original = path.read_bytes()
        old = original + ("\n" + name + " = 'OLD'\n").encode()
        new = original + ("\n" + name + " = 'NEW'\n").encode()
        self.assertEqual(len(old), len(new))
        timestamp = 1_690_000_000_000_000_000
        path.write_bytes(old)
        os.utime(path, ns=(timestamp, timestamp))
        cached = Path(py_compile.compile(str(path), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
        path.write_bytes(new)
        os.utime(path, ns=(timestamp, timestamp))
        self.assertTrue(cached.is_file())
        self.assertEqual(path.stat().st_mtime_ns, timestamp)
        return cached

    def test_fresh_bootstrap_installs_actual_import_observer_before_native_owners(self):
        outcome = self.bootstrap()
        self.assertTrue(outcome["accepted"], outcome)
        self.assertTrue(outcome["observer_installed"])
        self.assertEqual(outcome["command_sha256"], self.command.sha256)

    def test_fixture_executes_verified_bytes_despite_timestamp_valid_stale_pyc(self):
        self.timestamp_valid_stale_cache(self.launch_path, "FIXTURE_INITIALIZER")
        outcome = self.bootstrap(mode="fixture_stale")
        self.assertEqual(outcome["cached_fixture_initializer"], "OLD")
        self.assertTrue(outcome["accepted"], outcome)
        self.assertEqual(outcome["fixture_initializer"], "NEW")
        self.assertTrue(outcome["observer_installed"])

    def test_stale_production_module_initializer_fails_actual_import_attestation(self):
        self.timestamp_valid_stale_cache(self.root / "sentinel/adaptive/__init__.py",
                                         "PRODUCTION_INITIALIZER")
        outcome = self.bootstrap()
        self.assertFalse(outcome["accepted"])
        self.assertEqual(outcome["production_initializer"], "OLD")
        self.assertTrue(outcome["observer_installed"])
        self.assertEqual(outcome["reason"], "daily_executed_module_generation_mismatch")

    def test_foreign_canonical_root_refused_before_import(self):
        payload = self.payload()
        foreign = self.home / "foreign"
        foreign.mkdir()
        outcome = self.bootstrap(payload | {"canonical_source": str(foreign)})
        self.assertEqual(outcome["reason"], "scope_canonical_source_required")
        self.assertFalse(outcome["observer_installed"])

    def test_changed_fixture_pin_refused_before_import(self):
        payload = self.payload()
        self.launch_path.write_bytes(self.launch_path.read_bytes() + b"\n# changed\n")
        outcome = self.bootstrap(payload)
        self.assertEqual(outcome["reason"], "scope_fixture_changed")
        self.assertFalse(outcome["observer_installed"])

    def test_changed_production_source_pin_refused(self):
        payload = self.payload()
        path = self.root / "sentinel/adaptive/contracts.py"
        path.write_bytes(path.read_bytes() + b"\n# source changed\n")
        outcome = self.bootstrap(payload)
        self.assertFalse(outcome["accepted"])
        self.assertEqual(outcome["reason"], "daily_source_generation_mismatch")

    def test_changed_manifest_digest_refused(self):
        payload = self.payload()
        payload["generation"]["source_digest"] = "0" * 64
        outcome = self.bootstrap(payload)
        self.assertEqual(outcome["reason"], "scope_source_digest_changed")

    def test_bootstrap_requires_v2_and_full_original_generation(self):
        for change in ("version", "missing", "type", "extra"):
            payload = self.payload()
            if change == "version":
                payload["schema_version"] = 1
            elif change == "missing":
                del payload["generation"]["config_digest"]
            elif change == "type":
                payload["generation"]["singleton"] = True
            else:
                payload["generation"]["authorized"] = True
            with self.subTest(change=change):
                outcome = self.bootstrap(payload)
                self.assertFalse(outcome["accepted"])
                self.assertEqual(outcome["reason"], "scope_bootstrap_invalid" if change == "version"
                    else "scope_source_generation_changed")

    def test_preloaded_sentinel_cannot_replace_original_import_attestation(self):
        outcome = self.bootstrap(mode="preloaded")
        self.assertEqual(outcome["reason"], "scope_sentinel_preloaded")
        self.assertFalse(outcome["observer_installed"])

    def test_ambient_sentinel_provider_refused_before_import(self):
        (self.home / "ambient" / "sentinel").mkdir(parents=True)
        outcome = self.bootstrap(mode="ambient")
        self.assertEqual(outcome["reason"], "scope_ambient_sentinel_path")
        self.assertFalse(outcome["observer_installed"])


if __name__ == "__main__":
    unittest.main()
