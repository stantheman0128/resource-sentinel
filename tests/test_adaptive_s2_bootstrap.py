"""Actual source-only S2 subprocess checks, never a native S2 acceptance gate."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import subprocess
import unittest

from tests import test_adaptive_producer_bootstrap as bootstrap_tests


ROOT = Path(__file__).resolve().parents[1]
CLOSURE = (
    "tests/windows/run_adaptive_s2.py",
    "tests/windows/adaptive_producer_bootstrap.py",
    "tests/windows/adaptive_launch_producer.py",
    "tests/windows/adaptive_win32.py",
    "tests/fixtures/adaptive_launch_producer_child.py",
)


class S2SourceBootstrapTests(unittest.TestCase):
    def setUp(self):
        # Reuse only the isolated source-tree setup, not its S1 test methods.
        bootstrap_tests.ProducerBootstrapTests.setUp(self)
        for relative in CLOSURE:
            (self.producer / relative).write_bytes((ROOT / relative).read_bytes())
        self.entry = self.producer / CLOSURE[0]
        self.child = self.producer / CLOSURE[-1]
        self.environment = dict(os.environ, HOME=str(self.home), USERPROFILE=str(self.home))
        self.environment.pop("SENTINEL_ADAPTIVE_WINDOWS_SPIKES", None)

    def execute(self, entry, *arguments, isolated=True):
        return subprocess.run([self.python, *(["-I"] if isolated else []), str(entry), *arguments],
            env=self.environment, cwd=self.home, capture_output=True, text=True,
            encoding="utf-8", timeout=40, check=False)

    def source_pin(self):
        result = self.execute(self.entry, "--check-source")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        value = json.loads(result.stdout)
        self.assertEqual(value["status"], "source_verified")
        self.assertFalse(value["promotion"])
        return value["source_pin"]

    def invoke_child(self, pin):
        encoded = base64.b64encode(json.dumps(pin).encode()).decode("ascii")
        return self.execute(self.child, "--source-pin", encoded, "workload",
                            "--directory", str(self.home), "--token", "not-admission")

    def test_actual_parent_and_child_source_closures_match_without_native_artifacts(self):
        before = {path.relative_to(self.home) for path in self.home.rglob("*")}
        pin = self.source_pin()
        result = self.execute(self.child, "--check-source")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)["source_pin"], pin)
        self.assertEqual({path.relative_to(self.home) for path in self.home.rglob("*")}, before)
        self.assertFalse((self.home / ".resource-sentinel").exists())

    def test_entry_reports_missing_real_scope_without_native_work(self):
        result = self.execute(self.entry)
        self.assertEqual(result.returncode, 2, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["reason"], "s2_original_production_host_scope_unavailable")
        self.assertFalse(value["producer_native_work_started"])
        self.assertFalse(value["promotion"])

    def test_nonisolated_python_is_refused(self):
        result = self.execute(self.entry, "--check-source", isolated=False)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "bootstrap_failed")

    def test_boolean_schema_and_changed_runtime_pins_fail_before_work(self):
        pin = self.source_pin()
        for field, value in (("schema_version", True), ("python_sha256", "0" * 64)):
            with self.subTest(field=field):
                candidate = dict(pin, **{field: value})
                result = self.invoke_child(candidate)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("producer_bootstrap_source_pin_changed", result.stderr)
                self.assertNotIn("fixture-authorization.json", result.stderr)

    def test_changed_producer_source_cannot_use_old_pin(self):
        pin = self.source_pin()
        source = self.producer / "tests/windows/adaptive_win32.py"
        source.write_bytes(source.read_bytes() + b"\n# source drift after parent capture\n")
        result = self.invoke_child(pin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("producer_bootstrap_source_pin_changed", result.stderr)

    def test_changed_canonical_source_cannot_use_old_pin(self):
        pin = self.source_pin()
        source = self.runtime / "sentinel/adaptive/contracts.py"
        source.write_bytes(source.read_bytes() + b"\n# generation drift after parent capture\n")
        result = self.invoke_child(pin)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("producer_bootstrap_source_pin_changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
