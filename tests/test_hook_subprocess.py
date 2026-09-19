"""Exercise real hook entrypoints with a private USERPROFILE and queue only."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HookSubprocessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.home = Path(self.tmp.name)
        self.data = self.home / ".resource-sentinel"
        self.env = {**os.environ, "USERPROFILE": str(self.home)}

    def tearDown(self):
        self.tmp.cleanup()

    def gate(self, command):
        return subprocess.run(
            [sys.executable, str(ROOT / "hooks/sentinel-gate.py")],
            input=json.dumps({"tool_name": "Bash", "tool_use_id": "isolated-test",
                              "tool_input": {"command": command}}),
            capture_output=True, text=True, env=self.env, cwd=ROOT, timeout=15,
        )

    def test_read_only_paths_do_not_create_an_admission_database(self):
        for command in ("git show branch:app/build.gradle.kts",
                        "git add app/build.gradle.kts", "ls ~/.gradle/jdks"):
            with self.subTest(command=command):
                result = self.gate(command)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.data / "sentinel.db").exists())

    def test_real_gradle_is_queued_when_measurements_are_missing(self):
        result = self.gate('bash -c "cd app && ./gradlew.bat build"')
        self.assertEqual(result.returncode, 2, result.stderr)
        conn = sqlite3.connect(self.data / "sentinel.db")
        try:
            rows = conn.execute("SELECT resource_class FROM queue").fetchall()
            self.assertEqual(rows, [("HEAVY",)])
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reservations").fetchone()[0], 0)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
