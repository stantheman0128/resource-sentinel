"""scripts/adaptive-supervisor.ps1: a thin entry point with no stop path.

The structural cases read the script text. The subprocess cases run it with
Windows PowerShell against temporary directories that hold no ledger, so the
supervisor host refuses before it creates anything: with the capability refusal
a directly started interpreter gets here, or with
supervisor_host_ledger_unavailable where that interpreter passes the preflight.
No guardian is started either way.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from sentinel.adaptive.supervisor_host import EXIT_REFUSED


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "adaptive-supervisor.ps1"
# Anything that ends, pauses or reschedules a process, or installs a task.
FORBIDDEN = ("taskkill", "stop-process", ".kill(", "terminate", "suspend", "schtasks",
             "register-scheduledtask", "set-scheduledtask", "start-process", "invoke-expression",
             "priorityclass", "breakaway")


def code_lines():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    return [line for line in lines if not line.lstrip().startswith("#")]


class ScriptStructureTests(unittest.TestCase):
    def test_the_code_names_no_stop_path_and_installs_nothing(self):
        code = "\n".join(code_lines()).lower()
        for token in FORBIDDEN:
            self.assertNotIn(token, code)

    def test_both_directories_are_mandatory_and_have_no_default(self):
        code = "\n".join(code_lines())
        for name in ("DataDir", "JournalDir"):
            declaration = re.search(r"\[Parameter\(Mandatory = \$true\)\]\[string\]\$" + name + r"\b(.*)",
                                    code)
            self.assertIsNotNone(declaration)
            self.assertNotIn("=", declaration.group(1))
        self.assertNotIn(".resource-sentinel", code)
        self.assertNotIn("USERPROFILE", code)

    def test_the_launcher_only_names_the_interpreter_and_the_host_starts_without_it(self):
        code = "\n".join(code_lines())
        self.assertEqual(re.findall(r"&\s+(\S+)", code), ["py", "$Python"])
        self.assertIn("& py -c 'import sys; print(sys._base_executable or sys.executable)'", code)
        self.assertIn("& $Python @argsList", code)
        self.assertIn("'sentinel.adaptive.supervisor_host'", code)


def direct_interpreter_refusal():
    """What an interpreter started without the py launcher answers here, or None.

    The launcher assigns python.exe to a Job of its own, so the test runner's own
    answer says nothing about the process the script starts.
    """
    probe = ("from tests.test_adaptive_host_authority import live_capability_refusal\n"
             "print('refusal=' + (live_capability_refusal() or ''))")
    completed = subprocess.run([sys._base_executable, "-c", probe], capture_output=True, text=True,
                               timeout=60, cwd=REPO_ROOT)
    answers = [line for line in completed.stdout.splitlines() if line.startswith("refusal=")]
    if completed.returncode != 0 or len(answers) != 1:
        raise AssertionError("direct interpreter probe failed: " + completed.stderr[-400:])
    return answers[0][len("refusal="):] or None


class ScriptSubprocessTests(unittest.TestCase):
    def run_script(self, data_dir, journal_dir, *extra):
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT),
             "-DataDir", str(data_dir), "-JournalDir", str(journal_dir), "-Iterations", "1", *extra],
            capture_output=True, text=True, timeout=120, cwd=REPO_ROOT)

    def test_an_interpreter_path_that_is_not_a_file_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_script(temporary, temporary, "-Python",
                                        str(Path(temporary) / "absent.exe"))
            leftovers = sorted(path.name for path in Path(temporary).iterdir())
        self.assertEqual(completed.returncode, EXIT_REFUSED)
        self.assertIn("adaptive_supervisor_python_unresolved", completed.stderr)
        self.assertNotIn("supervisor_host", completed.stderr)
        self.assertEqual(leftovers, [])

    def test_a_missing_directory_is_refused_before_python_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = self.run_script(Path(temporary) / "absent", temporary)
        self.assertEqual(completed.returncode, EXIT_REFUSED)
        self.assertIn("adaptive_supervisor_directory_missing", completed.stderr)
        self.assertNotIn("supervisor_host", completed.stderr)

    def test_the_host_refusal_and_its_exit_code_pass_through(self):
        expected = direct_interpreter_refusal() or "supervisor_host_ledger_unavailable"
        for extra in ((), ("-Python", sys._base_executable)):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                completed = self.run_script(temporary, temporary, *extra)
                leftovers = sorted(path.name for path in Path(temporary).iterdir())
                self.assertEqual(completed.returncode, EXIT_REFUSED)
                records = [json.loads(line) for line in completed.stderr.splitlines()
                           if line.startswith("{")]
                self.assertEqual([record["event"] for record in records], ["supervisor_host_refused"])
                self.assertEqual(records[0]["reason"], expected)
                self.assertFalse(records[0]["guardian_created"])
                self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
