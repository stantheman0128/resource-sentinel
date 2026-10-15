import contextlib
import ctypes
import io
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from sentinel.guardian import daemon as D

ARGS = ["--instance", "rtest", "--port", "8791"]
ORIG = [r"C:\Py 3\python.exe", "-I", r"C:\R & D\scripts\guardian.py", *ARGS]
CREATED = subprocess.CompletedProcess([], 0, "0 4242\r\n", "")
LEAVING = "[guardian] leaving the job: starting again outside it through WMI"


def split(cmdline):
    """Windows' own parse of a command line (CommandLineToArgvW), independent of list2cmdline."""
    f = ctypes.windll.shell32.CommandLineToArgvW
    f.restype, f.argtypes = ctypes.POINTER(ctypes.c_wchar_p), [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_int)]
    n = ctypes.c_int()
    p = f(cmdline, ctypes.byref(n))
    try:
        return [p[i] for i in range(n.value)]
    finally:
        ctypes.windll.kernel32.LocalFree(p)


class LeaveJobTests(unittest.TestCase):
    def start(self, in_job=True, log=None, run=None, args=(), argv=None, out=None, utf8=0, exited=False):
        """D.main() as scripts/guardian.py calls it, stdout and stderr in one stream as under `>> log 2>&1`. Returns
        (exit code, what it printed to a StringIO); the Guardian, subprocess.run and exited_within mocks stay on
        self."""
        self.run, self.watch = run or mock.Mock(return_value=CREATED), mock.Mock(return_value=exited)
        out = out or io.StringIO()
        with mock.patch.object(sys, "argv", ["guardian.py", *ARGS, *args]), \
                mock.patch.object(sys, "orig_argv", [*ORIG, *args]), \
                mock.patch.object(sys, "flags", mock.Mock(utf8_mode=utf8)), \
                mock.patch.object(D, "ping", lambda i: None), \
                mock.patch.object(D.wj, "in_job", mock.Mock(return_value=in_job)), \
                mock.patch.object(D, "stdout_path", lambda: log), mock.patch.object(D.subprocess, "run", self.run), \
                mock.patch.object(D, "exited_within", self.watch), mock.patch.object(D, "Guardian") as self.G, \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = D.main(argv)
        return rc, out.getvalue() if isinstance(out, io.StringIO) else None

    def test_not_in_a_job_runs_in_place(self):
        self.assertEqual(self.start(in_job=False, log=r"C:\x\rtest.log"), (0, ""))
        self.run.assert_not_called()
        self.G.assert_called_once()

    def test_in_a_job_with_file_stdout_starts_again_through_wmi_and_watches_the_new_copy(self):
        for exited in (False, True):
            with self.subTest(exited=exited), tempfile.TemporaryDirectory() as d:
                log = os.path.join(d, "log dir", "rtest.log")
                os.mkdir(os.path.dirname(log))

                def create(*a, **k):  # the new copy appends through a handle of its own
                    with open(log, "a") as f:
                        f.write("new copy\n")
                    return CREATED
                with open(log, "w") as out:
                    rc, _ = self.start(log=log, run=mock.Mock(side_effect=create), out=out, exited=exited)
                self.assertEqual(rc, 0)
                argv, kw = self.run.call_args.args[0], self.run.call_args.kwargs
                self.assertEqual(argv[:4], [D.POWERSHELL, "-NoProfile", "-NonInteractive", "-Command"])
                self.assertIn("CommandLine = $env:GUARDIAN_RELAUNCH_COMMAND", argv[-1])
                self.assertFalse([x for x in argv if "8791" in x or "R & D" in x])  # nothing spliced into the script
                self.assertEqual(kw["env"]["GUARDIAN_RELAUNCH_CWD"], os.getcwd())
                self.assertEqual((kw["timeout"], kw["creationflags"]), (30, D.CREATE_NO_WINDOW))
                self.watch.assert_called_once_with(4242, 3.0)
                self.assertEqual(self.G.call_count, exited)  # runs in place only when the new copy died at once
                with open(log) as f:
                    lines = f.read().splitlines()
                self.assertEqual(lines[:2], [LEAVING, "new copy"])  # the leaving line first, then nothing overwritten
                self.assertEqual(len(lines), 2 + exited)
                if exited:
                    self.assertIn("the copy started outside the job (conhost pid 4242) exited at once", lines[2])

    def test_the_command_line_windows_reads_back_passes_utf8_mode_on(self):
        for utf8, x in ((0, []), (1, ["-X", "utf8"])):
            with self.subTest(utf8=utf8):
                self.start(log=r"C:\R & D\rtest.log", utf8=utf8)
                self.assertEqual(split(self.run.call_args.kwargs["env"]["GUARDIAN_RELAUNCH_COMMAND"]),
                                 [D.CONHOST, "--headless", sys.executable, *x, *ORIG[1:], "--stay-in-job",
                                  "--log", r"C:\R & D\rtest.log"])

    def test_no_file_stay_in_job_or_a_percent_warns_once_and_stays(self):
        for log, args, hint in ((None, (), "with stdout going to a file"),
                                (r"C:\x\rtest.log", ["--stay-in-job"], "--stay-in-job keeps it there"),
                                (r"C:\pct %USERNAME% dir\rtest.log", (), "conhost would expand %NAME%")):
            with self.subTest(hint=hint):
                rc, printed = self.start(log=log, args=args)
                self.run.assert_not_called()
                self.G.assert_called_once()
                self.assertEqual(len(printed.splitlines()), 1)
                self.assertIn("warning: the daemon runs inside a job", printed)
                self.assertIn(hint, printed)

    def test_wmi_failure_warns_once_and_stays(self):
        cases = [(mock.Mock(return_value=subprocess.CompletedProcess([], 0, "2 \r\n", "")), "returned 2"),
                 (mock.Mock(return_value=subprocess.CompletedProcess([], 1, "", "Invoke-CimMethod : no\r\n  +")),
                  "powershell exited with 1: Invoke-CimMethod : no +"),
                 (mock.Mock(return_value=subprocess.CompletedProcess([], 0, "0 \r\n", "")), "invalid literal"),
                 (mock.Mock(side_effect=subprocess.TimeoutExpired("powershell", 30)), "did not answer within 30 s"),
                 (mock.Mock(side_effect=FileNotFoundError(2, "no powershell")), "no powershell")]
        for run, why in cases:
            with self.subTest(why=why):
                rc, printed = self.start(log=r"C:\nowhere\rtest.log", run=run)
                self.assertEqual(rc, 0)
                self.G.assert_called_once()
                self.watch.assert_not_called()
                lines = printed.splitlines()
                self.assertEqual((len(lines), lines[0]), (2, LEAVING))
                self.assertIn("could not leave the job", lines[1])
                self.assertIn(why, lines[1])

    def test_argv_given_by_a_caller_never_starts_again(self):
        self.assertEqual(self.start(log=r"C:\x\rtest.log", argv=ARGS), (0, ""))
        self.run.assert_not_called()
        self.G.assert_called_once()

    def test_log_takes_stdout_and_stderr_before_anything_prints(self):
        tries = []

        def held_twice(*a, **k):  # the old copy's cmd lets go of the file a moment after the new copy starts
            tries.append(a)
            if len(tries) < 3:
                raise PermissionError(13, "Permission denied")
            return open(*a, **k)
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "rtest.log")
            with open(log, "w") as f:
                f.write("earlier\n")
            with mock.patch.object(sys, "stdout", sys.stdout), mock.patch.object(sys, "stderr", sys.stderr), \
                    mock.patch.object(D, "ping", lambda i: {"pid": 1}), mock.patch.object(D.time, "sleep"), \
                    mock.patch.object(D, "open", held_twice, create=True):
                self.assertEqual(D.main(["--instance", "rtest", "--log", log]), 1)  # already running
                out, err = sys.stdout, sys.stderr
                out.close()
            self.assertEqual(len(tries), 3)
            self.assertIs(out, err)
            self.assertEqual((out.mode, out.line_buffering, out.errors), ("a", True, "backslashreplace"))
            with open(log) as f:
                self.assertEqual(f.read(), "earlier\nGuardian rtest is already running\n")


class HelperTests(unittest.TestCase):
    def test_exited_within_sees_an_ended_a_running_and_a_gone_process(self):
        done = subprocess.Popen([sys.executable, "-c", ""])
        done.wait()  # Popen still holds its handle, so the pid is not reused
        self.assertTrue(D.exited_within(done.pid, 0.1))
        runs = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            t0 = time.monotonic()
            self.assertFalse(D.exited_within(runs.pid, 0.3))
            self.assertGreaterEqual(time.monotonic() - t0, 0.25)
        finally:
            runs.kill()
            runs.wait()
        with mock.patch.object(D.wj, "open_waitable", lambda pid: None):
            self.assertTrue(D.exited_within(4242, 3.0))

    def test_a_file_has_a_path_a_pipe_and_nul_do_not(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out file.log")
            with open(path, "w") as f:
                got = D.wj.disk_file_path(f.fileno())
                self.assertFalse(got.startswith("\\\\?\\"))
                self.assertTrue(os.path.samefile(got, path))
        r, w = os.pipe()
        try:
            self.assertIsNone(D.wj.disk_file_path(w))
        finally:
            os.close(r)
            os.close(w)
        with open(os.devnull, "w") as f:
            self.assertIsNone(D.wj.disk_file_path(f.fileno()))


if __name__ == "__main__":
    unittest.main()
