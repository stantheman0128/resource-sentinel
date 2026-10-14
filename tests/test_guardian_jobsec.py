import json
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Runs in a separate process of the same user: what any tool command of a controlled agent could try.
PROBE = r"""
import ctypes, json, sys
sys.path.insert(0, sys.argv[1])
from sentinel.guardian import winjob as wj
name, out = sys.argv[2], {"elevated": wj.is_elevated(), "open": {}}
for label, access in (("query", wj.JOB_OBJECT_QUERY), ("set_attributes", wj.JOB_OBJECT_SET_ATTRIBUTES),
                      ("all_access", wj.JOB_OBJECT_ALL_ACCESS), ("write_dac", wj.WRITE_DAC),
                      ("assign_process", wj.JOB_OBJECT_ASSIGN_PROCESS), ("terminate", wj.JOB_OBJECT_TERMINATE)):
    h = wj.OpenJobObjectW(access, False, wj.job_name(name))
    out["open"][label] = 0 if h else ctypes.get_last_error()
    if h:
        wj.CloseHandle(h)
try:
    wj.Job.create(name).close()
    out["create"] = "created"
except wj.JobTaken as e:
    out["create"], out["create_winerror"], out["create_pids"] = type(e).__name__, e.winerror, e.pids
print(json.dumps(out))
"""


def session_dir():
    import ctypes
    from ctypes import wintypes as w
    k32, session = ctypes.WinDLL("kernel32"), w.DWORD()
    k32.ProcessIdToSessionId(k32.GetCurrentProcessId(), ctypes.byref(session))
    return f"\\Sessions\\{session.value}\\BaseNamedObjects"


def nt_object(path, target=None):
    """(handle, NTSTATUS) for a symbolic link at path that points to target, or a directory when target is None.
    Made without OBJ_PERMANENT, it goes away with its last handle."""
    import ctypes
    from ctypes import wintypes as w

    class US(ctypes.Structure):
        _fields_ = [("Length", w.USHORT), ("MaximumLength", w.USHORT), ("Buffer", w.LPWSTR)]

    class OA(ctypes.Structure):
        _fields_ = [("Length", w.ULONG), ("RootDirectory", ctypes.c_void_p), ("ObjectName", ctypes.POINTER(US)),
                    ("Attributes", w.ULONG), ("SecurityDescriptor", ctypes.c_void_p),
                    ("SecurityQualityOfService", ctypes.c_void_p)]

    def us(s, buf):
        return US(len(s) * 2, len(s) * 2 + 2, ctypes.cast(buf, w.LPWSTR))

    nt, pb, tb = ctypes.WinDLL("ntdll"), ctypes.create_unicode_buffer(path), ctypes.create_unicode_buffer(target or "")
    us_path, us_target = us(path, pb), us(target or "", tb)
    oa = OA(ctypes.sizeof(OA), None, ctypes.pointer(us_path), 0x40, None, None)  # OBJ_CASE_INSENSITIVE
    h = ctypes.c_void_p()
    if target is None:
        status = nt.NtCreateDirectoryObject(ctypes.byref(h), 0xF000F, ctypes.byref(oa))
    else:
        status = nt.NtCreateSymbolicLinkObject(ctypes.byref(h), 0xF0001, ctypes.byref(oa), ctypes.byref(us_target))
    return h.value, status & 0xFFFFFFFF


@unittest.skipUnless(sys.platform == "win32", "Windows Job Objects")
class NamedJobSecurityTests(unittest.TestCase):
    def setUp(self):
        from sentinel.guardian import winjob as wj
        self.wj = wj
        self.name = f"jobsec-test-{uuid.uuid4().hex[:12]}"
        self.job = wj.Job.create(self.name)
        self.child = None

    def tearDown(self):
        if self.child and self.child.poll() is None:
            self.child.kill()
            self.child.wait(5)
        self.job.close()

    def probe(self):
        r = subprocess.run([sys.executable, "-I", "-c", PROBE, str(ROOT), self.name], capture_output=True, text=True,
                           timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(r.stdout)
        if out["elevated"]:
            self.skipTest("the probe process is elevated, and Administrators keep full access by design")
        return out

    def test_a_separate_same_user_process_may_only_query(self):
        out = self.probe()
        self.assertEqual(out["open"]["query"], 0)
        for right in ("set_attributes", "all_access", "write_dac", "assign_process", "terminate"):
            self.assertEqual(out["open"][right], self.wj.ERROR_ACCESS_DENIED, right)

    def test_a_second_create_of_the_name_is_locked(self):
        self.child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
        self.job.assign(self.child.pid)
        out = self.probe()
        self.assertEqual((out["create"], out["create_winerror"]), ("JobLocked", self.wj.ERROR_ACCESS_DENIED))
        self.assertEqual(out["create_pids"], [self.child.pid])

    def test_the_creator_handle_keeps_full_access(self):
        self.job.set_cpu(max_cores=1)
        self.assertEqual(self.job.cpu()["mode"], "hard_cap")
        self.child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"])
        self.job.assign(self.child.pid)
        self.assertTrue(self.job.contains(self.child.pid))
        self.job.terminate(3)
        self.assertEqual(self.child.wait(10), 3)

    def test_the_creator_sees_an_existing_name_as_taken_too(self):
        with self.assertRaises(self.wj.JobLocked) as cm:
            self.wj.Job.create(self.name)
        self.assertIs(cm.exception.guardian_dacl, True)

    def test_a_job_with_another_restrictive_dacl_is_locked_and_not_ours(self):
        import ctypes
        wj, name = self.wj, f"jobsec-foreign-{uuid.uuid4().hex[:12]}"
        sd = ctypes.c_void_p()
        sddl = f"D:P(A;;0x{wj.JOB_OBJECT_ALL_ACCESS:x};;;SY)(A;;0x120004;;;{wj.user_sid()})"
        self.assertTrue(wj.ConvertSddlToSd(sddl, 1, ctypes.byref(sd), None))
        try:
            sa = wj.SECURITY_ATTRIBUTES(ctypes.sizeof(wj.SECURITY_ATTRIBUTES), sd, False)
            h = wj.CreateJobObjectW(ctypes.byref(sa), wj.job_name(name))
        finally:
            wj.LocalFree(sd)
        self.assertTrue(h)
        try:
            with self.assertRaises(wj.JobLocked) as cm:
                wj.Job.create(name)
            self.assertIs(cm.exception.guardian_dacl, False)
            self.assertEqual(cm.exception.pids, [])
        finally:
            wj.CloseHandle(h)

    def test_a_symbolic_link_at_the_name_makes_it_unusable(self):
        wj, d = self.wj, session_dir()
        # a link into a missing directory, and one into directories a non-elevated user cannot write
        for target, code in (("\\??\\NoSuchDir\\x", 3), ("\\KernelObjects\\x", wj.ERROR_ACCESS_DENIED),
                             ("\\Windows\\x", wj.ERROR_ACCESS_DENIED)):
            with self.subTest(target=target):
                name = f"jobsec-link-{uuid.uuid4().hex[:12]}"
                link, status = nt_object(f"{d}\\Guardian.{name}", target)
                self.assertEqual(status, 0, hex(status))
                try:
                    with self.assertRaises(wj.NameUnusable) as cm:
                        wj.Job.create(name)
                    self.assertNotIsInstance(cm.exception, (wj.NameNotJob, wj.NameRedirected))
                    self.assertEqual(cm.exception.winerror, code)
                    self.assertIsNone(cm.exception.pids)
                finally:
                    wj.CloseHandle(link)

    def test_a_link_to_a_free_name_is_refused_and_leaves_no_job(self):
        wj, d, tag = self.wj, session_dir(), uuid.uuid4().hex[:12]
        name, folder = f"jobsec-redir-{tag}", f"jobsec-dir-{tag}"
        here = f"{d}\\Guardian.{name}"
        directory, status = nt_object(f"{d}\\{folder}")
        self.assertEqual(status, 0, hex(status))
        # each target as the link holder sees it, and as kernel32 opens it afterwards: another Local name, the
        # same last part in global \BaseNamedObjects, and the same last part in a subdirectory
        cases = ((f"{d}\\Guardian.jobsec-target-{tag}", f"Local\\Guardian.jobsec-target-{tag}"),
                 (f"\\BaseNamedObjects\\Guardian.{name}", f"Global\\Guardian.{name}"),
                 (f"{d}\\{folder}\\Guardian.{name}", f"Local\\{folder}\\Guardian.{name}"))
        try:
            for target, opened_as in cases:
                with self.subTest(target=target):
                    link, status = nt_object(here, target)
                    self.assertEqual(status, 0, hex(status))
                    try:
                        with self.assertRaises(wj.NameRedirected) as cm:
                            wj.Job.create(name)
                        e = cm.exception
                        self.assertTrue(wj._same_name(e.real, target), e.real)
                        self.assertTrue(wj._same_name(e.expected, here), e.expected)
                        self.assertEqual((e.winerror, e.pids), (0, None))
                        self.assertIn(target, str(e))
                        self.assertFalse(wj.OpenJobObjectW(wj.JOB_OBJECT_QUERY, False, opened_as))
                    finally:
                        wj.CloseHandle(link)
        finally:
            wj.CloseHandle(directory)

    def test_a_link_to_an_existing_job_is_refused_before_it_counts_as_taken(self):
        wj, d = self.wj, session_dir()
        permissive = f"jobsec-open-{uuid.uuid4().hex[:12]}"
        h = wj.CreateJobObjectW(None, wj.job_name(permissive))  # default DACL: the user may open it fully
        self.assertTrue(h)
        try:
            # without the link these would be JobExisted and JobLocked
            for target, code in ((permissive, wj.ERROR_ALREADY_EXISTS), (self.name, wj.ERROR_ACCESS_DENIED)):
                with self.subTest(target=target):
                    name = f"jobsec-redir-{uuid.uuid4().hex[:12]}"
                    link, status = nt_object(f"{d}\\Guardian.{name}", f"{d}\\Guardian.{target}")
                    self.assertEqual(status, 0, hex(status))
                    try:
                        with self.assertRaises(wj.NameRedirected) as cm:
                            wj.Job.create(name)
                        self.assertEqual(cm.exception.winerror, code)
                        self.assertTrue(wj._same_name(cm.exception.real, f"{d}\\Guardian.{target}"))
                    finally:
                        wj.CloseHandle(link)
                    still = wj.OpenJobObjectW(wj.JOB_OBJECT_QUERY, False, wj.job_name(target))
                    self.assertTrue(still)  # the job behind the link is left alone
                    wj.CloseHandle(still)
        finally:
            wj.CloseHandle(h)

    def test_a_name_whose_path_cannot_be_read_is_refused(self):
        from unittest import mock
        wj = self.wj
        for helper in ("_kernel_name", "_expected_kernel_name"):
            with self.subTest(helper=helper), mock.patch.object(wj, helper, return_value=None):
                name = f"jobsec-unread-{uuid.uuid4().hex[:12]}"
                with self.assertRaises(wj.NameRedirected) as cm:
                    wj.Job.create(name)
                self.assertIn("could not be read", str(cm.exception))
                self.assertFalse(wj.OpenJobObjectW(wj.JOB_OBJECT_QUERY, False, wj.job_name(name)))

    def test_a_name_held_by_a_mutex_is_taken(self):
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.restype = ctypes.c_void_p
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        name = f"jobsec-mutex-{uuid.uuid4().hex[:12]}"
        h = k32.CreateMutexW(None, False, self.wj.job_name(name))
        self.assertTrue(h, ctypes.get_last_error())
        try:
            with self.assertRaises(self.wj.NameNotJob) as cm:
                self.wj.Job.create(name)
            self.assertEqual(cm.exception.winerror, self.wj.ERROR_INVALID_HANDLE)
            self.assertIsNone(cm.exception.pids)
        finally:
            self.wj.CloseHandle(h)

    def test_unnamed_jobs_keep_the_default_security(self):
        j = self.wj.Job.create()
        try:
            self.assertIsNone(j.name)
            j.set_cpu(max_cores=1)
        finally:
            j.close()

    def test_open_defaults_to_query(self):
        j = self.wj.Job.open(self.name)
        try:
            self.assertEqual(j.cpu()["mode"], "none")
            with self.assertRaises(OSError):
                j.set_cpu(max_cores=1)
        finally:
            j.close()


if __name__ == "__main__":
    unittest.main()
