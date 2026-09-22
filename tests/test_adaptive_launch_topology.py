"""Synthetic native collaborator tests; these certify no Windows capability."""
from dataclasses import replace
import unittest
from types import SimpleNamespace

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.launch_topology import LaunchTopology, NativeLaunchCapture, OriginalLaunchProvenance
from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive.store import LifecycleError


LOGON = "S-1-5-5-7-8"


def identity(pid, birth):
    return ProcessIdentity(pid, birth, LOGON)


def topology(**changes):
    return replace(LaunchTopology(1, "powershell51", "a" * 64, "b" * 64, "c" * 64,
        ("pipe", "console", "character"), (None, 7, None), True,
        "SyntheticConsole", True, 65001, 65001, 0x80000, 0x100, "job_list_handle_list"), **changes)


class Process:
    def __init__(self, pid, birth, path, *, close_failure=None):
        self.identity = identity(pid, birth)
        self.path = path
        self.close_failure = close_failure
        self.closes = 0

    def observe(self):
        return SimpleNamespace(status=IdentityStatus.ALIVE)

    def close(self):
        self.closes += 1
        if self.close_failure:
            raise self.close_failure


class Backend:
    def __init__(self):
        self.handles = []
        self.parent_job = False

    def image_path(self, process):
        return process.path

    def created_image_path(self, process):
        return process.path

    def in_parent_job(self, process):
        return self.parent_job

    def stdio_observation(self, handle):
        self.handles.append(handle)
        return {10: ("pipe", None), 11: ("console", 7), 12: ("character", None)}[handle]

    def console_scope(self):
        return True, "SyntheticConsole", True, 65001, 65001


class LaunchTopologyTests(unittest.TestCase):
    def capture(self, *, parent=None, backend=None):
        current = Process(2, 200, "C:/synthetic/python.exe")
        parent = parent or Process(1, 100, "C:/synthetic/powershell.exe")
        backend = backend or Backend()
        hashes = {current.path: "b" * 64, parent.path: "a" * 64, "C:/synthetic/cmd.exe": "c" * 64}
        owner = NativeLaunchCapture(backend=backend, current=lambda: current,
            parent=lambda: parent, image_digest=lambda path: hashes[path])
        return owner, current, parent, backend

    def prepare(self, owner):
        return owner.capture(application="C:/synthetic/cmd.exe", stdio_handles=(10, 11, 12),
            creation_flags=0x80000, startup_flags=0x100)

    def test_canonical_roundtrip_keeps_modes_and_stdio(self):
        expected = topology()
        self.assertEqual(LaunchTopology.from_dict(expected.to_dict()), expected)
        self.assertEqual(LaunchTopology.from_dict(dict(reversed(list(expected.to_dict().items())))).sha256,
                         expected.sha256)
        self.assertNotEqual(replace(expected, console_output_cp=437).sha256, expected.sha256)

    def test_exact_actual_handles_and_created_root_finalize(self):
        owner, current, parent, backend = self.capture()
        self.prepare(owner)
        self.assertEqual(backend.handles, [10, 11, 12])
        self.assertIsNone(owner.provenance)
        root = SimpleNamespace(path="C:/synthetic/cmd.exe", full_identity=lambda **kw: identity(3, 300))
        proof = owner.bind_created(root)
        self.assertEqual(proof, OriginalLaunchProvenance(current.identity, parent.identity, identity(3, 300), topology()))
        self.assertEqual(OriginalLaunchProvenance.from_dict(proof.to_dict()), proof)
        self.assertEqual((current.closes, parent.closes), (1, 1))
        self.assertFalse(owner.cleanup_pending)

    def test_reused_parent_birth_refuses_without_repeat(self):
        owner, _, parent, _ = self.capture(parent=Process(1, 201, "C:/synthetic/powershell.exe"))
        with self.assertRaisesRegex(LifecycleError, "launch_parent_unverified"):
            self.prepare(owner)
        self.assertEqual(parent.closes, 1)
        with self.assertRaisesRegex(LifecycleError, "already_attempted"):
            self.prepare(owner)

    def test_uncertain_close_keeps_exact_owner_no_reclose(self):
        error = OSError("synthetic ambiguous close")
        owner, current, parent, _ = self.capture(parent=Process(1, 100,
            "C:/synthetic/powershell.exe", close_failure=error))
        with self.assertRaises(OSError):
            self.prepare(owner)
        self.assertIs(owner.failure, error)
        self.assertIs(error._launch_capture_owner, owner)
        self.assertTrue(owner.cleanup_pending)
        with self.assertRaises(LifecycleError):
            self.prepare(owner)
        with self.assertRaisesRegex(LifecycleError, "cleanup_unverified"):
            owner.retry_cleanup()
        self.assertEqual((current.closes, parent.closes), (1, 1))

    def test_known_failed_close_retries_only_its_original_owner(self):
        error = IdentityUnavailable("process_handle_close_failed", 5)
        owner, current, parent, _ = self.capture(parent=Process(1, 100,
            "C:/synthetic/powershell.exe", close_failure=error))
        with self.assertRaises(IdentityUnavailable):
            self.prepare(owner)
        parent.close_failure = None
        owner.retry_cleanup()
        self.assertFalse(owner.cleanup_pending)
        self.assertEqual((current.closes, parent.closes), (1, 2))
        self.assertIsNone(owner.provenance)

    def test_unknown_parent_job_is_not_false(self):
        backend = Backend()
        backend.parent_job = None
        owner, *_ = self.capture(backend=backend)
        with self.assertRaises(LifecycleError):
            self.prepare(owner)

    def test_created_image_mismatch_keeps_failed_capture(self):
        owner, *_ = self.capture()
        self.prepare(owner)
        root = SimpleNamespace(path="C:/synthetic/python.exe", full_identity=lambda **kw: identity(3, 300))
        with self.assertRaisesRegex(LifecycleError, "created_image_mismatch"):
            owner.bind_created(root)
        self.assertIsNone(owner.provenance)
        with self.assertRaisesRegex(LifecycleError, "finalize_unavailable"):
            owner.bind_created(root)

    def test_changed_stdio_or_console_between_capture_and_create_is_not_certified(self):
        owner, _, _, backend = self.capture()
        self.prepare(owner)
        backend.console_scope = lambda: (True, "SyntheticConsole", True, 437, 437)
        with self.assertRaisesRegex(LifecycleError, "topology_changed"):
            owner.confirm_launch()
        root = SimpleNamespace(path="C:/synthetic/cmd.exe", full_identity=lambda **kw: identity(3, 300))
        with self.assertRaisesRegex(LifecycleError, "topology_changed"):
            owner.bind_created(root)
        self.assertIsNone(owner.provenance)

    def test_foreign_flags_unknown_stdio_or_ambiguous_modes_refuse(self):
        for changes in ({"creation_flags": 0x80004}, {"startup_flags": True},
                        {"stdio_console_modes": (None, None, None)},
                        {"console_attached": False}, {"console_input_cp": None}):
            with self.subTest(changes=changes), self.assertRaises(LifecycleError):
                topology(**changes)

    def test_parent_other_is_retained_but_not_relabelled(self):
        owner, *_ = self.capture(parent=Process(1, 100, "C:/synthetic/broker.exe"))
        self.prepare(owner)
        root = SimpleNamespace(path="C:/synthetic/cmd.exe", full_identity=lambda **kw: identity(3, 300))
        self.assertEqual(owner.bind_created(root).topology.shell_kind, "other")


if __name__ == "__main__":
    unittest.main()
