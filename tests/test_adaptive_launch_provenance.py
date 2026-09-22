"""Synthetic launch/IPC/custody integration; no native capability is claimed."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.launch_topology import OriginalLaunchProvenance
from sentinel.adaptive.launch_transport import BindRootRequest, decode_request
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_guardian_launch as guardian_fixture
from tests import test_adaptive_launcher as launcher_fixture
from tests import test_adaptive_native_launcher as native_fixture
from tests.test_adaptive_launch_topology import topology


def proof(wrapper, root):
    parent = ProcessIdentity(wrapper.pid + 1000, wrapper.created_filetime_100ns - 1, wrapper.logon_id)
    return OriginalLaunchProvenance(wrapper, parent, root, topology())


class Capture:
    """Explicit test-only capture collaborator; never reads an OS handle."""
    def __init__(self, test, *, failure=None, pending=False, finalize_failure=None):
        self.test, self.failure = test, failure
        self.cleanup_pending = pending
        self.finalize_failure = finalize_failure
        self.prepared = self.finalized = self.retries = 0
        root = native_fixture.IDENTITY
        wrapper = ProcessIdentity(root.pid - 1, root.created_filetime_100ns - 10, root.logon_id)
        self.proof = proof(wrapper, root)

    def capture(self, **values):
        self.prepared += 1
        self.test.assertEqual(self.test.calls("CreateProcessW"), [])
        self.test.assertEqual(values["stdio_handles"], native_fixture.STDIO_COPIES)
        self.test.assertEqual((values["creation_flags"], values["startup_flags"]), (0x80000, 0x100))
        if self.failure:
            raise self.failure

    def bind_created(self, process):
        self.finalized += 1
        self.test.assertEqual(len(self.test.calls("CreateProcessW")), 1)
        self.test.assertEqual(process.handle, native_fixture.PROCESS_HANDLE)
        if self.finalize_failure:
            raise self.finalize_failure
        return self.proof

    def confirm_launch(self):
        self.test.assertEqual(self.test.calls("CreateProcessW"), [])

    def retry_cleanup(self):
        self.retries += 1
        self.cleanup_pending = False


class NativeProvenanceTests(unittest.TestCase):
    setUp = native_fixture.NativeLauncherTests.setUp
    launch = native_fixture.NativeLauncherTests.launch
    calls = native_fixture.NativeLauncherTests.calls

    def test_capture_surrounds_original_create_and_publishes_same_proof(self):
        capture = Capture(self)
        process = self.launch(capture_factory=lambda: capture)
        self.assertIs(process.launch_provenance, capture.proof)
        self.assertEqual((capture.prepared, capture.finalized), (1, 1))
        process.close()

    def test_unsupported_clean_capture_keeps_successful_admission_only_launch(self):
        capture = Capture(self, failure=LifecycleError("fixture_topology_unsupported"))
        process = self.launch(capture_factory=lambda: capture)
        self.assertIsNone(process.launch_provenance)
        self.assertEqual((capture.prepared, capture.finalized), (1, 0))
        self.assertEqual(len(self.calls("CreateProcessW")), 1)
        self.assertFalse(process.creation_definitely_absent)
        process.close()

    def test_unsettled_capture_cleanup_prevents_create_and_retains_owner(self):
        failure = LifecycleError("fixture_capture_cleanup_unverified")
        capture = Capture(self, failure=failure, pending=True)
        with self.assertRaises(LifecycleError):
            self.launch(capture_factory=lambda: capture)
        self.assertEqual(self.calls("CreateProcessW"), [])
        owner = failure.native_launch_owner
        self.assertIs(failure.cleanup_owner, owner)
        self.assertIs(owner._launch_capture, capture)
        self.assertTrue(owner.creation_definitely_absent)
        owner.close()
        self.assertEqual((capture.prepared, capture.retries), (1, 1))

    def test_unknown_create_keeps_capture_and_does_not_publish_provenance(self):
        capture = Capture(self)
        self.kernel.create_exception = OSError("fixture_unknown_create")
        with self.assertRaises(native_fixture.native.LaunchOutcomeUnknown) as failed:
            self.launch(capture_factory=lambda: capture)
        self.assertIs(failed.exception.process._launch_capture, capture)
        self.assertIsNone(failed.exception.process.launch_provenance)
        self.assertEqual((capture.prepared, capture.finalized), (1, 0))

    def test_postcreate_scope_mismatch_does_not_invent_never_created(self):
        capture = Capture(self, finalize_failure=LifecycleError("fixture_image_changed"))
        process = self.launch(capture_factory=lambda: capture)
        self.assertIsNone(process.launch_provenance)
        self.assertFalse(process.creation_definitely_absent)
        self.assertEqual((capture.prepared, capture.finalized), (1, 1))
        process.close()


class ProvenanceTransportTests(unittest.TestCase):
    def request(self):
        from tests.test_adaptive_launch_transport import common, NONCE, ROOT
        wrapper = ProcessIdentity(ROOT.pid - 1, ROOT.created_filetime_100ns - 10, ROOT.logon_id)
        return BindRootRequest(**common(), job_nonce=NONCE, root_identity=ROOT,
            root_handle_locator=440, launch_provenance=proof(wrapper, ROOT))

    def test_roundtrip_includes_proof_in_whole_authenticated_payload_hash(self):
        request = self.request()
        self.assertEqual(decode_request(request.to_dict()), request)
        altered = replace(request, launch_provenance=replace(request.launch_provenance,
            topology=replace(request.launch_provenance.topology, console_output_cp=437)))
        self.assertNotEqual(request.payload_hash(), altered.payload_hash())
        self.assertNotEqual(request.payload_hash(), replace(request, launch_provenance=None).payload_hash())

    def test_wire_cannot_replace_exact_root_or_add_hash_authority(self):
        request = self.request()
        with self.assertRaises(IpcError):
            replace(request, root_identity=replace(request.root_identity, pid=request.root_identity.pid + 1))
        raw = request.to_dict()
        raw["launch_provenance"]["supported"] = True
        with self.assertRaises(IpcError):
            decode_request(raw)

    def test_missing_provenance_is_explicit_admission_only_not_missing_wire_shape(self):
        request = replace(self.request(), launch_provenance=None)
        self.assertEqual(decode_request(request.to_dict()), request)
        raw = request.to_dict()
        raw.pop("launch_provenance")
        with self.assertRaises(IpcError):
            decode_request(raw)

    def test_managed_launcher_transmits_retained_provenance_unchanged(self):
        fixture = launcher_fixture.Harness()
        fixture.process.launch_provenance = proof(launcher_fixture.WRAPPER, launcher_fixture.ROOT)
        with patch.object(launcher_fixture.C, "WinDLL", side_effect=AssertionError("native call"), create=True):
            fixture.bound()
        arguments = next(values for name, values in fixture.client.calls if name == "bind")
        self.assertIs(arguments["launch_provenance"], fixture.process.launch_provenance)


class GuardianProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = guardian_fixture.GuardianLaunchTests(
            "test_actual_prepare_claim_bind_and_running_observation_have_one_allocation_and_no_set")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)

    def prepared(self, *, provenance=True):
        fixture = self.fixture
        case = fixture.admitted()
        fixture.prepare(case)
        fixture.claim(case)
        fixture.simulate_wrapper_launch(case)
        if provenance:
            case.bind_request = replace(case.bind_request,
                launch_provenance=proof(case.peer.identity, case.root.identity))
        return case

    def test_original_binding_retains_exact_custody_with_no_probe_on_lookup(self):
        fixture, case = self.fixture, self.prepared()
        fixture.bind(case)
        events = list(fixture.processes.events)
        retained = fixture.owner.launch_provenance_for(case.snapshot.execution_id)
        self.assertEqual(retained.provenance, case.bind_request.launch_provenance)
        self.assertEqual(retained.job_nonce, case.job.nonce)
        self.assertEqual(fixture.processes.events, events)
        self.assertTrue(fixture.bind(case).duplicate)
        self.assertIs(fixture.owner.launch_provenance_for(case.snapshot.execution_id), retained)

    def test_original_wrapper_identity_mismatch_is_rejected_before_binding(self):
        fixture, case = self.fixture, self.prepared()
        case.bind_request = replace(case.bind_request,
            launch_provenance=replace(case.bind_request.launch_provenance,
                wrapper_identity=replace(case.peer.identity, pid=case.peer.identity.pid + 1)))
        with self.assertRaisesRegex(LifecycleError, "provenance_mismatch"):
            fixture.bind(case)
        self.assertIsNone(fixture.owner.launch_provenance_for(case.snapshot.execution_id))
        self.assertEqual(fixture.row(case)["state"], "LAUNCHING")

    def test_changed_replay_cannot_replace_original_provenance(self):
        fixture, case = self.fixture, self.prepared()
        fixture.bind(case)
        retained = fixture.owner.launch_provenance_for(case.snapshot.execution_id)
        case.bind_request = replace(case.bind_request, launch_provenance=replace(
            retained.provenance, topology=replace(retained.provenance.topology, console_output_cp=437)))
        with self.assertRaisesRegex(LifecycleError, "request_mismatch"):
            fixture.bind(case)
        self.assertIs(fixture.owner.launch_provenance_for(case.snapshot.execution_id), retained)

    def test_missing_or_recovered_provenance_is_never_reconstructed_from_replay(self):
        fixture, case = self.fixture, self.prepared(provenance=False)
        fixture.bind(case)
        self.assertIsNone(fixture.owner.launch_provenance_for(case.snapshot.execution_id))
        other = self.prepared()
        fixture.bind(other)
        fixture.owner._launch_provenance.clear()  # model lost original metadata
        self.assertTrue(fixture.bind(other).duplicate)
        self.assertIsNone(fixture.owner.launch_provenance_for(other.snapshot.execution_id))

    def test_changed_native_binding_and_retired_custody_cannot_reuse_proof(self):
        fixture, case = self.fixture, self.prepared()
        fixture.bind(case)
        entry = fixture.owner.lifecycle._entries[case.snapshot.execution_id]
        entry.job.nonce = "f" * 32
        self.assertIsNone(fixture.owner.launch_provenance_for(case.snapshot.execution_id))
        entry.job.nonce = case.prepared.job_nonce
        self.assertIsNotNone(fixture.owner.launch_provenance_for(case.snapshot.execution_id))
        entry.closed = True
        self.assertIsNone(fixture.owner.launch_provenance_for(case.snapshot.execution_id))


if __name__ == "__main__":
    unittest.main()
