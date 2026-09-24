"""Portable source-contract checks; synthetic objects are never native gates."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import threading
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from tests.windows import adaptive_scope_launch as scope
from tests.windows import adaptive_scope_wrapper as wrapper_module


class ScopeCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.application = self.directory / "python.exe"
        self.application.write_bytes(b"synthetic-only")
        self.fixture = self.directory / "fixture with spaces.py"
        self.fixture.write_text("# pinned portable source\n", encoding="utf-8")

    def command(self, **kwargs):
        values = dict(application=self.application,
            arguments=("-I", str(self.fixture), "a b", 'literal"quote', "&|"),
            cwd=self.directory, fixture_paths=(self.fixture,))
        return scope.ScopeCommand.capture(**(values | kwargs))

    def test_roundtrip_pins_full_quoted_payload(self):
        command = self.command()
        self.assertEqual(scope.ScopeCommand.from_dict(command.to_dict()), command)
        self.assertIn('"a b"', command.command_line)
        self.assertEqual(len(command.sha256), 64)
        self.assertNotEqual(command.sha256,
            self.command(arguments=("-I", str(self.fixture), "different")).sha256)

    def test_nonisolated_python_rejected(self):
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_command_invalid"):
            self.command(arguments=(str(self.fixture),))

    def test_unpinned_script_rejected(self):
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_command_invalid"):
            self.command(arguments=("-I", str(self.directory / "other.py")))

    def test_fixture_content_changed_rejected(self):
        command = self.command()
        self.fixture.write_text("# different source\n", encoding="utf-8")
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_source_changed"):
            command.verify()

    def test_same_bytes_replaced_file_rejected(self):
        command = self.command()
        replacement = self.directory / "replacement.py"
        replacement.write_bytes(self.fixture.read_bytes())
        replacement.replace(self.fixture)
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_source_changed"):
            command.verify()

    def test_extra_wire_fields_and_bool_size_rejected(self):
        command = self.command()
        with self.assertRaises(scope.ScopeLaunchError):
            scope.ScopeCommand.from_dict(command.to_dict() | {"authorized": True})
        value = command.fixture_sources[0].to_dict() | {"size": True}
        with self.assertRaises(scope.ScopeLaunchError):
            scope.FixtureSource.from_dict(value)

    def test_constructor_is_not_original_owner_factory(self):
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_original_factory_required"):
            scope.ScopeLaunch()


class OnceLaunchTests(unittest.TestCase):
    def test_same_attempt_replay_never_launches_again(self):
        state = scope.OnceLaunchState("a" * 64)
        request_id = str(uuid4())
        self.assertTrue(state.begin(request_id, "a" * 64))
        # Models a lost reply AFTER the original native side effect boundary.
        self.assertFalse(state.begin(request_id, "a" * 64))
        self.assertTrue(state.attempted)

    def test_changed_attempt_or_payload_refused(self):
        state = scope.OnceLaunchState("a" * 64)
        request_id = str(uuid4())
        state.begin(request_id, "a" * 64)
        for rid, checksum in ((str(uuid4()), "a" * 64), (request_id, "b" * 64)):
            with self.assertRaises(scope.ScopeLaunchError):
                state.begin(rid, checksum)

    def test_seal_precedes_create_and_is_irreversible(self):
        state = scope.OnceLaunchState("a" * 64)
        state.seal()
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_launch_sealed"):
            state.begin(str(uuid4()), "a" * 64)
        self.assertFalse(state.attempted)

    def test_protocol_exact_scope_and_schema(self):
        sid, rid = str(uuid4()), str(uuid4())
        value = scope.request("launch", sid, rid, "a" * 64)
        self.assertEqual(scope.validate_request(value, sid, "a" * 64), value)
        for changed in (value | {"scope_id": str(uuid4())}, value | {"schema_version": True},
                        value | {"control_allowed": True}):
            with self.assertRaises(scope.ScopeLaunchError):
                scope.validate_request(changed, sid, "a" * 64)


class SyntheticTransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.events = []
        self.guardian = ProcessIdentity(101, 10001, "S-1-5-5-1-2")
        self.wrapper = ProcessIdentity(102, 10002, self.guardian.logon_id)
        self.root = ProcessIdentity(103, 10003, self.guardian.logon_id)
        self.owner = scope.ScopeLaunch(_token=scope._NEW)
        self.owner.scope_id = str(uuid4())
        self.owner.deadline = float("inf")
        self.owner.guardian_identity = self.guardian
        self.owner.command = SimpleNamespace(sha256="a" * 64)
        self.owner._request_marker = Path(self.temp.name) / "marker.json"
        self.owner.wrapper_witness = SimpleNamespace(identity=self.wrapper,
            observe=lambda: SimpleNamespace(status=IdentityStatus.ALIVE))
        self.owner.job = SimpleNamespace(handle=900)
        self.created_root = SimpleNamespace(identity=self.root,
            query_owned_job_membership=lambda handle: self.events.append(("membership", handle)) or True)
        test = self

        class Peer:
            identity = test.wrapper

            def duplicate_remote_handle(self, locator, *, expected):
                test.events.append(("duplicate", locator, expected))
                return test.created_root

        class Connection:
            @contextmanager
            def verified_peer(self, expected):
                test.events.append(("authenticate", expected))
                yield Peer()
                test.events.append(("peer_close",))

            def close(self):
                test.events.append(("connection_close",))

        self.connection = Connection()
        self.owner.listener = SimpleNamespace(accept=lambda deadline: self.connection)

    def result(self, operation="launch", **changes):
        return dict(schema_version=1, kind="S1ScopeResult", scope_id=self.owner.scope_id,
            request_id=self.owner._request_ids[operation], command_sha256="a" * 64,
            attempted=True, sealed=False, creation_outcome="created",
            root=dict(identity=self.root.to_dict(), handle_locator=700), local_closed=False,
            reason="scope_observed", launch_provenance=None) | changes

    def exchange(self, operation="launch", result=None, confirmation=None):
        hello = dict(schema_version=1, kind="S1ScopeHello", scope_id=self.owner.scope_id,
            wrapper_identity=self.wrapper.to_dict(), command_sha256="a" * 64)
        result = result or self.result(operation)
        messages = iter((hello, result, confirmation or scope.receipt_confirmation(result)))

        def read(*unused):
            value = next(messages)
            self.events.append(("read", value["kind"]))
            return value

        with patch("sentinel.adaptive.pipe_windows.NativeDeadline.after_ms", return_value=object()), \
                patch("sentinel.adaptive.ipc.read_frame", side_effect=read), \
                patch("sentinel.adaptive.ipc.write_frame",
                    side_effect=lambda connection, value, deadline: self.events.append(("write", value["kind"]))):
            return self.owner._exchange(operation)

    def test_root_transfer_uses_authenticated_original_peer_before_receipt(self):
        self.exchange()
        self.assertIs(self.owner.root_witness, self.created_root)
        self.assertLess(self.events.index(("authenticate", self.wrapper)),
                        self.events.index(("duplicate", 700, self.root)))
        self.assertLess(self.events.index(("membership", 900)),
                        self.events.index(("write", "S1ScopeReceipt")))
        self.assertLess(self.events.index(("read", "S1ScopeReceiptConfirmed")),
                        self.events.index(("connection_close",)))
        self.assertEqual(self.events[-1], ("connection_close",))
        self.assertTrue(self.owner._root_membership_verified)

    def test_observation_reuses_same_root_without_second_transfer(self):
        self.exchange()
        self.exchange("observe")
        self.assertEqual(sum(event[0] == "duplicate" for event in self.events), 1)

    def test_changed_locator_quarantines_without_new_transfer(self):
        self.exchange()
        result = self.result("observe", root=dict(identity=self.root.to_dict(), handle_locator=701))
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_root_changed"):
            self.exchange("observe", result)
        self.assertTrue(self.owner._transport_unknown)
        self.assertEqual(sum(event[0] == "duplicate" for event in self.events), 1)
        self.assertIs(self.owner.root_witness, self.created_root)

    def test_unknown_membership_never_acknowledged_as_custody(self):
        self.created_root.query_owned_job_membership = lambda handle: None
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_root_membership_unverified"):
            self.exchange()
        self.assertIs(self.owner.root_witness, self.created_root)
        self.assertNotIn(("write", "S1ScopeReceipt"), self.events)
        self.assertTrue(self.owner._transfer_attempted)
        self.assertFalse(self.owner._root_membership_verified)

    def test_membership_provenance_requires_same_original_launcher_job_and_witness(self):
        scope._OWNERS[self.owner.scope_id] = self.owner
        self.addCleanup(scope._OWNERS.pop, self.owner.scope_id)
        self.assertFalse(self.owner.root_job_bound)
        self.exchange()
        self.assertTrue(self.owner.root_job_bound)
        self.owner.job = SimpleNamespace(handle=900)
        self.assertFalse(self.owner.root_job_bound)

    def test_local_close_message_does_not_claim_transport_closure(self):
        result = self.result("drain", sealed=True, root=None, local_closed=True)
        self.exchange("drain", result)
        self.assertTrue(self.owner._drain_receipt_sent)
        self.assertFalse(self.owner._transport_closed)
        self.assertFalse(self.owner._closed)

    def test_lost_confirmation_retains_connection_and_never_claims_drain_ack(self):
        result = self.result("drain", sealed=True, root=None, local_closed=True)
        confirmation = scope.receipt_confirmation(result) | {"result_sha256": "b" * 64}
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_receipt_confirmation_invalid"):
            self.exchange("drain", result, confirmation)
        self.assertTrue(self.owner._transport_unknown)
        self.assertIs(self.owner.connection, self.connection)
        self.assertFalse(self.owner._drain_receipt_sent)
        self.assertNotIn(("connection_close",), self.events)

    def test_post_create_error_preserves_transferred_root_without_success_claim(self):
        result = self.result(reason="scope_operation_unverified")
        self.exchange(result=result)
        self.assertIs(self.owner.root_witness, self.created_root)
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_launch_unverified"):
            self.owner._require_launch_success(result)

    def test_partial_drain_retains_guardian_root_without_claiming_local_close(self):
        self.exchange()
        result = self.result("drain", sealed=True, root=None, local_closed=False,
                             reason="scope_operation_unverified")
        self.exchange("drain", result)
        self.assertIs(self.owner.root_witness, self.created_root)
        self.assertFalse(self.owner._wrapper_local_closed)
        self.assertFalse(self.owner._drain_receipt_sent)

    def test_rejected_authorization_can_drain_only_with_authentic_sealed_never_used_job(self):
        self.owner._launch_attempted = self.owner._sealed = True
        self.owner._last_result = self.result("seal", attempted=False, sealed=True,
            creation_outcome="not_attempted", root=None)
        accounting = SimpleNamespace(total_processes=0, active_processes=0)
        job = SimpleNamespace(accounting=lambda: accounting, active_pids=lambda: (),
                              query_cpu=lambda: SimpleNamespace(flags=0))
        with patch.object(self.owner, "_job"), patch.object(self.owner, "_exchange") as exchange:
            status = self.owner.drain_once(job)
            self.assertTrue(status.root_dead)
            self.assertFalse(status.complete)
            exchange.assert_called_once_with("drain")
            exchange.reset_mock()
            accounting.total_processes = 1
            self.assertFalse(self.owner.drain_once(job).root_dead)
            exchange.assert_not_called()

    def test_missing_root_without_authenticated_seal_is_not_absence_proof(self):
        self.owner._sealed = True
        job = SimpleNamespace(accounting=lambda: SimpleNamespace(total_processes=0, active_processes=0),
            active_pids=lambda: (), query_cpu=lambda: SimpleNamespace(flags=0))
        with patch.object(self.owner, "_job"), patch.object(self.owner, "_exchange") as exchange:
            self.assertFalse(self.owner.drain_once(job).root_dead)
            exchange.assert_not_called()

    def test_unsealed_cleanup_and_created_root_absence_rejected(self):
        for result in (self.result("drain", root=None, local_closed=True),
                       self.result(root=None)):
            with self.assertRaises(scope.ScopeLaunchError):
                self.owner._validate_result(result,
                    scope.request("launch", self.owner.scope_id, result["request_id"], "a" * 64))


class SyntheticCleanupTests(unittest.TestCase):
    def parent_owner(self):
        owner = scope.ScopeLaunch(_token=scope._NEW)
        owner.scope_id = str(uuid4())
        return owner

    def test_original_never_entered_create_closes_preparation_only(self):
        owner = self.parent_owner()
        owner.listener = SimpleNamespace(close=Mock())
        owner.registry = SimpleNamespace(status=lambda: SimpleNamespace(resources=0, pending=0, quarantined=0))
        owner.close()
        self.assertTrue(owner._closed)
        owner.listener.close.assert_called_once_with()

    def test_source_verification_cannot_extend_original_wrapper_create_deadline(self):
        from sentinel.adaptive import native_launcher as native
        owner = self.parent_owner()
        owner.guardian_identity = ProcessIdentity(101, 10001, "S-1-5-5-1-2")
        owner.command = SimpleNamespace(application="fixture-python", cwd="fixture-directory")
        owner.wrapper_command_line = "fixture-python -I fixture-wrapper"
        owner.deadline = 101.0
        clock = SimpleNamespace(now=100.0)
        verify = Mock(side_effect=lambda: setattr(clock, "now", 101.0))
        owner.fixture_sources = (SimpleNamespace(verify=verify),)
        kernel = SimpleNamespace(CreateProcessW=Mock(side_effect=AssertionError("expired Create")))
        with patch.object(native, "_WindowsBackend", return_value=SimpleNamespace(kernel=kernel)), \
                patch.object(scope.time, "monotonic", side_effect=lambda: clock.now):
            with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_deadline_expired") as caught:
                owner.create_inert()
        verify.assert_called_once_with()
        kernel.CreateProcessW.assert_not_called()
        self.assertIs(caught.exception.scope_launch_owner, owner)
        self.assertFalse(owner._wrapper_create_entered)
        self.assertTrue(owner.process.creation_definitely_absent)
        owner.close()
        self.assertTrue(owner._closed)

    def test_documented_create_false_retains_owner_until_positive_close(self):
        owner = self.parent_owner()
        owner._created = owner._wrapper_create_entered = True
        owner.process = SimpleNamespace(creation_definitely_absent=True, close=Mock())
        owner.close()
        self.assertTrue(owner._closed)
        owner.process.close.assert_called_once_with()

    def test_unknown_create_with_missing_witness_cannot_close(self):
        owner = self.parent_owner()
        owner._created = owner._wrapper_create_entered = True
        owner.process = SimpleNamespace(creation_definitely_absent=False, close=Mock())
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_custody_unsettled"):
            owner.close()
        owner.process.close.assert_not_called()
        self.assertFalse(owner._closed)

    def wrapper_owner(self):
        owner = wrapper_module.WrapperOwner(dict(scope_id=str(uuid4())), scope,
                                           SimpleNamespace(sha256="a" * 64), None)
        self.addCleanup(wrapper_module._RETAINED.remove, owner)
        owner.guardian = ProcessIdentity(101, 10001, "S-1-5-5-1-2")
        return owner

    def test_documented_root_create_false_has_no_root_offer_but_retains_cleanup(self):
        owner = self.wrapper_owner()
        owner.state.begin(str(uuid4()), "a" * 64)
        owner._creation_outcome = "not_created"
        owner.process = SimpleNamespace(_lock=threading.RLock(), handle=None,
            full_identity=Mock(side_effect=AssertionError("no root handle exists")),
            creation_definitely_absent=True, close=Mock())
        result = owner._result(dict(request_id=str(uuid4())))
        self.assertIsNone(result["root"])
        self.assertEqual(result["creation_outcome"], "not_created")
        owner.errors.append(ValueError("documented native Create FALSE"))
        owner.state.seal()
        owner._drain()
        owner.process.close.assert_called_once_with()
        self.assertTrue(owner._local_closed)

    def test_source_refusal_diagnostic_does_not_block_positive_never_created_cleanup(self):
        owner = self.wrapper_owner()
        owner.errors.append(scope.ScopeLaunchError("scope_source_changed"))
        owner.state.seal()
        owner._drain()
        self.assertTrue(owner._local_closed)

    def test_observe_never_erases_original_launch_failure(self):
        owner = self.wrapper_owner()
        owner._launch_failed = True
        result = owner._result(dict(request_id=str(uuid4()), operation="observe"))
        self.assertEqual(result["reason"], "scope_launch_unverified")

    def test_uncertain_constructor_remains_retained(self):
        owner = self.wrapper_owner()
        owner.state.seal()
        owner._acquisition_pending = True
        with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_wrapper_custody_quarantined"):
            owner._drain()
        self.assertFalse(owner._local_closed)


if __name__ == "__main__":
    unittest.main()
