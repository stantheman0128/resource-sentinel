"""Fixed bootstrap consumers with explicit synthetic native collaborators.

The authenticated child protocol is real, as are bounded private-file parsing
and the dispatcher. Native process/pipe/ACL operations are fixture backends;
none of these tests is a Windows capability or production-host gate.
"""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_child_host as module
from sentinel.adaptive import experiment_host_transport as transport
from sentinel.adaptive.guardian_host import GuardianHost
from sentinel.adaptive.helper_control_host import OperationalHelperHost
from sentinel.adaptive.wrapper_host import WrapperHost
from sentinel.adaptive.store import LifecycleStore
from tests import test_adaptive_experiment_host_roles as roles
from tests import test_adaptive_experiment_host_transport as fixtures
from tests.test_adaptive_ipc import wire_frame


class Protection:
    def __init__(self, logon):
        self.logon, self.events = logon, []

    def verify(self, path, *, directory):
        self.events.append(("verify", Path(path), directory))

    def protect_file(self, path):
        # Credential-bearing bytes must not exist before protection.
        if Path(path).read_bytes():
            raise AssertionError("credential preceded protection")
        self.events.append(("protect", Path(path)))

    def close(self):
        self.events.append(("close",))


class ExperimentChildHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentTransportTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = Path(self.fixture.directory.name)
        self.path = self.root / (".experiment-child-" + fixtures.MEMBER + ".json")
        self.protection = Protection(fixtures.LOGON)
        self.owner = module.ExperimentChildHost(self.path)
        for override in (patch.object(module, "_WindowsProtection", return_value=self.protection),
                         patch.object(module.VerifiedProcess, "current", return_value=self.fixture.child)):
            override.start()
            self.addCleanup(override.stop)

    def registration(self, role=None):
        role = roles.guardian() if role is None else role
        role = replace(role, member_id=fixtures.MEMBER,
                       data_dir=str(self.root))
        manifest = replace(self.fixture.manifest, role=role.role,
            isolated_ledger_path=str(self.root / "sentinel.db"),
            permitted_member_ids=(role.workload_member_id,) if role.role == "wrapper" else ())
        value = transport.ExperimentChildRegistration(manifest, fixtures.KEY, role_spec=role)
        self.fixture.manifest, self.fixture.registration = manifest, value
        self.fixture.request = transport.BindExperimentChildRequest(manifest)
        self.fixture.client = transport.ExperimentChildClient(value, self.fixture.child)
        self.path.write_bytes(module.registration_bytes(value))
        return value

    def authenticate(self, registration, context=None, *, wrong_mac=False):
        release = dict(version=1, plan_sha256=registration.manifest.plan_sha256,
            actor_member_id=fixtures.MEMBER, role_spec=registration.role_spec.to_dict(),
            guardian={} if context is None else context)
        result = dict(bound_manifest=registration.manifest.to_dict(), role_release=release)
        response = self.fixture.message("ExperimentChildResult", "result", result=result)
        if wrong_mac:
            response["mac"] = "0" * 64
        connection = fixtures.Pipe(fixtures.PARENT,
            wire_frame(self.fixture.challenge()) + wire_frame(response))
        with patch.object(transport.NativePipeConnection, "connect", return_value=connection):
            self.owner.authenticate()
        return connection

    def test_registration_roundtrip_is_private_data_with_closed_schema(self):
        value = self.registration()
        raw = module.registration_bytes(value)
        parsed = module.parse_registration(raw)
        self.assertEqual(parsed, value)
        self.assertNotIn(fixtures.KEY.hex(), repr(parsed))
        data = json.loads(raw)
        for changed in (data | {"source_root": "C:\\foreign"}, data | {"version": True},
                        data | {"auth_key": "00"}, data | {"capacity_granted": True}):
            with self.subTest(keys=tuple(changed)), self.assertRaises(module.ExperimentChildHostError):
                module.parse_registration(json.dumps(changed).encode())
        with self.assertRaises(module.ExperimentChildHostError):
            module.parse_registration(b" " * (module.MAX_REGISTRATION_BYTES + 1))

    def test_missing_file_is_inert_and_retains_original_self_handle(self):
        with self.assertRaises(FileNotFoundError):
            self.owner.authenticate()
        self.assertIs(self.owner.process, self.fixture.child)
        self.assertIsNone(self.owner.host)
        self.assertIsNone(self.owner.daily_store)
        self.assertIsNone(self.owner.client)
        self.assertFalse(self.owner.dispatched)
        self.assertEqual(self.fixture.child_backend.closed, [])

    def test_real_parent_exchange_precedes_any_host_or_ledger_construction(self):
        value = self.registration()
        with patch.object(LifecycleStore, "__init__", side_effect=AssertionError("premature ledger")), \
                patch.object(GuardianHost, "for_experiment", side_effect=AssertionError("premature host")):
            connection = self.authenticate(value)
        self.assertTrue(connection.closed)
        self.assertTrue(self.owner.authenticated)
        self.assertIs(self.owner.role, self.owner.registration.role_spec)
        self.assertEqual(self.protection.events, [("verify", self.path, False)])
        self.assertIsNone(self.owner.host)
        self.owner.binding.close()

    def test_invalid_parent_mac_cannot_dispatch_or_sample(self):
        value = self.registration()
        with self.assertRaises(transport.ExperimentChildError):
            self.authenticate(value, wrong_mac=True)
        with self.assertRaisesRegex(module.ExperimentChildHostError, "authenticated_original"):
            self.owner.dispatch()
        self.assertIsNone(self.owner.host)
        self.assertIsNone(self.owner.daily_store)
        self.assertFalse(self.owner.dispatched)

    def test_registration_replacement_after_authentication_is_rejected(self):
        value = self.registration()
        original = transport.ExperimentChildClient.bind
        def changed(client, **kwargs):
            binding = original(client, **kwargs)
            self.path.write_bytes(self.path.read_bytes() + b" ")
            return binding
        with patch.object(transport.ExperimentChildClient, "bind", changed), \
                self.assertRaisesRegex(module.ExperimentChildHostError, "registration_changed"):
            self.authenticate(value)
        self.assertFalse(self.owner.authenticated)
        self.assertIsNotNone(self.owner.binding)
        self.assertIsNone(self.owner.host)
        self.owner.binding.close()

    def test_actual_guardian_factory_receives_original_binding_and_both_stores(self):
        value = self.registration()
        self.authenticate(value)
        host = GuardianHost.__new__(GuardianHost)
        def initialize(store, *, db_path, existing_path):
            self.assertTrue(existing_path)
            self.assertTrue(self.owner.authenticated)
            store.db_path = db_path
        with patch.object(self.owner, "_profile", return_value=b"profile"), \
                patch.object(LifecycleStore, "__init__", initialize), \
                patch.object(GuardianHost, "for_experiment", return_value=host) as factory:
            self.assertIs(self.owner.dispatch(), host)
        factory.assert_called_once_with(self.owner.role, child_binding=self.owner.binding,
            isolated_store=self.owner.isolated_store, daily_store=self.owner.daily_store)
        self.assertEqual(self.owner.daily_store.db_path, value.manifest.daily_ledger_path)
        self.assertEqual(self.owner.isolated_store.db_path, value.manifest.isolated_ledger_path)
        with self.assertRaisesRegex(module.ExperimentChildHostError, "authenticated_original"):
            self.owner.dispatch()
        self.owner.binding.close()

    def test_partial_construction_owner_is_registered_before_constructor_and_never_replaced(self):
        value = self.registration()
        self.authenticate(value)
        failure = RuntimeError("synthetic constructor result unknown")
        seen = []
        def initialize(store, **kwargs):
            self.assertIs(self.owner.daily_store, store)
            self.assertIs(self.owner.constructing["daily_store"], store)
            seen.append(store)
            raise failure
        with patch.object(self.owner, "_profile", return_value=b"profile"), \
                patch.object(LifecycleStore, "__init__", initialize), self.assertRaises(RuntimeError) as raised:
            self.owner.dispatch()
        self.assertIs(raised.exception, failure)
        self.assertIs(self.owner.daily_store, seen[0])
        self.assertTrue(self.owner.dispatched)
        with self.assertRaises(module.ExperimentChildHostError):
            self.owner.dispatch()
        self.assertEqual(len(seen), 1)
        self.owner.binding.close()

    def test_file_replacement_changes_retained_identity_even_for_same_bytes(self):
        self.registration()
        original = module._read(self.path, module.MAX_REGISTRATION_BYTES)
        replacement = self.path.with_suffix(".new")
        replacement.write_bytes(original[0])
        replacement.replace(self.path)
        self.assertNotEqual(module._read(self.path, module.MAX_REGISTRATION_BYTES), original)

    def test_helper_dispatch_constructs_only_operational_shadow_host(self):
        example = Path(__file__).resolve().parents[1] / "config" / "adaptive.example.json"
        profile = self.root / "shadow.json"
        raw = json.dumps(json.loads(example.read_bytes()) | {"mode": "shadow"}).encode()
        profile.write_bytes(raw)
        role = replace(roles.helper(), profile_path=str(profile), profile_sha256=hashlib.sha256(raw).hexdigest())
        value = self.registration(role)
        guardian = replace(fixtures.PARENT, pid=fixtures.PARENT.pid + 2)
        context = dict(guardian_identity=guardian.to_dict(), guardian_epoch="experiment.epoch",
            control_instance_id=roles.uid(20), instance_id=roles.uid(21), operator_instance_id=roles.uid(22),
            parent_instance_id=roles.uid(23), parent_identity=fixtures.PARENT.to_dict(),
            policy_instance_id=value.manifest.isolated_policy_instance_id)
        self.authenticate(value, context)
        host = self.owner.dispatch()
        self.assertIs(type(host), OperationalHelperHost)
        self.assertIs(host._experiment_child_binding, self.owner.binding)
        self.assertIs(host._experiment_role_spec, self.owner.role)
        self.assertEqual(host.parent_identity, fixtures.PARENT)
        self.assertEqual(host.guardian_endpoint.server_identity, guardian)
        self.assertFalse(host._started)
        self.assertFalse(hasattr(host, "control"))
        self.owner.binding.close()

    def test_wrapper_dispatch_uses_partition_and_backing_without_independent_admission(self):
        from sentinel.coordinator import Coordinator
        from sentinel.adaptive.admission import ManagedAdmission
        from sentinel.adaptive.experiment_partition_admission import ExperimentPartitionCoordinator
        from sentinel.adaptive.experiment_backing_transport import ExperimentBackingPublication
        value = self.registration(replace(roles.wrapper(), max_wait_sec=60))
        guardian = replace(fixtures.PARENT, pid=fixtures.PARENT.pid + 2)
        context = dict(guardian_identity=guardian.to_dict(), guardian_epoch="experiment.epoch",
            launch_instance_id=roles.uid(20), reservation_id=roles.uid(21), backing_request_id=roles.uid(22))
        self.authenticate(value, context)
        admission, publication = SimpleNamespace(), SimpleNamespace()
        host = WrapperHost.__new__(WrapperHost)
        with patch.object(LifecycleStore, "__init__", return_value=None), \
                patch.object(Coordinator, "__init__", return_value=None), \
                patch.object(Coordinator, "admit_managed", side_effect=AssertionError("second machine admission")), \
                patch.object(ExperimentPartitionCoordinator, "__init__", return_value=None) as partition, \
                patch.object(ManagedAdmission, "current", return_value=admission) as current, \
                patch.object(ExperimentBackingPublication, "prepare", return_value=publication) as backing, \
                patch.object(WrapperHost, "for_experiment", return_value=host) as factory:
            self.assertIs(self.owner.dispatch(), host)
        partition.assert_called_once_with(coordinator=self.owner.coordinator, child_binding=self.owner.binding,
            member_id=self.owner.role.workload_member_id, reservation_id=context["reservation_id"],
            daily_store=self.owner.daily_store)
        spec = self.owner.role.launch_spec
        current.assert_called_once_with(command=spec.command, cwd=spec.cwd, repo_identifier=spec.repo_identifier,
            requested=spec.requested, role=spec.role, priority=spec.priority)
        backing.assert_called_once_with(self.owner.binding, admission, member_id=self.owner.role.workload_member_id,
            reservation_id=context["reservation_id"], request_id=context["backing_request_id"])
        self.assertIs(factory.call_args.args[0], spec)
        self.assertIs(factory.call_args.kwargs["partition"], self.owner.partition)
        self.assertIs(factory.call_args.kwargs["publication"], publication)
        self.assertEqual(factory.call_args.kwargs["endpoint"].server_identity, guardian)
        self.owner.binding.close()

    def test_private_publication_never_overwrites_existing_registration(self):
        registration = self.registration()
        original = self.path.read_bytes()
        with patch.dict(module._PUBLICATIONS, {}, clear=True):
            owner = module.ChildRegistrationPublication.prepare(registration, self.root)
            self.assertIs(module.ChildRegistrationPublication.prepare(registration, self.root), owner)
            with self.assertRaisesRegex(module.ExperimentChildHostError, "already_exists"):
                owner.publish()
            self.assertEqual(self.path.read_bytes(), original)
            self.assertIsNotNone(owner.failure)
            self.assertTrue(owner.started)
            self.assertFalse(owner.published)
            self.assertIs(owner.protection, self.protection)
            with self.assertRaisesRegex(module.ExperimentChildHostError, "outcome_unknown"):
                owner.publish()
            owner.close()
            with patch.object(module.Path, "stat", side_effect=AssertionError("SQL filesystem probe")), \
                    patch.object(Protection, "verify", side_effect=AssertionError("SQL native probe")):
                self.assertIsNone(owner.assert_closed())
            self.assertEqual(self.path.read_bytes(), original)

    def test_terminal_publication_is_settled_before_binding_and_self_handle_close(self):
        import sys
        events = []
        terminal = SimpleNamespace(assert_settled=lambda: events.append("receipt"))
        transport_module = SimpleNamespace(publish_host_closed=lambda *args: terminal)
        self.owner.host_closed = True
        self.owner.host = object()
        self.owner.binding = SimpleNamespace(close=lambda: events.append("binding"))
        self.owner.protection = SimpleNamespace(close=lambda: events.append("protection"))
        self.owner.process = SimpleNamespace(close=lambda: events.append("process"))
        with patch.dict(sys.modules, {"sentinel.adaptive.experiment_host_retirement_transport": transport_module}):
            self.owner.finish()
        self.assertEqual(events, ["receipt", "binding", "protection", "process"])
        self.assertTrue(self.owner.closed)

    def test_close_retry_retains_original_receipt_without_republishing(self):
        import sys
        events = []
        terminal = SimpleNamespace(assert_settled=lambda: events.append("receipt"))
        transport_module = SimpleNamespace(publish_host_closed=lambda *args: terminal)
        self.owner.host_closed = True
        self.owner.host = object()
        failure = RuntimeError("synthetic cleanup unavailable")
        def binding_close():
            events.append("binding")
            if events.count("binding") == 1:
                raise failure
        self.owner.binding = SimpleNamespace(close=binding_close)
        self.owner.protection = SimpleNamespace(close=lambda: events.append("protection"))
        self.owner.process = SimpleNamespace(close=lambda: events.append("process"))
        with patch.dict(sys.modules, {"sentinel.adaptive.experiment_host_retirement_transport": transport_module}):
            with self.assertRaises(RuntimeError):
                self.owner.finish()
            self.assertFalse(self.owner.closed)
            self.assertIs(self.owner.terminal, terminal)
            self.owner.finish()
        self.assertEqual(events, ["receipt", "binding", "binding", "protection", "process"])
        self.assertTrue(self.owner.closed)

    def test_registration_path_does_not_accept_arbitrary_config_or_relative_files(self):
        for path in ("relative.json", self.root / "config.json", self.root / ".." / self.path.name):
            with self.subTest(path=str(path)), self.assertRaises(module.ExperimentChildHostError):
                module.ExperimentChildHost(path)

    def test_entry_has_fixed_source_finder_without_ambient_path_or_pyc_loading(self):
        import ast
        path = Path(__file__).resolve().parents[1] / "scripts" / "adaptive-experiment-child.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        calls = [ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        self.assertNotIn("sys.path.insert", calls)
        self.assertIn("compile", calls)
        source = path.read_text(encoding="utf-8")
        self.assertIn("sys.flags.isolated", source)
        self.assertNotIn("source_root=", source)


if __name__ == "__main__":
    unittest.main()
