"""Synthetic supervisor/creation custody regressions, not Windows gate evidence.

These cases use the actual SupervisorHost, ExperimentSupervisor, CreationAttempt,
VerifiedProcess and RetainedGuardianCreation classes. Class-level scope gates,
POLICY contexts and the native ABI are explicit in-memory doubles. No process,
Job, reservation, SQLite database, pipe or production setting is created here.
The connected scope and native suites remain responsible for those boundaries.
"""
from contextlib import contextmanager
from pathlib import Path
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import experiment_supervisor as integration
from sentinel.adaptive import identity as identities
from sentinel.adaptive import pipe_windows
from sentinel.adaptive import supervisor_host as supervisors
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from sentinel.adaptive.experiment_host_ledger import MemberClaim
from sentinel.adaptive.experiment_host_roles import GuardianRoleSpec, HelperRoleSpec
from sentinel.adaptive.recovery_owner import RetainedGuardianCreation


LOGON = "S-1-5-5-100-200"
PARENT = ProcessIdentity(100, 134342315823996100, LOGON)


class SyntheticPolicy:
    def __init__(self, name, binding, events):
        self.name, self.binding, self.events = name, binding, events
        self.guard = None

    def current_guard(self):
        return self.guard

    def prepare(self, logon_id):
        if logon_id != LOGON:
            raise AssertionError("unexpected synthetic logon")
        return SimpleNamespace(binding=self.binding, _nonce_clear_confirmed=False,
            _native_exit_confirmed=False, _native_no_entry_confirmed=False)

    @contextmanager
    def hold(self, guard):
        if self.guard is not None:
            raise AssertionError("synthetic POLICY reentry")
        self.guard = guard
        self.events.append(self.name + ":enter")
        try:
            yield guard
        finally:
            self.events.append(self.name + ":exit")
            self.guard = None
            guard._native_exit_confirmed = True
            guard._nonce_clear_confirmed = True


class SyntheticIdentityBackend:
    def __init__(self, events):
        self.events = events
        self.identities = {100: PARENT}
        self.states = {}
        self.duplicates, self.closes = [], []
        self.close_errors = {}

    def duplicate_into(self, source, output, *, source_process=None):
        if source_process is not None:
            raise AssertionError("unexpected remote duplicate")
        handle = 900 + len(self.duplicates)
        self.duplicates.append((source, handle))
        self.identities[handle] = self.identities[source]
        output.value = handle
        self.events.append(("duplicate", source, handle))

    def identity(self, handle):
        return self.identities[handle]

    def wait(self, handle):
        return self.states.get(self.identities[handle].pid, IdentityStatus.ALIVE)

    def close(self, handle):
        self.closes.append(handle)
        self.events.append(("duplicate_close", handle))
        if handle in self.close_errors:
            raise self.close_errors[handle]

    def open_process(self, pid):
        raise AssertionError("experimental creation must not reopen a PID")


class ExperimentSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.events, self.raw_closes, self.creates, self.publications = [], [], [], []
        self.raw_close_results = {}
        self.create_error = self.registration_error = None
        self.create_result, self.write_output = 1, True
        self.scope = scopes.ProductionExperimentScope(_token=scopes._CREATE)
        self.scope.demand = SimpleNamespace(_source_root=Path("C:\\isolated\\source"))
        self.scope.spec = SimpleNamespace(suite="P4", isolated_policy_instance_id=str(uuid4()))
        self.scope._prepared = True
        resources = ResourceDemand(cpu_units=1, physical_bytes=1 << 28,
                                   commit_bytes=1 << 28, io_slots=0)
        self.guardian_member = MemberClaim(str(uuid4()), "infrastructure", "guardian", resources)
        self.helper_member = MemberClaim(str(uuid4()), "infrastructure", "helper", resources)
        self.guardian_role = GuardianRoleSpec(member_id=self.guardian_member.member_id,
            data_dir="C:\\isolated\\data", journal_dir="C:\\isolated\\journal",
            profile_path="C:\\isolated\\guardian.json", profile_sha256="a" * 64,
            guardian_epoch="predeclared-guardian-epoch", launch_instance_id=str(uuid4()),
            query_instance_id=str(uuid4()), control_instance_id=str(uuid4()),
            instance_id=str(uuid4()), operator_instance_id=str(uuid4()),
            policy_instance_id=self.scope.spec.isolated_policy_instance_id)
        self.helper_role = HelperRoleSpec(member_id=self.helper_member.member_id,
            data_dir=self.guardian_role.data_dir, profile_path="C:\\isolated\\helper.json",
            profile_sha256="b" * 64, iterations=2)
        self.scope.plan = SimpleNamespace(members=(self.guardian_member, self.helper_member),
                                         roles=(self.guardian_role, self.helper_role))
        self.backend = SyntheticIdentityBackend(self.events)
        self.scope.process = identities.VerifiedProcess(self.backend, 100, PARENT)
        self.binding = SimpleNamespace(instance_id=self.scope.spec.isolated_policy_instance_id,
                                       logon_id=LOGON)
        self.daily = self.scope._daily_policy = SyntheticPolicy("daily", object(), self.events)
        self.isolated = SyntheticPolicy("isolated", self.binding, self.events)

        def original(scope, demand, spec, registered=None):
            if scope is not self.scope or demand is not scope.demand or spec is not scope.spec:
                raise AssertionError("synthetic original scope mismatch")

        def native_init(native):
            native.kernel = SimpleNamespace(CreateProcessW=self.create_native,
                CloseHandle=self.close_native, WaitForSingleObject=self.wait_native)

        def creation_gate(scope, attempt):
            original(scope, scope.demand, scope.spec)
            self.assertIs(scope._attempts[attempt.member.member_id], attempt)
            self.assertIs(scope._guard, self.daily.current_guard())
            self.assertIsNotNone(scope._guard)
            self.assertIsNotNone(self.isolated.current_guard())
            self.assertIsNone(scope._active_sql)

        @contextmanager
        def operation(scope):
            original(scope, scope.demand, scope.spec)
            scope._guard = self.daily.prepare(LOGON)
            try:
                with self.daily.hold(scope._guard):
                    yield scope._guard
            finally:
                scope._guard = None

        def create_actor(scope, member):
            with operation(scope):
                with scope._supervisor_integration.creation_scope(member):
                    command = creation.ChildCommand("C:\\Python\\python.exe",
                        ("-m", "sentinel.adaptive.experiment_host_child", "inert"),
                        "C:\\isolated\\source")
                    attempt = creation.CreationAttempt._prepare(scope, member, command)
                    attempt.create(scope)
                    attempt.capture_identity(scope)
                    self.events.append(("actor_published", member.role))
                    return attempt

        def publish(scope, attempt, *, permitted_member_ids=()):
            self.assertIsNone(scope._guard)
            self.assertIsNone(self.daily.current_guard())
            self.assertIsNone(self.isolated.current_guard())
            self.assertIsNone(scope._active_sql)
            owner = scope._supervisor_integration
            child = owner.host.guardian if attempt.member is self.guardian_member else owner.host.helper
            self.assertIs(owner._records[attempt.member.member_id]["child"], child)
            self.publications.append(attempt)
            self.events.append(("registration", attempt.member.role))
            if self.registration_error is not None:
                raise self.registration_error
            return object()

        def open_dispatcher(scope):
            original(scope, scope.demand, scope.spec)
            self.events.append("dispatcher:ready")
            if scope._host_dispatcher is None:
                scope._host_dispatcher = SimpleNamespace(poll_once=lambda **kw: False)
            return scope._host_dispatcher

        def bind_supervisor(scope, host):
            original(scope, scope.demand, scope.spec)
            self.assertIs(type(host), supervisors.SupervisorHost)
            scope._supervisor_host = host
            scope._supervisor_pin = (host, host._operational_current, host.startup,
                                     host.store, host.operations, host._instance_id)

        for replacement in (
            patch.object(scopes.ProductionExperimentScope, "_assert_ledger_original", original),
            patch.object(scopes.ProductionExperimentScope, "_assert_creation_gate", creation_gate),
            patch.object(scopes.ProductionExperimentScope, "create_actor", create_actor),
            patch.object(scopes.ProductionExperimentScope, "publish_child_registration", publish),
            patch.object(scopes.ProductionExperimentScope, "open_dispatcher", open_dispatcher),
            patch.object(scopes.ProductionExperimentScope, "bind_supervisor", bind_supervisor),
            patch.object(creation._NativeCreation, "__init__", native_init),
            patch.object(identities, "_backend", return_value=self.backend),
            patch.object(supervisors, "_Creation", side_effect=AssertionError("ordinary launcher used")),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def create_native(self, *arguments):
        member = self.scope._supervisor_integration._current_creation["member"]
        index = len(self.creates)
        self.creates.append(member)
        self.events.append(("create", member.role))
        self.assertEqual(arguments[4:7], (False, 0, None))
        if self.write_output:
            process_handle, thread_handle, pid = 800 + index * 2, 801 + index * 2, 101 + index
            self.backend.identities[process_handle] = ProcessIdentity(pid, PARENT.created_filetime_100ns + pid, LOGON)
            info = arguments[-1]._obj
            info.hProcess, info.hThread = process_handle, thread_handle
            info.dwProcessId, info.dwThreadId = pid, pid + 100
        if self.create_error is not None:
            raise self.create_error
        return self.create_result

    def close_native(self, handle):
        self.raw_closes.append(handle)
        self.events.append(("raw_close", handle))
        result = self.raw_close_results.get(handle, 1)
        if isinstance(result, BaseException):
            raise result
        return result

    def wait_native(self, handle, timeout):
        self.assertEqual(timeout, 0)
        return 0 if self.backend.wait(handle) is IdentityStatus.DEAD else 0x102

    def ready(self):
        host = supervisors.SupervisorHost.for_experiment(self.scope)
        owner = host._experiment_supervisor

        def fresh():
            self.assertIsNotNone(self.daily.current_guard())
            self.assertIsNotNone(self.isolated.current_guard())
            self.events.append("startup:fresh")

        host.startup = SimpleNamespace(binding=self.binding, _current=self.scope.process,
            assert_fresh_locked=fresh, assert_held=lambda: self.events.append("startup:held"),
            _closed=False)
        host.store = SimpleNamespace(_policy=self.isolated)
        host.operations = SimpleNamespace()
        host._operational_current = self.scope.process
        owner.bind_operations()
        return owner, host

    def guardian(self):
        owner, host = self.ready()
        child = host._start_initial_guardian()
        return owner, host, child

    def helper(self):
        owner, host, guardian = self.guardian()
        host.guardian_descriptor = SimpleNamespace(state="ready")
        child = host._start_helper()
        return owner, host, guardian, child

    def dead(self, child):
        self.backend.states[child.pid] = IdentityStatus.DEAD

    def test_factory_requires_exact_original_scope_host_and_single_binding(self):
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "original_factory_required"):
            integration.ExperimentSupervisor()
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "original_scope_required"):
            integration.ExperimentSupervisor.prepare(SimpleNamespace())
        class DerivedHost(supervisors.SupervisorHost):
            pass
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "original_host_required"):
            DerivedHost.for_experiment(self.scope)
        host = supervisors.SupervisorHost.for_experiment(self.scope)
        self.assertIs(type(host), supervisors.SupervisorHost)
        self.assertIs(host._experiment_supervisor, self.scope._supervisor_integration)
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "unused_scope_required"):
            supervisors.SupervisorHost.for_experiment(self.scope)
        self.assertEqual(self.creates, [])

    def test_declared_epoch_endpoints_and_helper_selectors_are_bound_before_start(self):
        owner, host = self.ready()
        self.assertEqual(host._initial_epoch, self.guardian_role.guardian_epoch)
        expected = {key: getattr(self.guardian_role, key) for key in
            ("instance_id", "operator_instance_id", "launch_instance_id", "query_instance_id", "control_instance_id")}
        self.assertEqual(host._guardian_endpoints, {self.guardian_role.guardian_epoch: expected})
        self.assertEqual(tuple(host._helper_endpoints.values()),
                         self.scope._role_release_data[self.helper_member.member_id])
        self.assertIsNone(host.creation)
        self.assertEqual((host.max_guardians, host.max_helpers), (1, 1))
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "declared_epoch_required"):
            owner.start_guardian(epoch="replacement")
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "declared_epoch_required"):
            owner.start_guardian(epoch=host._initial_epoch, previous_epoch="previous")
        self.assertEqual(self.creates, [])

    def test_startup_uses_predeclared_epoch_without_instantiating_ordinary_launcher(self):
        owner, host = self.ready()
        host.startup.assert_fresh = lambda: None
        host.operations.epoch = self.guardian_role.guardian_epoch
        host.capability = SimpleNamespace(pid=PARENT.pid, to_dict=lambda: {"synthetic": True})
        with patch.object(supervisors.SupervisorHost, "_attach", return_value=object()):
            result = host._finish_startup({"synthetic": True})
        self.assertEqual(result["event"], "supervisor_host_started")
        self.assertTrue(result["attached"])
        self.assertEqual(result["guardian_epoch"], self.guardian_role.guardian_epoch)
        self.assertEqual(self.creates, [self.guardian_member])
        self.assertIsNone(host.creation)
        self.assertFalse(owner.pending)

    def test_helper_selector_copy_cannot_replace_original_release_binding(self):
        owner, _ = self.ready()
        member_id = self.helper_member.member_id
        original = self.scope._role_release_data[member_id]
        self.scope._role_release_data[member_id] = tuple(list(original))
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "helper_selectors_changed"):
            owner.assert_original()
        self.assertEqual(self.creates, [])

    def test_actual_host_uses_daily_then_isolated_creation_and_publishes_after_both_exit(self):
        owner, host, guardian, helper = self.helper()
        for role in ("guardian", "helper"):
            create_index = self.events.index(("create", role))
            published_index = self.events.index(("actor_published", role))
            registration_index = self.events.index(("registration", role))
            daily_index = self.events.index("daily:enter", create_index - 3)
            isolated_index = self.events.index("isolated:enter", daily_index)
            self.assertLess(daily_index, isolated_index)
            self.assertLess(isolated_index, create_index)
            self.assertEqual(self.events[published_index + 1:published_index + 3],
                             ["isolated:exit", "daily:exit"])
            self.assertLess(published_index + 2, registration_index)
            self.assertLess(create_index, published_index)
        self.assertEqual(self.creates, [self.guardian_member, self.helper_member])
        self.assertIs(type(guardian.creation_witness), RetainedGuardianCreation)
        self.assertIsNot(guardian.process, self.scope._attempts[self.guardian_member.member_id].process)
        self.assertIs(helper.process, self.scope._attempts[self.helper_member.member_id].process)
        self.assertFalse(owner.pending)
        self.assertEqual((host.started_guardians, host.started_helpers), (1, 1))
        self.assertIs(host._start_initial_guardian(), guardian)
        self.assertEqual(len(self.creates), 2)

    def test_creation_context_refuses_reverse_lock_order_before_native_entry(self):
        owner, _ = self.ready()
        owner._current_creation = {"member": self.guardian_member}
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "ordered_creation_scope_required"):
            with owner.creation_scope(self.guardian_member):
                self.fail("unfenced context yielded")
        self.assertEqual(self.creates, [])
        self.assertEqual(self.isolated.current_guard(), None)

    def test_helper_requires_retained_ready_guardian_without_creating_process(self):
        owner, host, _ = self.guardian()
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "ready_guardian_required"):
            host._start_helper()
        self.assertEqual(self.creates, [self.guardian_member])
        self.assertNotIn(self.helper_member.member_id, self.scope._attempts)
        self.assertTrue(owner._records[self.helper_member.member_id]["no_creation"])
        self.assertFalse(owner.pending)
        with self.assertRaises(supervisors.SupervisorHostRefused):
            owner.assert_closed()

    def test_registration_failure_keeps_original_child_and_cannot_duplicate_creation(self):
        owner, host = self.ready()
        self.registration_error = RuntimeError("synthetic registration failure")
        with self.assertRaisesRegex(RuntimeError, "synthetic registration failure"):
            host._start_initial_guardian()
        child = host.guardian
        attempt = self.scope._attempts[self.guardian_member.member_id]
        self.assertIsNotNone(child)
        self.assertIs(owner._records[self.guardian_member.member_id]["attempt"], attempt)
        self.assertTrue(owner.pending)
        with self.assertRaises((RuntimeError, supervisors.SupervisorHostRefused)):
            host._start_initial_guardian()
        self.assertIs(host.guardian, child)
        self.assertEqual(self.creates, [self.guardian_member])
        self.registration_error = None
        owner.poll_once()
        self.assertFalse(owner.pending)
        self.assertIs(host._start_initial_guardian(), child)
        self.assertIs(self.publications[-1], attempt)
        self.assertEqual(self.creates, [self.guardian_member])

    def test_unknown_native_creation_retains_attempt_and_prevents_second_create(self):
        owner, host = self.ready()
        self.create_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            host._start_initial_guardian()
        attempt = self.scope._attempts[self.guardian_member.member_id]
        self.assertIs(owner._records[self.guardian_member.member_id]["attempt"], attempt)
        self.assertTrue(owner.pending)
        with self.assertRaises(supervisors.SupervisorHostRefused):
            host._start_initial_guardian()
        self.assertEqual(self.creates, [self.guardian_member])
        self.assertEqual(self.raw_closes, [])

    def test_interrupted_host_adoption_cannot_publish_or_retry_partial_child(self):
        owner, host = self.ready()
        original_setattr = supervisors.SupervisorHost.__setattr__

        def interrupt_adoption(target, name, value):
            if target is host and name == "guardian" and value is not None:
                raise KeyboardInterrupt("synthetic adoption interrupted")
            original_setattr(target, name, value)

        with patch.object(supervisors.SupervisorHost, "__setattr__", interrupt_adoption):
            with self.assertRaises(KeyboardInterrupt):
                host._start_initial_guardian()
        record = owner._records[self.guardian_member.member_id]
        self.assertEqual(record["phase"], "creating")
        self.assertIsNotNone(record["child"])
        self.assertIsNotNone(record["child_pin"])
        self.assertIsNotNone(record["witness_pin"])
        self.assertIsNone(host.guardian)
        self.assertTrue(owner.pending)
        owner.poll_once()
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "adopted_child_required"):
            owner._publish_registration(record)
        with self.assertRaises(supervisors.SupervisorHostRefused):
            host._start_initial_guardian()
        self.assertEqual(self.publications, [])
        self.assertEqual(self.creates, [self.guardian_member])
        self.assertEqual(self.raw_closes, [])

    def test_positive_no_create_is_terminal_without_live_child_or_capacity_claim(self):
        owner, host = self.ready()
        self.create_result, self.write_output = 0, False
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_failed"):
            host._start_initial_guardian()
        attempt = self.scope._attempts[self.guardian_member.member_id]
        record = owner._records[self.guardian_member.member_id]
        self.assertTrue(attempt.never_created)
        self.assertTrue(attempt.native_settled)
        self.assertTrue(record["no_creation"])
        self.assertFalse(owner.pending)
        self.assertIsNone(host.guardian)
        self.assertEqual(self.publications, [])
        self.assertEqual(self.raw_closes, [])
        try:
            host._start_initial_guardian()
        except supervisors.SupervisorHostRefused:
            pass
        self.assertEqual(self.creates, [self.guardian_member])
        host.draining = True
        owner.assert_close_ready()
        with self.assertRaises(supervisors.SupervisorHostRefused):
            owner.assert_closed()

    def test_guardian_recovery_duplicate_closes_before_attempt_handles_exactly_once(self):
        owner, host, guardian = self.guardian()
        self.dead(guardian)
        host._close_retired_child(guardian)
        owner.close_child(guardian)
        self.assertEqual(self.backend.closes, [901, 900])
        self.assertEqual(self.raw_closes, [801, 800])
        self.assertLess(self.events.index(("duplicate_close", 901)),
                        self.events.index(("duplicate_close", 900)))
        self.assertTrue(self.scope._attempts[self.guardian_member.member_id].native_settled)

    def test_helper_borrows_attempt_capture_and_never_closes_it_twice(self):
        owner, host, _, helper = self.helper()
        attempt = self.scope._attempts[self.helper_member.member_id]
        self.assertIs(helper.process, attempt.process)
        self.assertEqual(self.backend.duplicates, [(800, 900), (800, 901), (802, 902)])
        self.dead(helper)
        host._close_retired_child(helper)
        owner.close_child(helper)
        self.assertEqual(self.backend.closes, [902])
        self.assertEqual(self.raw_closes, [803, 802])
        self.assertTrue(attempt.native_settled)

    def test_live_child_and_substituted_child_cannot_release_creation_custody(self):
        owner, _, guardian = self.guardian()
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "child_death_unverified"):
            owner.close_child(guardian)
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "original_child_required"):
            owner.close_child(SimpleNamespace(**guardian.__dict__))
        self.assertEqual(self.backend.closes, [])
        self.assertEqual(self.raw_closes, [])

    def test_nested_recovery_witness_substitution_refuses_before_any_close(self):
        owner, _, guardian = self.guardian()
        self.dead(guardian)
        witness = guardian.creation_witness
        process = witness.process
        substitutions = (
            (witness, "_process", identities.VerifiedProcess(self.backend, 950, process.identity)),
            (process, "_backend", object()),
            (process, "_handle", 950),
            (process, "_lock", threading.Lock()),
            (witness, "_guardian_epoch", "substituted-epoch"),
        )
        for target, field, value in substitutions:
            with self.subTest(field=field):
                original = getattr(target, field)
                setattr(target, field, value)
                try:
                    with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "recovery_witness_changed"):
                        owner.close_child(guardian)
                finally:
                    setattr(target, field, original)
        self.assertEqual(self.backend.closes, [])
        self.assertEqual(self.raw_closes, [])

    def test_recovery_witness_close_failure_retains_attempt_until_same_owner_retry(self):
        owner, _, guardian = self.guardian()
        self.dead(guardian)
        self.backend.close_errors[901] = identities.IdentityUnavailable("process_handle_close_failed", 6)
        with self.assertRaises(identities.IdentityUnavailable):
            owner.close_child(guardian)
        self.assertEqual(self.backend.closes, [901])
        self.assertEqual(self.raw_closes, [])
        self.assertFalse(self.scope._attempts[self.guardian_member.member_id].native_settled)
        self.assertTrue(owner.pending)
        self.backend.close_errors.clear()
        owner.close_child(guardian)
        self.assertEqual(self.backend.closes, [901, 901, 900])
        self.assertEqual(self.raw_closes, [801, 800])
        self.assertFalse(owner.pending)

    def test_unknown_raw_close_retains_custody_without_retrying_numeric_handle(self):
        owner, _, guardian = self.guardian()
        self.dead(guardian)
        self.raw_close_results[801] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            owner.close_child(guardian)
        self.raw_close_results.clear()
        with self.assertRaises(creation.CreationCustodyError):
            owner.close_child(guardian)
        self.assertEqual(self.raw_closes, [801, 800])
        self.assertFalse(self.scope._attempts[self.guardian_member.member_id].native_settled)
        with self.assertRaises(supervisors.SupervisorHostRefused):
            owner.assert_closed()

    def test_original_host_and_positive_close_record_cannot_be_forged(self):
        owner, host = self.ready()
        host.draining = host._closed = True
        host._close_record = {"cleanup_errors": []}
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "positive_close_required"):
            owner.assert_closed()
        copied = object.__new__(integration.ExperimentSupervisor)
        copied.__dict__.update(owner.__dict__)
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "original_integration_required"):
            copied.assert_closed()
        host.operations = SimpleNamespace()
        with self.assertRaisesRegex(supervisors.SupervisorHostRefused, "operations_changed"):
            owner.assert_original()

    def test_actual_host_close_finishes_child_before_operator_and_startup_custody(self):
        owner, host, guardian = self.guardian()
        self.dead(guardian)
        host.draining = host._guardian_settled = True
        host.supervisor = host.helper = None
        host._registry_results[("guardian", id(guardian))] = SimpleNamespace(complete=True, changed=True)
        host.descriptor = object()

        def remove_descriptor(descriptor, *, owner_process):
            self.assertIs(descriptor, host.descriptor)
            self.assertIs(owner_process, self.scope.process)
            self.events.append("descriptor:remove")

        def close_startup():
            self.events.append("startup:close")
            host.startup._closed = True

        host.startup.close = close_startup
        host.operator_listener = SimpleNamespace(close=lambda: self.events.append("operator:close"))
        host.discovery = SimpleNamespace(remove_instance=remove_descriptor,
                                          close=lambda: self.events.append("discovery:close"))
        runtime = {"mode": "off", "registry_revision": 3,
                   "admission_barrier": "NONE", "policy_entry_nonce": None}
        registry = SimpleNamespace(status=lambda: SimpleNamespace(pending=0, quarantined=0, resources=0))
        with patch.object(supervisors.SupervisorHost, "_runtime_observation", return_value=(runtime, None)), \
                patch.object(pipe_windows, "_GLOBAL_REGISTRY", registry):
            owner.close()
            owner.assert_closed()
            events = list(self.events)
            owner.close()
            self.assertEqual(self.events, events)
        self.assertTrue(host._closed)
        self.assertTrue(host.startup._closed)
        self.assertEqual(self.backend.closes, [901, 900])
        self.assertEqual(self.raw_closes, [801, 800])
        self.assertLess(self.events.index(("raw_close", 800)), self.events.index("descriptor:remove"))
        self.assertLess(self.events.index("descriptor:remove"), self.events.index("operator:close"))
        self.assertLess(self.events.index("operator:close"), self.events.index("discovery:close"))
        self.assertLess(self.events.index("discovery:close"), self.events.index("startup:close"))

    def test_transport_failure_enters_drain_without_starving_actual_host_recovery(self):
        owner, host = self.ready()
        calls = []

        def recovery(target):
            self.assertIs(target, host)
            self.assertTrue(target.draining)
            calls.append("recovery")
            return {"event": "synthetic_recovery_tick"}

        def operational(target):
            self.assertIs(target, host)
            self.assertTrue(target.draining)
            calls.append("operational")

        with patch.object(integration.ExperimentSupervisor, "poll_once",
                side_effect=RuntimeError("private synthetic transport details")), \
                patch.object(supervisors.SupervisorHost, "_run_recovery_once", recovery), \
                patch.object(supervisors.SupervisorHost, "_operational_tick", operational), \
                patch.object(supervisors.SupervisorHost, "_custody_snapshot", return_value={"settled": False}):
            result = host.run_once()
        self.assertIs(host._experiment_supervisor, owner)
        self.assertTrue(host.draining)
        self.assertEqual(calls, ["recovery", "operational"])
        self.assertTrue(result["draining"])
        self.assertIn("experiment_transport_error", result)
        self.assertNotIn("private synthetic transport details", str(result))


if __name__ == "__main__":
    unittest.main()
