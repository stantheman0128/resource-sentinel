"""Original remote readiness with isolated SQL and explicit synthetic native I/O.

The real client issues retained DailyReadinessAuthority objects through the
synthetic authenticated peer transport. Source bytes/manifest checks are real;
loaded-import attestation and native backends remain named portable fixtures.
No native, source activation, remote provider or capability gate is established.
"""
from contextlib import closing, contextmanager
import copy
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive import experiment_demand, experiment_exclusion, experiment_scope as scope
from sentinel.adaptive import exemption_sync
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.native_job import CpuState, NativeJob
from sentinel.adaptive.pipe_windows import NativeDeadline
from sentinel.exemptions import Exemptions
from tests import test_adaptive_daily_readiness_lock_boundary as readiness_fixture
from tests import test_adaptive_experiment_release_native as release_fixture
from tests.test_adaptive_ipc import Clock
from tests.windows import adaptive_scope_launch as launch_module


class ScopedReadinessHelperTests(unittest.TestCase):
    def setUp(self):
        self.fixture = readiness_fixture.DailyReadinessLockBoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.row = generation.read_generation(self.fixture.conn)

    def validate(self, row=None):
        return generation.revalidate_scoped_readiness(self.fixture.db,
            expected_generation=self.row if row is None else row)

    def test_unscoped_validation_never_acquires_authority(self):
        with patch.object(generation, "_owned_readiness_scope",
                side_effect=AssertionError("validator acquired a scope")), \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_required"):
            self.validate()
        self.assertNotIn("rpc", self.fixture.events)

    def test_exact_group_member_restores_isolated_selector_without_sql_or_rpc(self):
        isolated = self.fixture.isolated_store()
        with generation.readiness_scopes((self.fixture.db, isolated.db_path),
                absent_paths=(isolated.db_path,)):
            daily = generation._READINESS_LOCAL.group[self.fixture.db.resolve()]
            with generation.readiness_scope(isolated.db_path) as other:
                with patch.object(generation.sqlite3, "connect", side_effect=AssertionError("helper SQL")), \
                        patch.object(transport.NativePipeConnection, "connect", side_effect=AssertionError("helper RPC")):
                    deadline = self.validate()
                    self.assertIs(deadline, daily.authority._deadline)
                    self.assertIs(type(deadline), NativeDeadline)
                    self.assertIs(generation._READINESS_LOCAL.scope, other)
                    with self.assertRaises(generation.DailyGenerationUnavailable):
                        self.validate(dict(self.row, readiness_instance_id=str(uuid4())))
                    self.assertIs(generation._READINESS_LOCAL.scope, other)
                    with self.assertRaises(generation.DailyGenerationUnavailable):
                        generation.revalidate_scoped_readiness(isolated.db_path, expected_generation=self.row)
        self.assertEqual(self.fixture.events.count("rpc"), 1)

    def test_complete_original_schema_and_types_are_required(self):
        with generation.readiness_scope(self.fixture.db) as original:
            cases = [dict(self.row, **{key: value + "changed"}) for key, value in self.row.items()
                     if type(value) is str]
            cases += [dict(self.row, singleton=True), dict(self.row, schema_version=1.0),
                      dict(self.row, extra="unknown"), {key: value for key, value in self.row.items()
                          if key != "owner_identity_json"}]
            for changed in cases:
                with self.subTest(changed=changed), self.assertRaisesRegex(
                        generation.DailyGenerationUnavailable, "scope_binding_changed"):
                    self.validate(changed)
            for value in (True, 1.0):
                original.row = dict(self.row, singleton=value)
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_binding_changed"):
                    self.validate()
            original.row = dict(self.row)
            self.assertIs(self.validate(), original.authority._deadline)

    def test_source_config_and_file_identity_changes_refuse_original_scope(self):
        fixture = self.fixture
        source = fixture.root / "sentinel/coordinator.py"
        config = fixture.root / "config.json"
        with generation.readiness_scope(fixture.db):
            for path, reason in ((source, "generation_mismatch"), (config, "config_changed")):
                before = path.read_bytes()
                try:
                    path.write_bytes(before + b"\n ")
                    with self.assertRaisesRegex(generation.DailyGenerationUnavailable, reason):
                        self.validate()
                finally:
                    path.write_bytes(before)
            original = generation._ledger_identity(fixture.db)
            with patch.object(generation, "_ledger_identity", return_value=(original[0], original[1] + 1)), \
                    self.assertRaisesRegex(generation.DailyGenerationUnavailable, "identity_changed"):
                self.validate()

    def test_source_validation_consumes_same_original_rpc_deadline(self):
        with generation.readiness_scope(self.fixture.db) as original:
            deadline, start, end = original.authority._deadline, original.authority._deadline._start, original.authority._deadline._end
            verify = generation.verify_import_provenance
            def expensive(manifest, root):
                result = verify(manifest, root)
                self.fixture.clock.now += 1000
                return result
            with patch.object(generation, "verify_import_provenance", side_effect=expensive), \
                    self.assertRaisesRegex(Exception, "pipe_timeout"):
                self.validate()
            self.assertIs(original.authority._deadline, deadline)
            self.assertEqual((deadline._start, deadline._end), (start, end))
        self.assertEqual(self.fixture.events.count("rpc"), 1)

    def test_local_pin_proved_once_and_replacement_cannot_be_adopted(self):
        fixture = self.fixture
        with patch.dict(generation._LOCAL_GENERATIONS, {fixture.owner.generation: fixture.owner}), \
                patch.object(fixture.owner, "assert_ready", wraps=fixture.owner.assert_ready) as ready:
            with generation.readiness_scope(fixture.db) as original:
                self.assertIs(original.local_owner, fixture.owner)
                self.assertIsNone(original.authority)
                with patch.object(generation.sqlite3, "connect", side_effect=AssertionError("local helper opened SQL")):
                    self.assertIsNone(self.validate())
                ready.assert_called_once()
                with patch.dict(generation._LOCAL_GENERATIONS, {fixture.owner.generation: object()}), \
                        self.assertRaisesRegex(generation.DailyGenerationUnavailable, "local_owner_changed"):
                    self.validate()
        self.assertNotIn("rpc", fixture.events)

    def test_original_remote_branch_ignores_later_local_registration(self):
        fixture = self.fixture
        with generation.readiness_scope(fixture.db) as original:
            self.assertIsNone(original.local_owner)
            with patch.dict(generation._LOCAL_GENERATIONS, {fixture.owner.generation: fixture.owner}), \
                    patch.object(fixture.owner, "_assert_owner", side_effect=AssertionError("remote adopted local")):
                self.assertIs(self.validate(), original.authority._deadline)
                fixture.bind(fixture.conn)
                fixture.conn.execute("SELECT sentinel_daily_generation()").fetchone()
                fixture.server_backend.status = IdentityStatus.DEAD
                with self.assertRaisesRegex(Exception, "original_peer_unavailable"):
                    self.validate()
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_foreign_thread_copied_cleanup_and_closed_scopes_refuse(self):
        with generation.readiness_scope(self.fixture.db) as original:
            failures = []
            def foreign_thread():
                try:
                    self.validate()
                except BaseException as error:
                    failures.append(error)
            thread = threading.Thread(target=foreign_thread)
            thread.start()
            thread.join()
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], generation.DailyGenerationUnavailable)
            generation._READINESS_LOCAL.scope = copy.copy(original)
            try:
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "original_scope_required"):
                    self.validate()
            finally:
                generation._READINESS_LOCAL.scope = original
            original.cleanup = (object(), object())
            try:
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "capacity_scope_required"):
                    self.validate()
            finally:
                original.cleanup = None
            original.close()
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_unavailable"):
                self.validate()

    def test_unknown_original_authority_close_retains_scope_and_prevents_reacquisition(self):
        error = OSError("synthetic retained witness close unknown")
        with self.assertRaises(OSError) as raised:
            with generation.readiness_scope(self.fixture.db) as original:
                self.validate()
                self.fixture.server_backend.close_error = error
        self.assertIs(raised.exception, error)
        self.assertIs(generation._READINESS_SCOPES[id(original)], original)
        self.assertIs(original.error, error)
        self.assertTrue(original.authority._close_unknown)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending"):
            with generation.readiness_scope(self.fixture.db):
                self.fail("unknown original close was replaced")
        self.assertEqual(self.fixture.events.count("rpc"), 1)


class _TrackedPolicy:
    def __init__(self, original, name, fixture):
        self.original, self.name, self.fixture = original, name, fixture

    def current_logon(self):
        return self.original.current_logon()

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        fixture = self.fixture
        fixture.events.append("enter:" + self.name)
        fixture.active.append(self.name)
        try:
            with self.original.hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
        finally:
            fixture.assertEqual(fixture.active.pop(), self.name)
            fixture.events.append("leave:" + self.name)


class OriginalRemoteExperimentScopeTests(unittest.TestCase):
    def setUp(self):
        actual_ready = scope.ExperimentNativeScope._ready
        self.fixture = release_fixture.ExperimentNativeReleaseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.events, self.active, self.wrapper_deadlines = [], [], []
        self.clock = Clock()
        self.db = self.fixture.db.resolve()
        source_root = self.fixture.fixture.scope.resolve()
        for relative in generation.REQUIRED_PATHS:
            path = source_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# portable original source fixture\n", encoding="utf-8")
        manifest = generation.SourceManifest.capture(source_root)
        self.fixture.fixture.generation.update(source_digest=manifest.digest,
            source_manifest_json=experiment_demand._canonical(manifest.to_dict()))
        self.demand, self.command = self.fixture.admitted()
        self.row = self.demand._original_generation_binding()
        # Initialize the real sticky exemption binding under the original
        # daily POLICY before installing the synthetic remote generation.
        # Setter tests still execute the actual bounded grants snapshot.
        policy = self.demand._admission._submission_policy
        guard = policy.prepare(self.fixture.guardian.identity.logon_id)
        with policy.hold(guard):
            exemption_sync.bind_policy_locked(Exemptions(self.db.parent), policy.store)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in self.row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" + ",".join("?" for _ in self.row) + ")",
                tuple(self.row.values()))
            generation._install_triggers(conn)
            conn.commit()
        # Reuse the real client transport fixture against this full admission
        # ledger. The peer/backends are synthetic, never an assert_ready stub.
        self.pipe = readiness_fixture.DailyReadinessLockBoundaryTests()
        self.pipe.db, self.pipe.events, self.pipe.clock = self.db, self.events, self.clock
        self.pipe.identity = self.pipe.caller_identity = self.fixture.guardian.identity
        self.pipe.server_backend = readiness_fixture.NativeIdentityFixture(self.pipe.identity, self.events)
        self.pipe.caller_backend = readiness_fixture.NativeIdentityFixture(self.pipe.caller_identity, self.events)
        self.pipe.connections, self.pipe.reply_changes = [], {}
        self.pipe.rpc_callback = self.pipe.peer_cleanup_error = self.pipe.pipe_cleanup_error = None
        self.pipe.conn = sqlite3.connect(self.db)
        self.addCleanup(self.pipe.conn.close)
        test = self
        class ActiveProvider:
            @property
            def active(self):
                return bool(test.active)
        self.pipe.provider = ActiveProvider()
        policy = self.demand._admission._submission_policy
        policy.provider = _TrackedPolicy(policy.provider, "daily", self)
        initialize = scope._IsolatedStore.__init__
        def initialize_isolated(store, path):
            initialize(store, path)
            store._policy.provider = _TrackedPolicy(store._policy.provider, "isolated", self)
        class JobMutex(release_fixture._JobMutex):
            @contextmanager
            def acquire(self, *, timeout_ms):
                test.assertIn(test.active, (["daily", "isolated"], ["isolated"]))
                test.events.append("enter:job")
                test.active.append("job")
                try:
                    with super().acquire(timeout_ms=timeout_ms) as lease:
                        yield lease
                finally:
                    test.assertEqual(test.active.pop(), "job")
                    test.events.append("leave:job")
        changes = (
            patch.object(scope.ExperimentNativeScope, "_ready", actual_ready),
            patch.object(scope, "daily_generation", generation),
            patch.object(experiment_exclusion, "daily_generation", generation),
            patch.object(generation, "daily_locations", return_value=(source_root, self.db.parent)),
            patch.object(generation, "verify_import_provenance", side_effect=lambda value, root: value.verify(root)),
            patch.object(generation.VerifiedProcess, "current", side_effect=self.pipe.current),
            patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock),
            patch.object(transport.NativePipeConnection, "connect", side_effect=self.pipe.connect),
            patch.object(scope._IsolatedStore, "__init__", initialize_isolated),
            patch.object(scope, "NativePolicyMutex", JobMutex),
        )
        for change in changes:
            change.start()
            self.addCleanup(change.stop)
        self.addCleanup(self.remove_readiness_originals)

    def remove_readiness_originals(self):
        # Only this fixture's exact temporary ledgers; unknown fake handles are
        # deliberately not described as positively closed production owners.
        paths = {self.db, (self.demand.directory / "s1-scope.sqlite3").resolve()}
        with generation._READINESS_SCOPES_LOCK:
            for pool in (generation._READINESS_SCOPES, generation._ABSENCE_SCOPES):
                for key, original in tuple(pool.items()):
                    if original.path in paths:
                        pool.pop(key)
        owner = self.demand._native_preparation
        if owner is not None and owner not in self.fixture.scopes:
            self.fixture.scopes.append(owner)

    def create_wrapper(self, launcher, *, native_deadline=None):
        self.assertEqual(self.active, ["daily", "isolated", "job"])
        original = generation._READINESS_LOCAL.group[self.db]
        self.assertIs(native_deadline, original.authority._deadline)
        native_deadline.require()
        self.wrapper_deadlines.append(native_deadline)
        return self.fixture.create_wrapper(launcher, native_deadline=native_deadline)

    def prepare(self):
        with patch.object(launch_module.ScopeLaunch, "create_inert", autospec=True,
                side_effect=self.create_wrapper):
            owner = scope.ExperimentNativeScope.prepare(self.demand, self.command)
        self.fixture.scopes.append(owner)
        self.assertTrue(owner._registered)
        return owner

    def journal(self, owner):
        with closing(sqlite3.connect(owner.ledger_path)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_experiment_scope_journal").fetchone())

    def test_original_factory_and_setter_receive_same_lexical_deadlines(self):
        owner = self.prepare()
        self.assertEqual(self.events.count("rpc"), 2)  # preflight, then both-ledger group
        self.assertLess(self.events.index("rpc"), self.events.index("enter:daily"))
        created_deadline = NativeJob.create.call_args.kwargs["native_deadline"]
        self.assertIs(created_deadline, self.wrapper_deadlines[0])
        self.assertEqual(created_deadline._end - created_deadline._start, 1000)
        self.events.clear()
        setter = owner.job.set_cpu_rate_unverified
        def set_original(rate, *, native_deadline=None):
            self.assertEqual(self.active, ["daily", "isolated", "job"])
            daily = generation._READINESS_LOCAL.group[self.db]
            self.assertIs(native_deadline, daily.authority._deadline)
            return setter(rate, native_deadline=native_deadline)
        with patch.object(owner.job, "set_cpu_rate_unverified", side_effect=set_original) as call:
            self.assertEqual(owner.set_cpu_rate(), CpuState(5, 2500))
        self.assertEqual(call.call_count, 1)
        self.assertEqual(self.events.count("rpc"), 1)
        self.assertEqual([value for value in self.events if value.startswith("enter:")],
            ["enter:daily", "enter:isolated", "enter:job"])
        self.assertFalse(self.active)
        self.assertIsNone(generation._READINESS_LOCAL.scope)
        self.assertIsNone(generation._READINESS_LOCAL.group)

    def test_full_generation_row_is_checked_on_actual_coverage_transaction(self):
        owner = self.prepare()
        for field, value in (("readiness_instance_id", str(uuid4())),
                ("source_root", self.row["source_root"] + "-changed"),
                ("owner_identity_json", experiment_demand._canonical(self.fixture.wrapper.identity.to_dict()))):
            with self.subTest(field=field), self.assertRaisesRegex(scope.ExperimentScopeError, "generation_changed"):
                with owner._scope(daily=True):
                    with owner.daily_store._transaction() as conn:
                        conn.execute("UPDATE adaptive_daily_generation SET " + field + "=?", (value,))
                        owner._coverage_locked(conn, restrictive=True)
            with closing(sqlite3.connect(self.db)) as conn:
                self.assertEqual(generation.read_generation(conn), self.row)

    def test_original_launch_authorization_needs_no_ambient_lexical_scope(self):
        owner = self.prepare()
        self.events.clear()
        self.assertIsNone(getattr(generation._READINESS_LOCAL, "scope", None))
        self.assertIsNone(getattr(generation._READINESS_LOCAL, "group", None))
        self.assertIs(owner.launch_once(), self.fixture.root)
        self.assertTrue(owner._launch_authorized)
        self.assertTrue(owner.launch.root_job_bound)
        self.assertEqual(self.events.count("rpc"), 1)
        self.assertFalse(self.active)

    def test_expiry_after_control_intent_keeps_owned_intent_and_restore_independent(self):
        owner = self.prepare()
        begin = owner.journal.begin_control_locked
        def commit_then_expire(conn, target):
            result = begin(conn, target)
            self.clock.now += 1000
            return result
        with patch.object(owner.journal, "begin_control_locked", side_effect=commit_then_expire), \
                self.assertRaisesRegex(Exception, "pipe_timeout"):
            owner.set_cpu_rate()
        self.assertEqual(self.fixture.native.calls("SetInformationJobObject"), [])
        self.assertEqual(json.loads(self.journal(owner)["pending_target_json"]), dict(flags=5, rate_bp=2500))
        self.assertNotIn("generation_readiness", owner._preparation_pending)
        self.events.clear()
        self.assertEqual(owner.restore(), CpuState(0, 0))
        self.assertNotIn("rpc", self.events)
        self.assertEqual([value for value in self.events if value.startswith("enter:")],
            ["enter:isolated", "enter:job"])
        self.assertIsNone(self.journal(owner)["pending_target_json"])

    def test_failed_daily_readiness_withdraws_owned_cap_without_daily_dependency(self):
        owner = self.prepare()
        self.assertEqual(owner.set_cpu_rate(), CpuState(5, 2500))
        self.events.clear()
        self.pipe.reply_changes["source_digest"] = "f" * 64
        # observe_control returns the actual NativeJob.disable readback; flags
        # are cleared while the raw (inactive) rate remains 10000.
        self.assertEqual(owner.observe_control(), CpuState(0, 10000))
        self.assertEqual(self.events.count("rpc"), 1)  # failed daily attempt only
        self.assertEqual([value for value in self.events if value.startswith("enter:")],
            ["enter:isolated", "enter:job"])
        self.assertNotIn("generation_readiness", owner._preparation_pending)

    def test_clean_preflight_deadline_rejection_does_not_fabricate_pending_acquisition(self):
        verify = generation.verify_import_provenance
        def expire_after_rpc(manifest, root):
            result = verify(manifest, root)
            if "rpc" in self.events:
                self.clock.now += 1000
            return result
        with patch.object(generation, "verify_import_provenance", side_effect=expire_after_rpc), \
                self.assertRaisesRegex(Exception, "pipe_timeout"):
            scope.ExperimentNativeScope.prepare(self.demand, self.command)
        owner = self.demand._native_preparation
        self.assertIs(scope._OWNERS[owner.scope_id], owner)
        self.assertFalse(owner._preparation_pending)
        self.assertFalse(owner._create_attempted)
        self.assertTrue(all(value == "not_entered" for value in owner._preparation_acquisitions.values()))
        self.assertEqual(owner.close_native().snapshot()["disposition"], "PREPARATION_CLOSED")


if __name__ == "__main__":
    unittest.main()
