"""Portable original wrapper boundary tests, never native acceptance evidence.

Wire validation, OnceLaunchState, WrapperOwner, ScopeCommand, timing files and
native launch ownership are real. Readiness transport, Job/mutex APIs and the
Win32 process API use explicit in-process fixtures; no DLL or process is opened.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import native_job
from sentinel.adaptive import native_launcher
from sentinel.adaptive import pipe_windows
from sentinel.adaptive import windows
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.pipe_windows import NativeDeadline
from tests import test_adaptive_native_launcher as launch_fixture
from tests.test_adaptive_ipc import Clock
from tests.windows import adaptive_scope_launch as api
from tests.windows import adaptive_scope_wrapper as wrapper


class LaunchBoundsWireTests(unittest.TestCase):
    def setUp(self):
        self.scope_id, self.request_id = str(uuid4()), str(uuid4())
        self.bounds = dict(reservation_id=str(uuid4()), binding_sha256="b" * 64,
            expires_at=300.0, lease_deadline_monotonic_ns=200_000_000_000)

    def request(self, operation="launch", **kwargs):
        return api.request(operation, self.scope_id, self.request_id, "a" * 64, **kwargs)

    def test_launch_requires_exact_v2_bounds_and_nonlaunch_keeps_v1_shape(self):
        value = self.request(launch_bounds=self.bounds)
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["launch_bounds"], self.bounds)
        self.assertEqual(api.validate_request(value, self.scope_id, "a" * 64), value)
        with self.assertRaises(api.ScopeLaunchError):
            self.request()
        for operation in ("observe", "seal", "drain"):
            value = self.request(operation)
            self.assertEqual(value["schema_version"], 1)
            self.assertNotIn("launch_bounds", value)
            self.assertEqual(api.validate_request(value, self.scope_id, "a" * 64), value)
            with self.assertRaises(api.ScopeLaunchError):
                self.request(operation, launch_bounds=self.bounds)

    def test_strict_bounds_reject_unknown_missing_nonfinite_or_wrong_scalar_types(self):
        changed = [dict(self.bounds, extra=True), {key: value for key, value in self.bounds.items()
            if key != "binding_sha256"}]
        for field, values in (("expires_at", (True, 0, -1, float("inf"), float("nan"), "300")),
                ("lease_deadline_monotonic_ns", (True, 0, -1, 200.0, "200")),
                ("reservation_id", (None, "")), ("binding_sha256", (None, "g" * 64, "b" * 63))):
            changed.extend(dict(self.bounds, **{field: value}) for value in values)
        for bounds in changed:
            with self.subTest(bounds=bounds), self.assertRaises(api.ScopeLaunchError):
                self.request(launch_bounds=bounds)
        valid = self.request(launch_bounds=self.bounds)
        for altered in (valid | {"schema_version": True}, valid | {"schema_version": 1},
                valid | {"scope_id": str(uuid4())}, valid | {"other": 1}):
            with self.subTest(altered=altered), self.assertRaises(api.ScopeLaunchError):
                api.validate_request(altered, self.scope_id, "a" * 64)

    def test_once_state_retains_canonical_bounds_and_rejects_changed_replay(self):
        state = api.OnceLaunchState("a" * 64)
        supplied = dict(self.bounds)
        self.assertTrue(state.begin(self.request_id, "a" * 64, launch_bounds=supplied))
        self.assertFalse(state.begin(self.request_id, "a" * 64, launch_bounds=dict(self.bounds)))
        supplied["expires_at"] += 1
        with self.assertRaises(api.ScopeLaunchError):
            state.begin(self.request_id, "a" * 64, launch_bounds=supplied)
        for field, value in (("reservation_id", str(uuid4())), ("binding_sha256", "c" * 64),
                ("expires_at", 301.0), ("lease_deadline_monotonic_ns", 199_000_000_000)):
            with self.subTest(field=field), self.assertRaises(api.ScopeLaunchError):
                state.begin(self.request_id, "a" * 64, launch_bounds=dict(self.bounds, **{field: value}))
        with self.assertRaises(api.ScopeLaunchError):
            state.begin(str(uuid4()), "a" * 64, launch_bounds=self.bounds)
        self.assertFalse(state.begin(self.request_id, "a" * 64, launch_bounds=self.bounds))


class WrapperBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.native = launch_fixture.NativeLauncherTests()
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.clock, self.events = Clock(), []
        self.active_job = self.active_readiness = False
        self.monotonic, self.wall = 100.0, 200.0
        self.acquire_error = self.exit_error = self.revalidation_error = None
        self.acquire_unknown = False
        self.on_mutex = None
        self.readiness_body_errors = []
        self.scope_id, self.nonce, self.request_id = str(uuid4()), uuid4().hex, str(uuid4())
        self.guardian = ProcessIdentity(601, 11001, launch_fixture.IDENTITY.logon_id)
        self.wrapper_identity = ProcessIdentity(602, 11002, self.guardian.logon_id)
        application = self.directory / "python.exe"
        application.write_bytes(b"explicit synthetic application")
        script = self.directory / "cpu_fixture.py"
        script.write_text("# explicit source fixture; never executed\n", encoding="utf-8")
        self.fixture_sha256 = hashlib.sha256(script.read_bytes()).hexdigest()
        self.generation = dict(singleton=1, schema_version=1, generation=str(uuid4()), state="ACTIVE",
            source_digest="a" * 64, config_digest="b" * 64, source_manifest_json="{}",
            source_root=str(self.directory), ledger_path=str(self.directory / "daily.sqlite3"),
            owner_identity_json=json.dumps(self.guardian.to_dict(), sort_keys=True, separators=(",", ":")),
            ledger_identity_json='["1","2"]', readiness_instance_id=str(uuid4()))
        arguments = ("-I", str(script), "--canonical-root", str(self.directory),
            "--source-generation", self.generation["generation"], "--source-digest", self.generation["source_digest"],
            "--fixture-sha256", self.fixture_sha256, "--nonce", self.nonce,
            "--job-name", "Local\\ResourceSentinel.Test.Job." + self.nonce,
            "--directory", str(self.directory), "--seconds", "2", "--workers", "1",
            "--scope-id", self.scope_id, "--scope-bound-stdin")
        self.command = api.ScopeCommand.capture(application=application, arguments=arguments,
            cwd=self.directory, fixture_paths=(script,))
        self.bounds = dict(reservation_id=str(uuid4()), binding_sha256="c" * 64,
            expires_at=300.0, lease_deadline_monotonic_ns=190_000_000_000)
        self.payload = dict(schema_version=2, scope_id=self.scope_id, job_nonce=self.nonce,
            job_name="Local\\ResourceSentinel.Test.Job." + self.nonce,
            guardian_identity=self.guardian.to_dict(), endpoint_instance=str(uuid4()),
            deadline_monotonic=210.0, command=self.command.to_dict(), command_sha256=self.command.sha256,
            canonical_source=str(self.directory), generation=deepcopy(self.generation),
            reservation_id=self.bounds["reservation_id"], binding_sha256=self.bounds["binding_sha256"],
            request_marker=str(self.directory / ("scope-request-" + self.scope_id + ".json")),
            fixture_sources=[], python_sha256="d" * 64)
        self.owner = wrapper.WrapperOwner(self.payload, api, self.command, object())
        self.owner.guardian = self.guardian
        self.owner.current = SimpleNamespace(identity=self.wrapper_identity, close=Mock())
        self.owner.endpoint = object()
        self.owner.registry = SimpleNamespace(status=lambda: SimpleNamespace(resources=0, pending=0, quarantined=0))
        self.addCleanup(self.cleanup_fixture)
        self.original_scope = SimpleNamespace(closed=False, error=None)
        self.observed_generation = deepcopy(self.generation)
        self.job = SimpleNamespace(handle=launch_fixture.JOB_HANDLE, logon_sid=self.guardian.logon_id,
            accounting=lambda: SimpleNamespace(total_processes=0, active_processes=0),
            active_pids=lambda: (), query_cpu=lambda: SimpleNamespace(flags=0), close=Mock())
        fixture = self
        class JobMutex:
            @contextmanager
            def acquire(mutex, *, timeout_ms):
                fixture.events.append("job-enter")
                fixture.active_job = True
                if fixture.on_mutex is not None:
                    fixture.on_mutex()
                try:
                    yield SimpleNamespace(abandoned=False)
                finally:
                    fixture.active_job = False
                    fixture.events.append("job-exit")

            def close(mutex):
                fixture.events.append("mutex-close")
        self.mutex = JobMutex()
        for change in (
                patch.object(pipe_windows, "_backend", return_value=self.clock),
                patch.object(wrapper.time, "monotonic", side_effect=lambda: self.monotonic),
                patch.object(wrapper.time, "monotonic_ns", side_effect=lambda: int(self.monotonic * 1_000_000_000)),
                patch.object(wrapper.time, "time", side_effect=lambda: self.wall),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "readiness_scope", side_effect=self.readiness),
                patch.object(generation, "revalidate_scoped_readiness", side_effect=self.revalidate),
                patch.object(native_job.NativeJob, "open", return_value=self.job),
                patch.object(windows, "NativePolicyMutex", return_value=self.mutex),
                patch.dict(sys.modules, {"msvcrt": SimpleNamespace(get_osfhandle=lambda fd: fd)})):
            self.stack.enter_context(change)
        self.ipc_deadline = NativeDeadline.after_ms(5000)
        self.readiness_deadline = NativeDeadline.after_ms(1000)
        self.original_launch = native_launcher.launch_in_job
        self.launch_calls = []
        self.stack.enter_context(patch.object(native_launcher, "launch_in_job", side_effect=self.launch))

    def cleanup_fixture(self):
        # Only temporary Python streams are force-closed for test teardown.
        # Simulated unknown owners are never described as production cleanup.
        for stream in self.owner.files:
            try:
                if not stream.closed:
                    stream.close()
            except BaseException:
                pass
        if self.owner in wrapper._RETAINED:
            wrapper._RETAINED.remove(self.owner)

    def incoming(self, **changes):
        bounds = dict(self.bounds, **changes)
        return api.request("launch", self.scope_id, self.request_id, self.command.sha256, launch_bounds=bounds)

    @contextmanager
    def readiness(self, path):
        self.assertFalse(self.active_job, "readiness acquisition happened under Job mutex")
        self.assertEqual(Path(path), Path(self.generation["ledger_path"]))
        self.assertTrue(self.owner.state.attempted)
        self.events.append("readiness-enter")
        if self.acquire_error is not None:
            if self.acquire_unknown:
                self.original_scope.error = self.acquire_error
                self.acquire_error.daily_readiness_scope = self.original_scope
                self.acquire_error.add_note("daily_readiness_scope_cleanup_unknown")
            else:
                self.original_scope.closed = True
            raise self.acquire_error
        self.active_readiness = True
        try:
            yield self.original_scope
        except BaseException as error:
            self.readiness_body_errors.append(error)
            raise
        finally:
            self.active_readiness = False
            self.events.append("readiness-exit")
            if self.exit_error is not None:
                self.original_scope.error = self.exit_error
                self.exit_error.daily_readiness_scope = self.original_scope
                self.exit_error.add_note("daily_readiness_scope_cleanup_unknown")
                raise self.exit_error
            self.original_scope.closed = True

    def revalidate(self, path, *, expected_generation):
        self.assertTrue(self.active_readiness)
        self.assertEqual(Path(path), Path(self.generation["ledger_path"]))
        self.assertEqual(expected_generation, self.generation)
        self.events.append("readiness-revalidate")
        if expected_generation != self.observed_generation:
            raise generation.DailyGenerationUnavailable("synthetic_full_generation_mismatch")
        if self.revalidation_error is not None:
            raise self.revalidation_error
        self.readiness_deadline.require()
        return self.readiness_deadline

    def launch(self, job, application, command, **kwargs):
        self.assertTrue(self.active_readiness)
        self.assertTrue(self.active_job)
        self.assertIs(job, self.job)
        self.assertIs(kwargs["native_deadline"], self.ipc_deadline)
        self.assertIs(kwargs["readiness_deadline"], self.readiness_deadline)
        self.assertEqual(kwargs["scope_deadline_monotonic"], self.payload["deadline_monotonic"])
        self.assertEqual(kwargs["lease_deadline_monotonic_ns"], self.bounds["lease_deadline_monotonic_ns"])
        self.assertEqual(kwargs["lease_expires_at"], self.bounds["expires_at"])
        stream = self.owner.files[0]
        self.assertTrue(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        self.assertEqual(stream.tell(), 0)
        self.assertEqual(kwargs["stdin_handle"], stream.fileno())
        self.assertLessEqual(os.fstat(stream.fileno()).st_size, 4096)
        self.events.append("native-launch")
        self.launch_calls.append(dict(kwargs))
        return self.original_launch(job, application, command, backend=self.native.backend, **kwargs)

    def creates(self):
        return [value for value in self.native.kernel.calls if value[0] == "CreateProcessW"]

    def test_original_readiness_and_timing_stream_are_used_at_actual_launch(self):
        self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertEqual(len(self.creates()), 1)
        self.assertLess(self.events.index("readiness-enter"), self.events.index("job-enter"))
        self.assertLess(self.events.index("job-exit"), self.events.index("readiness-exit"))
        self.assertIs(self.owner._readiness_scope, self.original_scope)
        self.assertTrue(self.original_scope.closed)
        self.assertIs(type(self.owner.process), native_launcher.CreatedProcess)
        self.assertEqual(self.owner._creation_outcome, "created")
        stream = self.owner.files[0]
        record = json.loads(stream.read())
        self.assertEqual(record, dict(schema_version=1, kind="S1ScopeTiming", scope_id=self.scope_id,
            job_nonce=self.nonce, source_generation=self.generation["generation"],
            source_digest=self.generation["source_digest"], fixture_sha256=self.fixture_sha256,
            scope_deadline_monotonic_ns=210_000_000_000))
        self.assertNotIn("command_sha256", record)
        self.assertFalse(stream.closed)
        self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertEqual(len(self.creates()), 1)
        self.assertEqual(self.events.count("readiness-enter"), 1)

    def test_changed_replay_bounds_never_acquire_fresh_readiness_or_create(self):
        self.owner._launch(self.incoming(), self.ipc_deadline)
        with self.assertRaises(api.ScopeLaunchError):
            self.owner._launch(self.incoming(expires_at=self.bounds["expires_at"] + 1), self.ipc_deadline)
        self.assertEqual(len(self.creates()), 1)
        self.assertEqual(self.events.count("readiness-enter"), 1)

    def test_bootstrap_allocation_mismatch_refuses_before_native_or_readiness(self):
        with self.assertRaises(api.ScopeLaunchError):
            self.owner._launch(self.incoming(reservation_id=str(uuid4())), self.ipc_deadline)
        self.assertEqual(self.creates(), [])
        self.assertNotIn("readiness-enter", self.events)

    def test_full_original_generation_mismatch_refuses_before_create(self):
        self.observed_generation["readiness_instance_id"] = str(uuid4())
        with self.assertRaises(generation.DailyGenerationUnavailable):
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertTrue(self.owner.state.attempted)
        self.assertEqual(self.creates(), [])
        self.assertTrue(self.original_scope.closed)
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)

    def test_mutex_wait_consumes_original_readiness_deadline_without_refresh(self):
        self.on_mutex = lambda: setattr(self.clock, "now", self.clock.now + 1000)
        with self.assertRaisesRegex(RuntimeError, "pipe_timeout"):
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.events.count("readiness-enter"), 1)
        self.assertTrue(self.original_scope.closed)
        self.on_mutex = None
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)

    def test_clean_readiness_rejection_drains_without_new_acquisition(self):
        self.acquire_error = generation.DailyGenerationUnavailable("synthetic_clean_readiness_refusal")
        with self.assertRaises(generation.DailyGenerationUnavailable) as raised:
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertIs(raised.exception, self.acquire_error)
        self.assertEqual(self.creates(), [])
        self.assertTrue(self.owner.state.attempted)
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)
        self.assertEqual(self.events.count("readiness-enter"), 1)

    def test_unknown_pre_yield_readiness_cleanup_retains_original_and_blocks_drain(self):
        self.acquire_error = OSError("synthetic original reader close unknown")
        self.acquire_unknown = True
        with self.assertRaises(OSError) as raised:
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertIs(raised.exception, self.acquire_error)
        self.assertIs(self.owner._readiness_error, self.acquire_error)
        self.assertIs(raised.exception.daily_readiness_scope, self.original_scope)
        self.owner.state.seal()
        with self.assertRaises(api.ScopeLaunchError):
            self.owner._drain()
        self.assertFalse(self.owner._local_closed)
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.events.count("readiness-enter"), 1)

    def test_unknown_readiness_exit_after_create_keeps_root_offer_and_blocks_local_close(self):
        self.exit_error = OSError("synthetic original retained readiness peer close unknown")
        with self.assertRaises(OSError) as raised:
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertIs(raised.exception, self.exit_error)
        self.assertIs(self.owner._readiness_scope, self.original_scope)
        self.assertIs(self.owner._readiness_error, self.exit_error)
        self.assertEqual(len(self.creates()), 1)
        self.assertEqual(self.owner._creation_outcome, "created")
        result = self.owner._result(self.incoming())
        self.assertEqual(result["root"]["identity"], launch_fixture.IDENTITY.to_dict())
        self.assertEqual(result["root"]["handle_locator"], launch_fixture.PROCESS_HANDLE)
        self.native.kernel.wait_result = 0
        self.owner.state.seal()
        with self.assertRaises(api.ScopeLaunchError):
            self.owner._drain()
        self.assertFalse(self.owner._local_closed)
        self.assertIsNotNone(self.owner.process.handle)

    def test_native_create_false_is_deferred_until_positive_readiness_exit(self):
        self.native.kernel.create_result = 0
        self.native.kernel.process_info = (0, 0, 0, 0)
        with self.assertRaises(native_launcher.NativeLaunchError):
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertTrue(self.original_scope.closed)
        self.assertEqual(self.readiness_body_errors, [])
        self.assertTrue(self.owner.process.creation_definitely_absent)
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)

    def test_native_setup_expiry_retains_known_not_attempted_process_and_closes_readiness(self):
        original = self.native.kernel.UpdateProcThreadAttribute
        def expire(*args):
            result = original(*args)
            self.clock.now = 2000
            return result
        with patch.object(self.native.kernel, "UpdateProcThreadAttribute", side_effect=expire), \
                self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout"):
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertEqual(self.creates(), [])
        self.assertTrue(self.owner.process.creation_definitely_absent)
        self.assertTrue(self.original_scope.closed)
        self.assertEqual(self.readiness_body_errors, [])
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)

    def test_native_known_cleanup_failure_does_not_poison_clean_readiness(self):
        self.native.kernel.create_result = 0
        self.native.kernel.process_info = (0, 0, 0, 0)
        self.native.kernel.close_failures.add(launch_fixture.STDIO_COPIES[0])
        with self.assertRaises(native_launcher.NativeLaunchError) as raised:
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertIs(raised.exception.native_launch_owner, self.owner.process)
        self.assertTrue(self.owner.process.creation_definitely_absent)
        self.assertTrue(self.original_scope.closed)
        self.assertEqual(self.readiness_body_errors, [])
        self.assertFalse(self.owner._readiness_unsettled())
        self.native.kernel.close_failures.clear()
        self.owner.state.seal()
        self.owner._drain()
        self.assertTrue(self.owner._local_closed)
        self.assertTrue(self.owner.process._closed)

    def test_timing_bindings_reject_changes_to_pinned_command_before_native(self):
        original = wrapper.timing_record(self.command, self.payload)
        self.assertLessEqual(len(original), 4096)
        for key, value in (("scope_id", str(uuid4())), ("job_nonce", uuid4().hex),
                ("job_name", self.payload["job_name"] + "-changed"),
                ("canonical_source", str(self.directory / "changed"))):
            with self.subTest(key=key), self.assertRaises(ValueError):
                wrapper.timing_record(self.command, self.payload | {key: value})
        for key, value in (("generation", str(uuid4())), ("source_digest", "e" * 64)):
            changed = self.payload | {"generation": self.payload["generation"] | {key: value}}
            with self.subTest(key=key), self.assertRaises(ValueError):
                wrapper.timing_record(self.command, changed)
        self.assertEqual(wrapper.timing_record(self.command, self.payload), original)
        self.assertEqual(self.creates(), [])
        self.assertEqual(self.events, [])

    def test_timing_stream_unknown_close_is_retained_and_never_retried(self):
        original_factory = wrapper.tempfile.TemporaryFile
        raw = original_factory(mode="w+b", dir=self.directory)
        self.addCleanup(raw.close)
        error = OSError("synthetic timing stream close unknown")
        class Stream:
            attempts = 0

            def __getattr__(stream, name):
                return getattr(raw, name)

            def close(stream):
                stream.attempts += 1
                raise error
        stream = Stream()
        self.acquire_error = generation.DailyGenerationUnavailable("synthetic_clean_refusal")
        with patch.object(wrapper.tempfile, "TemporaryFile", return_value=stream), \
                self.assertRaises(generation.DailyGenerationUnavailable):
            self.owner._launch(self.incoming(), self.ipc_deadline)
        self.assertIs(self.owner.files[0], stream)
        self.assertTrue(self.original_scope.closed)
        self.owner.state.seal()
        with self.assertRaises(OSError) as raised:
            self.owner._drain()
        self.assertIs(raised.exception, error)
        self.assertFalse(self.owner._local_closed)
        self.assertFalse(raw.closed)
        with self.assertRaises(api.ScopeLaunchError):
            self.owner._drain()
        self.assertEqual(stream.attempts, 1)
        self.assertIs(self.owner.files[0], stream)
        self.assertEqual(self.creates(), [])

    def test_wrong_authenticated_peer_never_reaches_request_or_readiness(self):
        @contextmanager
        def wrong_peer(expected):
            self.assertEqual(expected, self.guardian)
            yield SimpleNamespace(identity=self.wrapper_identity)
        connection = SimpleNamespace(verified_peer=wrong_peer, close=Mock())
        with patch.object(pipe_windows.NativePipeConnection, "connect", return_value=connection), \
                patch.object(NativeDeadline, "after_ms", return_value=self.ipc_deadline), \
                patch("sentinel.adaptive.ipc.read_frame", side_effect=AssertionError("unauthenticated request read")), \
                patch("sentinel.adaptive.ipc.write_frame", side_effect=AssertionError("unauthenticated reply")), \
                self.assertRaisesRegex(api.ScopeLaunchError, "guardian_changed"):
            self.owner.serve_once()
        self.assertEqual(self.creates(), [])
        self.assertNotIn("readiness-enter", self.events)
        self.assertFalse(self.owner.state.attempted)

    def test_authenticated_original_guardian_precedes_readiness_in_serve_once(self):
        test = self
        incoming = self.incoming()
        sent = []
        class Connection:
            @contextmanager
            def verified_peer(connection, expected):
                test.assertEqual(expected, test.guardian)
                test.events.append("authenticated")
                yield SimpleNamespace(identity=test.guardian)
                test.events.append("guardian-peer-closed")

            def close(connection):
                test.events.append("guardian-connection-closed")
        connection = Connection()
        count = 0
        def read(channel, deadline):
            nonlocal count
            count += 1
            return incoming if count == 1 else api.receipt(next(value for value in sent if value["kind"] == "S1ScopeResult"))
        with patch.object(pipe_windows.NativePipeConnection, "connect", return_value=connection), \
                patch.object(NativeDeadline, "after_ms", return_value=self.ipc_deadline), \
                patch("sentinel.adaptive.ipc.read_frame", side_effect=read), \
                patch("sentinel.adaptive.ipc.write_frame", side_effect=lambda channel, value, deadline: sent.append(value)):
            self.assertFalse(self.owner.serve_once())
        self.assertLess(self.events.index("authenticated"), self.events.index("readiness-enter"))
        self.assertLess(self.events.index("readiness-exit"), self.events.index("guardian-peer-closed"))
        self.assertEqual(len(self.creates()), 1)
        self.assertTrue(next(value for value in sent if value["kind"] == "S1ScopeResult")["attempted"])


if __name__ == "__main__":
    unittest.main()
