"""Display-only fixture tests: no real sessions, leases, or native mutations."""
import json
import importlib.util
import math
import sqlite3
import tempfile
import unittest
from contextlib import closing, contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sentinel.lease_display import (FILETIME_UNIX_EPOCH, MAX_SESSION_REGISTRY_BYTES,
                                  claude_session_metadata, legacy_psutil_epoch, native_process_identity)
from sentinel.lease_display import exemption_leases


class ClaudeSessionAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home / 'sessions').mkdir()
        self.pid = 4242
        self.filetime = 134342000123456789  # synthetic; never a real session ID
        self.started = float(self.filetime - FILETIME_UNIX_EPOCH) / 10000000.0
        self.file = self.home / 'sessions' / f'{self.pid}.json'
        self.record = dict(pid=self.pid, procStart=str(self.filetime), name='Fixture task',
                           sessionId='fixture-session', cwd='C:/private/project-name',
                           unknown_private_field='MUST NOT BE PUBLISHED')
        self.write_record()
        self.held = False
        self.identity_reads = 0

    def write_record(self, **changes):
        self.file.write_text(json.dumps(dict(self.record, **changes)), encoding='utf-8')

    @contextmanager
    def identity(self, pid):
        self.assertEqual(pid, self.pid)
        self.assertFalse(self.held)
        self.held = True
        try:
            def read():
                self.assertTrue(self.held)
                self.identity_reads += 1
                return self.filetime
            yield read
        finally:
            self.held = False

    def resolve(self, **kwargs):
        return claude_session_metadata(kwargs.pop('pid', self.pid), kwargs.pop('started', self.started),
                                       home=self.home, process_identity=kwargs.pop('process_identity', self.identity),
                                       **kwargs)

    def test_exact_identity_enriches_labels_only_and_holds_handle_during_read(self):
        original = self.file.read_bytes()
        original_open = Path.open
        def checked_open(path, *args, **kwargs):
            self.assertTrue(self.held)
            self.assertEqual(path, self.file)
            return original_open(path, *args, **kwargs)
        with patch.object(Path, 'open', checked_open):
            result = self.resolve()
        self.assertEqual(result, dict(session_name='Fixture task', session_id='fixture-session', agent='Claude',
                                      project='project-name', attribution_source='claude_session_registry'))
        self.assertEqual(self.identity_reads, 2)
        self.assertFalse(self.held)
        self.assertEqual(original, self.file.read_bytes())
        self.assertNotIn('private', json.dumps(result))

    def test_legacy_conversion_matches_psutil7_operation_order(self):
        self.assertEqual(legacy_psutil_epoch(self.filetime), self.started)
        # Converting the whole 1601 epoch count to double first loses more bits.
        wrong_order = float(self.filetime) / 10000000.0 - 11644473600.0
        self.assertNotEqual(wrong_order, self.started)
        self.assertEqual(self.resolve(started=wrong_order), {})

    def test_lease_timestamp_has_no_epsilon_match(self):
        for started in (math.nextafter(self.started, math.inf), self.started + .001,
                        self.started - 1, math.nan, math.inf, -1, True, str(self.started)):
            with self.subTest(started=started):
                self.assertEqual(self.resolve(started=started), {})

    def test_bad_pid_and_path_traversal_never_open_process_or_registry(self):
        probe = Mock(side_effect=AssertionError('must not inspect an invalid PID'))
        for pid in ('../secrets', '../4242', '4242', 0, -1, 2**32, 4242.0, True, None):
            with self.subTest(pid=pid):
                self.assertEqual(self.resolve(pid=pid, process_identity=probe), {})
        probe.assert_not_called()

    def test_registry_pid_or_birth_mismatch_and_malformed_identity_reject(self):
        for changes in (dict(pid=4243), dict(pid=True), dict(pid='4242'),
                        dict(procStart=str(self.filetime + 1)), dict(procStart=float(self.filetime)),
                        dict(procStart=True), dict(procStart='1e17'), dict(procStart='１２３'),
                        dict(procStart=str(2**64)), dict(procStart='9' * 100)):
            with self.subTest(changes=changes):
                self.write_record(**changes)
                self.assertEqual(self.resolve(), {})

    def test_missing_exact_file_does_not_search_other_sessions(self):
        self.file.rename(self.home / 'sessions' / '4243.json')
        with patch.object(Path, 'glob', side_effect=AssertionError('no scan')), \
                patch.object(Path, 'iterdir', side_effect=AssertionError('no scan')):
            self.assertEqual(self.resolve(), {})

    def test_oversize_file_is_not_opened(self):
        self.file.write_bytes(b' ' * (MAX_SESSION_REGISTRY_BYTES + 1))
        with patch.object(Path, 'open', side_effect=AssertionError('oversize registry must not be read')):
            self.assertEqual(self.resolve(), {})

    def test_malformed_registry_is_unrecorded(self):
        for raw in (b'not json', b'[]', b'null', b'\xff',
                    b'{"pid":4242,"pid":4242}', b'[' * 1100 + b']' * 1100):
            with self.subTest(raw=raw[:30]):
                self.file.write_bytes(raw)
                self.assertEqual(self.resolve(), {})

    def test_incomplete_or_oversize_labels_reject(self):
        for changes in (dict(name=''), dict(name=None), dict(name='a'*1001),
                        dict(sessionId=''), dict(sessionId=42), dict(sessionId='a'*161)):
            with self.subTest(changes=changes):
                self.write_record(**changes)
                self.assertEqual(self.resolve(), {})

    def test_directory_redirection_rejects_without_reading(self):
        real_resolve = Path.resolve
        def redirected(path, **kwargs):
            if path == self.home / 'sessions':
                return self.home / 'elsewhere'
            return real_resolve(path, **kwargs)
        with patch.object(Path, 'resolve', redirected), \
                patch.object(Path, 'open', side_effect=AssertionError('no redirected read')):
            self.assertEqual(self.resolve(), {})

    def test_unknown_process_identity_never_reads_registry(self):
        @contextmanager
        def unavailable(pid):
            yield lambda: None
        with patch.object(Path, 'open', side_effect=AssertionError('no unverified read')):
            self.assertEqual(self.resolve(process_identity=unavailable), {})

    def test_exit_during_read_rejects_and_closes_scope(self):
        @contextmanager
        def exited(pid):
            read = Mock(side_effect=[self.filetime, None])
            yield read
            self.assertEqual(read.call_count, 2)
        self.assertEqual(self.resolve(process_identity=exited), {})

    def test_access_denied_keeps_attribution_unrecorded(self):
        @contextmanager
        def denied(pid):
            raise PermissionError('fixture access denied')
            yield  # pragma: no cover
        self.assertEqual(self.resolve(process_identity=denied), {})


class NativeIdentityContractTests(unittest.TestCase):
    def kernel(self):
        native = SimpleNamespace(OpenProcess=Mock(return_value=0x123456789),
                                 GetProcessId=Mock(return_value=4242),
                                 GetProcessTimes=Mock(return_value=True),
                                 WaitForSingleObject=Mock(return_value=258), CloseHandle=Mock())
        def process_times(handle, created, exited, system, user):
            value = 134342000123456789
            created._obj.dwHighDateTime = value >> 32
            created._obj.dwLowDateTime = value & 0xffffffff
            return True
        native.GetProcessTimes.side_effect = process_times
        return native

    def test_same_pointer_sized_handle_is_queried_twice_and_always_closed(self):
        native = self.kernel()
        with patch('sentinel.lease_display.os.name', 'nt'), \
                patch('ctypes.WinDLL', return_value=native, create=True):
            with self.assertRaisesRegex(RuntimeError, 'fixture'):
                with native_process_identity(4242) as identity:
                    self.assertEqual(identity(), 134342000123456789)
                    self.assertEqual(identity(), 134342000123456789)
                    native.CloseHandle.assert_not_called()
                    raise RuntimeError('fixture')
        native.OpenProcess.assert_called_once_with(0x101000, False, 4242)
        native.CloseHandle.assert_called_once_with(0x123456789)
        self.assertTrue(all(call.args[0] == 0x123456789 for call in native.GetProcessTimes.call_args_list))

    def test_wait_failure_exit_or_pid_mismatch_never_returns_identity(self):
        for wait, pid in ((0,4242), (0xffffffff,4242), (258,9999)):
            native = self.kernel()
            native.WaitForSingleObject.return_value = wait
            native.GetProcessId.return_value = pid
            with self.subTest(wait=wait, pid=pid), patch('sentinel.lease_display.os.name', 'nt'), \
                    patch('ctypes.WinDLL', return_value=native, create=True):
                with native_process_identity(4242) as identity:
                    self.assertIsNone(identity())
            native.GetProcessTimes.assert_not_called()
            native.CloseHandle.assert_called_once_with(0x123456789)

    def test_open_failure_has_no_handle_to_close(self):
        native = self.kernel()
        native.OpenProcess.return_value = 0
        with patch('sentinel.lease_display.os.name', 'nt'), \
                patch('ctypes.WinDLL', return_value=native, create=True):
            with native_process_identity(4242) as identity:
                self.assertIsNone(identity())
        native.CloseHandle.assert_not_called()


class LeaseDisplayEnrichmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.database = self.path / 'exemptions.sqlite3'
        self.now = 1000.
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            conn.execute('''CREATE TABLE exemptions (id TEXT,root_pid INTEGER,root_started REAL,
                created_at REAL,expires_at REAL,revoked_at REAL,owner_metadata TEXT)''')

    def insert(self, key, *, expires=2000., revoked=None, metadata=None):
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            conn.execute('INSERT INTO exemptions VALUES (?,?,?,?,?,?,?)',
                         (str(key), key, 100., self.now, expires, revoked, json.dumps(metadata or {})))

    def test_enrichment_preserves_occupancy_deadlines_and_database_bytes(self):
        self.insert(1)
        self.insert(2, expires=900.)
        self.insert(3, revoked=950.)
        self.insert(4, metadata=dict(session_name='Recorded task', agent='Codex'))
        before = self.database.read_bytes()
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}) as probe:
            original = exemption_leases(self.path, {1:100., 2:100., 3:100., 4:100.}, self.now, limit=3)
            probe.assert_called_once_with(1, 100.)
        with patch('sentinel.lease_display.claude_session_metadata', return_value=dict(
                session_name='Fixture Claude task', agent='Claude', attribution_source='claude_session_registry')) as probe:
            result = exemption_leases(self.path, {1:100., 2:100., 3:100., 4:100.}, self.now, limit=3)
            probe.assert_called_once_with(1, 100.)
        self.assertEqual(result['occupied'], 2)
        self.assertEqual(result['next_expiry'], original['next_expiry'])
        self.assertEqual(result['limit'], 3)
        for old, row in zip(original['leases'], result['leases']):
            for key in ('id','root_pid','root_started','created_at','expires_at','revoked_at','state','occupies_slot'):
                self.assertEqual(old[key], row[key])
        recorded = next(row for row in result['leases'] if row['id']=='4')
        self.assertEqual(recorded['session_name'], 'Recorded task')
        self.assertEqual(before, self.database.read_bytes())

    def test_corrupt_overlimit_database_still_bounds_lookup_to_three(self):
        for key in range(1, 7):
            self.insert(key)
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}) as probe:
            result = exemption_leases(self.path, None, self.now, limit=3)
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(result['occupied'], 6)  # do not hide corrupt accounting
        self.assertEqual(result['state'], 'unknown')
        self.assertTrue(all(row['attribution_source']=='unrecorded' for row in result['leases']))

    def test_unspecified_policy_limit_stays_unknown_and_missing_db_is_not_created(self):
        self.insert(1)
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}):
            result = exemption_leases(self.path, {1:100.}, self.now)
        self.assertIsNone(result['limit'])
        missing = self.path / 'absent'
        result = exemption_leases(missing, None, self.now)
        self.assertEqual(result['occupied'], 0)
        self.assertIsNone(result['limit'])
        self.assertFalse(missing.exists())

    def test_old_schema_without_metadata_remains_read_only(self):
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            conn.execute('DROP TABLE exemptions')
            conn.execute('''CREATE TABLE exemptions (id TEXT, root_pid INTEGER, root_started REAL,
                created_at REAL, expires_at REAL, revoked_at REAL)''')
            conn.execute('INSERT INTO exemptions VALUES (?,?,?,?,?,?)', ('old', 42, 100., 900., 2000., None))
        before = self.database.read_bytes()
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}) as lookup:
            result = exemption_leases(self.path, None, self.now)
        lookup.assert_called_once_with(42, 100.)
        self.assertEqual(result['occupied'], 1)
        self.assertEqual(before, self.database.read_bytes())

    def test_row_limit_rejects_incomplete_counts(self):
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            conn.executemany('INSERT INTO exemptions VALUES (?,?,?,?,?,?,?)',
                [(str(i), i, 100., 900., 2000., None, '{}') for i in range(1, 502)])
        with self.assertRaisesRegex(ValueError, 'observation_row_limit'):
            exemption_leases(self.path, None, self.now)

    def test_missing_pid_does_not_prove_exit_or_release_a_newer_lease(self):
        self.insert(1)
        before = self.database.read_bytes()
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}):
            result = exemption_leases(self.path, {}, self.now)
        self.assertEqual(result['leases'][0]['state'], 'identity_unknown')
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['occupied'], 1)
        self.assertEqual(result['next_expiry'], 2000.)
        self.assertTrue(result['leases'][0]['occupies_slot'])
        self.assertEqual(before, self.database.read_bytes())

    def test_observed_different_birth_is_mismatch_not_positive_exit_evidence(self):
        self.insert(1)
        with patch('sentinel.lease_display.claude_session_metadata', return_value={}):
            result = exemption_leases(self.path, {1:500.}, self.now)
        self.assertEqual(result['leases'][0]['state'], 'identity_mismatch')
        self.assertEqual(result['state'], 'unknown')
        self.assertEqual(result['occupied'], 1)
        self.assertTrue(result['leases'][0]['occupies_slot'])


class SnapshotProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'exemption-snapshot.py'
        spec = importlib.util.spec_from_file_location('exemption_snapshot_fixture', script)
        cls.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.probe)

    def test_absent_constant_is_unknown_not_an_invented_policy(self):
        from sentinel import exemptions
        with patch.object(exemptions, 'MAX_CONCURRENT_EXEMPTIONS', None, create=True):
            self.assertIsNone(self.probe.installed_limit())

    def test_unknown_database_is_not_reported_as_empty(self):
        with tempfile.TemporaryDirectory() as temp:
            database = Path(temp) / 'exemptions.sqlite3'
            database.write_bytes(b'not a database')
            before = database.read_bytes()
            with patch.object(self.probe, 'installed_limit', return_value=None):
                result = self.probe.snapshot(temp, now=1000.)
            self.assertEqual(result['exemptions']['state'], 'unknown')
            self.assertIsNone(result['exemptions']['occupied'])
            self.assertEqual(result['limit_source'], 'unavailable')
            self.assertEqual(before, database.read_bytes())

    def test_missing_stale_and_duplicate_identities_are_unknown(self):
        self.assertIsNone(self.probe.read_identities(None, 1000.))
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / 'processes.json'
            for value in (
                dict(sampled_epoch=900., processes=[]),
                dict(sampled_epoch=900., sample_completed_epoch=999., processes=[dict(pid=1, create_time=100.)]),
                dict(sampled_epoch=1000., processes=[dict(pid=1, create_time=100.)] * 2),
                dict(sampled_epoch=1000., processes=[dict(pid=True, create_time=100.)]),
            ):
                source.write_text(json.dumps(value), encoding='utf-8')
                self.assertIsNone(self.probe.read_identities(source, 1000.))
            source.write_text(json.dumps(dict(sampled_epoch=1000., processes=[dict(pid=1, create_time=100.)])), encoding='utf-8')
            self.assertEqual(self.probe.read_identities(source, 1000.), {1:100.})


if __name__ == '__main__':
    unittest.main()
