import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing, contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

from sentinel import queue_cancellation as cancellation


ROOT = Path(__file__).resolve().parents[1]
KEY = "a" * 64
OTHER_KEY = "b" * 64
OWNER = 3000
STARTED = 300.0
CALLER = 4000


@contextmanager
def fixture_connection(db_path):
    with closing(sqlite3.connect(db_path)) as conn:
        with conn:
            yield conn


class FakeProcess:
    def __init__(self, pid, started, parent):
        self.pid, self.started, self.parent = pid, started, parent

    def create_time(self):
        return self.started

    def ppid(self):
        return self.parent


class CallerOwnershipTests(unittest.TestCase):
    def factory(self, nodes):
        def process(pid):
            started, parent = nodes[pid]
            return FakeProcess(pid, started, parent)
        return process

    def check(self, owner, nodes):
        with mock.patch.object(cancellation.os, "getpid", return_value=CALLER):
            return cancellation.caller_owner_started(owner, process_factory=self.factory(nodes))

    def test_caller_can_own_its_request(self):
        self.assertEqual(self.check(CALLER, {CALLER: (400.0, OWNER)}), 400.0)

    def test_real_current_process_identity_can_be_verified(self):
        import os
        import psutil
        self.assertEqual(cancellation.caller_owner_started(os.getpid()), psutil.Process().create_time())

    def test_verified_ancestor_can_own_request(self):
        self.assertEqual(self.check(OWNER, {CALLER: (400.0, OWNER), OWNER: (STARTED, 2000)}), STARTED)

    def test_arbitrary_owner_pid_is_not_authorization(self):
        with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_not_caller_ancestor"):
            self.check(9000, {CALLER: (400.0, OWNER), OWNER: (STARTED, 0)})

    def test_reused_parent_pid_is_rejected(self):
        with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_identity_unverified"):
            self.check(OWNER, {CALLER: (400.0, OWNER), OWNER: (500.0, 2000)})

    def test_inaccessible_process_fails_closed(self):
        with mock.patch.object(cancellation.os, "getpid", return_value=CALLER):
            with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_identity_unverified"):
                cancellation.caller_owner_started(OWNER, process_factory=mock.Mock(side_effect=PermissionError))

    def test_changed_birth_during_second_observation_is_rejected(self):
        calls = {}

        def process(pid):
            calls[pid] = calls.get(pid, 0) + 1
            return FakeProcess(pid, 400.0 + calls[pid] - 1, OWNER)

        with mock.patch.object(cancellation.os, "getpid", return_value=CALLER):
            with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_identity_unverified"):
                cancellation.caller_owner_started(CALLER, process_factory=process)

    def test_changed_parent_edge_is_rejected(self):
        calls = {}

        def process(pid):
            calls[pid] = calls.get(pid, 0) + 1
            if pid == CALLER:
                return FakeProcess(pid, 400.0, OWNER if calls[pid] == 1 else 9999)
            return FakeProcess(pid, STARTED, 0)

        with mock.patch.object(cancellation.os, "getpid", return_value=CALLER):
            with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_identity_unverified"):
                cancellation.caller_owner_started(OWNER, process_factory=process)

    def test_ancestry_walk_is_bounded(self):
        process = mock.Mock(side_effect=lambda pid: FakeProcess(pid, float(pid), pid - 1))
        with mock.patch.object(cancellation.os, "getpid", return_value=CALLER):
            with self.assertRaisesRegex(cancellation.CancellationRejected, "owner_ancestry_limit"):
                cancellation.caller_owner_started(1, process_factory=process)
        self.assertEqual(process.call_count, cancellation.MAX_ANCESTRY)

    def test_invalid_pid_rejected_without_process_query(self):
        process = mock.Mock()
        for pid in (0, -1, True, 2**32):
            with self.subTest(pid=pid), self.assertRaises(cancellation.CancellationRejected):
                cancellation.caller_owner_started(pid, process_factory=process)
        process.assert_not_called()


class QueueCancellationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.data = Path(self.tmp.name)
        self.db = self.data / "sentinel.db"
        with fixture_connection(self.db) as conn:
            conn.execute("CREATE TABLE queue (request_key TEXT PRIMARY KEY, owner_pid INTEGER, owner_started REAL, command_text TEXT)")
            conn.execute("CREATE TABLE reservations (id TEXT PRIMARY KEY, request_key TEXT, owner_pid INTEGER, owner_started REAL)")
            conn.execute("INSERT INTO reservations VALUES ('running', ?, ?, ?)", ("c" * 64, OWNER, STARTED))
        self.exemptions = self.data / "exemptions.sqlite3"
        with fixture_connection(self.exemptions) as conn:
            conn.execute("CREATE TABLE exemptions (id TEXT PRIMARY KEY, root_pid INTEGER)")
            conn.execute("INSERT INTO exemptions VALUES ('unchanged-lease', ?)", (OWNER,))
        self.exemption_bytes = self.exemptions.read_bytes()
        self.add(KEY)

    def tearDown(self):
        self.tmp.cleanup()

    def add(self, key, owner=OWNER, started=STARTED):
        with fixture_connection(self.db) as conn:
            conn.execute("INSERT INTO queue VALUES (?, ?, ?, ?)", (key, owner, started, "private command excluded from output"))

    def rows(self, table):
        with fixture_connection(self.db) as conn:
            return conn.execute("SELECT * FROM " + table + " ORDER BY 1").fetchall()

    def cancel(self, key=KEY, owner=OWNER, started=STARTED):
        with mock.patch.object(cancellation, "caller_owner_started", return_value=started):
            return cancellation.cancel_for_caller(self.data, request_key=key, owner_pid=owner)

    def assert_protected_state(self, before):
        self.assertEqual(self.rows("reservations"), before)
        self.assertEqual(self.exemptions.read_bytes(), self.exemption_bytes)

    def test_cancel_exactly_one_owned_queue_request(self):
        self.add(OTHER_KEY)
        before = self.rows("reservations")
        result = self.cancel()
        self.assertEqual(result, {"ok": True, "cancelled": 1, "reason": "cancelled",
                                  "request_key": KEY, "mirror_refresh": "deferred"})
        self.assertEqual([r[0] for r in self.rows("queue")], [OTHER_KEY])
        self.assert_protected_state(before)

    def test_another_owner_request_is_rejected(self):
        self.add(OTHER_KEY, owner=9999)
        before = self.rows("queue")
        result = self.cancel(OTHER_KEY)
        self.assertFalse(result["ok"])
        self.assertEqual(result["reason"], "queue_owner_mismatch")
        self.assertEqual(self.rows("queue"), before)

    def test_spoofed_cli_owner_is_rejected_before_database_open(self):
        with mock.patch.object(cancellation, "caller_owner_started", side_effect=cancellation.CancellationRejected("owner_not_caller_ancestor")):
            with mock.patch.object(cancellation.sqlite3, "connect") as connect:
                result = cancellation.cancel_for_caller(self.data, request_key=KEY, owner_pid=9999)
        self.assertFalse(result["ok"])
        connect.assert_not_called()

    def test_same_pid_with_different_birth_is_rejected(self):
        result = self.cancel(started=STARTED + .001)
        self.assertEqual(result["reason"], "owner_identity_mismatch")
        self.assertEqual(len(self.rows("queue")), 1)

    def test_unknown_legacy_birth_is_rejected(self):
        with fixture_connection(self.db) as conn:
            conn.execute("UPDATE queue SET owner_started=0 WHERE request_key=?", (KEY,))
        result = self.cancel()
        self.assertEqual(result["reason"], "owner_identity_unknown")
        self.assertEqual(len(self.rows("queue")), 1)

    def test_unavailable_caller_identity_rejects_without_mutation(self):
        before = self.rows("queue")
        with mock.patch.object(cancellation, "caller_owner_started", side_effect=cancellation.CancellationRejected("owner_identity_unverified")):
            result = cancellation.cancel_for_caller(self.data, request_key=KEY, owner_pid=OWNER)
        self.assertEqual(result["reason"], "owner_identity_unverified")
        self.assertEqual(self.rows("queue"), before)

    def test_missing_key_and_repeated_cancel_are_idempotent(self):
        self.assertEqual(self.cancel()["cancelled"], 1)
        for _ in range(2):
            result = self.cancel()
            self.assertTrue(result["ok"])
            self.assertEqual(result["cancelled"], 0)
            self.assertEqual(result["reason"], "not_queued")

    def test_active_reservation_key_never_releases_reservation(self):
        before = self.rows("reservations")
        result = self.cancel("c" * 64)
        self.assertEqual(result["reason"], "not_queued")
        self.assertEqual(result["cancelled"], 0)
        self.assertEqual(len(self.rows("queue")), 1)
        self.assert_protected_state(before)

    def test_owner_race_between_read_and_delete_does_not_cancel_replacement(self):
        actual_delete = cancellation.cancel_queued_row

        def replace_then_delete(db_path, **kwargs):
            with fixture_connection(db_path) as conn:
                conn.execute("UPDATE queue SET owner_started=? WHERE request_key=?", (STARTED + 1, KEY))
            return actual_delete(db_path, **kwargs)

        with mock.patch.object(cancellation, "cancel_queued_row", side_effect=replace_then_delete):
            result = self.cancel()
        self.assertEqual(result["cancelled"], 0)
        self.assertEqual(result["reason"], "not_queued_or_changed")
        self.assertEqual(len(self.rows("queue")), 1)

    def test_admission_race_never_cancels_new_reservation(self):
        actual_delete = cancellation.cancel_queued_row

        def admit_then_delete(db_path, **kwargs):
            with fixture_connection(db_path) as conn:
                conn.execute("DELETE FROM queue WHERE request_key=?", (KEY,))
                conn.execute("INSERT INTO reservations VALUES ('newly-running', ?, ?, ?)", (KEY, OWNER, STARTED))
            return actual_delete(db_path, **kwargs)

        with mock.patch.object(cancellation, "cancel_queued_row", side_effect=admit_then_delete):
            result = self.cancel()
        self.assertEqual(result["cancelled"], 0)
        self.assertEqual(len(self.rows("reservations")), 2)
        self.assertEqual(self.exemptions.read_bytes(), self.exemption_bytes)

    def test_cancel_does_not_initialize_or_migrate_database(self):
        with fixture_connection(self.db) as conn:
            before = conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
        self.assertEqual(self.cancel()["cancelled"], 1)
        with fixture_connection(self.db) as conn:
            after = conn.execute("SELECT type,name,sql FROM sqlite_master ORDER BY name").fetchall()
        self.assertEqual(after, before)

    def test_cancel_does_not_read_private_commands_or_other_tables(self):
        connect = sqlite3.connect

        def restricted_connect(*args, **kwargs):
            conn = connect(*args, **kwargs)

            def authorize(action, table, column, database, source):
                if action == sqlite3.SQLITE_READ and (table != "queue" or column == "command_text"):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            conn.set_authorizer(authorize)
            return conn

        with mock.patch.object(cancellation.sqlite3, "connect", side_effect=restricted_connect):
            result = self.cancel()
        self.assertEqual(result["cancelled"], 1)

    def test_database_disappearing_before_delete_is_not_recreated(self):
        actual_delete = cancellation.cancel_queued_row

        def remove_then_delete(db_path, **kwargs):
            Path(db_path).unlink()
            return actual_delete(db_path, **kwargs)

        with mock.patch.object(cancellation, "cancel_queued_row", side_effect=remove_then_delete):
            result = self.cancel()
        self.assertEqual(result["reason"], "queue_unavailable")
        self.assertFalse(self.db.exists())

    def test_missing_data_directory_is_not_created(self):
        missing = self.data / "missing-directory"
        with mock.patch.object(cancellation, "caller_owner_started", return_value=STARTED):
            result = cancellation.cancel_for_caller(missing, request_key=KEY, owner_pid=OWNER)
        self.assertEqual(result["reason"], "queue_unavailable")
        self.assertFalse(missing.exists())

    def test_invalid_key_is_rejected_without_identity_or_database_query(self):
        with mock.patch.object(cancellation, "caller_owner_started") as identity:
            result = cancellation.cancel_for_caller(self.data, request_key="", owner_pid=OWNER)
        self.assertEqual(result["reason"], "invalid_request_key")
        identity.assert_not_called()

    def test_cli_cancel_takes_narrow_path_without_coordinator_or_exemptions(self):
        spec = importlib.util.spec_from_file_location("sentinelctl_cancel_test", ROOT / "scripts" / "sentinelctl.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        out = io.StringIO()
        args = ["sentinelctl.py", "--data-dir", str(self.data), "cancel", "--request-key", KEY, "--owner-pid", str(OWNER)]
        with mock.patch.object(sys, "argv", args), redirect_stdout(out):
            with mock.patch.object(cancellation, "caller_owner_started", return_value=STARTED):
                with mock.patch.object(cli, "Coordinator") as coord, mock.patch.object(cli, "Exemptions") as exemptions:
                    self.assertEqual(cli.main(), 0)
        self.assertEqual(json.loads(out.getvalue())["cancelled"], 1)
        self.assertNotIn("private command", out.getvalue())
        coord.assert_not_called()
        exemptions.assert_not_called()

    def test_cli_spoofed_owner_exits_rejected_without_constructing_stores(self):
        spec = importlib.util.spec_from_file_location("sentinelctl_cancel_rejected_test", ROOT / "scripts" / "sentinelctl.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        out = io.StringIO()
        args = ["sentinelctl.py", "--data-dir", str(self.data), "cancel", "--request-key", KEY, "--owner-pid", "9999"]
        with mock.patch.object(sys, "argv", args), redirect_stdout(out):
            with mock.patch.object(cancellation, "caller_owner_started", side_effect=cancellation.CancellationRejected("owner_not_caller_ancestor")):
                with mock.patch.object(cli, "Coordinator") as coord, mock.patch.object(cli, "Exemptions") as exemptions:
                    self.assertEqual(cli.main(), 2)
        self.assertFalse(json.loads(out.getvalue())["ok"])
        self.assertEqual(len(self.rows("queue")), 1)
        coord.assert_not_called()
        exemptions.assert_not_called()

    def test_real_child_cli_cancels_request_owned_by_test_runner(self):
        import psutil
        with fixture_connection(self.db) as conn:
            conn.execute("UPDATE queue SET owner_pid=?,owner_started=? WHERE request_key=?",
                         (os.getpid(), psutil.Process().create_time(), KEY))
        before = self.rows("reservations")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sentinelctl.py"), "--data-dir", str(self.data),
             "cancel", "--request-key", KEY, "--owner-pid", str(os.getpid())],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["cancelled"], 1)
        self.assertNotIn("private command", result.stdout + result.stderr)
        self.assertEqual(self.rows("queue"), [])
        self.assert_protected_state(before)

    def test_real_cli_cannot_assert_another_owner_pid(self):
        other_owner = 0x7FFFFFFF
        self.add(OTHER_KEY, owner=other_owner)
        before = self.rows("queue")
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "sentinelctl.py"), "--data-dir", str(self.data),
             "cancel", "--request-key", OTHER_KEY, "--owner-pid", str(other_owner)],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(json.loads(result.stdout)["ok"])
        self.assertNotIn("private command", result.stdout + result.stderr)
        self.assertEqual(self.rows("queue"), before)


if __name__ == "__main__":
    unittest.main()
