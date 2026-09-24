"""Portable history data validation; synthetic closed tuples are not native proof.

Admission rows come from the actual managed-admission fixture. Historical data
is assembled in a separate in-memory database before its canonical guards are
installed. No original daily guard is removed or release capability fabricated.
"""
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sqlite3
import unittest
from uuid import uuid4

from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import experiment_exclusion as exclusion_module
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive.contracts import ProcessIdentity
from tests import test_adaptive_experiment_demand as demand_tests


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def insert(conn, table, row):
    conn.execute("INSERT INTO " + table + "(" + ",".join(row) + ") VALUES(" +
        ",".join("?" for _ in row) + ")", tuple(row.values()))


class ExperimentHistoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = demand_tests.ExperimentDemandTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.owner = self.fixture.capture()
        result = self.fixture.coordinator.admit_experiment(self.owner)
        self.assertTrue(result["allowed"])
        completion = self.owner.seal_without_native()
        self.completion = completion.snapshot()
        self.completion_digest = completion.digest
        source = self.fixture.fixture.conn()
        self.schemas = {row[0]: row[1] for row in source.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        self.managed = dict(source.execute("SELECT * FROM managed_executions").fetchone())
        self.allocation = dict(source.execute("SELECT * FROM reservations").fetchone())
        self.metadata = dict(source.execute("SELECT * FROM " + demand_module.TABLE).fetchone())
        self.runtime = dict(source.execute("SELECT * FROM adaptive_runtime").fetchone())
        self.record = self.make_record()

    def make_record(self):
        now = float(self.allocation["created_at"] + 10)
        pre = dict(managed=history.managed_image(self.managed), allocation=dict(self.allocation),
            queue=None, exclusion=None, registry_revision=self.runtime["registry_revision"])
        post = dict(managed=history.cancellation_image(pre["managed"], now),
            archive=history.archive_image(self.allocation, now), exclusion=None,
            registry_revision=pre["registry_revision"] + 1)
        return self.rehash(dict(schema_version=1, receipt_id=str(uuid4()), operation_id=str(uuid4()),
            experiment_id=self.metadata["experiment_id"], execution_id=self.metadata["execution_id"],
            reservation_id=self.metadata["reservation_id"], request_key=self.metadata["request_key"],
            suite=self.metadata["suite"], disposition="BEFORE_NATIVE",
            demand_binding_sha256=self.metadata["binding_sha256"], completion_digest=self.completion_digest,
            completion=deepcopy(self.completion), policy=dict(instance_id=self.runtime["policy_instance_id"],
                logon_id=self.runtime["policy_logon_id"]), transaction_time=now,
            preimage=pre, postimage=post))

    def rehash(self, record):
        record["completion_digest"] = hashlib.sha256((
            ("experiment-before-native-v1\n" if record["disposition"] == "BEFORE_NATIVE" else "") +
            canonical(record["completion"])).encode()).hexdigest()
        record["cleanup_digest"] = history.cleanup_digest(receipt_id=record["receipt_id"],
            operation_id=record["operation_id"], reservation_id=record["reservation_id"],
            demand_binding_sha256=record["demand_binding_sha256"], completion_digest=record["completion_digest"],
            demand=record["completion"]["demand"])
        if record["postimage"]["exclusion"] is not None:
            record["postimage"]["exclusion"]["cleanup_digest"] = record["cleanup_digest"]
        for kind in ("preimage", "postimage"):
            record[kind + "_sha256"] = history.image_digest(kind, record[kind])
        return record

    def native_record(self, disposition):
        record = deepcopy(self.record)
        original = record["completion"]["demand"]
        scope_id, nonce = str(uuid4()), uuid4().hex
        guardian = ProcessIdentity.from_dict(original["caller_identity"])
        wrapper = ProcessIdentity(guardian.pid + 1, guardian.created_filetime_100ns + 1, guardian.logon_id)
        path = str(Path(original["scope_directory"]) / "isolated.db")
        common = dict(schema_version=1, disposition=disposition, demand=original, scope_id=scope_id,
            isolated_ledger_path=path, deadline_monotonic_ns=123000000,
            reservation_id=record["reservation_id"], daily_binding_sha256=record["demand_binding_sha256"],
            acquisitions=dict(store="returned", launch="returned", mutex="returned", job="returned"))
        if disposition in {"PREPARATION_CLOSED", "WRAPPER_NOT_CREATED"}:
            binding = dict(experiment_id=record["experiment_id"], scope_id=scope_id,
                job_name="Local\\ResourceSentinel.Test.Job." + nonce, creation_nonce=nonce,
                guardian_identity=guardian.to_dict(), command_sha256=original["scope_sha256"],
                isolated_ledger_identity=[9, 77], wrapper_creation="never_created")
            if disposition == "PREPARATION_CLOSED":
                common["acquisitions"]["job"] = "failed_retained"
                terminal = dict(state=disposition, scope_id=scope_id, launch_sealed=True,
                    wrapper_created=False, job_factory="failed_retained")
            else:
                terminal = dict(state=disposition, scope_id=scope_id, launch_sealed=True,
                    root=None, total_processes=0, root_exit_code=None, cpu_flags=0, pending_intents=0)
        else:
            binding = exclusion_module.ExperimentExclusionBinding(experiment_id=record["experiment_id"],
                daily_execution_id=record["execution_id"], reservation_id=record["reservation_id"],
                source_generation=original["generation"]["generation"], scope_execution_id=scope_id,
                isolated_ledger_path=path, isolated_ledger_identity=(9, 77),
                isolated_policy_instance_id=str(uuid4()), job_name="Local\\ResourceSentinel.Test.Job." + nonce,
                creation_nonce=nonce, logon_id=guardian.logon_id, guardian_identity=guardian,
                wrapper_identity=wrapper)._values()
            exclusion = binding | dict(phase="REGISTERED", cleanup_digest=None, registered_revision=1,
                binding_sha256=hashlib.sha256(canonical(binding).encode()).hexdigest())
            record["preimage"]["exclusion"] = exclusion
            record["postimage"]["exclusion"] = exclusion | dict(phase="CLOSED", cleanup_digest="0" * 64)
            journal_binding = dict(schema_version=1, experiment_id=record["experiment_id"], scope_id=scope_id,
                daily_execution_id=record["execution_id"], reservation_id=record["reservation_id"],
                isolated_ledger_identity=[9, 77], job_name=binding["job_name"], creation_nonce=nonce,
                guardian_identity=guardian.to_dict(), wrapper_identity=wrapper.to_dict(),
                command_sha256=original["scope_sha256"], source_generation=original["generation"]["generation"],
                source_digest=original["generation"]["source_digest"], config_digest=original["generation"]["config_digest"],
                deadline_monotonic_ns=common["deadline_monotonic_ns"])
            terminal = journal_binding | dict(binding_sha256=hashlib.sha256(canonical(journal_binding).encode()).hexdigest(),
                state=disposition, revision=4, launch_sealed=1, root=None, last_applied_cpu=None,
                pending_target_cpu=None, root_exit_code=None, total_processes=0, original_cpu=dict(flags=0, rate_bp=0))
            if disposition == "FINISHED":
                terminal.update(root=ProcessIdentity(wrapper.pid + 1, wrapper.created_filetime_100ns + 1,
                    wrapper.logon_id).to_dict(), root_exit_code=0, total_processes=1)
        record["disposition"] = disposition
        record["completion"] = common | dict(binding=binding, terminal=terminal)
        return self.rehash(record)

    def database(self, record=None, *, active=False, mutate=None, missing_guard=None):
        record = deepcopy(self.record if record is None else record)
        conn = sqlite3.connect(":memory:", isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        for sql in self.schemas.values():
            conn.execute(sql)
        if exclusion_module.TABLE not in self.schemas:
            conn.execute(exclusion_module._SCHEMA)
        if history.TABLE not in self.schemas:
            conn.execute(history.TABLE_SQL)
        runtime = self.runtime | {"registry_revision": record["postimage"]["registry_revision"]}
        insert(conn, "adaptive_runtime", runtime)
        insert(conn, demand_module.TABLE, self.metadata)
        row = dict(self.managed)
        if active:
            insert(conn, "reservations", self.allocation)
        else:
            row.update({key: value for key, value in record["postimage"]["managed"].items()
                if not key.endswith("_sha256")})
            row["claim_token_hash"] = ""
            insert(conn, "executions", record["postimage"]["archive"])
            encoded = canonical(record)
            columns = {key: record[key] for key in history.FIELDS if key not in {"receipt_json", "receipt_sha256"}}
            columns.update(receipt_json=encoded, receipt_sha256=hashlib.sha256(
                ("experiment-cleanup-receipt-v1\n" + encoded).encode()).hexdigest())
            insert(conn, history.TABLE, columns)
        insert(conn, "managed_executions", row)
        exclusion = record["preimage" if active else "postimage"]["exclusion"]
        if exclusion is not None:
            insert(conn, exclusion_module.TABLE, exclusion)
        if mutate is not None:
            mutate(conn)
        for guards in (demand_module._TRIGGER_SQL, exclusion_module._GUARDS, history.TRIGGER_SQL):
            for name, sql in guards.items():
                if name != missing_guard:
                    conn.execute(sql)
        conn.execute("BEGIN")
        return conn

    def add_synthetic_active(self, conn):
        """Additional data fixture only; no HMAC/native/publication authority."""
        demand = deepcopy(self.completion["demand"])
        demand.update(experiment_id=str(uuid4()), execution_id=str(uuid4()),
            spec_hash=hashlib.sha256(uuid4().bytes).hexdigest(),
            admission_binding_hash=hashlib.sha256(uuid4().bytes).hexdigest())
        allocation = self.allocation | dict(id=uuid4().hex, execution_id=demand["execution_id"],
            tool_use_id="managed-v1:" + demand["execution_id"], managed_spec_hash=demand["spec_hash"],
            command_signature=demand["spec_hash"][:20])
        key = f"{allocation['owner_pid']}:{allocation['owner_started']:.3f}:{allocation['repo']}:{allocation['tool_use_id']}"
        demand["request_key"] = allocation["request_key"] = hashlib.sha256(key.encode()).hexdigest()
        values = {key: allocation[key] for key in ("repo", "command_signature", "resource_class", "priority",
            "cpu_units", "ram_gib", "io_slots", "commit_bytes")}
        allocation["spec_hash"] = hashlib.sha256(canonical(values).encode()).hexdigest()
        metadata = history._metadata(demand, allocation["id"])
        managed = self.managed | dict(execution_id=demand["execution_id"], reservation_id=allocation["id"],
            task_id="synthetic-" + uuid4().hex, spec_hash=demand["spec_hash"],
            admission_binding_hash=demand["admission_binding_hash"])
        for table, row in ((demand_module.TABLE, metadata), ("managed_executions", managed), ("reservations", allocation)):
            insert(conn, table, row)
        conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        return demand["experiment_id"]

    def test_exact_before_native_tuple_is_read_only_immutable_data(self):
        conn = self.database()
        writes = conn.total_changes
        observation = history.verify_experiment_history_locked(conn)
        self.assertEqual(observation.completed_execution_ids, frozenset({self.metadata["execution_id"]}))
        self.assertEqual(observation.active_experiment_ids, frozenset())
        self.assertGreater(observation.bytes_used, len(observation.receipts_json[0]))
        self.assertGreater(observation.rows_used, 3)
        self.assertEqual(conn.total_changes, writes)
        with self.assertRaises(FrozenInstanceError):
            observation.bytes_used = 0
        copied = json.loads(observation.receipts_json[0])
        copied["completion"]["demand"]["generation_binding"]["readiness_instance_id"] = str(uuid4())
        self.assertEqual(history.verify_experiment_history_locked(conn), observation)

    def test_each_native_completion_disposition_requires_its_exact_tuple(self):
        for kind in sorted(history.DISPOSITIONS - {"BEFORE_NATIVE"}):
            with self.subTest(disposition=kind):
                record = self.native_record(kind)
                encoded, digest = history.canonical_receipt(record)
                result = history.verify_experiment_history_locked(self.database(record))
                self.assertEqual(result.receipts_json, (encoded,))
                self.assertEqual(len(digest), 64)

    def test_preparation_closed_before_daily_coverage_accepts_only_two_nulls(self):
        record = self.native_record("PREPARATION_CLOSED")
        record["completion"].update(reservation_id=None, daily_binding_sha256=None)
        history.canonical_receipt(self.rehash(record))
        record["completion"]["daily_binding_sha256"] = self.metadata["binding_sha256"]
        with self.assertRaises(history.ExperimentHistoryError):
            history.canonical_receipt(self.rehash(record))

    def test_active_original_retains_the_one_scope_obligation(self):
        result = history.verify_experiment_history_locked(self.database(active=True))
        self.assertEqual(result.active_experiment_ids, frozenset({self.metadata["experiment_id"]}))
        self.assertFalse(result.completed_execution_ids)

    def test_completed_history_and_one_later_active_obligation_are_partitioned(self):
        ids = []
        conn = self.database(self.native_record("FINISHED"), mutate=lambda conn:
            ids.append(self.add_synthetic_active(conn)))
        result = history.verify_experiment_history_locked(conn)
        self.assertEqual(result.completed_execution_ids, frozenset({self.metadata["execution_id"]}))
        self.assertEqual(result.active_experiment_ids, frozenset(ids))
        self.assertEqual(len(result.exclusions_json), 1)
        self.assertEqual(json.loads(result.exclusions_json[0])["phase"], "CLOSED")

    def test_two_unresolved_experiments_are_not_freed_by_history(self):
        with self.assertRaisesRegex(history.ExperimentHistoryError, "active_scope_bound"):
            history.verify_experiment_history_locked(self.database(active=True, mutate=self.add_synthetic_active))

    def test_receipt_requires_transaction_and_never_installs_schema(self):
        conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(conn.close)
        with self.assertRaisesRegex(history.ExperimentHistoryError, "transaction_required"):
            history.schema_locked(conn)
        conn.execute("BEGIN")
        self.assertFalse(history.schema_locked(conn))
        with self.assertRaisesRegex(history.ExperimentHistoryError, "original_schema_installer_required"):
            history.schema_locked(conn, create=True)
        self.assertEqual(conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)

    def test_data_digest_cannot_insert_update_or_delete_receipts(self):
        conn = self.database()
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("INSERT INTO " + history.TABLE + " SELECT * FROM " + history.TABLE)
        for statement in ("UPDATE " + history.TABLE + " SET disposition=disposition", "DELETE FROM " + history.TABLE):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "history_immutable"):
                conn.execute(statement)

    def test_unknown_fields_boolean_integer_and_partial_generation_refused(self):
        variants = []
        for field, value in (("unexpected", None), ("schema_version", True)):
            changed = deepcopy(self.record)
            changed[field] = value
            variants.append(changed)
        changed = deepcopy(self.record)
        changed["preimage"]["managed"]["claim_consumed"] = False
        variants.append(changed)
        changed = deepcopy(self.record)
        del changed["completion"]["demand"]["generation_binding"]["readiness_instance_id"]
        variants.append(changed)
        for record in variants:
            with self.subTest(keys=list(record)), self.assertRaises(history.ExperimentHistoryError):
                history.canonical_receipt(record)

    def test_correct_hashes_cannot_authorize_arbitrary_terminal_postimage(self):
        for key, value in (("finished_at", self.record["transaction_time"] + 1), ("floor_io_slots", 1),
                ("state_revision", self.managed["state_revision"] + 2), ("claim_consumed", 0)):
            record = deepcopy(self.record)
            record["postimage"]["managed"][key] = value
            with self.subTest(field=key), self.assertRaisesRegex(history.ExperimentHistoryError, "postimage_invalid"):
                history.canonical_receipt(self.rehash(record))

    def test_wrong_archive_missing_archive_or_duplicate_archive_refused(self):
        mutations = (
            lambda conn: conn.execute("DELETE FROM executions"),
            lambda conn: conn.execute("UPDATE executions SET outcome='managed_finished'"),
            lambda conn: insert(conn, "executions", self.record["postimage"]["archive"]),
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(self.database(mutate=mutate))

    def test_no_receipt_or_metadata_or_changed_terminal_row_cannot_resolve(self):
        for table in (history.TABLE, demand_module.TABLE):
            with self.subTest(table=table), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(self.database(
                    mutate=lambda conn: conn.execute("DELETE FROM " + table)))
        with self.assertRaises(history.ExperimentHistoryError):
            history.verify_experiment_history_locked(self.database(mutate=lambda conn:
                conn.execute("UPDATE managed_executions SET heartbeat_at=heartbeat_at+1")))

    def test_remaining_reservation_or_queue_blocks_closed_history(self):
        with self.assertRaisesRegex(history.ExperimentHistoryError, "obligation_remaining"):
            history.verify_experiment_history_locked(self.database(mutate=lambda conn:
                insert(conn, "reservations", self.allocation)))
        queue = {key: self.allocation[key] for key in history.QUEUE_FIELDS if key in self.allocation}
        queue.update(queued_at=self.allocation["created_at"], managed_execution_id=self.metadata["execution_id"],
            managed_binding_hash=self.metadata["admission_binding_hash"])
        with self.assertRaisesRegex(history.ExperimentHistoryError, "obligation_remaining"):
            history.verify_experiment_history_locked(self.database(mutate=lambda conn: insert(conn, "queue", queue)))

    def test_closed_exclusion_requires_cleanup_digest_and_exact_scope_binding(self):
        record = self.native_record("NEVER_LAUNCHED")
        for field, value in (("cleanup_digest", record["completion_digest"]), ("isolated_policy_instance_id", str(uuid4()))):
            with self.subTest(field=field), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(self.database(record, mutate=lambda conn:
                    conn.execute("UPDATE " + exclusion_module.TABLE + " SET " + field + "=?", (value,))))

    def test_registered_scope_id_and_isolated_ledger_cannot_be_substituted(self):
        record = self.native_record("NEVER_LAUNCHED")
        changed_id = str(uuid4())
        record["completion"]["binding"]["scope_execution_id"] = changed_id
        for kind in ("preimage", "postimage"):
            record[kind]["exclusion"]["scope_execution_id"] = changed_id
            record[kind]["exclusion"]["binding_sha256"] = hashlib.sha256(
                canonical(record["completion"]["binding"]).encode()).hexdigest()
        with self.assertRaisesRegex(history.ExperimentHistoryError, "terminal_binding_changed"):
            history.canonical_receipt(self.rehash(record))
        for kind in ("PREPARATION_CLOSED", "WRAPPER_NOT_CREATED", "NEVER_LAUNCHED", "FINISHED"):
            record = self.native_record(kind)
            identity = record["completion"]["demand"]["ledger_identity"]
            if kind in {"PREPARATION_CLOSED", "WRAPPER_NOT_CREATED"}:
                record["completion"]["binding"]["isolated_ledger_identity"] = identity
            else:
                record["completion"]["binding"]["isolated_ledger_identity_json"] = canonical(identity)
                for image in ("preimage", "postimage"):
                    record[image]["exclusion"]["isolated_ledger_identity_json"] = canonical(identity)
                    record[image]["exclusion"]["binding_sha256"] = hashlib.sha256(
                        canonical(record["completion"]["binding"]).encode()).hexdigest()
                terminal = record["completion"]["terminal"]
                terminal["isolated_ledger_identity"] = identity
                terminal["binding_sha256"] = hashlib.sha256(canonical(
                    {key: terminal[key] for key in history._SCOPE_BINDING}).encode()).hexdigest()
            with self.subTest(kind=kind), self.assertRaises(history.ExperimentHistoryError):
                history.canonical_receipt(self.rehash(record))

    def test_preparation_acquisition_order_requires_returned_predecessors(self):
        for field, value in (("store", "entered"), ("launch", "not_entered"), ("mutex", "known_absent")):
            record = self.native_record("PREPARATION_CLOSED")
            record["completion"]["acquisitions"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(history.ExperimentHistoryError, "preparation_order_invalid"):
                history.canonical_receipt(self.rehash(record))
        for states in (("not_entered", "not_entered", "not_entered", "not_entered"),
                ("entered", "not_entered", "not_entered", "not_entered"),
                ("returned", "returned", "known_absent", "not_entered")):
            record = self.native_record("PREPARATION_CLOSED")
            record["completion"]["acquisitions"] = dict(zip(("store", "launch", "mutex", "job"), states))
            record["completion"]["terminal"]["job_factory"] = "not_entered"
            if states[0] != "returned":
                record["completion"]["binding"]["isolated_ledger_identity"] = None
            history.canonical_receipt(self.rehash(record))

    def test_routed_task_alias_and_invalid_direct_alias_preserve_obligations(self):
        routed = dict(id=uuid4().hex, task_id=self.managed["task_id"], worker_id="synthetic-worker",
            failure_domain="synthetic", ram_gib=1.0, cpu_units=.5, disk_gib=0.0,
            created_at=self.allocation["created_at"], heartbeat_at=self.allocation["heartbeat_at"],
            expires_at=self.allocation["expires_at"], metadata_json="{}")
        for active in (False, True):
            with self.subTest(active=active), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(self.database(active=active, mutate=lambda conn:
                    insert(conn, "worker_reservations", routed)))
        def malformed_alias(conn):
            # Model a damaged legacy row only in this unfenced synthetic copy.
            # Production schema and original fixture connections are untouched.
            conn.execute("PRAGMA ignore_check_constraints=ON")
            insert(conn, "managed_executions", self.managed | dict(execution_id=str(uuid4()), allocation_kind="invalid"))
            conn.execute("PRAGMA ignore_check_constraints=OFF")
        with self.assertRaisesRegex(history.ExperimentHistoryError, "tuple_missing_or_duplicate"):
            history.verify_experiment_history_locked(self.database(mutate=malformed_alias))

    def test_closed_experiment_cannot_coexist_with_production_launch_history(self):
        side = dict(execution_id=self.metadata["execution_id"], operation="ClaimLaunch", request_id=str(uuid4()),
            payload_hash="a" * 64, spec_hash=self.metadata["spec_hash"], guardian_epoch="synthetic")
        with self.assertRaisesRegex(history.ExperimentHistoryError, "daily_native_history_present"):
            history.verify_experiment_history_locked(self.database(mutate=lambda conn:
                insert(conn, "adaptive_launch_requests", side)))

    def test_terminal_native_boolean_counts_and_live_cpu_are_not_completion(self):
        for field, value in (("total_processes", False), ("launch_sealed", True),
                ("last_applied_cpu", dict(flags=5, rate_bp=2500)), ("pending_target_cpu", dict(flags=0, rate_bp=0))):
            record = self.native_record("NEVER_LAUNCHED")
            record["completion"]["terminal"][field] = value
            with self.subTest(field=field), self.assertRaises(history.ExperimentHistoryError):
                history.canonical_receipt(self.rehash(record))

    def test_rehashed_active_metadata_cannot_hide_changed_resource_allocation(self):
        with self.assertRaisesRegex(history.ExperimentHistoryError, "allocation_changed"):
            history.verify_experiment_history_locked(self.database(active=True, mutate=lambda conn:
                conn.execute("UPDATE reservations SET io_slots=io_slots+1")))

    def test_missing_canonical_guard_and_additional_receipt_trigger_refused(self):
        with self.assertRaisesRegex(history.ExperimentHistoryError, "schema_invalid"):
            history.verify_experiment_history_locked(self.database(missing_guard="experiment_reservation_delete_guard"))
        conn = self.database(mutate=lambda conn: conn.execute("CREATE TRIGGER extra_receipt_guard BEFORE DELETE ON " +
            history.TABLE + " BEGIN SELECT 1; END"))
        with self.assertRaisesRegex(history.ExperimentHistoryError, "schema_invalid"):
            history.verify_experiment_history_locked(conn)

    def test_additive_byte_budget_row_bound_and_preprojection_cell_bound(self):
        conn = self.database()
        result = history.verify_experiment_history_locked(conn)
        self.assertEqual(history.verify_experiment_history_locked(conn, max_bytes=result.bytes_used), result)
        with self.assertRaisesRegex(history.ExperimentHistoryError, "bytes_exceeded"):
            history.verify_experiment_history_locked(conn, max_bytes=result.bytes_used - 1)
        oversized = self.database(mutate=lambda conn: conn.execute("UPDATE " + demand_module.TABLE +
            " SET scope_directory=?", ("x" * (history.MAX_CELL_BYTES + 1),)))
        with self.assertRaisesRegex(history.ExperimentHistoryError, "cell_exceeded"):
            history.verify_experiment_history_locked(oversized)
        rows = sqlite3.connect(":memory:")
        self.addCleanup(rows.close)
        rows.execute("CREATE TABLE bounded(value INTEGER)")
        rows.executemany("INSERT INTO bounded VALUES(?)", ((number,) for number in range(history.MAX_HISTORY + 1)))
        with self.assertRaisesRegex(history.ExperimentHistoryError, "history_exceeded"):
            history._rows(rows, "bounded", ("value",), history._Budget(history.MAX_BYTES))

    def test_remaining_row_budget_composes_all_tables_and_rejects_before_overflow_payload(self):
        conn = self.database()
        complete = history.verify_experiment_history_locked(conn)
        self.assertEqual(history.verify_experiment_history_locked(conn, max_rows=complete.rows_used), complete)
        with self.assertRaisesRegex(history.ExperimentHistoryError, "history_exceeded"):
            history.verify_experiment_history_locked(conn, max_rows=complete.rows_used - 1)
        marker = self.metadata["experiment_id"].encode()
        def no_overflow_payload(value):
            if value == marker:
                raise AssertionError("zero row allowance materialized demand payload")
            return value.decode("utf-8")
        conn.text_factory = no_overflow_payload
        with self.assertRaisesRegex(history.ExperimentHistoryError, "history_exceeded"):
            history.verify_experiment_history_locked(conn, max_rows=0)
        for invalid in (-1, history.MAX_ROWS + 1, True):
            with self.subTest(max_rows=invalid), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(conn, max_rows=invalid)

    def test_shared_4096_rows_are_not_a_per_table_allowance(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE first_batch(value INTEGER)")
        conn.execute("CREATE TABLE last_batch(value TEXT)")
        conn.executemany("INSERT INTO first_batch VALUES(?)", ((number,) for number in range(history.MAX_HISTORY - 1)))
        conn.executemany("INSERT INTO last_batch VALUES(?)", (("allowed",), ("overflow-payload",)))
        def no_overflow_payload(value):
            if value == b"overflow-payload":
                raise AssertionError("4097th payload crossed the shared SQL read boundary")
            return value.decode("utf-8")
        conn.text_factory = no_overflow_payload
        budget = history._Budget(history.MAX_BYTES)
        self.assertEqual(len(history._rows(conn, "first_batch", ("value",), budget)), history.MAX_HISTORY - 1)
        with self.assertRaisesRegex(history.ExperimentHistoryError, "history_exceeded"):
            history._rows(conn, "last_batch", ("value",), budget)
        self.assertEqual(budget.rows, history.MAX_HISTORY)
        self.assertEqual(len(budget.observed), history.MAX_HISTORY)

    def test_duplicate_json_key_and_inconsistent_receipt_column_refused(self):
        for mutate in (lambda conn: conn.execute("UPDATE " + history.TABLE +
                " SET receipt_json=?", ('{"schema_version":1,"schema_version":1}',)),
                lambda conn: conn.execute("UPDATE " + history.TABLE + " SET receipt_sha256=?", ("f" * 64,))):
            with self.subTest(mutation=mutate), self.assertRaises(history.ExperimentHistoryError):
                history.verify_experiment_history_locked(self.database(mutate=mutate))


if __name__ == "__main__":
    unittest.main()
