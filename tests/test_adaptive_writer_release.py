"""L1 writer-fence release faults; synthetic evidence proves no native behavior.

The real SQLite terminal transition and allocation archive run in one transaction.
These tests inject statement failures after the terminal CAS and require the
whole transaction, including nested lifecycle rows, to roll back.
"""
import sqlite3
import unittest

from sentinel.adaptive.contracts import AllocationKind
from tests import test_adaptive_lifecycle as fixtures
from tests import test_adaptive_prelaunch as prelaunch
from tests.fixtures.adaptive_evidence import fixture_evidence_provider


class AdaptiveWriterReleaseTests(unittest.TestCase):
    # Borrow only fixture helpers; do not inherit or re-run another test suite.
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.verifier = prelaunch.PrelaunchVerifier()
        self.store.evidence_provider = fixture_evidence_provider(self.verifier)

    @staticmethod
    def _contents(conn):
        # Compare private synthetic rows too: a failed cancellation must not
        # silently consume its claim or discard accounting metadata.
        return {
            table: [tuple(row) for row in conn.execute(
                f"SELECT * FROM {table} ORDER BY rowid")]
            for table in (
                "reservations", "worker_reservations", "managed_executions",
                "adaptive_runtime", "executions", "routed_executions",
            )
        }

    def _archive_fault(self, kind, operation, event):
        spec = self.spec(kind=kind)
        child = None
        if operation == "finalize":
            spec, current = self.running(spec)
            child = self.spec(kind=AllocationKind.PARENT, parent=spec.execution_id)
            self.store.prepare_registration(child, caller=fixtures.WRAPPER,
                                            now=fixtures.NOW)
            method = self.store.finalize_if_empty
            terminal = "FINISHED"
        else:
            spec, current = self.registered(spec)
            method = self.store.cancel_before_start
            terminal = "CANCELLED_BEFORE_START"

        conn = self.connection()
        table = ("reservations" if kind is AllocationKind.DIRECT
                 else "worker_reservations")
        archive = ("executions" if kind is AllocationKind.DIRECT
                   else "routed_executions")
        target = archive if event == "INSERT" else table
        reference = "NEW.reservation_id" if event == "INSERT" else "OLD.id"
        child_transition = ""
        if child is not None:
            # This ID is a generated fixture UUID. Observing it inside the
            # failed transaction proves the later RESERVED value is rollback,
            # rather than a child that was never transitioned in the first place.
            child_transition = f"""AND EXISTS(
                SELECT 1 FROM managed_executions child
                WHERE child.execution_id='{child.execution_id}'
                  AND child.state='FINISHED' AND child.launch_sealed=1
                  AND child.launch_in_flight=0)"""
        # A distinct error proves the fault was reached after terminal CAS.
        # RAISE(ABORT) only undoes this statement; production must roll back
        # the preceding lifecycle updates and (for DELETE) archive INSERT.
        conn.execute(f"""CREATE TRIGGER test_archive_failure
            BEFORE {event} ON {target}
            BEGIN
                SELECT CASE WHEN EXISTS(
                    SELECT 1 FROM managed_executions
                    WHERE reservation_id={reference} AND state='{terminal}'
                      AND launch_sealed=1 AND launch_in_flight=0)
                    {child_transition}
                THEN RAISE(ABORT,'synthetic_archive_failure')
                ELSE RAISE(ABORT,'terminal_transition_not_visible') END;
            END""")
        before = self._contents(conn)
        with self.assertRaisesRegex(sqlite3.IntegrityError,
                                    "^synthetic_archive_failure$"):
            method(spec.execution_id, caller=fixtures.WRAPPER,
                   expected_revision=current["state_revision"],
                   now=fixtures.NOW + 1)

        self.assertEqual(self._contents(conn), before)
        self.assertEqual(self.store.query(spec.execution_id)["state"],
                         current["state"])
        self.assertIsNotNone(conn.execute(
            f"SELECT id FROM {table} WHERE id=?", (spec.reservation.id,)
        ).fetchone())
        if child is not None:
            self.assertEqual(self.store.query(child.execution_id)["state"],
                             "RESERVED")

        conn.execute("DROP TRIGGER test_archive_failure")
        done = method(spec.execution_id, caller=fixtures.WRAPPER,
                      expected_revision=current["state_revision"],
                      now=fixtures.NOW + 2)
        self.assertEqual(done["state"], terminal)
        self.assertIsNone(conn.execute(
            f"SELECT id FROM {table} WHERE id=?", (spec.reservation.id,)
        ).fetchone())
        if child is not None:
            self.assertEqual(self.store.query(child.execution_id)["state"],
                             "FINISHED")
        committed = self._contents(conn)
        replay = method(spec.execution_id, caller=fixtures.WRAPPER,
                        expected_revision=done["state_revision"],
                        now=fixtures.NOW + 3)
        self.assertEqual(replay["state_revision"], done["state_revision"])
        self.assertEqual(self._contents(conn), committed)
        self.assertEqual(conn.execute(
            f"SELECT count(*) FROM {archive} WHERE reservation_id=?",
            (spec.reservation.id,),
        ).fetchone()[0], 1)

    def test_direct_cancel_archive_insert_failure_rolls_back(self):
        self._archive_fault(AllocationKind.DIRECT, "cancel", "INSERT")

    def test_direct_cancel_archive_delete_failure_rolls_back(self):
        self._archive_fault(AllocationKind.DIRECT, "cancel", "DELETE")

    def test_routed_cancel_archive_insert_failure_rolls_back(self):
        self._archive_fault(AllocationKind.ROUTED, "cancel", "INSERT")

    def test_routed_cancel_archive_delete_failure_rolls_back(self):
        self._archive_fault(AllocationKind.ROUTED, "cancel", "DELETE")

    def test_direct_finalize_archive_insert_failure_rolls_back_descendants(self):
        self._archive_fault(AllocationKind.DIRECT, "finalize", "INSERT")

    def test_direct_finalize_archive_delete_failure_rolls_back_descendants(self):
        self._archive_fault(AllocationKind.DIRECT, "finalize", "DELETE")

    def test_routed_finalize_archive_insert_failure_rolls_back_descendants(self):
        self._archive_fault(AllocationKind.ROUTED, "finalize", "INSERT")

    def test_routed_finalize_archive_delete_failure_rolls_back_descendants(self):
        self._archive_fault(AllocationKind.ROUTED, "finalize", "DELETE")


if __name__ == "__main__":
    unittest.main()
