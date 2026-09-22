"""Synthetic read-only cohort evidence. No OS process or daily store changes."""
from dataclasses import replace
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.daily_cohort import (
    CohortUnavailable, ProcessEntry, RetainedCohort,
)
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess


SELF = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class Backend:
    """Each captured handle remains tied to its original synthetic object."""

    def __init__(self):
        self.entries = [ProcessEntry(0, "[System Process]"),
                        ProcessEntry(SELF.pid, "python.exe"),
                        ProcessEntry(201, "pwsh.exe"),
                        ProcessEntry(202, "notepad.exe")]
        self.identities = {SELF.pid: SELF, 201: replace(SELF, pid=201)}
        self.images = {SELF.pid: "C:\\Python313\\python.exe",
                       201: "C:\\Program Files\\PowerShell\\7\\pwsh.exe"}
        self.objects, self.opened, self.closed = {}, [], []
        self.close_attempts = []
        self.enumerations = 0
        self.on_enumerate = None
        self.on_image = None
        self.close_failure = None
        self.capture_failure = None
        self.now = 0.0

    def monotonic(self):
        return self.now

    def current(self):
        return self.capture(SELF.pid)

    def capture(self, pid):
        if self.capture_failure == pid:
            raise IdentityUnavailable("process_open_unavailable", 5)
        handle = len(self.objects) + 1000
        self.objects[handle] = {"identity": self.identities[pid],
                                "image": self.images[pid],
                                "state": IdentityStatus.ALIVE}
        self.opened.append((pid, handle))
        return VerifiedProcess(self, handle, self.identities[pid])

    def image(self, process):
        if self.on_image:
            self.on_image(process)
        return self.objects[process._handle]["image"]

    def wait(self, handle):
        state = self.objects[handle]["state"]
        if state is IdentityStatus.UNKNOWN:
            # The native backend raises on an unavailable wait. VerifiedProcess
            # converts that failure into UNKNOWN with its required reason.
            raise IdentityUnavailable("process_wait_unavailable", 5)
        return state

    def close(self, handle):
        self.close_attempts.append(handle)
        if self.close_failure == "known":
            raise IdentityUnavailable("process_handle_close_failed", 6)
        if self.close_failure == "unknown":
            raise RuntimeError("synthetic interrupted native close")
        self.closed.append(handle)

    def enumerate(self, max_processes, deadline):
        self.enumerations += 1
        if self.on_enumerate:
            self.on_enumerate(self.enumerations)
        return tuple(self.entries)

    def add(self, pid, image, *, logon=None):
        self.entries.append(ProcessEntry(pid, image))
        self.identities[pid] = replace(SELF, pid=pid,
            logon_id=SELF.logon_id if logon is None else logon)
        self.images[pid] = "C:\\tools\\" + image

    def exit(self, pid):
        for item in self.objects.values():
            if item["identity"].pid == pid:
                item["state"] = IdentityStatus.DEAD
        self.entries = [entry for entry in self.entries if entry.pid != pid]


class DailyCohortTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()

    def capture(self, **kwargs):
        owner = RetainedCohort.capture_current(backend=self.backend, **kwargs)
        self.addCleanup(owner.close)
        return owner

    def capture_error(self, reason, **kwargs):
        with self.assertRaisesRegex(CohortUnavailable, reason) as failed:
            RetainedCohort.capture_current(backend=self.backend, **kwargs)
        owner = failed.exception.cohort
        self.assertIsInstance(owner, RetainedCohort)
        self.addCleanup(owner.close)
        return owner

    def test_stable_capture_is_ambiguous_and_has_no_writer_authority(self):
        owner = self.capture()
        summary = owner.summary()
        self.assertEqual(summary.retained_candidates, 1)
        self.assertEqual(summary.ambiguous_potential_consumers, 1)
        self.assertEqual(summary.completed_observations, 1)
        self.assertFalse(summary.unresolved)
        self.assertEqual(self.backend.enumerations, 2)
        self.assertEqual([pid for pid, _ in self.backend.opened], [101, 201])
        self.assertNotIn("path", summary.__dict__)
        self.assertNotIn("writer", summary.__dict__)
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retired()

    def test_all_supported_interpreters_and_other_logon_retained(self):
        for index, name in enumerate(("pythonw.exe", "Python3.13t.EXE", "py.exe",
                                      "powershell.exe", "pwsh.exe"), 301):
            self.backend.add(index, name, logon="S-1-5-5-300-400")
        owner = self.capture()
        self.assertEqual(owner.summary().retained_candidates, 6)

    def test_only_exact_current_excluded_ancestor_like_shell_retained(self):
        self.backend.add(99, "powershell.exe")
        owner = self.capture()
        self.assertEqual([pid for pid, _ in self.backend.opened], [101, 99, 201])
        self.assertEqual(owner.summary().retained_candidates, 2)

    def test_no_reopen_of_existing_live_candidate(self):
        owner = self.capture()
        self.backend.identities[201] = replace(SELF, pid=201, created_filetime_100ns=9)
        owner.observe_new()
        self.assertEqual([pid for pid, _ in self.backend.opened].count(201), 1)

    def test_only_original_handle_signaled_dead_allows_retired_observation(self):
        owner = self.capture()
        self.backend.exit(201)
        owner.assert_retired()
        self.assertEqual(owner.summary().retained_candidates, 1)
        self.assertEqual(self.backend.closed, [])

    def test_pid_disappearance_without_signaled_original_does_not_retire(self):
        owner = self.capture()
        self.backend.entries = [entry for entry in self.backend.entries if entry.pid != 201]
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retired()

    def test_new_consumer_captured_on_followup(self):
        owner = self.capture()
        self.backend.exit(201)
        self.backend.add(301, "python.exe")
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retired()
        self.assertEqual(owner.summary().retained_candidates, 2)

    def test_retained_only_recheck_does_not_discover_post_cutover_consumers(self):
        owner = self.capture()
        self.backend.exit(201)
        owner.assert_retired()
        enumeration_count = self.backend.enumerations
        opened = list(self.backend.opened)
        self.backend.add(301, "python.exe")
        owner.assert_retained_retired()
        self.assertEqual(self.backend.enumerations, enumeration_count)
        self.assertEqual(self.backend.opened, opened)
        self.assertEqual(owner.summary().retained_candidates, 1)
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retired()
        self.assertEqual(owner.summary().retained_candidates, 2)
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retained_retired()

    def test_retained_only_unknown_is_sticky_without_enumeration(self):
        owner = self.capture()
        enumeration_count = self.backend.enumerations
        self.backend.objects[1001]["state"] = IdentityStatus.UNKNOWN
        with self.assertRaisesRegex(CohortUnavailable, "retirement_unknown"):
            owner.assert_retained_retired()
        self.assertTrue(owner.summary().unresolved)
        self.backend.objects[1001]["state"] = IdentityStatus.DEAD
        with self.assertRaisesRegex(CohortUnavailable, "retirement_unknown"):
            owner.assert_retained_retired()
        self.assertEqual(self.backend.enumerations, enumeration_count)

    def test_retained_only_recheck_rejects_closed_witnesses(self):
        owner = self.capture()
        self.backend.exit(201)
        owner.assert_retained_retired()
        owner.close()
        with self.assertRaisesRegex(CohortUnavailable, "closed_or_closing"):
            owner.assert_retained_retired()

    def test_pid_reuse_keeps_old_dead_witness_and_captures_new_identity(self):
        owner = self.capture()
        self.backend.exit(201)
        self.backend.add(201, "pwsh.exe")
        self.backend.identities[201] = replace(SELF, pid=201, created_filetime_100ns=22)
        with self.assertRaisesRegex(CohortUnavailable, "ambiguous_consumers_still_alive"):
            owner.assert_retired()
        self.assertEqual(owner.summary().retained_candidates, 2)
        self.backend.exit(201)
        owner.assert_retired()

    def test_unknown_retained_wait_is_never_dead(self):
        owner = self.capture()
        self.backend.objects[1001]["state"] = IdentityStatus.UNKNOWN
        with self.assertRaisesRegex(CohortUnavailable, "retained_identity_unknown"):
            owner.observe_new()
        self.assertTrue(owner.summary().unresolved)

    def test_absent_candidate_unknown_cannot_be_erased_by_later_dead(self):
        owner = self.capture()
        self.backend.entries = [entry for entry in self.backend.entries if entry.pid != 201]
        self.backend.objects[1001]["state"] = IdentityStatus.UNKNOWN
        with self.assertRaisesRegex(CohortUnavailable, "retirement_unknown"):
            owner.assert_retired()
        self.assertTrue(owner.summary().unresolved)
        self.backend.objects[1001]["state"] = IdentityStatus.DEAD
        with self.assertRaisesRegex(CohortUnavailable, "retirement_unknown"):
            owner.assert_retired()

    def test_capture_access_denial_preserves_prior_and_current_handles(self):
        self.backend.add(301, "python.exe")
        self.backend.capture_failure = 301
        owner = self.capture_error("native_observation_unavailable")
        self.assertEqual(owner.summary().retained_candidates, 1)
        self.assertEqual(self.backend.closed, [])

    def test_snapshot_identity_name_race_is_sticky_and_keeps_handle(self):
        self.backend.images[201] = "C:\\tools\\other.exe"
        owner = self.capture_error("snapshot_identity_changed")
        self.assertEqual(owner.summary().retained_candidates, 1)
        with self.assertRaisesRegex(CohortUnavailable, "snapshot_identity_changed"):
            owner.assert_retired()

    def test_current_native_image_must_match_snapshot_even_if_not_python(self):
        self.backend.entries[1] = ProcessEntry(SELF.pid, "activator.exe")
        self.capture_error("current_image_mismatch")

    def test_exit_during_capture_is_unknown_not_successful_retirement(self):
        def during_image(process):
            if process.identity.pid == 201:
                self.backend.objects[process._handle]["state"] = IdentityStatus.DEAD
        self.backend.on_image = during_image
        self.capture_error("capture_liveness_unverified")

    def test_all_pid_churn_not_only_candidate_churn_blocks(self):
        def churn(call):
            if call == 2:
                self.backend.entries.append(ProcessEntry(400, "notepad.exe"))
        self.backend.on_enumerate = churn
        owner = self.capture_error("inventory_changed")
        self.assertTrue(owner.summary().unresolved)

    def test_missing_current_process_fails_closed(self):
        self.backend.entries = [entry for entry in self.backend.entries if entry.pid != SELF.pid]
        self.capture_error("current_missing")

    def test_bad_or_duplicate_inventory_entry_fails_closed(self):
        for record in (ProcessEntry(500, ""), ProcessEntry(500, "bad\x00.exe"),
                       ProcessEntry(201, "pwsh.exe"), ProcessEntry(True, "pwsh.exe")):
            with self.subTest(record=record):
                self.backend = Backend()
                self.backend.entries.append(record)
                self.capture_error("cohort_(image_unavailable|inventory_invalid)")

    def test_process_and_candidate_bounds_preserve_captured_handles(self):
        self.capture_error("inventory_overflow_or_empty", max_processes=3, max_candidates=3)
        self.backend = Backend()
        self.backend.add(301, "python.exe")
        owner = self.capture_error("candidate_overflow", max_candidates=1)
        self.assertEqual(owner.summary().retained_candidates, 1)

    def test_elapsed_budget_is_fail_closed(self):
        self.backend.on_enumerate = lambda count: setattr(self.backend, "now", 10.0)
        self.capture_error("capture_budget_exceeded", budget_seconds=1)

    def test_invalid_bounds_rejected_before_opening_any_process(self):
        for kwargs in ({"max_processes": 0}, {"max_candidates": True},
                       {"max_candidates": 4097}, {"budget_seconds": float("nan")},
                       {"budget_seconds": 31}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                RetainedCohort.capture_current(backend=self.backend, **kwargs)
        self.assertEqual(self.backend.opened, [])

    def test_close_is_idempotent_and_cannot_be_used_as_retirement(self):
        owner = self.capture()
        owner.close()
        owner.close()
        self.assertEqual(sorted(self.backend.closed), [1000, 1001])
        with self.assertRaisesRegex(CohortUnavailable, "closed_or_closing"):
            owner.assert_retired()

    def test_known_failed_close_can_retry_independent_handles(self):
        owner = self.capture()
        self.backend.close_failure = "known"
        with self.assertRaisesRegex(CohortUnavailable, "cleanup_unsettled"):
            owner.close()
        self.backend.close_failure = None
        owner.close()
        self.assertEqual(sorted(self.backend.closed), [1000, 1001])

    def test_uncertain_close_never_reuses_numeric_handles(self):
        owner = RetainedCohort.capture_current(backend=self.backend)
        self.backend.close_failure = "unknown"
        with self.assertRaisesRegex(CohortUnavailable, "cleanup_unsettled"):
            owner.close()
        attempts = list(self.backend.close_attempts)
        self.backend.close_failure = None
        stored = len(owner._failures)
        for _ in range(20):
            with self.assertRaisesRegex(CohortUnavailable, "cleanup_unsettled"):
                owner.close()
            self.assertEqual(len(owner._failures), stored)
        self.assertEqual(self.backend.close_attempts, attempts)
        self.assertFalse(owner.summary().closed)

    def test_native_backend_is_not_loaded_for_synthetic_capture(self):
        with patch("sentinel.adaptive.daily_cohort._NativeBackend",
                   side_effect=AssertionError("native side effect")):
            owner = self.capture()
        self.assertEqual(owner.summary().retained_candidates, 1)


if __name__ == "__main__":
    unittest.main()
