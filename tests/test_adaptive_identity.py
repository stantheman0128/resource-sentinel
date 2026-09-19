"""Portable identity failures plus a separately selectable read-only smoke.

Neither suite launches a process, creates a Job, writes controls, admits work,
or opens a runtime database. Native smoke success does not satisfy P1 S1–S3.
"""
from dataclasses import replace
import ctypes
import os
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import (
    IdentityUnavailable, VerifiedProcess, observe_identity,
)

IDENTITY = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class Backend:
    def __init__(self):
        self.value = IDENTITY
        self.state = IdentityStatus.ALIVE
        self.member = True
        self.opened, self.closed, self.queries = [], [], []
        self.failure = None

    def check(self, name):
        if self.failure == name:
            raise IdentityUnavailable(name + "_unavailable", 5)

    def open_process(self, pid):
        self.check("open")
        self.opened.append(pid)
        return 700

    def identity(self, handle):
        self.check("identity")
        self.queries.append(("identity", handle))
        return self.value

    def wait(self, handle):
        self.check("wait")
        self.queries.append(("wait", handle))
        return self.state

    def membership(self, handle, job):
        self.check("membership")
        self.queries.append(("membership", handle, job))
        return self.member

    def close(self, handle):
        self.check("close")
        self.closed.append(handle)


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.override = patch("sentinel.adaptive.identity._backend", return_value=self.backend)
        self.override.start()
        self.addCleanup(self.override.stop)

    def test_exact_filetime_round_trip_never_uses_a_float(self):
        with VerifiedProcess.open(IDENTITY) as process:
            self.assertEqual(process.identity, IDENTITY)
            encoded = process.identity.to_dict()
            self.assertEqual(encoded["created_filetime_100ns"], "134342315823996135")
            self.assertEqual(ProcessIdentity.from_dict(encoded), IDENTITY)
            self.assertEqual(process.observe().status, IdentityStatus.ALIVE)
        self.assertEqual(self.backend.closed, [700])

    def test_a_single_tick_pid_reuse_or_different_logon_rejected_and_closed(self):
        for changed in (
            replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1),
            replace(IDENTITY, pid=102),
            replace(IDENTITY, logon_id="S-1-5-5-100-201"),
        ):
            with self.subTest(changed=changed):
                self.backend.value = changed
                with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
                    VerifiedProcess.open(IDENTITY)
        self.assertEqual(self.backend.closed, [700, 700, 700])

    def test_query_failure_closes_the_new_handle(self):
        self.backend.failure = "identity"
        observation = observe_identity(IDENTITY)
        self.assertEqual(observation.status, IdentityStatus.UNKNOWN)
        self.assertEqual(observation.reason, "identity_unavailable")
        self.assertEqual(self.backend.closed, [700])

    def test_open_failure_is_unknown_not_dead(self):
        self.backend.failure = "open"
        observation = observe_identity(IDENTITY)
        self.assertEqual(observation.status, IdentityStatus.UNKNOWN)
        self.assertEqual(observation.reason, "open_unavailable")
        self.assertEqual(self.backend.closed, [])

    def test_wait_failure_is_unknown_not_dead(self):
        with VerifiedProcess.open(IDENTITY) as process:
            self.backend.failure = "wait"
            self.assertEqual(process.observe().status, IdentityStatus.UNKNOWN)
            self.assertIsNone(process.is_in_job(None))

    def test_only_signaled_verified_handle_is_death_evidence(self):
        with VerifiedProcess.open(IDENTITY) as process:
            self.backend.state = IdentityStatus.DEAD
            self.assertEqual(process.observe().status, IdentityStatus.DEAD)
            self.assertIsNone(process.is_in_job(800))
            self.assertFalse(any(item[0] == "membership" for item in self.backend.queries))

    def test_membership_and_repeated_observation_reuse_the_original_handle(self):
        with VerifiedProcess.open(IDENTITY) as process:
            # Simulate a different process behind this PID if someone reopens.
            self.backend.value = replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1)
            self.assertTrue(process.is_in_job(800))
            self.backend.member = False
            self.assertFalse(process.is_in_job(None))
            self.assertEqual(process.observe().identity, IDENTITY)
            self.assertEqual(process.observe().status, IdentityStatus.ALIVE)
        self.assertEqual(self.backend.opened, [101])
        self.assertEqual([query for query in self.backend.queries if query[0] == "identity"],
                         [("identity", 700)])
        self.assertIn(("membership", 700, 800), self.backend.queries)

    def test_membership_failure_is_unknown_not_false(self):
        with VerifiedProcess.open(IDENTITY) as process:
            self.backend.failure = "membership"
            self.assertIsNone(process.is_in_job(800))

    def test_exit_or_wait_failure_during_membership_returns_unknown(self):
        for failure in (False, True):
            with self.subTest(failure=failure), VerifiedProcess.open(IDENTITY) as process:
                self.backend.state = IdentityStatus.ALIVE
                self.backend.failure = None
                original = self.backend.membership

                def exit_during_query(handle, job):
                    result = original(handle, job)
                    self.backend.state = IdentityStatus.DEAD
                    if failure:
                        self.backend.failure = "wait"
                    return result

                with patch.object(self.backend, "membership", side_effect=exit_during_query):
                    self.assertIsNone(process.is_in_job(800))
                self.backend.failure = None

    def test_close_is_idempotent_and_closed_observations_are_unknown(self):
        process = VerifiedProcess.open(IDENTITY)
        process.close()
        process.close()
        self.assertEqual(self.backend.closed, [700])
        self.assertEqual(process.observe().reason, "identity_handle_closed")
        self.assertIsNone(process.is_in_job(None))
        with self.assertRaisesRegex(IdentityUnavailable, "identity_handle_closed"):
            process.__enter__()

    def test_failed_close_retains_handle_for_explicit_retry(self):
        process = VerifiedProcess.open(IDENTITY)
        self.backend.failure = "close"
        with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable"):
            process.close()
        self.backend.failure = None
        process.close()
        self.assertEqual(self.backend.closed, [700])

    def test_current_bootstrap_uses_actual_pid_not_environment(self):
        self.backend.value = replace(IDENTITY, pid=os.getpid())
        with patch.dict(os.environ, {"SENTINEL_OWNER_PID": "999", "SENTINEL_LOGON_ID": "pretend"}):
            with VerifiedProcess.current() as process:
                self.assertEqual(process.identity, self.backend.value)
        self.assertEqual(self.backend.opened, [os.getpid()])

    def test_untyped_identity_and_invalid_job_handle_are_rejected(self):
        for value in (101, IDENTITY.to_dict(), None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                VerifiedProcess.open(value)
        self.assertEqual(self.backend.opened, [])
        with VerifiedProcess.open(IDENTITY) as process:
            for handle in (0, -1, "800", True, 1 << (8 * ctypes.sizeof(ctypes.c_void_p)),
                           (1 << 256) + 800):
                with self.subTest(handle=handle), self.assertRaises(ValueError):
                    process.is_in_job(handle)
        self.assertFalse(any(query[0] == "membership" for query in self.backend.queries))

    def test_context_closes_when_consumer_raises(self):
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with VerifiedProcess.open(IDENTITY):
                raise RuntimeError("consumer")
        self.assertEqual(self.backend.closed, [700])


@unittest.skipUnless(os.name == "nt", "native read-only identity requires Windows")
class NativeIdentitySmokeTests(unittest.TestCase):
    def test_current_process_exact_identity_and_same_handle_query(self):
        with VerifiedProcess.current() as process:
            expected = process.identity
            self.assertEqual(expected.pid, os.getpid())
            self.assertRegex(expected.logon_id, r"^S-1-5-5-[0-9]+-[0-9]+$")
            self.assertEqual(ProcessIdentity.from_json(expected.to_json()), expected)
            self.assertEqual(process.observe().status, IdentityStatus.ALIVE)
            # Either result is valid; an inherited Job is not an admission pass.
            self.assertIsInstance(process.is_in_job(None), bool)
            with VerifiedProcess.open(expected) as second:
                self.assertEqual(second.identity, expected)
                self.assertEqual(second.observe().status, IdentityStatus.ALIVE)
        self.assertEqual(process.observe().status, IdentityStatus.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
