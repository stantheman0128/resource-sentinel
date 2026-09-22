"""Portable isolated discovery fixtures, not evidence of native ACL gates."""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import ContractViolation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.host_discovery import (
    DiscoveryError, EndpointLocator, HostDescriptor, HostDiscovery, MAX_DESCRIPTOR_BYTES,
)
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive import host_discovery as module


LOGON = "S-1-5-5-112-223"
OTHER_LOGON = "S-1-5-5-112-224"
PARENT = ProcessIdentity(4101, 134343072000000001, LOGON)
CHILD = ProcessIdentity(4102, 134343072000000002, LOGON)
POLICY = "ab674b24-2519-4c89-8a1e-f1be56f8ce2d"
EPOCH = "guardian-test-epoch"


class NativeIdentityFixture:
    def __init__(self):
        self.status = IdentityStatus.ALIVE
        self.calls = 0

    def wait(self, handle):
        self.calls += 1
        return self.status

    def close(self, handle):
        pass


def owner(identity):
    return VerifiedProcess(NativeIdentityFixture(), object(), identity)


def endpoint(role, identity):
    return EndpointLocator(role, NativePipeEndpoint(LOGON, str(uuid4()), identity))


def supervisor(**changes):
    values = dict(instance_id=str(uuid4()), policy_instance_id=POLICY, logon_id=LOGON,
                  guardian_epoch=EPOCH, host_role="supervisor", host_identity=PARENT,
                  endpoints=(endpoint("operator", PARENT),), state="starting", revision=1)
    values.update(changes)
    return HostDescriptor(**values)


def guardian(parent, **changes):
    values = dict(instance_id=str(uuid4()), policy_instance_id=POLICY, logon_id=LOGON,
                  guardian_epoch=EPOCH, host_role="guardian", host_identity=CHILD,
                  endpoints=tuple(endpoint(role, CHILD) for role in ("operator", "launch", "query", "control")),
                  state="ready", revision=1, parent_identity=parent.host_identity,
                  parent_instance_id=parent.instance_id)
    values.update(changes)
    return HostDescriptor(**values)


class ProtectionFixture:
    """Explicit in-process fixture; no serialized protection bypass exists."""
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = []
        self.reject = False
        self.cleanup_error = None

    def create_directory(self, path):
        self.calls.append(("create", path))
        path.mkdir()

    def protect_file(self, path):
        self.calls.append(("protect", path))

    def verify(self, path, *, directory):
        self.calls.append(("verify", path, directory))
        if self.reject:
            raise DiscoveryError("discovery_security_dacl_mismatch")

    @contextmanager
    def write_scope(self, directory):
        with self.lock:
            try:
                yield
            finally:
                if self.cleanup_error is not None:
                    raise self.cleanup_error

    def close(self):
        self.calls.append(("close",))


def portable_publish(temporary, target, *, replace):
    if not replace and target.exists():
        failure = FileExistsError("fixture_exclusive_collision")
        failure._journal_exclusive_collision = True
        raise failure
    os.replace(temporary, target)


class HostDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-discovery-fixture-")
        self.addCleanup(temporary.cleanup)
        self.data = Path(temporary.name).resolve()
        self.protection = ProtectionFixture()
        self.discovery = HostDiscovery(self.data, logon_id=LOGON,
                                       protection=self.protection, publisher=portable_publish)
        self.parent = supervisor()
        self.child = guardian(self.parent)
        self.parent_owner, self.child_owner = owner(PARENT), owner(CHILD)

    def publish_parent(self, record=None, expected=None):
        record = self.parent if record is None else record
        return self.discovery.publish_instance(record, expected=expected,
            owner_process=self.parent_owner, child_process=self.child_owner)

    def publish_child(self, record=None, expected=None):
        record = self.child if record is None else record
        return self.discovery.publish_guardian(record, expected=expected,
            owner_process=self.child_owner, parent_process=self.parent_owner)

    def child_read(self, **changes):
        args = dict(parent_identity=PARENT, parent_instance_id=self.parent.instance_id,
                    child_identity=CHILD, instance_id=self.child.instance_id,
                    policy_instance_id=POLICY, guardian_epoch=EPOCH)
        args.update(changes)
        return self.discovery.read_guardian(**args)

    def assert_reason(self, reason, action):
        with self.assertRaises(DiscoveryError) as caught:
            action()
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def test_constructor_and_missing_read_have_no_side_effects(self):
        self.assertEqual(self.protection.calls, [])
        self.assertFalse(self.discovery.directory.exists())
        self.assert_reason("discovery_not_found", self.discovery.read_instance)
        self.assertFalse(self.discovery.directory.exists())
        self.assertEqual(self.protection.calls, [])
        self.assertFalse((self.data / "sentinel.db").exists())

    def test_missing_parent_read_and_constructor_never_provision_native_security(self):
        with patch.object(module, "_WindowsProtection", side_effect=AssertionError("no native setup")):
            subject = HostDiscovery(self.data / "missing", logon_id=LOGON)
            self.assert_reason("discovery_not_found", subject.read_instance)
        self.assertFalse((self.data / "missing").exists())

    def test_typed_roundtrip_and_decimal_identity(self):
        value = replace(self.parent, guardian=self.child, state="ready")
        payload = value.to_dict()
        self.assertEqual(payload["host_identity"]["created_filetime_100ns"], str(PARENT.created_filetime_100ns))
        self.assertEqual(payload["endpoints"][0]["endpoint"]["server_identity"], PARENT.to_dict())
        self.assertEqual(HostDescriptor.from_json(value.to_json()), value)
        self.assertEqual(EndpointLocator.from_json(value.endpoints[0].to_json()), value.endpoints[0])

    def test_schema_unknown_fields_and_noncanonical_identity_refused(self):
        for mutate in (lambda data: data.update(schema_version=2),
                       lambda data: data.update(protocol_version=2),
                       lambda data: data.pop("protocol_version"),
                       lambda data: data.update(tool="another-tool"),
                       lambda data: data.update(secret="never accepted"),
                       lambda data: data.pop("guardian"),
                       lambda data: data["host_identity"].update(created_filetime_100ns=PARENT.created_filetime_100ns),
                       lambda data: data.update(instance_id="00000000-0000-0000-0000-000000000000")):
            with self.subTest(mutate=mutate):
                data = self.parent.to_dict()
                mutate(data)
                with self.assertRaises(ContractViolation):
                    HostDescriptor.from_dict(data)

    def test_closed_role_state_and_revision(self):
        for changes in ({"host_role": "helper"}, {"state": "RUNNING"}, {"revision": True},
                        {"revision": 0}, {"logon_id": "fixture-logon"},
                        {"guardian_epoch": "contains spaces"}, {"endpoints": []}):
            with self.subTest(changes=changes), self.assertRaises(ContractViolation):
                replace(self.parent, **changes)

    def test_endpoint_role_id_and_complete_server_binding(self):
        for endpoints in ((self.parent.endpoints[0], self.parent.endpoints[0]),
                          (endpoint("operator", CHILD),),
                          (endpoint("launch", PARENT),)):
            with self.subTest(endpoints=endpoints), self.assertRaises(ContractViolation):
                replace(self.parent, endpoints=endpoints)
        with self.assertRaises(ContractViolation):
            EndpointLocator("apply", self.parent.endpoints[0].endpoint)

    def test_guardian_parent_and_topology_are_exact_and_one_level(self):
        for changes in ({"parent_identity": None}, {"parent_instance_id": None},
                        {"parent_identity": CHILD}, {"guardian": self.child}):
            with self.subTest(changes=changes), self.assertRaises(ContractViolation):
                replace(self.child, **changes)
        with self.assertRaises(ContractViolation):
            replace(self.parent, guardian=replace(self.child, parent_instance_id=str(uuid4())))
        with self.assertRaises(ContractViolation):
            replace(self.parent, state="ready")

    def test_supervisor_publish_read_replace_remove(self):
        self.assertEqual(self.publish_parent(), self.parent)
        self.assertEqual(self.discovery.read_instance(), self.parent)
        update = replace(self.parent, state="draining", revision=2)
        self.assertEqual(self.publish_parent(update, expected=self.parent), update)
        self.assertEqual(self.discovery.read_instance(), update)
        self.assert_reason("discovery_revision_conflict", lambda:
            self.discovery.remove_instance(self.parent, owner_process=self.parent_owner))
        self.assertTrue(self.discovery.remove_instance(update, owner_process=self.parent_owner))
        self.assertFalse(self.discovery.remove_instance(update, owner_process=self.parent_owner))
        self.assertFalse((self.data / "sentinel.db").exists())

    def test_direct_guardian_cannot_publish_canonical(self):
        self.assert_reason("discovery_canonical_supervisor_required", lambda:
            self.discovery.publish_instance(self.child, expected=None, owner_process=self.child_owner))
        self.assertFalse(self.discovery.directory.exists())

    def test_child_publication_and_ready_supervisor_bind_retained_witnesses(self):
        self.publish_child()
        ready = replace(self.parent, guardian=self.child, state="ready")
        self.assertEqual(self.publish_parent(ready), ready)
        self.assertEqual(self.discovery.read_instance(), ready)
        self.assertEqual(self.child_read(), self.child)
        self.assertGreater(self.parent_owner._backend.calls, 1)
        self.assertGreater(self.child_owner._backend.calls, 1)

    def test_ready_needs_matching_published_child_and_native_child(self):
        ready = replace(self.parent, guardian=self.child, state="ready")
        self.assert_reason("discovery_not_found", lambda: self.publish_parent(ready))
        self.publish_child()
        self.assert_reason("discovery_owner_mismatch", lambda:
            self.discovery.publish_instance(ready, expected=None, owner_process=self.parent_owner))
        self.child_owner._backend.status = IdentityStatus.DEAD
        self.assert_reason("discovery_owner_unverified", lambda: self.publish_parent(ready))
        self.assertFalse((self.discovery.directory / "instance.json").exists())

    def test_child_read_refuses_pid_reuse_parent_instance_policy_and_epoch(self):
        self.publish_child()
        for changes in ({"child_identity": replace(CHILD, created_filetime_100ns=CHILD.created_filetime_100ns + 1)},
                        {"parent_identity": replace(PARENT, created_filetime_100ns=PARENT.created_filetime_100ns + 1)},
                        {"parent_instance_id": str(uuid4())}, {"policy_instance_id": str(uuid4())},
                        {"guardian_epoch": "new-epoch"}):
            with self.subTest(changes=changes):
                self.assert_reason("discovery_child_mismatch", lambda: self.child_read(**changes))

    def test_changed_child_metadata_makes_old_canonical_unavailable(self):
        self.publish_child()
        self.publish_parent(replace(self.parent, guardian=self.child, state="ready"))
        newer = replace(self.child, revision=2, state="draining")
        self.publish_child(newer, expected=self.child)
        self.assert_reason("discovery_child_changed", self.discovery.read_instance)

    def test_owner_claim_is_not_native_witness_and_dead_unknown_refuse(self):
        self.assert_reason("discovery_owner_mismatch", lambda:
            self.discovery.publish_instance(self.parent, expected=None, owner_process=PARENT))
        for status in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            self.parent_owner._backend.status = status
            # UNKNOWN is converted to an unverified native observation even if
            # the fixture backend cannot supply its required reason.
            self.assert_reason("discovery_owner_unverified", self.publish_parent)
        self.assertFalse(self.discovery.directory.exists())

    def test_wrong_owner_and_foreign_logon_refuse_without_changes(self):
        self.assert_reason("discovery_owner_mismatch", lambda:
            self.discovery.publish_instance(self.parent, expected=None, owner_process=self.child_owner))
        other = HostDiscovery(self.data, logon_id=OTHER_LOGON, protection=self.protection,
                              publisher=portable_publish)
        self.assert_reason("discovery_logon_mismatch", lambda:
            other.publish_instance(self.parent, expected=None, owner_process=self.parent_owner))

    def test_stale_owner_cannot_delete_successor_instance(self):
        self.publish_parent()
        successor = supervisor()
        self.publish_parent(successor, expected=self.parent)
        self.assert_reason("discovery_revision_conflict", lambda:
            self.discovery.remove_instance(self.parent, owner_process=self.parent_owner))
        self.assertEqual(self.discovery.read_instance(), successor)

    def test_revision_change_and_same_instance_identity_change_refused(self):
        self.publish_parent()
        for update, reason in ((replace(self.parent, revision=3), "discovery_revision_conflict"),
                               (replace(self.parent, revision=2, guardian_epoch="different"), "discovery_binding_changed"),
                               (replace(self.parent, revision=2, endpoints=(endpoint("operator", PARENT),)), "discovery_binding_changed")):
            self.assert_reason(reason, lambda: self.publish_parent(update, expected=self.parent))
        self.assertEqual(self.discovery.read_instance(), self.parent)

    def test_publish_requires_explicit_expected_preimage(self):
        self.publish_parent()
        self.assert_reason("discovery_revision_conflict", self.publish_parent)
        self.assertEqual(self.discovery.read_instance(), self.parent)

    def test_two_cooperative_writers_cannot_both_replace_original_revision(self):
        self.publish_parent()
        other = HostDiscovery(self.data, logon_id=LOGON, protection=self.protection,
                              publisher=portable_publish)
        start = threading.Barrier(2)
        results = []

        def update(discovery, state):
            start.wait(timeout=2)
            try:
                value = discovery.publish_instance(replace(self.parent, revision=2, state=state),
                    expected=self.parent, owner_process=self.parent_owner)
                results.append(value)
            except DiscoveryError as error:
                results.append(error.reason)

        workers = [threading.Thread(target=update, args=(self.discovery, "draining")),
                   threading.Thread(target=update, args=(other, "unavailable"))]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(results), 2)
        self.assertEqual(results.count("discovery_revision_conflict"), 1)
        winner = next(item for item in results if isinstance(item, HostDescriptor))
        self.assertEqual(self.discovery.read_instance(), winner)

    def test_acl_rejection_cannot_repair_or_overwrite_existing_descriptor(self):
        self.publish_parent()
        before = (self.discovery.directory / "instance.json").read_bytes()
        self.protection.reject = True
        self.assert_reason("discovery_security_dacl_mismatch", self.discovery.read_instance)
        self.assert_reason("discovery_security_dacl_mismatch", lambda:
            self.publish_parent(replace(self.parent, revision=2), expected=self.parent))
        self.assertEqual((self.discovery.directory / "instance.json").read_bytes(), before)

    def test_size_schema_duplicate_keys_and_malformed_json(self):
        self.publish_parent()
        path = self.discovery.directory / "instance.json"
        for payload in (b"x" * (MAX_DESCRIPTOR_BYTES + 1), b"{", b'{"state":1,"state":2}',
                        json.dumps({**self.parent.to_dict(), "schema_version": 100}).encode()):
            with self.subTest(payload=payload[:20]):
                path.write_bytes(payload)
                self.assert_reason("discovery_invalid", self.discovery.read_instance)

    def test_reparse_stat_rejected_without_following(self):
        self.publish_parent()
        original = module.os.lstat
        path = self.discovery.directory / "instance.json"

        def replaced(target):
            result = original(target)
            if Path(target) != path:
                return result
            class Reparse:
                st_mode = result.st_mode
                st_ino = result.st_ino
                st_dev = result.st_dev
                st_size = result.st_size
                st_file_attributes = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            return Reparse()

        with patch.object(module.os, "lstat", side_effect=replaced):
            self.assert_reason("discovery_path_unsafe", self.discovery.read_instance)

    def test_namespace_fingerprint_change_refuses_original_reader(self):
        self.publish_parent()
        moved = self.data / "old-namespace"
        self.discovery.directory.rename(moved)
        self.discovery.directory.mkdir()
        self.assert_reason("discovery_directory_changed", self.discovery.read_instance)

    def test_file_replaced_during_read_fails_closed(self):
        self.publish_parent()
        path = self.discovery.directory / "instance.json"
        original = self.protection.verify
        switched = False

        def switch(target, *, directory):
            nonlocal switched
            original(target, directory=directory)
            if target == path and not switched:
                switched = True
                temporary = target.with_suffix(".replacement")
                temporary.write_bytes(path.read_bytes())
                os.replace(temporary, path)

        self.protection.verify = switch
        self.assert_reason("discovery_path_changed", self.discovery.read_instance)

    def test_partial_publish_preserves_unknown_outcome_and_no_retry(self):
        calls = []

        def lost_ack(temporary, target, *, replace):
            calls.append(target)
            portable_publish(temporary, target, replace=replace)
            raise OSError("private path must not leak")

        self.discovery._publisher = lost_ack
        error = self.assert_reason("discovery_publication_unverified", self.publish_parent)
        self.assertTrue(error.publication_may_have_occurred)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.discovery.read_instance(), self.parent)
        self.assertNotIn("private path", str(error))

    def test_owner_death_after_publish_is_uncertain_not_rollback(self):
        def die(temporary, target, *, replace):
            portable_publish(temporary, target, replace=replace)
            self.parent_owner._backend.status = IdentityStatus.DEAD

        self.discovery._publisher = die
        error = self.assert_reason("discovery_owner_unverified", self.publish_parent)
        self.assertTrue(error.publication_may_have_occurred)
        self.assertEqual(self.discovery.read_instance(), self.parent)

    def test_native_scope_cleanup_error_retains_owner_and_quarantines(self):
        self.protection.cleanup_error = OSError("fixture_close_failed")
        error = self.assert_reason("discovery_publication_unverified", self.publish_parent)
        self.assertTrue(error.publication_may_have_occurred)
        self.assertIsNotNone(self.discovery._retained_error)
        self.assert_reason("discovery_cleanup_quarantined", lambda:
            self.publish_parent(replace(self.parent, revision=2), expected=self.parent))
        self.assertEqual(self.discovery.read_instance(), self.parent)

    def test_scope_cleanup_failure_during_body_refusal_is_also_retained(self):
        self.publish_parent()
        self.protection.cleanup_error = RuntimeError("cleanup failed")
        self.assert_reason("discovery_revision_conflict", self.publish_parent)
        self.assertIsNotNone(self.discovery._retained_error)
        self.assert_reason("discovery_cleanup_quarantined", lambda:
            self.discovery.remove_instance(self.parent, owner_process=self.parent_owner))

    def test_interrupt_after_possible_publication_preserves_outcome(self):
        def interrupted(temporary, target, *, replace):
            portable_publish(temporary, target, replace=replace)
            raise KeyboardInterrupt

        self.discovery._publisher = interrupted
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.publish_parent()
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertTrue(self.discovery._quarantined)
        self.assertEqual(self.discovery.read_instance(), self.parent)

    def test_guardian_remove_is_exact_and_does_not_remove_parent(self):
        self.publish_parent()
        self.publish_child()
        self.assertTrue(self.discovery.remove_guardian(self.child, owner_process=self.child_owner))
        self.assertEqual(self.discovery.read_instance(), self.parent)
        self.assert_reason("discovery_not_found", self.child_read)

    def test_close_does_not_delete_locator(self):
        self.publish_parent()
        self.discovery.close()
        self.assertTrue((self.discovery.directory / "instance.json").exists())
        self.assertEqual(self.protection.calls[-1], ("close",))

    def test_protection_applies_before_any_private_staged_bytes(self):
        original = self.protection.protect_file

        def check_empty(path):
            self.assertEqual(path.stat().st_size, 0)
            original(path)

        self.protection.protect_file = check_empty
        self.publish_parent()
        self.assertEqual(list(self.discovery.directory.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
