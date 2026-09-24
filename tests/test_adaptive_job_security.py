"""Actual bounded security parser and Job custody with synthetic native APIs.

SID/ACL/ACE bytes and the implementation's ctypes readers are real. All kernel,
allocation and token APIs are explicit in-process fixtures; no Windows DLL,
native Job/security mutation or capability gate is exercised.
"""
import ctypes as C
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, replace
import struct
import unittest
from unittest.mock import patch

from sentinel.adaptive import native_job as native
from sentinel.adaptive import windows
from tests import test_adaptive_native_job as job_fixture


TOKEN = 880


def sid_bytes(text):
    parts = [int(value) for value in text.split("-")[1:]]
    revision, authority, *subauthorities = parts
    return bytes((revision, len(subauthorities))) + authority.to_bytes(6, "big") + b"".join(
        value.to_bytes(4, "little") for value in subauthorities)


def sid_text(pointer):
    header = C.string_at(pointer, 8)
    values = struct.unpack("<" + "I" * header[1], C.string_at(pointer + 8, header[1] * 4))
    return "S-" + str(header[0]) + "-" + str(int.from_bytes(header[2:], "big")) + "".join(
        "-" + str(value) for value in values)


class _Kernel(job_fixture.Kernel):
    def __init__(self):
        super().__init__()
        self.allocations = {}
        self.free_failure_kind = self.free_unknown_kind = None
        self.free_error = OSError("synthetic LocalFree outcome unknown")

    def CloseHandle(self, handle):
        # ctypes native bindings accept either representation. Normalize this
        # fake kernel's lookup/trace key while retaining the original output
        # cell in the production resource owner.
        return super().CloseHandle(getattr(handle, "value", handle))

    def LocalFree(self, pointer):
        address = getattr(pointer, "value", pointer)
        kind, buffer = self.allocations.get(address, ("untracked", None))
        self.calls.append(("LocalFree", kind, address))
        if kind == self.free_unknown_kind:
            raise self.free_error
        if kind == self.free_failure_kind:
            self.error = 6
            return address
        self.allocations.pop(address, None)
        return None


class _SecurityApi:
    """Native output cells point into retained, correctly bounded real buffers."""
    def __init__(self, kernel):
        self.kernel = kernel
        self.owner = job_fixture.OWNER
        self.logon = job_fixture.LOGON
        self.control, self.revision, self.control_result = 0x9004, 1, 1
        self.acl_revision, self.ace_count = 2, 1
        self.ace_type, self.ace_flags, self.mask = 0, 0, native._DACL_ACCESS
        self.descriptor_length = 128
        self.token_error = self.info_error = self.sid_error = None
        self.sid_error_kind = None
        self.token_result, self.info_code, self.sid_result = 1, 0, 1
        self.descriptors = []

    def OpenProcessToken(self, process, access, output):
        self.kernel.calls.append(("OpenProcessToken", process, access))
        output._obj.value = TOKEN
        if self.token_error is not None:
            raise self.token_error
        if not self.token_result:
            self.kernel.error = 5
        return self.token_result

    def GetTokenInformation(self, token, information_class, buffer, size, required):
        self.kernel.calls.append(("GetTokenInformation", getattr(token, "value", token), buffer is None))
        raw = sid_bytes(job_fixture.OWNER)
        offset = C.sizeof(windows._SidAndAttributes)
        required._obj.value = offset + len(raw)
        if buffer is None:
            self.kernel.error = 122
            return 0
        if size < required._obj.value:
            raise AssertionError("fixture token output buffer too small")
        C.memmove(C.addressof(buffer) + offset, raw, len(raw))
        windows._SidAndAttributes.from_buffer(buffer).sid = C.addressof(buffer) + offset
        return 1

    def ConvertSidToStringSidW(self, pointer, output):
        pointer = getattr(pointer, "value", pointer)
        kind = "token_sid"
        for descriptor in self.descriptors:
            start = C.addressof(descriptor)
            if start <= pointer < start + 128:
                kind = "descriptor_owner_sid" if pointer == start + 32 else "descriptor_logon_sid"
                break
        text = C.create_unicode_buffer(sid_text(pointer))
        address = C.addressof(text)
        self.kernel.allocations[address] = (kind, text)
        self.kernel.calls.append(("ConvertSidToStringSidW", kind, pointer))
        output._obj.value = address
        if self.sid_error is not None and self.sid_error_kind == kind:
            raise self.sid_error
        if not self.sid_result:
            self.kernel.error = 5
        return self.sid_result

    def GetSecurityInfo(self, handle, object_type, requested, owner, group, dacl, sacl, descriptor):
        self.kernel.calls.append(("GetSecurityInfo", handle, object_type, requested))
        buffer = C.create_string_buffer(128)
        start = C.addressof(buffer)
        owner_raw, logon_raw = sid_bytes(self.owner), sid_bytes(self.logon)
        C.memmove(start + 32, owner_raw, len(owner_raw))
        acl = windows._Acl.from_buffer(buffer, 64)
        acl.revision, acl.size, acl.ace_count = self.acl_revision, 16 + len(logon_raw), self.ace_count
        ace = windows._AceHeader.from_buffer(buffer, 72)
        ace.kind, ace.flags, ace.size, ace.mask = self.ace_type, self.ace_flags, 8 + len(logon_raw), self.mask
        C.memmove(start + 80, logon_raw, len(logon_raw))
        self.descriptors.append(buffer)
        self.kernel.allocations[start] = ("descriptor", buffer)
        owner._obj.value, dacl._obj.value, descriptor._obj.value = start + 32, start + 64, start
        if self.info_error is not None:
            raise self.info_error
        return self.info_code

    def GetSecurityDescriptorLength(self, descriptor):
        return self.descriptor_length

    def GetSecurityDescriptorControl(self, descriptor, control, revision):
        control._obj.value, revision._obj.value = self.control, self.revision
        if not self.control_result:
            self.kernel.error = 5
        return self.control_result


class _ParserBackend(windows._WindowsMutexBackend):
    def __init__(self, kernel, api):
        # Preserve real parser/acquisition/release methods without loading DLLs.
        self.kernel, self.security = kernel, api


class JobSecurityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = job_fixture.NativeJobTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.kernel = self.fixture.kernel = _Kernel()
        self.api = _SecurityApi(self.kernel)
        self.parser = _ParserBackend(self.kernel, self.api)
        self.backend = native._WindowsBackend(kernel=self.kernel,
            advapi=job_fixture.Advapi(self.kernel), security=self.parser)
        self.jobs = []

    def opened(self):
        owner = native.NativeJob.open(job_fixture.NAME, job_fixture.NONCE, job_fixture.LOGON,
            access=native.JobAccess.CONTROL, backend=self.backend)
        self.jobs.append(owner)
        return owner

    def calls(self, name):
        return [value for value in self.kernel.calls if value[0] == name]

    def assert_no_new_job_or_set(self):
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        self.assertEqual(len(self.calls("OpenJobObjectW")), 1)

    def test_frozen_complete_observation_comes_from_original_handle_and_real_buffers(self):
        job = self.opened()
        observed = job.query_security()
        self.assertIs(type(observed), native.JobSecurity)
        self.assertEqual(observed, native.JobSecurity(job_fixture.OWNER, job_fixture.LOGON,
            0x9004, 1, 2, 1, 0, 0, native._DACL_ACCESS, 0))
        with self.assertRaises(FrozenInstanceError):
            observed.ace_count = 2
        self.assertEqual(self.calls("GetSecurityInfo"),
            [("GetSecurityInfo", job_fixture.RETAINED, 6, 5)] * 2)
        self.assertEqual(self.kernel.allocations, {})
        self.assert_no_new_job_or_set()
        job.close()

    def test_readback_preserves_actual_control_revision_and_handle_flags(self):
        job = self.opened()
        first = job.query_security()
        self.api.control, self.api.revision = 0x1004, 2
        self.kernel.handle_flags[job_fixture.RETAINED] = 2
        later = job.query_security()
        self.assertEqual((later.descriptor_control, later.descriptor_revision, later.handle_flags), (0x1004, 2, 2))
        self.assertEqual((first.descriptor_control, first.descriptor_revision, first.handle_flags), (0x9004, 1, 0))
        self.kernel.handle_flags[job_fixture.RETAINED] = 0
        job.close()

    def test_parser_rejects_changed_owner_logon_controls_acl_and_ace(self):
        job = self.opened()
        cases = dict(owner="S-1-5-21-100-200-300-9999", logon="S-1-5-5-100-999",
            control=4, acl_revision=3, ace_count=2, ace_type=1, ace_flags=16, mask=native._DACL_ACCESS - 1,
            descriptor_length=19, control_result=0)
        for name, value in cases.items():
            original = getattr(self.api, name)
            try:
                setattr(self.api, name, value)
                with self.subTest(field=name), self.assertRaises(native.NativeJobError) as raised:
                    job.query_security()
                self.assertIsInstance(raised.exception._native_job_security_error, windows.NativePolicyMutexError)
                self.assertEqual(self.kernel.allocations, {})
            finally:
                setattr(self.api, name, original)
        self.assert_no_new_job_or_set()
        job.close()
        self.assertTrue(job.closed)

    def test_present_protected_acl_still_refuses_defaulted_control_bits(self):
        job = self.opened()
        for bit in (1, 8):
            self.api.control = 0x9004 | bit
            with self.subTest(bit=bit), self.assertRaises(native.NativeJobError):
                job.query_security()
        self.assertEqual(self.kernel.allocations, {})
        job.close()

    def test_inheritable_handle_requery_refuses_after_positive_descriptor_cleanup(self):
        job = self.opened()
        self.kernel.handle_flags[job_fixture.RETAINED] = 1
        with self.assertRaisesRegex(native.NativeJobError, "handle_inheritable"):
            job.query_security()
        self.assertEqual(self.kernel.allocations, {})
        self.assertFalse(job.closed)
        self.kernel.handle_flags[job_fixture.RETAINED] = 0
        job.close()

    def test_legacy_none_verifier_remains_constructor_only_compatibility(self):
        with patch.object(self.parser, "verify_security", return_value=None):
            job = self.opened()
            with self.assertRaisesRegex(native.NativeJobError, "security_observation_unavailable"):
                job.query_security()
        job.close()

    def test_typed_observation_does_not_accept_bool_or_wrong_binding(self):
        job = self.opened()
        actual = self.parser.verify_security(job.handle, job_fixture.LOGON, job_fixture.OWNER,
            access_mask=native._DACL_ACCESS)
        changes = [dict(owner_sid="S-1-5-21-9"), dict(logon_sid="S-1-5-5-1-2"),
            dict(ace_count=True), dict(descriptor_control=True), dict(ace_flags=False)]
        for change in changes:
            with self.subTest(change=change), patch.object(self.parser, "verify_security",
                    return_value=replace(actual, **change)), self.assertRaisesRegex(
                    native.NativeJobError, "security_observation_invalid"):
                job.query_security()
        job.close()

    def test_post_close_security_query_performs_no_native_calls(self):
        job = self.opened()
        job.close()
        calls = list(self.kernel.calls)
        with self.assertRaisesRegex(native.NativeJobError, "handle_unavailable"):
            job.query_security()
        self.assertEqual(self.kernel.calls, calls)

    def test_descriptor_free_false_after_successful_parse_retains_exact_owner(self):
        job = self.opened()
        self.kernel.free_failure_kind = "descriptor"
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        error = raised.exception
        original = error._native_job_security_error
        self.assertIs(error.__cause__, original)
        self.assertEqual(original.reason, "policy_mutex_security_free_failed")
        self.assertIs(error._native_job_cleanup[0], job)
        retained, = error._policy_mutex_cleanup
        self.assertIs(retained, original._policy_mutex_cleanup[0])
        self.assertEqual(retained._state, "owned")
        self.assertFalse(retained.closed)
        before = list(self.kernel.calls)
        with self.assertRaisesRegex(native.NativeJobError, "security_cleanup_unverified"):
            job.query_security()
        self.assertEqual(self.kernel.calls, before)
        self.kernel.free_failure_kind = None
        job.close()
        self.assertTrue(retained.closed)
        self.assertTrue(job.closed)
        self.assertEqual(self.kernel.allocations, {})

    def test_sid_free_failure_on_normal_exit_keeps_original_sid_and_descriptor_cleanup(self):
        job = self.opened()
        self.kernel.free_failure_kind = "descriptor_logon_sid"
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        retained, = raised.exception._policy_mutex_cleanup
        self.assertEqual(self.kernel.allocations[retained._value.value][0], "descriptor_logon_sid")
        self.assertFalse(any(kind == "descriptor" for kind, _ in self.kernel.allocations.values()))
        self.kernel.free_failure_kind = None
        job.close()
        self.assertTrue(retained.closed)
        self.assertTrue(job.closed)

    def test_parse_error_and_descriptor_free_failure_keep_both_original_errors(self):
        job = self.opened()
        self.api.ace_count = 2
        self.kernel.free_failure_kind = "descriptor"
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        original = raised.exception._native_job_security_error
        self.assertEqual(original.reason, "policy_mutex_dacl_mismatch")
        cleanup, = original._policy_mutex_cleanup_errors
        self.assertEqual(cleanup.reason, "policy_mutex_security_free_failed")
        self.assertIs(raised.exception._policy_mutex_cleanup_errors[0], cleanup)
        self.kernel.free_failure_kind = None
        job.close()
        self.assertTrue(job.closed)

    def test_unknown_descriptor_release_is_not_retried_or_hidden_by_job_close(self):
        job = self.opened()
        self.kernel.free_unknown_kind = "descriptor"
        with self.assertRaises(OSError) as raised:
            job.query_security()
        self.assertIs(raised.exception, self.kernel.free_error)
        retained, = raised.exception._policy_mutex_cleanup
        self.assertEqual(retained._state, "close_unknown")
        self.kernel.free_unknown_kind = None
        frees = list(self.calls("LocalFree"))
        for _ in range(2):
            with self.assertRaises(OSError) as cleanup:
                job.close()
            self.assertIs(cleanup.exception, raised.exception)
        self.assertEqual(self.calls("LocalFree"), frees)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", job_fixture.RETAINED)), 1)
        self.assertFalse(job.closed)
        self.assertFalse(retained.closed)

    def test_documented_token_close_false_retains_original_token(self):
        job = self.opened()
        self.kernel.close_failures.add(TOKEN)
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        retained, = raised.exception._policy_mutex_cleanup
        self.assertEqual(retained._value.value, TOKEN)
        self.assertEqual(retained._state, "owned")
        self.kernel.close_failures.remove(TOKEN)
        job.close()
        self.assertTrue(retained.closed)
        self.assertTrue(job.closed)

    def test_interrupted_security_allocations_retain_output_without_free_or_reacquire(self):
        for operation in ("token", "descriptor", "sid"):
            with self.subTest(operation=operation):
                # Each original test Job has its own original query failure;
                # cleanup never revisits the uncertain output of a prior case.
                self.api.token_error = self.api.info_error = self.api.sid_error = None
                job = self.opened()
                original = KeyboardInterrupt("synthetic security allocation interruption")
                if operation == "token":
                    self.api.token_error = original
                elif operation == "descriptor":
                    self.api.info_error = original
                else:
                    self.api.sid_error, self.api.sid_error_kind = original, "descriptor_owner_sid"
                with self.assertRaises(KeyboardInterrupt) as raised:
                    job.query_security()
                self.assertIs(raised.exception, original)
                retained, = original._policy_mutex_cleanup
                self.assertEqual(retained._state, "allocation_unknown")
                value = retained._value.value
                self.api.token_error = self.api.info_error = self.api.sid_error = None
                before = list(self.kernel.calls)
                with self.assertRaisesRegex(native.NativeJobError, "security_cleanup_unverified"):
                    job.query_security()
                self.assertEqual(self.kernel.calls, before)
                with self.assertRaises(KeyboardInterrupt):
                    job.close()
                self.assertFalse(job.closed)
                self.assertFalse(retained.closed)
                self.assertFalse(any(call[0] == "LocalFree" and call[2] == value
                    for call in self.kernel.calls[len(before):]))

    def test_documented_security_query_failure_ignores_undefined_descriptor_output(self):
        job = self.opened()
        self.api.info_code = 5
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        self.assertEqual(raised.exception._native_job_security_error.win32_error, 5)
        undefined = C.addressof(self.api.descriptors[-1])
        self.assertFalse(any(call[2] == undefined for call in self.calls("LocalFree")))
        self.assertEqual(job._security_cleanup_owners, ())
        job.close()
        self.assertTrue(job.closed)

    def test_constructor_error_cannot_hide_unknown_security_buffer_behind_closed_job(self):
        self.kernel.free_unknown_kind = "descriptor"
        with self.assertRaises(OSError) as raised:
            self.opened()
        original, = raised.exception._native_job_initialization_owners
        self.assertIs(raised.exception._native_job_cleanup[0], original)
        self.assertFalse(original.closed)
        self.assertEqual(original._job.state, "closed")
        retained, = raised.exception._policy_mutex_cleanup
        self.assertEqual(retained._state, "close_unknown")
        calls = list(self.kernel.calls)
        self.kernel.free_unknown_kind = None
        with self.assertRaises(OSError):
            native.retry_job_cleanup(raised.exception)
        self.assertEqual(self.kernel.calls, calls)

    def test_generic_owned_resource_normal_exit_retains_unknown_release_once(self):
        calls, original = [], OSError("synthetic normal-exit release unknown")
        def release(value):
            calls.append(value)
            raise original
        with self.assertRaises(OSError) as raised:
            with windows._owned_resource(4242, release, "fixture_cleanup_unverified"):
                pass
        self.assertIs(raised.exception, original)
        retained, = original._policy_mutex_cleanup
        self.assertFalse(windows.settle_retained(original))
        self.assertFalse(windows.settle_retained(original))
        self.assertEqual(calls, [4242])
        self.assertEqual(retained._state, "close_unknown")

    def test_unknown_create_failure_cleanup_owner_does_not_retry(self):
        calls, cleanup = [], OSError("synthetic outer create cleanup unknown")
        def release(value):
            calls.append(value)
        primary = windows.NativePolicyMutexError("policy_mutex_dacl_mismatch")
        windows._retain_native(primary, release, 909, "policy_mutex_handle_close_failed", cleanup)
        self.assertFalse(windows.settle_retained(primary))
        self.assertEqual(calls, [])
        self.assertIs(primary._policy_mutex_cleanup_errors[0], cleanup)

    def test_post_success_context_handoff_keeps_original_token_sid_and_descriptor(self):
        original_context = windows._owned_resource
        for target in ("token", "descriptor_owner_sid", "descriptor"):
            with self.subTest(target=target):
                job = self.opened()
                original = KeyboardInterrupt("synthetic post-success context-entry interruption")
                @contextmanager
                def interrupted(value, release, reason, *, owner=None):
                    address = getattr(value, "value", value)
                    kind = "token" if address == TOKEN else self.kernel.allocations.get(address, (None, None))[0]
                    if kind == target:
                        raise original
                    with original_context(value, release, reason, owner=owner) as retained:
                        yield retained
                with patch.object(windows, "_owned_resource", side_effect=interrupted), \
                        self.assertRaises(KeyboardInterrupt) as raised:
                    job.query_security()
                self.assertIs(raised.exception, original)
                retained, = original._policy_mutex_cleanup
                self.assertEqual(retained._state, "owned")
                self.assertIs(job._security_cleanup_owners[0], retained)
                job.close()
                self.assertTrue(retained.closed)
                self.assertTrue(job.closed)
                self.assertFalse(hasattr(original, "_policy_mutex_cleanup"))
                self.assertIs(job._security_cleanup_error, original)

    def test_post_success_classification_interruption_retains_unknown_output(self):
        job = self.opened()
        original = KeyboardInterrupt("synthetic classification interruption")
        fired = []
        def interrupt_classification(owner, name, value):
            if name == "_state" and value == "owned" and not fired:
                address = getattr(owner._value, "value", owner._value)
                if self.kernel.allocations.get(address, (None, None))[0] == "descriptor":
                    fired.append(owner)
                    raise original
            object.__setattr__(owner, name, value)
        with patch.object(windows._RetainedNative, "__setattr__", new=interrupt_classification), \
                self.assertRaises(KeyboardInterrupt):
            job.query_security()
        retained, = original._policy_mutex_cleanup
        self.assertIs(retained, fired[0])
        self.assertEqual(retained._state, "allocation_unknown")
        frees = list(self.calls("LocalFree"))
        with self.assertRaises(KeyboardInterrupt):
            job.close()
        self.assertFalse(job.closed)
        self.assertEqual(self.calls("LocalFree"), frees)

    def test_reused_known_failure_exception_becomes_unknown_without_security_retry(self):
        job = self.opened()
        original = windows.NativePolicyMutexError("policy_mutex_security_free_failed", 6)
        original._known_native_close_failed = True
        self.kernel.free_error, self.kernel.free_unknown_kind = original, "descriptor"
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        self.assertIs(raised.exception._native_job_security_error, original)
        self.assertIs(original._known_native_close_failed, False)
        self.assertIs(original._native_close_outcome_unknown, True)
        retained, = raised.exception._policy_mutex_cleanup
        self.assertEqual(retained._state, "close_unknown")
        self.kernel.free_unknown_kind = None
        frees = list(self.calls("LocalFree"))
        with self.assertRaises(native.NativeJobError):
            job.close()
        self.assertEqual(self.calls("LocalFree"), frees)
        self.assertFalse(job.closed)

    def test_reused_known_failure_exception_does_not_retry_native_job_handle(self):
        job = self.opened()
        original = native.NativeJobError("native_job_handle_close_failed", 6)
        original._known_native_close_failed = True
        self.kernel.close_exceptions[job_fixture.RETAINED] = original
        with self.assertRaises(native.NativeJobError) as raised:
            job.close()
        self.assertIs(raised.exception, original)
        self.assertIs(original._known_native_close_failed, False)
        self.assertIs(original._native_close_outcome_unknown, True)
        self.assertEqual(job._job.state, "close_unknown")
        self.kernel.close_exceptions.clear()
        closes = list(self.calls("CloseHandle"))
        with self.assertRaisesRegex(native.NativeJobError, "cleanup_outcome_unknown"):
            job.close()
        self.assertEqual(self.calls("CloseHandle"), closes)

    def test_known_constructor_free_failure_settles_pending_links_and_preserves_history(self):
        self.kernel.free_failure_kind = "descriptor"
        original_free = self.kernel.LocalFree
        def fail_once(pointer):
            result = original_free(pointer)
            if result:
                self.kernel.free_failure_kind = None
            return result
        with patch.object(self.kernel, "LocalFree", side_effect=fail_once), \
                self.assertRaises(native.NativeJobError) as raised:
            self.opened()
        error = raised.exception
        job, = error._native_job_initialization_owners
        original = error._native_job_security_error
        retained, = job._security_cleanup_owners
        self.assertTrue(retained.closed)
        self.assertTrue(job.closed)
        self.assertIs(job._security_cleanup_error, error)
        self.assertIs(error.__cause__, original)
        for member in (error, original):
            self.assertFalse(hasattr(member, "_policy_mutex_cleanup"))
            self.assertFalse(hasattr(member, "_native_job_cleanup"))
            self.assertTrue(any("security_free_failed" in note for note in member.__notes__))
        self.assertEqual(len([call for call in self.calls("LocalFree") if call[1] == "descriptor"]), 2)
        self.assertEqual(self.kernel.allocations, {})

    def test_positive_cleanup_prunes_only_exact_original_dependency(self):
        job = self.opened()
        self.kernel.free_failure_kind = "descriptor"
        with self.assertRaises(native.NativeJobError) as raised:
            job.query_security()
        error = raised.exception
        original = error._native_job_security_error
        own, = job._security_cleanup_owners
        foreign_calls = []
        foreign = windows._RetainedNative(lambda value: foreign_calls.append(value), 4242)
        for member in (error, original):
            member._policy_mutex_cleanup = (*member._policy_mutex_cleanup, foreign)
        self.kernel.free_failure_kind = None
        job.close()
        self.assertTrue(own.closed)
        self.assertTrue(job.closed)
        self.assertFalse(foreign.closed)
        self.assertEqual(foreign_calls, [])
        for member in (error, original):
            self.assertEqual(member._policy_mutex_cleanup, (foreign,))
        foreign.close()
