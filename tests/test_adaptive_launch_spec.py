"""Pure launch-transport contracts; no PowerShell or native execution proof."""
import base64
from dataclasses import FrozenInstanceError
import json
import subprocess
import traceback
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import MAX_MESSAGE_BYTES, Priority, ResourceDemand, Role
from sentinel.adaptive.launch_spec import (
    CMD_LIMIT, CREATE_PROCESS_LIMIT, MAX_BASE64_CHARS, LaunchCommand, LaunchSpec,
    LaunchSpecError, build_cmd_command_line, decode_launch_spec, encode_launch_spec,
    prepare_encoded_host_command, prepare_host_command, utf16_units,
)


COMMAND = 'echo "private-command-marker" & echo %PATH% ^& !VALUE!\r\nexit /b 7'
CWD = r"C:\private-cwd-marker\workspace"
REPOSITORY = "private-repository-marker"
PYTHON = r"C:\Program Files\Python\python.exe"
HOST = r"C:\Private host folder\launch_host.py"
CMD = r"C:\Windows\System32\cmd.exe"
DEMAND = ResourceDemand(1.5, 512 << 20, 768 << 20, 1)


def units(value):
    """Independent UTF-16 oracle for complete command-line boundaries."""
    return len(value.encode("utf-16-le")) // 2


class LaunchSpecTests(unittest.TestCase):
    def spec(self, **changes):
        arguments = dict(command=COMMAND, cwd=CWD, repo_identifier=REPOSITORY,
                         requested=DEMAND, role=Role.BACKGROUND, priority=Priority.P2)
        return LaunchSpec(**(arguments | changes))

    def wire(self, **changes):
        value = dict(command=COMMAND, cwd=CWD, repo_identifier=REPOSITORY,
                     requested=dict(cpu_units=1.5, physical_bytes=512 << 20,
                                    commit_bytes=768 << 20, io_slots=1),
                     role="background", priority="P2", admission_timeout_sec=1800,
                     schema_version=1)
        return value | changes

    def encoded(self, value):
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return base64.b64encode(raw).decode("ascii")

    def assert_reason(self, reason, function, *args, **kwargs):
        with self.assertRaises(LaunchSpecError) as caught:
            function(*args, **kwargs)
        self.assertIsInstance(caught.exception, ValueError)
        self.assertEqual(caught.exception.reason, reason)
        return caught.exception

    def host_python_at_limit(self, target, *, encoded="Zg==", astral=False):
        base = r"C:\p.exe"
        baseline = units(subprocess.list2cmdline((base, HOST, "--launch-spec-b64", encoded))) + 1
        suffix = "\U0001f642" if astral else ""
        padding = target - baseline - units(suffix)
        self.assertGreaterEqual(padding, 0)
        return "C:\\" + suffix + "x" * padding + "p.exe"

    def test_frozen_defaults_and_typed_round_trip_preserve_sensitive_fields(self):
        spec = self.spec()
        self.assertEqual(spec.admission_timeout_sec, 1800)
        self.assertEqual(spec.schema_version, 1)
        with self.assertRaises(FrozenInstanceError):
            spec.command = "replacement"
        restored = decode_launch_spec(encode_launch_spec(spec))
        self.assertEqual(restored, spec)
        self.assertIs(type(restored.requested), ResourceDemand)
        self.assertIs(restored.role, Role.BACKGROUND)
        self.assertIs(restored.priority, Priority.P2)

    def test_encoder_emits_canonical_utf8_json_and_standard_base64(self):
        command = 'echo "繁體中文 \U0001f642"\nexit /b 0'
        spec = self.spec(command=command)
        expected = json.dumps(self.wire(command=command), ensure_ascii=False, allow_nan=False,
                              sort_keys=True, separators=(",", ":")).encode("utf-8")
        encoded = encode_launch_spec(spec)
        self.assertEqual(encoded, base64.b64encode(expected).decode("ascii"))
        self.assertEqual(base64.b64decode(encoded, validate=True), expected)
        self.assertEqual(decode_launch_spec(encoded).command, command)

    def test_command_preserves_quotes_newlines_shell_operators_and_environment_spelling(self):
        commands = (COMMAND, '"unterminated & echo x', "  echo a\n\necho b  ",
                    r'echo %PATH% !DELAYED! ^& (x) | y > "result"', "\t echo spaced\t")
        for command in commands:
            with self.subTest(command_kind=commands.index(command)):
                spec = self.spec(command=command)
                self.assertEqual(decode_launch_spec(encode_launch_spec(spec)).command, command)
                self.assertEqual(build_cmd_command_line(command, cmd_path=CMD),
                                 '"' + CMD + '" /d /s /c "' + command + '"')

    def test_command_character_limit_is_independent_of_utf16_host_limit(self):
        for character in ("x", "\U0001f642"):
            with self.subTest(astral=character != "x"):
                command = character * CREATE_PROCESS_LIMIT
                self.assertEqual(self.spec(command=command).command, command)
                self.assert_reason("launch_payload_invalid", self.spec, command=command + character)

    def test_invalid_command_inputs_are_rejected_without_coercion(self):
        for command in (None, 7, True, b"echo", "", "echo\0payload", "\ud800", "\udfff",
                        "\ud83d\ude42"):
            with self.subTest(kind=type(command).__name__):
                self.assert_reason("launch_payload_invalid", self.spec, command=command)

    def test_absolute_windows_path_spellings_are_preserved(self):
        paths = ("C:\\", "C:\\work folder\\", "C:/work/folder", r"\\server\share\folder",
                 r"\\?\C:\workspace", "C:\\工作\\\U0001f642")
        for cwd in paths:
            with self.subTest(cwd_kind=paths.index(cwd)):
                self.assertEqual(decode_launch_spec(encode_launch_spec(self.spec(cwd=cwd))).cwd, cwd)

    def test_relative_control_quoted_and_surrogate_paths_are_rejected(self):
        paths = (None, 3, "", "workspace", "C:workspace", r"\workspace", "/workspace",
                 'C:\\"quoted"', "C:\\tab\tpath", "C:\\new\nline", "C:\\nul\0tail",
                 "C:\\\ud800", "C:\\\udfff")
        for cwd in paths:
            with self.subTest(kind=type(cwd).__name__):
                self.assert_reason("launch_payload_invalid", self.spec, cwd=cwd)

    def test_repo_identifier_uses_existing_opaque_identifier_contract(self):
        for value in ("a", "repo.name:@-1", "x" * 128):
            self.assertEqual(self.spec(repo_identifier=value).repo_identifier, value)
        for value in ("", "x" * 129, "private repo", "repo/path", "repo\\path", "倉庫", None, 3):
            with self.subTest(kind=type(value).__name__):
                self.assert_reason("launch_payload_invalid", self.spec, repo_identifier=value)

    def test_schema_timeout_and_enum_constructor_types_are_exact(self):
        for value in (0, 1, (1 << 31) - 1):
            self.assertEqual(self.spec(admission_timeout_sec=value).admission_timeout_sec, value)
        cases = [("schema_version", value) for value in (True, 1.0, "1", 0, 2, None)]
        cases += [("admission_timeout_sec", value) for value in (True, 0.0, "1800", -1, 1 << 31, None)]
        cases += [("role", "background"), ("priority", "P2"), ("requested", DEMAND.to_dict())]
        for field, value in cases:
            with self.subTest(field=field, kind=type(value).__name__):
                self.assert_reason("launch_payload_invalid", self.spec, **{field: value})

    def test_all_supported_role_priority_and_timeout_values_round_trip(self):
        for role in Role:
            for priority in Priority:
                spec = self.spec(role=role, priority=priority, admission_timeout_sec=0)
                self.assertEqual(decode_launch_spec(encode_launch_spec(spec)), spec)
        spec = self.spec(admission_timeout_sec=(1 << 31) - 1)
        self.assertEqual(decode_launch_spec(encode_launch_spec(spec)), spec)

    def test_decoder_requires_all_and_only_declared_fields(self):
        value = self.wire()
        for field in value:
            with self.subTest(missing=field):
                candidate = dict(value)
                candidate.pop(field)
                self.assert_reason("launch_payload_invalid", decode_launch_spec, self.encoded(candidate))
        for field in ("wrapper_identity", "launch_authorized", "execution_timeout_sec", "unknown"):
            self.assert_reason("launch_payload_invalid", decode_launch_spec,
                               self.encoded(value | {field: True}))

    def test_decoder_rejects_duplicate_json_keys_and_malformed_documents(self):
        valid = json.dumps(self.wire(), separators=(",", ":"))
        documents = (valid[:-1] + ',"schema_version":1}',
                     valid.replace('"cpu_units":1.5', '"cpu_units":1.5,"cpu_units":2'),
                     "{", "[]", "null", "1", valid + "{}")
        for raw in documents:
            with self.subTest(document=documents.index(raw)):
                self.assert_reason("launch_payload_invalid", decode_launch_spec,
                                   base64.b64encode(raw.encode("utf-8")).decode("ascii"))
        self.assert_reason("launch_payload_invalid", decode_launch_spec,
                           base64.b64encode(b"\xff\xfe").decode("ascii"))

    def test_decoder_enforces_schema_enum_timeout_and_requested_types(self):
        cases = [("schema_version", value) for value in (True, 1.0, "1", 2)]
        cases += [("role", value) for value in (True, "admin", None)]
        cases += [("priority", value) for value in (2, "P4", None)]
        cases += [("admission_timeout_sec", value) for value in (-1, 1 << 31, True, 1.0)]
        cases += [("requested", value) for value in (None, [], "demand")]
        for field, value in cases:
            with self.subTest(field=field, kind=type(value).__name__):
                self.assert_reason("launch_payload_invalid", decode_launch_spec,
                                   self.encoded(self.wire(**{field: value})))

    def test_resource_demand_rejects_nonfinite_boolean_fractional_and_unknown_fields(self):
        demand = self.wire()["requested"]
        cases = [("cpu_units", value) for value in (True, -1, float("nan"), float("inf"), "1")]
        cases += [("physical_bytes", value) for value in (True, 1.5, -1, 1 << 63)]
        cases += [("commit_bytes", value) for value in (True, -1, 1 << 63)]
        cases += [("io_slots", value) for value in (True, .5, -1)]
        for field, value in cases:
            with self.subTest(field=field, kind=type(value).__name__):
                self.assert_reason("launch_payload_invalid", decode_launch_spec,
                                   self.encoded(self.wire(requested=demand | {field: value})))
        missing = dict(demand)
        missing.pop("commit_bytes")
        for value in (missing, demand | {"ram_gib": 1}):
            self.assert_reason("launch_payload_invalid", decode_launch_spec,
                               self.encoded(self.wire(requested=value)))

    def test_base64_rejects_whitespace_urlsafe_padding_and_nonzero_unused_bits(self):
        malformed = ("", "Zg", "Zg=", "Zg===", "====", "=Zg=", "Zg==\n", " Zg==",
                     "Z g==", "Zg==\r\n", "Zg==\u00a0", "-_8=", "é===", "Zh==", "Zm9=")
        for encoded in malformed:
            with self.subTest(case=malformed.index(encoded)):
                self.assert_reason("launch_payload_invalid", decode_launch_spec, encoded)
                self.assert_reason("launch_payload_invalid", prepare_encoded_host_command, encoded,
                                   python_executable=PYTHON, host_path=HOST)
        for encoded in (None, b"Zg==", True, 4):
            self.assert_reason("launch_payload_invalid", decode_launch_spec, encoded)

    def test_exact_json_byte_limit_and_one_over_with_same_base64_character_length(self):
        raw = json.dumps(self.wire(), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        exact = raw + b" " * (MAX_MESSAGE_BYTES - len(raw))
        encoded = base64.b64encode(exact).decode("ascii")
        self.assertEqual(len(encoded), MAX_BASE64_CHARS)
        self.assertEqual(decode_launch_spec(encoded), self.spec())
        oversized = base64.b64encode(exact + b" ").decode("ascii")
        self.assertEqual(len(oversized), MAX_BASE64_CHARS)
        self.assert_reason("launch_payload_too_large", decode_launch_spec, oversized)

    def test_base64_character_prebound_rejects_before_decode(self):
        oversized = "A" * (MAX_BASE64_CHARS + 4)
        with patch("sentinel.adaptive.launch_spec.base64.b64decode") as decoder:
            self.assert_reason("launch_payload_too_large", decode_launch_spec, oversized)
        decoder.assert_not_called()

    def test_encoder_bounds_escaped_json_bytes_and_rejects_non_spec_objects(self):
        # Every component satisfies its own character limit, but JSON escaping
        # plus UTF-8 path bytes exceeds the complete transport budget.
        spec = self.spec(command="\x01" * CREATE_PROCESS_LIMIT,
                         cwd="C:\\" + "\U0001f642" * (CREATE_PROCESS_LIMIT - 3))
        self.assert_reason("launch_payload_too_large", encode_launch_spec, spec)
        for value in (self.wire(), None, "payload"):
            self.assert_reason("launch_payload_invalid", encode_launch_spec, value)

    def test_utf16_unit_count_is_exact_for_bmp_astral_and_invalid_unicode(self):
        self.assertEqual(utf16_units(""), 0)
        self.assertEqual(utf16_units("A中"), 2)
        self.assertEqual(utf16_units("A\U0001f642中"), 4)
        for value in (None, b"A", True, "\ud800", "\udfff", "\ud83d\ude42"):
            self.assert_reason("launch_payload_invalid", utf16_units, value)

    def test_host_argv_has_fixed_structure_and_quotes_only_transport_arguments(self):
        spec = self.spec()
        encoded = encode_launch_spec(spec)
        result = prepare_host_command(spec, python_executable=PYTHON, host_path=HOST)
        self.assertIs(type(result), LaunchCommand)
        self.assertEqual(result.argv, (PYTHON, HOST, "--launch-spec-b64", encoded))
        self.assertEqual(result.command_line, subprocess.list2cmdline(result.argv))
        self.assertEqual(result.payload, encoded)
        self.assertEqual(result, prepare_encoded_host_command(encoded, python_executable=PYTHON, host_path=HOST))
        self.assertNotIn(COMMAND, result.command_line)

    def test_encoded_host_accepts_canonical_non_json_transport_without_claiming_schema_validity(self):
        for raw in (b"not JSON", b"\xfb\xff", b'{"other_test_schema":1}'):
            encoded = base64.b64encode(raw).decode("ascii")
            result = prepare_encoded_host_command(encoded, python_executable=PYTHON, host_path=HOST)
            self.assertEqual(result.payload, encoded)
            self.assert_reason("launch_payload_invalid", decode_launch_spec, encoded)

    def test_host_path_validation_rejects_relative_quotes_controls_and_surrogates(self):
        invalid = ("python.exe", "C:python.exe", r"\python.exe", 'C:\\bad"path.exe',
                   "C:\\bad\npath.exe", "C:\\\ud800", None)
        for field in ("python_executable", "host_path"):
            for value in invalid:
                arguments = dict(python_executable=PYTHON, host_path=HOST) | {field: value}
                with self.subTest(field=field, kind=type(value).__name__):
                    self.assert_reason("launch_payload_invalid", prepare_encoded_host_command, "Zg==", **arguments)

    def test_complete_host_limit_includes_quotes_astral_units_and_terminating_nul(self):
        self.assertEqual(CREATE_PROCESS_LIMIT, 32767)
        for astral in (False, True):
            with self.subTest(astral=astral):
                python = self.host_python_at_limit(CREATE_PROCESS_LIMIT, astral=astral)
                result = prepare_encoded_host_command("Zg==", python_executable=python, host_path=HOST)
                self.assertEqual(units(result.command_line) + 1, CREATE_PROCESS_LIMIT)
                self.assert_reason("launch_payload_too_large", prepare_encoded_host_command, "Zg==",
                                   python_executable=python + "x", host_path=HOST)

    def test_oversized_host_rejection_precedes_base64_format_validation(self):
        with patch("sentinel.adaptive.launch_spec.base64.b64decode") as decoder:
            self.assert_reason("launch_payload_too_large", prepare_encoded_host_command,
                               "!" * CREATE_PROCESS_LIMIT, python_executable=PYTHON, host_path=HOST)
            python = self.host_python_at_limit(CREATE_PROCESS_LIMIT + 1, encoded="!!!!")
            self.assert_reason("launch_payload_too_large", prepare_encoded_host_command, "!!!!",
                               python_executable=python, host_path=HOST)
        decoder.assert_not_called()

    def test_cmd_path_is_exact_absolute_cmd_exe_with_case_insensitive_basename(self):
        cmd = r"C:\Private folder\CMD.EXE"
        self.assertEqual(build_cmd_command_line(COMMAND, cmd_path=cmd),
                         '"' + cmd + '" /d /s /c "' + COMMAND + '"')
        for path in ("cmd.exe", "C:cmd.exe", r"\cmd.exe", r"C:\Windows\powershell.exe",
                     r"C:\Windows\cmd.exe.extra", 'C:\\bad"folder\\cmd.exe', "C:\\bad\ncmd.exe"):
            self.assert_reason("cmd_payload_too_large_or_invalid", build_cmd_command_line, "echo x", cmd_path=path)

    def test_cmd_complete_literal_limit_counts_astral_units_and_wrapper_characters(self):
        self.assertEqual(CMD_LIMIT, 8191)
        available = CMD_LIMIT - units('"' + CMD + '" /d /s /c ""')
        for prefix in ("", "\U0001f642"):
            with self.subTest(astral=bool(prefix)):
                command = prefix + "x" * (available - units(prefix))
                line = build_cmd_command_line(command, cmd_path=CMD)
                self.assertEqual(units(line), CMD_LIMIT)
                self.assert_reason("cmd_payload_too_large_or_invalid", build_cmd_command_line,
                                   command + "x", cmd_path=CMD)

    def test_cmd_invalid_input_uses_one_sanitized_error_reason(self):
        for command in (None, b"echo", "", "echo\0secret", "\ud800", "x" * (CREATE_PROCESS_LIMIT + 1)):
            self.assert_reason("cmd_payload_too_large_or_invalid", build_cmd_command_line, command, cmd_path=CMD)

    def test_sensitive_spec_and_host_fields_are_excluded_from_repr(self):
        spec = self.spec()
        host = prepare_host_command(spec, python_executable=PYTHON, host_path=HOST)
        visible = repr(spec) + repr(host) + repr([spec, host])
        for value in (COMMAND, CWD, REPOSITORY, PYTHON, HOST, host.payload, host.command_line):
            self.assertNotIn(value, visible)

    def test_validation_errors_and_tracebacks_do_not_echo_private_values(self):
        calls = ((self.spec, (), {"command": COMMAND + "\0"}),
                 (self.spec, (), {"cwd": CWD + '"'}),
                 (self.spec, (), {"repo_identifier": REPOSITORY + " bad"}),
                 (decode_launch_spec, (self.encoded(self.wire(schema_version=99)),), {}),
                 (build_cmd_command_line, (COMMAND + "\0",), {"cmd_path": CMD}))
        for function, args, kwargs in calls:
            try:
                function(*args, **kwargs)
            except LaunchSpecError as error:
                visible = repr(error) + str(error) + "".join(traceback.format_exception(error))
                for marker in ("private-command-marker", "private-cwd-marker", REPOSITORY):
                    self.assertNotIn(marker, visible)
            else:
                self.fail("invalid private input was accepted")


if __name__ == "__main__":
    unittest.main()
