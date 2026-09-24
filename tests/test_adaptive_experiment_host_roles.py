"""Pure role-schema evidence, not authentication/dispatch/native readiness."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import Priority, ResourceDemand, Role
from sentinel.adaptive.experiment_host_roles import (
    DOMAIN, MAX_HELPER_ITERATIONS, MAX_ROLE_SPEC_BYTES, MAX_WRAPPER_WAIT_SEC,
    ExperimentRoleSpecError, GuardianRoleSpec, HelperRoleSpec, WrapperRoleSpec,
    role_spec_from_dict, role_spec_from_json,
)
from sentinel.adaptive.launch_spec import LaunchSpec


def uid(number):
    return f"00000000-0000-4000-8000-{number:012x}"


def guardian():
    return GuardianRoleSpec(member_id=uid(1), data_dir=r"C:\private\isolated",
        journal_dir=r"C:\private\journal", profile_path=r"C:\private\shadow.json",
        profile_sha256="a" * 64, guardian_epoch="isolated.epoch-1",
        launch_instance_id=uid(11), query_instance_id=uid(12),
        control_instance_id=uid(13), instance_id=uid(14),
        operator_instance_id=uid(15), policy_instance_id=uid(16))


def wrapper():
    spec = LaunchSpec(command='echo "private value" && echo 測試\nexit /b 7',
        cwd=r"C:\private\work", repo_identifier="private-repo",
        requested=ResourceDemand(.25, 32 << 20, 64 << 20, 0),
        role=Role.BACKGROUND, priority=Priority.P2, admission_timeout_sec=60)
    return WrapperRoleSpec(member_id=uid(2), data_dir=r"C:\private\isolated",
        launch_spec=spec, workload_member_id=uid(3), guardian_member_id=uid(1))


def helper():
    return HelperRoleSpec(member_id=uid(4), data_dir=r"C:\private\isolated",
        profile_path=r"C:\private\shadow.json", profile_sha256="a" * 64,
        iterations=300)


class ExperimentHostRoleTests(unittest.TestCase):
    def test_all_fixed_roles_roundtrip_through_typed_and_union_decoders(self):
        for original in (guardian(), wrapper(), helper()):
            with self.subTest(role=original.role):
                self.assertEqual(type(original).from_dict(original.to_dict()), original)
                self.assertEqual(type(original).from_json(original.to_json()), original)
                self.assertEqual(role_spec_from_dict(original.to_dict()), original)
                self.assertEqual(role_spec_from_json(original.to_json().encode("ascii")), original)
                self.assertEqual(original.sha256,
                    hashlib.sha256(original.to_json().encode("ascii")).hexdigest())

    def test_serialized_object_order_and_json_whitespace_do_not_change_plan_hash(self):
        original = guardian()
        reversed_fields = dict(reversed(list(original.to_dict().items())))
        parsed = role_spec_from_json(json.dumps(reversed_fields, indent=2))
        self.assertEqual(parsed.to_json(), original.to_json())
        self.assertEqual(parsed.sha256, original.sha256)
        self.assertIn('"domain":"' + DOMAIN + '"', original.to_json())

    def test_each_guardian_constructor_input_changes_bound_hash(self):
        original = guardian()
        changes = dict(member_id=uid(101), data_dir=r"C:\different\isolated",
            journal_dir=r"C:\different\journal", profile_path=r"C:\different\shadow.json",
            profile_sha256="b" * 64, guardian_epoch="isolated.epoch-2",
            launch_instance_id=uid(111), query_instance_id=uid(112),
            control_instance_id=uid(113), instance_id=uid(114),
            operator_instance_id=uid(115), policy_instance_id=uid(116), rpc_timeout_ms=101)
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(replace(original, **{field: value}).sha256, original.sha256)

    def test_wrapper_command_resources_and_declared_references_are_exactly_bound(self):
        original = wrapper()
        for changed in (replace(original, workload_member_id=uid(7)),
                        replace(original, guardian_member_id=uid(8)),
                        replace(original, max_wait_sec=12),
                        replace(original, launch_spec=replace(original.launch_spec,
                            command=original.launch_spec.command + " ")),
                        replace(original, launch_spec=replace(original.launch_spec,
                            requested=ResourceDemand(.5, 32 << 20, 64 << 20, 0)))):
            self.assertNotEqual(changed.sha256, original.sha256)
        parsed = role_spec_from_json(original.to_json())
        self.assertEqual(parsed.launch_spec.command, original.launch_spec.command)
        self.assertEqual(parsed.launch_spec.requested, original.launch_spec.requested)
        self.assertIs(type(parsed.launch_spec), LaunchSpec)

    def test_helper_profile_and_finite_run_inputs_change_hash(self):
        original = helper()
        for changes in (dict(profile_sha256="b" * 64), dict(profile_path=r"C:\other.json"),
                        dict(enroll_every_ticks=6), dict(report_every_ticks=11),
                        dict(iterations=301)):
            self.assertNotEqual(replace(original, **changes).sha256, original.sha256)

    def test_missing_or_extra_fields_are_rejected_for_every_role(self):
        for original in (guardian(), wrapper(), helper()):
            fields = original.to_dict()
            for missing in fields:
                with self.subTest(role=original.role, missing=missing):
                    altered = dict(fields)
                    del altered[missing]
                    with self.assertRaises(ExperimentRoleSpecError):
                        role_spec_from_dict(altered)
            with self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(fields | {"factory": "arbitrary.callback"})

    def test_cross_role_and_unsupported_supervisor_dispatch_are_rejected(self):
        with self.assertRaises(ExperimentRoleSpecError):
            GuardianRoleSpec.from_dict(helper().to_dict())
        for role in ("supervisor", "caller", "readiness_keeper", "active", None, True):
            with self.subTest(role=role), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(helper().to_dict() | {"role": role})
        with self.assertRaises(ExperimentRoleSpecError):
            role_spec_from_dict(helper().to_dict() | {"domain": DOMAIN + "-other"})

    def test_no_serialized_dynamic_guardian_identity_or_authority_fields(self):
        for field in ("guardian_pid", "guardian_created_filetime_100ns", "guardian_epoch",
                      "endpoint_instance_id", "ready", "parent_binding", "released",
                      "status_path", "config_path", "launcher_factory"):
            with self.subTest(field=field), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(wrapper().to_dict() | {field: 1})

    def test_helper_cannot_select_active_mode_or_control_parameters(self):
        for field, value in (("mode", "active"), ("mode", "shadow"),
                             ("target_rate", 10), ("control_purpose", "isolated_canary"),
                             ("evidence_sha256", "f" * 64), ("open_job", "callback")):
            with self.subTest(field=field), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(helper().to_dict() | {field: value})

    def test_exact_integer_bounds_reject_booleans_floats_and_unbounded_runs(self):
        cases = ((guardian(), "rpc_timeout_ms", 1, 1000),
                 (wrapper(), "rpc_timeout_ms", 1, 1000),
                 (wrapper(), "poll_interval_ms", 1, 1000),
                 (wrapper(), "max_wait_sec", 1, MAX_WRAPPER_WAIT_SEC),
                 (helper(), "enroll_every_ticks", 1, 3600),
                 (helper(), "report_every_ticks", 1, 3600),
                 (helper(), "iterations", 1, MAX_HELPER_ITERATIONS))
        for original, field, low, high in cases:
            for bad in (True, 1.0, "1", None, low - 1, high + 1):
                with self.subTest(role=original.role, field=field, bad=bad):
                    with self.assertRaises(ExperimentRoleSpecError):
                        replace(original, **{field: bad})
            self.assertEqual(getattr(replace(original, **{field: low}), field), low)
            self.assertEqual(getattr(replace(original, **{field: high}), field), high)

    def test_strict_uuid_hash_and_epoch_contracts(self):
        original = guardian()
        for changes in (dict(member_id="not-a-uuid"), dict(instance_id=True),
                        dict(query_instance_id=original.launch_instance_id),
                        dict(policy_instance_id=original.instance_id),
                        dict(profile_sha256="A" * 64), dict(profile_sha256="a" * 63),
                        dict(guardian_epoch="has space"), dict(guardian_epoch="x" * 129)):
            with self.subTest(changes=changes), self.assertRaises(ExperimentRoleSpecError):
                replace(original, **changes)

    def test_wrapper_actor_workload_and_guardian_are_distinct_canonical_references(self):
        original = wrapper()
        for changes in (dict(workload_member_id=original.member_id),
                        dict(guardian_member_id=original.member_id),
                        dict(guardian_member_id=original.workload_member_id),
                        dict(guardian_member_id="1"), dict(workload_member_id=False)):
            with self.subTest(changes=changes), self.assertRaises(ExperimentRoleSpecError):
                replace(original, **changes)

    def test_nil_uuid_is_rejected_before_actual_ledger_pipe_or_policy_consumption(self):
        nil = "00000000-0000-0000-0000-000000000000"
        cases = ((guardian(), ("member_id", "launch_instance_id", "query_instance_id",
                              "control_instance_id", "instance_id", "operator_instance_id",
                              "policy_instance_id")),
                 (wrapper(), ("member_id", "workload_member_id", "guardian_member_id")),
                 (helper(), ("member_id",)))
        for original, names in cases:
            for name in names:
                with self.subTest(role=original.role, field=name):
                    with self.assertRaises(ExperimentRoleSpecError):
                        replace(original, **{name: nil})
                    with self.assertRaises(ExperimentRoleSpecError):
                        role_spec_from_dict(original.to_dict() | {name: nil})

    def test_paths_are_strict_absolute_spelling_without_normalizing_plan_input(self):
        for bad in ("relative", r"C:relative", "C:\\private\\..\\elsewhere",
                    "C:/private/isolated", "C:\\bad\nname", "C:\\bad\0name", None, 1):
            with self.subTest(path=bad), self.assertRaises(ExperimentRoleSpecError):
                replace(helper(), data_dir=bad)
        unc = replace(helper(), data_dir=r"\\server\share\isolated")
        self.assertEqual(role_spec_from_json(unc.to_json()), unc)

    def test_existing_launch_spec_demand_and_enum_validation_is_used(self):
        original = wrapper().to_dict()
        for name, bad in (("cpu_units", float("nan")), ("physical_bytes", True),
                          ("commit_bytes", -1), ("io_slots", 1.5)):
            data = json.loads(json.dumps(original))
            data["launch_spec"]["requested"][name] = bad
            with self.subTest(name=name), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(data)
        for name, bad in (("priority", "P9"), ("role", "unmanaged"),
                          ("admission_timeout_sec", True), ("command", "bad\0command")):
            data = json.loads(json.dumps(original))
            data["launch_spec"][name] = bad
            with self.subTest(name=name), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_dict(data)
        with self.assertRaises(ExperimentRoleSpecError):
            replace(wrapper(), launch_spec=wrapper().launch_spec.to_dict())

    def test_json_duplicates_nonfinite_numbers_and_nonobjects_are_rejected(self):
        duplicate = helper().to_json().replace('"iterations":300', '"iterations":1,"iterations":300')
        for payload in (duplicate, '{"role":"helper","iterations":NaN}', "[]", "null",
                        "{", b"\xff", True):
            with self.subTest(payload=payload), self.assertRaises(ExperimentRoleSpecError):
                role_spec_from_json(payload)

    def test_byte_bound_applies_to_input_and_canonical_non_ascii_representation(self):
        with self.assertRaisesRegex(ExperimentRoleSpecError, "too_large"):
            role_spec_from_json(b" " * (MAX_ROLE_SPEC_BYTES + 1))
        # LaunchSpec itself permits this command. Its private canonical role
        # envelope exceeds the smaller bootstrap/plan per-role byte bound.
        large = replace(wrapper().launch_spec, command="測" * 15000)
        with self.assertRaisesRegex(ExperimentRoleSpecError, "too_large"):
            replace(wrapper(), launch_spec=large)

    def test_parse_and_hash_do_not_open_files_stat_or_spawn(self):
        encoded = tuple(item.to_json() for item in (guardian(), wrapper(), helper()))
        with patch("builtins.open", side_effect=AssertionError("file IO")), \
                patch("os.open", side_effect=AssertionError("file IO")), \
                patch("pathlib.Path.stat", side_effect=AssertionError("stat")), \
                patch("subprocess.Popen", side_effect=AssertionError("process creation")):
            for payload in encoded:
                restored = role_spec_from_json(payload)
                self.assertEqual(restored.to_json(), payload)
                self.assertEqual(len(restored.sha256), 64)

    def test_data_is_frozen_and_private_launch_values_are_absent_from_repr_errors(self):
        original = wrapper()
        with self.assertRaises(FrozenInstanceError):
            original.max_wait_sec = 12
        for value in (original.data_dir, original.launch_spec.command,
                      original.launch_spec.cwd, original.launch_spec.repo_identifier):
            self.assertNotIn(value, repr(original))
        with self.assertRaises(ExperimentRoleSpecError) as caught:
            role_spec_from_dict(original.to_dict() | {"private-extra": original.launch_spec.command})
        self.assertEqual(str(caught.exception), "experiment_role_invalid")


if __name__ == "__main__":
    unittest.main()
