"""Synthetic receipt binding, not evidence that any native launch passed."""
from dataclasses import replace
from types import SimpleNamespace
import unittest

from sentinel.adaptive.launch_scope import MeasuredLaunchTopologies, RetainedLaunchProvenance, RetainedLaunchScopeSource
from sentinel.adaptive.launch_topology import OriginalLaunchProvenance
from sentinel.adaptive.store import LifecycleError
from tests.test_adaptive_launch_topology import topology, identity


EXECUTION = "aeb9d5b5-89a9-4191-9e4f-6059e1ee0d13"


class LaunchScopeTests(unittest.TestCase):
    def setUp(self):
        self.binding = dict(execution_id=EXECUTION, config_revision="a" * 64,
            host_fingerprint="b" * 64, bundle_sha256="c" * 64)
        self.proof = OriginalLaunchProvenance(identity(2, 200), identity(1, 100), identity(3, 300), topology())
        self.retained = RetainedLaunchProvenance(EXECUTION, "d" * 32, self.proof)
        self.measured = MeasuredLaunchTopologies("a" * 64, "b" * 64, "c" * 64, (topology(),))
        self.owner = SimpleNamespace(launch_provenance_for=lambda execution_id: self.retained)
        self.authority = SimpleNamespace(prepared_launch_topologies=lambda: self.measured)
        self.source = RetainedLaunchScopeSource(owner=self.owner, authority=self.authority)

    def test_equal_actual_observations_produce_hashes_internally(self):
        receipt = self.source(**self.binding)
        self.assertEqual(receipt.measured_topology_sha256, topology().sha256)
        self.assertEqual(receipt.actual_topology_sha256, topology().sha256)

    def test_changed_stdio_codepage_parent_binary_or_flags_not_certified(self):
        for changes in ({"console_output_cp": 437}, {"shell_image_sha256": "e" * 64},
                        {"stdio_types": ("disk", "console", "character")}):
            self.retained = replace(self.retained, provenance=replace(self.proof, topology=replace(topology(), **changes)))
            with self.subTest(changes=changes), self.assertRaises(LifecycleError):
                self.source(**self.binding)

    def test_unprepared_or_reconstructed_dict_is_not_a_receipt(self):
        self.measured = None
        with self.assertRaises(LifecycleError):
            self.source(**self.binding)
        self.measured = self.proof.to_dict()
        with self.assertRaises(LifecycleError):
            self.source(**self.binding)

    def test_other_bundle_profile_host_or_execution_refuses(self):
        for name in self.binding:
            value = "feb9d5b5-89a9-4191-9e4f-6059e1ee0d13" if name == "execution_id" else "f" * 64
            with self.subTest(name=name), self.assertRaises(LifecycleError):
                self.source(**(self.binding | {name: value}))

    def test_replacement_guardian_missing_original_custody_refuses(self):
        self.retained = None
        with self.assertRaises(LifecycleError):
            self.source(**self.binding)

    def test_unsupported_immediate_parent_cannot_be_measured_as_shell(self):
        with self.assertRaises(LifecycleError):
            replace(self.measured, topologies=(replace(topology(), shell_kind="other"),))


if __name__ == "__main__":
    unittest.main()
