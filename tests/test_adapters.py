import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.adapters import (
    AdapterConfigurationError,
    ConfiguredHttpAdapter,
    HttpAdapterConfig,
    HttpResponse,
    LocalCommandAdapter,
    PersistentLocalCommandAdapter,
    ManualAdapter,
    default_adapters,
)


class LocalCommandAdapterTests(unittest.TestCase):
    def test_argv_execution_lifecycle_and_json_output(self):
        adapter = LocalCommandAdapter()
        submitted = adapter.submit(
            {
                "task_id": "hello",
                "argv": [sys.executable, "-c", "print('hello adapter')"],
                "timeout_seconds": 5,
            }
        )
        self.assertIn(submitted["status"], {"RUNNING", "SUCCEEDED"})
        result = adapter.collect_result(submitted["job_id"], wait=True, timeout=5)
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["outcome"], "SUCCEEDED")
        self.assertIn("hello adapter", result["stdout"])
        json.dumps(result)

    def test_string_command_requires_explicit_shell(self):
        adapter = LocalCommandAdapter()
        with self.assertRaises(AdapterConfigurationError):
            adapter.submit({"command": "echo unsafe-by-default"})

    def test_explicit_shell_is_supported(self):
        adapter = LocalCommandAdapter()
        command = "echo explicit-shell"
        result = adapter.submit({"command": command, "shell": True})
        collected = adapter.collect_result(result["job_id"], wait=True, timeout=5)
        self.assertEqual(collected["status"], "SUCCEEDED")
        self.assertIn("explicit-shell", collected["stdout"])

    def test_timeout_is_failed_with_timed_out_outcome(self):
        adapter = LocalCommandAdapter()
        result = adapter.submit(
            {
                "argv": [sys.executable, "-c", "import time; time.sleep(10)"],
                "timeout_seconds": 0.05,
            }
        )
        deadline = time.time() + 5
        status = adapter.status(result["job_id"])
        while status["outcome"] != "TIMED_OUT" and time.time() < deadline:
            time.sleep(0.02)
            status = adapter.status(result["job_id"])
        self.assertEqual(status["status"], "FAILED")
        self.assertEqual(status["outcome"], "TIMED_OUT")

    def test_cancel(self):
        adapter = LocalCommandAdapter()
        submitted = adapter.submit(
            {"argv": [sys.executable, "-c", "import time; time.sleep(10)"]}
        )
        cancelled = adapter.cancel(submitted["job_id"])
        self.assertEqual(cancelled["status"], "CANCELLED")

    def test_secret_is_referenced_by_environment_name(self):
        adapter = LocalCommandAdapter()
        with patch.dict(os.environ, {"SENTINEL_TEST_SOURCE": "not-returned"}):
            submitted = adapter.submit(
                {
                    "argv": [
                        sys.executable,
                        "-c",
                        "import os; print('present=' + str(bool(os.getenv('CHILD_TOKEN'))))",
                    ],
                    "env_refs": {"CHILD_TOKEN": "SENTINEL_TEST_SOURCE"},
                }
            )
            result = adapter.collect_result(submitted["job_id"], wait=True, timeout=5)
        self.assertIn("present=True", result["stdout"])
        self.assertNotIn("not-returned", json.dumps(result))

    def test_unreferenced_parent_secret_is_not_inherited(self):
        adapter = LocalCommandAdapter()
        with patch.dict(os.environ, {"UNREFERENCED_PARENT_SECRET": "must-not-cross"}):
            submitted = adapter.submit({
                "argv": [
                    sys.executable, "-c",
                    "import os; print(os.getenv('UNREFERENCED_PARENT_SECRET', 'absent'))",
                ],
            })
            result = adapter.collect_result(submitted["job_id"], wait=True, timeout=5)
        self.assertEqual(result["stdout"].strip(), "absent")


class PersistentLocalCommandAdapterTests(unittest.TestCase):
    def test_new_adapter_instance_reconciles_detached_job(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            first = PersistentLocalCommandAdapter(temp)
            submitted = first.submit({
                "task_id": "restart-safe",
                "argv": [sys.executable, "-c", "import time; time.sleep(.15); print('persisted-ok')"],
                "timeout_seconds": 5,
            })
            restarted = PersistentLocalCommandAdapter(temp)
            deadline = time.time() + 5
            status = restarted.status(submitted["job_id"])
            while status["status"] == "RUNNING" and time.time() < deadline:
                time.sleep(0.03)
                status = restarted.status(submitted["job_id"])
            result = restarted.collect_result(submitted["job_id"])
            self.assertEqual(result["status"], "SUCCEEDED", result)
            self.assertIn("persisted-ok", result["stdout"])
            self.assertTrue(result["metrics_available"], result)
            self.assertGreaterEqual(result["duration_seconds"], 0.1)
            self.assertGreater(result["peak_working_set_gib"], 0)
            self.assertGreaterEqual(result["metric_samples"], 1)

    def test_job_state_does_not_persist_command_or_secret_values(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            adapter = PersistentLocalCommandAdapter(temp)
            with patch.dict(os.environ, {"PERSIST_SOURCE": "very-secret-value"}):
                submitted = adapter.submit({
                    "task_id": "no-secrets-on-disk",
                    "argv": [sys.executable, "-c", "import time; time.sleep(.2)"],
                    "env_refs": {"CHILD_TOKEN": "PERSIST_SOURCE"},
                })
            job_dir = Path(temp) / submitted["job_id"]
            persisted = "".join(
                path.read_text(encoding="utf-8", errors="ignore")
                for path in job_dir.iterdir() if path.suffix == ".json"
            )
            self.assertNotIn("very-secret-value", persisted)
            self.assertNotIn("time.sleep", persisted)
            adapter.cancel(submitted["job_id"])

    def test_persistent_output_is_bounded_while_job_runs(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as temp:
            adapter = PersistentLocalCommandAdapter(temp, max_output_bytes=1024)
            submitted = adapter.submit({
                "task_id": "bounded-output",
                "argv": [sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"],
                "timeout_seconds": 5,
            })
            deadline = time.time() + 5
            result = adapter.collect_result(submitted["job_id"])
            while result["status"] == "RUNNING" and time.time() < deadline:
                time.sleep(0.03)
                result = adapter.collect_result(submitted["job_id"])
            self.assertEqual(result["status"], "SUCCEEDED", result)
            self.assertTrue(result["output_truncated"], result)
            self.assertEqual(len(result["stdout"].encode("utf-8")), 1024)
            self.assertGreaterEqual(result["stdout_total_bytes"], 200000)


class ManualAdapterTests(unittest.TestCase):
    def test_manual_adapter_truthfully_awaits_human(self):
        adapter = ManualAdapter("grok", instructions="Dispatch in Grok UI")
        submitted = adapter.submit({"task_id": "manual-1"}, {"id": "grok-cloud"})
        self.assertEqual(submitted["status"], "AWAITING_MANUAL")
        self.assertEqual(submitted["worker_id"], "grok-cloud")
        self.assertFalse(adapter.probe()["available"])
        recorded = adapter.record_result(submitted["job_id"], {"diff": "abc"})
        self.assertEqual(recorded["status"], "SUCCEEDED")
        self.assertEqual(adapter.collect_result(submitted["job_id"])["result"]["diff"], "abc")

    def test_default_registry_only_automates_local_execution(self):
        adapters = default_adapters()
        self.assertIsInstance(adapters["local"], LocalCommandAdapter)
        self.assertIsInstance(adapters["cursor"], ManualAdapter)
        self.assertEqual(
            adapters["github_actions"].submit({"task_id": "cloud"})["status"],
            "AWAITING_MANUAL",
        )


class FakeTransport:
    def __init__(self):
        self.calls = []

    def request(self, **request):
        self.calls.append(request)
        path = request["url"]
        method = request["method"]
        if path.endswith("/probe"):
            return HttpResponse(200, {"ok": True})
        if path.endswith("/jobs") and method == "POST":
            return HttpResponse(202, {"job": {"id": "remote-42", "state": "queued"}})
        if path.endswith("/jobs/remote-42/cancel"):
            return HttpResponse(200, {"state": "cancelled"})
        if path.endswith("/jobs/remote-42/result"):
            return HttpResponse(
                200,
                {"state": "completed", "output": {"artifact": "artifact.zip"}},
            )
        if path.endswith("/jobs/remote-42"):
            return HttpResponse(200, {"state": "running"})
        return HttpResponse(404, {})


def http_config(**overrides):
    values = {
        "provider": "example-cloud",
        "base_url": "https://provider.invalid/api/",
        "credential_env_var": "EXAMPLE_PROVIDER_TOKEN",
        "endpoints": {
            "probe": {"method": "GET", "path": "probe"},
            "submit": {"method": "POST", "path": "jobs"},
            "status": {"method": "GET", "path": "jobs/{job_id}"},
            "cancel": {"method": "POST", "path": "jobs/{job_id}/cancel"},
            "collect_result": {"method": "GET", "path": "jobs/{job_id}/result"},
        },
        "id_field": "job.id",
        "status_field": "state",
        "result_field": "output",
    }
    values.update(overrides)
    return HttpAdapterConfig(**values)


class ConfiguredHttpAdapterTests(unittest.TestCase):
    def test_default_has_no_network_transport_and_requires_manual_action(self):
        adapter = ConfiguredHttpAdapter(http_config())
        submitted = adapter.submit({"task_id": "no-network"})
        self.assertEqual(submitted["status"], "AWAITING_MANUAL")
        self.assertEqual(submitted["message"], "transport_not_configured")
        self.assertFalse(adapter.probe()["available"])

    def test_injected_transport_drives_complete_lifecycle(self):
        transport = FakeTransport()
        adapter = ConfiguredHttpAdapter(http_config(), transport=transport)
        with patch.dict(os.environ, {"EXAMPLE_PROVIDER_TOKEN": "test-secret"}):
            self.assertTrue(adapter.probe()["available"])
            submitted = adapter.submit({"task_id": "cloud-1", "prompt": "do work"})
            self.assertEqual(submitted["job_id"], "remote-42")
            self.assertEqual(submitted["status"], "QUEUED")
            self.assertEqual(adapter.status("remote-42")["status"], "RUNNING")
            result = adapter.collect_result("remote-42")
        self.assertEqual(result["status"], "SUCCEEDED")
        self.assertEqual(result["result"]["artifact"], "artifact.zip")
        self.assertTrue(any(call["headers"]["Authorization"] == "Bearer test-secret" for call in transport.calls))
        self.assertEqual(adapter.capabilities()["credential_env_var"], "EXAMPLE_PROVIDER_TOKEN")
        self.assertNotIn("test-secret", json.dumps(adapter.capabilities()))
        json.dumps(result)

    def test_cancel_with_injected_transport(self):
        transport = FakeTransport()
        adapter = ConfiguredHttpAdapter(http_config(), transport=transport)
        with patch.dict(os.environ, {"EXAMPLE_PROVIDER_TOKEN": "test-secret"}):
            submitted = adapter.submit({"task_id": "cloud-2"})
            cancelled = adapter.cancel(submitted["job_id"])
        self.assertEqual(cancelled["status"], "CANCELLED")

    def test_http_adapter_reconstructs_external_job_after_restart(self):
        transport = FakeTransport()
        with patch.dict(os.environ, {"EXAMPLE_PROVIDER_TOKEN": "test-secret"}):
            first = ConfiguredHttpAdapter(http_config(), transport=transport)
            submitted = first.submit({"task_id": "restart-http"})
            restarted = ConfiguredHttpAdapter(http_config(), transport=transport)
            status = restarted.status(submitted["job_id"])
        self.assertEqual(status["status"], "RUNNING")
        self.assertEqual(status["external_job_id"], "remote-42")

    def test_submit_forwards_dispatch_key_as_idempotency_header(self):
        transport = FakeTransport()
        with patch.dict(os.environ, {"EXAMPLE_PROVIDER_TOKEN": "test-secret"}):
            adapter = ConfiguredHttpAdapter(http_config(), transport=transport)
            adapter.submit({"task_id": "idempotent", "job_id": "dispatch-key-1"})
        submit_call = next(call for call in transport.calls if call["method"] == "POST")
        self.assertEqual(submit_call["headers"]["Idempotency-Key"], "dispatch-key-1")

    def test_missing_credential_does_not_call_transport(self):
        transport = FakeTransport()
        adapter = ConfiguredHttpAdapter(http_config(), transport=transport)
        with patch.dict(os.environ, {}, clear=True):
            submitted = adapter.submit({"task_id": "auth-missing"})
        self.assertEqual(submitted["status"], "AWAITING_MANUAL")
        self.assertIn("credential_environment_variable_missing", submitted["message"])
        self.assertEqual(transport.calls, [])

    def test_config_rejects_secret_literal_in_environment_name_field(self):
        with self.assertRaises(AdapterConfigurationError):
            http_config(credential_env_var="sk-secret-literal")


if __name__ == "__main__":
    unittest.main()
