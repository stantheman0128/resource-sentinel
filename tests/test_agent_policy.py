import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from sentinel.policy import agent_policy
from tests.test_hooks import load_script

class SharedAgentPolicyTests(unittest.TestCase):
    def test_missing_telemetry_still_publishes_shared_authorization_policy(self):
        hook = load_script("sentinel_policy_inject", "hooks/sentinel-inject.py")
        output = io.StringIO()
        with patch.object(hook, "register_session"), patch.object(hook, "load", return_value=None), \
             patch("sys.stdin", io.StringIO("{}")), redirect_stdout(output):
            hook.main()
        self.assertEqual(output.getvalue().strip(), agent_policy())

    def test_stale_telemetry_does_not_hide_authorization_policy(self):
        hook = load_script("sentinel_policy_stale", "hooks/sentinel-inject.py")
        output = io.StringIO()
        with patch.object(hook, "register_session"), patch.object(hook, "load", return_value={"generated_at": "2000-01-01 00:00:00"}), \
             patch("sys.stdin", io.StringIO("{}")), redirect_stdout(output):
            hook.main()
        self.assertIn(agent_policy(), output.getvalue())
        self.assertIn("監控失效", output.getvalue())

    def test_active_grant_suppresses_conflicting_red_warning(self):
        hook = load_script("sentinel_policy_red", "hooks/sentinel-inject.py")
        from datetime import datetime
        status = {"generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "light": "RED"}
        output = io.StringIO()
        with patch.object(hook, "register_session"), patch.object(hook, "load", return_value=status), \
             patch.object(hook, "process_chain", return_value=[(123, 456)]), \
             patch.object(hook, "Exemptions") as store, \
             patch("sys.stdin", io.StringIO("{}")), redirect_stdout(output):
            store.return_value.match.return_value = {"id": "test", "expires_at": 2000000000}
            hook.main()
        self.assertIn("使用者已授權", output.getvalue())
        self.assertNotIn("不要啟動 build", output.getvalue())


if __name__ == "__main__":
    unittest.main()
