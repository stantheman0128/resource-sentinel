import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sentinel.guardian import providers as PV

ROOT = Path(__file__).resolve().parents[1]
CLAUDE_APP = r"C:\Program Files\WindowsApps\Claude_2.31226.1.0_x64__pzs8sxrjxfjjc\app\claude.exe"
CLAUDE_EMBEDDED = r"C:\Users\x\AppData\Roaming\Claude\claude-code\2.1.295\d2e29494ec83\claude.exe"
CLAUDE_CLI = r"C:\Users\x\.local\bin\claude.exe"
CURSOR_NODE = r"C:\Users\x\AppData\Local\cursor-agent\versions\2026.10.01\node.exe"
PLAIN_NODE = r"C:\Program Files\nodejs\node.exe"
AGY_CLI = r"C:\Users\x\AppData\Local\Microsoft\WinGet\Packages\Google.AntigravityCLI_x\agy.exe"
AGY_APP = r"C:\Users\x\AppData\Local\Programs\Antigravity\Antigravity.exe"


def tree(*rows):
    """rows: (pid, ppid, image, path) -> (process table, image_path function)."""
    table = {pid: (ppid, image) for pid, ppid, image, _ in rows}
    paths = {pid: path for pid, _, _, path in rows}
    return table, paths.get


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_hook():
    return load("hooks/guardian-adopt.py", "guardian_adopt_hook")


class ProtectedAppTests(unittest.TestCase):
    def test_desktop_apps_are_recognised(self):
        self.assertEqual(PV.protected_app("ChatGPT.exe", r"C:\x\ChatGPT.exe"), "Codex app")
        self.assertEqual(PV.protected_app("Cursor.exe", r"C:\x\Cursor.exe"), "Cursor")
        self.assertEqual(PV.protected_app("claude.exe", CLAUDE_APP), "Claude app")
        self.assertEqual(PV.protected_app("Antigravity.exe", AGY_APP), "Antigravity app")

    def test_cli_images_are_not_apps(self):
        for image, path in (("claude.exe", CLAUDE_CLI), ("claude.exe", CLAUDE_EMBEDDED), ("codex.exe", r"C:\c.exe"),
                            ("grok.exe", r"C:\Users\x\.grok\bin\grok.exe"), ("node.exe", CURSOR_NODE),
                            ("agy.exe", AGY_CLI)):
            self.assertIsNone(PV.protected_app(image, path), image)


class FindCliTests(unittest.TestCase):
    def test_claude_cli_found_above_shell(self):
        table, path = tree((10, 1, "explorer.exe", ""), (20, 10, "claude.exe", CLAUDE_CLI),
                           (30, 20, "bash.exe", ""), (40, 30, "python.exe", ""))
        self.assertEqual(PV.find_cli("claude", 40, table, path), (20, ""))

    def test_cursor_needs_its_own_node(self):
        table, path = tree((20, 1, "node.exe", PLAIN_NODE), (30, 20, "cmd.exe", ""), (40, 30, "python.exe", ""))
        pid, why = PV.find_cli("cursor", 40, table, path)
        self.assertIsNone(pid)
        table, path = tree((19, 1, "powershell.exe", ""), (20, 19, "node.exe", CURSOR_NODE), (40, 20, "python.exe", ""))
        self.assertEqual(PV.find_cli("cursor", 40, table, path), (20, ""))

    def test_gemini_is_the_nearest_node(self):
        table, path = tree((20, 1, "node.exe", PLAIN_NODE), (30, 20, "cmd.exe", ""), (40, 30, "python.exe", ""))
        self.assertEqual(PV.find_cli("gemini", 40, table, path), (20, ""))

    def test_agy_runs_hooks_through_cmd(self):
        # agy 1.3.3 and 1.3.4: hook -> cmd.exe -> agy.exe; its background updater is another agy.exe beside the hook
        table, path = tree((10, 1, "explorer.exe", ""), (20, 10, "agy.exe", AGY_CLI), (25, 20, "agy.exe", AGY_CLI),
                           (30, 20, "cmd.exe", ""), (40, 30, "python.exe", ""))
        self.assertEqual(PV.find_cli("antigravity", 40, table, path), (20, ""))

    def test_hook_under_the_antigravity_app_is_refused(self):
        table, path = tree((5, 1, "Antigravity.exe", AGY_APP), (6, 5, "language_server.exe", ""),
                           (30, 6, "cmd.exe", ""), (40, 30, "python.exe", ""))
        pid, why = PV.find_cli("antigravity", 40, table, path)
        self.assertIsNone(pid)
        self.assertIn("Antigravity app", why)

    def test_embedded_claude_code_is_refused(self):
        # the Claude app's own Claude Code: the CLI image matches, but the app is further up the chain
        table, path = tree((5, 1, "claude.exe", CLAUDE_APP), (20, 5, "claude.exe", CLAUDE_EMBEDDED),
                           (30, 20, "bash.exe", ""), (40, 30, "python.exe", ""))
        pid, why = PV.find_cli("claude", 40, table, path)
        self.assertIsNone(pid)
        self.assertIn("Claude app", why)

    def test_codex_helper_under_the_codex_app_is_refused(self):
        table, path = tree((5, 1, "ChatGPT.exe", ""), (6, 5, "codex.exe", ""), (7, 6, "codex.exe", ""),
                           (40, 7, "python.exe", ""))
        pid, why = PV.find_cli("codex", 40, table, path)
        self.assertIsNone(pid)
        self.assertIn("Codex app", why)

    def test_no_cli_and_unknown_provider(self):
        table, path = tree((30, 1, "cmd.exe", ""), (40, 30, "python.exe", ""))
        self.assertIsNone(PV.find_cli("grok", 40, table, path)[0])
        self.assertIsNone(PV.find_cli("nope", 40, table, path)[0])

    def test_parent_loop_terminates(self):
        table, path = tree((30, 40, "cmd.exe", ""), (40, 30, "python.exe", ""))
        self.assertIsNone(PV.find_cli("codex", 40, table, path)[0])

    def test_app_among_checks_the_process_itself(self):
        table, path = tree((5, 1, "Cursor.exe", ""), (6, 5, "node.exe", PLAIN_NODE))
        self.assertEqual(PV.app_among(5, table, path), "Cursor")
        self.assertEqual(PV.app_among(6, table, path), "Cursor")
        table, path = tree((6, 999, "codex.exe", ""))  # parent already exited
        self.assertIsNone(PV.app_among(6, table, path))


class SweepTests(unittest.TestCase):
    def test_app_helpers_under_an_adopted_cli_stay_out(self):
        from sentinel.guardian.daemon import sweep_targets
        table, path = tree((20, 1, "codex.exe", ""), (30, 20, "Cursor.exe", ""), (40, 30, "node.exe", PLAIN_NODE),
                           (50, 20, "bash.exe", ""), (60, 50, "python.exe", ""), (70, 20, "python.exe", ""))
        self.assertEqual(sweep_targets([30, 40, 50, 60, 70], table, path, own={70}), [50, 60])
        self.assertEqual(sweep_targets([30, 40, 50, 60], table, path, skip={50}), [60])


class HookSessionTests(unittest.TestCase):
    def setUp(self):
        self.hook = load_hook()

    def test_launcher_session_wins_for_the_same_provider(self):
        with mock.patch.dict(os.environ, {"GUARDIAN_PROVIDER": "codex", "GUARDIAN_SESSION": "fix-12"}):
            self.assertEqual(self.hook.session_name("codex", {"session_id": "abcdef123456"}, 9), "fix-12")
            # a codex started as a tool command of a Guardian claude session keeps its own id
            self.assertEqual(self.hook.session_name("claude", {"session_id": "abcdef123456"}, 9), "ef123456")

    def test_cli_session_id_then_pid(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(self.hook.session_name("gemini", {"sessionId": "0f1e2d3c4b"}, 9), "1e2d3c4b")
            self.assertEqual(self.hook.session_name("grok", {}, 77), "pid77")
            self.assertEqual(self.hook.session_name("antigravity", {"conversationId": "0a1b-2c3d-4e5f"}, 9),
                             "2c3d4e5f")

    def test_time_ordered_ids_stay_apart(self):
        # Codex and Grok ids are UUIDv7: the first 8 hex digits are a timestamp that moves every 65 seconds
        a, b = "01a1350a-1b2c-7d3e-8f40-0123456789ab", "01a1350a-9c8d-7e6f-a5b4-ba9876543210"
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertNotEqual(self.hook.session_name("codex", {"session_id": a}, 9),
                                self.hook.session_name("codex", {"session_id": b}, 9))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.inst = load("scripts/guardian-install-hooks.py", "guardian_install_hooks")

    def test_only_guardian_commands_are_removed(self):
        ours = {"type": "command", "command": r"C:\py.exe -I C:\r\hooks\guardian-adopt.py codex --instance main"}
        theirs = {"type": "command", "command": "notes.py"}
        entries = [{"matcher": "startup", "hooks": [theirs, ours]}, {"hooks": [ours]}]
        self.assertEqual(self.inst.without_ours(entries), [{"matcher": "startup", "hooks": [theirs]}])

    def test_antigravity_keeps_other_named_hooks(self):
        theirs = {"lint": {"PostToolUse": [{"matcher": "run_command", "hooks": [{"command": "lint.cmd"}]}]}}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".gemini", "config", "hooks.json")
            self.assertIsNone(self.inst.plan_antigravity("main", True)[1])  # no file: nothing to remove
            f.parent.mkdir(parents=True)
            f.write_text(json.dumps(theirs), encoding="utf-8")
            path, data, _ = self.inst.plan_antigravity("main", False)
            self.assertEqual(path, f)
            self.assertEqual(data["lint"], theirs["lint"])
            self.assertIn("guardian-adopt.py antigravity --instance main",
                          data["guardian-adopt"]["SessionStart"][0]["command"])
            f.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(self.inst.plan_antigravity("side", False)[1].keys(), {"lint", "guardian-adopt"})
            self.assertEqual(self.inst.plan_antigravity("main", True)[1], theirs)
            f.write_text(json.dumps({"guardian-adopt": data["guardian-adopt"]}), encoding="utf-8")
            self.assertIsNone(self.inst.plan_antigravity("main", True)[1])  # only ours: the file goes

    def test_antigravity_keeps_the_users_commands_and_name(self):
        ours = self.inst.command("antigravity", "main", False)
        mixed = {"mine": {"enabled": True, "SessionStart": [{"type": "command", "command": ours},
                                                            {"type": "command", "command": "my-own.cmd"}]},
                 "guardian-adopt": {"SessionStart": [{"type": "command", "command": "their-guardian.cmd"}]}}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".gemini", "config", "hooks.json")
            f.parent.mkdir(parents=True)
            f.write_text(json.dumps(mixed), encoding="utf-8")
            kept = {"mine": {"enabled": True, "SessionStart": [{"type": "command", "command": "my-own.cmd"}]},
                    "guardian-adopt": mixed["guardian-adopt"]}
            self.assertEqual(self.inst.plan_antigravity("main", True)[1], kept)
            data = self.inst.plan_antigravity("main", False)[1]
            self.assertEqual({k: data[k] for k in kept}, kept)
            self.assertEqual(data["guardian-adopt-2"]["SessionStart"][0]["command"], ours)


class ShimTests(unittest.TestCase):
    def setUp(self):
        self.inst = load("scripts/guardian-install-shims.py", "guardian_install_shims")

    def test_path_entry_goes_first_and_comes_out_alone(self):
        d = Path(r"C:\Users\x\.resource-sentinel\guardian\shims")
        old = r"C:\a;%USERPROFILE%\b;;C:\Users\x\.resource-sentinel\guardian\shims\;C:\c"
        self.assertEqual(self.inst.with_dir(old, d), str(d) + r";C:\a;%USERPROFILE%\b;;C:\c")
        self.assertEqual(self.inst.without_dir(self.inst.with_dir(old, d), d), r"C:\a;%USERPROFILE%\b;;C:\c")
        self.assertEqual(self.inst.with_dir("", d), str(d))
        self.assertEqual(self.inst.without_dir(r"C:\a;C:\c", d), r"C:\a;C:\c")

    def test_wrappers_carry_the_mark_and_pass_arguments(self):
        w = self.inst.wrappers("cursor", Path(r"C:\Py\python.exe"), Path(r"C:\r's\scripts\guardian-shim.py"))
        self.assertEqual(set(w), {"cursor-agent.cmd", "cursor-agent", "cursor-agent.ps1"})
        self.assertIn(r'''"C:\Py\python.exe" -I "C:\r's\scripts\guardian-shim.py" cursor %*''', w["cursor-agent.cmd"])
        self.assertIn('''exec "C:/Py/python.exe" -I "C:/r's/scripts/guardian-shim.py" cursor "$@"''', w["cursor-agent"])
        self.assertIn(r"& 'C:\Py\python.exe' -I 'C:\r''s\scripts\guardian-shim.py' cursor $args", w["cursor-agent.ps1"])
        self.assertTrue(w["cursor-agent.ps1"].startswith("\ufeff"))
        self.assertIn("\r\n", w["cursor-agent.cmd"])
        self.assertNotIn("\r", w["cursor-agent"])
        self.assertNotIn("cursor-agent.ps1", self.inst.wrappers("cursor", Path("p.exe"), Path("s.py"), ps1=False))
        with tempfile.TemporaryDirectory() as d:
            for name, text in w.items():
                Path(d, name).write_bytes(text.encode())
                self.assertTrue(PV.is_shim(Path(d, name)), name)
            Path(d, "notes.txt").write_text("about the guardian-shim: wrappers\n", encoding="ascii")
            self.assertFalse(PV.is_shim(Path(d, "notes.txt")))
        self.assertIn("cursor-agent.ps1", self.inst.file_names())
        self.assertNotIn("notes.txt", self.inst.file_names())

    def test_real_cli_skips_wrappers_wherever_they_sit(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            Path(a, "zzcli.cmd").write_bytes(self.inst.wrappers("codex", Path("p.exe"), Path("s.py"))["codex.cmd"]
                                             .encode())
            Path(b, "zzcli.cmd").write_text("@echo off\r\necho real\r\n", encoding="ascii")
            self.assertTrue(PV.is_shim(Path(a, "zzcli.cmd")))
            self.assertFalse(PV.is_shim(Path(b, "zzcli.cmd")))
            self.assertEqual(Path(PV.real_cli("zzcli", os.pathsep.join([a, b]))).parent, Path(b))
            self.assertIsNone(PV.real_cli("zzcli", a))

    def test_real_cli_ignores_the_current_folder_unless_path_names_it(self):
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as b:
            Path(cwd, "zzcli.bat").write_text("@echo off\r\necho planted\r\n", encoding="ascii")
            Path(b, "zzcli.cmd").write_text("@echo off\r\necho real\r\n", encoding="ascii")
            old = os.getcwd()
            os.chdir(cwd)
            try:
                self.assertEqual(Path(PV.real_cli("zzcli", b)).parent, Path(b))
                self.assertIsNone(PV.real_cli("zzcli", r"C:\nowhere"))
                self.assertEqual(Path(PV.real_cli("zzcli", os.pathsep.join([".", b]))).name, "zzcli.bat")
            finally:
                os.chdir(old)

    def test_shim_steps_aside_for_guardian_jobs_apps_and_off(self):
        shim = load("scripts/guardian-shim.py", "guardian_shim")
        table = {}
        with mock.patch.object(shim.wj, "in_named_job", return_value=None), \
                mock.patch.object(shim.PV, "app_among", return_value=None):
            with mock.patch.dict(os.environ, {"GUARDIAN_SHIM": "off"}):
                self.assertEqual(shim.why_direct("main", table), "GUARDIAN_SHIM=off")
            with mock.patch.dict(os.environ, {"GUARDIAN_SHIM": "", "CLAUDE_CODE_ENTRYPOINT": "cli"}):
                self.assertIsNone(shim.why_direct("main", table))
                with mock.patch.object(shim.wj, "in_named_job", return_value=True):
                    self.assertIn("Guardian session", shim.why_direct("main", table))
                with mock.patch.object(shim.PV, "app_among", return_value="Claude app"):
                    self.assertIn("desktop app", shim.why_direct("main", table))
            # Git Bash's sh exits after starting the wrapper, so the app is no longer among the parents
            with mock.patch.dict(os.environ, {"GUARDIAN_SHIM": "", "CLAUDE_CODE_ENTRYPOINT": "claude-desktop"}):
                self.assertIn("desktop app", shim.why_direct("main", table))

    def test_shim_passes_everything_after_the_provider(self):
        shim = load("scripts/guardian-shim.py", "guardian_shim")
        self.assertEqual(shim.split_argv(["codex", "--", "-x", "--session", "s"]),
                         ([], "codex", ["--", "-x", "--session", "s"]))
        self.assertEqual(shim.split_argv(["--session", "codex", "--cls", "batch", "claude", "--", "hi"]),
                         (["--session", "codex", "--cls", "batch"], "claude", ["--", "hi"]))
        self.assertEqual(shim.split_argv(["--verbose"]), (["--verbose"], None, []))

    def test_shim_writes_arguments_for_cmd_exe_when_the_cli_is_a_cmd(self):
        shim = load("scripts/guardian-shim.py", "guardian_shim")
        args = ["a&b", "plain-1.x", "two words", 'note "x', "%PATH%", "end\\", 'a\\"b', ""]
        executable, line = shim.command_line([r"C:\npm\gemini.cmd"] + args)
        self.assertEqual(executable, shim.CMD)
        self.assertEqual(line, f'"{shim.CMD}" /e:ON /v:OFF /d /c ""C:\\npm\\gemini.cmd" "a&b" plain-1.x "two words" '
                               '"note ""x" "%%cd:~,%PATH%%cd:~,%" "end\\\\" "a\\\\""b" """')
        self.assertEqual(shim.command_line([r"C:\x\claude.exe", "a&b"]), (None, [r"C:\x\claude.exe", "a&b"]))
        with self.assertRaises(ValueError):
            shim.command_line([r"C:\npm\gemini.cmd", "line one\nline two"])

    def test_shim_resumes_the_cli_when_guardian_never_answers(self):
        shim = load("scripts/guardian-shim.py", "guardian_shim")
        with mock.patch.object(shim, "adopt", side_effect=lambda *a, **k: time.sleep(5)):
            t0 = time.monotonic()
            r = shim.adopt_within(1, "codex", "s", "normal", "check", limit=0.3)
            self.assertLess(time.monotonic() - t0, 2)
        self.assertFalse(r["ok"])
        self.assertEqual(r["state"], "timeout")
        with mock.patch.object(shim, "adopt", side_effect=RuntimeError("boom")):
            r = shim.adopt_within(1, "codex", "s", "normal", "check", limit=5)
        self.assertEqual((r["ok"], r["state"]), (False, "error"))


class WhereamiTests(unittest.TestCase):
    def test_candidates_come_from_env_then_adopt_log(self):
        wa = load("scripts/guardian-whereami.py", "guardian_whereami")
        with tempfile.TemporaryDirectory() as d:
            rows = [{"provider": "codex", "session": "aaaa1111", "cli_pid": 50, "state": "refused"},
                    {"provider": "grok", "session": "grok/other", "cli_pid": 99, "state": "adopted"},
                    {"provider": "codex", "session": "codex/bbbb2222", "cli_pid": 50, "state": "adopted"}]
            Path(d, "adopt.log").write_text("\n".join(json.dumps(r) for r in rows) +
                                            "\nnot json\n[1, 2]\nnull\n" + json.dumps({"provider": "x", "session": 5,
                                                                                         "cli_pid": 50}) + "\n",
                                            encoding="utf-8")
            with mock.patch.object(wa, "home_dir", lambda inst: Path(d)), \
                    mock.patch.dict(os.environ, {"GUARDIAN_PROVIDER": "Claude", "GUARDIAN_SESSION": "my sess.1"}):
                # names as the daemon makes them: safe(), provider lower case
                self.assertEqual(wa.candidates([10, 20, 50], "check"),
                                 [("claude", "my_sess_1"), ("codex", "bbbb2222"), ("codex", "aaaa1111")])


if __name__ == "__main__":
    unittest.main()
