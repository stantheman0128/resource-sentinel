import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from multiprocessing.connection import Pipe
from pathlib import Path
from unittest import mock

from sentinel.guardian import client as GC
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

    def run_main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(self.inst.main(list(argv)), 0)
        return out.getvalue()

    def test_claude_merges_into_settings_and_remove_restores_them(self):
        secret = "sk-fake-env-value-0123"
        theirs = [{"hooks": [{"type": "command", "command": 'py "C:/x/context.py"'}]},
                  {"matcher": "startup", "hooks": [{"type": "command", "command": "echo \u4f60\u597d"}]}]
        settings = {"cleanupPeriodDays": 30, "env": {"FAKE_TOKEN": secret},
                    "permissions": {"allow": ["Bash(git:*)"]},
                    "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "a.py"}]}],
                              "SessionStart": theirs,
                              "Stop": [{"hooks": [{"type": "command", "command": "b.py"}]}]},
                    "language": "\u7e41\u9ad4\u4e2d\u6587", "theme": "dark"}
        seed = (json.dumps(settings, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".claude", "settings.json")
            self.assertIn("not present", self.run_main("claude", "--remove", "--apply"))
            f.parent.mkdir(parents=True)
            f.write_bytes(seed)
            out = self.run_main("claude")  # dry run
            self.assertEqual(f.read_bytes(), seed)
            self.assertEqual(list(f.parent.iterdir()), [f])
            self.assertIn("hooks.SessionStart:", out)
            for hidden in (secret, "FAKE_TOKEN", "permissions", "a.py", "b.py"):
                self.assertNotIn(hidden, out)

            out = self.run_main("claude", "--apply")
            self.assertNotIn(secret, out)
            self.assertEqual(len(list(f.parent.glob("settings.json.bak-guardian-*"))), 1)
            raw = f.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r\n", raw)
            self.assertIn("\u7e41\u9ad4\u4e2d\u6587".encode("utf-8"), raw)
            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(list(data), list(settings))
            self.assertEqual(list(data["hooks"]), list(settings["hooks"]))
            self.assertEqual({k: v for k, v in data.items() if k != "hooks"},
                             {k: v for k, v in settings.items() if k != "hooks"})
            self.assertEqual(data["hooks"]["SessionStart"][:2], theirs)
            ours = data["hooks"]["SessionStart"][2]
            self.assertEqual(ours["matcher"], "startup|resume")
            self.assertEqual(ours["hooks"], [{"type": "command", "command": self.inst.command("claude", "main", False),
                                              "timeout": 30}])
            self.assertNotIn("\\", ours["hooks"][0]["command"])

            installed = f.read_bytes()
            self.assertIn("already as wanted", self.run_main("claude", "--apply"))
            self.assertEqual(f.read_bytes(), installed)

            out = self.run_main("claude", "--remove", "--apply")
            self.assertNotIn(secret, out)
            self.assertEqual(json.loads(f.read_bytes().decode("utf-8")), settings)
            self.assertEqual(f.read_bytes(), seed)

    def test_claude_adds_and_drops_the_hooks_key(self):
        settings = {"env": {"FAKE_TOKEN": "fake"}, "theme": "dark"}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".claude", "settings.json")
            f.parent.mkdir(parents=True)
            f.write_text(json.dumps(settings), encoding="utf-8")
            self.assertIn("already as wanted", self.run_main("claude", "--remove"))
            data = self.inst.plan_claude("main", False)[1]
            self.assertEqual(list(data), ["env", "theme", "hooks"])
            f.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(self.inst.plan_claude("main", True)[1], settings)
            f.write_text(json.dumps(dict(settings, hooks={})), encoding="utf-8")  # an empty hooks of the user's stays
            self.assertEqual(self.inst.plan_claude("main", True)[1], dict(settings, hooks={}))

    def test_cursor_keeps_flat_entries_and_version(self):
        pulse = {"command": "powershell.exe -File pulse-hook.ps1 -Source cursor", "timeout": 10}
        context = {"command": 'C:/Python313/python.exe "C:/x/hooks/cursor-sentinel-context.py"', "timeout": 5}
        old_ours = {"command": self.inst.command("cursor", "side", False), "timeout": 30}
        original = {"hooks": {"stop": [pulse], "sessionStart": [pulse, context]}, "version": 1}
        seed = json.dumps(original, indent=2).replace("\n", "\r\n").encode("utf-8")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".cursor", "hooks.json")
            f.parent.mkdir(parents=True)
            f.write_bytes(seed)
            self.run_main("cursor")  # dry run
            self.assertEqual(f.read_bytes(), seed)
            self.assertEqual(list(f.parent.iterdir()), [f])

            out = self.run_main("cursor", "--apply")
            self.assertNotIn("pulse-hook", out)
            raw = f.read_bytes()
            self.assertEqual(raw.count(b"\n"), raw.count(b"\r\n"))  # the file's CRLF stays
            data = json.loads(raw)
            ours = {"command": self.inst.command("cursor", "main", False), "timeout": 30}
            self.assertEqual(data, {"hooks": {"stop": [pulse], "sessionStart": [pulse, context, ours]}, "version": 1})
            self.assertEqual(list(data), ["hooks", "version"])

            f.write_text(json.dumps({"hooks": {"sessionStart": [old_ours, pulse]}}), encoding="utf-8")
            data = self.inst.plan_cursor("main", False)[1]
            self.assertEqual(data, {"hooks": {"sessionStart": [pulse, ours]}, "version": 1})
            f.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(self.inst.plan_cursor("main", True)[1], {"hooks": {"sessionStart": [pulse]}, "version": 1})

            f.write_bytes(seed)
            self.run_main("cursor", "--apply")
            self.run_main("cursor", "--remove", "--apply")
            self.assertEqual(json.loads(f.read_bytes()), original)

    def test_changes_print_only_what_differs(self):
        old = {"env": {"K": "secret"}, "hooks": {"SessionStart": [{"a": 1}], "Stop": [{"b": 2}]}}
        new = {"env": {"K": "secret"}, "hooks": {"SessionStart": [{"a": 1}, {"c": 3}], "Stop": [{"b": 2}]},
               "version": 1}
        self.assertEqual(self.inst.changes(old, new),
                         ["hooks.SessionStart:", '  + "(other hook, not shown)"', "version: + 1"])

    def test_other_hooks_in_a_mixed_entry_are_never_printed(self):
        side = {"type": "command", "command": self.inst.command("claude", "side", False)}
        ours = {"matcher": "startup|resume", "hooks": [
            {"type": "command", "command": self.inst.command("claude", "main", False), "timeout": 30}]}
        other = '"(other hook, not shown)"'
        gone = f'    - {{"matcher": "startup", "hooks": [{other}, {json.dumps(side)}]}}'
        stays = f'    + {{"matcher": "startup", "hooks": [{other}]}}'
        for theirs in ({"type": "command", "command": "curl -H 'Authorization: Bearer SEKRET' x"},
                       {"type": "http", "url": "http://x/?token=SEKRET"}):
            mixed = json.dumps({"hooks": {"SessionStart": [{"matcher": "startup", "hooks": [theirs, side]}]}})
            kept = {"matcher": "startup", "hooks": [theirs]}
            with self.subTest(theirs["type"]), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(self.inst, "HOME", Path(d)):
                f = Path(d, ".claude", "settings.json")
                f.parent.mkdir(parents=True)
                f.write_text(mixed, encoding="utf-8")
                out = self.run_main("claude")  # dry run
                self.assertEqual(f.read_text(encoding="utf-8"), mixed)
                for line in (gone, stays, f"    + {json.dumps(ours)}"):
                    self.assertIn(line, out.splitlines())

                out += self.run_main("claude", "--apply")
                self.assertEqual(json.loads(f.read_bytes()), {"hooks": {"SessionStart": [kept, ours]}})

                f.write_text(mixed, encoding="utf-8")
                removed = self.run_main("claude", "--remove", "--apply")
                self.assertEqual(json.loads(f.read_bytes()), {"hooks": {"SessionStart": [kept]}})
                self.assertIn(gone, removed.splitlines())
                self.assertIn(stays, removed.splitlines())
                self.assertNotIn("SEKRET", out + removed)

    def test_other_cursor_hooks_are_never_printed(self):
        theirs = {"command": "curl -H 'Authorization: Bearer SEKRET' x", "timeout": 5}
        side = {"command": self.inst.command("cursor", "side", False), "timeout": 30}
        ours = {"command": self.inst.command("cursor", "main", False), "timeout": 30}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".cursor", "hooks.json")
            f.parent.mkdir(parents=True)
            f.write_text(json.dumps({"hooks": {"sessionStart": [theirs, side]}, "version": 1}), encoding="utf-8")
            out = self.run_main("cursor") + self.run_main("cursor", "--apply")
            self.assertIn(f"    - {json.dumps(side)}", out.splitlines())
            self.assertEqual(json.loads(f.read_bytes()), {"hooks": {"sessionStart": [theirs, ours]}, "version": 1})
            out += self.run_main("cursor", "--remove", "--apply")
            self.assertEqual(json.loads(f.read_bytes()), {"hooks": {"sessionStart": [theirs]}, "version": 1})
            self.assertNotIn("SEKRET", out)
        # a flat list that goes as a whole prints its other hooks masked as well
        self.assertEqual(self.inst.changes({"sessionStart": [theirs, side]}, {}),
                         ["sessionStart:", '  - "(other hook, not shown)"', f"  - {json.dumps(side)}"])

    def test_context_and_status_hooks_come_and_go_with_the_flags(self):
        theirs = {"hooks": [{"type": "command", "command": "py C:/x/prompt-notes.py"}]}
        settings = {"env": {"FAKE_TOKEN": "fake"}, "hooks": {"UserPromptSubmit": [theirs]}}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(self.inst, "HOME", Path(d)):
            f = Path(d, ".claude", "settings.json")
            f.parent.mkdir(parents=True)
            f.write_text(json.dumps(settings), encoding="utf-8")
            out = self.run_main("claude", "--context", "--status")  # dry run
            self.assertIn("hooks.UserPromptSubmit:", out)
            self.assertIn("guardian-status.py", out)
            self.assertNotIn("prompt-notes", out)
            data = self.inst.plan_claude("main", False, True, True)[1]
            start = data["hooks"]["SessionStart"][0]["hooks"][0]["command"]
            self.assertTrue(start.endswith("guardian-adopt.py claude --instance main --context"), start)
            prompt = data["hooks"]["UserPromptSubmit"]
            self.assertEqual(prompt[0], theirs)
            self.assertEqual(prompt[1], {"hooks": [{"type": "command", "timeout": 10, "command":
                                                    self.inst.command("claude", "main", False, self.inst.STATUS)}]})
            self.assertNotIn("\\", prompt[1]["hooks"][0]["command"])
            f.write_text(json.dumps(data), encoding="utf-8")
            plain = self.inst.plan_claude("main", False)[1]  # no flags: the plain adopt hook, no prompt hook
            self.assertEqual(plain["hooks"]["UserPromptSubmit"], [theirs])
            self.assertNotIn("--context", json.dumps(plain))
            self.assertEqual(self.inst.plan_claude("main", True)[1], settings)

            c = Path(d, ".codex", "hooks.json")
            c.parent.mkdir(parents=True)
            stop = {"Stop": [{"hooks": [{"type": "command", "command": "py C:/x/notify.py"}]}]}
            c.write_text(json.dumps({"hooks": stop}), encoding="utf-8")
            data = self.inst.plan_codex("main", False, True, True)[1]
            self.assertTrue(data["hooks"]["SessionStart"][0]["hooks"][0]["command"].endswith(" --context"))
            status = data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
            self.assertIn("hooks\\guardian-status.py codex", status)
            c.write_text(json.dumps(data), encoding="utf-8")
            self.assertEqual(self.inst.plan_codex("main", True)[1], {"hooks": stop})

            data = self.inst.plan_cursor("main", False, True, True)[1]
            self.assertEqual(list(data["hooks"]), ["sessionStart"])  # no prompt hook: Cursor's only allows or blocks
            self.assertTrue(data["hooks"]["sessionStart"][0]["command"].endswith(" --context"))
            for plan in (self.inst.plan_grok, self.inst.plan_antigravity):
                self.assertEqual(plan("main", False, True, True)[1], plan("main", False)[1])


class BudgetContextTests(unittest.TestCase):
    """R4: what the hooks tell an agent about its own Guardian session."""

    def guardian(self):
        from types import SimpleNamespace
        from sentinel.guardian import daemon as D
        from sentinel.guardian import policy as P
        g = D.Guardian.__new__(D.Guardian)  # no jobs or threads: budget_of only
        g.world, g.cap, g.alloc, g.control = 12, P.CapState(cap=50.0), P.AllocState(), True
        g.pool_priority, g.agent_io, g.mem, g.mem_paused = "below_normal", "low", P.MemState(), set()
        g.sample = SimpleNamespace(available_gib=18.24)
        s, other = D.Session("claude", "abc12345", "normal", None), D.Session("codex", "s1", "batch", None)
        g.queue = [SimpleNamespace(session=s), SimpleNamespace(session=other), SimpleNamespace(session=s)]
        return g, s

    def where(self, **budget):
        b = {"key": "claude/abc12345", "cls": "normal", "cap_cores": 2.4, "pool_cap_cores": 6.0, "world_cpus": 12,
             "control": True, "priority": "below_normal", "io": "low", "admission_open": True,
             "admission_reason": "", "queued": 0, "paused": False, "memory_rung": 0, "available_gib": 18.2,
             "exempt_left_s": None}
        b.update(budget)
        return {"pid": 4242, "session": b["key"], "priority": "below_normal", "budget": b}

    def test_budget_of_names_the_session_cap_and_its_own_queue(self):
        g, s = self.guardian()
        g.alloc.caps[s.key] = 2.4
        b = g.budget_of(s)
        self.assertEqual((b["key"], b["cls"], b["cap_cores"], b["pool_cap_cores"], b["world_cpus"]),
                         ("claude/abc12345", "normal", 2.4, 6.0, 12))
        self.assertEqual((b["queued"], b["paused"], b["available_gib"], b["exempt_left_s"]), (2, False, 18.2, None))
        g.mem_paused.add(s.key)
        g.cap.admission_open, g.cap.admission_reason = False, "CAPACITY_PRESSURE"
        b = g.budget_of(s)
        self.assertEqual((b["paused"], b["admission_open"], b["admission_reason"]), (True, False, "CAPACITY_PRESSURE"))
        s.cls, s.exempt_until = "exempt", time.time() + 300
        self.assertTrue(295 <= g.budget_of(s)["exempt_left_s"] <= 300)
        g.sample = None
        self.assertIsNone(g.budget_of(s)["available_gib"])

    def test_the_prompt_line_and_the_session_start_context(self):
        line = GC.budget_text(self.where())
        self.assertEqual(line, "Guardian: claude/abc12345 normal, CPU cap 2.4 of 12 cores, 18.2 GiB RAM available")
        long = GC.budget_text(self.where(), long=True)
        self.assertIn(line, long)
        self.assertIn("The agents together may use 6 cores", long)
        self.assertIn("below_normal CPU priority and low I/O priority", long)
        self.assertIn("About 2 parallel workers", long)
        self.assertIn("scripts/srun.py --provider claude --session abc12345 -- <command>", long)
        self.assertLess(len(long), 10000)  # Claude Code's cap on hook context
        self.assertIn("CPU cap 6 of 12 cores", GC.budget_text(self.where(cap_cores=None)))  # the pool's cap
        self.assertIn("CPU cap 6 of 12 cores", GC.budget_text(self.where(cap_cores=8.0)))
        busy = GC.budget_text(self.where(paused=True, admission_open=False, admission_reason="LOW_MEMORY",
                                         memory_rung=1, queued=2, available_gib=None))
        self.assertEqual(busy, "Guardian: claude/abc12345 normal, CPU cap 2.4 of 12 cores, paused, "
                               "new srun commands wait (LOW_MEMORY), memory pressure, 2 queued")
        off = GC.budget_text(self.where(control=False), long=True)
        self.assertIn("control off, nothing capped", off)
        self.assertNotIn("parallel workers", off)
        exempt = GC.budget_text(self.where(cls="exempt", exempt_left_s=290))
        self.assertIn("exempt from caps for 4 more minutes", exempt)
        for where in (None, {}, {"pid": 1, "session": None, "budget": None}):
            self.assertEqual(GC.budget_text(where), "")

    def test_hook_output_takes_the_shape_each_cli_reads(self):
        for provider in ("claude", "codex"):
            for event in ("SessionStart", "UserPromptSubmit"):
                self.assertEqual(json.loads(GC.hook_output(provider, event, "hi")),
                                 {"hookSpecificOutput": {"hookEventName": event, "additionalContext": "hi"}})
        self.assertEqual(json.loads(GC.hook_output("cursor", "sessionStart", "hi")), {"additional_context": "hi"})
        for args in (("cursor", "beforeSubmitPrompt", "hi"), ("grok", "SessionStart", "hi"),
                     ("antigravity", "SessionStart", "hi"), ("claude", "Stop", "hi"), ("claude", "SessionStart", "")):
            self.assertEqual(GC.hook_output(*args), "")

    def run_hook(self, hook, argv, env=None):
        out = io.StringIO()
        with mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out):
            hook.main(argv)
        return out.getvalue()

    def test_adopt_hook_gives_context_only_when_asked(self):
        from sentinel.guardian import winjob as wj
        hook, rows = load_hook(), []
        where = self.where()
        with mock.patch.object(hook, "read_payload", return_value={"hook_event_name": "SessionStart"}), \
                mock.patch.object(hook, "log", side_effect=lambda instance, row: rows.append(row)), \
                mock.patch.object(wj, "process_table", return_value={4242: (1, "claude.exe")}), \
                mock.patch.object(PV, "find_cli", return_value=(4242, "")), \
                mock.patch.object(GC, "adopt", return_value={"ok": True, "state": "adopted"}), \
                mock.patch.object(GC, "whereis", return_value=where) as wi:
            env = {"GUARDIAN_ADOPT": "", "GUARDIAN_INSTANCE": ""}
            self.assertEqual(self.run_hook(hook, ["claude"], env), "")
            wi.assert_not_called()
            out = json.loads(self.run_hook(hook, ["claude", "--context"], env))
            self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")
            self.assertIn("Guardian: claude/abc12345 normal", out["hookSpecificOutput"]["additionalContext"])
            self.assertEqual(wi.call_args[0][:2], (4242, "main"))
            self.assertEqual(rows[-1]["context"], out["hookSpecificOutput"]["additionalContext"])
            self.assertEqual(self.run_hook(hook, ["grok", "--context", "--stdout", "{}"], env), "{}")
            self.assertEqual(self.run_hook(hook, ["claude", "--context"], dict(env, GUARDIAN_ADOPT="0")), "")
            with mock.patch.object(PV, "find_cli", return_value=(None, "the Claude app is among the hook's parents")):
                self.assertIn("additionalContext", self.run_hook(hook, ["claude", "--context"], env))
                self.assertEqual(wi.call_args[0][0], os.getpid())  # a desktop job holds the hook itself
            wi.side_effect = OSError("pipe gone")
            self.assertEqual(self.run_hook(hook, ["claude", "--context"], env), "")
            self.assertIn("pipe gone", rows[-1]["context_error"])

    def test_status_hook_prints_one_line_and_never_waits_long(self):
        hook = load("hooks/guardian-status.py", "guardian_status_hook")
        env = {"GUARDIAN_STATUS": "", "GUARDIAN_INSTANCE": ""}
        with mock.patch.object(hook, "read_payload", return_value={"hook_event_name": "UserPromptSubmit"}), \
                mock.patch.object(GC, "whereis", return_value=self.where()) as wi:
            out = json.loads(self.run_hook(hook, ["claude"], env))
            self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
            self.assertTrue(out["hookSpecificOutput"]["additionalContext"].startswith("Guardian: claude/abc12345"))
            self.assertEqual(wi.call_args[0][:2], (os.getpid(), "main"))
            self.assertEqual(self.run_hook(hook, ["cursor"], env), "")
            self.assertEqual(self.run_hook(hook, ["claude"], dict(env, GUARDIAN_STATUS="0")), "")
            wi.return_value = {"pid": 1, "session": None, "budget": None}  # not in a Guardian session
            self.assertEqual(self.run_hook(hook, ["claude"], env), "")
        with mock.patch.object(GC, "whereis", side_effect=lambda *a, **k: time.sleep(3)):
            t0 = time.monotonic()
            self.assertEqual(hook.status("claude", "main", {}, wait=0.2), "")
            self.assertLess(time.monotonic() - t0, 1.5)


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


class PipeHandshakeTests(unittest.TestCase):
    def exchange(self, server_key, client_key):
        a, b = Pipe()
        out = {}

        def side(name, conn, key, server):
            try:
                GC.handshake(conn, key, server=server, seconds=2)
                out[name] = "ok"
            except Exception as e:
                out[name] = e.__class__.__name__

        t = threading.Thread(target=side, args=("server", a, server_key, True))
        t.start()
        side("client", b, client_key, False)
        t.join(5)
        a.close()
        b.close()
        return out

    def test_same_key_passes_both_ways(self):
        self.assertEqual(self.exchange(b"k" * 64, b"k" * 64), {"server": "ok", "client": "ok"})

    def test_wrong_key_is_refused_on_both_ends(self):
        self.assertEqual(self.exchange(b"k" * 64, b"x" * 64),
                         {"server": "AuthenticationError", "client": "AuthenticationError"})

    def test_a_peer_that_never_answers_times_out(self):
        for server in (True, False):
            a, b = Pipe()
            try:
                t0 = time.monotonic()
                with self.assertRaises(TimeoutError):
                    GC.handshake(a, b"k" * 64, server=server, seconds=0.3)
                self.assertLess(time.monotonic() - t0, 2)
            finally:
                a.close()
                b.close()


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


CODEX_APP = r"C:\Program Files\WindowsApps\OpenAI.ChatGPT-Desktop_1.2026.1.0_x64__2p2nqsd0c76g0\app\ChatGPT.exe"
CODEX_APP_CLI = r"C:\Users\x\AppData\Local\OpenAI\Codex\bin\4f2a9c7e1b0d\codex.exe"


def desktop_tree(*extra):
    """The Claude app with a Code-tab session (pid 200) and the Codex app with its codex.exe (pid 320)."""
    return tree((4, 1, "svchost.exe", ""), (100, 4, "claude.exe", CLAUDE_APP), (110, 100, "claude.exe", CLAUDE_APP),
                (200, 100, "claude.exe", CLAUDE_EMBEDDED), (210, 200, "bash.exe", ""),
                (220, 210, "node.exe", PLAIN_NODE), (300, 4, "ChatGPT.exe", CODEX_APP),
                (310, 300, "node_repl.exe", ""), (320, 310, "Codex.exe", CODEX_APP_CLI), *extra)


class DesktopTargetTests(unittest.TestCase):
    def test_code_tab_claude_and_codex_app_codex_are_picked(self):
        self.assertEqual(PV.desktop_targets(*desktop_tree()), [(200, "claude"), (320, "codex")])

    def test_app_processes_nested_targets_and_terminal_clis_are_skipped(self):
        table, path = desktop_tree(
            (230, 200, "claude.exe", CLAUDE_EMBEDDED),     # a second claude.exe under the Code-tab session
            (240, 210, "codex.exe", CODEX_APP_CLI),        # the Codex app's binary, but under the Claude app
            (400, 1, "WindowsTerminal.exe", ""), (410, 400, "pwsh.exe", ""),
            (420, 410, "claude.exe", CLAUDE_CLI),          # Claude Code from a terminal
            (430, 410, "claude.exe", CLAUDE_EMBEDDED),     # the app's copy, started from a terminal
            (440, 410, "codex.exe", CODEX_APP_CLI),
            (450, 300, "codex.exe", None),                 # path unreadable
            # an app process whose path also matches the CLI's: still the app
            (460, 100, "claude.exe", r"C:\Users\x\AppData\Local\AnthropicClaude\claude\claude-code\1.0\claude.exe"))
        self.assertEqual(PV.desktop_targets(table, path), [(200, "claude"), (320, "codex")])

    def test_a_parent_loop_back_to_the_target_keeps_it(self):
        # pid reuse: the app's parent pid now belongs to the CLI itself
        table, path = tree((500, 510, "claude.exe", CLAUDE_EMBEDDED), (510, 500, "claude.exe", CLAUDE_APP))
        self.assertEqual(PV.desktop_targets(table, path), [(500, "claude")])

    def test_the_sweep_takes_the_cli_children_but_not_an_app_it_started(self):
        from sentinel.guardian.daemon import desktop_sweep, sweep_targets
        table, path = desktop_tree((250, 200, "Cursor.exe", r"C:\x\Cursor.exe"), (260, 250, "node.exe", PLAIN_NODE),
                                   (270, 210, "python.exe", ""))
        self.assertEqual(sorted(desktop_sweep(200, table, path, own={270})), [210, 220])
        # without the cut, the Claude app above the CLI would keep every child out
        self.assertEqual(sweep_targets([210, 220], table, path), [])
        self.assertEqual(desktop_sweep(999, table, path), [])


CURSOR_APP = r"C:\Users\x\AppData\Local\Programs\cursor\Cursor.exe"
CURSOR_WORKER = (r"C:\Users\x\AppData\Roaming\Cursor\User\globalStorage\anysphere.cursor-agent-worker\agent-cli"
                 r"\.local\share\cursor-agent\versions\2026.10.16-e3cb207\node.exe")
CHAT = "0c9f6a1e-3b2d-4f7a-9e11-5d2c8b7a6f30"


def cursor_tree(*extra):
    """Cursor (500) with an extension host (510) that runs the agent-cli worker (520), an agent command in a shell
    (530, marked) with a child (540, marked too), and Stan's own terminal shell (550, unmarked)."""
    return tree((4, 1, "svchost.exe", ""), (500, 4, "Cursor.exe", CURSOR_APP), (510, 500, "Cursor.exe", CURSOR_APP),
                (520, 510, "node.exe", CURSOR_WORKER), (525, 520, "conhost.exe", ""),
                (530, 510, "pwsh.exe", ""), (540, 530, "node.exe", PLAIN_NODE), (550, 510, "pwsh.exe", ""), *extra)


def cursor_env(marked):
    return lambda pid: ({"CURSOR_AGENT": "1", "CURSOR_CONVERSATION_ID": CHAT, "Path": "x"} if pid in marked
                        else {"Path": "x"})


class CursorAppTests(unittest.TestCase):
    def test_the_agent_cli_worker_is_a_desktop_target(self):
        table, path = cursor_tree((600, 4, "pwsh.exe", ""), (610, 600, "node.exe", CURSOR_NODE),
                                  (620, 600, "node.exe", CURSOR_WORKER))  # the worker's binary, outside Cursor
        self.assertEqual(PV.desktop_targets(table, path), [(520, "cursor")])

    def test_the_topmost_marked_process_under_cursor_is_an_agent_command(self):
        table, path = cursor_tree((600, 4, "pwsh.exe", ""), (610, 600, "python.exe", ""))
        read = []
        env = cursor_env({530, 540, 610, 500})

        def environment(pid):
            read.append(pid)
            return env(pid)
        self.assertEqual(PV.agent_commands(table, path, environment), [(530, "cursor", CHAT)])
        # of Cursor's own processes only the one right above the command is read, for whether it has the mark too
        self.assertEqual((read.count(510), read.count(500)), (1, 0))
        self.assertNotIn(610, read)  # nothing outside Cursor is read either

    def test_covered_and_unreadable_processes_are_left_out(self):
        table, path = cursor_tree()
        self.assertEqual(PV.agent_commands(table, path, cursor_env({530, 540}), inside={530, 540}), [])
        self.assertEqual(PV.agent_commands(table, path, lambda pid: None), [])
        # the parent's block cannot be read: the marked child counts as the topmost one
        env = cursor_env({540})
        self.assertEqual(PV.agent_commands(table, path, env), [(540, "cursor", CHAT)])

    def test_a_command_without_a_chat_id_has_none(self):
        table, path = cursor_tree()
        self.assertEqual(PV.agent_commands(table, path, lambda pid: {"CURSOR_AGENT": "1"} if pid == 530 else {}),
                         [(530, "cursor", None)])

    def test_commands_of_one_chat_share_a_session(self):
        from sentinel.guardian import daemon as D
        table, _ = cursor_tree()
        g = D.Guardian.__new__(D.Guardian)
        g.sessions = {}
        g.place_desktop, g.join_desktop = mock.Mock(return_value="placed"), mock.Mock(return_value=True)
        g.place_command(530, "cursor", CHAT, table)
        name = "chat-0c9f6a1e3b2d"
        self.assertEqual(g.place_desktop.call_args.args[:4], (530, "cursor", table, name))
        s = g.sessions["cursor/" + name] = D.Session("cursor", name, "normal", FakeJob())
        s.desktop = True
        g.place_desktop.reset_mock()
        self.assertIs(g.place_command(560, "cursor", CHAT, table), s)
        g.place_desktop.assert_not_called()
        g.join_desktop.return_value = False  # under another extension host's job
        g.place_command(570, "cursor", CHAT, table)
        self.assertEqual(g.place_desktop.call_args.args[3], name + "-570")
        g.place_command(580, "cursor", None, table)
        self.assertEqual(g.place_desktop.call_args.args[3], "cmd-580")

    def test_whereami_reads_a_chat_or_command_job_by_name(self):
        wa = load("scripts/guardian-whereami.py", "guardian_whereami")
        table, path = cursor_tree()

        def answer(env, named):
            out = []
            with tempfile.TemporaryDirectory() as d, mock.patch.object(wa, "whereis", lambda pid, inst: None), \
                    mock.patch.object(wa, "home_dir", lambda inst: Path(d)), \
                    mock.patch.dict(os.environ, {"GUARDIAN_PROVIDER": "", "GUARDIAN_SESSION": ""}), \
                    mock.patch.object(wa.wj, "process_table", lambda: table), \
                    mock.patch.object(wa.wj, "image_path", path), mock.patch.object(wa.wj, "in_job", lambda *a: True), \
                    mock.patch.object(wa.wj, "priority_class", lambda pid: "below_normal"), \
                    mock.patch.object(wa.wj, "environment", env), \
                    mock.patch.object(wa.wj, "in_named_job", lambda pid, name: name in named), \
                    mock.patch("builtins.print", out.append):
                wa.main(["--pid", "540", "--instance", "main", "--json"])
            return json.loads(out[0])["answer"]
        self.assertTrue(answer(cursor_env({530, 540}), {"main.d.cursor.chat-0c9f6a1e3b2d"}).startswith(
            "CONTROLLED: session cursor/chat-0c9f6a1e3b2d (desktop job under the Cursor's job"))
        self.assertTrue(answer(cursor_env({530, 540}), {"main.d.cursor.chat-0c9f6a1e3b2d-530"}).startswith(
            "CONTROLLED: session cursor/chat-0c9f6a1e3b2d-530 "))
        no_chat = lambda pid: {"CURSOR_AGENT": "1"}  # noqa: E731
        self.assertTrue(answer(no_chat, {"main.d.cursor.cmd-530"}).startswith("CONTROLLED: session cursor/cmd-530 "))
        self.assertEqual(answer(cursor_env(set()), {"main.d.cursor.cmd-530"}),
                         "NOT CONTROLLED: Guardian main is not running")

    def test_the_environment_of_a_live_process_is_read(self):
        from sentinel.guardian import winjob as wj
        env = dict(os.environ, GUARDIAN_TEST_MARK="m=1;x")
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], env=env)
        try:
            for _ in range(50):
                got = wj.environment(p.pid)
                if got:
                    break
                time.sleep(0.05)
            self.assertEqual(got.get("GUARDIAN_TEST_MARK"), "m=1;x")
            self.assertIsNone(wj.environment(0))
        finally:
            p.kill()
            p.wait()


class AgentPriorityTests(unittest.TestCase):
    def guardian(self):
        from sentinel.guardian import daemon as D
        g = D.Guardian.__new__(D.Guardian)
        g.niced, g.agent_io, g.agent_memory, g.decide = {}, "low", "low", mock.Mock()
        return D, g

    def test_each_new_member_is_set_once_and_forgotten_when_it_leaves(self):
        D, g = self.guardian()
        calls = []
        refused = {3}

        def setter(kind):
            return lambda pid, name: calls.append((kind, pid, name)) or pid not in refused
        with mock.patch.object(D.wj, "set_io_priority", setter("io")), \
                mock.patch.object(D.wj, "set_memory_priority", setter("mem")):
            g.nice_sweep({1, 2})
            self.assertEqual(sorted(calls), [("io", 1, "low"), ("io", 2, "low"), ("mem", 1, "low"), ("mem", 2, "low")])
            calls.clear()
            g.nice_sweep({1, 2, 3})
            self.assertEqual(sorted(calls), [("io", 3, "low"), ("mem", 3, "low")])
            self.assertEqual(g.niced, {1: True, 2: True, 3: False})
            calls.clear()
            g.nice_sweep({2, 3})  # a refused pid is not tried again while it stays
            self.assertEqual((calls, g.niced), ([], {2: True, 3: False}))

    def test_restore_and_a_new_level_set_every_member_again(self):
        D, g = self.guardian()
        g.niced = {1: True, 2: True}
        calls = []
        with mock.patch.object(D.wj, "set_io_priority", lambda pid, name: calls.append(("io", pid, name))), \
                mock.patch.object(D.wj, "set_memory_priority", lambda pid, name: calls.append(("mem", pid, name))):
            g.restore_priority([1])
        self.assertEqual(calls, [("io", 1, "normal"), ("mem", 1, "normal")])
        self.assertEqual(g.niced, {2: True})
        with self.assertRaises(ValueError):
            g.set_agent_priority(io="high")
        with self.assertRaises(ValueError):
            g.set_agent_priority(memory="lowest")
        g.set_agent_priority(io="very_low")
        self.assertEqual((g.agent_io, g.agent_memory, g.niced), ("very_low", "low", {}))

    def test_a_lowered_process_passes_both_priorities_to_later_children(self):
        from sentinel.guardian import winjob as wj
        code = ("import subprocess, sys; sys.stdin.readline(); "
                "c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
                "print(c.pid, flush=True); sys.stdin.readline(); c.kill()")
        p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertTrue(wj.set_io_priority(p.pid, "low"))
            self.assertTrue(wj.set_memory_priority(p.pid, "low"))
            self.assertEqual((wj.io_priority(p.pid), wj.memory_priority(p.pid)), ("low", "low"))
            p.stdin.write("go\n")
            p.stdin.flush()
            child = int(p.stdout.readline())
            self.assertEqual((wj.io_priority(child), wj.memory_priority(child)), ("low", "low"))
            self.assertTrue(wj.set_io_priority(p.pid, "normal") and wj.set_memory_priority(p.pid, "normal"))
            self.assertEqual((wj.io_priority(p.pid), wj.memory_priority(p.pid)), ("normal", "normal"))
            p.stdin.write("done\n")
            p.stdin.flush()
        finally:
            p.kill()
            p.wait()


class OutsideLoadTests(unittest.TestCase):
    def test_groups_by_image_and_skips_members_idle_new_and_reused_pids(self):
        from sentinel.guardian.apps import LoadObserver
        samples = iter([
            {0: ("", 100.0), 10: ("chrome.exe", 5.0), 11: ("Chrome.exe", 1.0), 12: ("node.exe", 0.0),
             13: ("raycast.exe", 2.0), 14: ("old.exe", 9.0)},
            {0: ("", 120.0), 10: ("chrome.exe", 7.0), 11: ("Chrome.exe", 2.0), 12: ("node.exe", 4.0),
             13: ("raycast.exe", 2.5), 14: ("new.exe", 9.5), 15: ("fresh.exe", 3.0)},
        ])
        busy = iter([None, 0.5])
        obs = LoadObserver(times=lambda: next(samples), busy=lambda: next(busy), cpus=12)
        self.assertIsNone(obs.sample(set(), now=0.0))
        out = obs.sample({12}, now=2.0)  # node.exe 12 is in a Guardian job
        self.assertEqual(out["top"], [{"name": "chrome.exe", "cores": 1.5, "processes": 2},
                                      {"name": "raycast.exe", "cores": 0.25, "processes": 1}])
        self.assertEqual((out["cores"], out["processes"]), (1.75, 3))
        # 6 busy cores: 1.75 outside, 2.0 in the job, the rest is in no process row
        self.assertEqual((out["machine_cores"], out["unattributed_cores"]), (6.0, 2.25))

    def test_one_system_call_reads_this_process_like_getprocesstimes(self):
        from sentinel.guardian import apps
        sum(range(2_000_000))
        name, cpu_s = apps._process_times()[os.getpid()]
        self.assertEqual(name.lower(), Path(sys.executable).name.lower())
        self.assertLess(abs(cpu_s - apps._process_cpu_s(os.getpid())), 0.1)


class FakeJob:
    def __init__(self):
        self.calls = []

    def set_cpu(self, max_cores=None):
        self.calls.append(("cpu", max_cores))

    def set_cpu_rate(self, rate):
        self.calls.append(("rate", rate))

    def cpu(self):
        return {"mode": "fake"}


class DesktopAllocateTests(unittest.TestCase):
    def setUp(self):
        from sentinel.guardian import daemon as D
        from sentinel.guardian import policy as P
        self.D, self.P, self.wj = D, P, D.wj
        g = self.g = D.Guardian.__new__(D.Guardian)  # no jobs, ledger or threads: allocate() and its helpers only
        g.cfg, g.world, g.cap, g.alloc = P.merged(P.DEFAULTS, None), 12, P.CapState(cap=10.0), P.AllocState()
        g.allocator_on, g.control, g.sessions, g.providers, g.ledger, g.live = True, True, {}, {}, mock.Mock(), {}
        g.mem_paused, g.agents_gib = set(), 0.0

    def add(self, key, usage, desktop=False, runs=1):
        provider, name = key.split("/")
        self.g.providers.setdefault(provider, {"name": provider, "job": FakeJob(), "paused": False})
        s = self.g.sessions[key] = self.D.Session(provider, name, "normal", FakeJob())
        s.usage, s.live_runs, s.desktop = usage, runs, desktop
        return s

    def test_a_desktop_cap_is_absolute_cores(self):
        desk, tree_s = self.add("claude/desk-200", 1.2, desktop=True), self.add("codex/s1", 0.6)
        self.g.allocate()  # budget 10% of 12 CPUs = 1.2 cores, both press for more: 0.6 cores each
        self.assertEqual(desk.job.calls, [("cpu", 0.6)])
        self.assertEqual(desk.applied, ("abs", 0.6))
        self.assertEqual(tree_s.job.calls, [("cpu", 0.5 * self.wj.NCPU)])  # in the tree: half of the pool's rate

    def test_without_an_allocator_cap_a_desktop_session_gets_the_whole_budget(self):
        desk = self.add("claude/desk-200", 0.9, desktop=True)
        self.g.allocate()  # alone, so not contended
        self.assertEqual(desk.job.calls, [("cpu", 1.2)])
        self.g.allocator_on = False
        self.g.cap = self.P.CapState(cap=20.0)
        self.g.allocate()
        self.assertEqual(desk.job.calls[-1], ("cpu", 2.4))

    def test_an_idle_desktop_session_takes_no_share(self):
        idle = self.add("claude/desk-200", 0.0, desktop=True)
        a, b = self.add("codex/s1", 0.6), self.add("codex/s2", 0.6)
        self.g.allocate()
        self.assertEqual(idle.job.calls, [("cpu", 1.2)])  # inactive: the budget, never uncapped
        self.assertEqual(a.job.calls, [("cpu", 0.5 * self.wj.NCPU)])
        self.assertEqual(b.job.calls, [("cpu", 0.5 * self.wj.NCPU)])

    def test_pause_and_control_off(self):
        desk = self.add("claude/desk-200", 0.3, desktop=True)
        self.g.providers["claude"]["paused"] = True
        self.g.allocate()
        self.assertEqual(desk.job.calls, [("rate", 1)])
        self.g.providers["claude"]["paused"] = False
        self.g.control = False
        self.g.allocate()
        self.assertEqual(desk.job.calls[-1], ("cpu", None))
        self.assertIsNone(desk.applied)


class RunJob(FakeJob):
    h = 7

    def accounting(self):
        return {"cpu_s": 3.0, "active": 0}

    def limits(self):
        return {"peak_job_mem_bytes": 0}

    def close(self):
        self.calls.append(("close",))


class ExemptTests(unittest.TestCase):
    """Stan's exempt class: no session cap, no queue gates, new runs outside the tree. Not reachable from srun."""
    add = DesktopAllocateTests.add

    def setUp(self):
        DesktopAllocateTests.setUp(self)
        g = self.g
        g.log, g.lock, g.queue, g.hold, g.sample = mock.Mock(), threading.RLock(), [], False, object()
        g.last_launch, g.launch_starts, g.root = -1e9, [], RunJob()

    def run_in(self, s, t, est_s):
        r = self.D.Run(uuid.uuid4().hex[:6], s, ["x"], None, None, False, 1.0, "requested", False, "x", "f")
        r.t_request, r.est_s = t, est_s
        return r

    def test_an_exempt_session_takes_no_share_and_gets_no_cap(self):
        a, b, c = self.add("codex/a", 0.6), self.add("codex/b", 0.6), self.add("codex/c", 0.6)
        self.g.allocate()  # 1.2 cores for three: a third each
        self.assertEqual(c.job.calls[-1], ("cpu", round(1 / 3, 3) * self.wj.NCPU))
        self.g.set_exempt(c, 5, "set by Stan")
        self.g.allocate()  # c leaves the split: a and b share the budget
        self.assertEqual(c.job.calls[-1], ("cpu", None))
        self.assertEqual(a.job.calls[-1], ("cpu", 0.5 * self.wj.NCPU))
        self.assertIn("exempt: no session cap", self.g.ledger.decision.call_args.args[6])
        self.assertIsNone(self.g.desktop_want(c, 0.3, 1.2))  # an exempt desktop job runs without a cap
        c.paused = True
        self.assertEqual(self.g.desktop_want(c, 0.3, 1.2), "paused")  # pause still holds

    def test_an_exemption_ends_back_in_the_old_class(self):
        s = self.add("codex/a", 0.0)
        s.cls = "focus"
        self.g.set_exempt(s, 5, "set by Stan")
        self.assertEqual(s.cls, "exempt")
        self.assertAlmostEqual(s.exempt_until, time.time() + 300, delta=2)
        self.g.end_exemptions()
        self.assertEqual(s.cls, "exempt")
        s.exempt_until = time.time() - 1
        self.g.end_exemptions()
        self.assertEqual((s.cls, s.exempt_until), ("focus", None))

    def test_exempt_skips_the_admission_gates_but_not_a_pause(self):
        s = self.add("codex/a", 0.0)
        run = self.run_in(s, 0, 10)
        self.g.set_exempt(s, 5, "set by Stan")
        with mock.patch.object(self.P, "admission", side_effect=AssertionError("gates ran for an exempt run")):
            self.assertEqual(self.g.can_admit(run, 0, 0.0), (True, ""))
            s.paused = True
            self.assertEqual(self.g.can_admit(run, 0, 0.0), (False, "SESSION_PAUSED"))

    def test_admission_walks_the_queue_in_the_chosen_order(self):
        heavy, light = self.add("codex/heavy", 0.0), self.add("codex/light", 0.0)
        heavy.cpu_s, light.cpu_s = 500.0, 10.0
        first, second = self.run_in(heavy, 0, 5), self.run_in(light, 1, 50)
        self.g.queue = [first, second]
        seen = []
        self.g.can_admit = lambda run, now, unused: (seen.append(run), (False, "WAIT"))[1]
        for order, want in (("fifo", [first, second]), ("sjf", [first, second]), ("fair", [second, first])):
            seen.clear()
            self.g.cfg["queue"]["order"] = order
            self.g.admit_once(10)
            self.assertEqual(seen, want, order)

    def test_an_exempt_run_starts_outside_the_tree(self):
        s = self.add("codex/a", 0.0)
        s.job = RunJob()
        chains = []
        proc = mock.Mock(pid=4242)  # never reaches Windows: spawn, in_job and priority_class are patched
        spawn = lambda argv, chain, **kw: (chains.append(chain), proc)[1]
        with mock.patch.object(self.wj.Job, "create", lambda *a: RunJob()), \
                mock.patch.object(self.wj, "spawn_in_jobs", spawn), \
                mock.patch.object(self.wj, "in_job", lambda pid, h: False), \
                mock.patch.object(self.wj, "priority_class", lambda pid: "normal"):
            inside = self.run_in(s, 0, 1)
            self.g.launch(inside)
            self.g.set_exempt(s, 5, "set by Stan")
            outside = self.run_in(s, 0, 1)
            self.g.launch(outside)
        self.assertEqual(len(chains[0]), 4)
        self.assertEqual(chains[1], [outside.job])
        self.assertTrue(outside.outside)
        self.assertEqual(outside.coverage, "exempt, outside the pool, priority normal")
        self.g.live[outside.run_id] = outside
        s.live_runs = 1
        self.g.finish(outside, "done", 0)
        self.assertEqual(s.outside_done_s, 3.0)  # its CPU still counts for the session's fair share

    def test_only_stan_sets_it_and_only_for_a_bounded_time(self):
        self.assertNotIn("exempt", GC.CLASSES)  # srun, the adopt pipe and /api/adopt keep to CLASSES
        s = self.add("codex/a", 0.0)
        for bad in (0, -5, 24 * 60 + 1):
            with self.assertRaises(ValueError):
                self.g.action("/api/session", {"key": "codex/a", "cls": "exempt", "minutes": bad})
        self.g.action("/api/session", {"key": "codex/a", "cls": "exempt"})
        self.assertAlmostEqual(s.exempt_until, time.time() + 60 * 60, delta=2)  # the default hour
        self.g.action("/api/session", {"key": "codex/a", "cls": "batch"})
        self.assertEqual((s.cls, s.exempt_until), ("batch", None))
        with self.assertRaises(ValueError):
            self.g.action("/api/queue_order", {"order": "lifo"})
        self.g.action("/api/queue_order", {"order": "hrrn"})
        self.assertEqual(self.g.cfg["queue"]["order"], "hrrn")


class MemJob(FakeJob):
    def __init__(self, pids):
        super().__init__()
        self._pids = list(pids)

    def pids(self):
        return self._pids


class MemoryLadderTests(unittest.TestCase):
    """R2: under memory pressure Guardian trims working sets, then pauses the session holding the most commit."""
    add = DesktopAllocateTests.add

    def setUp(self):
        ExemptTests.setUp(self)
        self.g.trimmed, self.g.trimmed_gib, self.g.mem = {}, 0.0, self.P.MemState()
        self.GiB = self.D.GiB

    def test_rung_one_trims_the_largest_first_once_per_spacing(self):
        GiB = self.GiB
        mem = {11: (1 * GiB, 2 * GiB), 12: (3 * GiB, 1 * GiB), 13: None}
        self.g.mem = self.P.MemState(since=0.0, rung=1)
        trimmed = []
        with mock.patch.object(self.wj, "trim_working_set", lambda pid: (trimmed.append(pid), GiB // 2)[1]):
            self.g.memory_ladder(mem, 100.0)
            self.g.memory_ladder(mem, 110.0)  # inside the 30 s spacing: nothing
            self.g.memory_ladder(mem, 131.0)
            self.assertEqual(trimmed, [11, 12, 11, 12])  # by working set; a process that cannot be read is skipped
            self.assertEqual(self.g.trimmed_gib, 2.0)
            self.assertEqual(self.g.ledger.decision.call_args.args[:2], ("memory_trim", "agent processes"))
            self.g.memory_ladder({12: mem[12]}, 200.0)
        self.assertEqual(set(self.g.trimmed), {12})  # a process that left is forgotten

    def test_rung_two_pauses_the_largest_session_until_the_pressure_ends(self):
        GiB = self.GiB
        big, small, mine, ex = (self.add(k, 0.5) for k in ("codex/big", "codex/small", "codex/mine", "claude/ex"))
        big.job, small.job, mine.job, ex.job = MemJob([1, 2]), MemJob([3]), MemJob([4]), MemJob([5])
        mine.paused, ex.cls = True, "exempt"
        mem = {1: (2 * GiB, 0), 2: (2 * GiB, 0), 3: (3 * GiB, 0), 4: (9 * GiB, 0), 5: (9 * GiB, 0)}
        self.g.mem = self.P.MemState(since=0.0, rung=2)
        with mock.patch.object(self.wj, "trim_working_set", lambda pid: None):
            self.g.memory_ladder(mem, 50.0)
            self.g.memory_ladder(mem, 51.0)  # one session at a time
        self.assertEqual(self.g.mem_paused, {"codex/big"})  # 4 GiB over 3; Stan's pause and the exempt one are skipped
        self.g.allocate()
        self.assertEqual(big.job.calls[-1], ("rate", 1))
        self.assertNotIn(("rate", 1), small.job.calls)
        self.g.mem = self.P.MemState()
        self.g.memory_ladder(mem, 52.0)
        self.assertEqual(self.g.mem_paused, set())
        self.assertEqual(self.g.ledger.decision.call_args.args[:2], ("memory_resume", "codex/big"))
        self.g.allocate()
        self.assertNotEqual(big.job.calls[-1], ("rate", 1))

    def test_stan_sets_the_budget_and_the_hard_limit(self):
        root = self.g.root = mock.Mock()
        root.limits.return_value = {"mem_max_bytes": None}
        for bad in ({"budget_gib": 0}, {"budget_gib": 2000}, {"hard_limit_gib": -1}):
            with self.assertRaises(ValueError):
                self.g.action("/api/memory", bad)
        self.g.action("/api/memory", {"budget_gib": 6, "pause": True})
        m = self.g.cfg["memory"]
        self.assertEqual((m["agent_memory_budget_gib"], m["pressure_pause"], m["pressure_trim"]), (6.0, True, True))
        root.set_limits.assert_not_called()
        self.g.action("/api/memory", {"hard_limit_gib": 8})
        root.set_limits.assert_called_with(mem_max_bytes=8 * self.GiB)
        self.g.action("/api/memory", {"hard_limit_gib": None, "budget_gib": None})
        root.set_limits.assert_called_with(clear_mem=True)
        self.assertIsNone(m["agent_memory_budget_gib"])
        self.assertIsNone(self.P.DEFAULTS["memory"]["agent_memory_budget_gib"])  # the defaults stay untouched


class DesktopPlaceTests(unittest.TestCase):
    def test_a_desktop_job_name_that_already_exists_is_refused(self):
        from sentinel.guardian import daemon as D
        wj = D.wj
        table, path = desktop_tree()
        g = D.Guardian.__new__(D.Guardian)  # no jobs, ledger or threads: place_desktop() and its helpers only
        g.instance, g.sessions, g.ledger, g.log, g.desktop_skip = "main", {}, mock.Mock(), mock.Mock(), set()
        g.providers, g.root, g.probe_proc = {"claude": {"name": "claude", "job": FakeJob(), "paused": False}}, \
            mock.Mock(), None
        create = mock.Mock(side_effect=wj.JobExisted("main.d.claude.desk-200", 183, [12345]))
        opened = mock.Mock(side_effect=AssertionError("Guardian opened a desktop job it did not create"))
        close = mock.Mock()
        with mock.patch.object(wj.Job, "create", create), mock.patch.object(wj.Job, "open", opened), \
                mock.patch.object(wj, "in_job", lambda *a: False), mock.patch.object(wj, "CloseHandle", close), \
                mock.patch.object(wj, "open_waitable", lambda p: 99), mock.patch.object(wj, "image_path", path), \
                mock.patch.object(wj, "process_table", lambda: table), \
                mock.patch.object(wj, "is_elevated", lambda: False):
            g.place_desktop(200, "claude", table)
        create.assert_called_once_with("main.d.claude.desk-200")
        opened.assert_not_called()
        self.assertNotIn("claude/desk-200", g.sessions)
        self.assertEqual(g.desktop_skip, {200})
        close.assert_called_once_with(99)
        kind, target, *_, reason, _ = g.ledger.decision.call_args.args
        self.assertEqual((kind, target), ("desktop_refused", "claude/desk-200"))
        self.assertIn("12345", reason)  # the reason names the process in the job


class DesktopSwitchTests(unittest.TestCase):
    def test_on_for_main_only_unless_given(self):
        from sentinel.guardian import daemon as D
        with tempfile.TemporaryDirectory() as d, mock.patch.object(D, "home_dir", lambda inst: Path(d) / inst), \
                mock.patch.object(D, "Ledger", mock.Mock()), mock.patch.object(D, "secret", lambda path, n: "00"):
            self.assertTrue(D.Guardian("main").desktop_on)
            self.assertFalse(D.Guardian("check").desktop_on)
            self.assertTrue(D.Guardian("check", desktop=True).desktop_on)
            self.assertFalse(D.Guardian("main", desktop=False).desktop_on)

    def test_the_flag_reaches_the_daemon(self):
        from sentinel.guardian import daemon as D
        with mock.patch.object(D, "ping", lambda inst: False), mock.patch.object(D, "Guardian") as G:
            D.main(["--instance", "check", "--desktop", "on"])
            self.assertIs(G.call_args.args[7], True)
            D.main(["--desktop", "off"])
            self.assertIs(G.call_args.args[7], False)
            D.main([])
            self.assertIsNone(G.call_args.args[7])


class DesktopWhereamiTests(unittest.TestCase):
    def run_whereami(self, whereis, named):
        wa = load("scripts/guardian-whereami.py", "guardian_whereami")
        table, path = desktop_tree()
        out = []
        with mock.patch.object(wa, "whereis", whereis), mock.patch.object(wa.wj, "process_table", lambda: table), \
                mock.patch.object(wa.wj, "image_path", path), mock.patch.object(wa.wj, "in_job", lambda *a: True), \
                mock.patch.object(wa.wj, "priority_class", lambda pid: "below_normal"), \
                mock.patch.object(wa.wj, "in_named_job", named), mock.patch("builtins.print", out.append):
            rc = wa.main(["--pid", "210", "--instance", "main", "--json"])
        return rc, json.loads(out[0])["answer"]

    def test_a_desktop_session_is_controlled(self):
        def whereis(pid, inst):
            mine = pid in (210, 220, 200)
            return {"session": "claude/desk-200" if mine else None, "in_guardian": mine, "desktop": mine}
        rc, answer = self.run_whereami(whereis, lambda pid, name: None)
        self.assertEqual(rc, 0)
        self.assertEqual(answer, "CONTROLLED: session claude/desk-200 (desktop job under the Claude app's job, "
                                 "instance main), priority below_normal")

    def test_the_job_name_answers_when_the_pipe_is_out_of_reach(self):
        rc, answer = self.run_whereami(lambda pid, inst: None,
                                       lambda pid, name: True if name == "main.d.claude.desk-200" else None)
        self.assertEqual(rc, 0)
        self.assertTrue(answer.startswith("CONTROLLED: session claude/desk-200 (desktop job under the Claude app's "
                                          "job, instance main, read from the job"), answer)


# Claude Code in a terminal (pid 20), an MCP server it started (30) and the adopt hook (40)
TERMINAL_CLAUDE = ((10, 1, "WindowsTerminal.exe", ""), (20, 10, "claude.exe", CLAUDE_CLI),
                   (30, 20, "node.exe", PLAIN_NODE), (40, 20, "python.exe", ""))


class MemberJob(FakeJob):
    """A fake job that keeps its members. refuse: "OpenProcess" or "AssignProcessToJobObject" makes assign fail
    with that call's error, as winjob words it."""

    def __init__(self, name=None, refuse=None, members=()):
        super().__init__()
        self.name, self.refuse, self.members, self.closed = name, refuse, set(members), False
        self.total = len(self.members)  # TotalProcesses: every process that was ever in the job
        self.h = self  # the in_job fake reads the members through the handle

    def assign(self, pid):
        from sentinel.guardian import winjob as wj
        if self.refuse == "OpenProcess":
            raise wj.WinError(f"OpenProcess({pid})", 5)
        if self.refuse:
            raise wj.WinError(f"AssignProcessToJobObject(pid {pid})", 5)
        self.members.add(pid)
        self.total += 1

    def set_limits(self, priority=None):
        self.calls.append(("limits", priority))

    def limits(self):
        return {"priority": None, "flags": 0}

    def pids(self):
        return sorted(self.members)

    def accounting(self):
        return {"active": len(self.members), "total": self.total, "cpu_s": 0.0}

    def close(self):
        self.closed = True


class NestedAdoptTests(unittest.TestCase):
    """A hook-adopted CLI that sits in a job of its own (claude, cursor, gemini) cannot join the tree, so it gets a
    fresh job, which Windows nests under the CLI's job, outside AllAgents."""

    def setUp(self):
        from sentinel.guardian import daemon as D
        from sentinel.guardian import policy as P
        self.D, self.wj = D, D.wj
        g = self.g = D.Guardian.__new__(D.Guardian)  # no threads, and every job is a MemberJob
        g.instance, g.sessions, g.providers, g.live, g.adopted = "t", {}, {}, {}, {}
        g.ledger, g.log, g.probe_proc, g.lock = mock.Mock(), mock.Mock(), None, threading.RLock()
        g.cfg, g.world, g.cap, g.alloc = P.merged(P.DEFAULTS, None), 12, P.CapState(cap=10.0), P.AllocState()
        g.allocator_on, g.control, g.mask, g.pool_priority = True, True, None, "below_normal"
        g.desktop_on, g.desktop_skip, g.niced, g.mem_paused = False, set(), {}, set()
        # the pool already holds work, so a process in a job of its own cannot join it
        g.root = MemberJob("t.AllAgents", "AssignProcessToJobObject", members={5})
        self.jobs, self.refuse = {}, {}
        self.table, self.path = tree(*TERMINAL_CLAUDE)
        self.created = mock.Mock(side_effect=self.make_job)
        for p in (mock.patch.object(self.wj.Job, "create", self.created),
                  mock.patch.object(self.wj, "in_job", lambda pid, h=None: h is None or pid in h.members),
                  mock.patch.object(self.wj, "process_table", lambda: self.table),
                  mock.patch.object(self.wj, "image_path", lambda pid: self.path(pid)),
                  mock.patch.object(self.wj, "open_waitable", lambda pid: 99),
                  mock.patch.object(self.wj, "CloseHandle", mock.Mock()),
                  mock.patch.object(self.wj, "priority_class", lambda pid: "below_normal"),
                  mock.patch.object(self.wj, "is_elevated", lambda: False),
                  # the pids here are made up: never let them reach a real process
                  mock.patch.object(self.wj, "set_io_priority", lambda pid, name: True),
                  mock.patch.object(self.wj, "set_memory_priority", lambda pid, name: True)):
            p.start()
            self.addCleanup(p.stop)

    def make_job(self, name=None):
        refuse = self.refuse.get(name)
        if isinstance(refuse, Exception):
            raise refuse
        j = self.jobs[name] = MemberJob(name, refuse)
        return j

    def add(self, *rows):
        self.table, self.path = tree(*TERMINAL_CLAUDE, *rows)

    def decisions(self):
        return [c.args[:2] for c in self.g.ledger.decision.call_args_list]

    def test_a_cli_in_a_job_of_its_own_gets_a_nested_job(self):
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"], r["session"], r["nested"], r["processes"]),
                         (True, "adopted", "claude/abcd1234", True, 2))
        self.assertIn("AllAgents", r["reason"])
        d = self.jobs["t.d.claude.abcd1234"]
        self.assertEqual(d.members, {20, 30})  # the CLI and its MCP server; the hook stays out
        self.assertTrue(self.jobs["t.s.claude.abcd1234"].closed)  # the tree session it could not join is gone
        self.assertEqual(self.g.root.members, {5})
        s = self.g.sessions["claude/abcd1234"]
        self.assertIs(s.job, d)
        self.assertTrue(s.nested and s.desktop)
        self.assertEqual(s.live_runs, 1)
        # capped as a desktop job: pool priority, then the whole budget in cores (10% of 12 CPUs)
        self.assertEqual(d.calls, [("limits", "below_normal"), ("cpu", 1.2)])
        self.assertEqual(self.decisions()[-1], ("adopt", "claude/abcd1234"))
        self.assertTrue(r["coverage"].startswith("enforced (nested job)"), r["coverage"])

    def test_no_nested_job_when_guardian_cannot_open_the_process(self):
        self.g.root.refuse = "OpenProcess"
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("cannot open the process", r["reason"])
        self.assertNotIn("t.d.claude.abcd1234", self.jobs)
        self.assertEqual(self.g.sessions, {})

    def test_no_nested_job_for_a_cli_under_a_desktop_app(self):
        self.table, self.path = desktop_tree()
        r = self.g.adopt(200, "claude", "abcd1234")
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("Claude app", r["reason"])
        self.created.assert_not_called()

    def test_no_nested_job_under_a_desktop_job_name(self):
        r = self.g.adopt(20, "claude", "desk-20", skip={40})
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("job outside Guardian's tree", r["reason"])
        self.assertNotIn("t.d.claude.desk-20", self.jobs)

    def test_a_nested_job_that_refuses_too_keeps_the_old_answer(self):
        self.refuse["t.d.claude.abcd1234"] = "AssignProcessToJobObject"
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("job outside Guardian's tree; start it with gagent/srun instead", r["reason"])
        self.assertIn("nested job", r["reason"])
        self.assertTrue(self.jobs["t.d.claude.abcd1234"].closed)
        self.assertEqual(self.g.sessions, {})
        self.assertEqual(self.decisions()[-1], ("adopt_failed", "claude/abcd1234"))

    def test_a_taken_nested_name_is_refused_like_a_session(self):
        self.refuse["t.d.claude.abcd1234"] = self.wj.JobExisted("t.d.claude.abcd1234", 183, [4242])
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("4242", r["reason"])
        self.assertIn(("session_refused", "claude/abcd1234"), self.decisions())
        self.assertEqual(self.g.sessions, {})

    def test_a_cli_in_a_job_never_comes_first_in_a_fresh_pool(self):
        # a pool that has never held a process takes anyone, and the first one would put it under its own job
        self.g.root = MemberJob("t.AllAgents")
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"], r["nested"], r["processes"]), (True, "adopted", True, 2))
        self.assertEqual((self.g.root.members, self.g.root.total), (set(), 0))
        self.assertEqual(self.jobs["t.d.claude.abcd1234"].members, {20, 30})
        self.assertTrue(self.jobs["t.s.claude.abcd1234"].closed)

    def test_a_cli_in_no_job_still_joins_a_fresh_pool(self):
        self.g.root = MemberJob("t.AllAgents")
        with mock.patch.object(self.wj, "in_job", lambda pid, h=None: h is not None and pid in h.members):
            r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["ok"], r["state"], r["nested"]), (True, "adopted", False))
        self.assertEqual(self.g.root.members, {20, 30})
        self.assertEqual(self.jobs["t.s.claude.abcd1234"].members, {20, 30})
        self.assertNotIn("t.d.claude.abcd1234", self.jobs)

    def test_a_fresh_pool_stays_empty_when_no_nested_job_is_possible(self):
        self.g.root = MemberJob("t.AllAgents")
        r = self.g.adopt(20, "claude", "desk-20", skip={40})  # a desktop job's name gets no nested job
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("job outside Guardian's tree", r["reason"])
        self.g.session("claude", "queued", "normal")  # srun made it, and its run has not started yet
        r = self.g.adopt(20, "claude", "queued", skip={40})
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertIn("never held a process", r["reason"])
        self.assertEqual(self.g.root.total, 0)
        self.assertNotIn(20, self.jobs["t.s.claude.queued"].members)

    def test_a_second_adopt_answers_already(self):
        self.g.adopt(20, "claude", "abcd1234", skip={40})
        made = self.created.call_count
        self.add((50, 20, "cmd.exe", ""))  # a tool command started before the second hook ran
        again = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((again["ok"], again["state"], again["session"], again["nested"], again["swept"]),
                         (True, "already", "claude/abcd1234", True, 1))
        self.assertIn(50, self.jobs["t.d.claude.abcd1234"].members)
        # /clear gives the same CLI a new session id, so the hook sends a new name
        other = self.g.adopt(20, "claude", "ffff0000", skip={40})
        self.assertEqual((other["state"], other["session"]), ("already", "claude/abcd1234"))
        self.assertEqual(self.created.call_count, made)
        self.assertEqual(list(self.g.sessions), ["claude/abcd1234"])

    def test_already_sees_a_desktop_session(self):
        s = self.g.sessions["claude/desk-20"] = self.D.Session("claude", "desk-20", "normal",
                                                               MemberJob("t.d.claude.desk-20", members={20}))
        s.desktop = True
        r = self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.assertEqual((r["state"], r["session"], r["nested"]), ("already", "claude/desk-20", False))
        self.created.assert_not_called()
        self.assertEqual(self.g.root.members, {5})

    def test_another_cli_under_a_nested_session_name_is_refused(self):
        self.g.adopt(20, "claude", "abcd1234", skip={40})
        self.add((60, 10, "claude.exe", CLAUDE_CLI))
        self.g.root.refuse = None  # even a CLI the pool would take must not land there without a session
        r = self.g.adopt(60, "claude", "abcd1234")
        self.assertEqual((r["ok"], r["state"]), (False, "refused"))
        self.assertNotIn(60, self.g.root.members)
        self.assertEqual(self.jobs["t.d.claude.abcd1234"].members, {20, 30})

    def test_desktop_off_keeps_nested_sessions_capped(self):
        self.g.adopt(20, "claude", "abcd1234", skip={40})
        desk = self.g.sessions["codex/desk-320"] = self.D.Session("codex", "desk-320", "normal",
                                                                  MemberJob("t.d.codex.desk-320", members={320}))
        desk.desktop = True
        self.g.set_desktop(False, "test")
        self.assertNotIn("codex/desk-320", self.g.sessions)
        self.assertTrue(desk.job.closed)
        d = self.jobs["t.d.claude.abcd1234"]
        self.assertIn("claude/abcd1234", self.g.sessions)
        self.assertEqual(d.calls, [("limits", "below_normal"), ("cpu", 1.2)])  # nothing released
        self.assertFalse(d.closed)
        self.assertIn(20, self.g.adopted)
        kind, _, _, _, readback, *_ = self.g.ledger.decision.call_args.args
        self.assertEqual((kind, readback), ("desktop", {"released": 1, "nested_kept": 1}))

    def test_an_exited_nested_session_ends_while_desktop_is_off(self):
        self.g.adopt(20, "claude", "abcd1234", skip={40})
        d = self.jobs["t.d.claude.abcd1234"]
        self.g.stop = mock.Mock()
        with mock.patch.object(PV, "desktop_targets", mock.Mock(side_effect=AssertionError("placed while off"))):
            self.g.stop.wait.side_effect = [False, True]
            self.g.desktop_loop()  # the CLI still runs: the session stays
            self.assertIn("claude/abcd1234", self.g.sessions)
            d.members.clear()  # the CLI and its MCP server exit; tick() ends the adopted row
            self.g.end_adopted(self.g.adopted[20])
            self.g.stop.wait.side_effect = [False, True]
            self.g.desktop_loop()
        self.assertNotIn("claude/abcd1234", self.g.sessions)
        self.assertTrue(d.closed)
        self.assertIn("nested session claude/abcd1234 ended", [c.args[0] for c in self.g.log.call_args_list])


class NestedWhereamiTests(unittest.TestCase):
    def run_whereami(self, whereis, named):
        wa = load("scripts/guardian-whereami.py", "guardian_whereami")
        table, path = tree(*TERMINAL_CLAUDE)
        out = []
        with tempfile.TemporaryDirectory() as d:
            row = {"provider": "claude", "session": "claude/abcd1234", "cli_pid": 20, "state": "adopted",
                   "nested": True}
            Path(d, "adopt.log").write_text(json.dumps(row) + "\n", encoding="utf-8")
            with mock.patch.object(wa, "whereis", whereis), mock.patch.object(wa, "home_dir", lambda inst: Path(d)), \
                    mock.patch.dict(os.environ, {"GUARDIAN_PROVIDER": "", "GUARDIAN_SESSION": ""}), \
                    mock.patch.object(wa.wj, "process_table", lambda: table), \
                    mock.patch.object(wa.wj, "image_path", path), mock.patch.object(wa.wj, "in_job", lambda *a: True), \
                    mock.patch.object(wa.wj, "priority_class", lambda pid: "below_normal"), \
                    mock.patch.object(wa.wj, "in_named_job", named), mock.patch("builtins.print", out.append):
                rc = wa.main(["--pid", "40", "--instance", "main", "--json"])
        return rc, json.loads(out[0])["answer"]

    def test_a_nested_session_is_controlled(self):
        def whereis(pid, inst):
            mine = pid in (40, 20)
            return {"session": "claude/abcd1234" if mine else None, "in_guardian": mine, "desktop": False,
                    "nested": mine}
        rc, answer = self.run_whereami(whereis, lambda pid, name: None)
        self.assertEqual(rc, 0)
        self.assertEqual(answer, "CONTROLLED: session claude/abcd1234 (nested job under the CLI's own job, instance "
                                 "main), priority below_normal")

    def test_the_nested_job_name_answers_when_the_pipe_is_out_of_reach(self):
        named = {"main.AllAgents": False, "main.d.claude.abcd1234": True}
        rc, answer = self.run_whereami(lambda pid, inst: None, lambda pid, name: named.get(name))
        self.assertEqual(rc, 0)
        self.assertTrue(answer.startswith("CONTROLLED: session claude/abcd1234 (nested job under the CLI's own job, "
                                          "instance main, read from the job"), answer)
        rc, answer = self.run_whereami(lambda pid, inst: None, lambda pid, name: None)
        self.assertEqual((rc, answer), (1, "NOT CONTROLLED: Guardian main is not running"))


SLEEPER = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]
# stands in for an agent CLI: each "spawn" line starts a child and prints its pid
CLI_STANDIN = r"""
import subprocess, sys
kids = []
for line in sys.stdin:
    if line.strip() == "spawn":
        kids.append(subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(60)"]))
        print(kids[-1].pid, flush=True)
"""


@unittest.skipUnless(sys.platform == "win32", "Windows Job Objects")
class NestedJobLiveTests(unittest.TestCase):
    """Real jobs and only processes this test starts: a CLI stand-in in a job of its own with libuv's flags (kill on
    close, breakaway allowed) and a pool that already holds work."""

    def setUp(self):
        self.procs, self.jobs = [], []

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait(5)
            for f in (p.stdin, p.stdout):
                if f:
                    f.close()
        for j in self.jobs:
            j.close()  # closing the CLI's own job ends its children too

    def start(self, argv, **kw):
        p = subprocess.Popen(argv, **kw)
        self.procs.append(p)
        return p

    def spawn(self, cli):
        cli.stdin.write("spawn\n")
        cli.stdin.flush()
        return int(cli.stdout.readline())

    def guardian(self):
        """A daemon with a real, never-used pool job and no threads."""
        from sentinel.guardian import daemon as D
        from sentinel.guardian import policy as P
        wj = D.wj
        inst = f"nesttest-{uuid.uuid4().hex[:12]}"
        g = D.Guardian.__new__(D.Guardian)
        g.instance, g.sessions, g.providers, g.live, g.adopted = inst, {}, {}, {}, {}
        g.ledger, g.log, g.probe_proc, g.lock = mock.Mock(), mock.Mock(), None, threading.RLock()
        g.cfg, g.world, g.cap, g.alloc = P.merged(P.DEFAULTS, None), wj.NCPU, P.CapState(cap=10.0), P.AllocState()
        g.allocator_on, g.control, g.mask, g.pool_priority = True, True, None, "below_normal"
        g.desktop_on, g.desktop_skip, g.mem_paused = False, set(), set()
        g.root = wj.Job.create(f"{inst}.AllAgents")
        self.jobs.append(g.root)
        self.addCleanup(lambda: [x.close() for x in [s.job for s in g.sessions.values()] +
                                 [p["job"] for p in g.providers.values()]])
        return g, wj, inst

    def cli_in_its_own_job(self, wj):
        """(CLI stand-in, a child it started, its own job with libuv's flags)."""
        cli = self.start([sys.executable, "-I", "-c", CLI_STANDIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         text=True)
        early = self.spawn(cli)
        own = wj.Job.create()
        self.jobs.append(own)
        e = own.extended()
        e.Basic.LimitFlags |= wj.LIMIT_KILL_ON_JOB_CLOSE | wj.LIMIT_BREAKAWAY_OK | wj.LIMIT_SILENT_BREAKAWAY_OK
        own._set(wj.EXTENDED_LIMIT, e)
        own.assign(cli.pid)
        own.assign(early)  # libuv puts each child in its job itself
        return cli, early, own

    def test_a_cli_in_its_own_job_is_adopted_into_a_nested_job(self):
        g, wj, inst = self.guardian()
        g.root.assign(self.start(SLEEPER).pid)
        cli, early, own = self.cli_in_its_own_job(wj)
        name = f"{inst}.d.claude.abcd1234"
        with mock.patch.object(PV, "app_among", return_value=None):  # this test may run under a desktop app
            r = g.adopt(cli.pid, "claude", "abcd1234")
            self.assertEqual((r["ok"], r["state"], r.get("nested"), r.get("processes")), (True, "adopted", True, 2),
                             r)
            self.assertTrue(wj.in_named_job(cli.pid, name))
            self.assertTrue(wj.in_named_job(early, name))
            self.assertTrue(wj.in_job(cli.pid, own.h))  # still in its own job: the nested job sits under it
            self.assertFalse(wj.in_job(cli.pid, g.root.h))
            self.assertIsNone(wj.in_named_job(cli.pid, f"{inst}.s.claude.abcd1234"))  # the empty session job is gone
            s = g.sessions["claude/abcd1234"]
            self.assertEqual((s.job.cpu()["mode"], s.job.limits()["priority"]), ("hard_cap", "below_normal"))
            late = self.spawn(cli)  # the nested job allows no breakaway, so the outer job's flags do not apply
            self.assertTrue(wj.in_named_job(late, name))
            again = g.adopt(cli.pid, "claude", "abcd1234")
            self.assertEqual((again["state"], again["session"], again["swept"]), ("already", "claude/abcd1234", 0))
            self.assertEqual(list(g.sessions), ["claude/abcd1234"])
        own.close()  # kill on close: the CLI and both children end
        cli.wait(10)
        for run in list(g.live.values()):
            if wj.has_exited(run.handle):
                g.end_adopted(run)
        deadline = time.monotonic() + 10
        while s.job.accounting()["active"] and time.monotonic() < deadline:
            time.sleep(0.05)
        g.drop_ended()
        self.assertEqual(g.sessions, {})
        self.assertIsNone(wj.in_named_job(os.getpid(), name))  # its last handle closed, so the name is gone

    def test_a_fresh_pool_never_ends_up_under_a_cli(self):
        # a never-used pool would take the CLI and nest under its job, and every later run with it
        g, wj, inst = self.guardian()
        cli, early, own = self.cli_in_its_own_job(wj)
        with mock.patch.object(PV, "app_among", return_value=None):
            r = g.adopt(cli.pid, "claude", "abcd1234")
        self.assertEqual((r["ok"], r["state"], r.get("nested"), r.get("processes")), (True, "adopted", True, 2), r)
        self.assertTrue(wj.in_named_job(cli.pid, f"{inst}.d.claude.abcd1234"))
        self.assertEqual(g.root.accounting()["total"], 0)
        run = self.start(SLEEPER)
        g.root.assign(run.pid)  # what launch() does with the next srun
        self.assertFalse(wj.in_job(run.pid, own.h))
        own.close()  # kill on close: the CLI and its children end, the run does not
        cli.wait(10)
        self.assertIsNone(run.poll())


class MemoryLadderPauseTests(unittest.TestCase):
    """R2: a ladder pause follows the settings and ends with its session, an exemption or Stan's own pause, so the
    ladder can pause the next largest session; trims wait for pressure_trim, and a shutdown leaves no ladder behind."""
    add = DesktopAllocateTests.add

    def setUp(self):
        MemoryLadderTests.setUp(self)
        g, GiB = self.g, self.GiB
        g.desktop_on, g.desktop_skip, g.niced, g.agents_gib = True, set(), {}, 5.0
        g.cfg["memory"].update(agent_memory_budget_gib=4, pressure_pause=True)
        g.mem = self.P.MemState(since=0.0, rung=2)
        self.trimmed = []
        for p in (mock.patch.object(self.wj, "trim_working_set", lambda pid: self.trimmed.append(pid)),
                  # the pids here are made up: never let them reach a real process
                  mock.patch.object(self.wj, "set_io_priority", lambda pid, name: True),
                  mock.patch.object(self.wj, "set_memory_priority", lambda pid, name: True)):
            p.start()
            self.addCleanup(p.stop)
        # a desktop chat session (4 GiB in two processes) and a session in the tree (3 GiB)
        self.big, self.small = self.add("cursor/chat-a", 0.5, desktop=True, runs=0), self.add("codex/small", 0.5)
        self.big.job, self.small.job = MemberJob("t.d.cursor.chat-a", members={1, 2}), MemJob([3])
        self.mem = {1: (2 * GiB, GiB), 2: (2 * GiB, GiB), 3: (3 * GiB, GiB)}

    def resumed(self):
        return [(c.args[1], c.args[6]) for c in self.g.ledger.decision.call_args_list if c.args[0] == "memory_resume"]

    def test_memory_pause_off_resumes_while_the_pressure_lasts(self):
        g, P = self.g, self.P
        g.mem = P.MemState()
        for t in (0.0, 20.0, 21.0):  # what tick() does each second
            if t == 21.0:
                g.action("/api/memory", {"pause": False})  # guardctl memory-pause off
            g.mem, _ = P.memory_step(g.mem, P.Sample(t=t, age_s=0.5, available_gib=30.0), g.agents_gib, g.cfg)
            g.memory_ladder(self.mem, t)
            if t == 20.0:
                self.assertEqual(g.mem_paused, {"cursor/chat-a"})
        self.assertEqual((g.mem.rung, g.mem_paused), (1, set()))
        self.assertEqual(self.resumed(), [("cursor/chat-a", "pressure_pause turned off")])
        g.allocate()
        self.assertEqual(self.big.job.calls, [("cpu", 1.2)])

    def test_the_pause_rung_trims_only_while_trim_is_on(self):
        self.g.cfg["memory"]["pressure_trim"] = False
        self.g.memory_ladder(self.mem, 50.0)
        self.assertEqual((self.trimmed, self.g.mem_paused), ([], {"cursor/chat-a"}))
        self.g.cfg["memory"]["pressure_trim"] = True
        self.g.memory_ladder(self.mem, 51.0)
        self.assertEqual(sorted(self.trimmed), [1, 2, 3])

    def test_a_paused_session_that_ends_lets_the_ladder_pause_the_next(self):
        g = self.g
        g.memory_ladder(self.mem, 50.0)
        self.assertEqual(g.mem_paused, {"cursor/chat-a"})
        self.big.job.members.clear()  # the chat's last command exited
        g.drop_ended()
        self.assertNotIn("cursor/chat-a", g.sessions)
        self.assertEqual(self.resumed(), [("cursor/chat-a", "the session ended")])
        g.memory_ladder({3: self.mem[3]}, 51.0)
        self.assertEqual(g.mem_paused, {"codex/small"})
        again = self.add("cursor/chat-a", 0.5, desktop=True)  # a later command of the same chat gets the same key
        g.allocate()
        self.assertNotIn(("rate", 1), again.job.calls)

    def test_desktop_jobs_switched_off_end_the_pause_of_a_desktop_session(self):
        g = self.g
        g.memory_ladder(self.mem, 50.0)
        g.set_desktop(False, "test")
        self.assertNotIn("cursor/chat-a", g.sessions)
        self.assertEqual(self.resumed(), [("cursor/chat-a", "desktop jobs switched off, so the session left Guardian")])
        g.memory_ladder({3: self.mem[3]}, 51.0)
        self.assertEqual(g.mem_paused, {"codex/small"})

    def test_an_exempted_session_leaves_the_ladder(self):
        g = self.g
        g.memory_ladder(self.mem, 50.0)
        g.allocate()
        self.assertEqual(self.big.job.calls[-1], ("rate", 1))
        g.action("/api/session", {"key": "cursor/chat-a", "cls": "exempt"})
        self.assertEqual(self.resumed(), [("cursor/chat-a", "Stan exempted the session")])
        self.assertEqual(self.big.job.calls[-1], ("cpu", None))  # an exempt desktop job runs without a cap
        g.pool_priority, g.agent_io, g.sample = "below_normal", "low", None
        self.assertFalse(g.budget_of(self.big)["paused"])
        g.memory_ladder(self.mem, 51.0)
        self.assertEqual(g.mem_paused, {"codex/small"})  # the next largest; an exempt session is never picked

    def test_stans_resume_keeps_a_ladder_pause_and_his_own_pause_takes_it_over(self):
        g = self.g
        g.memory_ladder(self.mem, 50.0)
        g.allocate()
        g.action("/api/session", {"key": "cursor/chat-a", "paused": False})
        self.assertEqual((g.mem_paused, self.resumed()), ({"cursor/chat-a"}, []))
        self.assertEqual(self.big.job.calls[-1], ("rate", 1))
        g.action("/api/session", {"key": "cursor/chat-a", "paused": True})
        self.assertEqual(self.resumed(),
                         [("cursor/chat-a", "Stan paused the session, and that pause holds it now")])
        self.assertEqual(self.big.job.calls[-1], ("rate", 1))
        g.memory_ladder(self.mem, 51.0)
        self.assertEqual(g.mem_paused, {"codex/small"})
        g.action("/api/session", {"key": "cursor/chat-a", "paused": False})  # now Stan's resume runs it again
        self.assertEqual(self.big.job.calls[-1][0], "cpu")

    def test_a_session_holding_no_private_commit_is_never_the_one_paused(self):
        g = self.g
        g.memory_ladder({1: None, 2: (0, 0), 3: None}, 50.0)  # nothing held, or nothing readable: a pause frees nothing
        self.assertEqual(g.mem_paused, set())
        g.memory_ladder({1: None, 2: (0, 0), 3: (self.GiB, 0)}, 51.0)
        self.assertEqual(g.mem_paused, {"codex/small"})

    def test_a_tick_after_shutdown_pauses_and_trims_nothing(self):
        g, D, GiB = self.g, self.D, self.GiB
        g.memory_ladder(self.mem, 50.0)
        g.allocate()
        self.assertEqual(self.big.job.calls[-1], ("rate", 1))
        g.root = mock.Mock()
        g.root.accounting.return_value, g.root.pids.return_value = {"cpu_s": 3.0}, [3]
        self.small.job.accounting = lambda: {"cpu_s": 1.0, "active": 1}
        g.busy_fn, g.last_core_ok, g.lingering, g.history, g.apps_rows = (lambda: 0.5), 0.0, [], [], []
        g.probe_enabled, g.probe_proc, g.inject, g.media, g.probe_last = False, None, None, None, None
        g.pool_priority_readback, g.stop, g.agent_io, g.agent_memory = "below_normal", threading.Event(), "low", "low"
        perf = {"available": 30 * GiB, "commit_limit": 64 * GiB, "commit_total": 16 * GiB}
        with mock.patch.object(D.os, "_exit") as exit_, mock.patch.object(D.time, "sleep"), \
                mock.patch.object(self.wj, "performance_info", lambda: perf), \
                mock.patch.object(self.wj, "process_memory", lambda pid: self.mem.get(pid)):
            g.shutdown()
            exit_.assert_called_once_with(0)
            self.assertEqual(self.big.job.calls[-1], ("cpu", None))
            self.assertEqual((g.control, g.mem, g.mem_paused), (False, self.P.MemState(), set()))
            self.trimmed.clear()
            g.tick((time.monotonic() - 1, 0.0))  # a tick that waited for the lock while shutdown() held it
        self.assertEqual(self.big.job.calls[-1], ("cpu", None))
        self.assertNotIn(("rate", 1), self.small.job.calls)
        self.assertEqual((self.trimmed, g.mem_paused), ([], set()))
        g.root.set_cpu.assert_called_once_with()  # the shutdown's release only: no cap applied after it


class CursorCommandPlacementTests(unittest.TestCase):
    """The real desktop loop, desktop_once, place_desktop, join_desktop and track_desktop on fake jobs and a fake
    Cursor process table: each agent command is placed once, and nothing under a Cursor that carries the mark."""
    make_job = NestedAdoptTests.make_job
    # Cursor (500), an extension host (510) and Stan's own terminal shell (550)
    HOST = ((4, 1, "svchost.exe", ""), (500, 4, "Cursor.exe", CURSOR_APP), (510, 500, "Cursor.exe", CURSOR_APP),
            (550, 510, "pwsh.exe", ""))
    COMMAND = ((530, 510, "pwsh.exe", ""), (540, 530, "node.exe", PLAIN_NODE))  # an agent command and its child
    WORKER = ((520, 510, "node.exe", CURSOR_WORKER), (525, 520, "conhost.exe", ""), (527, 520, "pwsh.exe", ""))
    CHAT_JOB = "t.d.cursor.chat-0c9f6a1e3b2d"

    def setUp(self):
        NestedAdoptTests.setUp(self)
        self.g.desktop_on, self.g.marked_apps = True, set()
        self.env = cursor_env(set())
        p = mock.patch.object(self.wj, "environment", lambda pid: self.env(pid))  # made-up pids: never read for real
        p.start()
        self.addCleanup(p.stop)

    def scan(self, *rows):
        """One pass of the desktop loop over Cursor with these processes added."""
        self.table, self.path = tree(*self.HOST, *rows)
        self.g.stop = mock.Mock()
        self.g.stop.wait.side_effect = [False, True]
        self.g.desktop_loop()
        self.assertFalse([c for c in self.g.log.call_args_list if "desktop poll failed" in c.args[0]])

    def test_a_new_workers_marked_child_stays_in_its_job_and_the_chat_takes_a_second_command(self):
        self.env = cursor_env({527, 530, 540, 560})
        self.scan(*self.COMMAND)
        chat = self.jobs[self.CHAT_JOB]
        self.assertEqual(chat.members, {530, 540})
        # the worker shows up with a child that already carries the mark, next to a second command of the chat
        second = (560, 510, "python.exe", "")
        self.scan(*self.COMMAND, *self.WORKER, second)
        self.assertEqual(sorted(self.jobs), [self.CHAT_JOB, "t.d.cursor.desk-520", "t.p.cursor"])
        self.assertEqual(self.jobs["t.d.cursor.desk-520"].members, {520, 525, 527})
        self.assertEqual(chat.members, {530, 540, 560})  # the second command joined; the worker's child did not
        self.assertEqual([self.g.sessions[k].live_runs for k in ("cursor/chat-0c9f6a1e3b2d", "cursor/desk-520")],
                         [2, 1])
        made = self.created.call_count
        self.scan(*self.COMMAND, *self.WORKER, second)
        self.assertEqual(self.created.call_count, made)
        self.assertEqual(chat.members, {530, 540, 560})

    def test_a_command_under_a_worker_gets_no_job_of_its_own(self):
        self.env = cursor_env({527})
        self.scan(*self.WORKER)  # the chat has no job yet
        self.assertEqual(sorted(self.jobs), ["t.d.cursor.desk-520", "t.p.cursor"])
        self.assertEqual(self.jobs["t.d.cursor.desk-520"].members, {520, 525, 527})

    def test_a_command_under_a_refused_worker_is_left_alone(self):
        self.env = cursor_env({527})
        self.g.desktop_skip.add(520)
        self.scan(*self.WORKER)
        self.created.assert_not_called()

    def test_a_command_another_command_swept_in_this_pass_is_not_placed_again(self):
        # a marked command (530), an unmarked child (540), and under it a marked command without a chat id (545)
        self.env = lambda pid: ({"CURSOR_AGENT": "1", "CURSOR_CONVERSATION_ID": CHAT} if pid == 530 else
                                {"CURSOR_AGENT": "1"} if pid == 545 else {})
        self.scan(*self.COMMAND, (545, 540, "python.exe", ""))
        self.assertEqual(sorted(self.jobs), [self.CHAT_JOB, "t.p.cursor"])
        self.assertEqual(self.jobs[self.CHAT_JOB].members, {530, 540, 545})

    def test_nothing_under_a_cursor_that_carries_the_mark_is_a_command(self):
        # `cursor .` run by an agent command: Cursor starts with the mark, and everything under it inherits it
        table, path = tree(*self.HOST, *self.COMMAND, *self.WORKER)
        env, read, apps = cursor_env({500, 510, 520, 525, 527, 530, 540, 550}), [], {}

        def environment(pid):
            read.append(pid)
            return env(pid)
        self.assertEqual(PV.agent_commands(table, path, environment, marked_apps=apps), [])
        self.assertEqual(apps, {510: True})
        self.assertEqual((read.count(510), read.count(500)), (1, 0))  # the nearest app process only, once
        # an extension host without the mark lets its commands count, whatever the process above it has
        self.assertEqual(PV.agent_commands(table, path, cursor_env({500, 530, 540})), [(530, "cursor", CHAT)])
        # one whose environment cannot be read keeps them out too
        apps = {}
        self.assertEqual(PV.agent_commands(table, path, lambda pid: None if pid == 510 else env(pid),
                                           marked_apps=apps), [])
        self.assertEqual(apps, {510: None})

    def test_a_marked_cursor_keeps_its_commands_out_and_says_so_once(self):
        self.env = cursor_env({500, 510, 520, 525, 527, 530, 540, 550})
        for _ in range(3):
            self.scan(*self.COMMAND, *self.WORKER)
        self.assertEqual(sorted(self.jobs), ["t.d.cursor.desk-520", "t.p.cursor"])  # the worker is found by its path
        said = [c.args[0] for c in self.g.log.call_args_list if "pid 510" in c.args[0]]
        self.assertEqual(said, ["Cursor.exe pid 510 carries the agent mark itself, so every process under it has it: "
                                "its agent commands stay out of desktop jobs"])


class OutsideRunAndControlOffTests(unittest.TestCase):
    """Review package D: the runs an exempt session starts outside the tree follow every pause, control off reports
    what is in effect, the outside load leaves Guardian's own processes out, and the hooks keep one deadline."""
    add, run_in = DesktopAllocateTests.add, ExemptTests.run_in

    def setUp(self):
        ExemptTests.setUp(self)
        self.g.desktop_skip, self.g.niced = set(), {}

    def outside_run(self, s):
        r = self.run_in(s, 0, 1)
        r.job, r.outside, r.state = RunJob(), True, "running"
        self.g.live[r.run_id] = r
        return r

    def launch(self, s):
        """launch() a run of s as serve_run does, with every Windows call patched; returns the run and its chain."""
        chains, proc = [], mock.Mock(pid=4242)  # never reaches Windows: spawn, in_job and priority_class are patched
        spawn = lambda argv, chain, **kw: (chains.append(chain), proc)[1]
        with mock.patch.object(self.wj.Job, "create", lambda *a: RunJob()), \
                mock.patch.object(self.wj, "spawn_in_jobs", spawn), \
                mock.patch.object(self.wj, "in_job", lambda pid, h: False), \
                mock.patch.object(self.wj, "priority_class", lambda pid: "normal"):
            run = self.run_in(s, 0, 1)
            self.g.live[run.run_id] = run
            self.g.launch(run)
        return run, chains[0]

    def test_an_exempt_desktop_session_runs_outside_and_desktop_off_lets_the_runs_go(self):
        s = self.add("claude/desk-200", 0.0, desktop=True)
        s.job = MemberJob("t.d.claude.desk-200")
        self.g.set_exempt(s, 5, "set by Stan")
        run, chain = self.launch(s)
        self.assertEqual(chain, [run.job])  # the tree's chain fails: the desktop job sits under the app's job
        self.assertTrue(run.outside)
        s.paused = True
        self.g.allocate()
        self.assertEqual(run.job.calls[-1], ("rate", 1))
        self.g.set_desktop(False, "test")
        self.assertNotIn(s.key, self.g.sessions)
        self.assertEqual(run.job.calls[-1], ("cpu", None))  # no pause reaches it once its session is gone

    def test_a_run_admitted_before_a_pause_starts_paused(self):
        s = self.add("codex/a", 0.0)
        s.job = RunJob()
        self.g.set_exempt(s, 5, "set by Stan")
        run, _ = self.launch(s)
        self.assertEqual(run.job.calls, [])
        for held in ("session", "provider"):
            s.paused, self.g.providers["codex"]["paused"] = held == "session", held == "provider"
            run, chain = self.launch(s)
            self.assertEqual((chain, run.job.calls), ([run.job], [("rate", 1)]), held)
            self.assertIn("starts paused", self.g.log.call_args.args[0])

    def test_a_provider_pause_reaches_the_runs_outside_with_control_on_or_off(self):
        s, other = self.add("codex/a", 0.0), self.add("claude/b", 0.0)
        self.g.set_exempt(s, 5, "set by Stan")
        self.g.set_exempt(other, 5, "set by Stan")
        run, theirs = self.outside_run(s), self.outside_run(other)
        act = self.g.action
        for control in (False, True):
            self.g.control = control
            act("/api/provider", {"name": "codex", "paused": True})
            self.assertEqual(run.job.calls[-1], ("rate", 1), control)
            act("/api/provider", {"name": "codex", "paused": False})
            self.assertEqual(run.job.calls[-1], ("cpu", None), control)
        self.assertEqual(theirs.job.calls, [])  # another provider's run is left alone
        # after the exemption: resuming the session under a paused provider, or the provider under Stan's own
        # pause of the session, keeps the run held
        s.cls, s.exempt_until = "normal", None
        act("/api/provider", {"name": "codex", "paused": True})
        act("/api/session", {"key": "codex/a", "paused": True})
        act("/api/session", {"key": "codex/a", "paused": False})
        self.assertEqual(run.job.calls[-1], ("rate", 1))
        act("/api/session", {"key": "codex/a", "paused": True})
        act("/api/provider", {"name": "codex", "paused": False})
        self.assertEqual(run.job.calls[-1], ("rate", 1))
        act("/api/session", {"key": "codex/a", "paused": False})
        self.assertEqual(run.job.calls[-1], ("cpu", None))

    def test_rollback_releases_the_runs_outside_that_a_provider_pause_held(self):
        s = self.add("codex/a", 0.0)
        self.g.set_exempt(s, 5, "set by Stan")
        run = self.outside_run(s)
        self.g.action("/api/provider", {"name": "codex", "paused": True})
        self.assertEqual(run.job.calls[-1], ("rate", 1))
        root = self.g.root = mock.Mock()
        root.limits.return_value, root.pids.return_value, root.cpu.return_value = {"priority": "normal"}, [], {}
        self.g.mask = None
        with mock.patch.object(self.wj, "set_job_affinity", mock.Mock()):
            self.g.rollback("test")
        self.assertEqual(run.job.calls[-1], ("cpu", None))
        self.assertFalse(self.g.providers["codex"]["paused"])

    def test_control_off_reports_the_priorities_and_the_limit_in_effect(self):
        g, s = self.g, self.add("codex/a", 0.0)
        g.agent_io, g.agent_memory, g.pool_priority = "low", "very_low", "below_normal"
        g.pool_priority_readback = "normal"
        g.cfg["memory"]["job_commit_hard_limit_gib"] = 8.0
        g.experience = lambda now: (None, None)
        g.instance, g.sample, g.pool_cores, g.desktop_on, g.agents_gib = "t", None, 0.0, False, 0.0
        g.mem, g.trimmed_gib, g.probe_last, g.inject = self.P.MemState(), 0.0, None, None
        g.apps_rows, g.outside, g.events, g.history = [], None, [], []
        guardctl = load("scripts/guardctl.py", "guardctl")
        for control, io_, memory, hard in ((True, "low", "very_low", 8.0), (False, "normal", "normal", None)):
            g.control = control
            st = g.state()
            a, m = st["agent_priority"], st["memory"]
            self.assertEqual((a["io"], a["memory"], a["io_configured"], a["memory_configured"]),
                             (io_, memory, "low", "very_low"), control)
            self.assertEqual((m["hard_limit_gib"], m["hard_limit_configured_gib"]), (hard, 8.0), control)
            b = g.budget_of(s)
            self.assertEqual((b["io"], b["io_configured"]), (io_, "low"), control)
            text, told = guardctl.summary(st), GC.budget_text({"budget": b, "priority": "normal"}, long=True)
            if control:
                self.assertIn("agent I/O priority low  memory priority very_low  set on", text)
                self.assertIn("hard limit 8 GiB  trimmed", text)
                self.assertIn("low I/O priority, so Stan's own apps go first.", told)
            else:
                self.assertIn("agent I/O priority normal (configured low, applied when control is on)  "
                              "memory priority normal (configured very_low, applied when control is on)", text)
                self.assertIn("hard limit off (configured 8 GiB, applied when control is on)", text)
                self.assertIn("normal I/O priority. ", told)

    def test_the_outside_load_leaves_out_the_probe_and_the_runs_outside(self):
        g, s = self.g, self.add("codex/a", 0.0)
        inside, out, broken, gone = (self.outside_run(s) for _ in range(4))
        inside.outside, inside.job, out.job = False, MemJob([600]), MemJob([500, 501])
        broken.job = mock.Mock(**{"pids.side_effect": OSError("job closed")})
        gone.job, gone.state, g.lingering = MemJob([502]), "done", [g.live.pop(gone.run_id)]
        g.members, g.probe_proc, g.pool_cores, g.stop = (lambda: {10}), mock.Mock(pid=77), 0.0, mock.Mock()
        g.stop.wait.side_effect = [False, True]
        load_obs = mock.Mock()
        with mock.patch("sentinel.guardian.apps.LoadObserver", return_value=load_obs), \
                mock.patch("sentinel.guardian.apps.AppObserver", return_value=mock.Mock(**{"sample.return_value": []})):
            g.apps_loop()
        self.assertEqual(load_obs.sample.call_args.args[0], {10, 77, os.getpid(), 500, 501, 502})
        self.assertIs(g.outside, load_obs.sample.return_value)

    def test_the_srun_line_names_an_instance_other_than_main(self):
        plain = "--session abc12345 -- <command>."
        for instance, tail in (("pd", "--session abc12345 --instance pd -- <command>."), ("main", plain), (None, plain)):
            where = BudgetContextTests.where(self)
            if instance:
                where["instance"] = instance
            self.assertTrue(GC.budget_text(where, long=True).endswith(tail), instance)

    def test_whereis_keeps_one_deadline_for_the_handshake_and_the_answer(self):
        key = b"k" * 64

        def daemon_side(conn, delay, answer, got):
            try:
                time.sleep(delay)
                GC.handshake(conn, key, server=True, seconds=5)
                got.append(conn.recv_bytes())
                if answer:
                    conn.send_bytes(b"J" + json.dumps({"pid": 1}).encode())
            except Exception:  # the client gave up first
                pass

        with tempfile.TemporaryDirectory() as d:
            Path(d, "pipe-authkey").write_text(key.decode(), encoding="ascii")
            # the daemon answers; it accepts late and never answers; its handshake comes after the deadline
            for delay, answer, want, asked in ((0.0, True, {"pid": 1}, True), (0.6, False, None, True),
                                               (1.5, False, None, False)):
                a, b, got = *Pipe(), []
                t = threading.Thread(target=daemon_side, args=(a, delay, answer, got), daemon=True)
                with mock.patch.object(GC, "home_dir", lambda instance: Path(d)), \
                        mock.patch.object(GC, "Client", lambda *args, **kw: b):
                    t.start()
                    t0 = time.monotonic()
                    self.assertEqual(GC.whereis(1, "t", timeout=1.0), want, delay)
                    took = time.monotonic() - t0
                t.join(5)
                a.close()
                self.assertLess(took, 1.4, delay)  # 1.0 s in all, not 1.0 s after a handshake of up to 5 s
                self.assertEqual(bool(got) and json.loads(got[0][1:])["op"] == "whereis", asked, delay)

    def test_the_adopt_hook_stops_waiting_for_the_context_in_time(self):
        hook, row = load_hook(), {"cli_pid": 4242, "event": "SessionStart"}
        with mock.patch.object(GC, "whereis", side_effect=lambda *a, **k: time.sleep(3)):  # a busy pipe
            t0 = time.monotonic()
            self.assertEqual(hook.context("claude", row, "main", wait=0.2), "")
            self.assertLess(time.monotonic() - t0, 1.5)
        self.assertIn("TimeoutError", row["context_error"])


if __name__ == "__main__":
    unittest.main()
