import importlib.util
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def load():
    spec = importlib.util.spec_from_file_location("guardian_install_autostart",
                                                  ROOT / "scripts" / "guardian-install-autostart.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AutostartTaskTests(unittest.TestCase):
    def setUp(self):
        self.inst = load()

    def test_arguments_keep_quoted_paths_for_cmd(self):
        args = self.inst.arguments(Path(r"C:\Py 3\python.exe"), Path(r"C:\R & D\scripts\guardian.py"), 8769,
                                   Path(r"C:\Users\x\.resource-sentinel\guardian\main-daemon.log"))
        self.assertTrue(args.startswith(r"--headless C:\Windows\System32\cmd.exe /d /s /c " + '"'))
        # /s: cmd drops the first and the last quote and runs what is between them as written
        inner = args.split(" /c ", 1)[1][1:-1]
        self.assertEqual(inner, r'"C:\Py 3\python.exe" -I "C:\R & D\scripts\guardian.py" --instance main '
                                r'--port 8769 >> "C:\Users\x\.resource-sentinel\guardian\main-daemon.log" 2>&1')

    def test_task_xml_settings_and_escaping(self):
        args = self.inst.arguments(Path(r"C:\Python313\python.exe"), Path(r"C:\R & D\scripts\guardian.py"), 8765,
                                   Path(r"C:\log.txt"))
        root = ET.fromstring(self.inst.task_xml(r"PC\stan", args, Path(r"C:\R & D")).encode("utf-16"))
        get = lambda path: root.find(path, NS).text
        self.assertEqual(get("t:Settings/t:ExecutionTimeLimit"), "PT0S")
        self.assertEqual(get("t:Settings/t:MultipleInstancesPolicy"), "IgnoreNew")
        self.assertEqual(get("t:Settings/t:DisallowStartIfOnBatteries"), "false")
        self.assertEqual(get("t:Triggers/t:LogonTrigger/t:UserId"), r"PC\stan")
        self.assertEqual(get("t:Principals/t:Principal/t:RunLevel"), "LeastPrivilege")
        self.assertEqual(get("t:Actions/t:Exec/t:Command"), r"C:\Windows\System32\conhost.exe")
        self.assertEqual(get("t:Actions/t:Exec/t:Arguments"), args)
        self.assertEqual(get("t:Actions/t:Exec/t:WorkingDirectory"), r"C:\R & D")


if __name__ == "__main__":
    unittest.main()
