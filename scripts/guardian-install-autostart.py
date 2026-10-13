#!/usr/bin/env python3
"""Start the Guardian daemon (instance main) at logon through a scheduled task, so the PATH wrappers and the adopt
hooks find it running. Without --apply it only prints what it would change.

  python -I scripts/guardian-install-autostart.py [--port N] [--remove] [--apply]

The task, ResourceSentinelGuardian, runs conhost.exe --headless, so no window opens, with cmd.exe appending the
daemon's output to ~/.resource-sentinel/guardian/main-daemon.log. It has no run time limit and never starts a
second copy. --apply registers it, replacing an earlier version, and starts it when the daemon does not answer yet.
--remove deletes the task and leaves a running daemon alone. Run it from the main checkout: the task calls the
guardian.py that sits next to this script, with the Python that runs this script.

Task Scheduler puts the action in a job of its own (no limits, no breakaway, measured 2026-10-14), so Guardian's
jobs nest under that job. Stop-ScheduledTask ends only conhost; cmd and the daemon keep running.
"""
import argparse
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import home_dir, ping

TASK = "ResourceSentinelGuardian"
DAEMON = ROOT / "scripts" / "guardian.py"
CONHOST = r"C:\Windows\System32\conhost.exe"
CMD = r"C:\Windows\System32\cmd.exe"


def arguments(python, daemon, port, log):
    """conhost's arguments. cmd /s /c strips the outer quotes and keeps the rest as written."""
    inner = f'"{python}" -I "{daemon}" --instance main --port {port} >> "{log}" 2>&1'
    return f'--headless {CMD} /d /s /c "{inner}"'


def task_xml(user, args, workdir):
    """At logon of user, no time limit, one copy, normal priority (the task default 7 is below normal)."""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Guardian daemon, instance main (guardian-install-autostart.py --remove deletes it)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{escape(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{escape(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{escape(CONHOST)}</Command>
      <Arguments>{escape(args)}</Arguments>
      <WorkingDirectory>{escape(str(workdir))}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def schtasks(*args):
    return subprocess.run(["schtasks.exe", *args], capture_output=True, text=True, timeout=60)


def port_free(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765, help="the daemon's dashboard port (default 8765)")
    ap.add_argument("--remove", action="store_true", help="delete the task instead")
    ap.add_argument("--apply", action="store_true", help="make the change (default: print it only)")
    a = ap.parse_args(argv)
    exists = schtasks("/query", "/tn", TASK).returncode == 0
    up = ping("main")
    if a.remove:
        if not exists:
            print(f"no task {TASK}; nothing to change")
            return 0
        print(f"{'would delete' if not a.apply else 'delete'} the scheduled task {TASK}")
        if not a.apply:
            print("\nNothing changed. Add --apply to delete it.")
            return 0
        r = schtasks("/delete", "/tn", TASK, "/f")
        if r.returncode:
            print(f"schtasks /delete failed: {(r.stderr or r.stdout).strip()}")
            return 1
        if up:
            print(f"the daemon keeps running (pid {up.get('pid')}) until logoff or taskkill /PID {up.get('pid')}")
        return 0
    python = Path(sys.executable).resolve()
    if "\\.claude\\worktrees\\" in str(ROOT).lower() or "\\windowsapps\\" in str(python).lower():
        print(f"warning: the task would call {python} and {DAEMON}; run this from the main checkout with a "
              "regular python.exe so it keeps working")
    if not up and not port_free(a.port):
        print(f"port {a.port} is in use by another program, so the daemon would stop at once; pick a free one "
              "with --port")
        return 1
    log = home_dir("main").parent / "main-daemon.log"
    args = arguments(python, DAEMON, a.port, log)
    print(f"{'would ' if not a.apply else ''}{'replace' if exists else 'register'} the scheduled task {TASK}: at "
          f"logon, no time limit, one copy\n  {CONHOST} {args}")
    if up:
        print(f"the daemon already runs (pid {up.get('pid')}); the task takes effect at the next logon")
    if not a.apply:
        print("\nNothing changed. Add --apply to register it.")
        return 0
    user = f"{os.environ['USERDOMAIN']}\\{os.environ['USERNAME']}"
    with tempfile.TemporaryDirectory() as d:
        xml = Path(d) / "task.xml"
        xml.write_text(task_xml(user, args, ROOT), encoding="utf-16")  # schtasks /xml reads UTF-16
        r = schtasks("/create", "/tn", TASK, "/xml", str(xml), "/f")
    if r.returncode:
        print(f"schtasks /create failed: {(r.stderr or r.stdout).strip()}")
        return 1
    if up:
        return 0
    schtasks("/run", "/tn", TASK)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 20:
        up = ping("main")
        if up:
            print(f"the daemon is up (pid {up.get('pid')}), dashboard http://127.0.0.1:{a.port}/")
            return 0
        time.sleep(0.5)
    print(f"the daemon did not answer within 20 s; see {log}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
