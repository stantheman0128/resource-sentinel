#!/usr/bin/env python3
"""Run a command, or a whole agent CLI, inside a Guardian session job.

  srun --provider codex --session fix-123 -- codex exec "run the tests"
  srun --provider claude --session demo --cls focus --console -- claude
  srun --provider claude --session s1 --bash 'pytest -q'      (what the route hook writes)

A whole CLI started this way puts the agent and every tool command it runs into one session job, so pause,
class and caps apply to all of it. --console opens the CLI in its own window (interactive). If the daemon is not
running the command runs locally and stderr says coverage=unavailable.
"""
import argparse
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import CLASSES, run

GIT_BASH = r"C:\Program Files\Git\bin\bash.exe"


def main(argv=None):
    ap = argparse.ArgumentParser(usage="srun [options] -- command [args...]  |  srun [options] --bash 'command'")
    ap.add_argument("--provider", default="other")
    ap.add_argument("--session", default="default")
    ap.add_argument("--cls", choices=CLASSES, default="normal")
    ap.add_argument("--est-gib", type=float, help="memory estimate for admission (default: profile or 0.5 GiB)")
    ap.add_argument("--console", action="store_true", help="own console window, for interactive CLIs")
    ap.add_argument("--bash", metavar="COMMAND", help="run COMMAND with bash -c (Git Bash on Windows)")
    ap.add_argument("--instance", default="main")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if a.bash is not None:
        bash = shutil.which("bash") or GIT_BASH
        cmd = [bash, "-c", a.bash]
    if not cmd:
        ap.error("nothing to run")
    return run(cmd, a.provider, a.session, a.cls, a.est_gib, a.console, a.instance, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
