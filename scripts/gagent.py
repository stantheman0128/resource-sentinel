#!/usr/bin/env python3
"""Start an agent CLI inside Guardian, so the CLI and every command it runs share one session job.

  gagent claude                                        Claude Code in its own console window
  gagent codex --session fix-12 --headless -- exec "run the tests"     output comes back here
  gagent gemini --cls batch
  gagent cursor --headless -- -p "explain this repo"
  gagent list                                          the CLIs Guardian knows and where they are installed

Providers: claude, codex, gemini, cursor (cursor-agent), grok, antigravity (agy). Without --headless the CLI opens
its own console window, because an interactive CLI needs a real terminal. --start starts the daemon first if it is
not running.
"""
import argparse
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import CLASSES, ping, run, start_daemon
from sentinel.guardian.providers import PROVIDERS


def main(argv=None):
    ap = argparse.ArgumentParser(usage="gagent <provider|list> [options] [-- CLI arguments]")
    ap.add_argument("provider", choices=sorted(PROVIDERS) + ["list"])
    ap.add_argument("--session", help="session name (default: <provider>-<time>)")
    ap.add_argument("--cls", choices=CLASSES, default="normal")
    ap.add_argument("--headless", action="store_true", help="no console window; relay the CLI's output here")
    ap.add_argument("--instance", default="main")
    ap.add_argument("--port", type=int, default=8765, help="dashboard port when --start starts the daemon")
    ap.add_argument("--start", action="store_true", help="start the daemon first if it is not running")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("args", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    if a.provider == "list":
        for name, p in sorted(PROVIDERS.items()):
            print(f"{name:12} {p.command:14} {shutil.which(p.command) or 'not on PATH'}")
        return 0
    p = PROVIDERS[a.provider]
    if not shutil.which(p.command):
        print(f"[guardian] {p.command} is not on PATH", file=sys.stderr)
        return 127
    if a.start and not start_daemon(a.instance, a.port):
        print(f"[guardian] the daemon did not start; see ~/.resource-sentinel/guardian/{a.instance}-daemon.log",
              file=sys.stderr)
    elif not ping(a.instance):
        print(f"[guardian] Guardian {a.instance} is not running (add --start); the CLI runs without control",
              file=sys.stderr)
    extra = a.args[1:] if a.args[:1] == ["--"] else a.args
    session = a.session or f"{a.provider}-{time.strftime('%H%M%S')}"
    if not a.headless:
        print(f"[guardian] {p.command} opens in its own window, session {a.provider}/{session}", file=sys.stderr)
    return run([p.command] + extra, a.provider, session, a.cls, None, not a.headless, a.instance, a.verbose)


if __name__ == "__main__":
    raise SystemExit(main())
