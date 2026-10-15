#!/usr/bin/env python3
"""Start the Guardian daemon. Started inside a job (a scheduled task, an agent app) with stdout going to a file, it
starts itself again outside any job through WMI and exits, so srun and gagent runs can enter its jobs. With stdout
on a console or a pipe, with --stay-in-job, or when it cannot start again (a % in its command line, WMI fails, the
new copy exits within 3 s), it stays in the job and warns."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.daemon import main

if __name__ == "__main__":
    raise SystemExit(main())
