#!/usr/bin/env python3
"""Start the Guardian daemon. Start it from Explorer, a plain console or a scheduled task so it sits in no app's
job; started from inside an agent app it still works, but its whole tree then nests under that app's job."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.daemon import main

if __name__ == "__main__":
    raise SystemExit(main())
