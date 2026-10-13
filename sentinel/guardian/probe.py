"""Scheduler probe: a Normal-priority thread that wakes every frame and does a little work, like a video player.

It runs as its own process outside the agent pool and prints one JSON line per second:
frames, dropped (finished after the next frame deadline), lag p95 / max in ms (wake-up plus work lateness).
It measures whether a Normal-priority foreground thread still gets the CPU on time; it does not see the GPU,
the display pipeline or a browser. Cost: about 1 ms of work per 16.7 ms frame, so 6% of one core.
Usage: python -I probe.py [work_ms]
"""
import json
import sys
import time

FRAME = 1 / 60


def spin(seconds):
    end = time.perf_counter() + seconds
    while time.perf_counter() < end:
        pass


def main():
    work = float(sys.argv[1]) / 1000 if len(sys.argv) > 1 else 0.001
    nxt = time.perf_counter() + FRAME
    window_end = time.perf_counter() + 1.0
    lags, frames, dropped = [], 0, 0
    while True:
        d = nxt - time.perf_counter()
        if d > 0:
            time.sleep(d)
        spin(work)
        fin = time.perf_counter()
        lags.append((fin - nxt) * 1000)
        frames += 1
        if fin > nxt + FRAME:
            dropped += 1
        nxt += FRAME
        if fin > nxt:
            nxt = fin  # skip frames already missed, like a player
        if fin >= window_end:
            lags.sort()
            out = {"t": time.time(), "frames": frames, "dropped": dropped,
                   "drop_pct": round(100 * dropped / max(1, frames), 1),
                   "lag_p95_ms": round(lags[min(len(lags) - 1, int(0.95 * len(lags)))], 1),
                   "lag_max_ms": round(lags[-1], 1)}
            try:
                print(json.dumps(out), flush=True)
            except OSError:
                return  # the daemon went away
            lags, frames, dropped = [], 0, 0
            window_end = fin + 1.0


if __name__ == "__main__":
    main()
