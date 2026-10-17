"""Pure decision logic for the Guardian: no Win32 calls and no clock.

Every input arrives as plain values (time included), so a recorded run can be replayed tick by tick.
The daemon applies the returned decisions and records them; nothing here touches a process.

Measurements this policy relies on (audits/20261013-session-control/poc/exp, 2026-10-13, Ryzen 5 7500F,
12 logical CPUs, build 26340.9616). Observations first; the inference is marked as such.
  E10 Windows WEIGHT_BASED on two sibling jobs, same worker, 3 rounds of 5/5, 8/2, 2/8:
      parent quota is the limit (2-core hard cap, 6 CPUs about half idle): share of A 0.48-0.50 for every
      setting, no measurable difference. Processors are the limit (2 CPUs 100% busy, no cap): the order
      8/2 > 5/5 > 2/8 held in all 3 rounds, but the 5/5 baseline itself moved between 0.27 and 0.44.
      Inference: WEIGHT_BASED acts when runnable threads compete for processors, not on how a parent's
      hard-cap quota is split. Guardian's pool always runs under a parent hard cap, which is the first case.
  E8b per-session hard caps relative to the parent landed on target (2.44 / 0.65 for 2.4 / 0.6).
  E9  a below_normal pool kept a 60 fps foreground task at baseline (0% dropped, p95 3.5 ms) while the pool
      still used 3.75 of 4 CPUs; with no control the same task dropped 6.5% of frames.
So: session importance = Guardian allocation weights turned into per-session hard caps (weighted max-min),
chosen because a hard cap is predictable and can be read back, and because native weights showed no effect
under the parent cap Guardian needs. Foreground protection = pool priority below_normal plus the dynamic
parent cap. A cap is a ceiling: it does not promise the session that much CPU.
"""
import math
from dataclasses import dataclass, field, replace

POLICY_VERSION = "guardian-policy/1"

DEFAULTS = {
    "cpu": {
        "initial_cap_percent": 50,
        "minimum_cap_percent": 10,
        "maximum_cap_percent": 95,          # Stan: agents may use up to 95% of the machine
        "decrease_factor": 0.8,
        "increase_step_percentage_points": 5,
        "healthy_before_increase_seconds": 20,
        "increase_spacing_seconds": 10,
        "decrease_cooldown_seconds": 3,
        # R1 (2026-10-17). None turns a rule off and gives the controller of 10-13.
        "backoff_idle_cores": None,              # degraded while this many CPUs sit idle: not contention, cap held
        "recover_idle_cores": None,              # this many idle CPUs allow the faster recovery below
        "recover_idle_wait_seconds": 5,          # healthy seconds before a faster recovery step
        "recover_idle_share": 0.5,               # a faster step hands the agents this share of the idle CPUs
        "no_experience_probe_max_percent": 50,   # doc rule when nothing measures the foreground
        "proxy_probe_max_percent": 95,           # scheduler probe healthy and pool below_normal (E9)
        "demand_fraction_for_increase": 0.8,
        "memory_alarm_cap_percent": 20,
        "stale_cap_percent": 50,
        "pool_priority": "below_normal",
        "allocation_weights": {"focus": 8, "normal": 5, "batch": 2},
        "contention_fraction": 0.85,
        "relax_after_ticks": 2,
        "min_session_cores": 0.05,
        "agent_cpu_low_cores": 0.5,
    },
    "memory": {
        "physical_available_target_gib": 6,      # Stan keeps 6 GiB for himself
        "physical_admission_margin_gib": 2,
        "commit_headroom_target_gib": 4,
        "commit_admission_margin_gib": 1,
        "job_commit_hard_limit_gib": None,
        "exploration_reservation_gib": 0.5,
        "agent_memory_priority": "low",          # agents' pages leave RAM's standby list before Stan's
    },
    "io": {
        "agent_io_priority": "low",              # Stan's disk reads and writes go first
    },
    "observation": {
        "sample_interval_ms": 1000,
        "stale_core_sample_seconds": 3,
        "probe_warning_lag_ms": 10,
        "probe_warning_drop_percent": 2.0,     # one dropped frame in a 60-frame window is idle noise (measured)
        "probe_severe_lag_ms": 200,
        "media_window_seconds": 10,
        "media_minimum_frame_count": 120,
        "media_drop_warning_fraction": 0.01,
        "sensor_valid_seconds": 5,
    },
    "queue": {
        "order": "class_fifo",                   # R3: one of QUEUE_ORDERS, see queue_order
        "default_run_seconds": 60,               # expected length of a command that has no finished run yet
        "exempt_minutes": 60,                    # how long Stan's exemption lasts when he names no time
    },
    "unknown_work": {
        "maximum_simultaneous_launch_observations": 2,
        "launch_spacing_ms": 500,
        "initial_observation_seconds": 2,
    },
    "safety": {
        "auto_kill_user_work": False,
        "auto_suspend_user_work": False,
        "kill_interactive_jobs_on_last_handle_close": False,
    },
}


def merged(base, over):
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in base.items()}
    for k, v in (over or {}).items():
        out[k] = merged(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


# ---- experience: turn sensor windows into ok / warn / degraded / severe ------------------------------

def probe_window_level(window, obs):
    """One second of the scheduler probe: {'lag_p95_ms', 'lag_max_ms', 'drop_pct', 'frames'}."""
    if not window or not window.get("frames"):
        return None
    if window["lag_max_ms"] >= obs["probe_severe_lag_ms"]:
        return "severe"
    if window["lag_p95_ms"] > obs["probe_warning_lag_ms"] or window["drop_pct"] > obs["probe_warning_drop_percent"]:
        return "warn"
    return "ok"


def media_window_level(window, obs):
    """A browser companion window: deltas of droppedVideoFrames and totalVideoFrames over a playing interval.
    Reset counters, seeking, paused or background playback and short windows are not evidence either way."""
    if not window or window.get("state") != "playing" or window.get("reset"):
        return None
    total, dropped = window.get("d_total", 0), window.get("d_dropped", 0)
    if window.get("seconds", 0) < obs["media_window_seconds"] or total < obs["media_minimum_frame_count"]:
        return None
    return "warn" if dropped / total > obs["media_drop_warning_fraction"] else "ok"


def sustained(levels):
    """2 of the last 3 valid windows over the line = degraded; any severe window = severe."""
    recent = [x for x in levels if x][-3:]
    if any(x == "severe" for x in recent[-1:]):
        return "severe"
    if sum(1 for x in recent if x in ("warn", "severe")) >= 2:
        return "degraded"
    return "ok" if recent else None


# ---- the parent cap ------------------------------------------------------------------------------

@dataclass
class Sample:
    t: float
    age_s: float
    cpu_busy: float = None            # whole machine, 0..1
    pool_cores: float = None          # AllAgents usage over the last tick
    available_gib: float = None
    commit_headroom_gib: float = None
    experience: str = None            # ok | degraded | severe | None (no valid sensor)
    experience_kind: str = None       # media | probe | injected
    pool_priority: str = "below_normal"
    ncpu: int = 12                    # CPUs open to agents
    machine_cpus: int = None          # every logical CPU; None = ncpu


@dataclass
class CapState:
    cap: float
    last_decrease: float = -math.inf
    last_increase: float = -math.inf
    healthy_since: float = None
    mode: str = "UNKNOWN"
    admission_open: bool = True
    admission_reason: str = ""
    notes: list = field(default_factory=list)


def max_allowed(sample, cfg):
    c = cfg["cpu"]
    if sample.experience_kind == "media" and sample.experience == "ok":
        return c["maximum_cap_percent"]
    if sample.experience_kind == "probe" and sample.experience == "ok" and sample.pool_priority == "below_normal":
        return min(c["maximum_cap_percent"], c["proxy_probe_max_percent"])
    return min(c["maximum_cap_percent"], c["no_experience_probe_max_percent"])


def cap_step(state, s, cfg):
    """One control tick. Returns (new_state, decision or None). decision = dict(kind, before, after, reason)."""
    c, m, o = cfg["cpu"], cfg["memory"], cfg["observation"]
    st = replace(state, notes=[])
    before = st.cap

    def decide(kind, after, reason):
        st.cap = float(after)
        if after < before:
            st.last_decrease = s.t
            st.healthy_since = None
        elif after > before:
            st.last_increase = s.t
        return st, {"kind": kind, "before": before, "after": st.cap, "reason": reason}

    if s.age_s > o["stale_core_sample_seconds"] or s.cpu_busy is None or s.available_gib is None:
        st.mode, st.admission_open, st.admission_reason = "UNKNOWN", False, "DEGRADED_TELEMETRY"
        st.healthy_since = None
        if st.cap > c["stale_cap_percent"]:
            return decide("stale_clamp", c["stale_cap_percent"], "core telemetry older than "
                          f"{o['stale_core_sample_seconds']} s: no new admissions, cap held at or below "
                          f"{c['stale_cap_percent']}%")
        return st, None

    ram_low = s.available_gib < m["physical_available_target_gib"]
    commit_low = s.commit_headroom_gib is not None and s.commit_headroom_gib < m["commit_headroom_target_gib"]
    st.mode = {"ok": "OBSERVED_OK" if s.experience_kind == "media" else "PROXY_OK", "degraded": "DEGRADED",
               "severe": "DEGRADED"}.get(s.experience, "SYSTEM_ONLY")
    if ram_low or commit_low:
        what = "Available RAM" if ram_low else "commit headroom"
        st.admission_open, st.admission_reason = False, "CAPACITY_PRESSURE"
        st.healthy_since = None
        st.notes.append("CPU throttling does not return memory")
        if st.cap > c["memory_alarm_cap_percent"]:
            return decide("memory_alarm", c["memory_alarm_cap_percent"],
                          f"{what} below target: no new admissions, cap to {c['memory_alarm_cap_percent']}%")
        return st, None
    st.admission_open, st.admission_reason = True, ""

    ceiling = max_allowed(s, cfg)
    pool = s.pool_cores or 0.0
    cap_cores = st.cap / 100 * s.ncpu
    machine = s.machine_cpus or s.ncpu
    # idle CPUs open to the agents, at least: the CPUs kept from them count as idle, and the probe runs pinned to
    # the agents' CPUs, so only theirs can explain its lateness
    idle = max(0.0, machine * (1 - s.cpu_busy) - (machine - s.ncpu))
    if s.experience in ("degraded", "severe"):
        if pool < c["agent_cpu_low_cores"]:
            st.healthy_since = None
            st.notes.append("intervention_no_observed_benefit: foreground degraded but agents use little CPU")
            return st, None
        if s.experience == "degraded" and c["backoff_idle_cores"] is not None and idle >= c["backoff_idle_cores"]:
            # with CPUs left idle over the window the foreground did not wait for a CPU, so a lower agent cap would
            # not have helped; the healthy clock keeps running. A severe window still backs off.
            st.notes.append(f"not_cpu_contention: foreground degraded with {idle:.1f} CPUs idle, cap held")
            return st, None
        st.healthy_since = None
        cooled = s.t - st.last_decrease >= c["decrease_cooldown_seconds"]
        if cooled and st.cap > c["minimum_cap_percent"]:
            after = max(c["minimum_cap_percent"], math.floor(st.cap * c["decrease_factor"]))
            return decide("foreground_backoff", after, f"foreground {s.experience} ({s.experience_kind}): "
                          f"cap x{c['decrease_factor']}")
        return st, None

    if st.cap > ceiling:
        return decide("ceiling_clamp", ceiling, f"no valid foreground sensor for a higher cap (mode {st.mode})")
    if st.healthy_since is None:
        st.healthy_since = s.t
    healthy_for = s.t - st.healthy_since
    wants_more = pool >= c["demand_fraction_for_increase"] * cap_cores
    free = min(idle, s.ncpu - pool)  # idle CPUs the agents could grow into
    fast = c["recover_idle_cores"] is not None and free >= c["recover_idle_cores"]
    wait = c["recover_idle_wait_seconds"] if fast else c["healthy_before_increase_seconds"]
    if (healthy_for >= wait and wants_more and st.cap < ceiling
            and s.t - st.last_increase >= c["increase_spacing_seconds"]):
        step = c["increase_step_percentage_points"]
        if fast:
            step = max(step, math.floor(100 * c["recover_idle_share"] * free / s.ncpu))
        after = min(ceiling, st.cap + step)
        return decide("recover", after, f"healthy {healthy_for:.0f} s and agents use "
                      f"{pool:.1f} of {cap_cores:.1f} cores"
                      + (f", {free:.1f} CPUs idle" if fast else "") + f": +{step} points")
    return st, None


# ---- sessions inside the pool --------------------------------------------------------------------

def weighted_maxmin(budget, demand, weight):
    """Give every session min(demand, its weighted share); split what the satisfied ones leave by weight."""
    alloc, left, b = {}, dict(demand), budget
    while left:
        unit = b / sum(weight[k] for k in left)
        done = [k for k in left if left[k] <= weight[k] * unit]
        if not done:
            alloc.update({k: weight[k] * unit for k in left})
            break
        for k in done:
            alloc[k] = left.pop(k)
            b -= alloc[k]
    return alloc


@dataclass
class AllocState:
    caps: dict = field(default_factory=dict)       # session key -> cores, None = uncapped
    relaxed_ticks: int = 0


def allocate(state, budget_cores, sessions, cfg):
    """sessions: {key: {'allocation_weight', 'usage', 'paused'}}. Returns (new_state, changes {key: cores or None})."""
    c = cfg["cpu"]
    active = {k: v for k, v in sessions.items() if not v.get("paused")}
    used = sum(v["usage"] for v in active.values())
    # A session presses its cap when it uses at least 90% of a cap Guardian set. Only then is its demand unknown
    # (it might take more); everyone else is asked for what they use plus headroom, so a light session lends
    # what it does not use. While anyone presses, caps stay: releasing them would hand the lent share back and
    # flip between capped and uncapped every few ticks.
    pressing = {k for k, v in active.items() if state.caps.get(k) is not None
                and v["usage"] >= 0.9 * state.caps[k] and v["usage"] >= c["min_session_cores"]}
    contended = len(active) > 1 and (used >= c["contention_fraction"] * budget_cores or bool(pressing))
    new = AllocState(dict(state.caps), state.relaxed_ticks)
    if not contended:
        new.relaxed_ticks += 1
        if new.relaxed_ticks >= c["relax_after_ticks"]:
            new.caps = {k: None for k in active}
        return new, _diff(state.caps, new.caps, active)
    new.relaxed_ticks = 0
    demand = {k: math.inf if k in pressing else v["usage"] * 1.2 + 0.2 for k, v in active.items()}
    alloc = weighted_maxmin(budget_cores, demand, {k: v["allocation_weight"] for k, v in active.items()})
    new.caps = {k: max(c["min_session_cores"], round(a, 2)) for k, a in alloc.items()}
    return new, _diff(state.caps, new.caps, active)


def _diff(old, new, active):
    out = {}
    for k in active:
        a, b = old.get(k), new.get(k)
        if a is None and b is None:
            continue
        if a is None or b is None or abs(a - b) > max(0.05, 0.05 * a):
            out[k] = b
    return out


# ---- admission -----------------------------------------------------------------------------------

def admission(est_gib, s, unused_ram_gib, unused_commit_gib, cap_state, cfg, manual_hold=False):
    """Returns (ok, reason, numbers). Room = current headroom minus the target, the margin and growth that
    running work already reserved but has not used yet (what it already uses is in the live numbers)."""
    m = cfg["memory"]
    ram_room = (s.available_gib or 0) - m["physical_available_target_gib"] - m["physical_admission_margin_gib"] \
        - unused_ram_gib
    commit_room = (s.commit_headroom_gib if s.commit_headroom_gib is not None else math.inf) \
        - m["commit_headroom_target_gib"] - m["commit_admission_margin_gib"] - unused_commit_gib
    nums = {"est_gib": round(est_gib, 2), "ram_room_gib": round(ram_room, 2),
            "commit_room_gib": round(commit_room, 2) if commit_room != math.inf else None}
    if manual_hold:
        return False, "HELD_BY_USER", nums
    if not cap_state.admission_open:
        return False, cap_state.admission_reason or "ADMISSION_CLOSED", nums
    if est_gib > ram_room:
        return False, "CAPACITY_PRESSURE: RAM room {:.1f} GiB < estimate {:.1f} GiB".format(ram_room, est_gib), nums
    if est_gib > commit_room:
        return False, "CAPACITY_PRESSURE: commit room {:.1f} GiB < estimate {:.1f} GiB".format(commit_room, est_gib), nums
    return True, "", nums


def launch_slot(now, active_starts, last_launch, cfg):
    """Burst control for work without a profile: at most N launches observed at once, spaced apart.
    active_starts = start times of unprofiled runs still inside their observation window."""
    u = cfg["unknown_work"]
    live = [t for t in active_starts if now - t < u["initial_observation_seconds"]]
    if len(live) >= u["maximum_simultaneous_launch_observations"]:
        return False, "launch observation slots full"
    if now - last_launch < u["launch_spacing_ms"] / 1000:
        return False, "launch spacing"
    return True, ""


def estimate(profile_rows, requested_gib, cfg):
    """Memory estimate for a new run: explicit request > profile of successful runs > exploration default.
    profile_rows = peak commit (GiB) of earlier successful, unconstrained runs with the same fingerprint."""
    if requested_gib:
        return float(requested_gib), "requested", 0
    rows = sorted(r for r in profile_rows if r is not None)
    n = len(rows)
    if n >= 3:
        return rows[min(n - 1, math.ceil(0.9 * n) - 1)], f"profile p90 of {n}", n
    if n:
        return rows[-1] * 1.2, f"max of {n} x1.2", n
    return cfg["memory"]["exploration_reservation_gib"], "exploration", 0


# ---- the srun queue ------------------------------------------------------------------------------

CLASS_RANK = {"exempt": -1, "focus": 0, "normal": 1, "batch": 2}
QUEUE_ORDERS = ("class_fifo", "fifo", "sjf", "hrrn", "fair")


def estimate_seconds(durations, cfg):
    """Expected wall seconds of a new run: the median of earlier successful runs of the same command."""
    rows = sorted(d for d in durations if d is not None and d >= 0)
    n = len(rows)
    if not n:
        return float(cfg["queue"]["default_run_seconds"]), "default"
    return (rows[n // 2] if n % 2 else (rows[n // 2 - 1] + rows[n // 2]) / 2), f"median of {n}"


def queue_order(runs, order, now):
    """Waiting runs in the order admission tries them. A run is a dict with cls, t_request, est_s (from
    estimate_seconds) and share (CPU seconds its session has used, over its class weight). Stan's exempt runs come
    first in every order. Admission still tries each run in turn, so a small run starts while a bigger one ahead
    of it waits for memory.
      class_fifo  class rank, then arrival (the order of 10-13)
      fifo        arrival only
      sjf         shortest expected run first; a long run waits for as long as short ones keep arriving
      hrrn        highest response ratio (wait + expected) / expected: short runs first, and waiting lifts a
                  long one until it goes
      fair        the session that used the least CPU per class weight first"""
    if order not in QUEUE_ORDERS:
        raise ValueError(f"queue order must be one of {', '.join(QUEUE_ORDERS)}")

    def key(r):
        late = r["cls"] != "exempt"
        if order == "fifo":
            return late, r["t_request"]
        if order == "sjf":
            return late, r["est_s"], r["t_request"]
        if order == "hrrn":
            est = max(r["est_s"], 1.0)
            return late, -(now - r["t_request"] + est) / est, r["t_request"]
        if order == "fair":
            return late, r["share"], r["t_request"]
        return late, CLASS_RANK.get(r["cls"], 1), r["t_request"]
    return sorted(runs, key=key)
