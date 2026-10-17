import contextlib
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinel.guardian import daemon as D
from sentinel.guardian import policy as P

CFG = P.merged(P.DEFAULTS, {})


def sample(t, **kw):
    base = dict(t=t, age_s=0.5, cpu_busy=0.5, pool_cores=6.0, available_gib=30.0, commit_headroom_gib=50.0,
                experience="ok", experience_kind="probe", pool_priority="below_normal", ncpu=12)
    base.update(kw)
    return P.Sample(**base)


def run(state, samples):
    return run_cfg(state, samples, CFG)


def run_cfg(state, samples, cfg):
    out = []
    for s in samples:
        state, d = P.cap_step(state, s, cfg)
        out.append((s.t, state.cap, d))
    return state, out


class CapControllerTests(unittest.TestCase):
    def test_injected_lag_backs_off_fast_then_recovers_slowly(self):
        st = P.CapState(cap=60)
        # 6 s of degraded foreground with busy agents: x0.8 at most every 3 s
        st, trace = run(st, [sample(t, experience="degraded", pool_cores=7.0) for t in range(6)])
        caps = [c for _, c, _ in trace]
        self.assertEqual(caps[0], 48)          # floor(60 * 0.8)
        self.assertEqual(caps[1], 48)          # cooldown
        self.assertEqual(caps[3], 38)          # floor(48 * 0.8)
        # healthy again: nothing for 20 s, then +5 at most every 10 s
        st, trace = run(st, [sample(t, pool_cores=11.0) for t in range(6, 60)])  # agents want more than the cap
        ups = [(t, d["after"]) for t, _, d in trace if d and d["kind"] == "recover"]
        self.assertEqual(ups[0], (26, 43))
        self.assertEqual(ups[1], (36, 48))
        self.assertTrue(all(b - a >= 10 for (a, _), (b, _) in zip(ups, ups[1:])))

    def test_no_backoff_when_agents_are_idle(self):
        st, trace = run(P.CapState(cap=60), [sample(t, experience="degraded", pool_cores=0.1) for t in range(5)])
        self.assertEqual(st.cap, 60)
        self.assertIn("intervention_no_observed_benefit", st.notes[0])

    def test_no_increase_without_demand(self):
        st, trace = run(P.CapState(cap=40), [sample(t, pool_cores=1.0) for t in range(80)])
        self.assertEqual(st.cap, 40)

    def test_low_ram_closes_admission_and_clamps(self):
        st, trace = run(P.CapState(cap=70), [sample(0, available_gib=5.0)])
        self.assertEqual(st.cap, 20)
        self.assertFalse(st.admission_open)
        self.assertEqual(st.admission_reason, "CAPACITY_PRESSURE")
        self.assertIn("CPU throttling does not return memory", st.notes)

    def test_stale_sample_holds_at_or_below_50(self):
        st, trace = run(P.CapState(cap=80), [sample(0, age_s=4.0)])
        self.assertEqual(st.cap, 50)
        self.assertEqual(st.mode, "UNKNOWN")
        self.assertFalse(st.admission_open)

    def test_no_sensor_limits_to_50(self):
        st, _ = run(P.CapState(cap=70), [sample(0, experience=None, experience_kind=None)])
        self.assertEqual(st.cap, 50)
        self.assertEqual(st.mode, "SYSTEM_ONLY")

    def test_probe_counts_only_with_below_normal_pool(self):
        st, _ = run(P.CapState(cap=70), [sample(0, pool_priority="normal")])
        self.assertEqual(st.cap, 50)
        st, _ = run(P.CapState(cap=70), [sample(0)])
        self.assertEqual(st.cap, 70)

    def test_idle_cpus_mean_not_contention_and_keep_the_healthy_clock(self):
        cfg = P.merged(CFG, {"cpu": {"backoff_idle_cores": 2}})
        st = P.CapState(cap=60, healthy_since=0.0)
        # 3 of 12 CPUs idle: degraded, but no back-off; the healthy clock started at 0 keeps running
        st, d = P.cap_step(st, sample(30, experience="degraded", pool_cores=7.0, cpu_busy=0.75), cfg)
        self.assertEqual((st.cap, d, st.healthy_since), (60, None, 0.0))
        self.assertIn("not_cpu_contention", st.notes[0])
        # under 2 idle: back-off as before; a severe window backs off even with idle CPUs
        st, d = P.cap_step(st, sample(31, experience="degraded", pool_cores=7.0, cpu_busy=0.9), cfg)
        self.assertEqual((d["kind"], st.cap), ("foreground_backoff", 48))
        st, d = P.cap_step(st, sample(35, experience="severe", pool_cores=7.0, cpu_busy=0.5), cfg)
        self.assertEqual((d["kind"], st.cap), ("foreground_backoff", 38))
        # 10 of 12 CPUs open to agents: the 2 kept from them count as idle, so 3 idle in all is 1 idle of theirs
        st, d = P.cap_step(P.CapState(cap=60), sample(0, experience="degraded", pool_cores=6.0, cpu_busy=0.75,
                                                     ncpu=10, machine_cpus=12), cfg)
        self.assertEqual(d["kind"], "foreground_backoff")
        # rule off (the default): idle CPUs do not matter
        st, d = P.cap_step(P.CapState(cap=60), sample(0, experience="degraded", pool_cores=7.0, cpu_busy=0.5), CFG)
        self.assertEqual(d["kind"], "foreground_backoff")

    def test_idle_cpus_bring_the_cap_back_faster(self):
        cfg = P.merged(CFG, {"cpu": {"recover_idle_cores": 1, "recover_idle_share": 0.5}})
        # agents use their whole cap and others 6 cores, so 6 - cap cores sit idle: after 5 healthy s each step hands
        # the agents half the idle CPUs, at most every 10 s
        st, ups = P.CapState(cap=10), []
        for t in range(40):
            use = st.cap / 100 * 12
            st, d = P.cap_step(st, sample(t, pool_cores=use, cpu_busy=(6 + use) / 12), cfg)
            if d:
                ups.append((t, d["after"]))
        self.assertEqual(ups, [(5, 30), (15, 40), (25, 45), (35, 50)])  # +floor(50 * 4.8 / 12), +10, +5 (normal step)
        # under 1 free CPU the normal path: 20 s healthy, +5
        st, trace = run_cfg(P.CapState(cap=10), [sample(t, pool_cores=1.2, cpu_busy=0.95) for t in range(30)], cfg)
        self.assertEqual([(t, d["after"]) for t, _, d in trace if d], [(20, 15)])

    def test_cap_never_leaves_bounds(self):
        st, _ = run(P.CapState(cap=12), [sample(t, experience="degraded", pool_cores=5) for t in range(0, 60, 3)])
        self.assertEqual(st.cap, 10)
        st, _ = run(P.CapState(cap=93), [sample(t, pool_cores=12) for t in range(0, 200)])
        self.assertEqual(st.cap, 95)


class ExperienceTests(unittest.TestCase):
    def test_sustained_needs_two_of_three(self):
        self.assertEqual(P.sustained(["ok", "warn", "ok"]), "ok")
        self.assertEqual(P.sustained(["warn", "ok", "warn"]), "degraded")
        self.assertEqual(P.sustained(["ok", "ok", "severe"]), "severe")
        self.assertIsNone(P.sustained([None, None]))

    def test_media_window_ignores_short_or_paused(self):
        obs = CFG["observation"]
        self.assertIsNone(P.media_window_level({"state": "paused", "seconds": 20, "d_total": 600}, obs))
        self.assertIsNone(P.media_window_level({"state": "playing", "seconds": 4, "d_total": 600}, obs))
        self.assertEqual(P.media_window_level({"state": "playing", "seconds": 10, "d_total": 600, "d_dropped": 12},
                                              obs), "warn")


class AllocatorTests(unittest.TestCase):
    def test_weighted_maxmin_gives_leftover_to_busy_sessions(self):
        a = P.weighted_maxmin(3.0, {"a": math.inf, "b": math.inf, "c": 0.3}, {"a": 8, "b": 2, "c": 5})
        self.assertAlmostEqual(a["c"], 0.3)
        self.assertAlmostEqual(a["a"], 2.7 * 0.8)
        self.assertAlmostEqual(a["b"], 2.7 * 0.2)

    def test_many_threads_do_not_buy_more_share(self):
        # uncapped, eight threads take 2.6 of 3 cores and two CPU-bound threads get 0.4; same allocation weight
        st, _ = P.allocate(P.AllocState(), 3.0, {"wide": {"allocation_weight": 5, "usage": 2.6},
                                                  "narrow": {"allocation_weight": 5, "usage": 0.4}}, CFG)
        for _ in range(3):  # both press their first caps, then split by allocation weight
            usage = {k: min(st.caps[k], {"wide": 8.0, "narrow": 2.0}[k]) for k in st.caps}
            st, _ = P.allocate(st, 3.0, {k: {"allocation_weight": 5, "usage": u} for k, u in usage.items()}, CFG)
        self.assertAlmostEqual(st.caps["wide"], 1.5, places=2)
        self.assertAlmostEqual(st.caps["narrow"], 1.5, places=2)

    def test_uncontended_sessions_are_released(self):
        st = P.AllocState(caps={"a": 1.0, "b": 2.0})
        sessions = {"a": {"allocation_weight": 5, "usage": 0.3}, "b": {"allocation_weight": 5, "usage": 0.2}}
        for _ in range(CFG["cpu"]["relax_after_ticks"]):
            st, changes = P.allocate(st, 3.0, sessions, CFG)
        self.assertEqual(st.caps, {"a": None, "b": None})

    def test_paused_sessions_take_no_share(self):
        sessions = {"a": {"allocation_weight": 5, "usage": 2.9}, "b": {"allocation_weight": 5, "usage": 0.0, "paused": True},
                    "c": {"allocation_weight": 5, "usage": 0.1}}
        st, _ = P.allocate(P.AllocState(), 3.0, sessions, CFG)
        self.assertNotIn("b", st.caps)

    @staticmethod
    def plant(caps, want, budget=3.0):
        """Toy machine: a capped session gets min(want, cap); uncapped busy sessions split what the parent cap
        leaves equally. 'want' is what the session would use with no limit (inf = CPU-bound)."""
        used = {k: min(want[k], caps[k]) for k in want if caps.get(k) is not None}
        free = [k for k in want if caps.get(k) is None]
        left = max(0.0, budget - sum(used.values()))
        for k in sorted(free, key=lambda k: want[k]):
            used[k] = min(want[k], left / len(free))
            left -= used[k]
            free.remove(k)
        return used

    def run_ticks(self, st, want, ticks, budget=3.0):
        trace = []
        for _ in range(ticks):
            usage = self.plant(st.caps, want, budget)
            sessions = {k: {"allocation_weight": 8 if k == "focus" else 2, "usage": usage[k]} for k in want}
            st, _ = P.allocate(st, budget, sessions, CFG)
            trace.append(usage)
        return st, trace

    def test_idle_share_is_lent_and_taken_back(self):
        busy, idle = math.inf, 0.0
        st, trace = self.run_ticks(P.AllocState(), {"focus": busy, "batch": busy}, 6)
        self.assertAlmostEqual(trace[-1]["focus"], 2.4, places=2)
        self.assertAlmostEqual(trace[-1]["batch"], 0.6, places=2)
        # focus goes idle but keeps a live run: batch may borrow nearly the whole pool within a few ticks
        st, trace = self.run_ticks(st, {"focus": idle, "batch": busy}, 6)
        first = next(i for i, u in enumerate(trace) if u["batch"] >= 0.9 * 3.0)
        self.assertLessEqual(first, CFG["cpu"]["relax_after_ticks"] + 1)
        # focus turns busy again: its low usage while idle must not stick as low demand
        st, trace = self.run_ticks(st, {"focus": busy, "batch": busy}, 6)
        first = next(i for i, u in enumerate(trace) if u["focus"] >= 0.9 * 2.4)
        self.assertLessEqual(first, 2)
        self.assertAlmostEqual(trace[-1]["batch"], 0.6, places=2)

    def test_light_use_does_not_become_a_permanent_low_cap(self):
        st, trace = self.run_ticks(P.AllocState(), {"focus": 0.3, "batch": math.inf}, 6)
        self.assertLess(st.caps["focus"], 1.0)                  # focus only asked for 0.3, batch borrowed the rest
        self.assertTrue(all(u["batch"] >= 2.3 for u in trace[1:]), trace)  # steady lending, no capped/uncapped flip
        st, trace = self.run_ticks(st, {"focus": math.inf, "batch": math.inf}, 6)
        first = next(i for i, u in enumerate(trace) if u["focus"] >= 0.9 * 2.4)
        self.assertLessEqual(first, 2)


class AdmissionTests(unittest.TestCase):
    def test_ram_room_counts_target_margin_and_unused_reservations(self):
        cap = P.CapState(cap=50)
        s = sample(0, available_gib=20.0, commit_headroom_gib=60.0)
        ok, reason, nums = P.admission(4.0, s, unused_ram_gib=3.0, unused_commit_gib=3.0, cap_state=cap, cfg=CFG)
        self.assertTrue(ok)
        self.assertEqual(nums["ram_room_gib"], 9.0)          # 20 - 6 - 2 - 3
        ok, reason, _ = P.admission(30.0, s, 3.0, 3.0, cap, CFG)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("CAPACITY_PRESSURE"))

    def test_commit_room_blocks(self):
        s = sample(0, available_gib=40.0, commit_headroom_gib=7.0)
        ok, reason, _ = P.admission(3.0, s, 0, 0, P.CapState(cap=50), CFG)
        self.assertFalse(ok)
        self.assertIn("commit", reason)

    def test_closed_admission_and_manual_hold(self):
        cap = P.CapState(cap=20, admission_open=False, admission_reason="CAPACITY_PRESSURE")
        self.assertEqual(P.admission(0.5, sample(0), 0, 0, cap, CFG)[1], "CAPACITY_PRESSURE")
        self.assertEqual(P.admission(0.5, sample(0), 0, 0, P.CapState(cap=50), CFG, manual_hold=True)[1],
                         "HELD_BY_USER")

    def test_launch_slots_and_spacing(self):
        self.assertEqual(P.launch_slot(10.0, [9.5, 9.0], 9.0, CFG), (False, "launch observation slots full"))
        self.assertEqual(P.launch_slot(10.0, [7.0], 9.8, CFG), (False, "launch spacing"))
        self.assertEqual(P.launch_slot(10.0, [7.0], 9.0, CFG), (True, ""))

    def test_estimate_order(self):
        self.assertEqual(P.estimate([1, 2], 8, CFG)[1], "requested")
        self.assertEqual(P.estimate([], None, CFG), (0.5, "exploration", 0))
        self.assertAlmostEqual(P.estimate([1.0], None, CFG)[0], 1.2)
        self.assertEqual(P.estimate([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], None, CFG)[0], 9)


class QueueTests(unittest.TestCase):
    def runs(self, *rows):
        return [{"id": i, "cls": c, "t_request": t, "est_s": e, "share": sh} for i, c, t, e, sh in rows]

    def order(self, runs, order, now):
        return "".join(r["id"] for r in P.queue_order(runs, order, now))

    def test_each_order_and_exempt_first(self):
        runs = self.runs(("a", "normal", 0, 100, 5), ("b", "batch", 1, 5, 0.1), ("c", "focus", 2, 50, 3),
                         ("x", "exempt", 3, 500, 99))
        self.assertEqual(self.order(runs, "class_fifo", 10), "xcab")
        self.assertEqual(self.order(runs, "fifo", 10), "xabc")
        self.assertEqual(self.order(runs, "sjf", 10), "xbca")
        self.assertEqual(self.order(runs, "fair", 10), "xbca")
        with self.assertRaises(ValueError):
            P.queue_order(runs, "lifo", 10)

    def test_hrrn_lets_a_long_wait_pass_a_short_job(self):
        long_wait = self.runs(("a", "normal", 0, 100, 0), ("d", "normal", 990, 5, 0))
        self.assertEqual(self.order(long_wait, "sjf", 1000), "da")
        self.assertEqual(self.order(long_wait, "hrrn", 1000), "ad")  # (1000 + 100) / 100 beats (10 + 5) / 5
        both_fresh = self.runs(("a", "normal", 0, 100, 0), ("d", "normal", 9, 5, 0))
        self.assertEqual(self.order(both_fresh, "hrrn", 10), "da")

    def test_expected_length_is_the_median_of_earlier_runs(self):
        self.assertEqual(P.estimate_seconds([], CFG), (60.0, "default"))
        self.assertEqual(P.estimate_seconds([30, 10, None, 20], CFG), (20, "median of 3"))
        self.assertEqual(P.estimate_seconds([10, 20, -1], CFG), (15.0, "median of 2"))


class MemoryLadderTests(unittest.TestCase):
    def cfg(self, **memory):
        return P.merged(P.DEFAULTS, {"memory": memory})

    def test_the_agents_budget_is_one_more_room_for_admission(self):
        cap, s, cfg = P.CapState(cap=50), sample(0), self.cfg(agent_memory_budget_gib=4)
        ok, reason, nums = P.admission(1.0, s, 0.5, 0.5, cap, cfg, agents_gib=3.0)
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("AGENT_MEMORY_BUDGET"))
        self.assertEqual(nums["budget_room_gib"], 0.5)  # 4 - 3 held - 0.5 reserved
        self.assertTrue(P.admission(0.4, s, 0.5, 0.5, cap, cfg, agents_gib=3.0)[0])
        self.assertTrue(P.admission(1.0, s, 0.5, 0.5, cap, CFG, agents_gib=30.0)[0])  # no budget: only RAM rooms

    def test_trim_then_pause_and_release_only_inside_the_margin(self):
        cfg = self.cfg(agent_memory_budget_gib=4, pressure_pause=True)
        st, d = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        self.assertEqual((st.rung, d["kind"]), (1, "memory_pressure"))
        self.assertIn("budget 4", d["reason"])
        st, d = P.memory_step(st, sample(10), 5.0, cfg)
        self.assertIsNone(d)
        st, d = P.memory_step(st, sample(20), 5.0, cfg)  # 20 s of pressure: the pause rung
        self.assertEqual((st.rung, d["rung"]), (2, 2))
        st, d = P.memory_step(st, sample(21), 3.5, cfg)  # under the budget, not by the 1 GiB margin: hold
        self.assertEqual((st.rung, d), (2, None))
        st, d = P.memory_step(st, sample(22), 2.5, cfg)
        self.assertEqual((st, d["kind"]), (P.MemState(), "memory_relief"))

    def test_stans_reserve_is_pressure_without_a_budget(self):
        st, d = P.memory_step(P.MemState(), sample(0, available_gib=5.5), 1.0, CFG)
        self.assertEqual(st.rung, 1)
        self.assertIn("Stan keeps 6", d["reason"])
        st, d = P.memory_step(st, sample(60, available_gib=5.5), 1.0, CFG)
        self.assertEqual((st.rung, d), (1, None))  # pause is off by default: trimming is the last rung

    def test_with_every_rung_off_nothing_happens_and_the_clock_resets(self):
        cfg = self.cfg(agent_memory_budget_gib=4, pressure_trim=False, pressure_pause=True)
        st, d = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        self.assertEqual((st.rung, d), (0, None))
        st, _ = P.memory_step(st, sample(5), 1.0, cfg)  # pressure gone before the pause
        self.assertEqual(st, P.MemState())
        st, d = P.memory_step(st, sample(30), 5.0, cfg)  # a new episode starts its own clock
        self.assertEqual((st.rung, d), (0, None))


class MemoryLadderSettingsTests(unittest.TestCase):
    """The rung follows pressure_trim and pressure_pause on every step, so a step Stan turns off ends while pressure
    lasts; the episode keeps its start, and the release margin is unchanged."""

    def cfg(self, **memory):
        return P.merged(P.DEFAULTS, {"memory": dict(agent_memory_budget_gib=4, **memory)})

    def test_turning_pause_off_lowers_the_rung_while_pressure_lasts(self):
        cfg = self.cfg(pressure_pause=True)
        st, _ = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        st, _ = P.memory_step(st, sample(20), 5.0, cfg)
        self.assertEqual(st, P.MemState(0, 2))
        cfg["memory"]["pressure_pause"] = False  # guardctl memory-pause off
        st, d = P.memory_step(st, sample(21), 5.0, cfg)
        self.assertEqual((st, d["kind"], d["rung"]), (P.MemState(0, 1), "memory_pressure", 1))
        self.assertIn("budget 4: pressure_pause turned off, trim the agents' working sets", d["reason"])
        st, d = P.memory_step(st, sample(22), 5.0, cfg)
        self.assertEqual((st, d), (P.MemState(0, 1), None))
        cfg["memory"]["pressure_pause"] = True  # on again: the pressure has lasted 23 s, so the pause is due at once
        st, d = P.memory_step(st, sample(23), 5.0, cfg)
        self.assertEqual((st, d["rung"]), (P.MemState(0, 2), 2))

    def test_turning_trim_off_ends_the_trims_and_with_both_off_no_step_is_left(self):
        cfg = self.cfg()
        st, _ = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        cfg["memory"]["pressure_trim"] = False
        st, d = P.memory_step(st, sample(5), 5.0, cfg)
        self.assertEqual((st, d["rung"]), (P.MemState(0, 0), 0))
        self.assertIn("pressure_trim turned off, no step taken", d["reason"])
        cfg["memory"].update(pressure_trim=True, pressure_pause=True)
        st, _ = P.memory_step(st, sample(30), 5.0, cfg)
        self.assertEqual(st, P.MemState(0, 2))
        cfg["memory"].update(pressure_trim=False, pressure_pause=False)
        st, d = P.memory_step(st, sample(31), 5.0, cfg)
        self.assertEqual((st, d["rung"]), (P.MemState(0, 0), 0))
        self.assertIn("pressure_pause turned off, no step taken", d["reason"])
        st, d = P.memory_step(st, sample(32), 2.5, cfg)  # at rung 0 the end of the pressure needs no decision
        self.assertEqual((st, d), (P.MemState(), None))

    def test_inside_the_line_but_not_the_margin_the_rung_holds_unless_a_step_is_turned_off(self):
        cfg = self.cfg(pressure_pause=True)
        st, _ = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        st, d = P.memory_step(st, sample(25), 3.5, cfg)  # 20 s have passed, but the band only holds the rung
        self.assertEqual((st, d), (P.MemState(0, 1), None))
        st, _ = P.memory_step(st, sample(26), 5.0, cfg)
        self.assertEqual(st.rung, 2)
        cfg["memory"]["pressure_pause"] = False
        st, d = P.memory_step(st, sample(27), 3.5, cfg)
        self.assertEqual((st, d["rung"]), (P.MemState(0, 1), 1))
        self.assertIn("not 1 GiB inside the line yet: pressure_pause turned off", d["reason"])
        st, d = P.memory_step(st, sample(28), 2.5, cfg)
        self.assertEqual((st, d["kind"]), (P.MemState(), "memory_relief"))
        cfg["memory"]["pressure_pause"] = True
        st, _ = P.memory_step(st, sample(30), 5.0, cfg)  # a new episode at the trim rung
        cfg["memory"]["pressure_trim"] = False
        st, d = P.memory_step(st, sample(55), 3.5, cfg)  # in the band the pause, due by now, is not added either
        self.assertEqual((st, d["rung"]), (P.MemState(30, 0), 0))
        self.assertIn("pressure_trim turned off, no step taken", d["reason"])

    def test_with_trim_off_a_dip_inside_the_line_keeps_the_pause_clock(self):
        cfg = self.cfg(pressure_trim=False, pressure_pause=True)
        st, d = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        self.assertEqual((st, d), (P.MemState(0, 0), None))
        st, d = P.memory_step(st, sample(10), 3.5, cfg)  # inside the budget, not by the 1 GiB margin: still timed
        self.assertEqual((st, d), (P.MemState(0, 0), None))
        for t in range(11, 20):
            st, d = P.memory_step(st, sample(t), 5.0, cfg)
            self.assertEqual((st, d), (P.MemState(0, 0), None), t)
        st, d = P.memory_step(st, sample(20), 5.0, cfg)  # 20 s since the pressure began, as with trim on
        self.assertEqual((st, d["kind"], d["rung"]), (P.MemState(0, 2), "memory_pressure", 2))

    def test_with_trim_off_the_margin_stops_the_clock_and_has_nothing_to_relieve(self):
        cfg = self.cfg(pressure_trim=False, pressure_pause=True)
        st, _ = P.memory_step(P.MemState(), sample(0), 5.0, cfg)
        st, d = P.memory_step(st, sample(10), 2.5, cfg)  # 1 GiB inside: no step was taken at rung 0, so no relief
        self.assertEqual((st, d), (P.MemState(), None))
        st, d = P.memory_step(st, sample(11), 5.0, cfg)  # a new episode starts its own clock
        self.assertEqual((st, d), (P.MemState(11, 0), None))
        st, _ = P.memory_step(st, sample(30), 5.0, cfg)
        self.assertEqual(st.rung, 0)
        st, _ = P.memory_step(st, sample(31), 5.0, cfg)
        self.assertEqual(st.rung, 2)


class PolicyFileTests(unittest.TestCase):
    def refused(self, over):
        with self.assertRaises(ValueError) as e:
            P.check_over(over)
        return str(e.exception)

    def test_unknown_keys_are_refused_with_their_path(self):
        self.assertEqual(self.refused({"cpu": {"backoff_idle_core": 2}}), "cpu.backoff_idle_core: unknown key")
        self.assertEqual(self.refused({"cpuu": {"decrease_factor": 0.5}}), "cpuu: unknown key")
        self.assertEqual(self.refused({"cpu": {"allocation_weights": {"exempt": 1}}}),
                         "cpu.allocation_weights.exempt: unknown key")

    def test_wrong_types_are_refused(self):
        self.assertEqual(self.refused({"cpu": {"decrease_factor": "1"}}),
                         'cpu.decrease_factor must be a number, not "1"')
        self.assertEqual(self.refused({"cpu": 5}), "cpu must be an object")
        self.assertIn("must be a number or null", self.refused({"cpu": {"backoff_idle_cores": True}}))
        self.assertIn("must be true or false", self.refused({"safety": {"auto_kill_user_work": 1}}))
        self.assertIn("must be more than 0", self.refused({"cpu": {"allocation_weights": {"focus": 0}}}))
        self.assertEqual(self.refused([{"cpu": {}}]), "the file must hold a JSON object")

    def test_numbers_that_are_not_finite_are_refused(self):
        # json.loads takes NaN, Infinity and -Infinity, and 1e400 parses to inf; a NaN weight passed "v <= 0"
        slots = (('{"cpu": {"allocation_weights": {"focus": %s}}}', "cpu.allocation_weights.focus"),
                 ('{"cpu": {"decrease_factor": %s}}', "cpu.decrease_factor"),
                 ('{"memory": {"agent_memory_budget_gib": %s}}', "memory.agent_memory_budget_gib"))
        for text in ("NaN", "Infinity", "-Infinity", "1e400", "1" + "0" * 400):  # the last stays an int
            for slot, where in slots:
                with self.subTest(text=text, where=where):
                    self.assertTrue(self.refused(json.loads(slot % text)).startswith(
                        f"{where} must be a finite number, not "))
        self.assertEqual(self.refused(json.loads('{"cpu": {"maximum_cap_percent": 1e400}}')),
                         "cpu.maximum_cap_percent must be a finite number, not Infinity")
        self.assertEqual(self.main('{"cpu": {"allocation_weights": {"batch": NaN}}}')[0], 2)

    def test_numbers_outside_their_range_are_refused(self):
        for over, told in (
                ({"cpu": {"decrease_factor": 1}}, "cpu.decrease_factor must be more than 0 and less than 1, not 1"),
                ({"cpu": {"decrease_factor": 0}}, "cpu.decrease_factor must be more than 0 and less than 1, not 0"),
                ({"cpu": {"maximum_cap_percent": 101}},
                 "cpu.maximum_cap_percent must be more than 0 and at most 100, not 101"),
                ({"cpu": {"initial_cap_percent": 0}},
                 "cpu.initial_cap_percent must be more than 0 and at most 100, not 0"),
                ({"cpu": {"increase_step_percentage_points": 0}},
                 "cpu.increase_step_percentage_points must be more than 0, not 0"),
                ({"cpu": {"increase_spacing_seconds": -1}}, "cpu.increase_spacing_seconds must be at least 0, not -1"),
                ({"cpu": {"backoff_idle_cores": -1}}, "cpu.backoff_idle_cores must be at least 0, or null, not -1"),
                ({"cpu": {"demand_fraction_for_increase": 1.5}},
                 "cpu.demand_fraction_for_increase must be at least 0 and at most 1, not 1.5"),
                ({"cpu": {"min_session_cores": 0}}, "cpu.min_session_cores must be more than 0, not 0"),
                ({"cpu": {"relax_after_ticks": 0}}, "cpu.relax_after_ticks must be at least 1, not 0"),
                ({"memory": {"agent_memory_budget_gib": 0}},
                 "memory.agent_memory_budget_gib must be more than 0 and at most 1024, or null, not 0"),
                ({"memory": {"job_commit_hard_limit_gib": -2}},
                 "memory.job_commit_hard_limit_gib must be more than 0 and at most 1024, or null, not -2"),
                ({"memory": {"pressure_release_margin_gib": -1}},
                 "memory.pressure_release_margin_gib must be at least 0, not -1"),
                ({"observation": {"media_minimum_frame_count": 0}},  # a window of 0 frames divides by 0
                 "observation.media_minimum_frame_count must be at least 1, not 0"),
                ({"observation": {"probe_warning_drop_percent": 101}},
                 "observation.probe_warning_drop_percent must be at least 0 and at most 100, not 101"),
                ({"observation": {"sensor_valid_seconds": 0}},
                 "observation.sensor_valid_seconds must be more than 0, not 0"),
                ({"queue": {"exempt_minutes": 1441}},
                 "queue.exempt_minutes must be more than 0 and at most 1440, not 1441"),
                ({"unknown_work": {"maximum_simultaneous_launch_observations": 0}},
                 "unknown_work.maximum_simultaneous_launch_observations must be at least 1, not 0")):
            with self.subTest(over=over):
                self.assertEqual(self.refused(over), told)
        self.assertEqual(self.main('{"cpu": {"decrease_factor": 1.5}}')[0], 2)

    def test_the_minimum_cap_stays_at_or_below_the_maximum(self):
        # /api/cap clamps to max(minimum, min(maximum, cap)): a minimum above the maximum puts the cap over the maximum
        self.assertEqual(self.refused({"cpu": {"minimum_cap_percent": 60, "maximum_cap_percent": 50}}),
                         "cpu.minimum_cap_percent 60 must be at most cpu.maximum_cap_percent 50")
        self.assertEqual(self.refused({"cpu": {"maximum_cap_percent": 5}}),  # under the default minimum of 10
                         "cpu.minimum_cap_percent 10 must be at most cpu.maximum_cap_percent 5")
        P.check_over({"cpu": {"minimum_cap_percent": 2, "maximum_cap_percent": 5}})

    def test_every_range_names_a_number_slot_of_the_defaults(self):
        for where in P.RANGES:
            d = P.DEFAULTS
            for k in where.split("."):
                d = d[k]
            with self.subTest(where=where):
                self.assertTrue(d is None or isinstance(d, (int, float)) and not isinstance(d, bool))

    def test_levels_outside_their_set_are_refused(self):
        self.assertIn("io.agent_io_priority must be one of very_low, low, normal",
                      self.refused({"io": {"agent_io_priority": "below_normal"}}))
        self.assertIn("memory.agent_memory_priority", self.refused({"memory": {"agent_memory_priority": "Low"}}))
        self.assertIn("queue.order", self.refused({"queue": {"order": "lifo"}}))
        self.assertIn("cpu.pool_priority", self.refused({"cpu": {"pool_priority": "high"}}))

    def test_good_files_pass_unchanged(self):
        over = {"cpu": {"backoff_idle_cores": 2, "recover_idle_cores": None, "decrease_factor": 0.5,
                        "allocation_weights": {"focus": 9.5}},
                "memory": {"agent_memory_priority": "very_low", "pressure_pause": True, "agent_memory_budget_gib": 8},
                "io": {"agent_io_priority": "very_low"}, "queue": {"order": "hrrn"}}
        self.assertIs(P.check_over(over), over)
        P.check_over(P.DEFAULTS)
        P.check_over({})
        # the ends a range includes
        P.check_over({"cpu": {"maximum_cap_percent": 100, "healthy_before_increase_seconds": 0,
                              "recover_idle_share": 1},
                      "memory": {"agent_memory_budget_gib": 1024, "physical_available_target_gib": 0},
                      "observation": {"media_minimum_frame_count": 1}, "queue": {"exempt_minutes": 1440}})

    def main(self, text, encoding="utf-8", argv=()):
        """daemon.main with a --policy file holding text (None: no file, False: no --policy) and more argv; nothing
        real starts. A parser error comes back as its exit code."""
        err, out = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "policy.json"
            if isinstance(text, str):
                path.write_text(text, encoding=encoding)
            with mock.patch.object(D, "ping", return_value=False), mock.patch.object(D, "leave_job") as leave, \
                    mock.patch.object(D, "Guardian") as guardian, contextlib.redirect_stderr(err), \
                    contextlib.redirect_stdout(out):
                try:
                    rc = D.main(["--instance", "pc"] + ([] if text is False else ["--policy", str(path)]) + list(argv))
                except SystemExit as e:
                    rc = e.code
        leave.assert_not_called()
        return rc, guardian, err.getvalue()

    def test_main_refuses_a_max_cap_out_of_range(self):
        # type=float takes nan and inf, so --max-cap goes through check_over as well
        for cap in ("nan", "inf", "-inf", "1e400", "0", "-5", "101", "5"):  # 5 is under the default minimum of 10
            with self.subTest(cap=cap):
                rc, guardian, err = self.main(False, argv=[f"--max-cap={cap}"])  # "-inf" alone reads as an option
                self.assertEqual(rc, 2)
                guardian.assert_not_called()
                self.assertIn("argument --max-cap: cpu.m", err)
        rc, guardian, err = self.main(False, argv=["--max-cap", "80"])
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(guardian.call_args.args[3], {"cpu": {"maximum_cap_percent": 80.0}})
        rc, guardian, err = self.main('{"cpu": {"minimum_cap_percent": 2}}', argv=["--max-cap", "5"])
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(guardian.call_args.args[3], {"cpu": {"minimum_cap_percent": 2, "maximum_cap_percent": 5.0}})

    def test_main_refuses_a_bad_file_before_any_guardian(self):
        for text in ('{"cpu": {"backoff_idle_core": 2}}', '{"io": {"agent_io_priority": "below_normal"}}', "",
                     "{not json", "[]", None):
            rc, guardian, err = self.main(text)
            self.assertEqual(rc, 2, text)
            guardian.assert_not_called()
            self.assertTrue(err.startswith("Guardian pc: bad --policy "), err)
        self.assertIn("cpu.backoff_idle_core: unknown key", self.main('{"cpu": {"backoff_idle_core": 2}}')[2])

    def test_main_takes_a_file_with_a_bom(self):
        over = {"cpu": {"backoff_idle_cores": 2}}
        rc, guardian, err = self.main(json.dumps(over), encoding="utf-8-sig")
        self.assertEqual((rc, err), (0, ""))
        self.assertEqual(guardian.call_args.args[3], over)


if __name__ == "__main__":
    unittest.main()
