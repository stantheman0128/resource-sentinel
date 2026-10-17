import math
import unittest

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


if __name__ == "__main__":
    unittest.main()
