# Guardian: CPU control for local agent sessions

Guardian runs agent work (Claude Code, Codex, Cursor, or any CLI) inside Windows Job Objects so the person at the
keyboard keeps a responsive machine while agents use the rest. It is a separate daemon from the Sentinel collector
and lives in `sentinel/guardian/`.

## What it controls

Every process started through Guardian lands in a job tree, and child processes inherit the job, so a whole CLI and
every tool command it runs stay inside it:

```
<instance>.AllAgents        dynamic hard cap, priority class below_normal, optional CPU affinity
  provider job              claude / codex / cursor; pause a whole tool
    session job             one agent session; per-session hard cap from its allocation weight
      run job               one command; cancel kills the whole tree
```

- **Dynamic cap.** The AllAgents cap is a percent of the CPUs open to agents. When the foreground probe is over the
  line in 2 of the last 3 one-second windows (p95 lateness above 10 ms or more than 2% late), the cap is multiplied
  by 0.8. After 20 healthy seconds it rises by 5 points. Range 10% to 95% by default; the demos use 80%.
- **Allocation weights.** focus 8, normal 5, batch 2. Weighted max-min turns them into per-session hard caps; a
  light session lends what it does not use and gets it back when it resumes. A cap is a ceiling, not a guarantee.
- **CPUs open to agents.** `--world-cpus N` at start, or the dashboard / `guardctl world N` at run time, limits the
  agents to the top N logical CPUs. The rest stay free for the foreground, for example a remote desktop session.
- **Control off.** `rollback` removes every cap and puts the agents back at normal priority; the CPU limit stays.
  `resume-control` turns it back on.

Guardian only controls work it launched. It reads the Claude, Codex and Cursor desktop apps but never assigns them
to a job. Cloud sessions run on remote machines and use no local CPU, so there is nothing to control locally.

## The foreground probe

`probe.py` is a normal-priority process that asks for the CPU 60 times a second, does 1 ms of work each time, and
reports how late the slowest 5% of those wake-ups were. It stands in for any ordinary program waiting its turn. It
does not see the GPU, the display pipeline or a browser, which is why a GPU-decoded video can look fine while the
probe reports lateness.

## Running it

```
python -I scripts/guardian.py --instance main                     # daemon + dashboard on http://127.0.0.1:8765/
python -I scripts/srun.py --provider claude --session s1 -- <cmd>  # run a command inside Guardian
python -I scripts/srun.py --provider claude --session s1 --console -- claude   # a whole interactive CLI
python -I scripts/guardctl.py status | pause claude/s1 | class claude/s1 focus | cap 40 | world 10 | rollback
```

Demos (instance `onoff`, dashboard on port 8767 unless noted):

| Script | What it shows |
|---|---|
| `guardian-demo.py` | three fake sessions in a 3-CPU miniature world (instance `demo`, port 8766) |
| `guardian-demo-onoff.py` | timed control off / on with fake sessions; `--full` uses every CPU, `--manual` lets you toggle |
| `guardian-demo-claude.py` | a real Claude Code CLI inside Guardian, working as an agent until Esc; `--cpus 10` |
| `guardian-demo-workload.py` | the CPU-heavy work both sides run; prints speed, cores, priority and job membership |

## Measured on this machine

Ryzen 5 7500F, 12 logical CPUs, 2026-10-13. "Late" is the probe's p95 lateness.

| Run | Control off | Control on |
|---|---|---|
| 3-CPU world, fake sessions | 2.73 cores, 28.9 ms late, 21.4% late frames | 2.16 cores, 1.6 ms, 0% |
| 12 CPUs, fake sessions | 10.67 cores, 135.8 ms, 34.5% | 7.04 cores, 2.0 ms, 0.3% |
| 12 CPUs, toggled by hand | 9.05 cores, 31.2 ms, 26.2% | 6.87 cores, 1.7 ms, 0.3% |
| 12 CPUs, real Claude Code CLI | 9.0 to 9.3 cores, about 1085 MiB/s, 26 to 77 ms | 7.1 cores, about 845 MiB/s, 1.5 to 6 ms |

With control on, the agents give up about a fifth of their speed and the foreground waits a few milliseconds
instead of tens.

## Known limits

- The dashboard page embeds the HTTP token, so any local process can read it. It listens on 127.0.0.1 only.
- Pausing a session sets its CPU rate to 0.01%. A paused CLI cannot service its network connections either, and
  they may time out, so keep pauses short.
- `hooks/guardian-route.py` (routing an agent's Bash calls through Guardian automatically) is not written yet.
