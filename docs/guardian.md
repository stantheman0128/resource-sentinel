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

Guardian only controls work it launched or adopted (see below). It reads the Claude, Codex and Cursor desktop apps
but never assigns them to a job. Cloud sessions run on remote machines and use no local CPU, so there is nothing to control locally.

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
| `guardian-demo-workload.py` | the CPU-heavy work both sides run; prints speed, cores, priority and whether control is on |

srun, gagent, the adopt hook, the PATH wrappers and whereami talk to the daemon over the named pipe
`\\.\pipe\resource-sentinel-guardian-<instance>-<USERNAME>`. A client proves it holds the instance's `pipe-authkey`
through the HMAC challenge of Python's `multiprocessing.connection`. The daemon runs that challenge on each
connection's own thread and drops a client that has not finished it within 5 s, so a client that connects and then
stalls delays nobody else. A client likewise treats Guardian as not running when the daemon has not finished the
challenge within 5 s, though waiting for a free pipe instance can still take the standard library's 20 s. A client
that answers with the wrong key gets `#FAILURE#` and a closed pipe, and one that never answers is dropped at 5 s.
guardctl and the dashboard use the HTTP API, not the pipe.

## Agent CLIs: launch, wrap or adopt

A CLI gets into Guardian one of three ways:

1. **Launch.** `python -I scripts/gagent.py <claude|codex|gemini|cursor|grok|antigravity> [--session NAME]
   [-- CLI args]` starts the CLI through srun in its own console window. The CLI is in its session job before it
   runs its first instruction, and every tool command inherits the job. This works for all six CLIs.
2. **Wrap.** After `python -I scripts/guardian-install-shims.py --apply`, typing `claude`, `codex`, `gemini`,
   `cursor-agent`, `grok` or `agy` in a new terminal runs a wrapper (`.ps1` for PowerShell, `.cmd` for cmd, an sh script
   for Git Bash) that calls `scripts/guardian-shim.py`. The shim starts the real CLI suspended in the same console,
   has the daemon assign it to root, provider and session job, then lets it run, so it is in its session from its
   first instruction, like a launch. This is the way in for Claude Code and Cursor Agent outside gagent. Arguments
   after the CLI name reach the CLI as the shell passed them on (PowerShell and cmd change a few things first,
   see Known limits). The CLI runs as before, without a word, when its parent is already in
   a Guardian session (a tool command of another CLI inherits that job), when a desktop app started it, or with
   `GUARDIAN_SHIM=off`. When the daemon is down, refuses, or gives no answer within 15 seconds, the CLI runs anyway
   and one `[guardian]` line says why. `GUARDIAN_SHIM_INSTANCE` picks the instance (default `main`), and
   `GUARDIAN_SHIM_VERBOSE=1` also prints where the CLI runs.
3. **Adopt.** A session-start hook runs `hooks/guardian-adopt.py <provider>`, which finds the CLI among its
   parents and asks the daemon to move it and its children into root, provider and session job. Later children
   inherit the job. `guardctl adopt <pid> <provider> [session]` does the same by hand. Adopting is refused when a
   desktop app (Claude, Codex, Cursor or Antigravity) is among the parents, and it fails for a CLI that put itself
   in a job of its own at start. Windows lets such a process join only a job inside its current job tree, or a job
   that never held a process, which then nests under the CLI's job and can never join Guardian's tree (measured
   2026-10-14).

Guardian never sets the breakaway limits on its jobs (`JOB_OBJECT_LIMIT_BREAKAWAY_OK` and
`JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK`; winjob.py only reads them back), so every child a controlled CLI starts
stays in its session job. A process that Windows starts on the CLI's behalf is not its child and starts outside:
one created through WMI (`Win32_Process.Create`), a service, or a scheduled task.

`python -I scripts/guardian-whereami.py` answers from inside a session whether it is controlled; ask an agent to
run it as a shell command. When a CLI sandbox blocks the daemon's pipe (Codex's does), it reads the named jobs
directly. `python -I scripts/guardian-provider-check.py` checks every CLI against its own daemon instance `check`
(port 8768): `version` starts the CLI through srun, `srun` makes the agent run whereami through srun, `hook` starts
the CLI outside Guardian with a hook config for that run only, `shimver` and `shim` start it through the wrapper
(written to the run's own folder, so nothing global changes) with `--version` and with the whereami prompt. Where
no model call can run, a child of the CLI process stands in for a tool command: gemini's node.exe runs whereami
through `NODE_OPTIONS=--require` at `--version`, and grok's session-start hook runs it at `shim`. agy runs a shell
command headless only with permission rules in its global settings or with `--dangerously-skip-permissions`, so at
`srun`, `hook` and `shim` it gets a plain prompt and a PreInvocation hook in the run folder's `.agents/hooks.json`
runs whereami as agy's own child; `--allow-yolo` asks for the shell command instead. The srun, hook and shim levels
make one model call each.

| CLI (version tested) | Launch | PATH wrapper | Adopt hook | Notes |
|---|---|---|---|---|
| Claude Code 2.1.296 | yes: tool command in the session | yes: tool command in the shim's session | no: claude.exe is in its own job, adopt refused | measured; use the wrapper or gagent |
| Codex CLI 0.156.0 | yes: tool command in the session | yes: tool command in the shim's session | yes: tool command in the adopted session; node.exe and node_repl.exe children were refused (Access denied) and stay outside | sandbox blocks the daemon pipe, whereami reads the jobs |
| Gemini CLI 0.1.3 | CLI starts in the session; tool command not tested | CLI starts in the session; a child of its node.exe (started through `NODE_OPTIONS=--require`, no model call) reports the shim's session; tool command not tested | no hooks in 0.1.3 | not signed in on 2026-10-13 (no auth type, no credentials), so no model call can run; headless shell also needs `--yolo`, which the check runs only with `--allow-yolo` |
| Cursor Agent 2026.10.01 | yes: tool command in the session | yes: tool command in the shim's session | no: its node.exe is in its own job, adopt refused | measured; start it outside Git Bash (see Known limits) |
| Grok 1.0.40 | yes: tool command in the session | yes: tool command and its session-start hook (its own child) in the shim's session | yes: tool command in the adopted session; powershell.exe and conhost.exe children were refused (Access denied) and stayed outside | measured after Stan signed in again (report 231319); the project hook needs a git root |
| Antigravity CLI 1.3.4 (`agy`) | yes: tool command in the session (with `--allow-yolo`), and its PreInvocation hook (its own child) | yes: the same, in the shim's session | yes: tool command in the adopted session; agy.exe adopted (2 processes, none refused) | reports 233349 and 233824 without the flag, 000722 with it. Measured besides: hooks run through cmd.exe and need no git root; the session name comes from `conversationId`; agy starts a background updater, another agy.exe, as its child, and it replaced 1.3.3 with 1.3.4 unasked before these runs |

Claude Code, Codex, Cursor Agent, Grok and agy, rerun together on one daemon (report 235302, 2026-10-13 23:53 to
00:04): every level passed except the hook level for Claude Code and Cursor Agent, which gave LIMIT as before. Both
passed srun and the PATH wrapper levels in the same run. Gemini CLI was left out.

To have new sessions join without gagent, Stan can run `python -I scripts/guardian-install-shims.py` from the main
checkout: it covers all six CLIs. It prints the change and writes nothing until `--apply`, which saves the old
user Path first; `--remove` undoes it. The `.ps1` wrappers are written only when PowerShell's execution policy
runs local scripts (RemoteSigned for Stan's user on 2026-10-13); otherwise PowerShell uses the `.cmd` ones. As a
second route for Codex, Grok and Antigravity, `python -I scripts/guardian-install-hooks.py` adds the adopt hook,
with the same dry run, a backup of the file and `--remove`. It covers Codex (`~/.codex/hooks.json`, then trust it
once with `/hooks` in codex), Grok (`~/.grok/hooks/guardian.json`) and Antigravity (a named hook `guardian-adopt`
in `~/.gemini/config/hooks.json`; the user's own hooks in that file stay). Wrappers and hook only act while the daemon
for that instance runs. `python -I scripts/guardian-install-autostart.py` keeps the main daemon running: it
registers the scheduled task ResourceSentinelGuardian, which starts the daemon at logon through `conhost --headless`
with no time limit and never a second copy, and appends its output to
`~/.resource-sentinel/guardian/main-daemon.log`. Same dry run and `--remove`. `--port` sets the dashboard port, and
the installer refuses one that another program holds. On Stan's machine another local server holds 8765, so the
task uses `--port 8769` (2026-10-14).

Measured 2026-10-14 with the wrappers and the autostart task: Task Scheduler starts its action in a job with no
limits (flags 0) that refuses breakaway (a child started with `CREATE_BREAKAWAY_FROM_JOB` got Access denied), so
Guardian's job tree nests under that job. `Stop-ScheduledTask` ended conhost only; cmd and the daemon kept running.
With the task's daemon up, `claude`, `codex`, `cursor-agent`, `grok` and `agy` with `--version` each went through its
wrapper into a session of its own (enforced, below_normal priority), from a cmd that Explorer opened and from a new
Windows Terminal tab. Neither shell was in a job, though WindowsTerminal.exe itself is. A Windows Terminal that was
already open keeps its old PATH until it is closed completely, and `wt.exe` hands a new tab the environment of the
program that called it: a tab opened from inside the Claude app carries `CLAUDE_CODE_ENTRYPOINT=claude-desktop`, so
its wrappers run the CLI directly. Not measured yet: the terminals inside VS Code and Cursor, whose shells sit in
the editor's job. The wrapper first starts the CLI outside that job, which works only if the job allows breakaway;
if it does not, the assignment should fail as the hook does for Claude Code, and the CLI runs with the one-line
notice.

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

The pipe, instance `hs`, 2026-10-13: how long one client's ping took while other clients sat on an unanswered
challenge.

| Stalled clients | Old: handshake inside the accept thread | Now: handshake per connection |
|---|---|---|
| 1, connected for 10 s | 9.99 s, the length of the stall | 0.002 s; the daemon dropped the stalled client at 5.1 s |
| 2, connected for 25 s | no answer: after 20.2 s the client reported Guardian as not running | 0.001 s |

## Known limits

- The dashboard page embeds the HTTP token, so any local process can read it. It listens on 127.0.0.1 only.
- Pausing a session sets its CPU rate to 0.01%. A paused CLI cannot service its network connections either, and
  they may time out, so keep pauses short.
- Claude Code and Cursor Agent sessions started neither through gagent nor through the PATH wrapper (by full path,
  from a terminal opened before the install, or by a tool that ignores PATH) stay outside Guardian. A session
  started inside a desktop app's terminal is refused on purpose, as long as the app is still among its parents.
- The wrappers sit on the user Path, which Windows puts after the system Path. A CLI installed into a system Path
  folder is found first and bypasses its wrapper; the installer warns about that.
- Grok reads Claude, Cursor and Codex hook files as well as its own, so one CLI may run another CLI's hooks. The
  adopt hook then finds no CLI of its provider and does nothing.
- cursor-agent 2026.10.01 started with Git Bash's variables (`MSYSTEM`, `SHELL` and others) runs its hooks through
  bash but writes each hook line in PowerShell. Every hook fails, and Cursor then rejects every shell command, with
  or without Guardian. Start it from PowerShell or cmd. The provider check removes those variables for this reason.
- A child that Windows will not move (Access denied, usually because it already sits in a job of its own) stays
  outside: node.exe and node_repl.exe under Codex, powershell.exe and conhost.exe under Grok. The adopt reports
  `partial` and names them. Children started after the adopt join.
- The desktop-app refusal follows the parent chain. A CLI whose launcher has already exited no longer shows the
  app above it and is adopted. Git Bash starts programs through an emulated fork and exec, which leaves an exited
  process above sh, so the wrapper also checks `CLAUDE_CODE_ENTRYPOINT=claude-desktop`, which the Claude app
  passes to everything it starts. For the Codex app and Cursor there is no such check yet: a wrapper started under
  them through Git Bash is taken in.
- From cmd.exe, the `.cmd` wrapper hands its arguments to cmd again, like npm's own `.cmd` wrappers: `%NAME%` is
  expanded, an unquoted `&` `|` `<` `>` or `^` splits the line, and after Ctrl+C cmd asks "Terminate batch job
  (Y/N)?" once the CLI exits. PowerShell runs the `.ps1` wrapper instead, which adds none of these, but PowerShell
  binds the arguments before the wrapper sees them, as with npm's own `.ps1` wrappers: it keeps the first bare `--`
  for itself (write `'--'`), and it splits a single-dash option with a colon, so `-c:x` arrives as `-c:` and `x`.
- Gemini and Cursor Agent are installed as `.cmd` files, so the shim runs them through cmd.exe
  (`/e:ON /v:OFF /d /c`) and writes each argument the way Rust's standard library does for batch files: quoted
  unless plain, double quotes doubled, `%` neutralized. 200 random arguments made of `" \ % & | < > ^ ( ) !`,
  spaces and tabs arrived unchanged, and none ran as a command. cmd.exe cannot carry a line break inside an
  argument, so the shim refuses to start such a CLI with one `[guardian]` line and exit code 2.
- Guardian's named jobs, AllAgents and the provider and session jobs, get a protected DACL: SYSTEM and
  Administrators have full access, the user who runs the daemon may only query, wait and read the DACL, and an
  OWNER RIGHTS entry takes away the owner's implicit right to rewrite it. Unnamed run jobs keep the default
  security. Measured 2026-10-13 on instance `sec`: a separate non-elevated process of the same user, whose token
  holds Administrators as deny-only, opens all of them with query access, while SET_ATTRIBUTES, full access,
  WRITE_DAC, ASSIGN_PROCESS and TERMINATE fail with access denied. A low-integrity child gets query and nothing
  else. The daemon keeps the job rights through the handle it got when it created each job. That handle's granted
  access is 0x13003F, which has no WRITE_DAC either. From inside Codex 0.156's sandbox, whereami still reads the
  session from the jobs.
- A process of the same user can still open the daemon process with PROCESS_DUP_HANDLE and copy its job handle,
  which keeps the full job rights (0x13003F), because Guardian does not lock down its own process. It can also
  create a job, another named object or a symbolic link under a Guardian name first, which makes the daemon refuse
  that name. Both were measured. It can end member processes one at a time, since they are its own processes
  (Windows behavior, not measured here). Elevated processes and SYSTEM keep full access through the DACL by design.
  A daemon started elevated therefore opens an existing AllAgents job with full access, cannot tell Guardian's DACL
  from a permissive one, and refuses it too. An AppContainer process resolves `Local\` to its own namespace
  (documented, not measured), so it does not find the jobs by name and whereami cannot read them there.
- A job's name lasts only while some process holds a handle to it; member processes alone do not keep it
  (measured). A restarted daemon therefore normally creates fresh jobs, and the old daemon's sessions run on in
  nameless jobs that nothing controls any more. A clean shutdown removes their caps first. After a crash they keep
  whatever cap or pause they had, and since the job has no name left, nothing can find it to lift the limit;
  ending the CLI is the way out (measured with a paused test job). If the AllAgents name still exists at startup,
  because the old daemon still runs with its pipe out of reach or a script holds the job open, the daemon refuses
  to start and lists the processes in the job. It also refuses a job whose DACL is permissive, such as one made by
  a Guardian version without the job DACL or one another process created first, and a name held by an object that
  is not a job or by a symbolic link. That includes a link to a free name or to another job: the daemon reads the
  kernel path of each job it gets and refuses one that does not sit under its own name. Each case was measured.
  The way out is to end the process that holds the job, the object or the link open, or to start with another
  `--instance`. If a provider or session name is taken that way while the daemon runs, the daemon refuses that
  srun or adopt with a logged `provider_refused` or `session_refused` decision and keeps running (measured).
- The Guardian pipe name includes `USERNAME`, so a process with a different `USERNAME` in its environment cannot
  reach the daemon. Inside a Guardian session whereami still reads the session from the jobs; without
  `GUARDIAN_PROVIDER` and `GUARDIAN_SESSION` it says only PARTLY KNOWN. Outside the pool it reports Guardian as not
  running even while the daemon is up (measured 2026-10-14 on `sec`).
- Codex 0.156 cannot parse a `hooks.json` that starts with a UTF-8 byte order mark. The installer writes without one.
