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

Guardian only controls work it launched, adopted or put in a desktop job (see below). It reads the Claude, Codex and
Cursor desktop apps but never assigns the apps' own processes to a job. Cloud sessions run on remote machines and
use no local CPU, so there is nothing to control locally.

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
python -I scripts/srun.py --provider codex --session api1 -- python my_api.py   # an API or SDK script
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

## Agent CLIs: launch, wrap, adopt or desktop job

A CLI gets into Guardian one of four ways:

1. **Launch.** `python -I scripts/gagent.py <claude|codex|gemini|cursor|grok|antigravity> [--session NAME]
   [-- CLI args]` starts the CLI through srun in its own console window. The CLI is in its session job before it
   runs its first instruction, and every tool command inherits the job. This works for all six CLIs.
2. **Wrap.** After `python -I scripts/guardian-install-shims.py --apply`, typing `claude`, `codex`, `gemini`,
   `cursor-agent`, `grok` or `agy` in a new terminal runs a wrapper (`.ps1` for PowerShell, `.cmd` for cmd, an sh script
   for Git Bash) that calls `scripts/guardian-shim.py`. The shim starts the real CLI suspended in the same console,
   has the daemon assign it to root, provider and session job, then lets it run, so it is in its session from its
   first instruction, like a launch. Outside gagent, Claude Code and Cursor Agent get in this way or through the
   adopt hook that `guardian-install-hooks.py` adds, which takes them in when their session starts, into a nested
   job (see Adopt). Arguments after the CLI name reach the CLI as the shell passed them on (PowerShell and cmd
   change a few things first, see Known limits). The CLI runs as before, without a word, when its parent is already in
   a Guardian session (a tool command of another CLI inherits that job), when a desktop app started it, or with
   `GUARDIAN_SHIM=off`. When the daemon is down, refuses, or gives no answer within 15 seconds, the CLI runs anyway
   and one `[guardian]` line says why. `GUARDIAN_SHIM_INSTANCE` picks the instance (default `main`), and
   `GUARDIAN_SHIM_VERBOSE=1` also prints where the CLI runs.
3. **Adopt.** A session-start hook runs `hooks/guardian-adopt.py <provider>`, which finds the CLI among its
   parents and asks the daemon to move it and its children into root, provider and session job. Later children
   inherit the job. `guardctl adopt <pid> <provider> [session]` does the same by hand. Adopting is refused when a
   desktop app (Claude, Codex, Cursor or Antigravity) is among the parents. A CLI that put itself in a job of its
   own at start (claude.exe, and the node.exe of Cursor Agent and Gemini CLI) cannot join the tree: Windows lets such
   a process join only a job inside its current job tree, or a job that never held a process, which then nests under
   the CLI's job (measured 2026-10-14). The daemon then gives it such a job,
   `Local\Guardian.<instance>.d.<provider>.<session>`, sweeps its children in as for a session job, and caps it like
   a desktop job (below): the pool's priority, the agents' CPU set and absolute cores, outside AllAgents. The adopt
   answers `adopted` with `nested`, a second hook for the same CLI answers `already`, and whereami answers
   `CONTROLLED: session <provider>/<session> (nested job under the CLI's own job, ...)`, also by the job's name when
   the daemon's pipe is out of reach. A nested job ends when its CLI and everything in it have exited: in the
   provider check of 2026-10-15 (report 220410) the daemon logged all three nested sessions as ended once their
   CLIs exited.
4. **Desktop job.** The Claude app's Code tab runs each session as a claude.exe of its own
   (`%APPDATA%\Claude\claude-code\<version>\<hash>\claude.exe`, a child of the app), and the Codex app runs
   `%LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\codex.exe` under ChatGPT.exe or its node_repl.exe. Both already sit in
   the app's job, so the rule above holds for them: a fresh job takes them and nests under the app's job. Measured
   2026-10-14 from a Code-tab session: a busy child of it joined a fresh job, a cap of 0.25 cores read 0.224 cores,
   an idle priority limit held, and the child's own child inherited the job. Every 2 s the daemon puts each such
   CLI it has not placed yet, with the children it has already started, into a desktop job of its own,
   `Local\Guardian.<instance>.d.<provider>.desk-<pid>`; what it starts later inherits the job. Only the top CLI of a
   chain gets one, and the apps' own processes never do. A desktop job gets the pool's priority, the agents' CPU
   set, and a hard cap in absolute cores, because the app's job above it has no CPU rate: the
   allocator's cap for that session, or the whole pool budget when the allocator sets none. While control is on, a
   desktop session is never uncapped. It counts as active for the allocator only while it uses more than 0.05
   cores, since about 20 Code-tab sessions stay open at once and each idle one would otherwise take a share of the
   budget. Pausing the session or its provider sets rate 1 on the desktop job, rollback lifts the cap and sets
   normal priority, and a shutdown lifts the cap and keeps the priority. Desktop jobs are on by default for
   instance `main` and off for every other instance; `--desktop on|off` at start and `guardctl desktop on|off` at
   run time switch them. Off lifts every limit on the desktop jobs (no cap, normal priority, every CPU) and places
   no new ones. The pool figure adds the desktop jobs' use to the tree's, and the Claude and Codex rows under apps
   leave it out, so no core is counted twice. whereami answers `CONTROLLED: session claude/desk-<pid> (desktop job
   under the Claude app's job, ...)`, and reads the job by name when the daemon's pipe is out of reach.

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
no model call can run, or a shell command needs a flag that approves every command, a child of the CLI process
stands in for a tool command. Gemini's node.exe runs whereami through `NODE_OPTIONS=--require` at `version`, `srun`
and `shim`, and a BeforeAgent hook runs it at `hook`; gemini's hook level always uses one folder,
`<instance home>/check/gemini-hook`, so gemini's list of trusted hooks gets one entry. Grok's session-start hook
runs whereami at `shim`. agy runs a shell command headless only with permission rules in its global settings or
with `--dangerously-skip-permissions`, so at `srun`, `hook` and `shim` it gets a plain prompt and a PreInvocation
hook in the run folder's `.agents/hooks.json` runs whereami as agy's own child. For gemini and agy, `--allow-yolo`
asks for the shell command instead. The srun, hook and shim levels make one model call each. At `hook`, LIMIT marks
a CLI in a job of its own that Windows kept out of a nested job too.

| CLI (version tested) | Launch | PATH wrapper | Adopt hook | Notes |
|---|---|---|---|---|
| Claude Code 2.1.296 | yes: tool command in the session | yes: tool command in the shim's session | nested: tool command in the nested session (report 220410). claude.exe sits in a job of its own, so the adopt gives it a nested job outside AllAgents; claude.exe and 19 children joined, a bash.exe child was refused (Access denied). Until 2026-10-15 the adopt was refused | measured; the wrapper or gagent put it inside AllAgents |
| Codex CLI 0.156.0 | yes: tool command in the session | yes: tool command in the shim's session | yes: tool command in the adopted session; node.exe and node_repl.exe children were refused (Access denied) and stay outside | sandbox blocks the daemon pipe, whereami reads the jobs |
| Gemini CLI 0.63.0 | CLI starts in the session (`--version`); tool command not tested | CLI starts in the session (`--version`); tool command not tested | nested: gemini's node.exe sits in a job of Node's own, so the adopt gives it a nested job outside AllAgents. In report 220410 node.exe and 4 children joined one and none was refused; the tool command did not run, because the sign-in failed before the BeforeAgent hook. Earlier on 2026-10-15 the adopt was refused | measured 2026-10-15 from a cmd outside any job; the wrapper or gagent put it inside AllAgents. Google refused the sign-in in that run (`IneligibleTierError`: this client no longer serves Gemini Code Assist for individuals, move to Antigravity), so no model call can run with Stan's account, and Stan uses agy. Gemini records the check folder's hooks in `~/.gemini/trusted_hooks.json`, one entry. 0.1.3, before 2026-10-13, had no hooks and was not signed in |
| Cursor Agent 2026.10.01 | yes: tool command in the session | yes: tool command in the shim's session | nested: tool command in the nested session (report 220410). Its node.exe sits in a job of its own, so the adopt gives it a nested job outside AllAgents; node.exe and 21 children joined, while wsl.exe, node.exe and two git.exe children were refused (Access denied) and a bash.exe child had already exited. Until 2026-10-15 the adopt was refused | measured; start it outside Git Bash (see Known limits) |
| Grok 1.0.40 | yes: tool command in the session | yes: tool command and its session-start hook (its own child) in the shim's session | yes: tool command in the adopted session; powershell.exe and conhost.exe children were refused (Access denied) and stayed outside | measured after Stan signed in again (report 231319); the project hook needs a git root |
| Antigravity CLI 1.3.4 (`agy`) | yes: tool command in the session (with `--allow-yolo`), and its PreInvocation hook (its own child) | yes: the same, in the shim's session | yes: tool command in the adopted session; agy.exe adopted (2 processes, none refused) | reports 233349 and 233824 without the flag, 000722 with it. Measured besides: hooks run through cmd.exe and need no git root; the session name comes from `conversationId`; agy starts a background updater, another agy.exe, as its child, and it replaced 1.3.3 with 1.3.4 unasked before these runs |

Gemini's job of its own comes from Node. The first time a node.exe starts a child, libuv, the library under Node's
child processes, puts that node.exe in a job that kills its members when the node.exe exits, and every child it
starts after that goes in too (libuv `src/win/process.c`). On 2026-10-15 a node.exe that only waited was in no job,
and a node.exe that had started a child was in one, together with the child. Unless `GEMINI_CLI_NO_RELAUNCH` is
set, Gemini 0.63.0 starts itself again as a second node.exe, which runs the session and its hooks, so the adopt hook
finds a CLI that is already in that job, and the daemon gives it a nested job. libuv's job allows breakaway, but a
child that the CLI starts after the adopt still stays in the nested job: Windows lets a child break away silently
only when its parent's innermost job allows it, and Guardian's jobs never do. `tests/test_guardian_adopt.py`
checks this with a job that carries libuv's flags, and in report 220410 the whereami that Cursor Agent's node.exe
started after the adopt ran in the nested job. A CLI that starts inside a Guardian job is different: Windows nests
Node's job inside the session job, which is why srun and the wrapper still put gemini in a session.

Claude Code, Codex, Cursor Agent, Grok and agy, rerun together on one daemon (report 235302, 2026-10-13 23:53 to
00:04): every level passed except the hook level for Claude Code and Cursor Agent, which gave LIMIT as before. Both
passed srun and the PATH wrapper levels in the same run. Gemini CLI was left out. Since 2026-10-15 the adopt gives
these CLIs a nested job instead of refusing them, and the hook level passed for both in report 220410 (2026-10-15
22:04 to 22:05). Gemini's adopt went nested in the same run, but its hook level failed: the sign-in failed before
the BeforeAgent hook could run whereami.

To have new sessions join without gagent, Stan can run `python -I scripts/guardian-install-shims.py` from the main
checkout: it covers all six CLIs. It prints the change and writes nothing until `--apply`, which saves the old
user Path first; `--remove` undoes it. The `.ps1` wrappers are written only when PowerShell's execution policy
runs local scripts (RemoteSigned for Stan's user on 2026-10-13); otherwise PowerShell uses the `.cmd` ones. As a
second route, `python -I scripts/guardian-install-hooks.py` adds the adopt hook, with the same dry run, a backup
of the file and `--remove`. It covers Claude Code (a SessionStart entry for startup and resume in
`~/.claude/settings.json`), Codex (`~/.codex/hooks.json`, then trust it once with `/hooks` in codex), Cursor Agent
(a sessionStart entry in `~/.cursor/hooks.json`), Grok (`~/.grok/hooks/guardian.json`) and Antigravity (a named
hook `guardian-adopt` in `~/.gemini/config/hooks.json`). The user's own keys and hooks in these files stay where
they were, and the dry run and `--apply` print only the hook event that changes, so the env block of
`~/.claude/settings.json` never shows. The Claude app's Code tab and Cursor's editor read the same files as the
CLIs; there the hook finds the app among its parents and only logs a refusal. The Claude app's sessions go into
desktop jobs instead, while Cursor's editor has none. Gemini CLI gets no hook from this installer, since
`~/.gemini/settings.json` also holds other tools' hooks. Wrappers and hook only act while the daemon
for that instance runs. `python -I scripts/guardian-install-autostart.py` keeps the main daemon running: it
registers the scheduled task ResourceSentinelGuardian, which starts the daemon at logon through `conhost --headless`
with no time limit and never a second copy, and appends its output to
`~/.resource-sentinel/guardian/main-daemon.log`. Same dry run and `--remove`. `--port` sets the dashboard port, and
the installer refuses one that another program holds. On Stan's machine another local server holds 8765, so the
task uses `--port 8769` (2026-10-14).

Measured 2026-10-14 with the wrappers and the autostart task: Task Scheduler starts its action in a job with no
limits (flags 0) that refuses breakaway (a child started with `CREATE_BREAKAWAY_FROM_JOB` got Access denied).
With the task's daemon up, `claude`, `codex`, `cursor-agent`, `grok` and `agy` with `--version` each went through its
wrapper into a session of its own (enforced, below_normal priority), from a cmd that Explorer opened and from a new
Windows Terminal tab. Neither shell was in a job, though WindowsTerminal.exe itself is. A Windows Terminal that was
already open keeps its old PATH until it is closed completely, and `wt.exe` hands a new tab the environment of the
program that called it: a tab opened from inside the Claude app carries `CLAUDE_CODE_ENTRYPOINT=claude-desktop`, so
its wrappers run the CLI directly. The terminals inside VS Code and Cursor have shells in the editor's job. A
process started with such a shell as its parent (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, the wrappers first on PATH)
stands in for a command typed there: in both editors its job had flags 0x800, so breakaway is allowed. From the VS
Code terminal `claude --version` went into a session of its own (enforced). From the Cursor terminal the wrapper ran
it directly, since Cursor.exe is among its parents and Guardian leaves the desktop apps and everything under them
alone. An editor that was open before the PATH change gives its terminals the old PATH until it is restarted.

A daemon left in Task Scheduler's job passes that job on to every run it starts. Once AllAgents holds a process
from outside the job, such as an adopted CLI, those runs cannot join AllAgents: on 2026-10-15
`AssignProcessToJobObject` returned Access is denied, and srun ran codex, grok, cursor, antigravity and gemini runs
without control. A daemon that starts inside a job with its output going to a file therefore starts itself again
through WMI's `Win32_Process.Create`, which puts the new copy in no job and in the same session. The new copy
appends to the same log and the task's copy exits, so Task Scheduler shows the task as Ready while the daemon runs,
and `guardctl shutdown` stops it. The daemon stays in the job and warns when stdout is on a console or a pipe, with
`--stay-in-job`, or when its command line holds a `%`, since the headless conhost would expand `%NAME%` in it. If
the new copy exits within 3 s, the first copy warns and runs in place. API and SDK scripts have no CLI to wrap or
hook, so they join through srun. After the main daemon was restarted through the task on 2026-10-15, srun put
guardian-whereami, standing in for such a script, into its session job for claude, codex, cursor, grok,
antigravity and gemini. `--version` of Claude Code, Codex, Gemini CLI 0.63.0, Cursor Agent, Grok and agy 1.3.4
went into a session of its own (enforced) both through srun and through its wrapper, run from a cmd outside any
job and outside the Claude app.

On instance main, each CLI then made one real model call from a cmd that Explorer opened (2026-10-14). Through the
wrappers, `claude`, `cursor-agent`, `codex`, `grok` and `agy` each ran guardian-whereami as a tool command inside
its session. With `GUARDIAN_SHIM=off`, the global adopt hook alone placed codex, grok and agy, and the tool command
reported the session. Codex and grok came out partial: helpers that sat in a job of their own before the hook ran
stayed out (node.exe and node_repl.exe for codex, powershell.exe and conhost.exe for grok).

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

Desktop jobs, instance `main`, 2026-10-14, after a restart of the daemon: it found 21 Code-tab claude.exe processes
and placed all 21 in desktop jobs. In one of them, nine busy loops asked for 9 cores under a cap that started
at 6 cores and that the allocator lowered to 5.28 while they ran; the session used 5.33 cores. Its
processes ran at below normal priority, and the Claude app's own process stayed at normal. The same day, opening
the Codex app started codex.exe under ChatGPT.exe, and the daemon placed it within 2 s. Its 28 children (node.exe,
node_repl.exe, cmd.exe and conhost.exe) joined with it and ran at below normal, and the job's hard cap followed the
pool budget down to 1.20 cores. The Codex app sat idle, so it put no load against that cap.

On 2026-10-15 a task in the Codex app ran four busy loops for 194 s, enough to keep 4 cores busy. Their load landed
in one of the app's two codex.exe desktop jobs. Over the run that job used 0.82 cores on average under a cap that
averaged 0.85, although the machine had 3.23 cores idle on average. The allocator changed the cap every second,
between 0.17 and 3.08 cores, while the controller raised the pool budget from 10% to 34% of the machine. Second by
second the cap held less tightly: in 46 of 170 one-second samples the job used more than 0.05 cores above both the
cap set before the sample and the one set after it, by 0.20 cores on average and 0.65 at most.

## Known limits

- The dashboard page embeds the HTTP token, so any local process can read it. It listens on 127.0.0.1 only.
- Pausing a session sets its CPU rate to 0.01%. A paused CLI cannot service its network connections either, and
  they may time out, so keep pauses short.
- Claude Code and Cursor Agent sessions started neither through gagent nor through the PATH wrapper (by full path,
  from a terminal opened before the install, or by a tool that ignores PATH) join Guardian only through the adopt
  hook that `guardian-install-hooks.py` adds, and then in a nested job outside AllAgents (see Adopt; the provider
  check's hook level passed for both on 2026-10-15). Without that hook they stay outside Guardian. A session
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
- Desktop jobs sit under the apps' jobs, not under AllAgents, so the root's hard cap does not hold them. The pool
  total, tree and desktop jobs together, holds only through the allocator's per-session caps, set once a second.
  While nothing contends, each desktop session may use the whole budget, so sessions that start to burst together
  can go over the total for up to one tick before the allocator caps them. A desktop job name that already exists
  is refused like a session name, with a logged `desktop_refused` decision, and that CLI stays outside Guardian
  while it runs.
- Over a whole run a desktop cap holds, but a single second can go over it. Under the Codex app on 2026-10-15 the
  allocator changed the cap every second, and in about a quarter of the one-second samples the job ran above the
  caps set around that second, by 0.20 cores on average. The samples do not show whether Windows applies a new cap
  late or a sample spans two caps.
- Turning desktop jobs off leaves each CLI in its old desktop job, without limits and without a name once the
  daemon closes its handle. Turning them on again nests a new desktop job under that one, so every off and on adds
  a level. A restart nests the same way: the old desktop job loses its name when the old daemon exits, and the new
  daemon puts the CLI in a fresh job under it (measured). As with the tree, a crashed daemon leaves its desktop caps
  in place.
- A nested job sits under the CLI's own job, outside AllAgents, so like a desktop job it is held only through the
  allocator's per-session caps. `guardctl desktop off` leaves nested jobs capped on purpose: their CLIs asked to
  join through the adopt hook, while the switch is about Guardian reaching into the apps. Rollback and shutdown
  lift their caps as for any session. A second CLI that arrives under the name of a nested or desktop session is
  refused, since it cannot join that job. A CLI's children that already sit in a job of their own when the hook
  runs stay outside, as in the tree. The first process in AllAgents fixes where that job sits for good, so while
  AllAgents has never held a process, a CLI in a job of its own gets a nested job as well. Joining would put
  AllAgents and every later run under the CLI's job (measured), and a job that kills on close, as Node's does,
  would end them all when the CLI exits. The same holds inside the nested job: when the CLI's own job kills on
  close, every child the CLI started ends with it, detached ones included, and a child started with
  `CREATE_BREAKAWAY_FROM_JOB` fails, since the nested job allows no breakaway. Outside Guardian, Node's job lets
  detached children leave and survive the CLI. Measured with a test job shaped like Node's.
