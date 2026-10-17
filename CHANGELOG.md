# Changelog

## Unreleased - 2026-10-17

- Guardian controls the Cursor app's agent. The bundled cursor-agent worker (one node.exe per open workspace) goes
  into a desktop job like the Claude and Codex app CLIs, and the agent commands Cursor starts outside the worker are
  told apart from Stan's own terminal commands by `CURSOR_AGENT=1` in their environment, read from the process's
  PEB. Each chat gets one desktop job, `cursor/chat-<id>`, that its commands share; whereami finds these jobs by
  name. Measured live on a test instance: both workers, three spoofed commands of one chat, one without a chat id,
  and the commands of a real Cursor chat were placed within 2 s; an unmarked command was left alone.
- winjob gains `environment(pid)`, I/O and memory priority setters and readers, and `trim_working_set(pid)`.
- Agent processes get low I/O and low memory priority. The daemon sets both once on each process that shows up in
  one of its jobs, and children started afterwards inherit them. `guardctl io-priority` and `memory-priority` change
  the level, the dashboard shows it, rollback restores normal, and a shutdown keeps it low.
- The dashboard and `guardctl status` show the load outside Guardian: the top five image names by CPU among the
  processes not in its jobs, protected ones included, next to the whole machine's busy cores and the part no process
  row accounts for.
- Two cap controller rules look at idle CPUs, and both are off by default. `backoff_idle_cores` holds the cap
  through a degraded window while that many CPUs sit idle, and `recover_idle_cores` lets it rise after 5 healthy
  seconds instead of 20, by a step that hands the agents half of the idle CPUs. `guardian.py --policy FILE` merges a
  JSON file over the policy defaults, and `scripts/guardian-sim.py` replays the controller over a ledger to compare
  settings offline. The simulation and a live ABBA run are in docs/guardian.md.
- The srun queue has five orders, picked with `guardctl queue-order` or the dashboard: class then arrival (the
  default), arrival, shortest expected run, highest response ratio, and least CPU per allocation weight. The
  expected run is the median wall time of the last 20 successful runs of the same command. Stan can exempt a session
  for up to 24 hours from the dashboard or `guardctl class KEY exempt [minutes]`. While it lasts the session has no
  cap, its queued commands skip the memory and launch gates, and its new commands run outside AllAgents at normal
  priority. srun, the hooks and adopt cannot set it. `scripts/guardian-queue-sim.py` compares the orders offline.
- The daemon now acts on memory pressure from running work. It adds up the private commit of every process in its
  jobs, and when available RAM falls under Stan's 6 GiB, or the agents pass an optional budget that also gates
  admission, it trims their working sets, largest first. With `pressure_pause` on, pressure that lasts 20 s pauses
  the session holding the most commit until memory is 1 GiB inside the threshold again. An optional hard limit puts
  a job memory limit on AllAgents. `guardctl memory-budget|memory-trim|memory-pause|memory-limit` set them, and the
  dashboard sets the budget, trim and pause; rollback and shutdown remove the limit. Trim is on by default, so the
  policy version is now guardian-policy/2.
- An agent can learn its own budget. With `--context` the adopt hook gives the model, at session start, its Guardian
  session, CPU cap, priorities, free RAM and the srun line for a long command, in the output shape of Claude Code,
  Codex or Cursor. `hooks/guardian-status.py` gives a one-line form before each prompt in Claude Code and Codex.
  `whereis` answers with the session's budget, and `guardian-install-hooks.py --context --status` installs both
  hooks, as a dry run until `--apply`. Measured with a real `claude -p` on a test instance: both texts reached the
  model's request, which a local server answered with 401.
- The acceptance run is in docs/guardian.md: control off and on under a mixed agent load in a 4-CPU world,
  a Cursor-style agent command included, and a second run that switches only the agents' I/O priority.
- The memory ladder follows its settings while pressure lasts. Turning `memory-trim` or `memory-pause` off stops
  that step on the next tick, and a ladder pause also ends when its session ends, is exempted, leaves with the
  desktop jobs or is paused by Stan. The ladder never picks a session that holds no private commit, and a tick that
  runs after shutdown trims and pauses nothing.
- `guardian.py --policy FILE` checks the file against the policy defaults before the daemon starts. An unknown
  key, a wrong type, a level outside its set or an allocation weight that is not above 0 stops it with exit code 2
  and a message naming the key. `guardian-sim.py` no longer fails on a ledger exactly `--seconds` long.
- Each Cursor agent command is placed once. A command under a Cursor agent worker, or one an earlier command
  already swept into a chat job, no longer gets a job of its own, so its CPU is not counted twice. A Cursor started
  with `CURSOR_AGENT=1` passes the mark to every process under it, so the daemon also reads the mark of the nearest
  Cursor.exe above a command and places nothing under one that carries it or cannot be read. It logs that once per
  Cursor.exe.

## Unreleased - 2026-10-13

- Add Guardian, a daemon that runs agent sessions inside Windows Job Objects: a dynamic hard cap on all agents
  driven by a foreground probe, below-normal agent priority, per-session caps from allocation weights, pause,
  cancel, and a control on/off switch. Includes srun, guardctl, a dashboard, and policy unit tests.
- The CPUs open to agents can be changed while sessions run (dashboard, `guardctl world N`, `--world-cpus`).
- Demos: fake sessions in a miniature world, timed or manual control on/off, and a real Claude Code CLI that
  works as an agent inside Guardian until stopped. See docs/guardian.md.
- Guardian for every agent CLI (Claude Code, Codex, Gemini, Cursor Agent, Grok): `gagent` launches any of them
  inside a session job; a session-start hook (`hooks/guardian-adopt.py`) and `guardctl adopt` move a running CLI
  and its children in, refusing the desktop apps; `guardian-whereami` tells a session whether it is controlled,
  also from inside a sandbox that blocks the daemon's pipe; `guardian-provider-check` proves it per CLI; and
  `guardian-install-hooks` (dry run unless `--apply`) adds the hook to Codex and Grok user configs.
- PATH wrappers for the same five CLIs: `guardian-install-shims` (dry run unless `--apply`, old Path backed up)
  puts claude, codex, gemini, cursor-agent and grok wrappers first on the user Path, and `guardian-shim` starts the
  real CLI suspended in the same console, has the daemon assign it, then lets it run. This also covers Claude Code
  and Cursor Agent, which put themselves in a job of their own and so cannot be adopted by a hook. The provider
  check gains the `shimver` and `shim` levels. The adopt sweep leaves desktop-app helpers under a CLI alone, and
  hook session names come from the tail of time-ordered (UUIDv7) ids.
- Wrapper fixes after the verifier pass: a `.ps1` wrapper for PowerShell (no cmd.exe in between), arguments after
  the CLI name reach it untouched (a leading `--` included), arguments for the CLIs installed as `.cmd` are
  written the way Rust's standard library writes batch-file arguments (a double quote or `%` in a prompt could
  otherwise make cmd.exe run part of it), the CLI is resumed within 15 s even when the daemon never answers or
  gives an unreadable answer, Ctrl+C during that wait no longer ends the shim, `GUARDIAN_SHIM=off` is silent, the
  current folder no longer counts as the real CLI, the Claude app is also recognized by `CLAUDE_CODE_ENTRYPOINT`
  (Git Bash breaks the parent chain), and `--remove` deletes only wrapper files with the guardian-shim note.
- Guardian's named jobs get a protected DACL, so other processes of the user can only query them; the daemon keeps
  its rights through the handle it got when it created each job. A daemon refuses to start while its AllAgents job
  is still held open, was made with a permissive DACL, or its name is held by another kind of object or a symbolic
  link, and refuses a srun or adopt whose job name is taken. A link counts wherever it points, a free name
  included, since the daemon compares the kernel path of each job it creates with its own name. `Job.open` now
  opens for query unless told otherwise.
- The pipe handshake runs on each connection's own thread with a 5 s deadline instead of inside the daemon's one
  accept thread. A client that connects and then stalls is dropped after 5 s and no longer holds up srun, gagent,
  the adopt hook, the PATH wrappers or whereami: with one stalled client, another client's ping took 0.002 s
  instead of 9.99 s. `client.connect()` also gives up when the daemon has not finished the challenge within 5 s.
  The `pipe-authkey` file and the bytes on the pipe are unchanged, so old and new clients and daemons work together,
  and clients with a wrong key or none are still refused.
- Desktop jobs: every 2 s the daemon finds the Claude Code CLIs of the Claude app's Code tab and the codex CLIs of
  the Codex app, puts each in a fresh job of its own (it nests under the app's job, since those CLIs cannot join
  AllAgents), and sweeps their children in. Each desktop session gets the pool priority, the agents' CPU set, and a
  cap in absolute cores from the allocator (the whole budget while nothing contends); pause, rollback, resume and
  shutdown treat it like the tree, and its CPU counts in the pool. On by default for the main instance only;
  `--desktop on|off`, `guardctl desktop on|off` and `/api/desktop` switch it, and off releases every desktop job.
  `guardian-whereami` reports such a session as controlled.
- Antigravity CLI (`agy`, provider `antigravity`) joins Guardian like the other CLIs: gagent, an `agy` PATH wrapper,
  the adopt hook as a named `guardian-adopt` hook in `~/.gemini/config/hooks.json` (installer, dry run unless
  `--apply`; the user's own hooks in that file stay), and the provider check. The Antigravity desktop app is refused
  like the other apps. agy 1.3.4 passed all five check levels: srun, hook and both wrapper levels in one run, the
  version level in a rerun after the first attempt waited on RAM room until it timed out. Since agy runs a shell
  command headless only with global permission rules or `--dangerously-skip-permissions`, the check judges it by a
  PreInvocation hook that agy starts as its own child, and asks for the shell command only with `--allow-yolo`.
  With that flag the shell command reported its session too, at srun, hook and shim (report 000722).
- `guardian-install-autostart` (dry run unless `--apply`, `--remove` deletes the task) registers a logon task that
  starts the main daemon through `conhost --headless`, with no time limit and never a second copy, and refuses a
  dashboard port that another program holds. With that daemon up, `claude`, `codex`, `cursor-agent`, `grok` and
  `agy` started from a cmd opened through Explorer and from a new Windows Terminal tab each went through their
  wrapper into a session of their own.
- The daemon leaves the job it starts in. The logon task's daemon sat in Task Scheduler's job, which refuses
  breakaway, so once AllAgents held an adopted CLI, srun and gagent runs could not join it and ran without control.
  A daemon started inside a job with its output going to a file now starts itself again outside any job through
  WMI's `Win32_Process.Create` and appends to the same log, and the first copy exits. `--stay-in-job` keeps it
  where it is. It also stays and warns with stdout on a console or a pipe, when its command line holds a `%` (the
  headless conhost would expand `%NAME%`), and when the new copy exits within 3 s. After the restart, srun put a
  stand-in for an API script into its session job for all six providers, and `--version` of all six CLIs ran
  enforced through srun and through the wrappers.
- The provider check covers Gemini CLI 0.63.0. Its hook level writes the hooks to one fixed folder, so gemini's
  `~/.gemini/trusted_hooks.json` gets a single entry, and every provider's hook level now starts the real CLI
  instead of the wrapper. Run from a cmd outside any job, the SessionStart hook ran and adopt was refused: gemini
  starts itself again as a second node.exe, and Node's libuv has already put it in a job of its own. Gemini is
  therefore marked like Claude Code and Cursor Agent (LIMIT) and joins through srun or the wrapper. Google refused
  the sign-in in the same run (`IneligibleTierError`), so Gemini CLI cannot make a model call with Stan's account.
- The adopt hook takes a CLI that sits in a job of its own (claude.exe, and the node.exe of Cursor Agent and Gemini
  CLI). Such a process cannot join the tree once AllAgents holds work, so the daemon now gives it a fresh job,
  `<instance>.d.<provider>.<session>`, which Windows nests under the CLI's job. It sweeps the CLI's children in
  and caps the job like a desktop job, outside AllAgents. A second hook for the same CLI answers `already`, also
  for desktop jobs. A nested job ends with its CLI even while desktop jobs are off, and `guardctl desktop off`
  leaves it capped. whereami reports it by the pipe or by the job's name, and the provider check counts it as
  PASS. Measured with real jobs in the tests: a stand-in CLI in a job with libuv's flags was adopted, a child it
  started afterwards stayed in the nested job, and the job's name went away after the CLI exited. While AllAgents
  has never held a process, such a CLI goes to a nested job too: as the first process there it would put AllAgents
  and every later run under its own job (measured). In the provider check's hook level (report 220410), Claude Code
  and Cursor Agent passed: each was adopted into a nested job (claude.exe with 19 children, Cursor's node.exe with
  21) and whereami, run as the agent's tool command, answered CONTROLLED for the nested session. Gemini's node.exe
  and its 4 children joined a nested job as well, but the sign-in failed before its BeforeAgent hook, so no tool
  command ran. All three sessions ended with their CLIs. Children the CLI starts, detached ones included, now end
  with a CLI whose own job kills on close, and cannot break away.
- `guardian-install-hooks` also adds the adopt hook for Claude Code (SessionStart in `~/.claude/settings.json`) and
  Cursor Agent (sessionStart in `~/.cursor/hooks.json`), keeping every other key and hook in those files. Its dry
  run and `--apply` output show only the hook event that changes, never the rest of the file, and any hook in it
  that is not Guardian's appears as `(other hook, not shown)`. Files keep their line endings and non-ASCII text.
  Gemini CLI stays without a hook from it.

## Unreleased - 2026-09-13

- Publish one shared user-exemption policy for ALL Sentinel agents in status.md and
  the prompt hook, including when telemetry is stale/missing. Installed Claude hooks
  now load repository entrypoints directly, preventing stale copied integrations.
- Add explicit user-authorized, expiring process-tree exemptions with grant/list/revoke,
  creation-time checks and dedicated command-wrapper cleanup. Exempt work still reserves
  capacity and is measured; normal callers retain the existing admission rules.
- Collector skips exempt CPU/I/O demotion and working-set trim, restores prior demotion,
  and publishes exemption identities. Document scope, expiry, and sampling latency.
- Fix the wrapper's Windows PowerShell local-time epoch conversion so process identities
  match Python on non-UTC hosts. Add isolated RED-load and process-policy tests.

## Unreleased - 2026-09-05

- Harden watchdog recovery with collector ownership checks, bounded stop/start,
  four-timestamp verification, cooldown/backoff, and a shared manual restart command.
- Record collector stages and durations without workload text; bound the optional
  nvidia-smi probe to three seconds. Add isolated PowerShell recovery tests.
- Live scheduler: watchdog timeout is four minutes; both tasks start when available.

- Recover scheduled collection from delayed startup and hung collectors: always attempt
  the first sample, bound each child to 45 seconds, preserve launcher exit codes,
  and log sanitized failure types. Live scheduled task timeout is now two minutes.

- Reduced the Commit admission headroom to 4 GiB and added boundary coverage.
- Excluded Google Drive capacity from collection and dashboard cards.
- Added a bounded :00/:30 collector runner and five-second publication alignment,
  preserving measurement timestamps separately from publication timestamps.
- Added the roadmap for control coverage, a local scheduler, fair resource allocation,
  live telemetry, and a unified cloud worker pool. These new systems remain planned,
  not deployed or verified end to end.

## 0.14.0 - 2026-08-28

- Added a durable one-shot orchestrator with task/job/event ledgers, retries, dependencies,
  cancellation, manual completion, agent-session heartbeats, and optional local verification tasks.
- Added provider-neutral adapter contracts (`submit`, `status`, `cancel`, `collect_result`). The local
  command adapter is the only ready/enabled bootstrap adapter; every unverified cloud provider uses a
  truthful manual/disabled default instead of claiming UI access is an API.
- Added atomic repo/base-SHA/path-scope workspace claims with heartbeat, state transition, TTL cleanup,
  overlap protection for concurrent agents, and conservative Git worktree materialization.
- Separated resource accounting into `SHARED_POOL` and `PER_EXECUTION`, with independent
  `capacity_pool`, `max_concurrency`, `quota_domain`, and `failure_domain` semantics. WORKER and
  explicitly handshaken SESSION tasks now spend the same reservations and recover expired leases.
- Added compare-and-set dispatch leases, stale ROUTING recovery, explicit unknown-dispatch
  resolution, retryable result collection, restart-safe idempotent local job IDs, and bounded output.
- Added local process-tree RAM/CPU/I/O measurements and P50/P90/P95 execution profiles; disk
  queue/latency now participate in the machine light with recovery hysteresis.
- Local commands now receive a minimal environment plus explicit `env_refs`; PID cancellation checks
  process creation identity, and the Claude hook recognizes the atomic wrapper without double booking.
- Updated worker bootstrap data with conservative concurrency and explicit adapter readiness. Added
  architecture and integration guidance: agent sessions are control endpoints, cloud workers are
  disposable executions rather than permanent computers, and secrets stay in environment variables.

## 0.13.0 - 2026-08-27

- Added a provider-neutral `Maintainer` with a persistent worker registry.
- Added atomic, memory-aware routing and reservations across local/cloud workers.
- Added failure-domain accounting so shared cloud computers are not double counted.
- Added capability, trust-domain, quota-state, and probe-freshness filtering.
- Added `maintainerctl.py`, bootstrap empirical worker data, and routing tests.

## 0.12.0 - 2026-08-25

- 新增 SQLite coordinator：`BEGIN IMMEDIATE` 原子 admission、P0-P3 priority queue、
  CPU/RAM/Commit/heavy-I/O reservation、PID+creation-time stale cleanup
- Claude gate 改成 per-tool reservation；修正同 session 平行重指令共用/誤釋放槽位問題
- Codex/Cursor 等無 hook agent 新增 `invoke-sentinel.ps1` reserve/run/finally-release wrapper
- collector 新增 Commit、pagefile、實體磁碟 active/queue/throughput/latency 與 30 天 SQLite telemetry
- GREEN/YELLOW/ORANGE/RED 加入 Commit pressure、recovery margin 與連續樣本 hysteresis
- G: 標示為 Google Drive 虛擬磁碟；文件釐清 `WriteTransferCount` 不是實體磁碟 bytes
- 新增 coordinator 單元測試與隔離的 PowerShell 5.1 end-to-end 驗證

## 0.11.0 - 2026-08-13

- SSD 定位修正（Stan 釐清）：不進排程，專職突縮偵測
  - 單分鐘剩餘空間縮 ≥5 GB（disk_alert_gb 可調）→ Telegram 通知，
    附前三名嫌疑寫入者，每磁碟 30 分鐘冷卻
  - 由你判斷要不要清理；agent 可代查 events.log 完整記錄

## 0.10.0 - 2026-08-13

- Stop hook sentinel-stop.py（Stan 明確核可）：session 在重活佇列中想結束回合會被擋回、
  命令跑 waiter；最多擋 3 次後自動移出佇列放行，防無限迴圈
- RAM 約束：RAM 達橘燈閾值時對 agent 樹 >300MB 進程做 working set trim
  （實測釋放 442MB/616MB），10 分鐘防重複，events.log 記錄
- SSD I/O 約束：橘/紅燈 agent 進程 I/O 優先權降 Low、綠燈恢復 Normal
  （NtSetInformationProcess，與 CPU 降級同進退）
- heartbeat 已接 healthchecks.io（Stan 提供 ping URL），整機失聯 10 分鐘雲端通知
- gate 擋下訊息改指令式三步驟；Codex AGENTS.md 補 waiter 用法

## 0.9.0 - 2026-08-13

- 每 session 進程明細：採集器輸出每棵樹 RAM 前 8 名成員（top_members），
  儀表板每個 session 可展開看「開哪些程式、各佔多少 RAM/CPU」
- config.heartbeat_url 待 Stan 填 healthchecks.io ping URL（接口已就緒）

## 0.8.0 - 2026-08-13

- 排隊制取代單純搶槽：queue.json FIFO、gate 回報佇列位置、10 分鐘未續期自動出隊
- wait-slot.ps1：被擋 session 跑它保持 active，輪到（隊首＋槽空＋綠/黃燈）即刻返回
- Telegram 全中文化：messages.json 模板（ASCII 轉義），雙發送端改 UTF-8 URL 編碼
  修 PS 5.1 hashtable body 中文亂碼雷
- 看門狗 ResourceSentinelWatchdog（每 5 分鐘）：狀態檔過期先自動重啟採集器，
  救回/救不回各發中文通知，60 分鐘冷卻；config.heartbeat_url 預留外部 dead-man 接口
- 驗證：排隊三路徑（擋+報位/放行佔槽/waiter 等到釋放秒過）、看門狗健康靜默、
  中文訊息實送成功

## 0.7.0 - 2026-08-13

- Telegram 警報：紅燈連續 5 分鐘發警報、回綠發解除，冷卻 60 分鐘
  - 共用 mobile-oss bot，config 只存 .env 路徑，token 不進 repo
  - 實測發送成功（message_id=8）
- 已知限制：採集器本身掛掉就發不了警報（dead man's switch 需外部服務，未做）

## 0.6.0 - 2026-08-13

- 中樞調控上線（Stan 核可：槽數 1、黃軟/橘紅硬擋）
  - sentinel-gate.py：PreToolUse 攔重活申請槽位、PostToolUse 釋放；
    紅燈全擋、橘燈擋新重活、槽被佔排隊；TTL 15 分鐘＋死進程自動釋放
  - OS 優先權降級：橘/紅燈全 agent 樹降 BelowNormal、綠燈自癒式恢復
    （不依賴名單，任何 BelowNormal 的 agent 進程綠燈一律升回）
  - status.md/json 新增 Arbiter 區塊（槽位持有者、降級進程數）
- 驗證：gate 五路徑（放行/紅擋/橘擋/佔槽擋/釋放）、紅燈實降 201 進程、
  綠燈實測恢復 Normal

## 0.5.0 - 2026-08-13

- 四層燈號 GREEN/YELLOW/ORANGE/RED（Stan 需求：RAM/CPU 百分比、磁碟絕對 GB）
  - RAM 75/85/92%、CPU 5分均 60/75/88%、C槽剩 50/35/20 GB，舊 config 自動遷移
- hook/儀表板/Codex AGENTS.md/Cursor 貼文同步四層
- 推上 GitHub public：https://github.com/stantheman0128/resource-sentinel

## 0.4.0 - 2026-08-13

- Claude Code hook `sentinel-inject.py`（spec 第 3 步）：每輪注入一行狀態、黃/紅燈升級警告、
  監控失效偵測、session pid+cwd 登記（沿祖先鏈找 agent 進程，修 shell 隔層問題）
- 歷史帳本（spec 第 4 步）：session→repo 歸因、per-repo 峰值 RAM 統計（最近 20 筆＋中位數）、
  修 treeOf uint32/int32 型別 bug
- Codex 全域 AGENTS.md 接入＋Cursor 貼規則說明（spec 第 5 步，docs/agent-integration.md）
- README、儀表板樹標籤加 repo 名

## 0.3.0 - 2026-08-13

- 靜態儀表板 dashboard.html（spec 第 2 步收尾＋Stan 新需求）
  - 燈號、CPU/RAM/GPU/磁碟卡片、近 3 小時趨勢圖、agent 用量表、寫入排行、異動事件表
  - 零常駐：採集器每輪輸出 data.js，頁面 60 秒自動刷新；瀏覽器直接開 `~\.resource-sentinel\dashboard.html`
- Task Scheduler 排程 `ResourceSentinel` 每分鐘執行（conhost --headless 無窗模式，不用 VBS）
- 驗證：排程自主執行 Last Result=0、儀表板全區塊渲染實測通過

## 0.2.0 - 2026-08-13

- GPU 量測（nvidia-smi 主、效能計數器備援）
- 磁碟寫入歸因：跨輪差分 WriteTransferCount，agent 樹標記
- events.log：磁碟單輪變動 ≥2 GB 記錄事件＋寫入排行快照（2 MB 上限自動修剪）
- 實測首捕：SearchIndexer 單輪寫入 14.2 GB

## 0.1.0 - 2026-08-12

- collect.ps1 採集器核心（spec 第 1 步）
  - 全機 CPU（效能計數器，含 Get-Counter 失敗時的進程差分 fallback）、RAM、各磁碟
  - agent 進程樹偵測與彙總（claude/cursor/codex 為根，BFS 含循環防護）
  - 綠/黃/紅燈號判定（閾值在 config.json 可調）
  - status.md + status.json 原子寫入（temp + rename）
  - samples.csv 追加與 5 分鐘 CPU 均值；行數上限防爆
  - 驗證：同時點 RAM 對照誤差 0.2pp、5 分鐘均值手算相符、連跑三次覆寫正常
