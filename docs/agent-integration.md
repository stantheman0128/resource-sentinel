# 各 agent 接入方式

告示板路徑固定：`C:\Users\stans\.resource-sentinel\status.md`（機器可讀版 `status.json`）。
任何能讀本機檔案的 agent 都能接入，不需要 MCP 或任何協定。

先分清兩個角色：agent session 是 Codex／Claude Code／Cursor 等控制端，負責理解任務、
修改與回報；execution worker 是實際跑 command 或 provider job 的本機／雲端環境。
session heartbeat 不能增加可用 RAM，worker probe 也不代表該 provider 能自動收任務。

## Claude Code / Claude Desktop（資源 admission 已自動接入）

`~/.claude/settings.json` 的 UserPromptSubmit 掛了 `sentinel-inject.py`：

- 每輪對話自動注入一行狀態（燈號、RAM、CPU、GPU、C 槽、本 repo 歷史峰值）
- 黃燈追加降速建議、紅燈追加強制警告
- 同時把 session 的 agent 進程 pid 與 cwd 登記到 `sessions.json`，
  採集器據此把進程樹歸因到 repo（歷史帳本的資料來源）
- 新開的 session 才會生效（hook 設定變更不影響已開的 session）

## Codex CLI / Cursor（atomic wrapper 可用）

全域 `C:\Users\stans\.codex\AGENTS.md` 會先讀 status.md。真正需要原子 reservation
的重量級指令，應透過 wrapper 執行，而不是只先讀燈號：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 `
  -Command "npm run build" -Priority P2
```

wrapper 會排隊、原子取得 CPU/RAM/I/O reservation、執行命令，最後在 `finally`
釋放。Claude hook 能精準辨識這個 wrapper，避免內外重複 reservation。
`-ResourceClass AUTO` 仍是 bootstrap rule；`orchestratorctl.py profiles` 提供歷史 P50/P90/P95
供後續調整顯式需求，但尚未自動改寫 task request。

## 登記 agent session

要讓中央帳本看見一個 session，可在開始工作和活動期間送 heartbeat：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  session-heartbeat --session-id codex-example-01 --agent-kind codex `
  --owner-pid 12345 --repo C:\src\example --state IDLE
```

`session-id` 必須穩定且每個 session 唯一；`owner-pid` 是 agent 根進程，不要填 command
子進程。開始／結束 task 時更新 `--state` 與 `--current-task-id`。目前 heartbeat 是
registry 與觀測資料，不會接管既有互動對話，也不會把某個 session 的 context 複製給
另一個 provider。

採集器從 process tree 自動發現的 session 只是 inventory，預設 `accepts_tasks=false`。
只有上述顯式 `session-heartbeat` 完成 broker handshake 的 session 才能 `session-pull`；被指派
的 SESSION task 會和 WORKER task 一樣扣除 bound worker 的 RAM/CPU/disk/concurrency。

查看目前 registry：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py sessions
```

Cursor 全域 rule 仍需手動貼一次，但重活應呼叫相同 wrapper；只讀 status.md
不能防止兩個 agent 同時起跑。

Cursor 的全域規則存在它自己的設定裡，沒有可靠的檔案路徑可以直接寫入。
打開 Cursor：Settings、Rules for AI，貼上下面這段：

```
Before running anything heavy (builds, installs, full test suites), read
C:\Users\stans\.resource-sentinel\status.md. GREEN: proceed. YELLOW: run heavy
commands with low priority and avoid parallel heavy work. ORANGE: defer new
heavy tasks; if one must run, low priority and one at a time. RED: light
operations only; tell the user the machine is overloaded. If the file is older
than 5 minutes, monitoring is down; say so and ignore its contents.
```

貼完之後 Cursor 的 session 就會在動手前自己去看告示板。

## 提交跨環境 task

task 應至少指定穩定 id、prompt 或 command、repo 及預計修改的 `path_scopes`。資源需求、
capability、trust domain 和執行偏好都放在 task，而不是寫死在 agent prompt：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py submit --task `
  '{"id":"example-fix-01","prompt":"Implement the fix","repo":"C:/src/example","base_sha":"0123456789abcdef0123456789abcdef01234567","path_scopes":["src","tests"],"priority":"P2","requirements":{"ram_gib":4,"cpu_units":2},"execution_preference":"CLOUD_PREFERRED","verification":{"command":"py -m pytest"}}'

py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py tick --limit 2
```

寫入 repo 的 task 必須同時提供不可變的 `base_sha` 與 `path_scopes`。dispatch 前會先取得
worker reservation 與 repo／base SHA／path scopes 的 workspace claim；本機 task 再建立或
安全重用 deterministic Git worktree，回傳的 `workspace.worktree_path` 才是工作目錄。
重疊範圍被其他 task 佔用時應等待，不要繞過 claim 在原 checkout 併寫。cloud phase
若有 `verification`，結果回收後會建立 `LOCAL_REQUIRED` 的 P1 子 task。

## Cloud provider 的預設行為

bootstrap 只讓本機 adapter 自動化。Cursor Cloud、Grok、Claude Web、Codex Cloud、
ChatGPT Work 和 GitHub runner 都是人工 probe 資料，預設 adapter 為 manual 且 disabled。
這表示我們知道一次觀測到的環境形狀，不表示已有可靠的 submit/status/cancel/result API。

人工 dispatch 的 task 會停在 `AWAITING_MANUAL`；在人類確實完成 provider 操作並取得
結果後再回報：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  complete-manual --task-id example-fix-01 --success --result '{"artifact":"commit-or-patch-id"}'
```

雲端 execution 通常是暫時 container／runner，不是永久電腦；不要依賴跨 job 的檔案、
登入狀態、IP 或背景程序。要啟用真正的 provider adapter，必須先逐項驗證 lifecycle 與
crash recovery。token、cookie、密碼不得寫入 task JSON、worker bootstrap、SQLite、log 或
Git；設定只保存環境變數名稱，值在執行時注入。本機 command 預設不繼承任意 parent
environment；需要的秘密用 `metadata.env_refs` 顯式列出。

provider submit 邊界若 crash，task 會停在 `dispatch_outcome_unknown`。不要直接重送；用：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  resolve-dispatch --task-id example-fix-01 --external-job-id <provider-job-id>
# 或在 provider 確認完全沒有送出後：--confirmed-not-submitted
```

## 之後新裝的任何本機 agent

只要它支援 system prompt、rules 檔或 AGENTS.md，把上面 Cursor 那段貼進去就接入了。
若只需要資源告示板，系統本身不用改任何東西；若要參與原子調度，再加 session heartbeat、
以 wrapper 執行重活，並用 orchestrator task／workspace claim 流程協調修改範圍。

完整架構與容量語義見 [`architecture.md`](architecture.md)。
