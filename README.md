# Resource Sentinel

讓本機所有 coding agent 開工前就知道電腦還剩多少資源，並以同一份 SQLite 帳本協調
本機與異質 execution workers。沒有常駐調度 daemon；Task Scheduler 週期性執行短命的
採集／reconciliation 程序，中斷後可從帳本恢復。

採集目標為每分鐘 `:00`、`:30`。每輪狀態發布等待下一個 5 秒刻度，
`generated_at` 記錄實際發布時間，`sampled_at` 保留量測時間；作業系統繁忙時可能延遲。
Dashboard 每 5 秒重新讀取快照，不會觸發採集。排程 runner 不補跑錯過的時段，
以 mutex 與 Task Scheduler 的 IgnoreNew 設定避免排程採集重疊。
Commit 安全餘額預設為 4 GiB；CPU、RAM、Commit 燈號與 I/O 准入仍獨立生效。

## 為什麼做這個

後續中控、公平調度、即時監控與第二雲端規劃見 [Roadmap](docs/roadmap.md)。
Roadmap 明確區分現有功能與尚未設置、測試的新系統。

多個 agent session 同時跑的時候，沒有誰知道整台機器的狀況。每個 session
都覺得自己可以開 build、裝依賴、跑測試，疊起來就把電腦拖到卡死。
這個工具給所有 agent 一張共用的「告示板」，開工前看一眼，超載就自己讓路。

## 架構

```
Task Scheduler（每 60 秒啟動 collect-scheduled.ps1）
  └─ collect.ps1（每分鐘 :00／:30 各一輪，逾時跳過，不重疊）
       ├─ 量測：CPU、RAM、GPU、磁碟、各 agent 進程樹用量
       ├─ 歸因：跨輪差分算出「上一輪間隔誰寫了多少磁碟」
       └─ 產出：status.md（告示板）、status.json、dashboard.html 資料

orchestratorctl tick（跑完就退）
  ├─ SQLite：agent sessions、tasks/jobs/events、workers/reservations、workspace claims
  ├─ maintainer：依容量、capability、trust、quota、probe freshness 選 worker
  └─ adapter：local 自動 lifecycle；未配置的 cloud 留在 AWAITING_MANUAL

讀取端（只讀檔案，零進程）：
  ├─ Claude Code：hook 每輪自動注入狀態，黃紅燈升級警告
  ├─ Codex CLI：AGENTS.md 指示開工前讀告示板
  ├─ Cursor：Rules for AI 同樣指示
  └─ 瀏覽器：開 dashboard.html 看儀表板（60 秒自動刷新）
```

## 主要能力

- 綠、黃、橘、紅燈號：RAM、Commit、CPU 五分鐘均值、系統碟剩餘、實體磁碟
  queue/latency 取最嚴，下降時需連續兩輪通過 hysteresis
- agent 進程樹用量：claude、cursor、codex 為根，往下彙總整棵樹
- 實體磁碟：active time、queue、throughput、read/write latency。另以 process
  `WriteTransferCount` 當相關性線索（它不是實體磁碟 bytes）；磁碟單輪變動超過
  2 GB 時把當下排行存進 events.log，不能單獨當成因果證據
- Commit/pagefile：和 physical RAM 分開量測，避免只看 Available RAM
- 結構化 telemetry：SQLite 保存 30 天全機與 agent-tree samples，完成的 reservation
- 異質 worker maintainer：同一個 SQLite registry 管理 local/cloud capacity、probe
  freshness、quota state 與跨 worker 記憶體預約。`SHARED_POOL` 依 capacity pool 加總
  reservation；`PER_EXECUTION` 檢查每個 job 的形狀與最大併發。failure domain 只描述
  相關故障，不再假裝是資源池。
  另存 execution ledger；`orchestratorctl.py profiles` 會彙整同類執行的 P50/P90/P95
- 任務 orchestrator：保存 task lifecycle、agent session heartbeat、provider job 與事件；
  WORKER／SESSION 走同一容量 reservation，dispatch 前原子取得 workspace claim；本機寫入
  task 從指定 base SHA 建立隔離 Git worktree，cloud 結果可排本機驗證子任務
- 歷史帳本：每個 repo 的 session 峰值 RAM 統計，agent 開工前
  可以拿「這個 repo 上次吃多少」對照現在剩多少餘裕
- 儀表板：趨勢圖、agent 用量表、寫入排行、異動事件，單一 HTML 檔

## 安裝

1. Clone 到本機，跑一次採集器確認有輸出：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\collect.ps1
```

2. 掛排程（不需管理員權限）：

```powershell
schtasks /create /f /tn "ResourceSentinel" /sc minute /mo 1 /tr "conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File <路徑>\scripts\collect-scheduled.ps1"
```

3. 瀏覽器開 `%USERPROFILE%\.resource-sentinel\dashboard.html`，釘成書籤。

4. agent 接入方式見 `docs/agent-integration.md`。

## 資料檔與保留策略

| 檔案 | 內容 | 上限 |
|---|---|---|
| status.md / status.json | 當前狀態，每輪覆寫 | 不成長 |
| history.json | 每 repo 峰值統計，最近 20 筆 | ~100 KB |
| samples.csv | 舊版 CPU/RAM/GPU 60 秒樣本 | 7 天滾動 |
| events.log | 磁碟異動事件 | 2 MB 自動修剪 |
| sentinel.db | reservation、queue、execution、tasks/jobs/events、sessions、workspace claims、resource samples | samples 30 天；ledger 依營運政策清理 |

## 中樞調控（v0.13）

觀測之上，兩層主動調控，仍然零常駐、零自動殺：

1. **原子 reservation（Claude Code + wrapper）**：PreToolUse hook 攔截重量級指令；
   Codex、Cursor 與其他沒有正式 hook 的 agent 透過 `invoke-sentinel.ps1` 執行重活。
   （build、安裝、全套測試，pattern 在 config.json 可調）。
   SQLite `BEGIN IMMEDIATE` 同時核算 CPU、RAM、Commit 與 heavy-I/O slot；priority
   採 P0–P3。橘燈起硬擋新重活、紅燈全擋。被擋的 session
   會收到訊息自己改做輕量步驟稍後重試。槽位預設帶 120 分鐘 TTL，
   佔槽進程死亡或 TTL 到期會歸檔並自動釋放。
2. **OS 優先權降級（管所有 agent）**：橘/紅燈時採集器把所有 agent
   進程樹降到 BelowNormal，綠燈自動恢復。不管 agent 聽不聽話都有效，
   桌面與遠端連線永遠搶得到 CPU。恢復採自癒式：凡 agent 樹內
   BelowNormal 的進程在綠燈一律升回，名單遺失也不會卡死在低優先權。

## Heterogeneous worker maintainer 與 orchestrator

匯入目前的人工 probe（保留量測時間；未明列期限時採七天 probe TTL）：

```powershell
py scripts\maintainerctl.py worker-import --workers config\workers.bootstrap.json
```

依記憶體與 capability 選擇一台 worker 並原子預約：

```powershell
py scripts\maintainerctl.py route --task '{"id":"issue-123","ram_gib":8,"cpu_units":2,"execution_preference":"CLOUD_PREFERRED"}'
```

完成後釋放：

```powershell
py scripts\maintainerctl.py release --task-id issue-123
```

這是 placement reservation，不是 shared-memory clustering；單一 execution 必須完整
fit 一台 worker。`capacity_scope=SHARED_POOL`（本機、Grok shared computer）會把同 pool
的 reservation 加總；`PER_EXECUTION`（Cursor、Claude、Codex、ChatGPT Work、GitHub）
不加總不同 job 的 RAM，但受保守的 `max_concurrency` 限制。

提交可恢復的 task，並執行一次有界 reconciliation：

```powershell
py scripts\orchestratorctl.py submit --task `
  '{"id":"issue-123","prompt":"Implement the requested change","repo":"C:/src/app","base_sha":"0123456789abcdef0123456789abcdef01234567","path_scopes":["src"],"requirements":{"ram_gib":4},"verification":{"command":"py -m pytest"}}'
py scripts\orchestratorctl.py tick --limit 2
py scripts\orchestratorctl.py show --task-id issue-123
```

本機 `local` 是 bootstrap 唯一設為 ready/enabled 的自動 adapter。其他 cloud worker 的
量測是人工 probe，不等於已有可靠 API；預設 `adapter=manual`、`adapter_ready=false`、
`enabled=false`，不會假裝自動送單。若保留人工流程，task 會標記 `AWAITING_MANUAL`，
完成後用 `complete-manual` 明確回報結果。只有驗證過完整 submit/status/cancel/result
lifecycle 後才應開啟 provider adapter，秘密只可透過環境變數注入。

本機 child 預設只繼承啟動所需的最小環境；秘密用 `metadata.env_refs` 顯式映射。
`inherit_all_env=true` 是可信本機工作的明確 opt-in，不能用在不可信 repo。若 provider submit
期間中斷且結果不明，普通 `retry` 會拒絕；先用 `resolve-dispatch` 附上 external job id，或
明確 `--confirmed-not-submitted`，避免重複副作用。

本機被選中時仍須通過既有 `invoke-sentinel.ps1` 的即時 Commit/RAM admission。agent
session 是提出／追蹤工作的控制端，execution worker 才是實際執行環境，兩者不混成同一
個資源池。

`collect.ps1` 每分鐘以 `sync-local` 更新本機 worker。GREEN/YELLOW 可參與 routing；
ORANGE/RED 會標成 `CAPACITY_FULL`。除了 allocatable reservation，router 也檢查
當下 free RAM 扣除 interactive headroom，避免只看安裝的 64 GB。

雲端 worker 通常是 provider 按 job 建立並回收的 container／runner，不是永久電腦。
不要依賴上一次 job 的檔案、登入狀態、IP 或背景程序；輸入應可重建，輸出應回收到
patch、commit、log 或 artifact，再做本機驗證。

完整資料模型、task lifecycle、capacity scope、workspace claim 與安全邊界見
[`docs/architecture.md`](docs/architecture.md)。

## 設計原則

- 零常駐：排程腳本跑完就退，猝死一次下一分鐘自動復原
- 不任意殺 agent：只對自己提交的 job 做取消／timeout；系統壓力靠 admission 與 OS
  priority 控制，不掃蕩其他工作
- 開放介面：簡單 agent 可讀 status 檔；需要原子協調時走 SQLite-backed CLI，不依賴 MCP
- 監控失效可偵測：狀態檔帶時間戳，超過 5 分鐘讀取端自動視為失效

設計文件：`docs/superpowers/specs/2026-08-12-resource-sentinel-design.md`
