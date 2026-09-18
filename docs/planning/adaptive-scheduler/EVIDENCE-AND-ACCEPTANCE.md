# 程式現況、設計缺口與驗收契約

## 證據邊界

此文件是 2026-09-19 的 read-only 原始碼調查；未跑 workload benchmark 或新 controller canary。
本輪只新增規劃文件與來源快照，不改 runtime、不切换 live collector、不改 OS 記憶體設定。
先前測試成果不是新控制器驗證，本包不以舊測試的成功替代此次設計所需的驗證。

本機設定 allowlist 當次讀到：`local_allocatable_ram_gib=58`、
`local_physical_headroom_gib=4`、`local_commit_headroom_gib=4`、
`collection_interval_sec=30`、`ram_orange_pct=85`。
這些是本機現況，非跨機器預設。完整 live config、DB、logs、prompt、provider output 不隨包發布。

manifest 每筆 SHA-256 對應來源原始 bytes；`.txt` snapshot 保留原檔內容，不做格式化。
manifest 的 captured_at 指擷取時間，不代表 runtime health 或已部署版本驗證。

## 入口與需要讀的程式

下表路徑相對 repo；選定檔案副本見 `source-snapshot/`。以函式/符號定位，避免依賴漂移行號。

| 入口 | 已觀察到的現況 | Pro 必須決策的影響 |
| --- | --- | --- |
| `scripts/collect-scheduled.ps1` | 分鐘 runner、:00/:30 slots、mutex、子採集 45 秒 timeout | 不能每秒重啟此 runner；fast helper 是否獨立及誰監督 |
| `scripts/collect.ps1` / `$treeOf`, `Get-ProcCpuPct` | 程序樹歸屬、跨輪 counters、五分鐘 CPU 指標、working set/private counters | 原程序樹不是 task identity；fast counter 單位/時間窗需重新定義 |
| `scripts/collect.ps1` / `apply_process_priority_policy` | resource-v2 CPU/IO 各自判斷；遍歷已辨識 agent 程序 | 新 controller 與既有 priority writer 的移交及 fallback |
| `scripts/collect.ps1` / `ram_guard...` | 85% RAM、300 MiB working-set 候選、同 PID 600 秒冷卻、EmptyWorkingSet | 不可把 target_mb 當釋放量；是否另案收窄 trim |
| `scripts/invoke-sentinel.ps1` / `Get-AgentIdentity` | 找 app 祖先 owner，隨機 tool_use_id，wait 後直接 cmd，finally release | app/session/task 區分、子程序啟動 containment、wrapper UX |
| `sentinel/coordinator.py` / `ResourceRequest`, `admit` | request key/spec hash、SQLite BEGIN IMMEDIATE、hook handoff、FIFO/priority | 新 task ID 如何銜接去重，不能新增第二套衝突 reservation |
| `sentinel/coordinator.py` / `pending_*`, `_routed_local_pending` | reservation grace、與 routed local worker 共用容量 | 限速後 measured 降低的 admission feedback；TTL/renew/child exit |
| `sentinel/coordinator.py` / `_default_pid_identity`, `_cleanup_locked` | admission 清理會查 owner identity | fast loop 不能在 DB transaction 裡繼承無界 OS 查詢 |
| `sentinel/pressure.py` / `describe`, `blockers` | 分資源壓力、恢復 streak、未知值、安全餘裕檢查 | 快採集 freshness 與慢報表 freshness 分開，既有介面兼容 |
| `sentinel/exemptions.py` / `grant`, `resolve` | 最多三租約；原子 grant；同 root identity 不續期；collector 可傳 snapshot | 豁免與 actuation 的同步、過期/撤銷生效、無資料時行為 |
| `scripts/exemption-policy.ps1` | mutation 前查 PID/start/expiry；還原優先權 | 僅快照不足以證明沒有新 grant；避免 restore 蓋掉其他 writer |
| `scripts/sentinelctl.py` | wrapper/collector CLI 入口及 wait/release/exemption | 新 IPC/CLI 能力怎麼嵌入、錯誤如何傳遞 |
| `scripts/collector-health.ps1`, `scripts/bounded-query.ps1` | collector health/recovery 與外部查詢 timeout | 快慢 health 必須分開，既有 recovery 不等於 Job cap recovery |

### 需要保留的工程經驗

既有 collector 曾卡在 psutil 讀程序 creation time，已改為重用 CIM snapshot 解析豁免，
並對查詢加 timeout。新設計不能為了更即時重新引入每秒無界全機查詢。
原本健康驗證包含 sample、publication、dashboard、completion 四個訊號；新 helper
還需要獨立 sample/decision/applied/recovery 證據，不能拿 collector 健康替代。

### 現有測試入口

`tests/test_coordinator.py`、`tests/test_pressure.py`、`tests/test_exemptions.py`、
`tests/test_exemption_policy.ps1`、`tests/test_collector_recovery.ps1` 均提供文字快照。
它們讓 planner 理解既有契約，並不代表已覆蓋新功能。請在 plan 指出保留/新增哪些測試，
哪些 Windows 行為必須用真實 subprocess/job canary，不能只 mock API。

## 必須裁決的設計問題

| ID | 要有具體答案，不能只写原則 |
| --- | --- |
| D01 | 首版控制獨立命令、整個 session 還是兩者？公平計帳主體如何和 actuator 主體分開？ |
| D02 | Python helper、native helper 或其他方式？為何足以符合 CPU/記憶體/啟動/分發限制？ |
| D03 | IPC、registration、版本、ACL、唯一 writer、fencing 及狀態 schema 的具體選擇 |
| D04 | 子程序 spawn/assign/resume 與取消協議；unsupported containment 的降級語義 |
| D05 | weight 或 rate？CPU 分母、最小額度、基準值、誰可調優先級、何時不調 |
| D06 | fast stale 的秒級標準、snapshot 一致性與 sleep/resume 的 reset；不可沿用 5 分鐘作秒級保護 |
| D07 | pending、measured、committed demand 與 allocated 的計帳公式；兩 DB/worker 互動 |
| D08 | CPU/IO/trim 舊 writer 的轉移；啟用/停用 mode、startup/crash rollback 狀態機 |
| D09 | controller fault 時限制如何有界撤回，誰持有必要身分及 job handle/名稱 |
| D10 | exemption grant/revoke/expiry 與即將執行的限速如何排序；lease 的時間語義 |
| D11 | 非納管/外部壓力、沒有 foreground mapping、缺進度資料時如何決策 |
| D12 | 能力探測、A/B、監控成本的具體 pass/fail；哪些結果應否決此路線 |

## 資料契約至少要涵蓋的概念

這是檢查清單，不強制 schema 命名：

- 穩定 task ID、accounting principal、app/session reference、root PID/start identity、job identity。
- 優先級/role 的來源；desired control、實際 applied control、API error/capability evidence。
- sample sequence、monotonic 時間與 wall-clock 記錄、freshness、counter reset、coverage。
- total machine use、per-job use、pending reservations、原始准入需求、原始與當前控制額度。
- controller epoch/lease、owner、original setting、last-applied setting、reason、恢復狀態。
- exemptions reference/version；這與最多三個使用者豁免 lease 的種類、名額及授權分開。
- metrics/事件需有 retention、寫入頻率與成本上限；不保存私人內容作控制輸入。

## 驗收矩陣：Pro 要補數字與方法

下列是必備案例；數值欄位交由 Pro 提議並標為待校準。不得填寫虛構的通過結果。

| 類型 | 案例 | 必須證明 |
| --- | --- | --- |
| 純演算法 | 短尖峰、長壓力、相鄰閾值抖動 | 不誤減量、不振盪、減量和恢復有界 |
| 資料 | stale/missing/NaN、counter reset、clock jump、sleep/resume | 不擴額、不沿用失效 PID、狀態可解釋 |
| 帳本 | 同時准入、hook/wrapper 重試、巢狀 wrapper、長任務、child orphan | 無雙重預約、漏算或借低實測超額放行 |
| Windows | wrapper 新 job + CPU-bound child + sibling control | 只有目標工作受控，child 歸屬正確，UI/sibling 不變 |
| Windows | nested job、權限不足、RDP/DFSS 不支援或未知 | 正確回報能力與 fallback，不能假裝 applied |
| 故障 | 強制結束 helper/失去 IPC/DB busy | 工作不被誤殺，已有限速在有界時間內由證據充分的路徑撤回 |
| 身分 | PID reuse、job 名稱衝突、owner 消失 | 不把舊控制套到新程序，不接管其他工具的 job |
| 豁免 | grant 在決策與 mutation 之間、revoke/expiry、第 4 租約 | 保留授權語義；第四租約仍拒絕；失效 controller 不續期 |
| 還原 | 外部程式改 priority/cap | 不無條件覆蓋別人的新值 |
| 記憶體 | RAM 高但低 paging、Commit 高、持續 paging | 不以低 CPU 替代 RAM 釋放、不把 soft faults 當 swap |
| 排程 | 大工作後面持續來小工作、同主體拆成多 task | 等待可解釋；若不保證 starvation-free 明確揭露 |
| 效果 | 相同 foreground proxy + background work 的開/關 A/B | latency/throughput/completion/queue/failure/overhead 的實測取捨 |

### 成功門檻的寫法

Pro 應提出可測的候選門檻，例如「偵測到持續 CPU 壓力後 applied latency 的 p95 上限」、
「每 1/10/50 jobs 時 helper CPU 與 RSS 上限」、「恢復故障的最長時間」、
「前景 proxy 改善的最低幅度與背景完成時間可接受退化」。不能只寫『低開銷』或『更流暢』。
測量需交代 CPU 百分比分母、負載、試驗次數、warmup、基線與 confounders。
不要要求把機器壓到 OOM 作驗收；壓力案例用有界合成工作与可重播 trace。

## 首版階段門檻（候選，請 Pro 修訂）

1. Planning：回答 D01–D12，未知項目有有界 spike；不改 live 設定。
2. Capability：獨立短命 canary 驗證 API/containment/還原，不接管現有 agent root。
3. Shadow：真實資料產生決策但不執行，量 overhead、false positives、coverage。
4. CPU canary：單個新 wrapper 工作，具備 crash recovery 與 rollback 證據。
5. Limited rollout：少量真實命令與使用者工作，達成 A/B 指標再擴大。
6. 後續：DRF/aging、合作式 worker resize、需求學習，各自有獨立價值與驗收。

任何階段失敗都保留工作與證據、退回已驗證路徑；關閉 feature flag 本身不足以
解除正在生效的 Job cap。恢復動作完成才算 rollback 完成。

## 交回 Codex 前的完成定義

計畫可在不重新發明整套架構的情況下開始第一個小步驟；每階段有明確輸入、輸出、
測試和失敗處置。所有尚未證明的 API/效能假設都標示，無『所有 agent 已覆蓋』之類過度承諾。
使用者再交回 plan 後才進入實作；本包沒有授權立即啟用方案。
