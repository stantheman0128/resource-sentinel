# Resource Sentinel：Commit 容量、工作估計與可靠接續建議

日期：2026-09-20（Asia/Taipei）  
性質：側邊討論交給主 session 的研究與決策材料。不是部署指令，也不是取代正式 IMPLEMENTATION-PLAN.md 的新規格。

## 1. 給主 session 的摘要

使用者希望減少「RAM 尚有空間，工作卻因 Commit 被擋」、「小任務被粗估為重工作」及「被擋後 agent 沒有自行接續」三種問題。

建議分別處理：

1. **容量緩衝：**評估將目前實際約 19.66 GiB 的分頁檔提高到約 32 GiB，使當時約 83.30 GiB 的 Commit 上限增加到約 95.64 GiB。這是候選，先核對最新狀態、尖峰與 dump 需求，再提出具體設定；不可因本文件直接修改日常 Windows 設定。
2. **估計準確度：**將 physical RAM 與 Commit 需求分開，從「命令粗分類」進到「實際操作、輸入範圍、工具版本與歷史實測」。未知工作保守處理，已知小工作不應永遠套 HEAVY 的 8 GiB 預設。
3. **執行可靠度：**保留單一准入權威，讓等待、啟動、結果保存與接收確認由執行層負責。不能只回覆 agent「稍後重試」，也不能把命令執行完成等同原 agent session 已恢復。

不建議另建一池可超賣的「虛擬 Commit」。排隊需求可以超過目前容量，但不是已承諾的啟動權；所有真正保留的容量仍由同一帳本原子核准。

## 2. 已核實事實與證據邊界

以下均是本次查詢時的歷史樣本，主 session 行動前必須重新讀取。沒有修改分頁檔、config、Scheduled Task、全域入口，也沒有取消、重跑或限速現有工作。

### 2.1 Windows 直接查詢：2026-09-20 07:52

透過 Win32_ComputerSystem、Win32_OperatingSystem、Win32_PerfFormattedData_PerfOS_Memory、Win32_PageFileUsage、Win32_PageFileSetting、固定磁碟資訊及 Memory Management／CrashControl registry 只讀查詢：

| 項目 | 結果 |
|---|---:|
| 系統可用實體 RAM 總量 | 63.64 GiB |
| RAM 可用 | 14.93 GiB |
| Commit 已用／上限 | 78.23／83.30 GiB |
| Commit 剩餘 | 5.07 GiB |
| AutomaticManagedPagefile | true |
| 分頁檔 | `C:\pagefile.sys` |
| 分頁檔已配置 | 20,136 MiB，約 19.66 GiB |
| 分頁檔實際使用 | 1,595 MiB，約 1.56 GiB |
| 系統回報的分頁檔使用峰值 | 4,264 MiB，約 4.16 GiB |
| C: 可用空間 | 179.69 GiB |
| CrashDumpEnabled | 7：Automatic memory dump |
| DedicatedDumpFile | 未設定 |

解讀：Commit 承諾額度偏緊，但實際分頁檔用量不高。分頁檔使用峰值不是 Commit 峰值；不能把兩者混用。單次樣本也不能證明自動增長失效、記憶體洩漏，或某個程序是根因。

### 2.2 排隊與等待：2026-09-20 約 07:58–08:04

從 sentinel.db 以 SQLite read-only 連線查詢，當時只有一筆 queue、沒有 active reservation。queue.json 只作顯示參考，不作權威。

- 工作：t3code-grok-parity 的 Windows x64 NSIS 產物建置。
- 明確申請：CPU 3 units、RamGiB 4、I/O 1 slot；不是 HEAVY 預設 8 GiB。
- 約 07:58 的純 blocker 計算：Commit required=4.0 GiB、available=1.36 GiB；當時是 Commit 阻擋。
- wrapper 與等待程序仍在，owner 建立時間與帳本相符，queue 心跳持續更新。
- 這筆 wrapper 明確設定 TimeoutSec=7200；不要拿預設 1800 秒解釋這筆工作的實際期限。
- 已失聯、已取消或沒有啟動 waiter 的 session，不一定出現在當前 queue；一筆現存 queue 不能反證使用者遇到其他 session 停住。

### 2.3 日常 source 的具體缺口

本次讀取的是 live source；implementation worktree 有較新的 adaptive 元件，不能因此宣稱 daily runtime 已部署。

| 位置 | 核對結果 |
|---|---|
| sentinel/coordinator.py：CLASS_DEFAULTS | MEDIUM 預設 CPU=2、RAM=4 GiB；HEAVY 預設 CPU=4、RAM=8 GiB |
| sentinel/pressure.py：blockers | 同一個 request.ram_gib 同時用於 physical 與 Commit 准入 |
| sentinel/command_classification.py | 已區分 executable／verb，不因 git show 或 ls 的 Gradle 路徑而升 HEAVY；動態／未知語法保守分類 |
| scripts/sentinelctl.py：wait | 自動重試，睡眠間隔最多 5 秒；未取得准入而離開等待時嘗試取消 exact request |
| scripts/invoke-sentinel.ps1 | 等待成功後執行原命令；預設等待 1800 秒，呼叫者可指定 |
| scripts/wait-slot.ps1 | 預設等待 480 秒；取得名額後提示 agent 重跑原命令，自己不執行原命令 |
| executions 表 | 保存申請值、起訖與結果；ram_gib 不是本工作實測峰值 |
| resource_samples 表 | 有整機與 agent 群組快照；未建立歸屬證據時，不能直接作每項 execution 的成本標籤 |

實際分類探查（只呼叫分類函式，未執行命令）：

| 命令示例 | 結果 |
|---|---|
| git show HEAD:app/build.gradle.kts | LIGHT |
| ls ~/.gradle/jdks | LIGHT |
| py -c "print(1)" | HEAVY |
| py -m unittest tests.test_one | HEAVY |
| pytest tests/test_one.py::test_one | MEDIUM |
| npm run typecheck | MEDIUM |
| gradlew.bat assembleDebug | HEAVY |

另一個方向的風險：rg、Get-Content 等常見 LIGHT 工具，若輸入巨大或掃描範圍失控也可能很重。因此不能只擴充 executable allowlist。

當時主機有 12 logical processors，local_allocatable_cpu=8。CPU 3 units 是約三個邏輯處理器滿載的需求估計，不是實際 CPU cap。08:03 的 CPU 5 分鐘平均 35.9% 相當於約 4.31 units；未扣其他預約時餘裕約 3.69 units。這只說明該樣本可容納 3 units，不證明工作瞬間不會超用。

打包腳本包含可執行 build:desktop、再 electron-builder 的流程，也有 skip-build 選項／環境設定。不能把所有「打包」都當純壓縮；本次未建立該 execution 實測峰值，不能斷定 4 GiB 必需或過大。

## 3. Commit／分頁檔候選調整

### 3.1 建議目標

以 07:52 的 Commit 用量固定不變為計算假設：

| 分頁檔實際配置 | 預期 Commit 上限約 | 比目前增加磁碟配置 | Commit 剩餘約 | 扣 4 GiB Commit reserve 後約 |
|---|---:|---:|---:|---:|
| 目前 19.66 GiB | 83.30 GiB | — | 5.07 GiB | 1.07 GiB |
| **候選一：32 GiB** | **95.64 GiB** | **12.34 GiB** | **17.41 GiB** | **13.41 GiB** |
| 候選二：40 GiB | 103.64 GiB | 20.34 GiB | 25.41 GiB | 21.41 GiB |

優先評估候選一，不為了壓低百分比直接拉到候選二。以上最後一欄還未扣未反映到 telemetry 的預約，且必須獨立通過 RAM／CPU／I/O 等條件；不是每個 agent 可領取的額度。

Windows 的實際 Commit limit 為準。只提高 maximum pagefile size，不代表分頁檔當下已增長，也不代表立即取得表中的 headroom。

### 3.2 實施前要做的具體工作

1. 重讀最新 current／peak Commit、實際 pagefile allocation、磁碟空間與 crash dump 設定；沒有峰值資料就標示缺口，不用 pagefile usage peak 代替。
2. 目前是系統自動管理。若選擇手動提高初始配置，需一併明確提出 initial／maximum、disk、是否需重啟、dump 相容性和回復方案。32 GiB 對應 32,768 MiB；本文件沒有決定 maximum，也未授權改成固定上限 32 GiB。
3. 提出可審閱的設定差異，再由主 session 依既有授權邊界取得所需的 runtime 變更授權。不得自動重啟使用者電腦。
4. 變更後用 OS counter 驗證實際 Commit limit，再驗證 Sentinel 新樣本反映新值；不能用設定寫入成功代替生效。
5. 重新計算同一排隊需求的 blockers。若其他條件仍不足，保持等待；不保證所有舊 session 自動恢復。

增加分頁檔不改变 58 GiB physical budget，也不消除記憶體洩漏。不得由 Sentinel 為追求准入成功不停增長 pagefile。

## 4. 精細分類與歷史估計

### 4.1 分類單位與特徵

管理單位是一次明確 execution／tool call；session 只作歸屬與結果接續。長存 agent baseline 和工具 burst 分開觀察，共享 UI／daemon 代執行部分不可假裝是 wrapper 的私有子樹。

| 工作族群 | 應辨識的差異 |
|---|---|
| 小型查詢 | 已知工具、限定檔案、輸出／輸入上界 |
| 搜尋／掃描 | 指定目錄、整個 repo、整顆磁碟；檔案量與大小 |
| 測試 | 單一 case／module／全套；worker 數；fixtures／外部服務 |
| 建置 | 增量／乾淨重建、debug／release、目標平台與平行度 |
| 封裝 | 既有產物／重建後封裝、資料規模、壓縮設定 |
| MCP／常駐工具 | 冷啟動、閒置、執行請求、正常關閉 |

工具族群不是容量承諾。單一測試可能建立大型 fixture；python -c 可執行任意操作。未知語法不可一律降級，分析器本身也要有輸入、時間與 I/O 上界。

### 4.2 每項工作要記什麼

- execution ID、可讀 session 名稱、程序建立身分、工具／版本／參數類型、輸入規模、冷／熱模式。
- requested physical、requested Commit、CPU units、I/O 分開保存；另外保存估計來源、模型／規則版本與可信程度。
- 實測 private physical、private Commit、CPU time、短窗口與持續 CPU、讀寫量、執行耗時；queue wait 另外記錄。
- 說明覆蓋範圍、採樣時間／間隔、漏樣、資料品質。沒有安全可歸屬的數字就保持 unknown；不能加總共享 Working Set 冒充精確占用。
- 完成、失敗、取消、user stop、失聯、recovery hold 分開記。失敗且提早退出的樣本不能當作成功完整工作的低成本證據。
- 不在公共資料或 Git 裡保存 raw command、環境值、工作輸出、credentials；採用必要的類別與脫敏指紋。資料保留與聚合成本有界。

### 4.3 如何用歷史

先讓估計器只觀察、不影響准入。依相同工具／版本／範圍比對實測，再對有足夠證據的類別開放細分估計。記錄低估率、誤擋率、預測區間覆蓋率、等待時間、監控成本；不能只看平均誤差。

初期使用可解釋的規則與保守歷史統計，不必先導入大型模型。少量樣本不足以保證 P95/P99；版本或輸入分布改變時退回保守估計。entropy 最多反映分類不確定性，不能直接換算 GiB 或取得准入。

歷史估計用於未來請求；不得因正在執行的工作 CPU 降低、正在等雲端、被限速或 RAM 換出，就降低其 active demand floor。也不得為了通過 gate 靜默降低使用者明確申報的需求。

## 5. 可靠等待與 agent 接續

### 5.1 不再依赖「請記得稍後重試」

保留同一 request／execution ID，讓執行層保有等待責任；容量變動或定時核對後再進原子准入與一次性 launch claim。event 是喚醒提示，不是容量授權；收到 event 仍需重新核對。

必要狀態至少能分辨：

- 現在不足，但可等待。
- 請求本身超過主機／政策能力，等待也不會解決。
- 監測或身分不明。
- 等待者活著、可自動繼續。
- 等待者失聯／session 無接續介面，需要明確處理。
- 已執行但回覆遺失，需 reconciliation，不能猜測未啟動後重跑。

對完成事件可考慮同一權威 DB 中的 durable outbox、event ID、接收確認與去重。這只能支撐可靠結果交付，不能憑空提供第三方 agent 的 resume API。不同 agent adapter 必須明示可用的背景工具／通知／接續能力。

### 5.2 小工作與公平性

已知、範圍有界的 LIGHT 操作依正式政策繼續；總體 RED／RESTRICTED 不是全面禁止小工作的理由。需准入的小工作使用有證據的需求估計，不靠改標籤繞過 reserve。

檢查是否發生隊首阻塞；有條件允許符合全部資源維度的工作先執行時，也要設 aging／等待時間保障，避免大工作被無限插隊。這是排程政策變更，需要測試，不在本文件暗中改既有優先級。

取消僅影響 exact queued request；執行後的 stop、恢復、資源釋放是不同契約。owner／root 死亡、TTL 過期、關閉 handle 都不能直接代表 children 已結束。

## 6. 六個外部專案：可借用與不可照搬

本次由三個 subagent 分頭閱讀，主 agent 統整並獨立核對重要發現。固定版本如下；沒有安裝、編譯、benchmark 或執行控制。Process Lasso 僅公開文件，無法審核專有核心；Ray 查閱的是相關路徑，不宣稱審閱整個巨型倉庫。

| 專案 | 查閱版本 | 借用 | 不採用／需改寫 |
|---|---|---|---|
| AgentCgroup | 551ca1689b7d2d30db6b8a8613414750103cc68b | per-tool identity、peak／duration、資源回饋 | Linux kernel／eBPF；wrapper 納管失敗仍跑；exit 137 直接稱 OOM；未確認 descendants 完成 |
| Pueue | 193ed2264338bd30a06e347b48183a8800bd178b | durable task metadata、結果取回、依賴、callback 介面 | restore 將 Running／Paused 標 Killed，不是接管原 execution；callback 無 durable ack；suspend／kill |
| Process Governor | 41f49007c24bdfbfd1f63b58f94e86ce3b45b9f7 | Job APIs、JOB_LIST、SafeHandle、具名 Job／IOCP | suspended launch、silent breakaway、PID-only 入口；缺少本案完整 restore-before-release 協定 |
| Ray | 4252b0cfcade02a15eecbf86dd9edab5452193db | 多資源原子分配、feasible vs available、不同等待原因 | 邏輯資源不是 OS 限制；OOM kill／重試；Linux RAM／swap 不等於 Windows Commit |
| Soflutionltd/McpHub | 10a9146a18ef6e9ea1a7d53e4044d0286c5479fc | cached schema、discover／execute 介面 | 重複 spawn、timeout 後未確認工作完成即可能回收、通用快取／重送；source 不完整疑慮 |
| Process Lasso | 2026-09-20 官方文件 | foreground awareness、暫時干預、原值與操作紀錄、GUI／actuator 分離 | 疊加 priority／affinity／trim；hard-throttling；無法核實內部 crash recovery |

重要補充：

- **AgentCgroup** 是研究原型。memory hint 是固定映射，不是學習模型；小樣本分類結果不能外推成準確率保證。memcg BPF 路徑有額外核心能力／patch 前提。借測量方法，不移植其 fail-open 行為。
- **Pueue** 的隊列保存不是 exactly-once 執行，也不是故障後接管。不要引入第二個獨立 capacity authority。
- **Process Governor** 的部分 Job 預設允許 silent breakaway；不是本案要求的全子樹覆蓋。IOCP 事件可作提示，但未核對 kernel 狀態不能完成釋放。不要把這個 GitHub 專案和 Process Lasso 同名的 Governor 元件混為一談。
- **Ray** 可借資源向量，但 CPU 邏輯額度不等於 CPU cap。研究當日 master 與 release 文件的 OOM 細節有差異，不能混成同一版本；無論選幾個 victim，都不適用本案禁止 workload kill 的政策。
- **McpHub**：主 agent 獨立確認 main.rs 宣告 auth module，但該 pinned tree 沒有對應檔案；proxy.rs 呼叫 cache::is_cache_valid，但完整 cache.rs 無此函式；SSE integration test 有 placeholder。這是靜態不一致，沒有執行 build，不能寫成已重現編譯失敗。降為概念參考，不建議直接部署該版本。
- MCP 的 schema discovery／cold start 也會啟動程序，不能省略其准入。需 per-server 單次啟動協調、session／workspace／auth 隔離、明確 inflight 與使用者引用。timeout 不等於服務端已停止；mutation 不可通用快取或盲目重送。
- Process Lasso 的 ProBalance 是 priority 調整；CPU Limiter 是 affinity 調整；SmartTrim 是 working-set／cache 處理。三者都不是 Commit 准入。

## 7. 與正式計畫的整合與範圍

主 session 應先閱讀最新正式 IMPLEMENTATION-PLAN.md，並核對自己的工作樹與待提交修改。本文件不要求重新 checkout 歷史版本，不覆蓋任何 dirty source，也不要求恢復已暫停的工作。

### 原計畫已有、應落實而非另造架構

- 一次 execution 的 lifecycle、exact identity、claim、children／restore reconciliation。
- CPU／physical／Commit 分開的共同 projection，避免已測量占用與預約重複或漏算。
- 58 GiB 整機預算、4 GiB physical／Commit reserves、最多三個明確使用者豁免。
- guardian 唯一正常 actuator、先排除舊 writer，max 10 Jobs／max 1 cap。
- off／admission-only fallback；P0–P6 按證據 gate 前進。

### 值得另列受控變更提案

- 日常 wrapper／request 的 physical 與 Commit 獨立欄位及相容遷移。避免先改一個入口造成另一入口漏帳。
- 歷史 telemetry 與估計器的 shadow 評估；它不能成為拖延既有 lifecycle 完工的新大型前置專案。
- 可靠結果交付與各 agent 接續 adapter。若要新增常駐 executor 或第三方 daemon，屬原 MVP 以外的架構變更，先寫出所有權、故障模型與成本，不默認加進 P3。
- 分頁檔調整是 Windows runtime 變更，獨立於 source commit／push，不因主 session 採納文件就自動部署。

不擴充 GPU、DRF、AIMD、工具 worker resize，也不自動 kill／RAM hard cap／週期 Suspend-Resume。CPU 退讓只處理 CPU contention，不能拿來宣稱釋放 Commit。

## 8. 建議的可審閱工作包與驗收

| 工作包 | 最小交付 | 驗收重點 |
|---|---|---|
| A：Commit 設定提案 | 最新 measurements＋具體 Windows 設定差異＋rollback | 未獲授權前無 runtime 變更；生效後 OS limit 與 Sentinel 樣本一致；RAM budget 不變 |
| B：獨立需求欄位 | physical／Commit request、相容規則、所有本機入口共同計帳 | 兩維度各自阻擋；不能因 pagefile 增大放寬 RAM；並發不可 double spend |
| C：分類與量測 | 有界工具分類、實測 attribution、估計 provenance | 小型查詢不因路徑誤判；真 build／動態未知不被輕放；共享頁不重複算；失敗樣本不冒充完整峰值 |
| D：可靠等待／交付 | stable request、原子 launch、結果留存、確認／去重 | 等待者失聯可見；不能假裝自動喚醒；crash／lost ACK 不重跑副作用；user Stop 不被重試覆蓋 |
| E：估計器 shadow | 與真實峰值比對的報表 | 低估率、誤擋率、等待時間、長工作公平性與監控成本均有證據；不以單次省 RAM 宣稱成功 |

先完成主線已有的 lifecycle／共用計帳責任，再把新建議接到同一入口。每包可以獨立審閱，不要求先整套更換為 Ray／Pueue／MCP proxy。所有測試沿正式 policy 准入，涉及控制的實驗只能使用隔離測試程序與資料；不對現有使用者工作做故障注入。

## 9. 可直接給主 session 的交接文字

> 請閱讀 docs/work/resource-admission-and-commit-recommendations-20260920.md，對照最新正式 IMPLEMENTATION-PLAN.md 與你目前的實作，提出最小整合差異。優先核對分頁檔約 32 GiB／Commit 上限約 96 GiB 候選、physical／Commit 分開計帳、小任務的精細估計，以及排隊後能否真正接續。分清楚原計畫已有事項、需新增驗收的事項與 runtime 變更；不要重寫一份泛泛 roadmap。Windows 設定、部署及 production adaptive control 未因這份文件獲得新增授權。不要引入第二套容量帳本、放寬 58/4/4/3，或以 kill／hard cap／盲目重試換取成功。引用文中的歷史數字前先重新查詢。

## 10. 主要參考來源與閱讀覆蓋

- Windows：[分頁檔與 Commit](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file)、[容量與 crash dump 需求](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows)、[自動增長過慢](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/slow-page-file-growth-memory-allocation-errors)。
- AgentCgroup：[wrapper](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/agentcg/bash_wrapper.sh)、[daemon](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/agentcg/agentcgroupd.py)、[memory abstraction](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/agentcg/memcg_controller.py)、[CPU scheduler](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/agentcg/scheduler/scx_flatcg.bpf.c)、[論文](https://arxiv.org/html/2602.09345v1)。另讀 README、memory BPF／patch 前提與研究限制。
- Pueue：[state restore](https://github.com/Nukesor/pueue/blob/193ed2264338bd30a06e347b48183a8800bd178b/pueue/src/daemon/internal_state/state.rs)、[spawn](https://github.com/Nukesor/pueue/blob/193ed2264338bd30a06e347b48183a8800bd178b/pueue/src/daemon/process_handler/spawn.rs)、[finish](https://github.com/Nukesor/pueue/blob/193ed2264338bd30a06e347b48183a8800bd178b/pueue/src/daemon/process_handler/finish.rs)、[Windows](https://github.com/Nukesor/pueue/blob/193ed2264338bd30a06e347b48183a8800bd178b/pueue/src/process_helper/windows.rs)。另讀 README、PID、kill、callback 與 restore tests。
- Process Governor：[Job API](https://github.com/lowleveldesign/process-governor/blob/41f49007c24bdfbfd1f63b58f94e86ce3b45b9f7/procgov-lib/Win32JobModule.cs)、[launch](https://github.com/lowleveldesign/process-governor/blob/41f49007c24bdfbfd1f63b58f94e86ce3b45b9f7/procgov-lib/Win32ProcessModule.cs)、[instance lifecycle](https://github.com/lowleveldesign/process-governor/blob/41f49007c24bdfbfd1f63b58f94e86ce3b45b9f7/procgov-lib/ProcessGovernorInstance.cs)。另讀 monitor、CLI 路徑與 LICENSE。
- Ray：[資源文件](https://docs.ray.io/en/latest/ray-core/scheduling/resources.html)、[OOM](https://docs.ray.io/en/latest/ray-core/scheduling/ray-oom-prevention.html)、[local resource manager](https://github.com/ray-project/ray/blob/4252b0cfcade02a15eecbf86dd9edab5452193db/src/ray/raylet/scheduling/local_resource_manager.cc)、[local lease manager](https://github.com/ray-project/ray/blob/4252b0cfcade02a15eecbf86dd9edab5452193db/src/ray/raylet/scheduling/local_lease_manager.cc)。另讀 cluster scheduling／lease、memory monitor factory／policy／accounting 及 Linux isolation 文件；release 文件與 master 分開解讀。
- McpHub：[child lifecycle](https://github.com/Soflutionltd/McpHub/blob/10a9146a18ef6e9ea1a7d53e4044d0286c5479fc/src/child.rs)、[proxy](https://github.com/Soflutionltd/McpHub/blob/10a9146a18ef6e9ea1a7d53e4044d0286c5479fc/src/proxy.rs)、[cache](https://github.com/Soflutionltd/McpHub/blob/10a9146a18ef6e9ea1a7d53e4044d0286c5479fc/src/cache.rs)、[SSE](https://github.com/Soflutionltd/McpHub/blob/10a9146a18ef6e9ea1a7d53e4044d0286c5479fc/src/sse.rs)。另讀 config、main、release workflow、integration tests，並核對 pinned recursive tree。
- Process Lasso：[架構](https://bitsum.com/apps/process-lasso/docs/getting-started/how-it-works/)、[ProBalance](https://bitsum.com/apps/process-lasso/docs/algorithms/probalance/)、[CPU Limiter](https://bitsum.com/apps/process-lasso/docs/algorithms/cpu-limiter/)、[SmartTrim](https://bitsum.com/apps/process-lasso/docs/algorithms/smarttrim/)、[Hard-Throttling](https://bitsum.com/apps/process-lasso/docs/algorithms/hard-throttling/)、[logging](https://bitsum.com/apps/process-lasso/docs/interface/logging/)。另讀 startup／Keep Running 文件；沒有審核 proprietary source 或採信未重現的效能保證。

來源授權概況：AgentCgroup GPL-2.0；Ray Apache-2.0（含第三方 notices）；Pueue MIT／Apache-2.0；Process Governor 與此 McpHub 為 MIT；Process Lasso 為專有產品。本文建議先借設計，不直接複製未審核的程式碼。
