# Resource Sentinel — Adaptive Scheduler Implementation Plan

**版本：1.0／規劃定稿，尚未實作或通過 Windows 驗收**  
**日期：2026-09-19（Asia/Taipei）**  
**交付對象：Codex implementation session**  
**建議入庫位置：`docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md`**

> 本文件選擇方案、定義契約及驗收門檻，不是已存在功能的說明。所有新增檔案、函式、CLI、schema 與數值門檻，除非標示「現況」，都是待實作規格。這一輪沒有修改 repository、runtime、Scheduled Task 或使用者機器，沒有執行 Windows canary，也沒有把文字快照安裝成程式。

## 0. 證據基準與執行前提

### 0.1 固定本次閱讀的版本

| 項目 | 基準 |
|---|---|
| Repository | `stantheman0128/resource-sentinel` |
| 規劃分支 | `codex/adaptive-scheduler-planning` |
| 本次固定 commit | `3ab1945885da0ef1b21d856329d7d8f7e2daf79f` |
| 交接記錄的原 committed baseline | `0b2f37819a2d4f68299fbec3fe619a4d05ba4749` |
| 快照時間 | `2026-09-19T02:35:53.9362590+08:00` |
| 執行基準 | **Codex 接手時的 live working tree**；必須先與快照比對，不能 checkout 舊根目錄覆蓋 dirty files |

已讀交接提示、README、SELF-GRILL、EVIDENCE-AND-ACCEPTANCE、snapshot manifest 與原提案。程式審查以 `source-snapshot/` 的 wrapper、Coordinator、pressure、exemptions、CLI、collector 相關控制／發布路徑及所附測試為主；另外讀取 pinned root 的 `maintainer.py` 相關路由／計帳段落與 `hooks/sentinel-gate.py`。沒有聲稱審查整個 repository、所有 local adapters 或使用者未公開的 runtime。[R1–R9]

**發現的交接缺口：**快照 `tests/test_pressure.py::test_local_worker_uses_same_commit_guard` 要求 Maintainer 消費 `admission_snapshot`／`admission_config`；但 manifest 沒有 dirty `sentinel/maintainer.py`，本次讀到的 pinned root 路由段落不能證明 live tree 已具備該整合。這是 **P0 的 baseline reconciliation gate**，不是可以用猜測補齊的細節。尚未重新計算 manifest 的本機檔案 SHA-256，也沒有重跑其測試。[R4,R8]

本文的事實與推論用以下方式區分：`現況` 指快照或已讀程式；`官方語意` 指文末官方 API 文件；`設計裁決` 是這份 plan 的選擇；`待驗證` 指 Windows 或真實工作負載尚須取得證據。所有 pass/fail 數字均為**建議起始驗收門檻，不是已量測成績或最佳參數**。

### 0.2 不得改動的政策

1. **58 GiB 是整台機器的准入使用預算**，不是每個 agent 的額度，也不是給受控 Job 的 RAM hard limit。對非豁免工作，同時保留 physical 4 GiB 與 Commit 4 GiB headroom。
2. 最多 **3 個原子化、未撤銷且未到期的豁免租約**。使用者明確授權的豁免仍計帳；不得因緊急負載、自動偵測或控制租約到期而撤銷、忽略或限速已豁免工作。保留既有豁免對 load/order gates 的 bypass 語意。[R7]
3. 不自動 kill 工作、不週期性 Suspend/Resume 工作、不設定 Job RAM hard cap、不強迫第三方程式回收記憶體。不把關閉 handle、清除記帳或改 UI 狀態當成解除 OS 限制。
4. 不把共享 app UI、雲端推理、WSL／Docker daemon 代執行的工作、未註冊工作假裝成可精準控制的 command Job。
5. 不覆蓋未提交修改，不修改交接快照，不公開 prompt、命令輸出、完整 command line、環境變數或 credentials。
6. Missing、stale、clock discontinuity 與 unknown 都不是可用容量。此系統不是 OOM prevention 的硬保證。

---

## 1. Hostile review：先否決不成立的部分

### 1.1 原提案不能直接進 implementation

原提案有合理方向：把慢報表與控制分離、辨識獨立命令、採取非致命手段。但它把「調度演算法」放在「工作身分、啟動原子性、唯一 writer、記帳與恢復」之前。**在這些基礎未成立時，DRF 或 AIMD 只會把錯誤更頻繁地執行。**[R2,R3]

| 問題／嚴重性 | 原提案或 SELF-GRILL 尚未解決的地方 | 裁決與可驗收替代 |
|---|---|---|
| H01／阻擋 | 以 RAM 下降、CPU 圖較低或 API 成功當作改善。CPU cap 可能延長工作持有 RAM 的時間。G01/G10/G21 只是承認問題。 | 驗收同時量桌面 latency、工作完成時間、throughput、queue wait、Commit/physical headroom 與監控成本；不能只看 RAM。§11 |
| H02／阻擋 | G04 認為應註冊 task，但現有 `Get-AgentIdentity` 仍找 app 祖先；同 app 多工具可能共用 owner。 | task/execution、session、app identity 分離；獨立 wrapper host 與 root process 使用完整 creation FILETIME。app 僅顯示歸屬。§4 |
| H03／阻擋 | G05 的 suspended→assign→resume 仍留下 launcher 在 assign 前崩潰、子程序永久 suspended 的縫隙。 | 優先驗證 `PROC_THREAD_ATTRIBUTE_JOB_LIST` 在 `CreateProcessW` 時納管；首版不採 post-spawn assignment，也不採未證明恢復的 suspended fallback。§4.3、S1 |
| H04／阻擋 | G06/G07 正確指出不可離開 Job，卻未指定誰保有 handle、如何關閉 cap、誰防止舊 writer 復活。 | guardian 唯一正常 actuator、具名 Job、先寫 recovery intent、控制短租約、wrapper restore-only fallback、OS mutex 與舊程序死亡確認。fencing number 本身不能 fence Windows API。§3、§8 |
| H05／阻擋 | 現有 collector 會改 priority、呼叫 `NtSetInformationProcess` 調 I/O、`EmptyWorkingSet`。G08 未給交接 barrier。 | 新 Job 建立前登記 exclusion；舊 writer 在每次 mutation 重新檢查 scope/epoch；未知則跳過，不與 cap 疊加。§3.3 |
| H06／阻擋 | G09 只說重新驗證豁免，仍可能「驗證後 grant、grant 後 Set」。 | 所有 grant/revoke 與新 actuator 共用 policy mutex；grant 的持久化和 OS restore acknowledgement 分開表達；子樹豁免會移除整個所在 Job 的 cap。§7.5 |
| H07／阻擋 | G12 的警告還不是帳本公式。現有 pending CPU/RAM 超過 grace 後不再計入；限速讓 measured 降低，再准入會產生錯誤回饋。 | 保留 active demand floor，不因 cap 或 age 下降；common projection 供 direct/local route 共用；首版有 cap 時再加一道非豁免新啟動 barrier。§7 |
| H08／阻擋 | G13 未處理 owner/app 存活與命令/子程序存活不同；目前 wrapper 沒有 running heartbeat。 | wrapper root exit 不等於 Job empty；guardian 接續 lease/accounting；TTL 到期變 `UNCERTAIN_HOLD`，不能直接釋放。§4.5 |
| H09／高 | 「CPU weight 降到 80%」不是有定義的效能目標；Windows weight 是相對值，nested cap denominator 也可能是 parent quota。 | 不用 weight；只測一個明確 whole-machine denominator 的 CPU hard-cap actuator。它限制 CPU 時間，不承諾效能比例。§6、§8 |
| H10／高 | G02/G03 不能用「1 秒」取代成本及最壞反應路徑。collector 內還有 CIM、GPU、SQLite、報表與外部程式。 | 常駐 cached handles、bounded work；sample/decision/apply 各自 timestamp；slow collector 不參與 fast loop。§5.5 |
| H11／高 | G16 承認 DRF 前提不合，卻未處理不可回收 RAM、瞬態需求、拆 task 與大工作餓死。 | 首版不實作 DRF；容量按 execution 唯一計帳、principal 聚合；保留 feasible priority/FIFO，明示沒有 starvation/sybil-proof 保證。§7.7 |
| H12／高 | G18 的 compare-and-restore 方向正確，但 legacy `demoted` 只有 PID；失去 map 後升回 Normal 仍會覆蓋使用者設定。 | 首版不新增 priority mutation。對新 scope 不沿用「任何 BelowNormal 都升 Normal」；無身份／原值證據就不猜。§3.3、§8.4 |
| H13／高 | G20 的「unknown 不要全開、不要全鎖」過於含糊。 | 新 admission fail closed；已執行工作繼續；限制 lease 到期時 restore；恢復不代表重新承認容量，必須等 fresh accounting。§6.4 |
| H14／高 | G22 的提醒不等於完整交接：測試與未附的 dirty Maintainer 可能不配套。 | P0 比對與隔離 baseline 測試；只取得舊 root 時停止 promotion，不覆寫補齊。§10 |
| H15／高 | `SetInformationJobObject` 成功不等於 cap 在真實 parent Job／RDP session 生效。 | 能力測試必須量 CPU consumption；unsupported/foreign nesting/DFSS 走明確 admission-only，而非靜默成功。§8、S1/S3 |
| H16／高 | 既有 scheduler runner 可對 collector subtree 執行 `taskkill /T /F`；把 guardian 或 command launcher 放入該 subtree 會破壞「不殺工作」前提。 | 新 guardian/helper 由獨立 supervisor task 啟動；不得由 bounded collector subprocess 啟動。local adapter 是否會被既有 kill tree 波及列入 S2；不推論它已安全。§3.2 |

H16 的依據是 `collect-scheduled.ps1` 的 45 秒 timeout 與 `collect.ps1` 尾段的 orchestrator tick；本文件沒有確認所有 adapter 的實際父子程序安排，因此將它列為需驗證的風險，而非斷言現有工作一定遭終止。[R5,R6]

### 1.2 對 SELF-GRILL 的總判斷

SELF-GRILL 是有效的問題清單，但多數答案是「應該如何」而不是可執行協議。G04–G09、G12–G14、G18–G20 必須被本文件的身份、交易、lease、writer 與復原規則取代，不能在 PR 說明裡用「SELF-GRILL 已回答」當作驗收。

G11 的風險辨識不足以校準 CPU cap；G16 也不能憑 DRF 原論文就宣稱這個 Windows 工具公平。原論文研究多資源公平分配；TCP AIMD 的 congestion/ACK 模型亦不是本系統的 CPU/Commit plant model。這裡**不移植其保證**，亦不聲稱本方案有穩定性證明。[W12,W13]

---

## 2. 架構裁決：只交付可以撤回的 CPU 小範圍實驗

### 2.1 三方案比較

以下是工程判斷，不是 benchmark 排名。

| 維度 | A：強化 admission／registration／priority，無常駐控制器 | B：bounded fast helper＋slow collector＋wrapper Jobs | C：先做工具合作式 concurrency／batch 調整 |
|---|---|---|---|
| 首要收益 | 防止超額啟動、改善記帳；不能快速處理已在跑的 CPU burst | 可對已確認的本機背景命令短時間退讓 CPU | 工具真的合作時，能降低下一批並行與記憶體需求 |
| 覆蓋 | 所有整合 admission 的呼叫者；priority 不保證資源份額 | 只有新 wrapper command、支援環境與已知 Job coverage | 限支援安全 resize/drain 的個別工具 |
| 監控成本 | 最低 | 固定兩個輕量常駐 process，加 bounded per-job 成本；須量測 | runtime 成本低至中；每個工具多一套 adapter |
| 實作／恢復 | 最簡單；但活躍工作的 owner/TTL 仍要修 | 最複雜；只有具體 guardian/restore 協議才可接受 | 工具相依，部分 shrink 會取消 worker，不能假稱非致命 |
| 關鍵缺陷 | 可能已足夠；也可能對桌面卡頓沒有明顯幫助 | CPU hard cap 自己可能帶來 jitter，控制成本可能大於收益 | build/test/install 並非都能執行中安全調節，不能普遍套用 |
| 裁決 | **作為第一個可獨立交付成果與正式 fallback** | **選為受 gate 限制的最小 adaptive 方案** | 延後，沒有通用 resize adapter 進 MVP |

**選 B，但縮成 B-min：**可靠 task lifecycle／共用記帳先交付；CPU adaptive 只有在 capability、恢復、成本及 A/B 四關都過後才能啟用。B 的 gate 失敗時，交付 A 的已驗收改善，不為了完成「adaptive」標籤而降低安全標準。

最強反方論點：相對於 admission-only，兩個 resident process、Job launch 與恢復協議的工程成本很高，而使用者卡頓可能主要來自磁碟或 Commit。**若 baseline 顯示 CPU 不是主要瓶頸，或 A/B 不勝過 A，就不啟用 B。**這是方案的淘汰條件，不是後續無限調參的理由。

### 2.2 MVP 明確範圍

- 全域 `adaptive.mode` 預設 `off`。其後可依序 promotion 到 `shadow`、`canary`、`limited`，沒有自動跳級。
- 僅 wrapper 新建的、明確 `role=background` 且 P2/P3 的獨立命令可被限速。P0/P1、`protected`、`neutral`、共享 app UI、豁免或身份不明者不選為 victim。
- 初始 enrollment 上限 **10 個 Job**、同時 active cap **1 個 Job**；50 Job 僅作 scaling 壓力測試，不是首版支援承諾。
- 唯一新增的執行中 OS actuator 是 **Job CPU rate HARD_CAP**。不新增 CPU weight、priority、I/O priority、memory trim、GPU quota、affinity 或 process suspension。
- RAM／Commit／disk 空間／I/O pressure 使用准入與警示。它們不能透過 CPU cap 被當作已解決。
- 不自動推斷「使用者正在操作哪一個 app」，不讀鍵鼠、不根據 exe 名猜 task 意義。不承諾通用進度偵測。
- 延後：weighted DRF、AIMD、需求預測、跨 cloud provider resize、個別工具 worker resize、work stealing、大型公平排程器、GPU／VM 精準治理。

### 2.3 最終控制優先序

`驗證身份／能力 → 使用者豁免 → recovery/restore → telemetry 有效性 → resource safety → explicit role/priority → CPU policy`。

豁免不是更高的 CPU priority，也不是 OS 權限。priority 只是是否可成為 victim 的 metadata；不得藉 P0/P1 繞過一般准入。有效豁免才保留既有 bypass。CPU cap 不得和新 priority demotion 疊加；舊 writer 對新管理 scope 必須停止寫入。

---

## 3. 架構、程序生命週期與唯一 writer

### 3.1 只新增必要的控制角色

```text
existing hooks / local router / invoke-sentinel.ps1
                      │ metadata + exact execution/reservation identity
                      ▼
            Coordinator + common accounting
              sentinel.db（唯一容量帳本）
                      │ approved launch / claim token
                      ▼
       wrapper host ──CreateProcessW(JOB_LIST)── command Job
        │ standard I/O、root exit                     │
        │ backup Job handle                          │ CPU/membership counters
        └──────────────┐                             ▼
                       │                 fast helper（read + pure policy）
                       │                             │ fresh decision + lease
                       ▼                             ▼
                 guardian/watchdog（唯一正常 Job cap writer）
                 named handles + recovery intents + restore
                       ▲
               independent supervisor task
              restart / restore-only；不執行工作命令

existing slow collector：30s 報表／disk／dashboard，非 fast control source
exemptions.sqlite3：唯一豁免 authority，與 sentinel.db 不假設跨 DB 原子性
```

| 角色 | 生命週期／責任 | 可以寫入什麼 | 明確不能做什麼 |
|---|---|---|---|
| slow collector | 原本 bounded single-shot，目標 30s cadence | 原有 status/report；受 mutation gate 約束的 legacy 範圍 | 不能啟動 fast loop、guardian 或精準 cap；不能把 30s snapshot 冒充 fresh fast sample |
| fast helper | 每個受支援 logon session 一個 resident process | 記憶體內 fast frames、policy decisions、低頻彙整 | 不呼叫 SetInformationJobObject；不拿正常 SET_ATTRIBUTES handle；不改豁免 |
| guardian/watchdog | 每 session 一個 resident process，留在所有 managed Jobs 之外 | 新建本工具的 named Jobs、cap set/verify/restore、lifecycle heartbeat、recovery manifest | 不接受任意外部 PID/job name 的限速請求；不持有工作 stdout；不 kill workload |
| wrapper host | 一個 command execution 一個 host；薄 PS wrapper 呼叫 Python host | 啟動、exact registration、傳遞 std handles、回傳 root exit code | 不執行一般 policy；只在 guardian 已死亡／被安全隔離後允許 restore-only |
| Coordinator | 既有 CLI/library，短交易 | queue/reservation、execution 關聯、claim/finalization、共同 projection | 不在 SQLite transaction 裡做 psutil/CIM/IPC 等可能阻塞的查詢；不把 TTL 當作 process death |
| supervisor | 獨立 Scheduled Task 的短檢查／重啟路徑 | 只重啟本工具 helper/guardian，先 restore 後接受新 policy | 不重啟工作命令、不用 `taskkill /T`、不靠程序名稱廣泛殺 python/powershell |

採用既有 Python 環境與 `ctypes` 封裝 Win32；不在首版另外引入 Rust/C++ service、driver 或第三個常駐資料庫。若 ABI、安全 launch 或監控成本 gate 不通過，退回 A；不自動擴張成原生重寫專案。

**兩個常駐 process 是為分離失效域，不是兩個 policy engine。**guardian 不計算另一套資源最佳化策略，只執行驗證、期限與還原。helper 卡住，guardian 仍可撤除 cap；wrapper 對自己的 Job 保留最後的 restore-only handle。

### 3.2 程序安排、排他與 fencing

- guardian/helper 由獨立、同一使用者、同一 logon session 的 supervisor 啟動，預設非 elevated；不得位於 command Job 或 collector 的 bounded kill subtree 中。
- instance mutex、policy mutex、每個 Job 的 mutate mutex，名稱含工具固定前綴、logon identifier 與隨機 instance/execution ID。Named Pipe、Job、mutex 使用明確 logon SID ACL，不依賴寬鬆預設 ACL。[W9]
- 正常模式只有 guardian 呼叫 cap Set API。helper/query clients 只有 query 所需權利；wrapper 保有 restore 權利，但其程式路徑只允許恢復本 Job 的原始 cap 設定。
- `guardian_epoch`、`policy_epoch`、`decision_seq` 防止舊訊息重播；**它們不是 kernel fencing**。接管 OS writer 還必須取得相同 mutate mutex，並確認舊 guardian 的持有 process handle 已 signaled。
- guardian 失聯但 process 仍活著：不能僅因 TTL 過期就讓第二個 writer 同時 Set。先要求 graceful restore；仍失聯時，supervisor 僅可終止**已驗證 PID + creation time + role + version 的本工具 guardian process 本身**，不含 `/T`，等待死亡後才接管。這不授權終止任何 workload 或 app。
- 同時重啟的 helper/wrapper/supervisor 以 instance mutex 合併成一個 restore-only recovery owner。新的正常 policy 必須等全部已知 cap reconcile 完成後才啟用。
- 無法驗證舊 owner、無法取得必要權限或 OS 無法排程 recovery 時，不宣稱 bounded recovery 已成立；標為 `RESTORE_UNVERIFIED`，停止新 enrollment／非豁免准入並提示具體失敗 Job。

**支援邊界：**首版限一個經能力測試的互動 Windows logon session、x64 Python／Windows、單 processor group 且最多 64 logical processors。多使用者／多 session 並行控制不是 MVP。其他 session 的消耗仍在全機 measured usage 中，不能被漏算。

### 3.3 舊 throttle/trim 與新 Job 的交接

現況 collector 的 `apply_process_priority_policy` 是 stage，而不是獨立函式；還有 RAM guard stage、`Set-IoPriority` 及 exemption restore。不得只在一處加 `if adaptive_enabled` 就當作交接完成。[R5]

**新增 `legacy mutation gate` 的規格：**

1. guardian 在建立／公開 Job 之前，在 `sentinel.db` 和 recovery manifest 註冊 scope；此操作與 collector mutation 共用 policy mutex。
2. collector 每批 mutation 取得 policy mutex，讀取當前 registry epoch；對候選 process 以持有的 process handle 驗證 creation time，再檢查是否屬於本工具的 managed Job 或已註冊的 wrapper/guardian/helper infrastructure identity。
3. 屬於新 scope 就跳過所有 priority、I/O priority、trim 與 legacy self-healing restore，包括 exemption restore 中無記錄便升 Normal 的分支。
4. registry、identity 或 Job membership 無法確定時，**該次不寫入**。registry 整體不可讀時，當次 legacy mutations 全部停止，但報表繼續。不得用一份過期 bare-PID exclusion list 硬做。
5. 單批 mutation lock 工作預算 250 ms；不得在鎖內等待 3 秒外部查詢。需要資料時先取得 bounded snapshot，再在短 critical section 重驗 epoch；超預算跳過剩餘 mutation。
6. 新 Job 的原始 CPU cap 必須是 disabled。命令的原始 process priority 不由本方案重設；可繼承原 launcher 值，但須記錄為 baseline metadata，A/B 保持相同。**不推定 BelowNormal 一定是 Sentinel 造成。**
7. 前一代 `demoted` PID-only 記錄不能移植成可靠 restore 證據。已在跑的舊工作不轉成 managed Job；保留原治理範圍，不 retroactively adopt。
8. rollback 先關閉並驗證新 cap；仍存活的 Job 繼續保留 exclusion，直到 Job empty 才還給舊 writer。不能為了回退，讓舊 collector 立刻對未退出的新 Job 疊加 throttle/trim。

這是 mutation **ownership handoff**，不是新 cap 和舊 priority 的優先競爭。未納管舊程序的治理不是本輪重寫目標；但任何新入口不得繞過既有有效豁免。

---

## 4. 任務身分、註冊、啟動與結束協議

### 4.1 身分模型

| 名稱 | 定義／不可混淆的邊界 |
|---|---|
| `app_identity` | 顯示用 app PID＋birth identity；不作精準 control scope |
| `session_id` | 上游穩定會話 ID；缺少時以有效 owner identity 建立 local session，不猜同名 exe 是同一 session |
| `principal_id` | 排隊／彙總群組，來自已註冊 session；缺少可靠來源時歸入同 logon 的 shared `unattributed` 群組，不讓每個隨機 task 自帶新份額 |
| `task_id` | 上游邏輯工作；允許多次明確 execution attempt |
| `execution_id` | 每次真正執行唯一 UUID；相同 command 並行執行必須不同 ID |
| `reservation_id` | 現有 direct 或 routed reservation 的精確 ID；一個 execution 只能有一個容量 source |
| `wrapper_identity` | command 專用 host PID＋GetProcessTimes creation FILETIME＋logon；不等於 app owner |
| `root_identity` | 首個 command process 的相同完整 identity |
| `job_name` | guardian 為 execution 建立的隨機具名 Job；不由 command 任意指定 |
| `parent_execution_id` | 只用於已證明在 parent managed Job 裡的 nested wrapper／subspan |

原生 creation FILETIME 在 JSON 以十進位字串表示，避免 JavaScript 53-bit 整數精度損失。舊 float epoch 僅供 compatibility；新增 OS mutation 禁止以 ±2 秒或 PID-only 判定同一 process。取得 handle 後驗證 birth，再使用**同一 handle**執行 query／membership 檢查，避免 PID 重用的 TOCTOU。

### 4.2 Task lifecycle state machine

```text
NEW → QUEUED → RESERVED → PREPARED → LAUNCHING → RUNNING → DRAINING → FINISHED
         │        │           │          │          │          │
         └────────┴───────────┴──→ CANCELLED_BEFORE_START        │
                               └→ START_FAILED                  │
                               └→ START_UNKNOWN ────────────────┤
                                                      UNCERTAIN_HOLD
                                                              │
                                                  RECONCILE → RUNNING / DRAINING / FINISHED
```

| Transition | 執行條件／持久化要求 |
|---|---|
| `NEW→QUEUED` | validate exact immutable spec、role、resources、caller identity；新 raw command 不進持久帳本 |
| `QUEUED→RESERVED` | 同一 SQLite 短交易完成共用 projection + queue 判定 + reservation；回傳 exact ID/claim token |
| `RESERVED→PREPARED` | guardian 已建立 empty named Job、持有 handle、原始 cap disabled、durable recovery manifest 已成功；legacy exclusion 已生效 |
| `PREPARED→LAUNCHING` | 一次性的 launch claim CAS 成功；wrapper identity 與 guardian epoch 重驗；尚未執行 user code |
| `LAUNCHING→RUNNING` | CreateProcess 成功、root handle/birth 驗證、Job membership 確認；guardian ACK 註冊。短命令可能直接轉 terminal，但仍只能建立一次 |
| `RUNNING→DRAINING` | root exit，Job 仍有 active processes；保留 allocated demand、IO slots 與 guardian ownership |
| `RUNNING/DRAINING→FINISHED` | 正向確認 Job active-process count 為 0，wrapper launch 已封口，不可能再 assign 新 process；archive/release exactly once |
| 任一 launch 不明 | `START_UNKNOWN`，不自動 retry command、不釋放容量；檢查 named Job、host、root handle 與 launch nonce |
| owner 心跳遺失、DB/identity 不明 | `UNCERTAIN_HOLD`；繼續計帳但停止控制 tightening；positive evidence 才結束 |

`state_revision` 用 CAS 防止 PostToolUse、wrapper finally、guardian reconciliation 重複 finalization。OS handle 是生存／birth 證據，DB state 不是 OS 已完成的證據。

### 4.3 啟動前納管：首選 atomic Job-list creation

**S1 通過前不允許 active enrollment。**官方提供 `PROC_THREAD_ATTRIBUTE_JOB_LIST`：在 process creation 時指定 Job list，最低支援 Windows 10／Server 2016；這是本方案的首選，取代「先跑再 assign」。[W3]

實作順序：

1. wrapper 確認 invocation role、命令語意、resource spec 與 caller；向 Coordinator 預約。`LIGHT` 的歷史 bypass 不能讓明確 `managed` invocation 繞過 lifecycle/accounting；未使用新模式的 legacy LIGHT 保留相容行為，但明確列為 unmanaged coverage。
2. guardian `prepare_execution()` 在持久 manifest 記錄 immutable execution identity、Job name、baseline disabled、版本與 allocation floor，持有 Job handle；建立新 Job 若收到 `ERROR_ALREADY_EXISTS` 一律拒絕當作新 execution 使用，不能把碰撞名稱指向的既存 Job 當成自有空 Job；確認 `KILL_ON_JOB_CLOSE`、time limit、active-process limit、memory limit、UI restrictions、breakaway flags **都未由 Sentinel 設定**。
3. wrapper 打開／取得自己的同一 Job handle。guardian 和 wrapper 同時持有，工作不能繼承這個 handle。
4. wrapper 使用 `STARTUPINFOEX`、`EXTENDED_STARTUPINFO_PRESENT`、`PROC_THREAD_ATTRIBUTE_JOB_LIST`，另以 `HANDLE_LIST` 明確傳遞必要 stdin/stdout/stderr。**不使用 `CREATE_SUSPENDED`；不把 app PID 作 Job root；不修改 parent process 來逃離 sandbox。**
5. 以 `CreateProcessW` 啟動原有 `cmd.exe /d /s /c` 語意；`applicationName` 使用解析且驗證的 cmd.exe 路徑，command string 不經自創 split/rejoin。原始 launch payload 只存在 wrapper 記憶體／短命 CLI 傳遞；不得送進 telemetry、manifest 或 DB。薄 PS wrapper→本機 Python host 的首版傳輸明定為 UTF-8 JSON 編碼成單一 Base64 argument（`--launch-spec-b64`），不占用 workload stdin。Base64 不是加密，內容仍可能被同使用者的程序檢查工具讀取；不能把它記入 debug log。建立 host 前先檢查完整 Windows command-line 長度；過長回傳 `launch_payload_too_large` 且不啟動，不改引號或偷偷切換 shell。此路徑須通過 S2；未通過就不宣稱該 host 相容。
6. CreateProcess 返回 root process/thread handles 後，立即驗證 birth、membership、guardian epoch，登記 `RUNNING`。thread handle 正常關閉；process handle 留到 exit。
7. API error、unknown outcome、IPC ACK 丟失都不自動改走無 Job 的第二次啟動。只有能證明尚未開始 user code 的 prelaunch failure，才能回報 retryable；由上游明確重新發起新的 attempt。

**不支援處置：**在 CreateProcess **之前**區分兩種能力失敗：Job-list／handle／console 隔離不成立，回傳 `managed_unavailable`；Job containment 成立但 CPU rate 因 DFSS 等因素不成立，可保留 `job_contained, control_eligible=false` 的 lifecycle-only 路徑，不宣稱能限速。新的 managed invocation 預設不自動改走無 Job 路徑；只有明確 `--allow-admission-only` 才能在確認尚未執行 user code 的情況選擇原 admission-only 入口，`--require-managed` 與該選項互斥。此相容 fallback 仍共帳，但標示 `coverage=unmanaged, lifecycle_evidence=limited`，不享有 Job empty 的精確證明；有子程序生存疑慮就保留 `UNCERTAIN_HOLD`，不能套用 managed 的 FINISHED/release 判準。未使用新 managed 選項的 legacy wrapper 維持原相容入口；不宣稱本次已解決其所有 lifecycle 限制。不得用 `CREATE_BREAKAWAY_FROM_JOB` 繞過外部政策。降級不是錯誤後默默再跑一次。

首版只對沒有 foreign parent Job，或已證明是同一 Sentinel parent execution 的情況納管。即使 OS 支援 nested Job，也不代表知道外層 CPU denominator；foreign nesting 的支援延後。

### 4.4 wrapper、hook、local route 的銜接

現況 `hooks/sentinel-gate.py::is_atomic_wrapper()` 已辨識直接 wrapper 呼叫並略過外層 reservation；保留這項 invariant，不再重複 reserve。[R9]

- **正常 wrapper 呼叫：**hook 不預約，wrapper 一次 reserve/launch。解析不明的複合命令不猜作 wrapper，也不由文字相似度自動領取其他 reservation。
- **已預約的 hook/waiter handoff：**新增顯式 `reservation_id + claim_token + spec_hash + caller identity` 介面。token 只用一次，同一 execution 的 retry 回傳同一狀態。v2 不採 `owner_pid + normalized command_signature + oldest row` 猜測領取。
- **舊 waiter 重跑原命令：**保留原 admission-only 路徑；不能自動升級成 managed。只有上游能帶 exact token 的整合才可切到新路徑。
- **local router：**`worker_reservations` 直接成為該 execution 的 allocation source，wrapper 用 `adopt_routed_reservation` 而非再呼叫 direct `admit`。兩者互斥，SQL 約束／交易測試保證只算一次。
- **local adapter 未完成 exact adoption 時：**仍用現有 execution engine，計入共同容量帳，但標 `coverage=unmanaged`，不享有 Job cap。不能為了 coverage 重寫 cloud adapters 或 workspace orchestration。
- PostToolUse / release by owner 只能結束 legacy rows；對已綁定 managed execution 的 row 必須經 `finalize_execution` 驗證 Job empty，避免 hook 成功事件提早釋放後代的 RAM／IO 預約。

### 4.5 nested wrapper、取消、退出與 orphan

**Nested wrapper：**由 guardian 驗證 child host 本身確實在已註冊 parent Job，不能只相信 `SENTINEL_EXECUTION_ID` 環境變數。child 只建立 subspan，不建立另一個 Job、不重複預約、不另算 CPU。parent 宣告的 resource envelope 必須覆蓋所有並行 child。要求大於 parent envelope 時回傳 `nested_budget_upgrade_required`，不讓 child 持有 parent allocation 再排隊等第二份容量。MVP 不實作 running parent 原子擴額；須由上游在 parent 啟動前合併估算。

**取消：**`TimeoutSec` 現況是 admission 等待期限，不是 execution deadline；保留此語意。`QUEUED/RESERVED/PREPARED` 可 exact-cancel；若 launch claim 已進入不可撤回邊界，就回傳 `cancel_pending_reconciliation`，不能假稱沒開始。running Ctrl+C 使用既有 console signal 行為，由工作自行處理；guardian 不呼叫 TerminateJobObject、taskkill 或遍歷 kill。記錄 cancel request 與 root outcome，不把「收到取消」當成 Job 已結束。

**root 退出但 children 存活：**wrapper 可回傳 root 的真實 exit code；guardian 保有 named Job handle、定期 Query Job active processes、保留 accounting。持續存活的 dev server 是 `DRAINING` 的合法結果，不因 TTL 而殺掉或釋放其資源。

**wrapper 被殺／崩潰：**guardian 以 Job membership 接管，不依 app owner 生存。正常 policy停止對失去可信生命周期證據的工作加嚴；已知本工具 cap 進 restore。工作本身繼續。

**Job 完成判斷：**completion port 只能作提示，不能作唯一事實來源。查詢 ActiveProcesses／process list，確定 launch terminal 且無後續 assign 可能，才 finalization；不把 job handle signaled 當成一般的「Job empty」事件。[W1]

**I/O／exit 相容驗收：**PS 5.1 與已安裝的 pwsh 分開測；包含 Unicode/空白路徑、內嵌雙引號、`& | > < ^ % !`、stdin、stdout/stderr 大量同時輸出、無輸出命令、exit 0/7/125、Ctrl+C、快速結束、parent 先走 child 延後結束。標準輸出只由 workload 使用，控制結果走 IPC；infra failure 的 wrapper code 可用 125，但需以 metadata 區分 child 自己返回 125。不要聲稱跨所有 PowerShell host 完全相容，未通過的 host 不啟用 managed mode。

---

## 5. 資料契約、採樣與成本邊界

### 5.1 契約共通規則

採用 `schema_version=1` 的新 adaptive namespace；不直接改掉既有 `resource_policy.version=2` 的意義。所有數值必須有限、單位明確、缺值使用 `null + validity/reason`，不以 0 代 unknown。CPU 與 bytes 欄位不得容許 NaN/Infinity/negative；JSON decoder 必須拒絕非標準 NaN/Infinity。

- 記憶體、Commit：內部整數 **bytes**；顯示 GiB = bytes / 2^30。既有 `ram_gib` 入界轉換一次，不將 GB、GiB 混用。
- CPU：`cpu_units=1` 代表一個 logical processor 持續忙碌的 CPU time，不是一個 physical core、priority、百分比或保證最低份額。
- cap：`cpu_rate_bp` 為 Windows 1/10000 rate；`disabled` 必須是獨立狀態，不以 rate=0 且 ENABLE 表達。
- `created_filetime_100ns`、clock ticks 在 JSON 用十進位字串；Python 用整數。外部顯示不回寫作身份判斷。
- `sample_seq` 每個 sampler epoch 嚴格增加；restart 換 epoch；重複／倒序 sample 不累計 streak，不延長控制租約。
- `config_revision` 是 allowlisted policy fields 的 hash，與私密設定分開。改 config 需通過驗證、增加 revision、清除舊 baseline；不能讓未知 config 觸發擴額。

### 5.2 Process、execution 與 scope 契約

以下只是資料範例，不是某個真實程序。

```json
{
  "schema_version": 1,
  "execution_id": "example-exec-a",
  "task_id": "example-task-a",
  "session_id": "example-session",
  "principal_id": "example-principal",
  "reservation": {"kind": "direct", "id": "example-reservation"},
  "parent_execution_id": null,
  "spec_hash": "example-immutable-spec-hash",
  "role": "background",
  "priority": "P2",
  "requested": {"cpu_units": 4.0, "physical_bytes": 8589934592, "commit_bytes": 8589934592, "io_slots": 1},
  "wrapper_identity": {"pid": 4100, "created_filetime_100ns": "134343072000000001", "logon_id": "example-logon"},
  "root_identity": {"pid": 4200, "created_filetime_100ns": "134343072010000002", "logon_id": "example-logon"},
  "job_name": "Local\\ResourceSentinel.Job.example-exec-a",
  "state": "RUNNING",
  "state_revision": 4,
  "coverage": "job_contained",
  "capability_id": "example-probe-result",
  "control_eligible": true
}
```

`spec_hash` 應包含 original command 的**本機 keyed hash**、canonical repo identifier、requested resources、role、parent execution 與 caller binding。新持久資料只保存 hash、allowlisted command family／使用者提供的 label；不要再把 regex-redacted command 當作隱私保證。原始 command、stdout/stderr、prompt、cwd 絕對路徑、env values 不進新的 action logs、registry exports 或回傳的公開報告。key 本機保管，不傳到 repo。

### 5.3 FastFrame

```json
{
  "schema_version": 1,
  "sampler_epoch": "example-sampler-epoch",
  "clock_epoch": "example-runtime-continuity",
  "sample_seq": 83,
  "window_start_tick_100ns": "812340000000",
  "window_end_tick_100ns": "812350000000",
  "published_tick_100ns": "812350180000",
  "sampled_at_utc": "2026-09-19T03:00:00Z",
  "config_revision": "example-policy-hash",
  "registry_revision": 17,
  "machine": {
    "logical_processors": 12,
    "processor_groups": 1,
    "cpu_busy_units": 10.9,
    "physical_total_bytes": 68719476736,
    "physical_available_bytes": 21474836480,
    "commit_used_bytes": 60129542144,
    "commit_limit_bytes": 103079215104
  },
  "jobs": [
    {
      "execution_id": "example-exec-a",
      "cpu_units": 6.0,
      "cpu_uncapped_high_water_units": 6.0,
      "private_working_set_bytes": 6442450944,
      "private_commit_bytes": 7516192768,
      "active_processes": 8,
      "membership_complete": true,
      "memory_validity": "valid",
      "counter_epoch": "example-job-counter-epoch"
    }
  ],
  "validity": "valid",
  "errors": [],
  "collection_cost_ms": 18.0,
  "collection_skew_ms": 22.0
}
```

frame 不含完整全機 process list；只含 enrolled execution 所需 aggregate。PID/birth 細節留在 ACL 保護的 internal registry。上述 12 LP 只是算例，實機必須 probe，不能沿用過去硬體記憶或固定寫 8/12/16。

**建議資料來源：**

| 指標 | Fast source／計算 | 不可混用 |
|---|---|---|
| 全機 CPU | `GetSystemTimes` 連續差分；kernel 包含 idle，busy = Δkernel + Δuser − Δidle；除以總時間，再乘 N | 不用 `cpu_5min_avg` 作 1s CPU；單 group 限制須 probe。[W6] |
| Job CPU | `QueryInformationJobObject` 的累積 user+kernel CPU time，除以實際 window 秒數；同一 Job 的已退出 process CPU 仍由 Job accounting 涵蓋 | 不將 parent/child Job 的 aggregate 再相加。[W1,W7] |
| Physical total/available、Commit | `GetPerformanceInfo`／經驗證相容的 Win32 memory API；page count 乘 PageSize | 不將 `sum(WorkingSet)` 當成全機 physical usage。[W10] |
| 可安全扣除的 task physical | 完整成員、同一窗口的 `PrivateWorkingSetSize` aggregate；功能可用時才使用 | shared WorkingSet 不可加總後從全機扣除；EX2 不支援則扣除量為 0。[W5] |
| task private Commit | `PrivateUsage` aggregate，完整 membership、相同窗口 | 不是 WorkingSet；不是 Job 設定的 memory limit。[W5] |
| disk space/queue/latency | 現有 slow collector 的 resource-v2 counters，各自 sampled timestamp | fast CPU 不代表 disk counters fresh；未知 disk 不新啟動需要該資訊的工作 |

**Freshness：**fast CPU/physical/Commit frame 的 `window_end` age ≤ 3s；正常 sample interval 目標 1s，可接受完整 CPU delta window 0.5–1.5s，超出即 reset streak/warmup。metadata publish time 不能掩蓋舊 measurement。涉及扣除的 job/machine measurement skew 目標 ≤100ms；超出或 membership 不完整時該 job 的 subtraction=0，不能使用舊 subtraction。

slow disk counters 的初始 admission freshness 上限為 `min(existing admission_status_stale_sec, 90s)`，獨立驗證 `sampled_at`；不假稱這能做到 disk 秒級控制。fast 模式不得在 helper stale 時自動降格使用 5 分鐘 CPU average 放行。所有新模式切換到 admission-only 的 fallback 都必須先完成 restore/reconcile，並明確標示 source 與 freshness policy。

### 5.4 clocks、reset 與錯誤

- fast durations、sample age、控制 lease、cooldown 使用 `QueryInterruptTimePrecise` 的同一系統 interrupt-time domain；它不跟隨使用者／NTP wall-clock 調整。QPC 可量函式成本，但不與其他 time domain 的 tick 直接相減。[W8]
- `clock_epoch` 是本工具的 runtime-continuity UUID，**不假裝是 OS 官方 boot UUID**。只在至少一個已驗證仍存活的 guardian/helper/wrapper witness 能證明 continuity 時沿用；cold restart 無 witness 就換 epoch、還原所有舊 cap、重做 warmup，不重播磁碟上的 monotonic lease。
- sleep/resume 或 sample gap >3s：清空所有 streak/baseline，restore 已知 cap，停止非豁免准入直到 fresh frames 與 accounting 完成。lease 不因睡眠被自動續期；無法證明 clock continuity 則舊租約直接失效。
- 豁免仍保留現有 `expires_at` UTC 與 idempotent、不延長 deadline 的語意；本 MVP **不另外重寫既有豁免的時間政策**。偵測 UTC 跳動時停用新的 restrictive action、fresh-read 豁免 DB；不得自行增加期限、重新 grant 或提前宣稱 revoke。解不出有效 scope 時移除自己 cap，不將此「不控制」冒稱為已核發的新豁免。
- counter reset、累積值下降、process/Job identity 改變、processor count/affinity domain 改變：該 delta invalid，換 counter epoch；至少收集兩個新 endpoint 才有 CPU delta，再重新滿足完整 warmup。

標準錯誤碼至少包含：

`identity_unavailable`、`identity_mismatch`、`membership_unknown`、`foreign_job_unsupported`、`job_list_unsupported`、`cpu_rate_unsupported`、`denominator_unknown`、`telemetry_stale`、`counter_reset`、`clock_discontinuity`、`exemption_unknown`、`exemption_restore_pending`、`registry_unavailable`、`db_busy`、`storage_unavailable`、`ipc_timeout`、`guardian_unavailable`、`launch_outcome_unknown`、`api_set_failed`、`api_readback_mismatch`、`external_control_conflict`、`restore_unverified`、`observer_budget_exceeded`、`launch_payload_too_large`、`revision_conflict`、`request_exceeds_host_budget`。

每個錯誤要附 `stage`、execution/action ID（若有）、重試分類、API error code（若有）；不能附 raw provider output 或 command。

### 5.5 IPC 與採集成本

本機 Named Pipe、明確 ACL、拒絕 remote clients。採 length-prefixed UTF-8 JSON，message 上限 256 KiB，protocol major 不符拒絕；caller PID／logon 以 OS 可驗證身份和一次性 token 綁定，不能只信 JSON 自報 PID。單一 client 不可建立無界排隊；全體 pending requests 上限 128，超過回 `busy`。[W9]

- `GetFastFrame` 讀 memory latest frame，response deadline 250ms；不喚起一次完整 collector。
- `PrepareExecution`、`ClaimLaunch`、`ReportRootExit`、`RequestRestore`、`QueryExecution`、`Reconcile`、`GrantExemption` 與 `RevokeExemption` 必須具 idempotency key。Grant/revoke 的呼叫者不得持鎖等待 RPC；見 §7.5。
- helper→guardian 的 control proposal 只含 execution、epoch、seq、fresh frame 引用與 typed actuator target；不接受任意 PID／任意 SetInformation class。
- idle 與正常 sampling 不每秒 spawn PowerShell/Python、不每秒做 CIM 全機枚舉、不每秒 fsync DB/log。不開 High/Realtime priority，不呼叫 timeBeginPeriod 追求 1ms timer。
- Job CPU sampling 每 1s；membership 至多每 2s query 一次並配合事件提示；每 tick 最多掃 256 個 managed process memory records，總 work budget 100ms。超額的 memory subtraction 退為 0；不得跳過全機 CPU／Commit 與 guardian lease 檢查。
- 快照保留最近 120 個 aggregate frames 在記憶體 ring；30s 彙整一次。`adaptive-status.json` 最快每5s發布一次供 UI，**admission 不以它代替 IPC fast frame**。
- allocation high-water 變更在記憶體即生效，批次至少每5s落帳；任何新 cap 生效前，該 Job 的 floor 必須已加入 durable recovery intent。DB write 失敗不忽略它：停止新 admission/tightening，恢復限制。
- lifecycle/first restrictive intent 必須先 durable；heartbeat 與純 telemetry 可 batched/best effort。禁止每秒更新每一個 Job 的 SQLite TTL。
- logs 採 bounded rotation：adaptive aggregate/events 總上限 20 MiB、保留7天，先刪最舊 telemetry；**未結束 execution 的 recovery manifests 不得為配額而刪除**。大量輸出只能走 workload stdio，不經 guardian log。

---

## 6. CPU 控制狀態機與偽碼

### 6.1 先設定非目標：不是 PID controller，也不是泛用 AIMD

採**最多兩階段的 bounded CPU retreat**，不用不斷乘 0.8，也不因 RAM/Commit 高就盲目降低 CPU。first version 只有一個 victim、一個 actuator、一個短 lease；控制精確與恢復證據優先於分配精緻度。

所有下表數值都是待校準起點。校準只在固定測試 trace/A/B 後改 config revision，不在 live 壓力中自動學習。

| 參數 | 起始值／語意 |
|---|---|
| sample interval | 1s，使用實際 delta time |
| fresh sample | age ≤3s；完整 window 0.5–1.5s |
| high CPU | 全機 busy ≥90%，連續3個不同且有效 sample |
| uncapped baseline `b` | victim 最近5個有效 uncapped sample 的 CPU units median |
| victim 最低實際負載 | `b ≥1.5 CPU units`，且占當時全機 busy CPU ≥10%；不以占 RAM 最大者替代 |
| retreat level 1 | cap target = `max(1.0, 0.75*b)` CPU units |
| retreat level 2 | 持續 high ≥10s 才可進入；target = `max(1.0, 0.50*b)` |
| 最低 cap ceiling | `max(1.0, 0.50*b)`；這是「不再更低的上限」，**不是 CPU minimum reservation／進度保證** |
| normal API change cooldown | 至少5s；restore、豁免、失效處理不受此延遲 |
| 正常恢復條件 | 全機 CPU <80%，連續10s fresh samples |
| 正常恢復步階 | level2→level1→`b`→disabled，每步至少5s；即使 `b` 已是原觀測值，最後也一定清掉 cap |
| 控制短 lease | 6s；fresh/helper decision 最多每1s續一次；舊 seq 不能續 |
| 單次 intervention 總上限 | 從 first applied cap 起60s，包含 tightening/recovery；到期直接 restore disabled |
| victim 冷卻 | 一次 intervention 後60s不再選同一 Job；每次離開 normal 都需新 baseline |
| fault/no-effect 退避 | restore，該 Job 暫停 eligibility 300s；能力失敗須重新 probe，不自動循環重試 |
| 全域範圍 | 最多10 enrolled Job、1個 active cap；scope unknown 則 active=0 |

**cap 換算：**對已確認 whole-machine denominator N，`cpu_rate_bp = ceil(10000 × target_cpu_units / N)`，限制在合法 1..10000。需要的 target ≥N 時不設定 cap。這個 ceiling 不等於程式效能比例，也不等於 reservation 宣告的 `cpu_units`。[W2]

例：僅作算例，N=12，背景 Job uncapped baseline b=6，level1 是4.5 units→3750 bp，level2 是3 units→2500 bp。原始 requested=4 不代表 baseline=4；先把 observed high-water 納入 accounting floor。恢復最終是**disabled**，不是把 cap 留在6 units。

### 6.2 controller state machine

```text
OFF → WARMUP → OBSERVING → PRESSURE_PENDING → CAPPED_L1 → CAPPED_L2
                  ▲               │              │             │
                  │               └──────────────┴──────→ RECOVERING
                  │                                            │
                  └────────────────── COOLDOWN ←──── VERIFIED_RESTORED

任何 restrictive state
  → EXEMPT_RESTORE / DEGRADED_RESTORE / CONTROLLER_LOSS_RESTORE
  → VERIFIED_RESTORED → WARMUP 或 OFF

restore 無法證明 → RESTORE_UNVERIFIED（不再 admission/tighten，不冒稱 OFF 已完成）
```

- **WARMUP：**helper/guardian/version/clock/capability/registry一致；cap inventory 已 reconcile；至少5個有效 uncapped samples。任何 invalid sample 都重置。
- **OBSERVING：**不改 OS；持續維護 demand floor 與 coverage。
- **PRESSURE_PENDING：**只計連續有效 samples，不能用同一個 slow snapshot累積3次。
- **CAPPED_L1/L2：**每次 renewal 都重驗 exemption、scope、identity、有效 frame與API readback。單一 victim不允許偷偷換人，先還原舊者才能選新者。
- **RECOVERING：**正常低壓以階梯恢復，但 absolute 60s intervention deadline優先；即使 CPU 又高也不得永久卡在恢復尾段。
- **EXEMPT_RESTORE：**grant 生效或 scope 可能涵蓋豁免，立即移除本工具 cap；不等5秒 cooldown，不降低 granted scope 的資源。
- **DEGRADED_RESTORE：**資料、DB、capability、clock、membership、storage、writer所有權不明；不新加限制，已有限制 bounded restore。
- **CONTROLLER_LOSS_RESTORE：**lease未被有效續期；guardian去掉 cap，不等待collector。

### 6.3 victim 選擇與 no-effect

先按 principal 彙總已知背景 CPU；再從最大 eligible principal 中選擇其中實際 CPU 最大、角色允許、capability已通過的 Job。不要把同一 app 的所有工作合併成一個 Job，也不要對 largest-RAM app 整棵樹限速。tie以最近被控制時間較早者、最後execution ID穩定排序。

以下情形不控制：主因是 memory/Commit/disk；多數負載來自unmanaged／exempt／protected；唯一eligible工作太小；CPU denominator未知；progress adapter報告critical section不可退讓；已有一個active cap。

`progress` 只有工具明確回報completed units／可比較checkpoint時才有意義；CPU time增加、stdout有字、process還活著都不是進度證明。MVP允許progress=unknown，但因此只能做有界intervention，不能宣稱避免starvation或保證完成。

`no-effect` 在受控 saturated canary 可由 CPU consumption 未受cap約束判斷；在真實I/O-bound工作不能以CPU低於cap判斷API壞了。真實情境若控制10s後system CPU未出現超過measurement noise的改變，不繼續加嚴第二個victim：先restore、標記`effect_unproven`，交給A/B判斷整體價值。

### 6.4 資源壓力與未知的明確行為

| 情況 | 已啟動工作 | 新的非豁免工作 | 豁免工作 |
|---|---|---|---|
| CPU high且有eligible背景Job | 最多一個短CPU退讓 | active cap期間暫停新啟動；pending可排隊 | 不限速；仍計帳；保留既有 bypass |
| physical/Commit headroom不足 | 不kill、不trim、不RAM cap；停止新增CPU tightening，現有CPU cap restore | 等待，回傳具體resource blockers | 不自動撤銷／忽略授權；報告policy overage |
| disk pressure | 不新增OS I/O actuator | 需要相應IO/disk條件者等待 | 保留既有豁免；不把unknown冒稱healthy |
| fast sample stale/unknown | 不加嚴；既有cap租約到期restore | fail closed，不使用舊CPU5m擴額 | 只有能驗證有效grant才bypass；未知不虛構grant |
| exemption DB不能讀 | 移除自己scope的cap，無法證明可控就不控 | 不能以未知豁免作bypass；正常准入還須滿足資料／帳本要求 | 已有可信授權不得被當成可限速；不自動revoke |
| 全部manager不可用 | workload不因我們的kill設定而退出；可能有殘留cap，走獨立recovery | 停止新managed launch | 不新增限制；恢復路徑優先處理 |

### 6.5 偽碼：policy 與 actuator 分離

以下為規格偽碼，不是可直接運行的 implementation。

```text
helper_tick(frame, registry, previous_state):
    if mode == OFF: return NO_POLICY_ACTION
    if any_required_evidence_invalid(frame, registry):
        return REQUEST_RESTORE_ALL_OWN_CAPS(reason), RESET_WARMUP
    update_monotone_demand_floors(frame)   # cap絕不降低allocated demand
    if physical_or_commit_reserve_breached(frame):
        return REQUEST_RESTORE_OWN_CAPS, BLOCK_NONEXEMPT_ADMISSION
    if active_intervention exists:
        if exemption_possible_or_granted or deadline_reached:
            return REQUEST_RESTORE
        if no_longer_eligible or effect_unproven:
            return REQUEST_RESTORE
        return next_bounded_state_or_renewal(frame, same_victim)
    if not consecutive_high_samples or not fresh_uncapped_baseline:
        return OBSERVE
    victim = select_one_explicit_background_job()
    if victim is NONE: return OBSERVE_UNMANAGED_PRESSURE
    return PROPOSE_LEVEL_1(victim, frame_seq, target, short_lease)

guardian_apply(proposal):
    acquire policy_mutex then job_mutate_mutex, each bounded
    verify guardian_epoch, policy_epoch, monotone_seq, fresh sample
    verify own Job identity, role, exact membership, capability, singleton cap
    reread authoritative exemption revision and affected scopes
    if exempt/unknown: restore_own_cap_if_present(); reject proposal
    query actual CPU control; detect external mutation
    if target unchanged and current Query matches verified applied state:
        renew only the in-memory lease, bounded by the absolute intervention deadline
        return RENEWED   # no Set, no new durable intent, no per-second fsync
    durably persist original + last_applied + intended_next + demand_floor
    if durability failed: reject tightening; restore if already capped
    call SetInformationJobObject(typed CPU rate only)
    immediately QueryInformationJobObject and compare flags/rate
    if query mismatch/failure: enter RESTORE_UNVERIFIED or verified rollback
    else publish APPLIED(action_id, actual flags/rate, lease_deadline)
    release locks

guardian_safety_tick():
    for own active cap (MVP最多1個):
        if helper_loss or lease_expired or exemption_changed or ownership_invalid:
            compare_and_restore_without_needing_SQLite_write()
    reconcile root exit / Job active process count
    heartbeat lifecycle in batches; never release active work on elapsed TTL
```

guardian不得把「收到了新 proposal」當作lease renewal；只有仍fresh、同epoch、符合豁免與scope規則的decision才續租。policy正常restore可不durably新增限制；安全還原失敗須獨立可見，不被telemetry寫入失敗遮住。

---

## 7. 記帳、一致性、豁免與公平性

### 7.1 不再混用五種數字

| 名稱 | 定義 | 是否可因限速下降 |
|---|---|---|
| `requested` | immutable request 的 CPU／physical／Commit／IO估算；參與spec hash | 否 |
| `measured` | 同一有效窗口的實際whole-machine或Job使用量 | 會；但本身不是未來capacity承諾 |
| `pending` | 已RESERVED/PREPARED/LAUNCHING但尚未可靠量到的工作需求 | 不因grace過去就歸零 |
| `allocated`／`demand_floor` | 已承認、仍須保留的需求底線；至少requested，必要時上調到有效observed high-water | **只能上調或terminal後釋放；cap不得降低** |
| `desired` | policy提出的CPU target、duration、reason、epoch | 可以改；不是OS事實、不改容量預約 |
| `applied` | Set後Query成功驗證的CPU flags/rate，加作用者、action ID、lease | 必須與desired分列；未知不能填成成功 |

CPU demand floor = `max(requested CPU, execution lifetime 內有效 uncapped CPU high-water)`。Physical／Commit floor至少requested；確認實際private需求超過估算時可上調到observed high-water。這只是保守的實測下界修正，**不是需求預測或自動縮額**。超出估算可以令 projected usage 超過預算；此時阻止新非豁免工作，不撤銷既有工作或grant。

提高floor必須同步到新admission使用的frame；SQLite可batch，但cap之前須durably保存該Job的floor。cold recovery無法取得較新floor時先hold，從manifest/DB最大值與新measurement重建，不用較低舊值開閘。

### 7.2 唯一容量來源與共同 projection

沿用 `sentinel.db` 的 `reservations` 與 `worker_reservations`；新增managed lifecycle/control metadata，但**不再建立第三套容量reservations**。一個execution對應direct或routed其中一種；subspan對應parent同一allocation source。

所有本機准入——Coordinator、Maintainer local route、managed wrapper——必須調用同一 `project_local_capacity(conn, frame, config)`。cloud pools保留原capacity scope，不納入本地58GiB，也不讓本機Job cap改變cloud worker quota。

對CPU／physical／Commit資源r：

```text
M_r = valid whole-machine measured usage
A_ir = active execution i 的allocated demand floor
m_ir = 可安全歸屬給i、已包含在M_r、同窗口且不重疊的measured usage
       pending / unregistered / stale / incomplete attribution 時為0

projected_r = M_r + Σ_i max(0, A_ir - m_ir)

nonexempt admission:
  projected_cpu + request_cpu <= configured local_allocatable_cpu
  projected_physical + request_physical <= min(58 GiB, physical_total - 4 GiB)
  projected_commit + request_commit <= commit_limit - 4 GiB
  active_io_slots + request_io_slots <= configured heavy_io_slots
  disk space / IO pressure / freshness guards 另外成立
```

`m_physical` **只能使用unique private working set**；shared pages留在whole-machine M內，不扣除。`m_commit`使用private commit。nested Job只有最外層Sentinel execution計一次；Job CPU aggregate與其child不能重複扣除。同一physical process不得出現在兩個可扣除集合。**一致性檢查先於 subtraction：**aggregate Job CPU 不能超過同窗口 machine busy units，private physical／Commit aggregate 不能超過各自全機值；超出、時點不一致或疑似 double attribution 時，該資源整組 `m_ir=0` 並附原因，不能以任意截斷後的數字假裝精確。machine CPU 必須在 `[0,N]`；記憶體值須符合 total/available/Commit 的基本邊界。合法但估算超出容量的 request 可回報 `request_exceeds_host_budget`，不得被靜默縮小。

有效但缺少EX2或memory attribution時，使用 `m_physical=0` 是刻意偏保守的double-count上界；不得用RSS／sum WorkingSet假裝精確。若此fallback讓大量合理工作無法進入，記錄acceptance failure，維持admission-only或要求該capability；不在runtime改小request來掩蓋。

若frame registry revision落後於交易內帳本，新增pending仍完整計入；對無法證明一致的舊measurement一律取消subtraction。不要先從另一連線讀reservation，再以過期結果決定本連線admit。交易內只讀DB與已取得的bounded frame，不發起OS/IPC。

### 7.3 兩個必要算例

**算例A：限速不能創造容量。**假設全機M_cpu=10，其中Job J實際6、其他工作4；J原requested=4，但uncapped high-water已把A提升為6。

- 限速前：`10 + max(0,6−6)=10`。
- 限速後J只用3、全機降成7：`7 + max(0,6−3)=10`。
- 因此不能把觀測降成7當作多出了3 units。若只保留requested=4，會算成8而漏記已知需求，故high-water floor是必要的。
- 此外MVP還有active-cap launch barrier：即使存在其他可用容量，也暫不啟動非豁免新工作。這是短期安全取捨，會影響queue wait，必須納入A/B。

**算例B：58GiB不是先扣所有agent再加58。**假設64GiB主機，全機physical used=50GiB；一個running Job A=8GiB，安全可扣的private working set=6GiB。

- projected physical = `50 + (8−6)=52GiB`。
- 新工作physical request=6GiB：等於58GiB，physical gate通過；仍須獨立通過Commit與其他gate。
- 新request=6.1GiB：超過58，等待。
- attribution未知時m=0，projected=58，新工作不能進。這是保守誤差方向，不能當作記憶體真的用滿。
- 若實機total只有59GiB，budget變`min(58,59−4)=55GiB`，不能因設定58而侵占physical reserve。

### 7.4 grace、TTL、queue、barrier

- 舊 `reservation_grace_sec` 只可作「launch尚未反映在telemetry」的diagnostic，不再作v2 active demand停止計帳的時刻。
- managed reservation按guardian Job lifecycle續存。建議lifecycle heartbeat每30s；沿用既有TTL作健康訊號，但TTL到期只轉`UNCERTAIN_HOLD`，不能刪除active row。
- PREPARED lease建議30s；只有未取得launch claim、Job empty且caller不可能再執行時才cancel/release。LAUNCHING超時一律START_UNKNOWN，不自動清帳。
- queued wait loop更新request活動；維持原timeout/cancel exact semantics。queue TTL與執行TTL分離，不能timeout後放掉正在running的reservation。
- guardian首個restrictive intent前，先在`sentinel.db`短交易設`admission_barrier=CONTROLLING`，再Set API；無法建立barrier則不加cap。
- **launch/barrier 互斥：**`ClaimLaunch` 與建立 cap barrier 共用 policy mutex；launch claim 的 CAS 同時登記 `launch_in_flight`。cap barrier 不得在任何未 reconciliation 的非豁免 `LAUNCHING`／`START_UNKNOWN` 存在時開始；有 barrier 就拒絕新的非豁免 launch claim，包括先前已 RESERVED 的工作。CreateProcess 本身不在 DB transaction 裡呼叫；claim 到 `bind_root`／可證明未啟動的失敗之間，由 in-flight 記錄封住這個空隙。失去 ACK 不清除 in-flight，不靠 timeout 猜測 user code 沒跑。預約可排隊，但 reserve≠不可撤回的啟動權。
- barrier涵蓋新的非豁免launch（包括P0/P1，因priority不是bypass）。已running工作與已核發grant不受新政策撤銷。這可能延後新的互動命令，必須在queue metrics顯示，不隱藏成成功。
- restore Query成功不立即清barrier。必須`all own caps restored + accounting reconciled + 5 fresh uncapped samples`後，CAS清除barrier；否則維持`RECOVERY_HOLD`。
- `off`／legacy模式不代表刪除現存managed lifecycle。舊binary不能在active rows存在時重新使用原TTL cleanup邏輯。

### 7.5 兩個SQLite store與豁免的線性化

`sentinel.db` 是容量/lifecycle authority；`exemptions.sqlite3` 是grant authority。現有WAL設定與兩個連線不能構成跨store原子交易；即使改用ATTACH，WAL下也不能假設跨DB crash atomicity。[W11]

**新增最小同步：**exemption store加入單一revision；所有新grant/revoke、managed cap Set／renew驗證與legacy mutation handoff，共用logon範圍的policy mutex。

固定lock order：`policy mutex → job mutation mutex（需要時）→ 一個DB的短transaction`。不得同時長持兩個DB transaction，不得在DB transaction內等待IPC、CIM、psutil、外部程式或另一個mutex。Coordinator先取得identity/telemetry，再進短交易；cleanup以明確的tri-state observations處理，不將lookup exception當作dead。

**RPC／lock 邊界：**guardian 健康時，CLI 的 `GrantExemption`／`RevokeExemption` 請求由 guardian 同一個序列化 mutation 路徑執行；caller 發 RPC 前不得持有 policy/job mutex 或 DB transaction。library 分開「外部 façade」與 `commit_grant_locked()` 之類內部受鎖方法，避免 guardian 呼叫自身 RPC 或非重入鎖造成死鎖。legacy grant 入口也必須接此 façade，不能留下不更新 revision 的 writer。

guardian 不可達而 grant DB 仍可用時，CLI 可在同一 policy mutex 下僅完成授權 commit，**先釋放鎖**，再要求獨立 recovery；回傳 `grant_state=recorded, enforcement_state=restore_pending`，不得自己變成正常 cap writer，也不得假稱 OS 已還原。無 active cap 的可驗證情況可回傳 `enforcement_state=not_applicable`。schema/readiness 不明則維持 pending，不因 recovery 失敗撤回已承諾授權。

**grant協議：**

1. validate明確使用者授權、duration、reason與root identity；保留既有1..1440分鐘、同scope重試不延長到期的語意。
2. policy mutex內，在exemptions DB `BEGIN IMMEDIATE`檢查未撤銷未到期租約數。保留「root退出也不提前釋放租約名額」規則，最多3；commit新grant與revision。
3. 找出grant scope涉及的managed Jobs；若grant落在某Job的子樹，**解除整個Job cap**。Job無法拆出子樹，寧可collateral unthrottle，不能保持cap讓grant不生效。collateral unthrottle不是新增第4個grant。
4. 對自己已施加cap做restore/readback。全部成功後回傳 `grant_state=active, enforcement_state=restored`。
5. DB已commit但API恢復失敗／crash：grant仍存在、slot仍占用，不rollback使用者授權；回報`enforcement_state=restore_pending`，停止相關cap renewal、走recovery。不得把API未完成包裝成「完全生效」。

**競爭順序：**cap先拿鎖完成，後grant就必須還原；grant先commit，後cap在鎖內重讀revision/scope就必須拒絕。不能只在helper讀一次grant或只驗舊collector snapshot。

**revoke／expiry：**使用者revoke或自然expiry移除的是授權，不是要求立即重加cap。後續需新的warmup、pressure與eligibility才能控制；舊proposal不能重播。controller lease expiry與exemption expiry完全不同：前者只撤除本工具限制，不撤銷使用者豁免。

**DB locked/corrupt：**guardian對exemption authority不可讀時不新增／維持restrictive lease；restore本工具cap不需要成功寫DB。新grant不能憑記憶體假發；新admission不能憑unknown grant bypass。保留已知grant記錄待reconcile，不擅自刪除。

**授權邊界：**`--user-authorized` 是上游對明確使用者指令的attestation，不是能阻止同一Windows使用者下惡意agent造假的security boundary。ACL與token防止錯scope/其他logon的誤操作，但MVP不宣稱能隔離同SID敵對process；要達到該威脅模型需另立權限架構，不能靠JSON欄位完成。

### 7.6 additive schema與持久化

| 位置 | 新增／調整 | 目的／限制 |
|---|---|---|
| `sentinel.db: reservations / worker_reservations` | additive execution binding、physical/commit bytes的明確兼容欄位、lifecycle managed tag | 舊resources保留；一個execution只能有一種allocation來源；managed rows不能被legacy cleanup刪除 |
| `sentinel.db: managed_executions` | execution/task/session/principal、parent、exact reservation reference、PID/birth、Job name、state/revision、coverage、high-water floors | 只存lifecycle與accounting metadata，不是第二份reservation |
| `sentinel.db: adaptive_runtime` | schema/protocol/version、mode、epochs、registry/config revision、admission barrier、last verified recovery | readiness有實際含義，不以process running代替健康 |
| `sentinel.db: adaptive_actions` | action ID、execution、epoch/seq、desired/applied、state、reason、API error、sample/decision/apply timestamps | idempotent audit；success必須有readback |
| `exemptions.sqlite3` | revision metadata；可選exact native birth欄位，保留legacy identity與expires_at | 不改既有最大3個、duration、expiry/revoke語意；舊grant無法精確驗證時不施加新限制 |
| `adaptive/recovery/<execution>.json` | 原始cap、last_applied、pending_intent、Job/owner身份、floor、schema/hash | ACL保護、單檔有界、先寫tmp再atomic replace及必要flush；不含raw command；DB失效時可獨立restore |

**最低 SQL constraints／indices 契約（實作以 additive migration 落地）：**

- `managed_executions.execution_id` 為 primary key；`job_name` unique；`state_revision` 非負整數。`allocation_kind` 只允許 `direct|routed|parent`；direct/routed 必須恰有一個精確 reservation reference，parent 必須指向同 logon 的已存在外層 execution，禁止 parent cycle。
- 一個 direct/routed allocation 只能綁定一個 top-level execution；subspan 可引用 parent，但沒有獨立 resource allocation。對多態 reference 的完整性，使用同交易驗證與 unique constraints，不把普通 FK 假稱成可以跨兩張表擇一驗證。
- CPU/bytes/io floors 非負且有限；所有 expected-revision 更新必須檢查 affected rows=1，否則 `revision_conflict`，不能吞掉失敗再 launch/release。
- `adaptive_actions` unique `(guardian_epoch, execution_id, decision_seq)`；`action_state` 只允許 `INTENDED|APPLIED|RESTORED|FAILED|UNVERIFIED|CONFLICT`。`APPLIED` 必須有 readback 與 apply timestamp；單純 desired 不能填入 actual 欄位。
- `adaptive_runtime` 在此部署只允許一個 active logon controller record；索引包含 `(state, heartbeat_at)`、`(principal_id, state)`、`(execution_id, decision_seq)` 與 queue 現有 priority/FIFO key。不要為每個 sample 建大型 SQL index。
- terminal archive/release、parent 子關聯與 execution finalization 在同一短交易完成；刪 DB row 不能觸發 OS side effect，不使用 cascade 把未驗證的 live execution 當作 terminal。

schema migration由獨立migration lock與transaction執行；新schema版本不明時拒絕寫入。備份使用SQLite安全backup路徑，不把正在寫入的DB與WAL隨意複製成「完整備份」。rollback不把舊DB直接覆蓋回去，否則會丟失目前的grants與live execution狀態。

### 7.7 公平性、拆task與大工作等待

MVP保留resource-v2「priority後，選feasible request」的排隊語意；不把公平系統塞進首版。

- **防止拆task增加總容量：**所有request進同一machine ledger；同一execution的nested wrappers共用allocation，不能靠更多Job獲得新的58GiB或額外exemption名額。principal由可信session關聯，不接受每個task自帶新的weight／credit。
- **控制選擇的聚合：**先比較principal aggregate，再選其實際Job，避免只按單一task排序造成明顯偏差。但拆成很多低於victim threshold的小工作仍可能降低cap覆蓋，**不宣稱strategy-proof或完整anti-sybil**。同SID是合作治理模型，不是對抗型排程安全邊界。
- **大工作：**顯示request age、各resource缺口、是否連理論budget都放不下、是否被既有long-running allocations占用。超過等待閾值（建議10分鐘）發一次有界通知；不把升priority當作創造RAM，不自動降低resource estimates。
- **starvation：**現有feasible-first可能讓大工作久候；MVP誠實保留此限制。後續可驗證「同principal併單＋bounded admission drain window」，但不能自動取消running jobs或使用者grant，亦不能稱已有保證。
- 不用隨機UUID作principal，不給每個task固定的額外minimum share。CPU cap floor只是最低允許ceiling，不是保證獲配量。

---

## 8. Windows 可行性與實際還原

### 8.1 API選擇與拒用清單

| 能力 | 選用 | 支援與限制／驗證方式 |
|---|---|---|
| 新工作隔離 | CreateJobObjectW、OpenJobObjectW、CreateProcessW + JOB_LIST | Job-list最低Windows10/Server2016；探測不等於所有host都兼容。[W1,W3] |
| CPU cap | Set/QueryInformationJobObject、JobObjectCpuRateControlInformation | 只用ENABLE+HARD_CAP；WEIGHT/MIN_MAX不用；DFSS可能回error50。[W2,W4] |
| 身份 | OpenProcess有限query權限、GetProcessTimes；操作期間持同一handle | creation time不明就不控制；不單靠exe名稱或PID |
| Job membership/finish | IsProcessInJob、Job basic accounting/process IDs；completion port只作提示 | query確認active=0才釋放；不依賴漏事件或一般job handle signal。[W1] |
| machine CPU/memory | GetSystemTimes、GetPerformanceInfo | 單processor-group假設必須明示，PageSize換算驗證。[W6,W10] |
| private attribution | GetProcessMemoryInfo + EX2可用時的private working set | EX2欄位需要較新的Windows更新；動態probe，不只看major version。[W5] |
| 時鐘 | QueryInterruptTimePrecise；QPC只量成本 | wall UTC僅audit及既有grantexpiry，不作fastlease唯一依據。[W8] |
| 同步／IPC | named mutex、Named Pipe明確logon ACL、peer identity verification | 不使用預設ACL當作完整安全保護。[W9] |

**不選：**TerminateJobObject、KILL_ON_JOB_CLOSE、hard process/job memory limit、active-process/time limit、週期SuspendThread/NtSuspendProcess、blind EmptyWorkingSet、undocumented class33 I/O priority作新增actuator、systemwide foreground spying、Breakaway旗標逃避外部Job。

Windows hard cap在OS CPU scheduling interval耗盡額度後會暫停該Job取得更多CPU直到下一interval。這與應用自己做週期Suspend/Resume不同，但仍可能造成jitter；所以不能把HARD_CAP宣傳成完全平滑、沒有暫停效果的柔性調整。這是A/B必須驗證的代價。[W2]

### 8.2 capability record與safe fallback

每次logon／版本變更生成capability record：OS build、Python bitness/version、logical count/group、parent-job presence、Job-list launch結果、cap readback、saturated consumption效果、restore效果、stdio/console host、Job ACL/reopen、helper/guardian是否位於任何受控Job、是否具DFSS/RDP疑慮。

`capability=unknown`與`unsupported`都不能enforce。MVP拒絕foreign parent Job精準控制，不嘗試用外層cap百分比推算whole-machine target。DFSS由API結果及效果canary判定，不能因看到RDP就斷言一定不可用，也不能因不是RDP就略過canary。多processor group或未知CPU affinity domain都不做active cap。

Job-list成立只證明由該launch產生且依規則繼承的process可被涵蓋；服務、WMI broker、cloud inference、container daemon等代執行工作不因此變成其Job成員。發現brokered workload即降低coverage，不能擴大scope到共享daemon。[W1]

### 8.3 handle、manifest、lease與crash恢復順序

**正常執行：**guardian與wrapper各保有Job handle；command不繼承Job handle。自有Job初始cap disabled。第一次tighten前寫入durable recovery intent；僅target transition要求durability，**純lease renewal不重寫manifest、不再呼叫Set、不每秒fsync**。

manifest至少含：schema/version、execution/job name、creation nonce、wrapper/root完整identity、guardian identity/epoch、original CPU control、last_applied、pending_intent（old/new pair）、allocated floor、manifest sequence/hash。事件順序：

`durable intent → OS Set → OS Query → applied ACK → batched audit commit`。

- crash在intent前：不得已經改OS。
- crash在intent後、Set前：recovery Query看到原值，視為已restore，不能盲目套desired。
- crash在Set後、audit前：Query可能等於pending new值；允許restore original，不能因DB沒有APPLIED就忽略cap。
- pending intent與last_applied都不匹配：標external/conflicting state，不任意覆盖外部設定。

**helper loss：**guardian拒絕續租；6s lease到期，立刻compare-and-restore。建議canary門檻：在OS正常排程且guardian存活時，從最後有效decision起8s內完成Query驗證還原。

**guardian crash：**wrapper若仍活著，等待guardian process handle signaled，取得mutate mutex，依manifest將自己的cap restore；helper／supervisor啟動restore-only guardian處理其他Job。兩者可能競爭但以mutex與Query做到idempotent；不是兩個正常writer。

**wrapper先退出、後guardian crash：**helper/supervisor透過manifest OpenJobObject重新持有Job，先restore再恢復lifecycle ownership。Job仍有process時不能假設最後handle關閉已移除限制。[W1]

**guardian hang：**lease到期本身不能把API writer fence。按§3.2驗證並停止本工具guardian本身，等待死亡／mutex釋放後restore。OS call長期不能返回、process不能終止或恢復者也無法獲得CPU時，8s不是硬保證，必須回報unverified。

**helper＋guardian＋wrapper全部不在：**僅靠兩個resident process不可能提供秒級恢復保證。啟用active模式前需有獨立supervisor task（建議每60s檢查一次，與existing collector task不同）；下一次成功排程啟動restore-only recovery。這是較慢的最後防線，**60s cadence不等於60s worst-case SLA**。task停用、系統掛起、storage失效等共同故障需要使用者／管理者執行recovery runbook，不能對外聲稱自癒已完成。

### 8.4 compare-and-restore的精確邊界

只恢復本工具建立、已驗證nonce/identity/ACL與manifest對應的Job。步驟：

1. fencing成立後，Query目前CPU控制資訊。
2. 若已disabled，標verified restored，不覆寫其他Job limit fields。
3. 若目前等於last_applied或durable pending intent的可能值，將CPU rate control回original disabled；Set後再Query確認。
4. **disabled binding 的 S1 驗證契約：**預定清除本工具 CPU rate `ENABLE` flag，其餘實際填值遵守該 API 結構與 probe 結果；第一個待測 encoding 是 `ControlFlags=0`、`CpuRate=10000`，而不是 `ENABLE` 配 rate=0。disabled 的 readback 判準是 ENABLE 未設、沒有本工具生效中的 CPU rate policy，不能要求 unused union 欄位恰好回傳0。此具體 binding 尚未在本輪執行，必須以 Query 加 saturated-canary consumption 恢復共同確認；S1 失敗則不啟用 cap。[W2,W4]
5. 若不同，標`external_control_conflict`，不使用「一律100%」或「一律Normal」覆蓋。停止控制，runbook要求操作者確認誰改了值。
6. restoration Query失敗時，維持`RESTORE_UNVERIFIED`與admission barrier；不能刪manifest、不能提前接回舊writer。

首版只還原自有Job CPU rate，priority未由新方案改動，沒有必要猜原priority。一般Windows API沒有對CPU control欄位的compare-and-swap；這裡的compare-and-restore只在本工具單writer與合作型外部程式模型內成立，不能防同SID敵對writer的ABA競爭。

---

## 9. 故障矩陣與失敗後的可觀察結果

下表的「restore」只指本工具已施加的CPU cap，不包含修改其他程式或撤銷grant。

| 故障／注入點 | 工作處理 | Admission／帳本 | Recovery及驗收重點 |
|---|---|---|---|
| helper crash／loop卡住 | 工作繼續；guardian lease-expiry restore | 阻止非豁免新啟動，保留allocation | 最後有效decision後8s目標內Query disabled；不得依賴collector |
| guardian crash | 不kill Job；wrapper/helper/supervisor接手restore | barrier保持；不以owner death釋放 | 舊process死亡＋mutex fencing；孤兒children仍計帳 |
| guardian alive但IPC失聯 | 不允許第二normal writer直接Set | admission hold | 有界grace後僅停止已驗證guardian本身，重啟restore-only |
| wrapper PREPARED前死 | 沒有工作應已啟動 | exact release；無Job則無cap | 不能清除其他同app的reservations |
| wrapper LAUNCHING中死／ACK遺失 | 不自動重跑command | START_UNKNOWN、保留需求 | Query named Job／root證據；測每個CreateProcess邊界 |
| wrapper RUNNING中死 | Job子程序繼續 | guardian續存；不按app owner釋放 | verified Job membership／active-process count |
| root成功exit但grandchild存活 | root exit code照回傳 | DRAINING、IO/RAM/Commit仍占用 | child退出後exactly-once finish；無遺失reservation |
| collector crash／超時／重啟 | 新Jobs不受其taskkill subtree影响 | fast CPU/memory可繼續；slow disk過期則IO准入hold | old/new writer互不覆蓋，fast功能不等下輪collector |
| sentinel.db busy／locked | 已執行工作繼續 | 新admission回db_busy，不忽略existing rows | 新tightening停止；restore不必先成功寫SQLite |
| exemption DB locked/corrupt | 不新增cap；已有cap restore | unknown不能創造bypass，不能刪grant | max3無超發；既有grant不被緊急規則撤銷 |
| disk full／read-only／manifest寫失敗 | 不加新限制；已有cap使用in-memory/durable original還原 | launch/tightening fail closed，保留uncertain rows | restore不能因audit寫不進去而跳過；bounded logs |
| IPC斷線／重複／亂序／過大message | 不再次執行command，不接受舊cap | idempotent key及seq拒绝 | duplicate不續lease；client queue bounded |
| sleep/resume | resume後撤已知cap，再warmup | hold直到fresh measurements與一致clock epoch | 舊streak、舊baseline、舊lease不可重播 |
| UTC clock jump | 不新tighten，不擅自revoke/renewgrant | fresh-read authority、clock異常可見 | fastlease使用interrupt time；expiry政策不私改 |
| PID reuse／birth讀不到 | 不操作新PID指向的process | uncertainty不等於dead；不提前release | 以持有handle＋birth驗證，barePID攻擊fixture零誤操作 |
| grant與Set競爭 | grant scope涉及的cap restore | grant仍計帳，最多3租約 | barrier測cap-before-grant與grant-before-cap兩順序 |
| grant在同Job的一個child | 整Job cap移除，不嘗試把child移出Job | 不新增額外grant名額 | Job不可拆時不能保留cap傷及豁免 |
| revoke／expiry與舊decision競爭 | 不立即重加cap | 後續正常准入規則 | 新warmup＋新seq才可control，oldproposal拒絕 |
| Set success但Query不同 | 不記APPLIED成功 | hold | immediate rollback/readback；API error與state分列 |
| Query cap存在但CPU效果無法證明 | 不盲目加碼 | conservatively維持accounting | saturated canary驗效果；I/O-bound不得誤判API失敗 |
| foreign/nested Job／DFSS | prelaunch明確admission-only或strict不執行 | 仍正常計帳 | 不breakaway、不靜默unmanaged double-launch |
| topology／processor group改變 | cap restore、capability invalid | 不用舊N擴額 | 重新probe、clearbaseline |
| monitoring成本超預算 | 不追趕missed ticks，不掃無界process list | stale/coverage規則生效 | restore、回shadow/admission-only；不能加高priority硬撐 |
| old binary／old collector重新啟動 | 不允許它寫managed scope | metadata版本與mode檢查阻止unsafe cleanup | active Job未empty不能整體binary rollback |
| 外部程式改Job cap | 不覆寫未知值 | conflict hold | 回報current/original/lastapplied metadata，不猜restore完成 |
| 同時失去所有recovery owners | 工作可能持續但殘留cap | 不承諾自動清帳 | 獨立supervisor／manualrestore；共同故障不宣稱8s保證 |

每個fault test都要保存：注入點、進入前state、精確execution identities、OS readback、reservation是否保留、exemption rows/revision、各timestamp與最終reason。不要只assert Python exception被catch。

---

## 10. 逐階段實作：檔案、函式、依賴與promotion證據

### 10.1 執行規則

每階段是一個可review的變更集合，不是一口氣merge所有功能。預設feature off；使用隔離data directory、測試Job prefix與測試Scheduled Task，不能拿使用者正在工作的程序驗證crash/kill/trim。下面新函式與CLI都是**待新增契約**；未讀過的live整合檔案必須在P0定位再改，不虛構其目前實作。

P0→P1→P2→P3→P4→P5→P6有序；P1只在隔離canary探索能力，不能先啟用production。任何gate失敗，提交失敗證據與已完成的安全改善，維持off/admission-only，不降低58/4/4/3政策或擴大scope使測試過關。

### P0 — 保護dirty tree、重建可驗證baseline

**要做：**保存`git status --short`、HEAD、各allowlisted live檔案hash與原本diff清單於本機交接區；比對snapshot-manifest。記錄live config的58GiB／4GiB／4GiB／max3與admission policy，不上傳完整config/DB/env。檢查`maintainer.py`、local worker同步、hooks、adapter runner及collector timeout subtree的live版本。

| 檔案／入口 | 變更內容 |
|---|---|
| `docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md` | 放入此plan；不改source-snapshot |
| `docs/planning/adaptive-scheduler/BASELINE-RECONCILIATION.md`（新增） | allowlisted差異、缺失dependency、測試環境、已知baseline failures；私密diff留本機 |
| `tests/test_coordinator.py`、`tests/test_pressure.py`、`tests/test_exemptions.py`、兩個PS測試 | 先在已對齊的隔離tree跑現況測試，不先為過關修改expectations |
| `sentinel/maintainer.py`、`scripts/maintainerctl.py`、`hooks/*`、`sentinel/adapters/local_runner.py`／`persistent_local.py`、`scripts/watchdog.ps1` | 本階段只read/locate；確認真實呼叫鏈，沒有被snapshot覆蓋的檔案不憑舊root推論 |

**退出證據：**清楚的live baseline manifest、哪些測試通過／原先就失敗／因環境skip；確認dirty檔案未被覆寫。`test_local_worker_uses_same_commit_guard`的live實作來源已定位。沒有這些證據就不進production整合。

**回退：**文件可留；不得reset使用者working tree或用舊DB覆蓋現況。

### P1 — 三組有界Windows capability spikes，先證明能撤回

| 新增測試檔案 | 探索內容 |
|---|---|
| `tests/windows/test_adaptive_job_capability.py` | JOB_LIST原子launch、membership、parent Job拒絕、DFSS/unsupported、rate set/query/effect/disable、具名Job reopen |
| `tests/windows/test_adaptive_launch_compatibility.py` | cmd語意、PS5.1/pwsh、stdio、Unicode、exit/Ctrl+C、fast exit、child survivors |
| `tests/windows/test_adaptive_recovery_capability.py` | guardian/helper/wrapper各crash時handle/restore、process身份、mutex owner death、pending-intent crash |
| `tests/fixtures/adaptive_cpu_worker.py`、`adaptive_spawn_tree.py`、`win32_ui_probe.py` | 只使用測試建立的process，CPU負載有停止機制；不使用真實agent當故障fixture |
| `docs/planning/adaptive-scheduler/CAPABILITY-RESULTS.md` | API errors、實際觀測、支援host矩陣、阻塞決策；不只寫supported=true |

可先建立非常小的test-onlyAPI封裝；production封裝在P3正式收斂。禁止用測試spike直接取代`invoke-sentinel.ps1`。

**退出證據：**S1/S2/S3（§12）通過；新process在user code前就位於Job；不採suspended fallback；cap實測有效且可重新OpenJobObject解除；不設定kill/memory/process-count/time limit。不能證明其中任一項，就停在A，不進active OS控制。

**回退：**Query確認所有測試Job已disabled／退出後關閉handles、移除測試task與fixture；不得對非測試Job操作。

### P2 — 先交付task lifecycle與共同計帳，仍不啟用cap

| 檔案／函式 | 具體變更 |
|---|---|
| `sentinel/accounting.py`（新增） | `project_local_capacity()`、`resolve_allocation_source()`、`update_demand_floor()`；所有local entry共享單位／pending／dedup公式 |
| `sentinel/adaptive/contracts.py`（新增） | typed ProcessIdentity、ExecutionSpec、FastFrame、ControlProposal、RecoveryManifest；version/finite/units/enum validation |
| `sentinel/adaptive/store.py`（新增） | additive migration、`prepare_registration()`、`claim_launch()`、`bind_root()`、`mark_root_exited()`、`finalize_if_empty()`；exact IDs與CAS |
| `sentinel/coordinator.py` | `admit()`、`retry_queued()`、`release()`、`_cleanup_locked()`／`_routed_local_pending()`接共同計帳；managed TTL→hold；exact claim取代managed signature guessing；OS identity查詢移出transaction |
| `sentinel/pressure.py` | 保留`describe()`對legacy報表語意；`blockers()`接typed projection，不再自行重算一份CPU/Commit available；unknown不能降為0 |
| `sentinel/maintainer.py` | `_pool_usage()`、`route_and_reserve()`與cleanup對local pool接相同ledger；remote/per-execution pool維持原本語意 |
| `scripts/maintainerctl.py` | local同步傳明確host pool identity與snapshot來源／freshness，不讓local alias重複當成新physical pool |
| `scripts/sentinelctl.py` | exact execution register/claim/query/finalize；legacy release不觸及active managed rows；傳遞caller identity |
| `hooks/sentinel-gate.py`、`scripts/wait-slot.ps1` | 保留直接wrapper不double reserve；新增明確claim傳遞介面；無token的舊waiter只走legacy/admission-only |
| `tests/test_coordinator.py`、`test_pressure.py`、`test_maintainer.py`、`test_hooks.py` | 保留既有邊界測試；增加兩入口競爭、不同命令/同命令並行、owner reuse、grace/TTL、nested parent共帳、unknown錯誤方向 |
| `tests/test_adaptive_contracts.py`、`test_adaptive_accounting.py`、`test_adaptive_lifecycle.py`（新增） | §4–§7規格的純測試，不要求真實Windows |

**重要：**若`hooks/sentinel-stop.py`仍有owner級release，P0定位後加入相同managed-row保護；不能只修主要gate忘記stop路徑。

**退出證據：**所有CPU/RAM/Commit算例與邊界測試通過；direct↔local route同時競爭不能double spend；同execution的adopt不double count；有效grant仍可bypass並計帳；未知identity不是dead。還沒有任何新增OS限制。

**回退：**功能旗標關閉新registration；additive欄位保留。沒有managed live executions時才可回前一binary；不得還原舊DB覆蓋新grants。

### P3 — 正式Job launcher、guardian與writer handoff；先restore能力，後限制

| 檔案／函式 | 具體變更 |
|---|---|
| `sentinel/adaptive/windows.py`（新增） | verified-handle helpers、`create_owned_job()`、`launch_in_job()`、`query_cpu_control()`、`set_cpu_control()`、`restore_cpu_control()`、membership/memory/clockAPI；集中ctypes ABI/handle ownership |
| `sentinel/adaptive/ipc.py`（新增） | bounded Named Pipe protocol、peer identity、ACL、idempotent request/seq、read deadlines；不傳raw command給guardian |
| `sentinel/adaptive/guardian.py`（新增） | sole normal actuator、`prepare_execution()`、`apply_proposal()`、`renew_lease()`、`reconcile_jobs()`、`restore_owned_caps()`、manifest先寫/Query後ACK |
| `sentinel/adaptive/launcher.py`（新增） | wrapper host、JOB_LIST creation、stdio/exit、exact launch claim、root/child狀態、restore-only fallback |
| `scripts/invoke-sentinel.ps1` | 新增明確managed／role／require-managed選項；採thin host；不再用app owner當managed task；保留admission TimeoutSec及退出語意 |
| `sentinel/exemptions.py` | revision、policy mutex、fresh scope；grant persisted/restore pending分離，max3與idempotent expiry不改 |
| `scripts/exemption-policy.ps1` | 新scope exclusion；沒有original identity/value不做Normal猜測；更新對應測試而非偷偷改全機legacy語意 |
| `scripts/collect.ps1` | 所有CPU/I/O/trim/restore stage接mutation gate；受控Job及infrastructure排除；未知registry則本輪不mutation；slow發布保持相容 |
| `scripts/adaptive-supervisor.ps1`（新增） | 獨立helper/guardian startup/recovery；不在collector task subtree；只可isolate自己verified manager，不`/T` |
| `scripts/sentinelctl.py` | `run-managed`、`adaptive-status`、`adaptive-recover`、mode/drain/audit新命令；stdout不混入workload控制JSON |
| `tests/test_adaptive_guardian.py`、`test_adaptive_exemption_races.py`、`tests/test_exemption_policy.ps1` | 故障點、跨store競爭、legacy/new ownership、scope與compare-and-restore |

**退出證據：**off／shadow狀態不產生任何新cap；可以註冊新Job並在root先走後正確保留children；guardian crash後可reopen/restore；exemption race兩順序通過；舊collector不得觸及managed scope。更新既有PS測試中「lost map一律升Normal」的expectation要在PR明確說明：新scope禁止此行為，不能無聲刪test。

**回退：**先drain並Query cap disabled（測試範圍亦同），存活Job仍由guardian保持accounting/exclusion。不能把wrapper切回舊版、停止guardian，然後假稱running Jobs已脫管。

### P4 — Fast helper與shadow policy，測成本而非調速

| 檔案／函式 | 具體變更 |
|---|---|
| `sentinel/adaptive/sampler.py`（新增） | cached handles、boundedCPU/memory/member sampling、epochs/freshness/coverage、reset、costmetrics；不全機CIM |
| `sentinel/adaptive/policy.py`（新增） | `next_state()`、`select_victim()`、`target_rate()`純函式；固定§6參數、單victim、deadline/cooldown/restore |
| `sentinel/adaptive/helper.py`（新增） | sample loop、memorylatestframe、bounded decisions、shadow mode、low-frequency persistence；無SetAPI |
| `sentinel/adaptive/store.py`、`scripts/sentinelctl.py` | readiness/config revisions、barrier、frame/error對外查詢；UI快照與admissionIPC分離 |
| `tests/test_adaptive_policy.py`、`test_adaptive_frames.py`、`test_adaptive_cost_bounds.py` | synthetic traces、亂序/reset/sleep、one-victim、lease／frozen floor、boundedloop |
| `config/adaptive.example.json`（新增） | 非秘密policy起點；mode=off，10 enrolled/1cap；不覆蓋使用者config |

**退出證據：**1/10/50 Job測得成本分布；shadow真的零Set；CPU5m與publish timestamp不能偷渡成fresh sample；randomized traces滿足所有invariants；helper/guardian高負載時仍能執行安全tick。

**回退：**停policy、drainregistry；不刪manifest；helper成本不達標就停止adaptive promotion，而非提高process priority。

### P5 — 單一隔離canary：驗證CPU actuator，不碰真實agent

**主要修改：**guardian/helper mode gate允許經capability核可的單一測試execution；`tests/windows/*`擴充full-stack測試；新增`tests/windows/test_adaptive_end_to_end.py`。本階段不擴大控制到全app或多victim。

**最小驗證：**saturated CPU worker的25%／37.5%等whole-machine rates與disabled恢復；grant中途到來；helper/guardian/wrapper逐一崩潰；duplicate/reordereddecisions；DB busy/disk-write failure；OS sleep/resume另作實機測試。不可用mock通過代替Windows證據。

**退出證據：**§11 hard gates及recovery gates全部通過；managed child達到cap、protected sibling與UI probe不被修改；independent supervisor經驗證可救無wrapper的Job。

**回退：**即時restore、Query、保留audit；無需殺fixture以達成解除cap。只有fixture自行約定的測試結束機制可終止測試負載。

### P6 — 小規模真實命令A/B與有限release

**新增／修改：**`tests/benchmarks/adaptive_ab.py`與`docs/planning/adaptive-scheduler/ACCEPTANCE-RESULTS.md`；必要時`dashboard/dashboard.html`僅加coverage/desired/applied/recovery/error顯示。不是dashboard redesign。

以固定commit、相同command/workspace與cache條件進行§11 A/B。前景probe是protected，背景只有明確enrolled的本機command。先做1個victim，再驗證最多10個enrolled／仍1cap的有限負載；不把50-job成本測試當productionpermission。

local routed execution的**精準Job控制可延後**：若要在本階段增加，只能在讀過live `sentinel/adapters/local_runner.py`、`persistent_local.py`後把該入口接`adopt_routed_reservation`；必須通過相同launch/lifecycle/stdio測試。未做則維持unmanaged但已共帳，不影響wrapper-only MVP完成。cloud adapters不改。

**退出證據：**可重現A/B、每組paired結果、監控成本、所有fault outcomes；gate通過才把可用的limited profile交付。production default仍off，使用者選擇啟用的範圍必須明確，不因merge自動納管既有工作。

**回退：**依§11.5，不是只把config改false。A/B不過時停止調參promotion，保留A與shadow證據，記錄不採用B的原因。

### 10.2 交付範圍控制

不得順手重寫`sentinel/orchestrator.py`、workspace、cloud provider adapters、agent prompt、排程公平系統或GPU治理。只有經P0證明為common ledger／lifecycle必要的呼叫點可做小範圍整合；額外功能另開計畫。

新增模組數量是分離ABI、純policy、IPC、lifecycle與recovery的測試邊界，不代表要做通用framework。禁止自動發現plugins、任意actuator registry、通用工作流引擎或新的webserver。

---

## 11. 驗收、A/B、release與回滾

### 11.1 四層證據，不能互相替代

| 層級 | 能證明什麼 | 不能證明什麼 |
|---|---|---|
| L1 純Python／PS parser／state simulation | schema、ledger、state/epoch、sequence、fault分支與race模型 | Windows APIs真的生效、CPU cap是否改善桌面 |
| L2 Windows isolated canary | Job launch/ACL/nesting/CPU effect/restore/console行為 | 真實agent吞吐與互動是否更好 |
| L3 真實command | pytest/build/install等特定工具的exit、stdio、childlifecycle、完成效率 | 所有apps、cloud inference、所有資源瓶頸 |
| L4 小規模桌面A/B | 被測情境的UI queue latency、工作makespan/throughput與成本trade-off | 硬即時、OOM保證或未測環境的泛化 |

portable suites可使用現有`unittest`；Windows-only測試在非Windows可以skip，但release checklist必須另列「未驗證」，不能把skip計入Windows通過率。不得只貼`N tests passed`而沒有環境、scope與故障清單。

### 11.2 建議pass/fail門檻

這些是本plan提出的門檻；沒有任何一項已在本輪測得。

| 類別 | Pass起點 | Fail／不得promotion |
|---|---|---|
| 安全不變量 | 0次wrong-PID／shared-UI mutation；0次有效grant遭新限制；0次scheduler kill workload；0次double-launch／double-reserve／active-child提早釋放 | 任一發生即停止、restore、保留證據，不以平均改善抵銷 |
| 原子grants | 8個以上併發grant競爭仍最多3個；重試不延長原deadline；root退出不提前空出租約名額 | 第4個未到期未撤銷grant被核發 |
| cap API與效果 | saturated canary連續30s的actual CPU units落在target ± `max(0.15 units, target×10%)`，且Query匹配；disabled後在相同無競爭條件回到uncappedbaseline的90%以上 | readback mismatch；cap表面存在但沒有可解釋的consumption效果；restore後仍受本工具cap |
| 反應時間 | warmup完成後，首個high sample window end到Query-confirmed level1的p95 ≤4s | 用設定1s代替測量；sample→decision→apply無法分解 |
| helper-loss還原 | 正常可排程canary，最後有效decision至Query disabled ≤8s | 留永久cap、需要下輪30scollector才還原 |
| guardian-loss還原 | wrapper/helper仍活且OS可排程時，guardian被確認退出至Query disabled ≤8s | 以DB flag=false或closehandle冒充還原 |
| grant restore ACK | 無故障canary中，已commit grant至Query確認解除cap的p95 ≤2s；不能完成就明示restore_pending | 回報完全生效但cap仍作用於scope |
| 監控CPU | 將helper＋guardian＋新增wrapper等待開銷合計：1/10/50 Job平均≤0.05/0.10/0.25 CPU units；以process CPU-time delta量，不含fixture workload | 達不到時降scope或回A，不提高監控priority |
| tick成本 | 10 Job fast tick p95 ≤50ms；50 Job壓測p95 ≤100ms；任何超額都不catch-up無界loop | 每秒全機CIM／外部process spawn；lease安全檢查被長scan餓死 |
| 監控記憶體 | helper＋guardian合計Private Commit穩態≤160MiB；新增wrapper host額外Private Commit每個≤48MiB；1小時壓測後同樣idle條件不持續成長 | 只看RSS平均、忽略每command新增host；unboundedhandle/row/log增長 |
| 新增wrapper延遲 | healthy、不含admission wait的launch overhead p95≤500ms（cold start與warm start分列） | 啟動延遲被藏在queue wait或排除不報 |
| 儲存 | logs bounded；firstintent durability後才Set；正常1s sample不fsync；active manifests不被rotation刪除 | diskfull使restore被skip；寫入失敗仍tighten |
| Ledger | §7算例、所有邊界與concurrent route/direct tests通過；cap前後projected demand不因本工具cap下降 | 超過grace就消失；owner death立即刪survivingchildren；用WorkingSet共享頁重複扣除 |
| 穩定性 | deterministic與random traces不超過1cap、不超deadline、無舊seq續lease、正常步階間隔≥5s | 快速震盪、無限乘降、低壓後留永久baseline cap |

CPU cap效果canary必須使用固定N、saturated workload、無foreign parent限制的環境。實際多工作競爭下actual低於target可能只是沒得到CPU，不能因此判定cap出錯；這些effect thresholds不能機械套到I/O-bound工作。

### 11.3 A/B設計：分離控制收益與observer成本

三個明確版本：

- **A0：**P0確認的live baseline，固定58/4/4/3與原config，記錄原collector行為。
- **A1：**已修lifecycle／accounting、啟用相同Job launch與legacy exclusions的shadow版。helper/guardian與監控存在，但不Set CPU cap。
- **B：**A1完全相同基準，只把經核可的單一victim CPU policy啟用。

A1↔B比較「CPU控制本身」；A0↔A1量observer／新launch／計帳改動成本；A0↔B檢查最終使用者是否真的受益。不能只選A1↔B而隱藏基礎設施造成的退步。

**工作場景：**CPU-bound build/test、I/O-bound install、memory-heavy但有安全上限的測試、unmanaged CPU壓力、exempt/background/protected混合、root/child長短不同、正常無壓力場景。不得刻意逼近OOM來驗證；用mock injection驗reserve不足，真實壓測設操作停止條件。

**桌面測量：**使用自己建立的Normal-priority Win32 message-loop probe，量message enqueue→WndProc處理／paint排程延遲，固定在Job scope之外。它是UI-thread responsiveness proxy，不等同真實鍵盤到螢幕或RDP network latency。另在相同IDE／terminal做一組固定、非私密的互動動作並記錄卡頓；不收集使用者鍵鼠內容、prompt或畫面內容作telemetry。

**方法：**每個主要場景至少10對paired runs；採AB/BA交錯、預先固定order seed。每次在上一run Job empty、CPU/Commit回baseline、cap audit為disabled後開始。固定commit、資料集、task count、cache冷暖、power plan、foreground probe、collector範圍；記錄OS build、N與thermal/power異常。不得只截一段最漂亮的CPU graph。

**報告：**每pair的foregroundp50/p95/p99、workload makespan、completed units/min、queue wait p50/p95、time-in-state、peak private Commit/physical、minimumheadroom、monitor CPU/Commit、APIerrors、restoretime、coverage。列paired差異與變異；樣本小就說樣本小，不用單一平均宣稱統計保證。

**建議promotion門檻：**

- CPU contention場景：B相對A1的foregroundp95 paired改善中位數≥15%，且絕對改善≥5ms；若A1本來p95<20ms，將該場景標為「沒有足夠需要控制的問題」，不能憑小百分比宣傳收益。
- 相同CPU場景：background整批makespan中位數劣化≤15%，吞吐中位數下降≤10%；queue wait單獨報，不以只算running時間遮住admission barrier代價。
- 無壓力／I/O／memory主導場景：B不應施加不相關cap；makespan與foregroundp95劣化不超過5%且不超出實測noise的合理範圍。負載噪音太大就補配對資料，不直接判pass。
- Physical/Commit headroom不得因新admission overbooking而失守；若既有／unmanaged／exempt負載造成不足，清楚區分，B不能把它宣稱已防止。不得出現新的持續性記憶體滯留問題而只報CPU改善。
- A0→B若總體成本／互動效果倒退，即使B勝過A1仍不promotion。沒有證據證明CPU是主要瓶頸，就維持admission-only。

### 11.4 rollout與停止條件

`off → shadow → isolated canary → explicit limited enrollment`。

每次promotion保存：code/config/capability版本、test結果、允許scope、回滾指令及健康deadline。mode文件寫入不代表服務已切換；需guardian ACK、cap inventory與registry revision一致。合併PR不自動啟用使用者所有agents。

任一安全invariant失敗、restore unverified、exemption race、未知foreignJob、repeatedobserveroverrun，立即停止新增enrollment/tightening並restore。效果不佳也停止promotion；不增加victim數、降低floor或縮reserve來維持故事。

### 11.5 真正的rollback protocol

以下CLI名稱是P3需實作的runbook介面，不是目前已存在命令。

```text
1. adaptive-mode --mode off --drain
2. adaptive-recover --restore-only --verify
3. adaptive-audit --require-no-active-caps
4. 等managed Jobs自然empty，或保持guardian＋exclusion繼續drain
5. audit確認lifecycle/accounting全部finalized後，停helper/guardian supervisor
6. 才考慮回退binary／legacy writer設定；保留additive DB與audit
```

詳細順序：

1. **Freeze：**設desired mode off、禁止新managed enrollment／policy tightening；保留restore與lifecycle服務。對新非豁免啟動設recovery barrier。
2. **Fence：**確保只有一個正常／恢復writer。guardian不健康時先隔離本工具舊guardian，不kill workload。
3. **Restore：**逐一Query所有manifest所列owned Jobs，compare-and-restore CPU control disabled；也處理audit未commit的pending intents。API query失敗不能跳過。
4. **Verify：**實際Query flags/rate、capabilitycanary必要時量解除效果；此時才能報「本工具cap已解除」。`config=false`、DB row刪除、closehandle、CPU暫時下降都不算證據。
5. **Reconcile accounting：**存活Job保持allocated/reservation、guardian/registry/exclusion；root退出不釋放children。freshuncappedsamples完成後可依共同ledger恢復admission。
6. **交回舊writer：****只對已empty/retired scope交回。**存活Job在off狀態仍保持exclusion，不讓舊priority/IO/trim突然接手，亦不能宣稱已移出Job。
7. **Uninstall／binary rollback：**只有所有managedJobs empty或相容lifecycle/recoveryshim仍在時才停止guardian。若未empty，回傳`rollback_draining`，不是`rollback_complete`。舊binary的owner/TTL cleanup不能重新清掉managedrows。
8. **資料：**保留exemptions與新live帳本，不恢復舊DB備份蓋掉它們；schema只做向後相容停用，不在incident裡drop tables。pending/conflicting manifests保留供診斷，不刪history掩蓋問題。

rollback期間使用者自行結束工作是另一個明確操作，不是scheduler偷偷做的恢復步驟。作業系統原有的foreign限制不屬於本工具可解除的範圍。

---

## 12. 風險、未決事項與有界 capability spikes

### 12.1 把未知轉成可停止的工程問題

以下不是交給使用者回答的技術問卷。Codex 應在隔離環境取得證據，依明確分支繼續或停止。數量是**測試工作量上限／起點**，不是開發耗時承諾；無法在界內確立能力就記錄 unsupported，不能不斷擴張平台、改政策或試到碰巧成功。

| Spike／對應階段 | 必須回答的問題 | 有界實驗與輸出 | 通過後／未通過時的裁決 |
|---|---|---|---|
| **S1：Job 建立、rate denominator、解除能力／P1** | 實機 JOB_LIST 是否可用？自己的 Job 是否在 user code 前成立？新 Job 的 rate 是否以已知整機 CPU 為分母？具名 Job 能否 reopen 並真的停用 cap？ | 僅當前實機、隔離同機測試環境及一個既有 Windows CI 環境，最多3種；每環境測正常、foreign parent、可取得的 RDP/DFSS 條件。每個支援 case 做10次建立→set/query→disable/query。CPU effect 每次固定30s窗口；記錄 OS/API錯誤，不為湊矩陣安裝RDS。記錄 disabled ABI encoding 與 consumption。 | 真正通過的環境才寫 capability allowlist。缺 Job-list／未知 parent denominator／DFSS失敗／不能還原，就 `admission_only`；不改成 suspended fallback、breakaway 或 weight。 |
| **S2：launch 語意、coverage、collector 子樹／P1** | PS5.1與已安裝pwsh能否保留原cmd語意、標準I/O、退出碼？新 manager 是否獨立於 collector timeout tree？local runner 是直接 child 還是 broker？ | 跑 §4.5 的固定 cases，每 host 每 case 至少3次；fast-exit/child-survival 各20次。以本工具fixture記錄父子birth與Job membership，模擬 collector timeout，不碰真實agent。明確列 supported shell/host，不新增未安裝shell。 | 啟動語意或containment不確定的host不啟用managed；broker work維持unmanaged。collector kill subtree問題沒隔離前，不能把guardian或精準localadapter接進該路徑。 |
| **S3：單一writer與故障恢復／P1，P3/P5再跑** | wrapper/guardian/helper死亡、Set與audit之間死亡、DB失效時，是否仍能還原？舊guardian復活會否重加cap？ | 固定注入：intent前、intent後Set前、Set後Query前、Query後audit前、root退出後、lease續租中、grant commit後restore前、guardian接管中。每點至少10次；每次fixture有自願結束機制與120s外部觀察截止。另測manager hang與恢復者競爭；記錄ownedJob API readback、mutex fencing與slot狀態。 | 任一wrong-writer、grant新限制、永久cap或假成功即阻擋active模式。共同故障只驗證獨立supervisor最終恢復，不把它算進8s單故障成績。 |
| **S4：counter與observer成本／P4** | Native memory API／EX2在實機是否可用？cached sampling能否符合1/10/50Job成本？多process成員是否過多？ | 三個固定規模，穩態至少10分鐘／規模，另一次1小時leak測試；同時跑會員增減與不可存取identity。記錄CPU units、Private Commit、handles、tick p95、subtraction=0比例與限額超時。 | 50Job失敗可只保留已驗證10Job範圍；10Job失敗則縮明確scope或回A。EX2缺失只可保守不扣除；導致嚴重准入損失就不promotion，不用共享RSS替代。 |
| **S5：live baseline與共帳完整性／P0/P2** | dirty Maintainer是否真有resource-v2 Commit guard？有沒有未接共同ledger的local入口／owner級release／舊cleanup？ | 一次allowlisted呼叫圖與檔案hash比對；direct與route兩入口同時競爭、waiter→wrapper、stop-hook、collector cleanup四種回歸組。找不到live依賴即列missing，不從舊root「推定應該如此」。 | baseline缺口未解決前，不做production patch/promotion。技術上可繼續隔離P1，但不把spike結果冒稱已整合live程式。 |
| **S6：是否真的值得adaptive／P6** | CPU是否主要卡頓來源？A1→B改善是否足以補償A0→A1成本、工作變慢與launch barrier？ | §11的預先登記paired A/B；最多兩個有理由、版本化的候選參數集合，每個都重跑相同資料。不得看完結果才換成功指標或只保留有利場景。 | 若兩組皆不能符合收益／安全／成本門檻，停止B promotion，正式交付A；下一輪要有新的瓶頸證據才另開研究，不無限調參。 |

上述120s只是某次故障fixture的**觀察截止**：達限即判該恢復測試失敗並保留診斷，不授權 kill 任意工作。測試cleanup只能操作自行建立且已核對identity的fixture；被測scheduler仍不能以kill達成「解除cap」。

### 12.2 明確保留的風險

**CPU cap 的 collateral latency。**Job中的console root、子工具、進度回報都分享同一 CPU cap；它不是只壓低純計算thread。首版不把guardian放進Job，也不把使用者互動app放進Job，但仍不能保證背景command完全沒有deadline或locking敏感性。明確background enrollment、60s intervention上限與真實tool A/B是減風險，不是證明無風險。

**Physical/Commit不是可硬回收配額。**本方案用估算與high-water保守准入；既有工作可以超出request，unmanaged或exempt也可以增加負載。不能保證永遠留下4GiB，能保證的是非豁免新准入不 knowingly 消費所要求的reserve，以及不把缺資料當作多出容量。遇到實測超額，回傳overage、不殺工作。

**保守floor可能降低使用率。**execution lifetime high-water不往下縮，加上缺EX2／membership時不扣除，會犧牲部分並行。這是首版明示代價。將來要回收allocation，需要可驗證的task phase或合作式工具契約；不在這一版以任意idle timeout縮額。

**Job沒有通用移出能力。**rollback撤的是Sentinel自己的CPU限制，不是把程序從Job剝離；正在存活的Job仍有lifecycle成本與legacy exclusion。使用者不能在live Jobs未drain時完整卸載相容recovery shim，卻期待同樣的恢復保證。[W1]

**恢復不是物理上的絕對保證。**磁碟毀損、所有witness同時消失、supervisor停用、OS無法排程、權限改變或外部競爭writer都可能破壞有界恢復。不得用「watchdog exists」省略這些條件；故障狀態與手動restore指令必須保持可見。

**same-user治理而非security sandbox。**隨機token、ACL與peer identity提供錯用隔離與跨logon保護，不能對抗同SID可讀寫本機資料、修改程序或冒稱授權的敵對agent。要抵禦此威脅需要獨立service identity／權限政策，非MVP。

**工具工作可能逃出可觀測scope。**透過service、既有daemon、RPC或外部provider執行的部分，不是wrapper Job的child就不能計為controlled。coverage不能因shell parent被納管就標全綠。[W1]

### 12.3 不需要補問就能採用的預設

本plan採「保持工作繼續、停止新的非豁免launch、撤除已知本工具限制」作故障取捨，不以持續限速交換看似穩定的CPU圖。capability失敗選A、production預設off、只有明確background新command能enroll；這些是本輪可決定的工程預設。

真正的使用者偏好是**日後要讓哪些command／session標記為background並啟用limited profile**。這不阻擋Codex完成off/shadow與隔離canary；不能為了省這個選擇而自動納管所有agents。啟用不是本planning回合的動作。

---

## 13. 交給Codex的凍結契約與完成定義

### 13.1 policy profile 起點

以下JSON是 `config/adaptive.example.json` 的**規劃範例**，不得整份覆蓋使用者既有config。58GiB、兩個4GiB與max3仍由既有共用政策驗證；不要再增加能與原值矛盾的第二組adaptive memory budget。

```json
{
  "schema_version": 1,
  "mode": "off",
  "max_enrolled_jobs": 10,
  "max_active_caps": 1,
  "eligible_roles": ["background"],
  "eligible_priorities": ["P2", "P3"],
  "sample_interval_ms": 1000,
  "sample_max_age_ms": 3000,
  "cpu_window_min_ms": 500,
  "cpu_window_max_ms": 1500,
  "attribution_max_skew_ms": 100,
  "high_cpu_pct": 90,
  "high_samples": 3,
  "baseline_samples": 5,
  "victim_min_cpu_units": 1.5,
  "victim_min_machine_busy_fraction": 0.10,
  "retreat_l1_fraction": 0.75,
  "retreat_l2_fraction": 0.50,
  "retreat_l2_after_ms": 10000,
  "cap_floor_cpu_units": 1.0,
  "normal_change_min_interval_ms": 5000,
  "recovery_cpu_pct": 80,
  "recovery_continuous_ms": 10000,
  "lease_ms": 6000,
  "intervention_max_ms": 60000,
  "victim_cooldown_ms": 60000,
  "fault_backoff_ms": 300000,
  "prelaunch_lease_ms": 30000,
  "lifecycle_heartbeat_ms": 30000,
  "admission_release_uncapped_samples": 5,
  "slow_required_counter_max_age_ms": 90000,
  "sample_ring_frames": 120,
  "memory_member_scan_max_per_tick": 256,
  "sampler_work_budget_ms": 100,
  "log_max_bytes": 20971520,
  "log_retention_days": 7
}
```

validation不得只檢查型別：`0<recovery_cpu_pct<high_cpu_pct<=100`、`0<l2_fraction<=l1_fraction<1`、`lease_ms>sample_max_age_ms`、正常change interval小於intervention期限、mode/role/priority只允許已知枚舉。`max_active_caps`在MVP只能是1；提高到2不是普通config調參，是需要新review的scope change。Shared policies若不是58/4/4/3就回報policy mismatch，不能由helper自行修正live config。

### 13.2 ControlProposal與Acknowledgement的最小契約

除了FastFrame與ExecutionSpec，以下欄位不能由Codex自行省略。

| 契約 | 必填欄位／不變式 |
|---|---|
| `ControlProposal` | `schema_version`、`request_id`、`execution_id`、`guardian_epoch`、`policy_epoch`、`decision_seq`、`sampler_epoch`、`sample_seq`、`clock_epoch`、`config_revision`、`registry_revision`、`exemption_revision_seen`、`decision_tick_100ns`、`sample_window_end_tick_100ns`、typed `target`、`reason`；helper引用的exemption revision不能取代guardian重新讀取authority |
| `target` | `kind=cpu_rate`；`mode=disabled|hard_cap`；hard_cap時有有限`target_cpu_units`、合法`cpu_rate_bp`、已驗證`denominator_logical_processors`；disabled沒有「0 units」的語意 |
| `ApplyAck` | `request_id`、`action_id`、execution/epoch/seq、`result=APPLIED|RENEWED|RESTORED|REJECTED|UNVERIFIED`、`applied_flags`／`applied_rate_bp`及有效性、`queried_tick_100ns`、`lease_deadline_tick_100ns`、`intervention_deadline_tick_100ns`、`reason`、`win32_error`；不適用的值用null，不能填0冒充成功 |
| `GrantAck` | `grant_id`、`grant_state=recorded|active|revoked`、原`expires_at`、`exemption_revision`、`enforcement_state=restored|restore_pending|not_applicable`、受影響的owned execution IDs；同idempotency key不建立第二份grant也不延長期限 |
| `LifecycleAck` | execution/reservation唯一binding、`state`、`state_revision`、`launch_claim_state`、`root_outcome`與`job_empty_verified`分列；`root_outcome=success`不表示reservation已釋放 |

**lease由guardian決定。**helper不能自報一個任意遠的deadline。guardian使用自身同時鐘域的now、sample age、policy常數及原intervention deadline建立期限；設定 `lease_deadline=min(now+lease_ms, sample_window_end+lease_ms, intervention_deadline)`，不得讓一個已接近freshness上限的舊sample在剛收到時重新取得完整6秒；重試同seq只回原ACK，不續命。RENEWED必須引用同一仍有效applied action；新的metadata ACK不能隱藏readback mismatch。

**fresh frame不足以清理pending。**只見最新全機CPU很低，不能清除未ACK的launch、unknown owner或active child的預約。資料的newness與lifecycle的completeness是不同判準。

### 13.3 本輪提示的逐項對應

| 要求 | 文件位置 |
|---|---|
| 先批判原提案與SELF-GRILL，至少五個實質缺點 | §1，16項hostile findings，含恢復、帳本、豁免、交接缺口 |
| 至少三架構比較並選最小可用方案 | §2，B-min與A fallback、C/DRF/AIMD延期 |
| 唯一writer、角色生命周期、legacy交接 | §3、§7.5、§8 |
| task/session/app/job、nested、啟動、取消與後代 | §4、§7.4 |
| schema、單位、denominator、clock、freshness、錯誤、成本 | §5、§7.6、§13.1–13.2 |
| 狀態機、觸發、retreat、floor、cooldown與恢復 | §4.2、§6 |
| measured/pending/allocated/desired/applied、grace/TTL、兩DB與公平 | §7 |
| Windows APIs、權限、nested/DFSS、真實restore | §8、S1–S3 |
| helper/wrapper/collector、DB/IPC/clock/grant/API故障 | §9 |
| 檔案與函式級階段、依賴、進入下一階段證據 | §10，P0–P6 |
| simulation/canary/真實agent/桌面A/B與rollback | §11 |
| 未決事項不退給使用者，有界spikes | §12 |
| 來源事實、現況、建議與未驗證界線 | §0及各節引用；§14完整來源 |

### 13.4 Codex結案checklist

- [ ] 已對齊live dirty baseline，保留原修改與機密資料；沒有把snapshot複製成production source。
- [ ] P0至目前階段各有獨立diff、測試命令、exit結果、環境與不可驗證項目；沒有以skip冒稱Windows通過。
- [ ] 58GiB／physical4GiB／Commit4GiB／3個grants保持原語意；同一execution只有一個allocation。
- [ ] 原命令只啟動一次；CreateProcess前已具備管理scope；late children不因root退出／TTL被清帳。
- [ ] guardian是正常唯一actuator，old writer不能碰新scope；helper不具正常Set路徑。
- [ ] grant與Set的兩種競爭順序、RPC鎖邊界與START_UNKNOWN/barrier的交錯都有測試。
- [ ] 任一cap的原值、intent、readback、lease及實際restore都可追溯；manager故障不以kill workload清理。
- [ ] measurement/accounting不能因cap下降擴額；stale／unknown不放行、不續restrictive lease。
- [ ] observer成本與對真實工作/桌面的影響各自有證據；A/B不過就停在A。
- [ ] rollback已在有活躍child的測試情境驗證，`off`／`draining`／`restored`／`complete`沒有混為一談。
- [ ] repository中的新範例config仍預設off；沒有因merge而自動部署或啟用全部agents。
- [ ] 結果報告明確說明「已實作、已測、未測、unsupported、未啟用」各是哪一部分。

**完成定義：**安全基礎可獨立交付；adaptive只在全部gate通過時稱為可啟用。若S1/S3或A/B失敗，正確產出是已驗收的admission/lifecycle改善、失敗證據與保持off的adaptive研究成果，而不是用未驗證Windows行為填滿功能表。

---

## 14. 來源索引與查證界線

### 14.1 Repository／交接來源

以下連結全部固定於本次閱讀的commit，不以未來branch HEAD代表本次審查。`.txt`為交接文字快照；它們不是應安裝的production source。函式與測試名稱是主要定位點，不把工具回傳JSON的行號當成程式行號。

**[R1] 提示與交接優先序。**
[GPT-PRO-PROMPT.md](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/GPT-PRO-PROMPT.md)、[handoff README](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/README.md)、[EVIDENCE-AND-ACCEPTANCE.md](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/EVIDENCE-AND-ACCEPTANCE.md)。支持固定約束、planning-only、快照優先、必備輸出與原驗收問題；不代表本文的新參數已被量測。

**[R2] 原提案。**
[docs/adaptive-agent-scheduling.md](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/adaptive-agent-scheduling.md)。作為待批判方案，不當作Windows行為的官方證據。

**[R3] SELF-GRILL。**
[SELF-GRILL.md](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/SELF-GRILL.md)。G01–G22的回答仍是設計假設；本plan的裁決優先於其模糊建議。

**[R4] 快照完整性與測試期望。**
[snapshot-manifest.json](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/snapshot-manifest.json)、[test_pressure.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/tests/test_pressure.py.txt)。`test_local_worker_uses_same_commit_guard`與[R8]的root Maintainer比對，支持「交接依賴待對齊」，不證明未提供的live檔案有bug。

**[R5] collector現有資料與寫入路徑。**
[collect.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/collect.ps1.txt)。重點為CIM/process sampling、CPU5m、`apply_process_priority_policy` stage、`Set-IoPriority`、RAM trim、status發布與orchestrator tick。

**[R6] bounded collector與恢復。**
[collect-scheduled.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/collect-scheduled.ps1.txt)、[collector-health.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/collector-health.ps1.txt)、[bounded-query.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/bounded-query.ps1.txt)、[test_collector_recovery.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/tests/test_collector_recovery.ps1.txt)。只支持所讀到的timeout／health流程；local runner實際scope仍需S2。

**[R7] 豁免authority與回歸測試。**
[exemptions.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/sentinel/exemptions.py.txt)、[exemption-policy.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/exemption-policy.ps1.txt)、[test_exemptions.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/tests/test_exemptions.py.txt)、[test_exemption_policy.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/tests/test_exemption_policy.ps1.txt)。重點是max3、BEGIN IMMEDIATE、expiry/idempotency、scope、explicit attestation與legacy restore。

**[R8] 現有帳本、准入、CLI與local route。**
[coordinator.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/sentinel/coordinator.py.txt)、[pressure.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/sentinel/pressure.py.txt)、[sentinelctl.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/sentinelctl.py.txt)、[test_coordinator.py.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/tests/test_coordinator.py.txt)、[root Maintainer（較舊）](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/sentinel/maintainer.py)。已讀的Coordinator准入／cleanup／release、Maintainer `_pool_usage`／route段落支持本文現況分析；非全repo安全審計。

**[R9] wrapper與hook handoff。**
[invoke-sentinel.ps1.txt](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/docs/planning/adaptive-scheduler/source-snapshot/scripts/invoke-sentinel.ps1.txt)、[hooks/sentinel-gate.py](https://github.com/stantheman0128/resource-sentinel/blob/3ab1945885da0ef1b21d856329d7d8f7e2daf79f/hooks/sentinel-gate.py)。支持app ancestor identity、cmd啟動／finally release與直接wrapper避免重複預約等現況。

### 14.2 官方API與原始研究

查閱日期：2026-09-19。官方文件支持API語意及限制；**不支持本plan自行提出的cap比例、lease秒數、監控預算或A/B收益門檻已是最佳值**。

| 編號 | 官方／原始來源 | 本文使用的範圍 |
|---|---|---|
| **W1** | Microsoft：[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) | Job membership／繼承與broker邊界、accounting、completion通知限制、object存續與KILL_ON_JOB_CLOSE。不能把close handle等同解除限制。 |
| **W2** | Microsoft：[JOBOBJECT_CPU_RATE_CONTROL_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information) | flags、rate以1/10000表示、relative weight與hard cap差異、nested denominator、DFSS限制。disabled的實際binding另由S1驗證。 |
| **W3** | Microsoft：[UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) | JOB_LIST在建立程序時指定Jobs、最低OS條件、HANDLE_LIST與handle inheritance。不是所有PowerShell host相容的證明。 |
| **W4** | Microsoft：[SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject) | CPU rate class、存取權利、DFSS的ERROR_NOT_SUPPORTED；用Set回傳與Query／效果共同驗證。 |
| **W5** | Microsoft：[PROCESS_MEMORY_COUNTERS_EX2](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2) | PrivateUsage與PrivateWorkingSetSize不同、API／OS版本可用性。缺功能不改用shared RSS扣帳。 |
| **W6** | Microsoft：[GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes) | CPU time、kernel包含idle、processor-group限制。CPU units公式是依該counter語意的計算。 |
| **W7** | Microsoft：[Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs)、[AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject) | hierarchy、繼承限制、assignment權限與可能失敗；不作首版post-spawn assignment方案。 |
| **W8** | Microsoft：[QueryInterruptTimePrecise](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise)、[Interrupt Time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/interrupt-time) | interrupt-time時鐘與wall-clock分離；sleep、runtime continuity與租約失效仍依本plan明確處理，不推導硬即時保證。 |
| **W9** | Microsoft：[Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)、[GetNamedPipeClientProcessId](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid) | 明確ACL、client PID查證、不能依賴預設寬鬆權限；不代表可以對抗同SID敵對程序。 |
| **W10** | Microsoft：[GetPerformanceInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getperformanceinfo) | 全機performance memory資訊的官方取得路徑；欄位單位必須按結構PageSize處理。 |
| **W11** | SQLite：[ATTACH DATABASE](https://www.sqlite.org/lang_attach.html) | WAL下不能宣稱多個attached databases的跨DB crash atomicity；本文以各DBauthority、短mutex及reconcile設計，不假造跨store ACID。 |
| **W12** | Ghodsi et al., NSDI 2011：[Dominant Resource Fairness: Fair Allocation of Multiple Resource Types](https://www.usenix.org/conference/nsdi11/dominant-resource-fairness-fair-allocation-multiple-resource-types) | 原研究入口，用來辨別公平分配問題；本文不採DRF，亦未援引其定理證明此實作公平。 |
| **W13** | IETF：[RFC 5681 — TCP Congestion Control](https://www.rfc-editor.org/rfc/rfc5681.html) | AIMD的TCP原脈絡；不把其network congestion語意當Windows CPU/Commit控制器的穩定性保證。 |

**最後裁決：先證明scope準確、帳不會少算、限制真的可撤回，再談控制收益。任何一項缺證據，MVP都應停在已驗收的admission-only，而不是默默擴大控制權。**
