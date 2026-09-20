# Resource governance：研究、P3–P6 對照與後續實作入口

日期：2026-09-20（Asia/Taipei）  
由 GPT-6 Astra Pro 協助整理。  
狀態：**研究／後續建議，不是已實作功能、部署指令或驗收通過宣告。**

## 讀法與範圍

本次只新增文件與導覽，不改動 runtime、hooks、Scheduled Tasks、正式 config、資料庫、權限、豁免或既有 adaptive 啟用狀態。沒有在使用者 Windows 主機執行測試，沒有呼叫 Jev API，也沒有把私人 workload、命令、程式碼或 telemetry 傳給模型供應商。

- [LANDSCAPE-2026-09-20.md](LANDSCAPE-2026-09-20.md)：相同問題與相鄰工具的分類、逐項差異、值得借鑑的做法、商業價值與替代基線。
- [LEARNING-AND-DECISION-DESIGN.md](LEARNING-AND-DECISION-DESIGN.md)：歷史→預測→實測→誤差→更新閉環、持久化排隊／續跑、資料契約、Jev 的可選位置、驗收與回退。
- [既有 IMPLEMENTATION-PLAN](../adaptive-scheduler/IMPLEMENTATION-PLAN.md)：原 P0–P6 的安全與 native control 計畫；本文件不取代或改寫它。

### 證據基準

| 項目 | 本次固定版本／證據 |
|---|---|
| 主分支 | `master`：`0b2f37819a2d4f68299fbec3fe619a4d05ba4749` |
| 原規劃分支 | `codex/adaptive-scheduler-planning`：`68b14eb0a2db19e709934e9beb08c30322326535` |
| 本次實作分支閱讀基準 | `codex/adaptive-scheduler-implementation`：`6efa302e84d6a156ba49f55812b7ef53cf879565` |
| 事實範圍 | GitHub 已提交文件、所讀程式及 commit 說明；不包括本機未提交／未推送的修改或未公開驗收證據 |
| 外部研究 | 2026-09-20 查閱的一手 README、產品／API 文件；不是完整安全審計或本機效能實測 |

外部 README 宣稱、有程式碼、有單元測試、Windows 效果驗證、使用者體驗 A/B、商業採用，是不同證據等級。本文不以其中一種代替其他種類。

## 1. 使用者真正要完成的事

使用者希望一次提交很多不同 provider 的 coding agent 工作，超過可用資源的部分排隊；有資源後自動執行並接回原 session，不必反覆手動說「繼續」。同時讓前景看影片、日常操作或遊戲維持可用。

建議產品定位：**跨 Agent 的本機受管工作協調器：保護前景體驗、持久化等待、可靠續跑、用歷史改善資源預估。**

需要區分：

1. 很多已登記的邏輯 session／task，不代表很多完整 IDE、MCP server、browser、agent runtime 必須一直駐留。
2. 控制活動 runtime 的數量，與控制 build/test 等重命令的併行，是兩層不同准入。
3. 資源排隊不是任務失敗；模型停止產生 token 也不是失敗。應由程式持有等待與結果交付責任。
4. 不承諾無限活動 session、硬即時、零 OOM、遊戲完全不受影響，或前景已佔滿硬體時背景仍必定前進。
5. 自動續跑只限經驗證、使用者授權的 adapter／入口，不等於接管任意第三方 GUI 對話。

## 2. 先前 P3–P6 各是什麼？

P 代表既有計畫中的 phase，**不是完成百分比，也不是 P0–P3 任務優先級**。以下是原計畫 §10 的意思，不是本輪重新編號。[R1]

| 階段 | 白話目標 | 主要交付 | 退出條件摘要 |
|---|---|---|---|
| P3 | 先確認每個工作由誰啟動、谁可控制、出錯如何解除限制 | 正式 Windows Job launcher、唯一正常 actuator 的 guardian、IPC／身分驗證、豁免同步、舊 collector writer handoff | child 存活時不能提早釋放；off/shadow 零新 cap；guardian 故障可還原；不得誤控共享 UI 或有效豁免 |
| P4 | 更快量測並模擬決策，但先不真的限速 | bounded fast sampler/helper、純函式 policy／狀態機、shadow decisions、成本量測 | shadow 零 Set；freshness／時鐘／亂序正確；在不同 Job 數下量測 overhead；不是只跑幾個 unit tests |
| P5 | 用隔離的測試工作，證明 CPU 控制真的有效、真的可撤回 | 一個核可 canary execution、cap 效果／readback、故障與豁免競爭測試 | Windows 真實效果、restore、helper/guardian/wrapper 故障回復等 gate；不拿真實 agent 作故障 fixture |
| P6 | 在少量真實命令驗證是否值得啟用 | 固定 command/cache/workspace 的 A0/A1/B、前景 proxy、吞吐與完成時間、有限 release evidence | 比較控制收益與 observer 成本；符合原 gate 才交付 limited profile；不因 merge 自動啟用 |

前置 P0 是 live baseline 對齊，P1 是 Windows capability/recovery spikes，P2 是 lifecycle 與共同計帳。P1 某項受阻，不妨礙所有獨立純函式／資料工作，但會阻擋依賴它的 native control promotion。[R1]

### 截至本次 baseline 的進度：不能說 P3–P6 都完成

- `P2-EVIDENCE-SCOPE.md` 記錄 evidence context 在 SQLite 交易期間的存續保護；它明說真實 provider 的 peer handling、Job ownership、launch fencing、guardian reconciliation 仍須完成，S1–S3、CPU effect/recovery、overhead 與 A/B 不能算通過。[R2]
- `P2-NATIVE-FOUNDATION-RESULTS.md` 記錄已測的 native identity／retained allocation 基礎，同時明列不是完整 native lifecycle，也不是 P3–P6 promotion。[R3]
- **最新讀取 commit `6efa302` 已加入 `sentinel/adaptive/decision.py` 的 P4 純決策層。**commit 明寫沒有 caller，沒有 helper/sampler/proposal consumer/actuator 接線；profile parser 只接受 off，因此它是部分實作，不是 P4 gate 通過。[R4]

所以狀態應寫為：**P2 與後續基礎持續實作；P4 已有未接線的純決策元件；完整 P3–P6 驗收仍未被上述公開證據證明。**不要把某個模組存在、或測試數量增加，換算成整體完成百分比。本機可能另有新進度，下一位實作者必須重新對齊。

## 3. 歷史用量現在做到哪裡？

接入文件已描述 `orchestratorctl.py profiles` 的 P50/P90/P95；同一文件也明說 `AUTO` 仍是 bootstrap rule，profiles 供調整顯式需求，尚未自動改寫 task request。[R5]

roadmap 已提出「歷史峰值、分位數、預估誤差校正」，但設計方向不等於已完成 prediction→admission 閉環。[R6]

因此本輪新增的是：如何保留原始預測、收集真實結果、校準、建立 shadow baseline、評估小型 ML，以及處理等待／續跑。這不是原 P3–P6 自動涵蓋的功能。

## 4. 新建議使用 R0–R6，避免污染原 P 編號

下列全部是待實作研究 backlog；編號是追蹤 ID，不代表必須機械式依序完成。

| ID | 建議增量 | 接點／候選檔案（須先查 live tree；不是已存在宣告） | 驗收／回退 |
|---|---|---|---|
| R0 | 可評估的觀測資料與 immutable prediction records | 現有 execution ledger／profiles；可另設 `sentinel/profiling/`，採 additive schema | 可追溯預測版本、原始值、控制條件、量測品質；關閉新 recorder 不影響 release／recovery |
| R1 | 持久化 queue＋一個正式 session adapter 的結果交付／續跑 | 現有 orchestrator、runner、hooks；可另設 `sentinel/continuations/` | 長等待、重啟、lost ACK 不丟單／不盲目重跑；停止新 dispatch，保留 pending results；不必為此先啟用 CPU cap |
| R2 | 統計 profile＋誤差校準，先 shadow | 預測 façade、離線 evaluation；單一既有容量帳本 | 與固定類別比較低估、保留過量、coverage；fallback 不減少 active demand floor |
| R3 | 小型 tabular ML／Quantile Regression | 離線 trainer、模型版本與驗證報告；非 fast loop | chronological/job-group split，與 R2 配對比較；可直接切回統計，不需 DB 回滾 |
| R4 | 前景模式、可解釋等待、公平性與體驗驗證 | UI policy、queue policy、原 A/B harness 的獨立擴充 | 觀測與 admission-only 模式可先評估；若含 CPU actuator，須遵守 P3/P5/P6 gate；不偷改豁免 |
| R5 | Jev 的可選語意分類／軟路由實驗 | 純 optional adviser／feature extractor，不連 OS actuator | 模型 off/timeout 時 scheduler 正常；資料外送需授權；不能靠模型通過硬 gate |
| R6 | 有真實需求才接一個遠端 execution worker | 現有 worker registry／provider adapter | submit/status/cancel/result/unknown-submit reconciliation 全部端到端驗證；不把換模型當執行卸載 |

優先判斷：先修正可觀測性與可靠等待／續跑，再讓統計預測參與 shadow；ML 必須證明比統計多帶來收益；Jev 不成為上述工作的依賴。可並行做離線研究，但不要趁本輪把範圍擴成新的通用 orchestrator。

## 5. 不得改變的安全界線

沿用 live tree 與原 plan 的 58 GiB 全機 admission budget、physical/Commit 各 4 GiB headroom、最多 3 個有效豁免的既有約定；這些是原計畫政策，不是對所有機器適用的最佳參數。本文沒有授權調整它们。[R1]

- 不自動 kill 真實工作、不用週期 suspend/resume 或強制 trim 當記憶體釋放保證。
- 不讓模型改寫 user priority、授予／撤销豁免、操縱 PID、放行未經授權的 offload。
- 同一 execution／allocation 共用既有帳本；predictor 不是第二個容量 authority。
- 新 admission 的關鍵身分或容量 unknown 時保守拒絕；Jev unavailable 則退回本機既有規則，不讓非必要模型故障鎖住全機。
- 既有有效豁免仍按原規則處理與計帳。「遊戲優先」不能悄悄撤回授權；若豁免工作佔滿資源，應揭露無法保證前景體驗。
- queue lease、native control lease、provider session lifetime 是不同事物。通知失敗不能直接釋放仍在執行的資源。

## 6. 值不值得做：用對照組回答

工程判斷：這是有意義的自用／OSS 問題；但競爭者與簡單替代方案已存在，不能從「Agent 很熱門」推出市場規模。[詳見研究](LANDSCAPE-2026-09-20.md)

保留原 P6 的 A0（live baseline）、A1（相同 infrastructure 的 shadow）、B（相同基準加 CPU 控制）以隔離效果；另做產品對照：固定重工作併行、固定併行＋Process Lasso、統計預測、ML、ML＋Jev。不要直接把不同 observer、不同命令或不同 cache 的結果混成同一張改善率表。

主要觀測：前景 latency/遊戲 frame time 或影片 dropped frames（後兩者是另行 opt-in 的真實情境，Win32 UI probe 不能代替）；工作 makespan/throughput、queue age/飢餓、低估與失敗、人工干預次數、scheduler 自身 CPU/Commit/I/O、API 延遲／費用。

判定方向：在相近完成效率下更流暢，或在相近前景品質下完成更多工作。沒有這種增量時，就保留較簡單的方案，不為了 ML 或 Jev 而加依賴。

## 7. 給下一個 Codex session 的交接指令

> 先讀本 README、兩份研究／設計附錄，以及既有 adaptive-scheduler/IMPLEMENTATION-PLAN.md 和最新 evidence 文件。先輸出目前 HEAD、dirty files、P0–P6 的「元件已寫／接線完成／實機 gate」對照，不要從舊快照覆蓋 live working tree。這份研究不是要求一次實作 R0–R6；先選定一個增量，預設從 R0 的記錄契約與離線 baseline 或已核可的 R1 小範圍 adapter 開始。保留原始預測，不減少 active floor，不建立第二套容量帳本；逐步測試，記錄 Windows skipped/unverified。未獲另外授權，不啟用 native cap、不調 config／豁免、不呼叫付費模型、不外送資料、不啟用雲端 worker。不把研究內容或 portable tests 宣稱成 Windows／使用者體驗驗收完成。任何模型均可完全關閉。

## 原始來源（固定版本）

- R1：[IMPLEMENTATION-PLAN，原 planning commit](https://github.com/stantheman0128/resource-sentinel/blob/68b14eb0a2db19e709934e9beb08c30322326535/docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md)，特別是 §7、§10、§11。
- R2：[P2-EVIDENCE-SCOPE](https://github.com/stantheman0128/resource-sentinel/blob/6efa302e84d6a156ba49f55812b7ef53cf879565/docs/planning/adaptive-scheduler/P2-EVIDENCE-SCOPE.md)。
- R3：[P2-NATIVE-FOUNDATION-RESULTS](https://github.com/stantheman0128/resource-sentinel/blob/6efa302e84d6a156ba49f55812b7ef53cf879565/docs/planning/adaptive-scheduler/P2-NATIVE-FOUNDATION-RESULTS.md)。
- R4：[6efa302：pure P4 decision layer with no caller](https://github.com/stantheman0128/resource-sentinel/commit/6efa302e84d6a156ba49f55812b7ef53cf879565)。
- R5：[agent-integration](https://github.com/stantheman0128/resource-sentinel/blob/6efa302e84d6a156ba49f55812b7ef53cf879565/docs/agent-integration.md)。
- R6：[既有 roadmap](https://github.com/stantheman0128/resource-sentinel/blob/6efa302e84d6a156ba49f55812b7ef53cf879565/docs/roadmap.md)。
