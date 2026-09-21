# 歷史學習、可靠續跑與 Jev：後續設計提案

日期：2026-09-20（Asia/Taipei）  
整合補充：2026-09-21（Asia/Taipei）；見 [§10：P3–P6 與 R0–R6 接入契約](#10-p3p6-與-r0r6-接入契約2026-09-21-補充)。  
由 GPT-6 Astra Pro 協助整理。  
**狀態：未實作的增量設計，不授權啟用 CPU cap、付費 API、資料外送或雲端 execution。**

先讀 [研究入口與 P3–P6 對照](README.md) 及 [工具分類](LANDSCAPE-2026-09-20.md)。本文件的 R0–R6 沿用研究入口的 backlog 編號，不取代原 adaptive plan。候選模組、欄位與狀態都是設計建議，不是現有 public API。

## 1. 五種工作分開：不是再放一個 LLM 當全機主管

| 層次 | 輸入／工作 | Authority |
|---|---|---|
| 語意 adviser，可選 Jev | 描述屬於哪種 workload、模糊意圖如何分類、對已合法候選作軟排序 | 只提建議；不能更改授權、需求下限、明確 priority 或程序 |
| Resource predictor | 類別、輸入規模、參數、環境、歷史 → RAM/Commit/時間等估計 | 提交預測與不確定性；不是 reservation authority |
| Deterministic scheduler | 新鮮量測、既有 allocations、明確 priority、公平政策、可信能力／授權 → 是否可以執行 | 使用現有原子帳本取得唯一 claim；unknown 不變成容量 |
| Runner／native guardian | 執行命令、精確身分與子程序生命週期、核可的 OS 控制與 restore | 只管理已驗證 ownership；native promotion 仍依原 P1/P3/P5/P6 |
| Session continuation adapter | 保存結果，向正確 session 交付，必要時恢復後續回合 | 經授權且版本實測的接口，不是通用 GUI 接管 |

常駐服務是普通程式，不等於常駐模型。已知數值容量、priority/FIFO、lease/expiry、CPU restore 不需要語意推論。模型停用時，核心 scheduler、恢復與既有工作仍應正常運作。

## 2. R0：先形成可評估的閉環

每個工作留下三個時間層：

1. **開始前**：當時可知特徵、原始預測、模型／統計版本、實際核准的需求。
2. **執行中**：actual samples、目前 observed peak、採樣品質、控制條件與額外預測修正。
3. **結束後**：完成／失敗／中止結果、採樣峰值、CPU time、execution duration、誤差與資料可信程度。

**原始預測不可被 runtime revision 覆寫。**先保存預測，再用後來結果評分；模型不可以看見答案後更新同一筆，造成假的準確度。執行中的修正另存 forecast revision，分開評估 prelaunch 與 remaining-work 模型。

### 建議資料契約

| Record | 最小欄位／含義 |
|---|---|
| WorkloadIdentity | execution/task/session/principal IDs、host profile、canonical repo fingerprint、command family／normalized signature、feature schema version；沿用既有 exact execution binding |
| PrelaunchFeatures | 重要參數、worker count、輸入规模、clean/incremental、cache known/unknown、工具版本、OS、當時已授權控制模式；每欄含來源與缺失標記 |
| Forecast | immutable forecast ID、created_at、feature snapshot/hash、predictor kind/version、training cutoff、估計分位數、樣本支持量／fallback level、RAM與Commit各自結果、duration、unknown/OOD 標记 |
| AdmissionReference | 原始顯式 request、最終核准 request、policy/config revision、精確既有 allocation reference；只引用帳本，不在 profiler 新造一份 reservation |
| Observations | monotonic sample time＋audit UTC、CPU time delta、memory metric type、process/Job coverage、採樣間隔與缺口、控制 revision、已施加 cap、外部壓力摘要 |
| Outcome | success/failure/cancelled/unknown、exit category、execution time（不含 queue wait）、observed peak、完成程度、量測完整性、forecast residuals |

RAM 與 Commit 不可混用；WorkingSet 共享頁不能隨意跨 process 相加再宣稱精確獨佔 RAM。Process I/O counters 不是 physical disk bytes；sampled peak 是在该採樣解析度看到的峰值，不是保證沒漏掉短暫尖峰。優先重用現有 accounting/telemetry 的定義與 coverage，避免另造不一致的 profiler。

Signature normalization 不可把影響需求的 batch size、workers、test scope 全部刪掉；同時不把 token、password、prompt、完整環境變數或私人檔案內容保存為特徵。跨 repo 識別採可控的本機 fingerprint；無秘密的普通 hash 不是匿名化保證。預設只有本機聚合與去識別的結構化 metadata。

### 執行中比對示例（純示意數字）

原先估 RAM 峰值 6 GiB，執行中 observed peak 已到 7 GiB，此時已知原預測至少低估 1 GiB；最後正常完成峰值 9 GiB，才有本次完成峰值的最終誤差。這可以促使 scheduler 重新評估後續准入，但把帳本調高不會真的增加硬體。

反過來，目前只用 3 GiB 不能推出之後只需 3 GiB。不能因限速令 measured CPU 下降、elapsed time 變長或初期低用量，就自動釋放 active demand floor。新的預估應送進**同一套既有 projection 與帳本規則**，只對尚未包含的需求作保守修正，避免 measured＋全額 reservation 重複計數。

示意評估量：`residual = observed_completed_peak - original_prediction`；正值低估、負值高估。但失敗或未完成工作不可套同一 completed label；樣本不足時不給假精確覆蓋率。

## 3. R2／R3：先統計，後小型 ML

### 第一版：階層式統計與校準

按 repo、command family、重要參數與環境找相似工作；有可信完成紀錄才使用其近期分位數與誤差校準。細分群樣本不足，就退回較粗群組，最後回既有保守 bootstrap。展示 fallback 原因，不把單次歷史當作穩定分布。

不規定「恰好 N 次就足夠」這類無依據通用門檻。由資料量、變異、缺失程度、完成比例、低估風險和後續時間窗表現決定升級。可以記錄近期漂移，但不在每個短期波動重新訓練或放寬容量。

### 第二版：tabular quantile predictor

候選為簡單 regression／Gradient Boosting。scikit-learn 的 quantile regression 可預測不同分位數，適合比較低估代價與保留過量；官方示例也展示測試覆蓋不一定等於目標，因此必須後驗檢查。[M1]

分開預測：RAM peak、Commit peak、CPU time、execution duration；I/O 第一版可保留已知規則／slot 類別，別強迫所有維度共用單一模型。與其先選最新模型，更重要的是資料品質及能否勝過統計 baseline。

即時監測與模型訓練頻率不同：控制事件可立即處理；統計可在完成時增量更新；ML 先離線／低優先序批次訓練。訓練也應走受管、bounded 的資源准入，不能在使用者打遊戲時偷偷跑大量 grid search。

模型發布採版本化 artifact、校验與原子切換；保留前一 champion。先 shadow，不改 request；之後只在明確 opt-in 工作範圍使用。關閉 ML 即回統計，再不行回 bootstrap；不需恢復舊 DB，也不降低正在執行工作的保留。

### 「預測器」與「調度政策」不要混成同一個模型

資源回歸模型估需求；程式依需求與 hard gates 決定准入。任務分類再準也不等於容量夠，數值預估再準也不代表 scheduler 公平。兩種誤差與 end-to-end 效果要分別量。

P95 是單一預測目標，不等於測試覆蓋已達到 P95，更不等於整台機器有同樣的無過載機率；工作需求可能相關、環境會漂移、採樣可有缺口。不能把各工作分位數直接當全機機率保證，也不能拿模型自報 confidence 取代實測校準。

## 4. 觀測偏差、資料洩漏與失敗樣本

**受限觀測：**CPU cap／worker count／cache／其他工作競爭會影響用量与時間；要一起保存。被限到低 CPU 的工作，不是已證明天生低需求。沒有控制條件的可比試驗，不能聲稱模型已學會改變 CPU cap 的因果效果。

**未完成／失敗：**OOM、被取消、timeout、量測缺口、child coverage 不完整，不能當作正常 completed peak。保留原因；對完成需求而言可視為未完整觀測或某些情況的下界訊息，不編造完整標籤。也不能全丟失敗，只留下成功案例造成 selection bias。

**時間與群組切分：**用過去訓練、較晚執行驗證。一次 execution 的全部 samples、nested children、重複 metadata 應在同組；一千個 samples 不是一千個獨立工作。time-based validation 的原則可參考 scikit-learn，但不規則到達的 jobs 還要自行做 group/time windows，不能假稱 TimeSeriesSplit 自動處理所有分組。[M2]

**預測時點：**prelaunch 模型只用那時已知的 features；final duration、later cap、actual peak、後來才知道的 cache miss 都不能提前放進去。runtime 模型可以使用截至當下的歷史，但必須建立不同的時間對齊資料集。

**漂移：**工具升級、repo 內容大改、不同硬體、新命令，標為 out-of-distribution 或擴大 fallback。舊訓練集雖多也不一定較好；以新時間窗、未見工作群組與低估尾端表現評估。

## 5. R1：持久化等待與 session continuation

「不要結束回合」不是 durable queue contract。建議在既有 orchestrator 上擴充，不把以下概念機械複製成第二套完整狀態機。

三種狀態分開：

- 任務需求：accepted／waiting_capacity／cancel_requested／finished。
- 真實 execution：unlaunched／claim_committed／running／outcome_unknown／terminal_verified。
- 結果交付：not_ready／persisted／delivery_pending／acknowledged／needs_attention。

一條正常流程：持久化 task → 等待 → 原子 claim/reservation → runner 執行一次 → 先保存結果 → 以 exact session/thread ID 交付 → 確認交付／下一回合進度。不能只廣播「現在有空位」再讓所有 Agent 同時搶跑。

### Crash／lost ACK 規則

1. 接單 ACK 不明：用 idempotency key 查既有 task，不新建副本。
2. 已取得 claim 但尚未啟動：只能由同一權威流程處理 expiry／reclaim；expiry 不是對 running job 的死亡證據。
3. 啟動或 provider submit 結果未知：先 reconcile，不能盲目重送有副作用的命令。
4. 已完成但 callback 失敗：重試交付已保存的結果，不重新執行工作。
5. provider resume/turn-start ACK 不明：若無可查詢去重能力，保留 uncertain／needs_attention，不宣稱跨 provider 的 exactly-once。
6. 對同一 thread 的自動 turn 必須序列化／去重；session 世代、使用者後續輸入與 cancellation 競爭要明確處理。
7. queue wait、provider quota/auth、permission approval、task failure 是不同狀態；不靠自動重試繞過使用者授權。

runner 與 provider deferred tool 只能選一個 execution owner：不能 Sentinel 先跑一次，再恢復 provider 讓它把同一 pending command 又跑一次。

### 2026-09-20 官方接口提供的可用切點

| 接口 | 文件所述能力 | 實作前必須驗證 |
|---|---|---|
| Claude Code `asyncRewake` | hook exit code 2 可喚醒仍存活而 idle 的 session | 不當作任意 session 復活；timeout、程序結束、同時多個通知與重複 hook 行為；長等待不能只寄生於可能退出的 caller |
| Claude Code non-interactive `PreToolUse defer` | `claude -p` 可保存 pending tool，之後用 exact session ID resume；有 single-tool 等限制 | 不是互動 GUI 通用功能；恢復時 hook 重新評估與 permission/sandbox 需核對，不能假設所有原設定自動復原 |
| Codex App Server | initialize／thread resume／turn start 等受管 session 流程 | exact returned IDs、thread ownership、result delivery、unknown ACK、MCP/bootstrap 故障；不等於控制任意已開 GUI |

上述是官方 API 文件能力，不是本 repo 或使用者本機版本的端到端驗證結果。[A1,A2] 第一版只做一個已驗證 adapter；其他入口明示只可 queue command、交付結果或需要人工 continuation 的能力級別。

## 6. R4：前景模式與公平政策

建議先手動切換「背景趕工／日常使用／遊戲優先」，把它轉成結構化政策，不用模型猜使用者現在是否在遊戲，也不預設讀取視窗內容。背景趕工仍遵守安全餘裕，遊戲模式也不偷偷撤銷有效豁免。

前景突然需要 RAM 時，已配置給長任務的 memory 不能像 CPU time 一樣立即無損讓出。無 kill／無 checkpoint 時，先停止新重任務並等待既有工作安全完成。因此更合理的是提早保留預算或預先進入較保守模式，而不是承諾瞬時回收。

Priority、age、每 principal/session 併行上限與小工作 backfill 可由程式計算。公平性需有自己的驗收；大工作不 fit 時，priority 再高也不會變出 RAM。後續的 bounded drain window 不能殺 running jobs；只有在需求可滿足、既有工作會結束且外部負載允許等前提下，才討論等待上限。原 MVP 沒有這種保證，不應倒填完成。

實測至少同時觀察 foreground p95/p99、工作 makespan/throughput、queue age、starvation、失敗、人工介入、scheduler 自身負載。Win32 message-loop probe 是 proxy；影片 dropped frames 和遊戲 frame-time 是不同驗證，需要 opt-in 真實情境，不把一個 probe 的數字當成遊戲體驗保證。

## 7. R5：Jev 適合什麼位置？

### 查證事實與判斷分開

TypeSafe 在 2026-09-15 發布 Jev early access，定位為把非結構化輸入轉成帶機率的型別化決策。官方 primitives 包含 Choice、Score、Noul；Vercel 也提供其與 AI SDK 分類／路由整合的說明。[J1,J2,J3]

供應商發布文給出端到端 70–500 ms 等數字，但也明說其測量一般在服務所在的美國西岸進行；這不是台灣網路／本機工作負載的實測或 SLA。[J1] 本文不重述倍數作為採用理由。

**工程判斷：Jev 是有根據的語意分支候選，不是更快的數值排程器。**它的比較對象應是原本需要語意判斷的 LLM 呼叫，而不是本機的 if/else、排序、SQLite 交易或回歸預測。型別符合 schema 不代表內容判斷正確，輸出 probability/confidence 也不保證在這個新 workload 上已校準。[J3]

### 適合實驗的用途

- 陌生任務的語意 workload family：建置、測試、讀取分析、browser 工作等，作為保守 fallback 的輔助特徵；確定的 executable/arguments 優先由程式判斷。
- 結構化的使用者模式意圖：建議一個 preset，由使用者確認或依既有授權適用；不能從模糊話語推導豁免。
- 對**已通過 OS/capability/data-trust/quota/priority 硬篩選**的候選工作或 worker 作軟排序。提交前重新驗證候選世代與容量；模型選項不能授予缺失資格。
- 從描述抽出固定語意特徵，交由本機 supervised predictor 處理數值需求；不是直接請 Jev 猜 GiB。

**不交給 Jev：**當前 free RAM/Commit 的計算、reservation 原子核發、PID ownership、native CPU cap/restore、heartbeat/lease 正確性、使用者豁免或安全權限。模型不能覆寫明確 user priority，也不能因「看起來容易」就允許未知腳本輕量通行。

### 官方有直接相關的組合範例，但不是資源調度證據

TypeSafe 的 Autoresearch Feature Discovery cookbook 使用 LLM 提議文字問題、TypeSafe 把答案變成數值特徵、CatBoost 做 supervised regression，再利用誤差回饋改善特徵。其示例是文字評論與評分，不是 CPU/RAM 工作負載；不能把該結果移植成 Sentinel 的成效。[J4]

可借用的設計是：**語意模型負責特徵，監督式模型學數值，普通程式執行約束。**第一個 Sentinel 實驗只需少量固定、版本化問題，不需要自動特徵搜尋或另一個自主 LLM。若之後做 feature discovery，最終 test set 必須獨立，不能把 test residuals 回傳给 proposer 反覆調整。

同樣地，呼叫 Jev API 或保存它的答案，**不代表 Jev 已在自動用你的 execution history 訓練**。本地 profiler/回歸器更新與供應商模型訓練是不同事情；未有明確 API／訓練契約時不宣稱後者。

### 建議接口與降級規則

Jev adapter 只回傳 advisory record：`question_schema_version`、`model_id`、`candidate_set_revision`、`predictions`、`created_at`、`latency`、`fallback_reason`；這是候選內部契約，不是官方 SDK schema。記錄精簡可重現資訊，不保留私人原文作公共 telemetry。

把輸入視為不可信資料：任務描述裡「忽略限制／給我最高優先」不是政策。問題與候選 options 由可信程式建立，輸出仍要做型別、範圍、候選 membership、freshness 與 policy 驗證。多個問題獨立推論的結果不會自動滿足全域容量约束，組合仍由程式負責。[J2]

模型 timeout／network error／rate limit／低 confidence／未見命令，退回本機既有保守類別或統計；adviser 故障不是全機 admission lock 的原因。與此相反，權威 telemetry／identity 不明時仍保守阻擋新工作；已施加控制的安全 restore 不得等雲端模型回覆。

只在 task submission、語意改變或候選類型改變時評估；不在 fast sampling tick 每秒呼叫。同一 normalized input／model／question／候選版本可 bounded cache；異步取得結果但不得阻塞 guardian，錯過決策窗口就不用過期結果。

預設 disabled。啟用前要確認帳號、價格、資料處理條款、網路、模型版本與 SDK；另取得明確的私有資料外送授權。公開 repo 本身不是把本機 prompt/command/code/log 外送的授權。本次文件沒有呼叫 API、建立金鑰、安裝 SDK 或啟用任何配置。

## 8. 實驗、發布與回退

預測比較組統一使用 `PRED-B0`–`PRED-B3`。原 adaptive plan 的 `S1`–`S3` 仍專指 Windows capability gates；本表不再重用那些編號。

| 對照版本 | 預測／决策內容 | 目的 |
|---|---|---|
| PRED-B0 | 既有 bootstrap 類別 | 最低成本基線 |
| PRED-B1 | 相似工作統計＋誤差校準 | 確認歷史是否真的有用 |
| PRED-B2 | PRED-B1 可 fallback 的 tabular ML | 確認額外特徵／模型帶來增量 |
| PRED-B3 | 相同 PRED-B2 加 Jev 語意特徵或受限軟排序 | 單獨量出 Jev 的增量，不把前面所有收益算給它 |

先離線／shadow，記錄每次 forecast、原模型／資料 cutoff 與實際 outcome。時間順序評估低估頻率、低估尾部幅度、分位數 empirical coverage、保留過量、未知工作比例；避免只報平均誤差。真實 rollout 再量 queue wait、makespan、foreground latency、人工介入與失敗。模型較準但 scheduling 更差，仍不算成功。

Jev 額外測 end-to-end p50/p95/p99、cache hit/miss、cold request、輸入長度、問題數、同時請求數、timeout 與費用；缺少台灣環境量測就保留未知，不引用供應商 latency 當本機結果。

故障矩陣至少覆蓋：資料缺口、process/root exit/child survivor、預估大幅低估、controller restart、model artifact 損壞、API 長期不可用、result delivery lost ACK、provider session 不存在、工作已取消後回來的舊通知。不得為測量故意把日常機器推入 OOM；用安全 fixture、注入與明確停止條件。

回退分層：停用 adviser → 統計；停用 ML → bootstrap；停用新 dispatch → drain 與保存待交付結果；native 控制按原 plan Query-confirmed restore。不可還原舊 DB 丟失 live allocations，不可把「config=false」等同已解除 OS cap。

推薦實作次序：R0 記錄正確＋R1 一個可靠等待／續跑入口；R2 統計 shadow；R3 有證據才 ML；R5 Jev 完全可選。R4 的觀測／模式與部分設計可平行，實際 native control 仍受既有 P 階段限制。對沒有穩定數值特徵、但描述能幫助分類的冷啟動工作，才優先評估 Jev 的價值。

## 9. 一手參考資料

- M1：[scikit-learn：Gradient Boosting Quantile Regression](https://scikit-learn.org/stable/auto_examples/ensemble/plot_gradient_boosting_quantile.html)。
- M2：[scikit-learn：TimeSeriesSplit](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html)。不規則 job 與 group split 需要另外設計。
- A1：[Claude Code hooks reference](https://code.claude.com/docs/en/hooks)，`asyncRewake`、`PreToolUse defer`、non-interactive/resume 限制；接入前核對本機版本。
- A2：[Codex App Server 官方文件入口](https://developers.openai.com/codex/app-server/)，本次導向 [App Server 文件](https://learn.chatgpt.com/docs/app-server)；核對 initialize、thread/resume、turn/start。
- J1：[TypeSafe 2026-09-15 發布文](https://typesafe.ai/blog/introducing-system-one-models-and-jev)，供應商宣稱及其測量限制。
- J2：[TypeSafe introduction](https://docs.typesafe.ai/introduction)，primitive／parallel questions 的介面。
- J3：[Vercel：classify, route, score with Jev and AI SDK](https://vercel.com/kb/guide/typesafe-jev-and-ai-sdk)，型別化決策與程式分支，型別正確不等於語意正確。
- J4：[TypeSafe：Autoresearch feature discovery](https://docs.typesafe.ai/cookbooks/autoresearch_feature_discovery)，文字→語意特徵→CatBoost 範例；不是資源預測 benchmark。
- [TypeSafe Python SDK](https://docs.typesafe.ai/sdk/python) 與 [confidence](https://docs.typesafe.ai/confidence) 為未來實驗查核入口；此文件不 pin 尚未在 Sentinel 驗證的套件版本。

## 10. P3–P6 與 R0–R6 接入契約（2026-09-21 補充）

本節把後續相容性核對正式入庫。結論：**不推倒原 P3–P6；R0–R6 是另外的增量，不能當成完成 P3–P6 時順手全部實作的清單。**本節只澄清範圍、接點與驗收，沒有修改原計畫的安全政策，也不代表相關功能已實作或啟用。

### 10.1 歷史快照與最新進度分開

研究入口的 `6efa302` 進度描述是 2026-09-20 固定快照，不是持續更新的 live status。本次補充先核對實作分支 `b64ce6e75102868cf306b5323dac7de9dc64748a`，它比研究 commit `55f5002` 多 20 個提交，包含 P3/P4 元件與 A/B 工具／文件的新工作；不得沿用舊快照斷言目前仍然只有未接線的純決策函式。

這也不表示新階段已通過：本次讀到的 [ACCEPTANCE-RESULTS.md](../adaptive-scheduler/ACCEPTANCE-RESULTS.md) 明示 A/B 為 `NOT_MEASURED`，尚無 measured run records。元件、harness、模板與效果驗收要分開判斷；本輪沒有重新執行其測試或對最新 runtime 做完整審查。

後續實作者先讀 [adaptive-scheduler README](../adaptive-scheduler/README.md)、[IMPLEMENTATION-PLAN](../adaptive-scheduler/IMPLEMENTATION-PLAN.md)、最新 evidence 與 [AB-THRESHOLD-CLARIFICATION](../adaptive-scheduler/AB-THRESHOLD-CLARIFICATION.md)，再對齊實際 HEAD 與未提交修改。不能 checkout 舊研究基準覆蓋後來實作。原計畫約束與本節衝突時，先停下受影響的啟用／政策變更，留下明確決策，不自行放寬。

### 10.2 範圍與唯一權威

| 新增項目 | 與原計畫的接點 | 接入要求 |
|---|---|---|
| R0 歷史／預測記錄 | P2 execution/accounting 與 P4 telemetry | 重用身分、單位、coverage 與採樣；不得新增第二套容量帳本或高頻全機掃描；新增寫入與監測成本納入 overhead |
| R1 等待／續跑 | 既有 orchestrator、Coordinator、runner 及 P3 lifecycle | 不另造可繞過准入的 launcher；單一 execution owner；長等待、重啟、通知與取消均不得導致重複執行 |
| R2/R3 預測 | 工作需求建立之前的 advisory 階段 | 初始 estimate 可改善新需求；既有 request／allocation 與 active floor 不由 predictor 任意改寫 |
| R4 前景／公平 | queue policy 與受管 CPU 控制 | 另外驗證，不自行擴大受控範圍、同時 cap 數或修改有效豁免；不能把模型分數當公平性保證 |
| R5 Jev | 非必要、低頻率的語意特徵／軟建議 | 不取代 P4 fast-loop policy，不接 reservation、PID、lease、restore authority；停用／失聯不妨礙核心恢復 |
| R6 遠端 worker | 後續獨立 adapter | 不混入原本機 CPU MVP；另驗證 submit/status/cancel/result、資料授權與結果未知時的 reconciliation |

原計畫 §10.2 禁止順手重寫 orchestrator、workspace、cloud adapters、公平系統及 GPU 治理。R1 等增量可能需要明確的小範圍修改，但應先列出檔案、契約、測試與回退，另作增量交付，不把「研究裡寫過」視為不受限的實作／部署授權。

### 10.3 啟動 barrier 不因有新排程器而失效

原計畫 §7.4 的保守 MVP 是：有 active CPU cap 時，阻擋新的非豁免 launch，已 RESERVED 但未啟動的工作亦須遵守；解除限制後要等指定的新鮮量測與計帳證據，不能只改顯示狀態就開放。

因此 R1 不得收到喚醒事件便跳過 barrier；R2/R3 也不能因预测較小或實測 CPU 因 cap 降低，就放入更多工作。通知只是一個重新檢查機會，不是容量授權；啟動前仍走同一權威路徑。

這個 MVP 尚不是「降速 A，同時自由把 B 放進來」。要支援邊限速邊准入，必須另立明確政策變更，驗證需求計帳、前景效果、競爭與恢復；不能把它包裝成 P4 微調。

本次基準的 A/B 驗收文件另外記錄：當被控 Job 已結束，如何取得解除 `RECOVERY_HOLD` 所需的證據仍有待政策釐清。這是一個文件所列的阻塞項，不是本輪已修正的功能。後續 R1 不可用排隊很久、通知已送達、TTL 到期或模型判斷代替所需證據；先對齊最新原生控制文件，明文解決其證據契約。

### 10.4 預測可以修正未來，不能偷改當前承諾

原計畫 §7 保留不可變的 `requested` 與執行中的 `demand_floor`。新工作的預測應在其需求建立／准入前生成，保留原始預測、顯式需求、政策版本與最終核准值；使用者明確需求不由模型悄悄覆寫。

工作進入既有生命週期後，新的 forecast revision 仍只是觀測／建議。不能因目前用量低、模型更新或 CPU cap 生效而下調 active floor 或重寫已綁定 allocation。實際低估的保守更新仍由既有帳本契約處理；事後學到較小需求可以用在後續 execution。未啟動請求要調整時，也須定義明確的更新／取消重建與去重流程，不直接修改雜湊或 binding。

不得以 `measured + 全額預測` 建立重複計帳，也不得把縮小預測視為真實釋放 RAM。模型估計不取代新鮮 telemetry、身份與 native evidence。

### 10.5 續跑與安全前提

R1 可以先做離線設計、持久化 metadata、結果交付測試，或經核可、使用既有 admission-only 路徑的小範圍 adapter；**不需要先啟用 CPU cap，不等於可以跳過必要的 execution identity、一次性 claim、permission 與故障核對。**

命令已完成但通知失敗：重送保存好的結果；命令是否已啟動不明：先 reconcile，不盲目重跑；主程序退出但子程序仍活著：按原生命周期保留資源；provider deferred tool 與 Sentinel runner 不得各執行一次。收到舊 resume 事件，也要核對 session 世代、取消與使用者後續操作。

新的 continuation service 不是第二個 native actuator，不取得自己的一套 cap／restore 權限。有效豁免繼續遵守原約定並計帳；遊戲模式、ML 或 Jev 均不得默默撤銷。無法同時滿足前景需求與背景進度時要揭露等待原因，不自動犧牲真實工作來兌現承諾。

### 10.6 驗收、命名與回退

保留原 P6 的 A0/A1/B，用相同基準隔離 observer 與 CPU 控制效果。預測比較另用本文件 §8 的 `PRED-B0`–`PRED-B3`；原 Windows `S1`–`S3` gate 與 P phase 不重編。舊研究文件的預測 S0–S3 標籤由這組 PRED 名稱取代，不能引用「S1 通過」混指統計預測。

增加 recorder、trainer、continuation runtime、queue policy 或 Jev 後，需重新量測整體 overhead 與受影響的體驗／安全結果；不能繼承先前 P6 分數，亦不能在一次測試同時改多種政策卻把收益歸給單一元件。不得在原 gates 下重命名新功能、重用舊測試結果，宣稱自動完成。

建议順序：保留 P3–P6 的 native 驗證路徑；可並行 R0 觀測契約、離線統計與 R1 小範圍設計；先 shadow 驗證預測，再逐項允許其影響新准入；公平／前景、Jev 與遠端另作增量。不因研究文件入庫而啟用全部項目。

每個增量交付前列出：讀取基準與 dirty files、要改哪些契約、依賴哪些已實測 gates、未覆蓋入口、新增 overhead、與舊模式並存方式、取消／lost ACK、回退後 live allocations 和待交付結果的處理。原 native rollback 仍需 Query-confirmed restore；關閉 predictor 不回滾資料庫，不抹去既有授權與執行狀態。
