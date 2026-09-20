# GPT Pro 規劃交接：Agent 動態資源調度

日期：2026-09-19。狀態：**正式計畫已入庫，分階段實作進行中；production adaptive 維持 off。**

目前交接入口是 [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md)、
[P0 對齊結果](BASELINE-RECONCILIATION.md)、[Windows capability 證據](CAPABILITY-RESULTS.md)
與 [P2 admission-only 實作紀錄](P2-ADMISSION-ONLY.md)。
以下「只做規劃」及 GPT Pro 提示是原規劃階段的歷史背景，不限制後續已授權的實作。

最新已測實作包含 [guardian 持有中 Job 的還原流程](P3-GUARDIAN-RESTORE.md)：
接上 compare-and-restore、DB 失效時的 retained native fence、lost-ACK 對帳及
不確定持有權的隔離。最後 64 項受影響測試全數通過；cold-start 接管、獨立
supervisor 與實機故障恢復仍未通過，完整 P3 及 P4–P6 尚未完成。

另含 [guardian lifecycle 續租](P3-LIFECYCLE-RENEWAL.md)：
保存原始固定租期、以 retained Job 證據續租、過期維持 HOLD，並封住 legacy routed
heartbeat 對已納管工作的續租入口。這仍不代表完整 P3 gate 通過。

[Authenticated wrapper launch](P3-AUTHENTICATED-LAUNCH.md)：
wrapper 准入、Prepare／Claim／BindRoot RPC 與 guardian 持有權交接已接入程式，
沿用 [guardian lifecycle consumer](P3-GUARDIAN-LIFECYCLE.md) 的 root/child 清帳流程。
仍需正式服務啟動、supervisor、host authority 與完整恢復驗證，P3 尚未完成。
完整階段表與環境限制見 [native launcher 與 gate 狀態](P3-NATIVE-LAUNCHER.md)；
以下各次測試紀錄不是 P3–P6 的通過聲明。

2026-09-20 前期整合：[S1 execution owner](P1-S1-EXECUTION-OWNER.md)
已串接準入、建立前登記、單次 launch claim、恢復與清帳；
481 項測試通過。這是 test-only 實作與帳本整合證據，
native P1 與完整 P3–P6 仍未完成。`continuous_admission_provider_unavailable`
表示 runtime authority 實作缺口，不是 Windows API 錯誤；之前觀測到的
unknown inherited Job 是另一項尚未通過的 native 環境條件。

後續已接上 [真實 ledger coverage 驗證](P2-LEDGER-COVERAGE.md)：S1 owner 會先直接
驗證同一帳本的 exact allocation 與保留額度，再呼叫 host callback；237 項
針對性測試通過。這不代表日常主機上所有舊 consumers 的 runtime 交接已完成。

最新 [control coordination 實作與證據](P3-CONTROL-COORDINATION.md) 已接上真正的
豁免寫入、單一持久控制名額及 S1 限速期間的 fresh-grant 檢查；388 項針對性
測試通過，日常 runtime 未部署。這是 P3 的部分依賴，不能當成正式 guardian、
legacy writer handoff、native P1 或 P3–P6 的完整通過。側邊資源研究的採納／
延後範圍亦記在同一份證據文件，不新增估計器作為本 MVP 的前置。

[Legacy writer handoff 的實際接線](P3-LEGACY-WRITER-HANDOFF.md) 已將 collector 的
priority／I/O／trim／restore 移入持有共用 POLICY 的 executor，並封住首次 wrapper
與 Job metadata 公開的競爭。517 個 Python 測試及兩個 PowerShell 測試通過，
最後增加一個案例後補跑的 23 個測試亦通過。這仍是 source 與隔離測試證據；
production supervisor、完整 loaded-writer 交接及 native gate 尚未通過。

[原生唯讀 machine sampler](P1-MACHINE-SAMPLER.md) 已完成實作與實機驗證。
第一次原生測試抓到精確時鐘的 DLL 載入錯誤，修正為官方 API-set 後，70 個
測試全數通過，其中兩個是真正 Windows 取樣。這提供恢復流程所需的機器
樣本；尚不代表完整 FastFrame、Job 控制能力或 P4 監控成本通過。

[S1 recovery consumer](P1-S1-RECOVERY-CONSUMER.md) 已接入實際 owner 收尾：
保留原始 Job custody，核對恢復、五筆新鮮樣本與共用帳本，再解除 barrier。
原生 power notification 的註冊／解除已實測，完整 native Job／sleep recovery
仍未通過；這不會解鎖尚缺實際 host authority 的 native 入口。

## 2026-09-20 接手紀錄：交還 Codex 前的現況

這一輪由 Claude 接手既有實作，沒有重寫架構。以下每一項都只有可攜測試證據，
Job、程序與 mutex 都是測試內標明的 synthetic backend。這台開發機的程序位於外層
Job 內，`require_supported_host()` 會拒絕，所以 native 測試一項都沒跑，P3 到 P6
沒有任何 gate 通過，adaptive 維持 off。

已入庫的程式與對應文件：

1. P3 流程 A 到 H 在同一份隔離帳本上用 production consumers 跑完，見
   [retained supervisor](P3-RETAINED-SUPERVISOR.md)。H 步驟由 supervisor 行程內的
   `OrphanDrainOwner` 完成：guardian 確認死亡並還原後，Job 經現場查詢確認為空才
   釋放控制名額並結案。它不接管 scope，不改寫 `guardian_identity` 與
   `guardian_epoch`，barrier 停在 `RECOVERY_HOLD`。
2. guardian 端的 ControlProposal consumer 見 [guardian control](P3-GUARDIAN-CONTROL.md)。
   順序依計畫 8.3：佔名額、寫入 durable intent、Set、Query、結算 manifest、回 ACK、
   批次稽核。帳本模式為 off 或 shadow 時不會套用或續期限速；模式離開 canary 時
   已持有的限速會以一次 native disable 還原。租約到期由 `tick()` 自行還原。
   結算 manifest 寫入失敗時，限速會循同一條還原路徑撤回，ACK 為 UNVERIFIED。
3. P4 的決策層、shadow helper 與 Job sampler 只有 source，沒有呼叫端把它接到 guardian。
   設定檔現在可選 off 與 shadow，選不到 enforce。
4. P5 的故障證據工具與唯讀成本探針、P6 的配對 A/B harness 已入庫。
   [驗收結果](ACCEPTANCE-RESULTS.md) 仍是空白範本，結論是 NOT_MEASURED。
   計畫 11.3 沒給數字的兩個比較，以 [門檻澄清](AB-THRESHOLD-CLARIFICATION.md)
   沿用計畫既有數字，並標明是澄清。
5. guardian、supervisor、wrapper 三個可執行的行程入口與共用的 live host authority，
   見 [process hosts](P3-PROCESS-HOSTS.md)。guardian 啟動時把自己登記進
   `adaptive_infrastructure`，supervisor 從自己建立 guardian 時留下的 creation handle
   取得 guardian 身分，只有確認 DEAD 才進入還原，UNKNOWN 不會重啟任何東西。
   這台機器上三個入口都會以 `host_foreign_parent_job` 拒絕啟動，這是預期結果。
6. helper 到 guardian 的 ControlProposal 傳輸與純函式的 proposal builder，見
   [control transport](P3-CONTROL-TRANSPORT.md)。呼叫者必須是 `adaptive_infrastructure`
   裡該 logon 唯一登記為 helper 的行程，先以 OS 驗證的 pipe peer 確認身分，
   之後才讀取請求內容。服務本身不讀模式、不快取 ACK，所有安全判斷仍在
   `GuardianControl`。guardian host 已在第三條 pipe 上提供這個服務；目前唯一的 helper
   行程只跑 shadow，所以實際上仍沒有任何東西會送出 proposal。
7. supervisor host 在確認 guardian 死亡、`supervisor.close()` 成功之後，會在 POLICY 之下
   把那個 guardian 的 `adaptive_infrastructure` 列移除，見 process hosts 文件。移除函式
   自己會在保留的 witness 上再驗一次 DEAD。supervisor 和 helper 的列沒有人持有死亡
   witness，所以不會被移除。
8. 常駐的 shadow helper host，見 [helper host](P4-HELPER-HOST.md)。它登記 helper 列，
   以 `JobAccess.QUERY` 開啟帳本上同 logon、`job_contained` 的 Job，跑 sampler 和決策
   迴圈，輸出只含計數與穩定代碼的成本紀錄。它選不到 enforce，不建立 proposal，
   不連 guardian。這台機器上它同樣以 `host_foreign_parent_job` 拒絕啟動，所以計畫 P4
   要的 1、10、50 個 Job 成本分布一筆都還沒量。
9. supervisor host 加上 `--helper-profile` 之後會自己建立一個 helper 子行程，保留它的
   creation handle 當作死亡 witness。witness 觀察到 DEAD 才會在 POLICY 之下移除 helper
   的登記列，移除沒有失敗、預算也允許時才啟動替代者。沒給這個選項時 supervisor 的
   行為和所有紀錄都不變。`scripts/adaptive-supervisor.ps1` 是計畫 P3 表列的入口，
   只在前景執行 supervisor host 並傳回它的 exit code，不註冊 Scheduled Task，兩個
   目錄都必填、沒有預設值，裡面沒有任何停止子行程的路徑。

已知缺口，都還沒有程式：

1. 沒有會送出 proposal 的 helper。shadow helper host 只觀察，enforce 模式依計畫要等
   P5 的 capability 核可，B 組因此仍然不能量測。不是由 supervisor 建立的 helper，
   結束後登記列仍會留著，下一次啟動會以 `helper_host_registry_occupied` 拒絕。
   supervisor 自己結束時，guardian 和 helper 的列也都會留下，主機上不再有任何 witness。
2. 沒有 endpoint 發現機制。wrapper 與 helper 要連哪個 guardian，目前只能由操作者
   手動傳入 pid、creation FILETIME、instance id 與 epoch。
3. 除了行程收到 interrupt 之外沒有正式的停止訊號。
4. wrapper 被拒絕之後，已綁定的 reservation 沒有釋放路徑，細節在 process hosts 文件。
5. guardian 在 supervisor 第一次 attach 成功之前死亡時無法被接管，因為
   `RecoveryOwner.capture` 要求 guardian 為 ALIVE。
6. guardian 在 supervisor attach 成功之前就結束時，它的登記列不會被移除，因為那條路徑
   到不了 `_replace`。registry 上限是 32 列。
7. 計畫 P3 與 P4 表列在 `scripts/sentinelctl.py` 的 `run-managed`、`adaptive-status`、
   `adaptive-recover` 與 mode、drain、audit 命令都還沒寫，目前只有唯讀的
   `adaptive-query`。這個檔案在工作目錄裡帶著
   另一項任務尚未提交的修改，這一輪無法乾淨分離，所以沒有動它。缺口 4 的釋放路徑
   會動到 `sentinel/coordinator.py`，原因相同。

需要 repo 擁有者裁決、程式目前一律 fail closed 的事項：

1. 計畫 7.4 沒說受控 Job 已經結束時，要用誰的五筆未限速樣本清除 barrier。
   現況是 Job 先結束或由 orphan drain 結案時，barrier 會一直停在 `RECOVERY_HOLD`。
   這一點在 canary 之前必須決定。
2. `cancel` 與 `start_failed` 兩種狀態缺 guardian 證據，無法退場，細節在
   retained supervisor 文件的 remaining gates。
3. 計畫 5.5 要求 caller 以 OS 可驗證身分和一次性 token 綁定。helper 沒有
   `ipc_auth_key`，registry 的欄位也是固定的，所以傳輸層目前只用 OS 驗證的 peer
   加上每次請求的 server nonce，沒有共享密鑰。這樣是否滿足計畫的 token 要求，
   需要擁有者確認；若要真正的共享密鑰，得先決定由誰簽發、存在哪一筆紀錄。
4. supervisor 自己由誰見證。supervisor 不登記自己，也沒有任何行程持有它的 witness，
   它結束之後留下的 guardian 列和 helper 列就沒有人能移除。另外，helper 的列移除失敗
   之後，supervisor host 不會重試移除，也不會再啟動 helper，之後每一輪只回報 absent；
   這是比照 guardian 路徑的保守做法，要不要改成每輪重試由擁有者決定。
5. `register_infrastructure_locked` 的兩個提前拒絕會留下 POLICY entry nonce，之後每一次
   `prepare` 都會得到 `policy_scope_busy`，沒有東西會清掉它。guardian 和 helper 的啟動
   路徑都會經過這裡。移除函式上同樣形狀的問題已經修掉，這一個沒動：兩條啟動路徑在
   同一個 scope 裡都先執行過 `initialize_registry_locked`，拒絕發生時帳本已經被碰過，
   不能直接當成 clean rejection。

整棵 adaptive 測試樹最後一次執行是 2026-09-21：80 個模組、1936 個測試、0 失敗、
0 錯誤、0 略過，經 `scripts/invoke-sentinel.ps1` 正常准入。傳輸層的未登記呼叫者
檢查沒有紅燈證據，因為產生紅燈必須先拿掉一道安全檢查，該次執行被權限分類器拒絕，
之後沒有繞過。這是 source 行為的證據，
不是任何 native gate 的通過聲明。

使用者要求：先自行嚴格質疑方案，把資料放入 repo；由使用者交給 GPT Pro
完成 plan，再交回 Codex 實作。本包不代表使用者已選定控制演算法、常駐服務或參數。

## 閱讀順序

1. [GPT Pro 提示](GPT-PRO-PROMPT.md)：可整段貼給規劃模型。
2. [自我質疑與修正](SELF-GRILL.md)：問題、暫定答案、仍須驗證的缺口。
3. [程式現況與驗收契約](EVIDENCE-AND-ACCEPTANCE.md)：實作入口與規劃輸出要求。
4. [前一版提案](../../adaptive-agent-scheduling.md)：背景與研究來源；數值只是候選。
5. [來源快照索引](snapshot-manifest.json)：本機選定程式與測試的 SHA-256、來源及擷取時間。
   `source-snapshot/` 內為 `.txt` 文字參考，不是可執行的新功能。

## 基準差異非常重要

本包建立時，GitHub master 與本機 HEAD 都是
`0b2f37819a2d4f68299fbec3fe619a4d05ba4749`。
本機另有未提交的 resource-v2、collector recovery、58 GiB 政策、三豁免上限及介面修改。
規劃分支只新增文件與選定原始碼的文字快照，**沒有把上述 runtime 修改合併到 master**。
目前實作以 P0 核對的本機 live working tree 為待對齊基準；快照僅供歷史比對，
不得批次複製回 source。根目錄同名程式可能仍是舊版。快照不是完整可執行 checkout；
其他相依項目需讀 repo，不能用它宣稱測試通過。

## 使用者真正想要的效果

- 多個 coding agent 工作時，能針對一個造成瓶頸的背景任務稍微降速，再自動恢復。
- 保護互動流暢度、工作進度與總體完成效率，不追求單純降低 RAM 顯示數字。
- 30 秒只適合作完整報表週期；需要更快的局部反應，但不能讓監控本身變成負擔。
- 保留 58 GiB 整機准入預算、4 GiB 實體及 4 GiB Commit 餘裕、最多三個豁免租約。
- 不殺工作、不週期凍結工作、不誤傷共享 UI、不自行增加豁免。

這裡的「互動優先」是產品方向，不等於已存在可靠 foreground-task 偵測能力。
GPT Pro 必須選擇可實作的識別方式與沒有識別資料時的預設行為。

## 接入規則補充：單一受管理區段與共用政策入口

使用者補充：另一個 session 已移除全域入口的舊重複段，保留正式受管理區段並前置。
本輪核對主 Codex 的 `.codex/AGENTS.md`：start/end marker 各一個，
區段本文與 `docs/agent-bootstrap.md` 相同（僅正規化 CRLF/LF 與區段首尾空白後比對），
`docs/agent-policy.md` 政策入口連結出現一次。這不是其他 agent 入口已全面複查的聲明。

後續實作應沿用此結構：`agent-bootstrap.md` 是受管理區段的來源；
`C:/Users/stans/Projects/resource-sentinel/docs/agent-policy.md` 是正式共用政策入口。
不要在各個 AGENTS/CLAUDE/GEMINI 等入口另外追加一份動態調度規則；若確有政策變更，
應先修改 canonical source，再以冪等方式同步既有受管理區段，並測試不存在重複區段。
runtime 調度細節應留在實作/設計文件，不要把所有控制器參數複製成全域 instructions。

資源 v2／legacy fallback、58 GiB budget、兩項 4 GiB reserve、三豁免上限、
授權期限、排隊與恢復要求都保留。使用者回報該次整併未改 Sentinel 程式或跨 agent
共用政策；本輪僅核對現況並補充交接，也未改這些來源、入口或 runtime。

## 自我質疑後的暫定結論

先解決 task 身分、量測與恢復責任，再選控制器。首版候選是 wrapper 啟動的獨立工作，
配合短週期量測與單一資源的 CPU 控制；RAM 先控制新增工作，公平排程與合作式 worker
調節後置。是否新增常駐 helper、是否從 shadow mode 開始，由 GPT Pro 明確比較並裁決。

1 秒取樣、持續 3 秒觸發、5 秒冷卻、20–30 秒恢復及 0.8 倍減量均未校準。
不能把這些數值或「AIMD + DRF」直接抄成規格。請允許以證據推翻原提案。

## 交回成果

請讓 GPT Pro 輸出可存為 `IMPLEMENTATION-PLAN.md` 的完整 Markdown。
必須包含架構選擇、狀態機、資料契約、失效恢復、具體檔案變更、分階段驗收與 rollback。
若只能在聊天回覆，直接回傳全文即可；本階段不需要產生程式碼或修改任何 runtime 設定。
