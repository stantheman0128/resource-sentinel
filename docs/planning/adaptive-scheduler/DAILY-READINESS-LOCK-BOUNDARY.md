# Daily readiness 的鎖外權限與鎖內重驗

2026-09-25：使用者已明確批准
[transaction boundary correction](DAILY-READINESS-TRANSACTION-DECISION.md)，
以正式計畫的 BEGIN 前觀察／交易內 metadata 核對／native action 前再驗證，
取代下文「每次 UDF write 重新查 native／filesystem」的觀察時點要求。
該修正尚未實作；下列測試數字是舊契約歷史證據，不能用來宣稱新邊界或
native promotion 通過。本輪依使用者要求暫停，最新進度以 README 為準。

日期：2026-09-24。狀態：**source 與 preparation 中央整合驗證已通過。**
原契約基準為 `codex/adaptive-scheduler-implementation` 的 `41cee4d`，並保留其
既有 dirty baseline。基礎八模組 217 tests 已過；新增雙帳本、absence pool、
local lexical 修補與 preparation 的 14 模組合跑 **413 tests 全過，47.653 秒，
0 failures／errors／skips**，其中 focused module 有 38 案。私人完整日誌為
`.local-adaptive/readiness-preparation-20260924-2.log`。首次同範圍有 1 failure／
4 errors：修正 genuine table-absence 與原始 connection fault 注入位置後重跑；
沒有改動 production validator 來配合 fixture。仍非 clean-clone 或 native gate。
完整 155 模組回歸曾有 2 failures／9 errors（4,166 tests），其中 connection
close 的公開 traceback 與 pinned ledger 選取順序是 source 回歸，已修正；
其餘為舊 guardian telemetry fixture。最終 18 模組整合 **493 tests 全過，
55.779 秒，0 failures／errors／skips**，包含上述全部失敗模組與 retirement
整合。私人日誌為 `.local-adaptive/readiness-host-regression-20260924-2.log`。
此最終回歸保留原始 connection／error 的私密 custody，公開例外保持 sanitized；
readiness 與實際 transaction 使用同一 pinned ledger，missing ledger 仍拒絕。
沒有重新執行完整 4,166 tests，不宣稱整套已通過。
此契約只修正目標 5 的 remote readiness 鎖界線；
不安裝 daily generation、不啟動 native experiment、不宣稱 P1–P6 通過。
Adaptive 保持 off，58 GiB／4 GiB／4 GiB／三個豁免租約的政策不變。

## 原契約基準已確認的 source 缺口

1. `daily_generation.prepare_connection()`（438 行起）呼叫
   `_prove_retained_owner_ready()`（490 行起）；remote 分支會以
   `DailyReadinessClient.assert_ready()` 發送 RPC。
2. `LifecycleStore._connection()`（`store.py` 913 行起）在 BEGIN 前呼叫
   該 hook，但 BEGIN 前並不等於 POLICY／Job 鎖外。
3. `PolicyCoordinator.hold()`（`policy.py` 207 行起）先取得 native POLICY，
   再以 `_connection()` 重驗 durable nonce。因此首次 yield 前就會在 POLICY
   內發送 readiness RPC。yield 內的 lifecycle query／transaction 亦然。
4. `Coordinator._admission_db_owned()` 在 POLICY 內呼叫自己的 `_connect()`；
   `legacy_writer._registry_locked()` 則在同一 lifecycle connection 再以
   `legacy_writer` role 呼叫 hook。只修正 LifecycleStore 的一個分支會漏接。
5. `Maintainer._connect()` 也是同一 daily generation 的容量 consumer，
   必須持有同樣的權限直到自己的 SQL 操作與 connection cleanup 結束。
6. 原 transport 的正面回傳是 `None`，其 pipe／peer 已關閉；這個結果不能
   當作稍後鎖內重驗的 native witness。`VerifiedProcess.duplicate()` 已存在，
   可在已驗證的 `verified_peer` scope 內保留該**同一個** authenticated peer。

以上行號與行為來自原基準 source 閱讀；本 worker 沒有執行 native、runtime 或測試。
654 個 retirement integration tests 是前一包的證據，不是本修補的證據。

## 權限契約

一次 top-level daily operation 在任何 POLICY／Job／SQLite transaction 之前，
取得一個 process-local、thread-bound 的 `DailyReadinessAuthority`。
它不能由 JSON、generation row、boolean、status、TTL cache 或 callback 建構。
只有原 transport 的完整 authenticated exchange 可以簽發 remote authority：

- request／reply 綁定 exact generation、source digest、config digest、ledger
  file identity、owner process identity、readiness endpoint instance、caller
  identity 與 request id；沿用現有 nonce、pipe OS peer 驗證及 server 原 owner。
- 在相同 `connection.verified_peer()` 內，以 `peer.duplicate()` 保留原始
  peer handle。不能在收到 ACK 後以 PID 重新開啟 process 來取代原 witness。
- 原 pipe、peer scope 與 current-caller handle 必須先正面 close；然後才可
  將包含 retained duplicate 的 authority 交給 consumer。任一 acquisition／
  close 不明即拒絕，保留原 owner、duplicate、cause 與 cleanup 狀態。
- authority 的期限從該次 RPC 開始計算，最多 **1,000 ms**，沿用既有 RPC
  deadline；mutex 等待、source 核對、SQL 等待都消耗同一期限。借用、重驗、
  重開 connection 或 nested scope 都不得延長。到期必須先退出所有鎖與該
  operation，才可由新的 top-level operation 重新進行 RPC。

authority 不是 capacity receipt、generation adoption 或 readiness cache。
它只允許本次 operation 在鎖內以原 witness 重新證明 readiness。每次 connection
binding，以及 capacity trigger 的實際 write 時，均須重驗：

1. 目前 thread／process 與簽發時一致，authority 尚未 close、poison 或過期；
2. 原 duplicate 的 `observe()` 為 ALIVE，完整 process identity 相同；
3. **同一個 consumer SQLite connection** 讀出的 generation row 與綁定資料
   完全相同，state 仍 ACTIVE，ledger 路徑與 native file identity 未改變；
4. 固定政策 config bytes digest、完整 source manifest、實際 loaded import
   provenance 仍相同，readiness endpoint identity 仍完全一致。

鎖內不得發送 RPC、開啟新 peer/process、重建 authority、重新讀另一個帳本
來代替 consumer 的 transaction，或以「先前成功」略過重驗。
`sentinel_daily_generation()` 不再是無條件回傳字串的 closure：它要對原
authority 做上述檢查後才回傳 generation，既有 SQL trigger 再比較 ACTIVE
generation。驗證例外在 SQL 中維持拒絕，不能吞掉後回傳舊 generation。

## 最小 API 與接線

| 檔案 | 最小變更 |
| --- | --- |
| `daily_readiness_transport.py` | 新增不可序列化的 retained authority 與 `acquire_ready()`；在原 authenticated peer scope 內 duplicate。實作保留 `assert_ready()` 原同步 exchange＋正面 pipe/peer close 路徑，不建立 duplicate，仍只回傳 `None`、不授予可重用權限；兩者共用封閉 protocol `_request`。如此避免純觀察 caller 平白新增 duplicate cleanup 義務。 |
| `daily_generation.py` | 新增 `readiness_scope(db_path)`，以明確 lexical owner 保存本次 authority；同 thread／同 exact ledger 的 nested scope 只能借用。`prepare_connection()` 變為本機驗證及 SQL binding，remote 分支沒有 scope 時直接拒絕，永不隱式 RPC。所有 authority／reader cleanup 持續保留原物件。 |
| `policy.py` | `hold()` 在 provider wait **之前**進入 readiness scope，涵蓋首次 nonce revalidation、yield、native release 與 exact nonce cleanup；scope 完成後才關 retained witness。既有 guard／nonce、不明 native release 與 clean-rejection 邏輯不變。 |
| `store.py` | `_connection()` 在開 consumer SQL connection 前取得或借用 scope，涵蓋整個 yield 及原 connection close；`_transaction()` 的鎖內檢查不發 RPC。現有 read-only coverage／IPC readers 不取得 capacity 權限。 |
| `coordinator.py` | `_db()` 及直接開 connection 的 `_cancel_managed_queue()` 持有 scope 至 connection close；managed admission 的 `_connect()` 借用外層 POLICY 同一權限。`admit_experiment()` 的外層 scope 包住原 demand 的 `_prepare_submission()`、POLICY 與 SQL 收尾，使直接 readiness hook 也有原始權限。直接 `_connect()` 遇到 remote generation 卻無 scope 時拒絕，不能建立短暫權限後丟棄 witness。 |
| `maintainer.py` | `_db()` 持有 scope 至正面 connection close，使用相同 exact-ledger binding。 |
| `windows.py` | 只新增既有 `_THREAD_NAMES` ownership registry 的目前 thread 唯讀檢查，讓 remote acquisition 在原 native POLICY／Job mutex 已 held 時拒絕。不改 mutex acquire/release/close 語義。 |
| `legacy_writer.py` | 既有 lifecycle scope 與 `legacy_writer` role 的二次驗證保留；它會借用外層 POLICY 權限，不另發 RPC。若無需 source hunk，以 integration test 固定此路徑。 |
| `experiment_demand.py` | 只補原 readiness scope／authority 的 cleanup custody 辨識及 raw reader close 不明的註記；原 demand、native scope 與 release 權限不變。 |

`readiness_scope` 的初始 generation observation 只能使用 bounded、read-only、
existing-path SQL reader；不得創建帳本、遷移 schema 或將 row 當成 readiness。
沒有 generation 的 pre-install 操作仍保留既有行為；若 scope 開始時沒有 row，
之後出現 ACTIVE generation，capacity connection binding 必須拒絕，不能在鎖內補 RPC
或借用新出現的 local owner。原 unactivated install／retirement 的 nonce-only
cleanup 特例保留；使用 scope 的 local capacity binding 與每次 UDF write 仍須
核對原 scope current／未 closed／未 poisoned、原 row 與 exact ledger 路徑。
程式內已有 original local `DailyGenerationOwner` 的路徑繼續使用該原 owner，
不透過自己的 pipe，也不以 local owner 名義接管 remote generation。

Guardian 正常 Job scopes 由 `PolicyCoordinator.hold()` 包住（或借用已 held
guard），因此取得同一 authority。`GuardianRestore.emergency()` 的 native-only
restore 和 `host_operations._read_scope()` 的原 retained read fence 不應增加
daily RPC 依賴；其 read-only coverage reader 仍然不會綁定 capacity generation。
若後續 source 核對發現這些直接 mutex 路徑新增了 `prepare_connection()` caller，
必須在改 source 前補上實際 outer-scope 呼叫點並重新核對 ownership，不能在
鎖內臨時 acquisition。

新增或變動的 `.py` 仍由 `SourceManifest` 的完整 source closure 收錄；
`REQUIRED_PATHS` 應明列 transport、policy、windows，防止 fixture 的不完整
manifest 省略這些 authority consumers。不得放寬 import provenance 或以
monkey-patched production function 當成 daily source 證據。

## Cleanup、原 owner 及退場

- scope owner 在開始 acquisition 前保存 pending operation，任何 BaseException
  保留原 acquired objects 與失敗原因。未知 CloseHandle／SQL close 不重試，
  也不以新的成功 scope 清除舊的不明 cleanup；bounded pending custody 滿時拒絕。
- borrowed scope 不 close witness，不接管清理責任。不同 ledger、thread 或
  generation 的借用拒絕。outer scope 必須等 nested SQL/native owners 正面
  收尾之後才 close 原 authority。
- authority 過期或 owner 死亡後不再授予 capacity／native setter 權限。
  `PolicyCoordinator._clear()` 僅能以原 guard、原 positively released scope
  與 exact generation binding 取得 **nonce-only** connection authorizer：
  只允許原 `adaptive_runtime.policy_entry_nonce` 清理，沒有 capacity UDF、
  DDL、reservation、mode 或 barrier 權限；不能要求新 RPC 才能清理原 nonce。
  generation 已更换或原 SQL／native cleanup 不明則保留 nonce。
- 現有 original install cleanup 路徑，以及 `DailyRetirementOperation` 在
  DRAINING 下的 nonce-only authorizer、原 install connection 收尾、original
  retirement inventory／cohort／native witness 均保留，不能擴張為一般 bypass。

## 必要回歸與驗收

新增 focused tests，使用明示 synthetic native backend 和隔離帳本；由主代理
統一經 Resource Sentinel 准入執行，本 worker 不執行 tests 或 native 操作。

1. exact authenticated peer duplicate 先於原 peer close，pipe／caller cleanup
   成功後才取得 authority；錯 peer、reply、nonce、endpoint、partial acquisition、
   peer duplicate／pipe／caller／retained witness close 不明都拒絕且保留 custody。
2. event-order trace 證明 remote RPC 完全位於 POLICY／Job／BEGIN 之外；
   POLICY 初次 revalidation、nested lifecycle、Coordinator managed admission、
   Maintainer 和 legacy writer 都用同一 retained authority，鎖內 RPC spy 必須為零。
3. readiness 與 lock acquisition 間改 generation、state、owner、endpoint、
   ledger identity、config 或 source；BEGIN 後 write 前再次改變或期限到期，
   都必須拒絕且無 capacity mutation。DEAD／UNKNOWN／PID reuse 同樣拒絕。
4. nested scope 不能刷新期限或替換 authority；cross-thread／cross-ledger／
   已 close／poisoned authority 拒絕；lock-held 且沒有 pre-lock authority 時
   直接拒絕，沒有自動 RPC。readiness 讀取和 mutex 等待消耗同一原 deadline。
5. consumer rollback／close 失敗、POLICY release 不明保留原 nonce與 original
   cleanup owner；authority 到期後的 exact nonce-only cleanup 不能寫 capacity。
6. absent generation、original local owner、unactivated install cleanup、
   retirement DRAINING cleanup 和 original 654-test retirement bundle 不退化。
7. source manifest／bootstrap import closure tests 涵蓋新增 authority consumers；
   fixture tests、byte comparison 或成功 RPC 均不計為 native acceptance。

Source review 後再由主代理更新 checkpoint 與實際測試結果；沒有 native evidence
以前，不宣稱 daily activation、fresh generation restart 或 grace 已可用。

## 2026-09-24 Source 實作中的額外呼叫路徑

基礎 scope source 與 focused tests 已寫入。主代理以正常 Resource Sentinel
准入跑八個模組，**217 tests 全過，31.34 秒，0 failures／errors／skips**；
私人日誌為 `.local-adaptive/readiness-lock-boundary-20260924-1.log`。
這只驗證基礎修補，尚未包含下列雙帳本整合。主代理另確認
`ExperimentNativeScope._scope(daily=True)` 依既有契約取得 daily POLICY、
isolated POLICY、Job。單一 ledger 的 borrowing API 會拒絕第二個 isolated
ledger；下列補充契約與 source 已加入鎖外預先取得兩個 exact-ledger lexical
owners，再於鎖內選用既存對應 owner，目前等待中央合併驗證。不能以基礎
focused tests 通過宣稱 native experiment path 已恢復；實際 native scope 的
`_ready()` 仍要求原 local generation owner，remote provider 接線是後續獨立工作。
不允許跨 ledger 借用 daily
capacity 權限，也不在 daily POLICY 內對 isolated ledger 新做 readiness RPC。

## 兩個原始帳本 scope 的最小補充契約

主代理已同意以下 source 邊界；此補充先提交，才開始這一段程式變更。

`readiness_scopes((daily_path, isolated_path))` 最多接受 **兩個**相異、已存在的
exact ledger 路徑。caller 必須在 SQLite transaction 前進入；程式檢查目前 thread
沒有已管理的 POLICY／Job 鎖及既有 readiness scope/group，並不宣稱能偵測任意
外部 SQLite connection 的鎖。它依序取得兩份獨立原始 lexical owner，
完成各自 bounded read-only reader 的正面 close，保存各自的 native file
identity 與 generation observation；有 daily generation 的 owner 另外取得
上述 authenticated authority。第二份取得失敗時只能關閉已取得的原 owner，
未知 cleanup 仍保留。兩份都取得之後才公開 group，所有原期限不變。

在 group 內，`readiness_scope(path)` 只選取 group 中已存在、完全相同 ledger
的 owner；未知第三個 path、已關閉、poisoned、其他 thread 或改變 file identity
一律拒絕。選取不讀另一個 DB、不發 RPC、不刷新 authority；退出恢復原 selector。
daily 與 isolated scopes 的 generation、authority、cleanup marker 和原錯誤
互相獨立。不能以 daily 的 witness、nonce cleanup 或 capacity UDF 授予 isolated
帳本任何權限。

原 isolated owner 觀察到沒有 generation 時，consumer connection 和取得 SQL
transaction 後的**同一個 connection**都必須再次核對：generation 仍不存在、
`PRAGMA database_list` 是原 path、原 native file identity 未更換。有 generation
突然出現或 ledger 被替換時，拒絕並退出原 scopes，不能在持鎖期間補 RPC。
沒有 generation 的 isolated connection 不安裝 daily capacity UDF。

`ExperimentNativeScope._scope(daily=True)` 在 daily POLICY 之前建立兩個 owner，
然後維持既有 **daily POLICY → isolated POLICY → Job** 順序；`_policy_scope`
在 prepare/readback/hold/clear 全程選取自己的 ledger owner。`_IsolatedStore`
的原 connection hook 也進入／借用自己的 exact scope，於原 connection 上
核對 absence 和 identity，SQL connection 的原 custody／close 行為不變。
`_scope(daily=False)` 只使用 isolated scope，不讀 daily generation、不發 daily
readiness RPC，維持原 native-only restore 對日常帳本故障的獨立性。

新增 focused integration trace 必須證明兩份 observation 都早於第一個 native
lock；中途沒有額外 RPC；daily transaction 在持有 isolated／Job 時仍只選取
已取得的 daily owner；isolated 不借 daily cleanup marker；generation 突然出現、
替換 file identity、partial second acquisition、原 owner close 不明及 native-only
restore 均有明確拒絕／保留原 custody 的案例。這段仍只做 source／isolated tests，
不執行 native experiment，也不改另一 worker 的 demand cleanup state machine。

### 原 native-only restore 的 custody 容量獨立性

實作 review 發現：若所有 observation 共用 daily 的八份 pending custody
名額，八個其他 daily cleanup 不明會連帶拒絕 isolated-only restore，與既有
恢復契約不符。因此增加只會縮小權限的明確參數：

`readiness_scopes(paths, absent_paths=(original_isolated_path,))`

`absent_paths` 必須是本次最多兩個 exact existing paths 的子集合。被列出的
原 ledger 使用另一個 **最多八份** pending absence observation pool；在開始
讀取以前就保留其原 owner，未知 read/close 繼續佔用原名額。此 pool 不能
取得 readiness RPC、native authority 或 daily capacity UDF；首次或後續同一
consumer connection 看到任何 generation row，都必須拒絕（包括原 local
owner 也不能特例通過）。它仍需原 file identity、相同 SQLite connection 的
absence 重驗、thread／lexical owner、正面 cleanup 和自己 pool 的容量限制。
把 daily path 宣告為 absent 不會得到豁免，只會在 generation 存在時更早拒絕。

沒有宣告 absent 的 path 仍使用原 daily readiness pool 與原所有檢查。
`ExperimentNativeScope._scope()` 在 daily=True 與 daily=False 時，都只把其
**原 isolated path** 宣告為 absent；daily=False 完全不進入 daily pool。
不是依 subclass、檔名、status、boolean readiness 或「native-only」標籤跳過
檢查，也不因其他 pool 已滿就改選 pool。兩個 pools 都保存原清理義務且不替換
未知 owner；這只移除本次修補引入的無關 daily custody 容量依賴。

回歸必須實際填滿 daily pending pool，證明 isolated-only observation／POLICY
仍可完成；填滿 absence pool 時自己仍拒絕，任何 active generation 被標為
absent 都不發 RPC且拒絕，generation 中途出現也不安裝或借用 daily UDF。
