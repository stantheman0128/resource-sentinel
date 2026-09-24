# Daily readiness 的鎖外權限與鎖內重驗

日期：2026-09-24。狀態：**source 修補前的契約；尚未實作或測試。**
基準為 `codex/adaptive-scheduler-implementation` 的 `41cee4d`，並保留其
既有 dirty baseline。此契約只修正目標 5 的 remote readiness 鎖界線；
不安裝 daily generation、不啟動 native experiment、不宣稱 P1–P6 通過。
Adaptive 保持 off，58 GiB／4 GiB／4 GiB／三個豁免租約的政策不變。

## 已確認的 source 缺口

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

以上來自目前 checkout 的 source 閱讀；沒有執行 native、runtime 或測試。
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
| `daily_readiness_transport.py` | 新增不可序列化的 retained authority 與 `acquire_ready()`；在原 authenticated peer scope 內 duplicate。現有 `assert_ready()` 保留為 acquire＋正面 close 的便利方法，既有無回傳 receipt 語義不變。 |
| `daily_generation.py` | 新增 `readiness_scope(db_path)`，以明確 lexical owner 保存本次 authority；同 thread／同 exact ledger 的 nested scope 只能借用。`prepare_connection()` 變為本機驗證及 SQL binding，remote 分支沒有 scope 時直接拒絕，永不隱式 RPC。所有 authority／reader cleanup 持續保留原物件。 |
| `policy.py` | `hold()` 在 provider wait **之前**進入 readiness scope，涵蓋首次 nonce revalidation、yield、native release 與 exact nonce cleanup；scope 完成後才關 retained witness。既有 guard／nonce、不明 native release 與 clean-rejection 邏輯不變。 |
| `store.py` | `_connection()` 在開 consumer SQL connection 前取得或借用 scope，涵蓋整個 yield 及原 connection close；`_transaction()` 的鎖內檢查不發 RPC。現有 read-only coverage／IPC readers 不取得 capacity 權限。 |
| `coordinator.py` | `_db()` 及直接開 connection 的 `_cancel_managed_queue()` 持有 scope 至 connection close；managed admission 的 `_connect()` 借用外層 POLICY 同一權限。直接 `_connect()` 遇到 remote generation 卻無 scope 時拒絕，不能建立短暫權限後丟棄 witness。 |
| `maintainer.py` | `_db()` 持有 scope 至正面 connection close，使用相同 exact-ledger binding。 |
| `windows.py` | 只新增既有 `_THREAD_NAMES` ownership registry 的目前 thread 唯讀檢查，讓 remote acquisition 在原 native POLICY／Job mutex 已 held 時拒絕。不改 mutex acquire/release/close 語義。 |
| `legacy_writer.py` | 既有 lifecycle scope 與 `legacy_writer` role 的二次驗證保留；它會借用外層 POLICY 權限，不另發 RPC。若無需 source hunk，以 integration test 固定此路徑。 |

`readiness_scope` 的初始 generation observation 只能使用 bounded、read-only、
existing-path SQL reader；不得創建帳本、遷移 schema 或將 row 當成 readiness。
沒有 generation 的 pre-install 操作仍保留既有行為；若 scope 開始時沒有 row，
之後出現 remote generation，connection binding 必須拒絕，不能在锁內補 RPC。
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
