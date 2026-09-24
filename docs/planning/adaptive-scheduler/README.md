# GPT Pro 規劃交接：Agent 動態資源調度

日期：2026-09-19。狀態：**正式計畫已入庫，分階段實作進行中；production adaptive 維持 off。**

## 2026-09-24 Codex 實作 checkpoint（目前狀態）

S1 workload root 的整棵程序樹就緒紀錄已補上。只有全部 child ready 與原始
Create witness 相符後才發布 bounded `tree-ready.json`，保留原始建立順序、
source pins 與共同截止時間；單 worker 的 child list 為空，leaf／foreign-parent
probe 不發布。缺檔、錯誤 birth、部分建立失敗或停止時不發布部分成功紀錄。
契約見 [S1-SERIAL-PROVIDER.md](S1-SERIAL-PROVIDER.md)。這是 root 的觀測紀錄，
consumer 接線尚未完成；不能當作 guardian 已持有 child handles 或已證明退場。

本次 **4 模組、124 PASS，0 failures／errors／skips，runner 3.413 秒**，
包含六個新增案例。使用原始 spawn／readiness 流程、隔離檔案及明確 synthetic
native calls，沒有執行 CPU workload 或改變任何實際 Job 限制。私人日誌
`.local-adaptive/tree-ready-commit-20260924-1.log`。可重現的正常准入命令：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command 'C:\Python313\python.exe -m unittest tests.test_adaptive_scope_cpu_worker tests.test_adaptive_scope_bootstrap tests.test_adaptive_scope_launch tests.test_adaptive_scope_wrapper_boundary -q' -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

這一批是獨立可提交的 fixture 改善，不代表 S1 或 P3–P6 native gate 通過。
Items 5/6 仍有下述 source 缺口；日常 runtime、config、Scheduled Task 與啟動入口
維持原狀，adaptive off。受保護 dirty baseline 仍未提交，測試依賴於 commit
message 揭露；未宣稱 clean-checkout 或 full-suite 通過。

另一次尚未通過的 bootstrap 草稿驗證，**不屬於以上已通過的切片**：
4 模組、127 tests、30 failures（含 subtest failures）、0 errors／skips，
runner 103.421 秒，私人日誌 `.local-adaptive/producer-bootstrap-commit-20260924-2.log`。
共同失敗代碼為 `daily_loaded_code_generation_mismatch`；尚未確認造成差異的
runtime function，不能略過這道檢查。較早 123 tests／22 failures／22.902 秒
先被 Windows path-stat 與 fstat 的 ctime 差異擋住；修正後才到目前的來源核對。
這些失敗不是 tree-ready 的回歸，也不是 native gate 的實測結果。

`tests/windows/adaptive_producer_bootstrap.py`、其 test module，以及尚無測試的
`adaptive_s1_measurements.py` 草稿均留在本機，未納入本次提交。前兩者的 review
已修正 imported binding 與 runtime parent alias 漏檢，但仍未通過執行驗證。
下一步先用隔離 source fixture 找到 loaded function／compiled code 的具體差異，
保留完整 source attestation，再驗證 helper；實際四模組 closure、entry、
capture/admission 與 v2 publication 接線也尚未完成。沒有新增 native 控制，
不需要撤回 Job CPU 限制。

### Serial provider checkpoint（歷史驗證）

Serial S1 provider 的原始 case／daily demand／admission／cleanup 接線已實作。
`tests/windows/adaptive_s1_provider.py` 保留同一個原始 case 與 command，排隊期間
不建立 native scope；准入後只準備一次 scope，部分失敗沿原始 owner 收尾，前一個
case 尚未正面釋放或取消時不能開始下一個。`recover_once()` 僅做原始 cleanup，
不重新准入、launch 或量測；marker／output 前置檢查失敗不阻止原始 close tick。
這不表示隔離 ledger 被破壞後仍能完成釋放；未知證據仍 HOLD。

獨立 review 找到的 public admission result handoff 缺口已補：呼叫前先記錄結果
未確認，exact bool 分類完成才清除；回覆遺失或本地賦值中斷，透過原始已完成
submission tuple 的唯讀 settlement，再做實際 abandon／release。清理完成不會
抹掉本次 run 的原始 errors。安全契約仍以
[S1-SERIAL-PROVIDER.md](S1-SERIAL-PROVIDER.md) 為準。

最終 **7 模組、140 PASS，0 failures／errors／skips，runner 29.899 秒**。
新增 provider 34 個案例，加上一個實際原始 scope prepare／completion／daily
release 整合案例。使用真實隔離 SQLite、Coordinator、原始 scope／launcher custody
與 release receipt；Win32、IPC、process creation 和 source attestation 為明確
fixtures，沒有 native workload 或 gate 通過聲明。三模組先行 67 PASS／15.987 秒；
更早 124 PASS／24.246 秒，測試重疊不相加。初次 provider 29 tests 有 2 failures：
synthetic process birth 與真實 PID observer 不一致，已讓兩個 fixture observer 使用
同一 identity，保留並補強 queue／capacity 斷言。最終私人日誌
`.local-adaptive/s1-provider-shared-20260924-2.log`。

```powershell
$sentinelS1ProviderTests = @(
    'tests.test_adaptive_s1_provider'
    'tests.test_adaptive_s1_provider_native'
    'tests.test_adaptive_experiment_demand'
    'tests.test_adaptive_experiment_admission_settlement'
    'tests.test_adaptive_experiment_unadmitted_cleanup'
    'tests.test_adaptive_experiment_generation_pin'
    'tests.test_adaptive_experiment_release_native'
)
$sentinelS1ProviderCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelS1ProviderTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelS1ProviderCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

Windows／base Python 3.13，正常日常 admission、沒有豁免。測試依賴受保護 dirty
baseline，commit message 揭露；未宣稱 clean-checkout 或 full-suite 通過。
**Items 5/6 仍未全部完成**：完整 serial S1 measurement、aggregate producer
bootstrap／v2 publication、fresh-generation restart、P4 aggregate/storage/overhead、
剩餘 S3 drivers／完整 orchestration 及 P6 A/B 仍有 source 工作。舊 common
admission placeholder 繼續拒絕，尚不能說只差使用者執行外部 console。未部署、
未變更日常 config／Scheduled Task／啟動入口，adaptive off；沒有實際 Job CPU
cap 需要撤回。下一步是將真正 S1 measurement runner 接上此原始 provider，並完成
aggregate fixture execution attestation／v2 producer publication。

### Job security observation checkpoint（歷史驗證）

Job security observation 與原始 dependency cleanup 已實作並驗證，契約見
[JOB-SECURITY-OBSERVATION.md](JOB-SECURITY-OBSERVATION.md)。`NativeJob.query_security()`
只查詢同一原始 handle，傳回實際 owner／logon SID、descriptor／ACL／ACE 及 handle
flags；buffer／token 正面清理後才產生 typed observation。中斷 acquisition／unknown
close 保留原始 owner，不能重做 native release；已知 FALSE 僅重試原始資源。
Job handle 已關閉仍不能掩蓋 security dependency 未清理。

Factory failure 先保管原始 partial Job，讓既有 readiness／POLICY scope 正面退出後
才重拋；未知退出仍保留原始錯誤與容量。已由 exact partial Job 管理的 security
owners 透過其實際 `.closed` gate 收尾，避免已知失敗稍後恢復仍被永久 pending
marker 阻擋。額外 owner、未知結果與其他 pending marker 保持 HOLD。

最終 **14 模組、339 PASS，0 failures／errors／skips，runner 39.635 秒**。
新增 24 個 security 與 5 個 scope integration 案例；使用真實 ctypes buffer、
隔離 SQLite／completion／release，以及明確 synthetic native／readiness fixtures。
獨立 review 找到的 acquisition handoff、舊 exception marker 與 delayed-known-close
問題已修正，另覆蓋額外 owner 與 readiness exit 再失敗。初測 157 tests 有 27 errors
（26 個新 fixture handle 型別錯誤與 1 個實際 scope pending 問題）；後續兩輪各有
1 個新 integration fixture 不完整問題，已補原始 mutex handle／persisted generation。
先前 159 PASS 與本輪重疊，不加總。私人日誌為
`.local-adaptive/job-security-shared-20260924-1.log`。

```powershell
$sentinelSecurityTests = @(
    'tests.test_adaptive_job_security'
    'tests.test_adaptive_scope_security_cleanup'
    'tests.test_adaptive_native_job'
    'tests.test_adaptive_policy_mutex'
    'tests.test_adaptive_host_discovery'
    'tests.test_adaptive_pipe_windows'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_native_deadlines'
    'tests.test_adaptive_experiment_probes'
    'tests.test_adaptive_native_launcher'
    'tests.test_adaptive_scope_wrapper_boundary'
)
$sentinelSecurityCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelSecurityTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelSecurityCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

Windows／base Python 3.13，正常日常 admission、沒有豁免。測試依賴受保護 dirty
baseline，commit message 揭露；不是 clean-clone full-suite 或 native gate 證據。
此 checkpoint 當時 Serial provider 尚待驗證（後續結果見頂端）；完整 measurement、aggregate producer
bootstrap／v2 publication、fresh-generation restart、P4／S3／P6 仍有 source 缺口。
Items 5/6 未完成；舊 common admission placeholder 繼續拒絕。未部署或變更日常
config／Scheduled Task／啟動入口，adaptive off，沒有施加或需撤回的實際 Job CPU cap。

成功准入的最終回覆若遺失，現在可用原始已保管的 submission tuple 做唯讀 settlement。
已清除的 guard 不重建、不重設；原始 POLICY／store／guard／binding／nonce、SQL
transaction 與正面 native／nonce cleanup 必須保持一致，否則繼續 HOLD。既有 pending
guard 路徑不變。契約見 [S1-SERIAL-PROVIDER.md](S1-SERIAL-PROVIDER.md) 的 result
handoff 段落。`tests.test_adaptive_experiment_admission_settlement` **32 PASS**
（10 個新案例），0 failures／errors／skips，runner 8.087 秒；日誌
`.local-adaptive/admission-return-20260924-1.log`。涵蓋成功 admitted／queued／第二次
queue poll、零持久寫入／新 native wait／nonce clear，以及替換或缺少原始證據的拒絕。
同樣使用正常 wrapper、隔離 SQL 與明確 native fixtures，仍非 native gate。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command 'C:\Python313\python.exe -m unittest tests.test_adaptive_experiment_admission_settlement -q' -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

### Mixed-source reader checkpoint（歷史驗證）

Mixed-source build reader／v2 consumer 已完成。契約見
[S1-SOURCE-BINDING.md](S1-SOURCE-BINDING.md)，serial custody 契約見
[S1-SERIAL-PROVIDER.md](S1-SERIAL-PROVIDER.md)。`SourceBoundBuildSource` 分別讀取
canonical runtime 與實際 fixture root，保留原始 SourceManifest、目錄 identity、
完整有界 inventories 及相對路徑 digest。重新驗證 actual canonical import
provenance；來源新增／移除／變動、目錄替換或意外 initializer 均拒絕。
Bundle v2 增加封閉 source binding；consumer 自行建立 reader，拒絕初始或事後
build callback 替換，v1 不變。磁碟來源核對不取代 producer 執行來源驗證。

最終四模組 **128 PASS，0 failures／errors／skips，runner 18.643 秒**；
先前三模組 111 PASS／17.068 秒，兩批重疊不加總。新檔有 25 個案例，包含
真實隔離檔案／目錄替換、來源變動、consumer 欄位／callback 拒絕與明確 synthetic
完整／缺 gate 資料。測試內 runtime import attestation 為明確 fixture；共同執行
既有 daily bootstrap 回歸。獨立 review 未發現 actionable defect，已補其建議的
runtime inventory、實際 root replacement 與完整 synthetic reducer 案例。
私人日誌 `.local-adaptive/source-binding-20260924-2.log`。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command 'C:\Python313\python.exe -m unittest tests.test_adaptive_capability_build tests.test_adaptive_capability_evidence tests.test_adaptive_capability_runner tests.test_adaptive_daily_bootstrap -q' -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

Windows／base Python 3.13，正常日常 admission，沒有豁免。測試依賴受保護 dirty
baseline 與同輪尚待獨立驗證的 Job security source；commit message 揭露。
沒有 actual native gate／clean-clone full-suite 通過聲明。尚未接通 aggregate
producer bootstrap、v2 publication 或完整 serial S1 measurement；舊 common
admission placeholder 仍拒絕。Job security observation 與 serial case custody
正在實作，不能當作已驗收。Items 5/6 仍有 source 缺口，後續 P4／S3／P6 缺口
維持未完成。未部署、未變更日常 config／Scheduled Task／啟動入口，adaptive off。

### 先前 S1 wrapper boundary checkpoint（歷史驗證）

S1 root／child scope timing 與 wrapper Create readiness source 已接線，先行契約
為 [`c64708c`](S1-WRAPPER-BOUNDARY.md)。Guardian 在原 allocation transaction
固定 reservation／binding、原始到期時間及保守 monotonic 截止點。Bootstrap v2
保留完整原始 generation；launch request v2 必須帶固定 bounds，重播不能換期限。
Wrapper 先保留單次 attempt，再在 Job lock 外取得自己的 readiness；Create 前
同時檢查原 IPC／readiness deadline、scope 與 lease，不能用父程序舊驗證代替。

Root 僅從繼承的有界 regular stdin 讀取 timing，逐一比對 immutable argv pins；
CPU cutoff 是原始啟動時間加 declared duration 與 scope 減四秒之較小值。Children
繼承同一 cutoff；bootstrap／Create 準備都消耗原期限。Native launch failure 在
readiness 正面收尾後才向外拋出；readiness 本身清理未知仍保留原 scope／error／
root，禁止宣稱 local_closed。獨立 read-only review 沒有 actionable finding。

首次 243 tests 有 9 errors，均為新 fixture 嘗試更新已不可變的 experiment
reservation。改為 capture／admission 前設定隔離測試 TTL，並驗證實際 SQL 拒絕
事後更新，沒有放寬 trigger。首次共用 414 tests 剩 2 errors，因注入早於 allocation
的 POLICY nonce transaction；已改為以真正 `_coverage_locked` 成功驗證的原始
connection 綁定注入點，保留 exactly-once 與原始 bounds／capacity 斷言。
另有四模組 **108 tests 全過**（runner 16.123 秒，0 failures／errors／skips）。

最終 **17 模組、414 tests 全過，0 failures／errors／skips**（unittest
58.231 秒／runner 58.500 秒），包含 54 個新增案例。完整私人日誌為
`.local-adaptive/scope-boundary-shared-20260924-2.log`。Windows／
`C:\Python313\python.exe`，正常日常 wrapper `HEAVY / P2 / CPU 1 / RAM 1 GiB /
I/O 0`，沒有豁免。實際隔離 SQLite、regular file 與隔離 Python bootstrap
subprocess 搭配明確 synthetic native／readiness fixtures；測試依賴受保護 dirty
baseline，commit message 揭露，不宣稱 clean checkout 或完整一般 suite 通過。

```powershell
$sentinelBoundaryTests = @(
    'tests.test_adaptive_scope_launch_bounds'
    'tests.test_adaptive_scope_wrapper_boundary'
    'tests.test_adaptive_scope_cpu_worker'
    'tests.test_adaptive_scope_bootstrap'
    'tests.test_adaptive_scope_launch'
    'tests.test_adaptive_native_launcher'
    'tests.test_adaptive_native_job'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_scope_journal'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_remote_readiness'
    'tests.test_adaptive_experiment_native_deadlines'
    'tests.test_adaptive_experiment_probes'
    'tests.test_adaptive_experiment_probe_history'
    'tests.test_adaptive_experiment_history_consumers'
)
$sentinelBoundaryCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelBoundaryTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelBoundaryCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

本批仍是 source／隔離測試證據；actual serial S1 provider、canonical aggregate
bootstrap、fresh-generation restart、P4 aggregate/storage/overhead、剩餘 S3
drivers／完整 orchestration 及 P6 A/B 仍有 source 工作，並非只差外部 console。
未進行 source activation、日常 config／Scheduled Task／啟動入口變更，adaptive
維持 off；沒有對實際 Job 施加 cap，也沒有需要撤回的限制。

原始 scope 的 reopened CONTROL probe／restore 已實作，契約見
[EXPERIMENT-REOPENED-PROBE.md](EXPERIMENT-REOPENED-PROBE.md)。Principal 始終保留；
每個 scope 最多兩次原始 open attempt、同時一個未收尾 probe。開啟失敗也保留
原始 factory owner；撤回限制使用指定 probe，principal／probe 都讀回 disabled
才 ACK。Probe 清理未知會阻止新限制與容量釋放，但不阻止有效的 principal restore。
所有 probe 正面關閉後才關 principal；沒有 probe 的 completion v1 保持原形狀，
使用 probe 的 v2 加入受 digest 保護的有界 custody 摘要，history 不取得 release 權限。

新增兩個測試檔共 30 個案例。History 初測 **50 PASS**（runner 9.756 秒），
scope／history／native Job 七模組 **158 PASS**（runner 30.993 秒），均無
failures／errors／skips。獨立 review 找到共用 factory exception 可能夾帶未記帳
owner，已修成核對完整 matching-owner 集合；涵蓋額外／重複 owner 拒絕及兩次合法
failed open 共用同一 exception。最後 read-only review 沒有其他 actionable finding。

最終共用回歸 **15 模組、288 PASS，0 failures／errors／skips**（unittest
64.815 秒／runner 65.095 秒），私人日誌
`.local-adaptive/scope-probes-shared-20260924-1.log`。涵蓋 probe／history、scope／
journal／preparation、release／custody／hooks、remote readiness、native deadline、
daily retirement 與 native Job 路徑。從 implementation worktree 執行等價命令：

```powershell
$sentinelProbeTests = @(
    'tests.test_adaptive_experiment_probes'
    'tests.test_adaptive_experiment_probe_history'
    'tests.test_adaptive_experiment_history'
    'tests.test_adaptive_experiment_history_consumers'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_scope_journal'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_release_custody'
    'tests.test_adaptive_experiment_release_hooks'
    'tests.test_adaptive_experiment_remote_readiness'
    'tests.test_adaptive_experiment_native_deadlines'
    'tests.test_adaptive_daily_retirement_integration'
    'tests.test_adaptive_native_job'
)
$sentinelProbeCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelProbeTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelProbeCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

本批使用 Windows／`C:\Python313\python.exe`、正常日常 wrapper 的
`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，沒有豁免。測試使用實際隔離 SQLite
和明確 synthetic native／transport fixtures；不代表實際 CPU 效果、P3–P6 native
gate 或 clean-clone full-suite 通過。受保護 dirty baseline 未納入提交，測試依賴會
在 commit message 揭露。日常 runtime／config／Scheduled Task／啟動入口未改，
adaptive 維持 off；沒有實際 Job cap 需要撤回。

S1 CPU fixture 的 child Create 邊界已補上原始 deadline 檢查：先保管尚未進入
Create 的 output cells，完成 command buffer／startup 參數後再查原期限，最後
才標記 Create 已進入。準備期間到期不建立 child，也不把它記成未知建立結果。
`tests.test_adaptive_scope_cpu_worker` **41 tests 全過，0 failures／errors／skips**
（runner 0.308 秒），私人日誌 `.local-adaptive/scope-child-deadline-20260924-1.log`。
新增案例在 buffer 準備耗盡期限，確認零 Create／duplicate／child wait／native
close，並正面清理原有 Job／self fixture owners。這不是 native 實測；後續完整 root／
child scope-bound protocol source 已接線，見上方最新 checkpoint。Reopened probe 的先行契約已入庫為
[`c59376a`](EXPERIMENT-REOPENED-PROBE.md)，source／整合測試已完成如上。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command 'C:\Python313\python.exe -m unittest tests.test_adaptive_scope_cpu_worker -q' -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

原始 experiment scope 的 remote readiness 接線已完成並驗證。Helper 只使用
鎖外已取得的原始 lexical scope／group member，不在鎖內開 SQL／RPC 或取得
替代 owner。Local owner 在同一次證明中固定；remote 分支不採用稍後出現的
local owner。Helper 與實際 coverage transaction 都核對完整原始 generation；
相鄰 Create／Set 將同一個原始 deadline 傳至既有底層檢查。Restore 繼續只依賴
isolated scope，不因日常 readiness 過期而失去撤回能力。

最後 **11 模組、364 tests 全過，0 failures／errors／skips**（runner 42.195 秒），
含 15 個新增案例；私人日誌 `.local-adaptive/remote-scope-shared-20260924-4.log`。
使用 Windows／`C:\Python313\python.exe` 與正常日常 wrapper，資源設定為
`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，沒有豁免。Actual SQLite／scope／
readiness authority 路徑使用明確 synthetic transport／native backends；不是 native
gate 或 clean-clone full-suite 證據。測試包含受保護 dirty baseline，commit 會揭露。

初次 349 tests 有 1 failure，修正原始 absence scope 的拒絕原因與驗證順序；
獨立審查另找到 launch 在取得 lexical scope 前提早呼叫 `_ready`，已修正並以
實際 `launch_once()` 回歸覆蓋。新增案例首輪有 1 failure／2 errors，原因是
fixture 未建立正式 exemption binding；改用原 POLICY 下的 `bind_policy_locked`。
下一輪僅 1 failure，修正新測試對 disabled 原始讀回值的預期（flags=0、rate=10000），
未更改 production disable 行為或豁免檢查。最後獨立 review 無 actionable finding。

父程序的一秒 readiness window 不代表稍後 wrapper root Create 的新鮮度；後續
wrapper 自身 readiness 與完整 root／child deadline source 已接線，見最新 checkpoint。
Actual serial provider、canonical aggregate fixture bootstrap 與
fresh-generation restart 仍是 source 缺口；P3–P6
尚未通過 native 驗收。日常 runtime／config／Scheduled Task／啟動入口未改，
adaptive 維持 off；本批沒有對實際工作施加 Job 限制，沒有需撤回的測試 cap。

從 implementation worktree 執行本批等價回歸：

```powershell
$sentinelRemoteTests = @(
    'tests.test_adaptive_daily_generation'
    'tests.test_adaptive_daily_readiness_lock_boundary'
    'tests.test_adaptive_daily_readiness_transport'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_native_deadlines'
    'tests.test_adaptive_native_job'
    'tests.test_adaptive_scope_launch'
    'tests.test_adaptive_experiment_remote_readiness'
)
$sentinelRemoteCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelRemoteTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelRemoteCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

### 原始 deadline 底層 checkpoint（歷史驗證）

Remote readiness 的原始 deadline 底層接線已完成：`NativeJob.create`、
`ScopeLaunch.create_inert` 與 `set_cpu_rate_unverified` 可接收 exact
`NativeDeadline`，在 security／fixture／command buffer／internal lock 準備後、
實際 Win32 Create／Set 前檢查同一原期限。預設 None 不改既有呼叫；disable／
restore 不被過期期限攔截。原始 setup owner 與未進入 Create 的證據繼續保留。
先行契約為 [EXPERIMENT-REMOTE-READINESS.md](EXPERIMENT-REMOTE-READINESS.md)。
四模組 **135 tests 全過，0 failures／errors／skips**（runner 0.315 秒），
包括 15 個新 deadline 案例，私人日誌為
`.local-adaptive/native-deadline-20260924-1.log`。獨立 review 無 actionable finding。
這是底層 source 邊界驗證；scope 的實際 remote authority 接線已在上方最新
checkpoint 完成，不能因 optional 參數或 synthetic Win32 fixtures 宣稱 native gate 通過。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command 'C:\Python313\python.exe -m unittest tests.test_adaptive_experiment_native_deadlines tests.test_adaptive_native_job tests.test_adaptive_native_launcher tests.test_adaptive_scope_launch -q' -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

原始 unadmitted experiment 收尾已實作，先行契約為
[`55adc56`](EXPERIMENT-UNADMITTED-CLEANUP.md)。
`Coordinator.abandon_experiment(demand)` 保留同一原始 demand、submission guard、
transaction、generation 與 process witness。它只刪除原始 queue row；admitted、
native preparation、未知清理或無原始提交證據的 absence 均拒絕。需要繼續的工作
仍須排隊；這個入口供確定放棄／終止的實驗收尾，不是繞過准入的方法。

刪除使用 exact-key UDF 與完整 preimage trigger；真正 writer 在 BEGIN IMMEDIATE
後才固定原列。Lost COMMIT ACK 只對帳同一 attempt；只有從未嘗試 COMMIT 且
原始 rollback／SQL close 都正面確認，才可重新讀取仍屬原請求的更新後 queue。
Readback 證明無義務後才關閉原 self witness；known FALSE 只重試原 handle，
unknown 保留原始 owner，成功重播只讀。不寫入假的 native completion／release
receipt，也不取消其他 owner、修改 reservation／exemption 或授予容量。

POLICY 原始 guard 在 native wait 前保留。普通 readmission 遇到 clear ACK 遺失，
必須在正面關閉的原始 NULL-nonce reader 後驗證 own clear attempt／native cleanup，
確認舊 guard 已清理才可 prepare 下一個 nonce。Pending submission 仍先用既有
settlement API，不能由 abandon 偷渡新 guard。獨立 review 的重試問題已修正：
known rollback 的 preimage 重取、clear ACK 後的 guard 銜接，以及 writer BEGIN
尚未成功就凍結 preimage。最終 review 沒有其他 actionable finding。

新增測試檔共 30 個案例；首批共用六模組 **125 tests 通過，28.074 秒**；修正後
四模組故障驗證 **71 tests 通過，13.312 秒，0 failures／errors／skips**，私人日誌為
`.local-adaptive/unadmitted-cleanup-20260924-1.log`。測試使用實際隔離 SQLite，
native handle／transport 使用明確 synthetic fixtures，不是 native acceptance。

最終 **26 模組、637 tests 全過，102.596 秒，0 failures／errors／skips**
（runner 102.868 秒），私人日誌為 `.local-adaptive/unadmitted-final-20260924-1.log`。
下方共用回歸命令已包含新增 unadmitted 模組，可重現此範圍。Windows／
`C:\Python313\python.exe`，經正常日常 wrapper 的
`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，無豁免。涵蓋 generation／readiness／
retirement、原始 scope／release、POLICY、guardian 與 managed admission；沒有執行
native 控制／故障 spikes。受保護 dirty baseline 保留，測試依賴會在 commit message
揭露；不宣稱 clean-clone full-suite 通過。日常 config／Scheduled Task／啟動入口
未變，adaptive 維持 off，沒有實際工作 Job 限制需要撤回。

### 先前原始 admission settlement checkpoint（歷史驗證）

原始 initial admission 的 sealed cleanup 入口已實作：
`Coordinator.settle_experiment_admission(demand)` 只接受同一 retained demand，
使用原始 generation／POLICY／nonce／transaction／process witness 做有界
READ／CLEAR。它不重新准入、不取得新 readiness／native mutex、不釋放容量，
也不製造 completion。原始 SQL 與 native cleanup 都正面確認後，才清除 pending
guard；之後原有 `seal_without_native()`／typed release 可繼續處理已准入需求。
重試仍綁定同一 owner；未知 close 保留原始物件並拒絕重新開啟。

同時補上 POLICY timeout／body failure 中被忽略的 nonce-clear exception，
以有界 error graph 保留確切 SQL／native owner。Readiness 只將「clear ACK 遺失、
但原始 SQL 已正面關閉」視為可收尾；未知清理仍保持隔離。兩個新增檔共 30 個
案例，涵蓋原始 SQLite admission／settlement／completion／release、DRAINING、
HOLD、複製物件拒絕、清理結果未知與本機 bookkeeping 中斷。

首次新增案例批次 84 tests 有 1 error：原 demand 已隔離，程式會在建立 settlement
前拒絕，但 fixture 仍讀取不存在的 operation。修正 fixture 為核對原始 exception／
connection 保留及重試無 SQL；沒有放寬 source 檢查。後續六模組 **92 tests 全過，
29.889 秒，0 failures／errors／skips**；私人日誌為
`.local-adaptive/admission-settlement-20260924-2.log`。獨立 review 完成，修正後
沒有其他 actionable finding。

最終共用 consumer 回歸 **25 模組、607 tests 全過，88.498 秒，
0 failures／errors／skips**（runner 88.753 秒），私人日誌為
`.local-adaptive/admission-settlement-final-20260924-1.log`。範圍包括 readiness、
generation／retirement、POLICY、guardian、native identity smoke、原始 experiment
scope／release 與 managed admission。與上述批次重疊，不加總 distinct cases。
使用 Windows／`C:\Python313\python.exe`、正常日常 wrapper 的
`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，沒有豁免。測試依賴受保護的未提交
baseline；沒有宣稱 clean-clone 全套通過。沒有執行 native CPU cap／fault spikes，
沒有修改日常 config、Scheduled Task 或全域啟動入口。

從 implementation worktree 執行最新整合回歸命令（含後續 unadmitted cleanup）：

```powershell
$sentinelSettlementTests = @(
    'tests.test_adaptive_daily_connection_hooks'
    'tests.test_adaptive_daily_generation'
    'tests.test_adaptive_daily_readiness_lock_boundary'
    'tests.test_adaptive_daily_readiness_transport'
    'tests.test_adaptive_daily_retirement_integration'
    'tests.test_adaptive_daily_retirement_policy'
    'tests.test_adaptive_evidence_scope'
    'tests.test_adaptive_experiment_demand'
    'tests.test_adaptive_experiment_exclusion'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_scope_journal'
    'tests.test_adaptive_guardian_accounting'
    'tests.test_adaptive_guardian_operations_host'
    'tests.test_adaptive_guardian_startup_retention'
    'tests.test_adaptive_native_job'
    'tests.test_adaptive_policy_fencing'
    'tests.test_adaptive_policy_scope'
    'tests.test_adaptive_experiment_admission_settlement'
    'tests.test_adaptive_policy_cleanup_custody'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release_custody'
    'tests.test_adaptive_experiment_release_hooks'
    'tests.test_adaptive_managed_admission'
    'tests.test_adaptive_experiment_unadmitted_cleanup'
)
$sentinelSettlementCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelSettlementTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelSettlementCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

Settlement 對 QUEUED／SUBMISSION_REJECTED／absence 仍只回報觀測狀態，不提供
cancel、self close 或釋放權限。這些需求的原始 context 最終收尾已由上方獨立
abandon 入口補上；native scope remote readiness 已在最新 checkpoint 接線；actual
serial provider、fresh-generation restart 及 P4／S3／P6 下述缺口仍需 source 工作。Native gate 未通過，
production adaptive 維持 off。

### 先前原始 release checkpoint（歷史驗證）

原始 experiment release 已實作：`Coordinator.release_experiment` 只接受原 demand
保留的 typed operation，在同一交易發布 receipt、unused daily cancellation、
archive、精確 reservation／queue 刪除、CLOSED exclusion 與 registry revision。
SQL／native POLICY 正面清理及完整歷史 readback 後，才關閉原始 self witness；
成功 replay 只讀。未知 close 保留原 owner，已知 FALSE 只允許同 handle 重試。
所有五種 completion 皆有原始 factory／scope 流程測試，沒有以 JSON 冒充 capability。

最終 **17 模組、322 tests 全過，85.971 秒，0 failures／errors／skips**；
私人日誌為 `.local-adaptive/experiment-release-final-20260924-1.log`。
獨立 review 找到的兩項問題已修正並納入：stored IPC key 必須比對原始 key；
只有從未嘗試 COMMIT、已正面 rollback 並完成原始清理的 candidate 才能重新
取得目前 preimage，避免正常 expiry／revision 變更永久卡住。Lost COMMIT ACK
仍只對帳原 candidate。修正後的獨立 review 沒有其他 actionable finding。

上述與此前三批驗證都使用 Windows、`C:\Python313\python.exe` 及正常日常 wrapper
（`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，無豁免）。前三批亦全部通過：

- 原子 release／fault／custody：**58 tests，20.604 秒**；
  `.local-adaptive/experiment-release-publication-20260924-3.log`。
- 原始 scope／release／consumer：**124 tests，33.557 秒**；
  `.local-adaptive/experiment-release-scope-20260924-1.log`。
- 共用 POLICY／admission／retirement 回歸：**194 tests，50.881 秒**；
  `.local-adaptive/experiment-release-policy-regression-20260924-1.log`。

上述範圍有重疊，不相加宣稱 distinct test 總數。兩個新增檔共 33 個案例；
實際 Win32 I/O、source/readiness attestation 與 transport 使用明確 synthetic
fixtures，尚未證明 fresh native admission／serial provider 或任何 native gate。
測試仍依賴受保護的 dirty baseline；沒有修改日常 config、Scheduled Task、啟動
入口，沒有對真實工作施加 Job 限制。當時尚缺的 initial admission sealed
cleanup 入口已在上方最新 checkpoint 補上；remote scope owner、actual provider
與 fresh restart 仍是 source 缺口，不能以新 admission、重設 seal 或假的
completion 代替。

本批 source 回歸可從 implementation worktree 以 PowerShell 執行下列等價命令。
它不會執行 S1–S3 native acceptance；私密逐例日誌由本機 runner 另外保存。

```powershell
$sentinelReleaseTests = @(
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_history_consumers'
    'tests.test_adaptive_experiment_exclusion'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_experiment_preparation'
    'tests.test_adaptive_policy_scope'
    'tests.test_adaptive_managed_admission'
    'tests.test_adaptive_terminal_custody'
    'tests.test_adaptive_daily_retirement_policy'
    'tests.test_adaptive_daily_retirement_integration'
    'tests.test_adaptive_experiment_history'
    'tests.test_adaptive_experiment_demand'
    'tests.test_adaptive_daily_retirement_inventory'
    'tests.test_adaptive_policy_fencing'
    'tests.test_adaptive_experiment_release_custody'
    'tests.test_adaptive_experiment_release_hooks'
)
$sentinelReleaseCommand = 'C:\Python313\python.exe -m unittest ' + ($sentinelReleaseTests -join ' ') + ' -q'
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $sentinelReleaseCommand -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

History consumer 接線已完成，**9 模組、204 tests 全過，44.941 秒，
0 failures／errors／skips**，私人日誌為
`.local-adaptive/experiment-release-consumers-20260924-2.log`。新准入與 exclusion
讀取先核對完整歷史，再計算仍未完成的名額；retirement 同時保留已完成實驗與
production FINISHED／C2 的各自證據，從同一 snapshot 的原始 SQL rows 計帳，
共用 16 MiB 上限。已完成 managed row 的所有欄位受到不可變 guard 保護。
首次 203 tests 有 1 failure／17 errors：舊 raw SQL fixture 缺少新的固定拒絕
UDF、舊拒絕位置／訊息預期，以及三個 C2 fixture 欄位引用錯誤；修正後仍保留
拒絕、實際 INSERT 失敗 rollback 與歷史完整性斷言。這個 consumer 提交本身
不提供原始 receipt publisher；原子 release 的後續驗證見上方最新 checkpoint。
此 consumer checkpoint 當時尚缺的 initial admission guard 公開收尾入口，
已由上方最新 settlement source 補上；其驗證不等於 native provider 完成。

Cleanup history 資料驗證器已完成：**9 模組、165 tests 全過，21.627 秒，
0 failures／errors／skips**，包含 23 個 history 案例；完整私人日誌為
`.local-adaptive/experiment-history-20260924-1.log`。它在同一 SQL snapshot
核對 immutable admission、確切 cancellation／archive、沒有殘留容量義務，
以及對應 CLOSED exclusion，並保留 4096 rows／table 與共用 16 MiB byte budget。
已涵蓋五種 completion 資料、混合已完成與一個未完成實驗、兩個未完成實驗拒絕、
scope／ledger 身分、preparation 順序、task／reservation aliases 與異常歷史。
獨立 review 已完成；測試使用隔離資料及 synthetic closed tuples，經正常日常
wrapper 准入，仍依賴受保護的 dirty baseline。這不是 native gate 證據。
**驗證器本身只讀，不發布 receipt、不釋放容量。** Consumer 接線已完成，見
上方最新驗證；原始 typed operation 的原子交易也已實作，見最新 checkpoint。

Cleanup 的原始 operation／read／nonce 接線已完成，**15 模組、351 tests 全過，
45.886 秒，0 failures／errors／skips**。`DailyExperimentDemand.prepare_release`
現在保留同一原始 completion、admission POLICY binding 與 generation；read／nonce
階段可在同 generation 的 ACTIVE／DRAINING 重驗，不取得新 readiness 或一般容量
UDF。未知 SQL close、native wait／constructor close 的原始 owner 會保留並拒絕
重新取得；lost nonce COMMIT ACK 則核對同一原始 candidate。完整私人日誌為
`.local-adaptive/experiment-release-custody-20260924-4.log`。
這批含 13 個原始 custody 與 11 個 hook／trigger 案例，原生 API 以明確 synthetic
backend 驗證控制流程，沒有實際 Job 控制。第一次 282 tests 有 2 failures／2 errors，
原因為更早的 canonical guard 拒絕及舊 queue fixture 缺少 request_key；修正 fixture
保留原本拒絕斷言後 283 tests 全過。後續 350 tests 的 10 errors 是新 release
lookup 對非 release 的 SQL-only POLICY fixture 不必要地讀取 db_path；改為先確認
有原始 release scope 才取路徑，最終 351 tests 全過。獨立 review 找到的 native
不確定持有者與 timeout-clear 例外覆蓋問題已修正並納入最終測試。
本段記錄 read／nonce 階段的歷史驗證；後續 publication 與 consumer 整合已完成，
不能將這批較早測試單獨視為容量釋放證據。

原始 experiment generation binding 已補上：同一 authenticated SQL reader 在
`BEGIN` 後重驗完整 generation row，正面 close 後才固定原始 pin；後續 admission
與 writer snapshot 比較所有欄位，completion 只回傳原始資料的副本。缺少原始
pin 的舊物件拒絕補建，不從 cleanup 時的新 row 推回來源。五個相關模組
**179 tests 全過，19.063 秒，0 failures／errors／skips**；包含 10 個新增案例，
私人日誌為 `.local-adaptive/experiment-generation-pin-20260924-1.log`，已提交並 push
為 `d78916a`。
測試經正常日常 wrapper 准入，依賴受保護的 dirty baseline；未執行 native 控制。
這是 typed release 的前置 binding；精確 cleanup-only SQL、receipt／history
交易、remote scope 與 native provider 仍待完成，尚未授予容量釋放權限。

最新完成 generation 正面退場整合：**654 tests 全過，94.827 秒，
0 failures／errors／skips**。包含固定凍結下的收尾、完整歷史與 journal inventory、
原始 SQL／POLICY／readiness／native owner 的正面 cleanup，以及 Windows
檔案身分修正。不是 native acceptance 或日常 activation；remote readiness 鎖外
接線另見下述 413-test 驗證；fresh restart、真正 native provider 與下述
P4/P6 source 缺口仍待完成。
完整私人日誌為 `.local-adaptive/retirement-integration-20260924-1.log`。
該包已提交為 `41cee4d`。Resident host bounded telemetry 與 helper 非阻塞
poll／cleanup 接線另通過 **276 tests，8.418 秒，0 failures／errors／skips**。
固定共用 20 MiB／7 天日誌上限已實作；P4 原始 sink 接線最新七模組
**259 tests 全過，13.765 秒，0 failures／errors／skips**。包含真實 offer／
append receipt、精確 shared inventory 對帳、closed P4 v2 schema，以及
提早拒絕超過 2 MiB 的 trace／拒絕保存錯誤 traceback 造成的隱藏滯留。
整份 artifact 上限與既有 idle／Private Commit／log gate 保持不變。
私人日誌為 `.local-adaptive/p4-sink-regression-20260924-1.log`；真正 aggregate
provider、storage-fault／rollover／recovery 證據及 native 成本仍缺。
P4 source 包已正常 push 為 `852044b`。
Telemetry 包為 `2b34df2`；原始 launch deadline 修正為 `10e42f5`，日常
legacy writer 的 experiment exclusion 為 `9f4d080`。原始 S1 scope／journal、
distinct wrapper 與 source bootstrap 最新 **303 tests 通過，19.533 秒，
0 failures／errors／skips**；CPU fixture 已提交為 `82e3450`。九個實際隔離
Python subprocess tests 驗證 stale `.pyc`／initializer 拒絕，沒有執行 native
Job 或 CPU 壓力實驗。Daily release／history、serial provider、native scope 的
remote owner 接線及 generation successor 仍是 source 工作，不是只等主控台執行。

後續 [readiness 鎖界線](DAILY-READINESS-LOCK-BOUNDARY.md)與 experiment preparation
的 14 模組整合 **413 tests 全過，47.653 秒，0 failures／errors／skips**。
已涵蓋兩帳本鎖外預先取得、獨立 absence pool、原 local scope 結束後拒絕寫入、
原始 preparation registration／不可逆 seal、正面 early cleanup，以及
`BEFORE_NATIVE` 收據的同連線／檔案身分重驗。這些完成證據仍不能自行釋放日常
reservation；typed release／歷史重用的原子交易尚未實作。S1 native 尚未接通。
首次同範圍有 1 failure／4 errors，均為新預讀路徑下的 fixture 注入位置及
空表與不存在表的區分，保留 production 檢查後修正並重跑。
完整私人日誌為 `.local-adaptive/readiness-preparation-20260924-2.log`。
[實驗 cleanup receipt 契約](EXPERIMENT-CLEANUP-RECEIPT.md)已先以
`ca2944b` 提交，完整 generation binding 與 cleanup-only SQL 階段補充為
`fdf2621`。失敗 Job factory 的原始物件保留修補為 `9b50531`，
**48 portable tests 全過，0.207 秒，0 failures／errors／skips**。
此修補分開保存已正面關閉與尚未確定的 acquisition，不把沒有回傳物件
當作沒有資源，也不授予任何新的 query／control 權限。

本輪另執行一般 adaptive 回歸：**155 個 root test modules，4,166 tests，
752.034 秒，2 failures／9 errors／0 skips**。沒有選入 `tests/windows` 的
控制 spikes。失敗確認為兩項 connection source 回歸（原始 close 例外進入
公開 traceback、existing-only 帳本檢查晚於 readiness 選取），以及 `2b34df2`
後尚未更新的 guardian telemetry fixture。Source 已保留私密原始 connection／
error custody 並恢復 sanitized exception；readiness 與 transaction 共同使用
實際 pinned ledger，既有 mode=rw 仍禁止遺失檔案被重建。Fixture 只接上真實
host emit 介面，保留全部同 owner、drain、no-relaunch、no-recreate 斷言。
完整失敗日誌為 `.local-adaptive/adaptive-full-20260924-1.log`；修正後的最終
18 模組回歸 **493 tests 全過，55.779 秒，0 failures／errors／skips**，
涵蓋全部原失敗模組及 readiness／preparation／retirement 整合。私人日誌為
`.local-adaptive/readiness-host-regression-20260924-2.log`。前一輪相同 493 tests
剩一個 fixture 未先建立 existing-only 帳本的 error，補上真實臨時 SQLite 後
重跑，未放寬檢查。沒有重新執行完整 4,166 tests，不把前述整套紀錄改寫為全過。

上述測試在 Windows／`C:\Python313\python.exe` 執行，使用正常日常 wrapper
准入，`HEAVY / P2 / CPU 1 / RAM 1 GiB / I/O 0`，無豁免。完整一般回歸的
精確清單留在 `.local-adaptive/adaptive-portable-modules-20260924.txt`；檔名不
代表全部只跑 portable mock，既有 Windows 自身身分／隔離 IPC／mutex 等
smoke 也在一般 suite 內。未執行 native CPU cap／故障控制 spikes，沒有
production activation。測試包含受保護的 dirty baseline；不宣稱 clean clone。

接手時 Coordinator 的既存 freshness／共用計帳修正已獨立提交為 `6abadba`。
裁決 ② 的[退場契約](P3-PRELAUNCH-RETIREMENT.md)先於程式提交為 `8cd06e7`。
目前的 source 已接上 shared launch fence、guardian never-started 證據、原子退場
receipt、supervisor 核對與 host 每輪 cleanup。完整 adaptive 回歸 82 個模組、
2,007 個測試通過（233.928 秒）；之後獨立 review 找到 wrapper mutex 關閉結果
不明時的重試風險，已修正並新增六個案例，最後重跑 102 個受影響測試全過
（24.642 秒）。這兩次均為 0 failures／errors／skips；完整回歸的 2,007 不包含
最後新增的六個測試。Native acceptance 仍未驗證。

裁決 ④ 的 [supervisor failsafe 契約](P3-SUPERVISOR-FAILSAFE.md)於 `2873a3f`
先提交。C4 source 現已完成：lifetime instance fence、沒有舊 handle 時的明確 HOLD、
原 creation witness 的 early-death recovery、每輪同 guard 的 registry/barrier retry、
完整歷史證據後的 epoch rollover。獨立 review 找到並修正建立後 POLICY exit 遺失
custody、SQL 暫時故障丟失 guard、interrupt 隱藏 pending operation，以及後續 attach
繞過未清理 operation 的問題。最後完整 adaptive 回歸 **2,127 tests 全過，236.798 秒，
0 failures／errors／skips**；其前 120 個針對性 tests 亦全過（20.556 秒）。
這是 source 與隔離 fixture 的驗證，不是 native P3–P6 通過。

目標 3 的 [helper control 接線契約](P4-HELPER-CONTROL-INTEGRATION.md)已先以
`e6f406d` 提交。Source 現已接上獨立 active sender、typed frame/restore transport、
guardian 驗證、ACK 驅動階梯恢復與單調 demand floor。原 shadow helper 保持 query-only；
沒有實測證據、啟動範圍證據或有效 receipt 時拒絕限速。外部 console 的 S1–S3、
成本、恢復時間與 A/B 結果尚未產生，不能由 fixture 或 mode 字串取代。
最後完整 adaptive 回歸 **91 個模組、2,298 tests 全過，305.309 秒，
0 failures／errors／skips**，包含 launch-scope 缺證據拒絕。此前 114 個
restore/floor、117 個 decision/helper 與 27 個 capability 針對性測試亦通過。

目標 4 的 [operational lifecycle 契約](P3-OPERATIONAL-LIFECYCLE.md)先以
`186178d` 入庫。第一個實作包完成 original-context queued／RESERVED cancellation、
同 request 的 Prepare／Claim 對帳、retained native no-create 證據，以及 wrapper
不丟棄 custody 的失敗收尾。直接 Prepare 先封住取消競態；取消交易核對 allocation
唯一性及兩種 queue 關聯。335 個 admission／launcher／terminal／transport 針對性
tests 全過（24.979 秒，0 failures／errors／skips）；此數包含尚在整合的 terminal
與 transport 包，不是本提交單獨的乾淨 checkout 測試數。CLI／helper observer 另有
110 tests 全過（14.175 秒），guardian operational host 57 tests 全過（1.009 秒）。
後續操作通訊／發現包已提交為 `cae36bc`，生命週期收尾包為 `8bcd3eb`。
Guardian／supervisor／helper、off-recovery 與 CLI 的 source 整合現已完成。
新增原子 guardian identity／epoch／logon 登記，讓空白 host 在第一個工作之前
就有可驗證的操作身分；登記 ACK 遺失或中斷保留同一 guard 與原持有者。
Drain 保留 BindRoot／退場／原請求 replay 通道，停止新授權；terminal native
cleanup 完成前保留 custody，未知 close 結果不會被當成退場。

最後完整 adaptive 回歸 **108 個模組、2,800 tests 全過，455.257 秒，
0 failures／errors／skips**。範圍為當時 Git 已追蹤的 adaptive tests 加上本次兩個
guardian registration/startup 模組；確切清單留在本機
`.local-adaptive/item4-regression-modules-2800.txt`。命令為
`C:\Python313\python.exe .local-adaptive\item4-regression.py`，透過下述日常 wrapper
正常准入。此前 364 個 host/drain integration tests 通過（82.491 秒），新增
startup 與 S3 foundation 的 157 個 targeted tests 亦通過（4.326 秒）。
完整測試仍使用受保護的 dirty baseline，且當時 capability／A/B tracked tests
有後續階段的未提交修改；這不是 clean-clone 或 native gate 已驗證的聲明。

這輪故障紀錄：首次完整 2,774 tests 有 1 error，舊測試在 admission commit ACK
遺失後直接索取 claim token。現改為確認 read-only reconciliation 不會結算原
guard，也不能匯出 unsettled token；沒有放寬 production 契約。首次 off/terminal
204 tests 有 1 failure／2 errors，分別修正已知拒絕逸出 POLICY 留下 nonce 的
source 問題，以及超過 10 個 active Job 的歷史 fixture。首次 startup 79 tests
有 11 errors，fixture 未建立 journal 目錄，修正後通過。另兩次 targeted 命令
各誤列一個不存在的 test module，已用正確模組與最終完整回歸取代；沒有把
loader error 或未跑的 native gate 算成 pass。

| 目標項目 | 已驗證狀態／剩餘工作 |
| --- | --- |
| 1. 裁決 ② | 契約與 source 完成；完整 2,007 tests，最後 cleanup 修正後 102 tests 通過。 |
| 2. 裁決 ④ | 契約與 source 完成；最後完整 adaptive 2,127 tests 通過。沒有舊 witness 的 cold adoption 仍不支援；native recovery 未驗證。 |
| 3. helper sender | Source 接線、獨立 review 與完整 2,298 tests 通過。後續 original launch/stdio provenance、guardian scope 比對與 helper proposal adapter 已接線，344 targeted tests 通過（30.960 秒，含 30 個專用 scope tests）。實際 S2 topology producer／native bundle／新增採集成本仍未驗證，缺證據不啟用控制。 |
| 4. release／CLI | Source 整合與完整 2,800 tests 通過；包含 exact discovery、typed operator transport、原子 off／audit、同 owner 收尾與三個 host 的 drain。後續 rootless C2 post-close receipt 已補上，保持原 terminal state，不偽造 FINISHED；新增 29 個案例。232 targeted tests 中 231 通過，唯一錯誤文字預期修正後單獨重跑通過，production 未因該失敗改動。沒有原始 close 證據的舊歷史仍 unknown。Native 操作通訊、控制及恢復仍未驗證。 |
| 5. 全程容量覆蓋 | [Source generation／retained cohort／readiness transport 與接線](P2-DAILY-ACTIVATION.md)已完成 installer、常駐 owner 與日常 consumers 接線。Generation 正面退場整合 654 tests 通過；typed daily release／history、sealed admission guard、queued／rejected 原始 context 收尾及 native scope remote readiness 均已實作。Reopened probe／restore 已提交 `c29bf14`，288 tests 通過；root／child scope timing 與 wrapper 自身 readiness 已接線，最新 17 模組 414 tests 全過（runner 58.500 秒）。真正 serial native provider 與 fresh restart 仍待完成。未執行日常安裝，grace 前提未解鎖。 |
| 6. console 驗收命令 | [P6 矩陣編排與 raw reducer](P6-RUNNER-CONTRACT.md)、[S1/S2 bridge 契約](S1-DAILY-BRIDGE-CONTRACT.md)、[S3 精確故障點與 14×10 記錄器](S3-REAL-HOST-RECOVERY.md)、[P4 實際 host 成本量測](P4-OVERHEAD-RUNNER.md)已提交。新 bounded telemetry／helper 非阻塞接線 276 tests 通過（8.418 秒）；P4 原 sink 與 v2 schema 最新 259 tests 通過（13.765 秒）。Actual provider、部分 S3 故障 driver／完整 orchestration、A0 等價性及 P4 native storage／overhead 證據仍缺；不是只剩 console 執行。 |

最新追加：項目 5 的同帳本 demand 與 retirement fence 已提交為 `1072786`／
`a48925a`；native scope source 曾通過 303-test 整合；後續正向 daily release
已實作，actual provider 仍缺。項目 6 的 P6 矩陣編排及 raw
reducer 已提交為 `ff6f31b`，S3 原始 action cutpoints／三個實際故障 driver／
14×10 記錄器為 `7307055`；真正 native provider、部分故障 driver、A0 等價性及
140 次完整實驗 orchestration 尚缺。[原始成員的 bounded memory 查詢](P4-MEMBER-MEMORY.md)
已提交為 `2922e09`，以 private working set／private Commit、原始 process handles
與完整 membership 證據計算；不使用共享 RSS，不完整採樣保持 unknown。

以上是目前缺口；下列較早日期的段落保留其歷史測試範圍。Native S1–S3、完整
P3–P6 都尚未通過。日常 config／Scheduled Task／啟動入口未修改。

下一步是項目 5 actual serial provider 與 fresh-generation restart。Scope 已接上
完整原始 generation 比對與相鄰 native 邊界的原始 deadline 重驗。Provider 仍須
保留同一 demand 的排隊／收尾、呼叫已完成的 reopened-handle restore，以及在 import
runner 前完成 canonical fixture bootstrap；不能把舊 S1Runtime 當作新 provider。
Root／child scope deadline 與 wrapper 自己的 launch readiness source 已完成；
provider 必須接上這些原始 API，不延長一秒 window 或重建已凍結的 command。新增測試繼續
使用隔離帳本；任何實際
日常 source activation 都需要獨立授權，不因 commit/push 自動執行。項目 6
尚未完成的內容不能以 mock、空 provider、另外一個 DB 或假量測取代。

Serial provider 的接線另有兩個具體 source 前提：`CurrentBuildSource` 目前將
runtime 與 tests inventory 都綁在 production module 的 `_ROOT`。Canonical
production 與已審核 worktree fixture 分置時，必須對實際載入的 fixture closure
計算 producer digest，不能發布另一個目錄的 hash。另 `NativeJob` 確實在原始
handle 上驗證 DACL，但沒有公開 S1 evidence 所需的實際 protected-DACL／ACE-count
observation；須保留原查詢／descriptor 正面 cleanup 後的 bounded 結果，不能從舊
`OwnedJob.security` 預設值或固定常數製造實測欄位。這兩項是 provider 接線工作，
不是 Windows capability 已失敗，也不需要放寬既有安全條件。

同帳本 experiment demand 的新增契約已先以 `ed0c2cf` 提交；
[generation 正面退場契約](DAILY-GENERATION-RETIREMENT.md)為 `b281fd3`。
日常 retirement fence 已實作並提交為 `a48925a`；同帳本 demand source 為
`1072786`，P6 編排與 raw trace reducer 為 `ff6f31b`。新增 demand 使用原本日常
reservation，不建立另一份容量；TTL、root exit 或未知 cleanup 都不能釋放它。
P6 現已固定七情境、三組比較、十配對，以及獨立 noise calibration；完整矩陣為
420 個比較 runs 加 420 個 calibration runs，尚未實際執行。

上述三包合跑 **308 tests 通過，21.977 秒，0 failures／errors／skips**：

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_daily_retirement_fence tests.test_adaptive_experiment_demand tests.test_adaptive_managed_admission tests.test_adaptive_admission_context tests.test_adaptive_abandon_admission tests.test_adaptive_coordinator tests.test_adaptive_orchestrator tests.test_adaptive_measurements tests.test_adaptive_scope_workload tests.test_adaptive_runner -q
```

測試依賴受保護的 dirty baseline 及相鄰未提交 retirement 整合；不是乾淨 clone
或 native gate 的證據。後續 original native scope／grant 同步／writer exclusion
及 wrapper source bootstrap 已有 source 與 303-test 證據；Demand 的 admitted
release、actual provider 的 canonical fixture module 接線、A0 source equivalence
與完整 native cleanup bridge 仍待整合。退場之後的明確 fresh-generation
restart 仍是 source 缺口；不能把關閉 keeper 說成恢復 admission-only。

Memory／helper／P4／S3 合跑 459 tests（18.746 秒），458 通過，唯一 error 是 P4
新增 fixture 直接建構缺少 35 個必填值的 `PolicyProfile()`。Memory 與 S3 全部通過；
P4 fixture 已改用既有驗證過的 profile。此前 memory 第一輪 179 tests 有一個
新 query 模組未列入結構白名單的 failure，以及一個不存在的 test module loader
error；已補上 query-only 結構斷言並用正確 operator 模組執行這次合跑。

P4 後續四模組重跑 **155 tests 全過（12.967 秒，0 failures／errors／skips）**。
同時修正原始 callback 核對：兩個 builtin functions 不能只因 `__self__` 相同、
`__func__` 都為空就視為同一個。實際 host 的 registry／operator poll／report
write+flush 均納入成本，50 query scopes 共用同一個 256 records／100 ms budget；
十個 managed Jobs 上限不變。只有預先指定 P4 類型的 artifact 使用 2 MiB 上限，
其他 artifact 與 IPC 仍為 256 KiB。

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_overhead_runner tests.test_adaptive_overhead_host tests.test_adaptive_capability_evidence tests.test_adaptive_capability_runner -q
```

P4 尚存的具體 source／native 缺口：actual provider 的 keeper role 必須綁定原始
daily-generation owner，不能只提供任意同 logon 的 live process；現有 operator
idle poll 已改成 nonblocking，但尚未實測 tick p95；bounded storage source 已通過
276 host tests；原 P4 stderr producer 已由真實 sink 與 v2 schema 取代，
新接線的 259 tests 通過，完整 authenticated aggregate provider 仍缺。
既有 idle-after log bytes 不可大於 idle-before 的 gate 比正式計畫
bounded growth 更嚴格，尚未放寬或忽略其失敗。所有 native 成本門檻仍未驗證。

舊 raw-only measurement runner 已補上 partial acquisition、`Popen` 前的原始
launch custody、雙 child cleanup、Ctrl+C／artifact／stdout 失敗保留，以及完成後
不可重複 native finish。新增 20 案例；兩模組 **70 tests 通過（1.727 秒，
0 failures／errors／skips）**。首次 70 tests 有四個 fixture errors，全部是 Mock
未宣告 `assert_covered` 介面；改用明確 `spec_set` 後重跑，未放寬 production。
Raw provider 仍被阻擋；此修補不代表 A0 qualification 或 native P6 完成。

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_runner tests.test_adaptive_orchestrator -q
```

後續 retirement／policy／guardian／transport 整合跑了 **653 tests，92.604 秒，
1 failure／26 errors**，保留為初次失敗證據。問題包含 nonce fixture 缺少 singleton、
prelaunch fixture 的 current-wrapper 身分範圍、renewal fixture 未走到預期分支、
host telemetry fixture 缺少 emit，以及 Windows journal inventory 的真正相容性
錯誤：`DirEntry.stat()` 在 Windows 的 device／inode／link count 為零，不能拿來
通過檔案身分檢查。本機唯讀比對已確認 `os.stat(..., follow_symlinks=False)`
提供真實值；[Python 官方契約](https://docs.python.org/3.13/library/os.html#os.DirEntry.stat)
亦如此規定。修正保留原本的檔案／reparse 安全檢查，不能接受零身分來換取通過。
2026-09-24 修正後重跑 **654 tests 全過（94.827 秒）**，新增 Windows metadata
回歸案例；fixture 修正保留原 current-wrapper 身分與真正連續 renewal 時間窗。
測試含受保護 dirty baseline、相鄰未提交 telemetry／experiment exclusion，不能
視為乾淨 checkout 或 native gate 已驗證。

原始 nonblocking pipe／operator core 則已獨立驗證：**205 tests 通過，16.096 秒，
0 failures／errors／skips**，已提交為 `c0d4edd`。範圍包含 pipe Windows／async、
operator、control、launch 與 daily-readiness transports。Helper 的實際 poll／
telemetry 收尾接線已在 2026-09-24 的 276 tests 中通過，不宣稱 native idle cost
已通過。完整私人 log 為
`.local-adaptive/pipe-core-regression-1.log`；等價的直接命令如下：

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_pipe_windows tests.test_adaptive_pipe_async tests.test_adaptive_operator_transport tests.test_adaptive_control_transport tests.test_adaptive_launch_transport tests.test_adaptive_daily_readiness_transport -q
```

較早確認的 remote readiness 鎖內 RPC 問題已由 2026-09-24 的 413-test 接線
修正：鎖外取得原始 authenticated authority，鎖內於實際 consumer connection
重驗 generation／ledger／source／native witness。Native scope 的 remote owner
接線已由最新 364-test 回歸驗證，真正 provider 仍未完成；不把 source 修正視為 S1 native 通過。

另修正 source keeper 在 stdout 失效時略過等待、持續忙轉的問題：診斷與 pacing
分開，保持同一原始 operation，固定每個錯誤邊界只保留第一個錯誤。
`C:\Python313\python.exe -m unittest tests.test_adaptive_daily_source_install -q`
通過 30 tests（3.928 秒，0 failures／errors／skips）；没有實際安裝或 runtime 操作。

最新 C2 回歸命令如下。首次 232 tests 用時 154.333 秒，有 1 failure：fixture
直接期待底層 `LifecycleError` 文字，但該例外沒有 `.reason`，既有 guardian
故意回固定的 `guardian_retirement_cleanup_unverified`。只修正該預期，原 owner
保留與零 native close 斷言完整保留；該案例重跑通過（0.724 秒）。

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_prelaunch_receipt tests.test_adaptive_guardian_retirement tests.test_adaptive_host_operations tests.test_adaptive_prelaunch_retirement_store tests.test_adaptive_terminal_receipt tests.test_adaptive_guardian_host tests.test_adaptive_supervisor_epoch tests.test_adaptive_supervisor_reconcile -q
C:\Python313\python.exe -m unittest tests.test_adaptive_guardian_retirement.GuardianRetirementTests.test_receipt_capture_failure_never_starts_native_cleanup -q
```

日常接線首次 252 tests 有 9 errors，全部是 activation-host 的 cohort Mock
缺少明確 `assert_retired` 介面；修正兩個 fixture，未放寬 production 檢查。
以下 279 tests 全過（10.587 秒，0 failures／errors／skips）：

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_daily_generation tests.test_adaptive_daily_prerequisites tests.test_adaptive_daily_cohort tests.test_adaptive_daily_bootstrap tests.test_adaptive_daily_readiness_transport tests.test_adaptive_daily_connection_hooks tests.test_adaptive_daily_source_handles tests.test_adaptive_daily_source_install tests.test_adaptive_daily_activation_host tests.test_adaptive_launch_producer -q
```

接線後另跑既有 admission／local worker／legacy writer 相容性測試，168 tests
全過（16.577 秒，0 failures／errors／skips），命令為：

```text
C:\Python313\python.exe -m unittest tests.test_coordinator tests.test_maintainer tests.test_adaptive_coordinator tests.test_adaptive_maintainer tests.test_adaptive_legacy_writer tests.test_adaptive_legacy_writer_fence tests.test_adaptive_legacy_mode -q
```

項目 5 foundation 的檢驗命令（同樣透過日常 wrapper、隔離 fixture）為：

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_daily_generation tests.test_adaptive_daily_prerequisites tests.test_adaptive_daily_cohort tests.test_adaptive_daily_bootstrap tests.test_adaptive_daily_readiness_transport -q
```

第一次混合 199 tests 有 3 failures／27 errors，來源是新 fixture 的 Mock 未宣告
`assert_held`／`assert_retired` 方法，以及 UNKNOWN identity 缺少必要 reason。
修正明確測試介面後，上述 130 tests 全過，未放寬 source 檢查。新增 inspector
只能核對 baseline，不能安裝或解鎖容量。Readiness 必須經過原持有者、真實 peer
驗證與 cleanup；它本身也不是 capacity/adoption 授權。尚未執行日常 migration。

本次命令均由日常 `C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1`
正常准入（P2、HEAVY、1 CPU、1 GiB RAM、0 I/O slots），在 implementation worktree 執行：

```text
C:\Python313\python.exe -m unittest discover -s tests -p test_adaptive*.py -q
C:\Python313\python.exe -m unittest tests.test_adaptive_launcher tests.test_adaptive_guardian_retirement tests.test_adaptive_prelaunch_retirement_store tests.test_adaptive_p3_flow tests.test_adaptive_wrapper_host -q
C:\Python313\python.exe -m unittest tests.test_adaptive_supervisor_startup tests.test_adaptive_supervisor_reconcile tests.test_adaptive_supervisor_epoch tests.test_adaptive_early_guardian_death tests.test_adaptive_guardian_host -q
```

第一次完整測試的七個錯誤來自 P3 flow 合成 fixture 缺少新要求的 lifetime process
counter；修正 fixture 後全過，未放寬 production 證據。更早的 targeted 故障與修正
見 C2 文件。測試仍依賴接手前 dirty tree 的 exemption／observability 整合內容；
那些檔案未納入本次窄提交，這不是乾淨 clone 已重跑的聲明。沒有新建或限速真實
test Job，沒有修改日常 runtime 或啟用 adaptive。

C4 先前 targeted runs 的故障記錄：48 tests 有 2 failures（epoch observation 錯誤
未轉穩定拒絕碼、fixture manifest 未有效封裝）；111 tests 有 10 errors（fixture
SQLite connection 未關閉導致 Windows temp cleanup 拒絕）；181 tests 有 1 failure
（epoch-reuse 測試從錯誤 seam 注入）。分別修正 source 錯誤回報及 fixture，再新增
review 找到的恢復案例，最後完整 2,127 全過。沒有刪除 assertion、降低 gate 或以
skip 取代實測。C4 的保守偏差：cold startup 連有效 terminal history 也 HOLD；
保留 witness 的 rollover 才分頁驗證歷史。詳見 C4 契約的 implementation checkpoint。

目標 3 的中間失敗與處理：首次 75 tests 有 3 failures／1 error，分別修正
DB ACK-loss fixture 的注入位置、native restore 後的 floor journal 結算，以及
orphan 的原 POLICY guard 重試。169 tests 的一個失敗來自不連續時間窗 fixture；
110 tests 的一個失敗則把安全 disable 誤算為新增 restrictive Set，改為核對完整
呼叫序列及保留 HOLD。Helper 42 tests 的一個 fixture 在 restore tick 未採樣後
錯把兩秒視為有效窗口，修正為先驗證拒絕、下一正常窗口才恢復觀察。Capability
首次 25 tests 有 19 failures，找到 Windows `lstat`／`fstat` 的 ctime 差異；
現在以 opened file 的 volume/file ID/size/mtime 比對，並保留前後完整 path
fingerprint 核對。另一次命令誤列不存在的 sampler test module，產生一個 loader
error，後續以真正的完整 discovery 驗證。以上都已包含在最後 2,298 全過的版本。
獨立 review 的 action-ID、cooldown、scope cleanup、current victim share 與
第二次 native readback 問題亦已補回歸測試；沒有以 skip 或放寬 gate 換取通過。

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
Job、程序與 mutex 都是測試內標明的 synthetic backend。native 測試一項都沒跑，P3 到
P6 沒有任何 gate 通過，adaptive 維持 off。

2026-09-22 更正：這一輪每一次 `host_foreign_parent_job` 都經過 `py` 啟動器。CPython 的
`PC/launcher2.c` 在 `launchEnvironment` 裡建立一個 Job，再把 python.exe 指派進去，
所以經 `py` 啟動的行程一定在 Job 內，`read_host_capability()` 一定拒絕。擁有者在 app
之外的 PowerShell 直接執行 `sys._base_executable` 指到的直譯器，同一個 preflight
通過，回報 build 26340、12 個邏輯處理器、1 個 processor group。擁有者接著在同一個
主控台用同一個直譯器跑正式 probe `tests/windows/probe_adaptive_host.py`，結果是
`in_any_job=false`、`validity=valid`、沒有錯誤、`active_host_candidate=true`、
`capability_status=host_only_not_control_verified`。probe 輸出留在本機，不入庫。這個
狀態只說明該主控台可以當 host，CPU 限速是否有效要由 S1 到 S3 量測，還沒做。這是到
目前為止唯一量到會通過的啟動路徑。[capability results](CAPABILITY-RESULTS.md) 在 2026-09-19 用真正
的直譯器路徑量過另外兩條：暫時的 Scheduled Task 與 Explorer shell 派發，子行程都回報
`in_any_job=true`，那兩個結果與啟動器無關，仍然成立。下面各項寫到的拒絕，指的都是
經 `py` 啟動的情況。

同一天在 Claude 的 agent session 裡，經 `scripts/invoke-sentinel.ps1` 直接執行
`C:\Python313\python.exe`，沒有經過 `py`，preflight 仍然回 `host_foreign_parent_job`。
`scripts/` 底下沒有任何建立 Job 的程式，所以那一層 Job 來自 agent 的執行環境，是哪個
行程建立的沒有查。結論是 agent 自己跑不了 native 測試，要由擁有者在 app 之外的
主控台用真正的直譯器執行。native 測試到現在還沒有人跑過。另一個後果：
`scripts/adaptive-supervisor.ps1` 從 Scheduled Task 啟動時，依 09-19 的量測會被拒絕，
目前只有互動式主控台這條路徑可用，常駐啟動方式因此還沒有答案。

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
   目錄都必填、沒有預設值，裡面沒有任何停止子行程的路徑。它只向 `py` 問直譯器的
   路徑，再直接啟動那個檔案，因為經 `py` 啟動的行程一定在 Job 內。

已知整合缺口（以開頭 checkpoint 的最新狀態為準）：

1. 沒有會送出 proposal 的 helper。shadow helper host 只觀察，enforce 模式依計畫要等
   P5 的 capability 核可，B 組因此仍然不能量測。不是由 supervisor 建立的 helper，
   結束後登記列仍會留著，下一次啟動會以 `helper_host_registry_occupied` 拒絕。
   supervisor 自己結束時，guardian 和 helper 的列也都會留下，主機上不再有任何 witness。
2. 沒有 endpoint 發現機制。wrapper 與 helper 要連哪個 guardian，目前只能由操作者
   手動傳入 pid、creation FILETIME、instance id 與 epoch。
3. 除了行程收到 interrupt 之外沒有正式的停止訊號。
4. wrapper 被拒絕之後，已綁定的 reservation 沒有釋放路徑，細節在 process hosts 文件。
5. C4 已補上同一 supervisor 持有原 creation witness 時的 early-death capture；
   一般 `RecoveryOwner.capture` 仍要求 ALIVE。沒有舊 handle 的冷啟動仍 HOLD。
6. C4 的 early-death 路徑經正向證據、cleanup 與 registry retirement 後才允許
   replacement；helper 列刪除失敗亦每輪重試。registry 上限仍是 32 列。
7. 計畫 P3 與 P4 表列在 `scripts/sentinelctl.py` 的 `run-managed`、`adaptive-status`、
   `adaptive-recover` 與 mode、drain、audit 命令都還沒寫，目前只有唯讀的
   `adaptive-query`。這個檔案在工作目錄裡帶著
   另一項任務尚未提交的修改，這一輪無法乾淨分離，所以沒有動它。缺口 4 的釋放路徑
   會動到 `sentinel/coordinator.py`，原因相同。

需要 repo 擁有者裁決的事項，以及擁有者在 2026-09-22 的答覆。還沒實作的部分，程式
仍然一律 fail closed：

1. 計畫 7.4 沒說受控 Job 已經結束時，要用誰的五筆未限速樣本清除 barrier。
   原本 Job 先結束或由 orphan drain 結案時，barrier 會一直停在 `RECOVERY_HOLD`。
   擁有者的答覆：Job 經現場查詢確認為空時視為可以清除，並留下稽核紀錄。已實作，
   契約與證據寫在 [barrier clear for a finished Job](BARRIER-CLEAR-FINISHED-JOB.md)。
   orphan drain 在結案的同一輪清除，之後每一輪遇到已 `FINISHED` 的列會再試一次；
   原本的五筆樣本路徑沒有改。只有可攜測試證據。guardian 端的對應方法沒有 production
   caller，列為項目 3 接線。C4 的新 supervisor startup/tick 已接上 durable
   finished-barrier janitor；其可驗證證據與限制見 [C4](P3-SUPERVISOR-FAILSAFE.md)。
2. `cancel` 與 `start_failed` 的 guardian 證據採
   [C2 正向退場契約](P3-PRELAUNCH-RETIREMENT.md)：共享啟動鎖、原始 retained Job
   的 lifetime 零程序證據、原子 receipt／archive。Source 已實作，targeted tests
   通過；wrapper host／CLI 接線仍屬目標項目 4，native race／cleanup gate 未驗證。
3. 計畫 5.5 要求 caller 以 OS 可驗證身分和一次性 token 綁定。helper 沒有
   `ipc_auth_key`，registry 的欄位也是固定的，所以傳輸層只用 OS 驗證的 peer
   加上每次請求的 server nonce，沒有共享密鑰。擁有者的答覆：接受現況。
4. supervisor failsafe 已採 [C4](P3-SUPERVISOR-FAILSAFE.md)：外部重啟服務仍屬部署，
   本次未安裝。新 supervisor 沒有舊 witness 時回報 `COLD_RECOVERY_HOLD`，不推測
   DEAD、不 restore、不建立競爭 guardian。保留原 witness 的 supervisor 能處理
   早期死亡，並每輪重試 helper/guardian 列移除及 C3 barrier 清理；預算耗盡也不丟
   清理義務。冷啟動目前更保守：連有效 terminal history 也拒絕；retained rollover
   則完整分頁驗證歷史後原子切換 epoch。未知 native cleanup 隔離、暫時 SQL 故障
   保留相同 guard 重試。Source 已完成；實測狀態以本頁最上方 checkpoint 為準。
5. `register_infrastructure_locked` 的兩個提前拒絕原本會留下 POLICY entry nonce，之後
   每一次 `prepare` 都會得到 `policy_scope_busy`。擁有者授權修正，已完成：
   `verify_infrastructure_candidate_locked` 在 scope 還沒碰帳本時先做同樣兩個檢查，
   guardian host 與 helper host 都在 hold 內第一個呼叫它。原函式不變，帳本被碰過之後
   才發生的拒絕仍然保留 nonce，有測試固定這個行為。細節在 process hosts 文件。

本段保留先前的歷史基準（最新結果見開頭 checkpoint）：2026-09-22，80 個模組、1961 個測試、0 失敗、
0 錯誤、0 略過，經 `scripts/invoke-sentinel.ps1` 正常准入。0 略過只對 agent session
成立，在通過 preflight 的主控台上，斷言拒絕代碼的測試會改走 `skipTest`。同一天較早的
一次執行有 1 個錯誤：`test_adaptive_guardian_launch` 出現 `coverage_read_timeout`，
來源是 `_coverage_read_transaction` 的 0.25 秒真實時間上限，當時主機負載偏高；該模組
單獨重跑 22 個測試全過。這個上限沒有改，列為 follow-up。傳輸層的未登記呼叫者
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
