# GPT Pro 規劃交接：Agent 動態資源調度

日期：2026-09-19。狀態：**正式計畫已入庫，分階段實作進行中；production adaptive 維持 off。**

## 2026-09-24 Codex 實作 checkpoint（目前狀態）

最新完成 generation 正面退場整合：**654 tests 全過，94.827 秒，
0 failures／errors／skips**。包含固定凍結下的收尾、完整歷史與 journal inventory、
原始 SQL／POLICY／readiness／native owner 的正面 cleanup，以及 Windows
檔案身分修正。不是 native acceptance 或日常 activation；remote readiness 鎖外
驗證、fresh restart、真正 native provider 與下述 P4/P6 source 缺口仍待完成。
完整私人日誌為 `.local-adaptive/retirement-integration-20260924-1.log`。
該包已提交為 `41cee4d`。Resident host bounded telemetry 與 helper 非阻塞
poll／cleanup 接線另通過 **276 tests，8.418 秒，0 failures／errors／skips**。
固定共用 20 MiB／7 天日誌上限已實作；P4 原始 sink 量測接線與 native 成本仍缺。
Telemetry 包為 `2b34df2`；原始 launch deadline 修正為 `10e42f5`，日常
legacy writer 的 experiment exclusion 為 `9f4d080`。原始 S1 scope／journal、
distinct wrapper 與 source bootstrap 最新 **303 tests 通過，19.533 秒，
0 failures／errors／skips**；CPU fixture 已提交為 `82e3450`。九個實際隔離
Python subprocess tests 驗證 stale `.pyc`／initializer 拒絕，沒有執行 native
Job 或 CPU 壓力實驗。Daily cleanup receipt、serial provider、remote readiness
整合及 generation successor 仍是 source 工作，不是只等主控台執行。

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
| 5. 全程容量覆蓋 | [Source generation／retained cohort／readiness transport 與接線](P2-DAILY-ACTIVATION.md)已完成 installer、常駐 owner 與日常 consumers 接線，279 tests 通過（10.587 秒）。同帳本 demand／retirement fence 已提交，與 P6 合跑 308 tests 通過（21.977 秒）。Generation 正面退場整合最新 654 tests 通過（94.827 秒）；remote readiness 鎖外驗證、真正 native experiment provider 與 fresh restart 仍待完成。未執行日常安裝，grace 前提未解鎖。 |
| 6. console 驗收命令 | [P6 矩陣編排與 raw reducer](P6-RUNNER-CONTRACT.md)、[S1/S2 bridge 契約](S1-DAILY-BRIDGE-CONTRACT.md)、[S3 精確故障點與 14×10 記錄器](S3-REAL-HOST-RECOVERY.md)、[P4 實際 host 成本量測](P4-OVERHEAD-RUNNER.md)已提交。P4 原 stderr producer 155 tests 通過（12.967 秒）；新 bounded telemetry／helper 非阻塞接線 276 tests 通過（8.418 秒）。Actual provider、部分 S3 故障 driver／完整 orchestration、A0 等價性及 P4 新 sink／schema 整合仍缺；不是只剩 console 執行。 |

最新追加：項目 5 的同帳本 demand 與 retirement fence 已提交為 `1072786`／
`a48925a`；native scope source 現已通過 303-test 整合，正向 daily release
與 actual provider 仍未提供。項目 6 的 P6 矩陣編排及 raw
reducer 已提交為 `ff6f31b`，S3 原始 action cutpoints／三個實際故障 driver／
14×10 記錄器為 `7307055`；真正 native provider、部分故障 driver、A0 等價性及
140 次完整實驗 orchestration 尚缺。[原始成員的 bounded memory 查詢](P4-MEMBER-MEMORY.md)
已提交為 `2922e09`，以 private working set／private Commit、原始 process handles
與完整 membership 證據計算；不使用共享 RSS，不完整採樣保持 unknown。

以上是目前缺口；下列較早日期的段落保留其歷史測試範圍。Native S1–S3、完整
P3–P6 都尚未通過。日常 config／Scheduled Task／啟動入口未修改。

下一步是項目 5 同一日常帳本的 native evidence fixture 全程容量覆蓋，以及
remote readiness 鎖外驗證與 fresh-generation restart。新增測試將繼續使用隔離帳本；任何實際
日常 source activation 都需要獨立授權，不因 commit/push 自動執行。項目 6
尚未完成的內容不能以 mock、空 provider、另外一個 DB 或假量測取代。

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
276 host tests，原 P4 stderr producer 還需接上實際 sink 與新的證據 schema。
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

另一個已確認的 source 整合問題仍待修正：remote daily readiness 在
`prepare_connection()` 中發送 RPC，但某些呼叫位於 POLICY 之內，與禁止鎖內 IPC
的契約衝突。需要在鎖外取得原始 authenticated readiness authority，再於鎖內
做 exact generation／ledger／native witness 核對；不能以 boolean、另外的 DB
或任意快取取代。這是 source 缺口，不是必須等 Windows 實驗才知道的限制。

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
