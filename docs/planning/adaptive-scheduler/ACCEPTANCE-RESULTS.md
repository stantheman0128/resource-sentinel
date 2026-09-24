# Acceptance results: adaptive scheduler A/B

Status: no A/B data has been measured. This document is an empty template.

Nothing below is a result. Every table is a placeholder, and the verdict is
NOT_MEASURED until measured records replace the placeholders. Do not cite this
file as evidence that the A/B comparison was run, was passed, or was completed.

## Why there is no data yet

Variant B is the A1 build with the approved single victim CPU policy enabled.
No CPU actuator exists yet, so variant B cannot run, and without variant B there
is no A1 to B or A0 to B comparison to report. The plan states plainly that none
of its thresholds have been measured in this round
(IMPLEMENTATION-PLAN.md, section 11.2).

Two rules apply to everything that is eventually written here:

- Without comparable measured A1 and B data, no one may claim the A/B is done.
- Setting a one second or six second timer is not a measurement of reaction time
  or restore time.

## How this document gets filled in

The harness is `tests/benchmarks/adaptive_ab.py`. It builds the schedule,
validates the run records, computes the paired statistics, applies the
thresholds from plan section 11.3, and renders the report that belongs in the
sections below. It launches no workload. A later stage has to implement the
`BenchmarkRunner` protocol to produce measured records; the only runner shipped
today is `DryRunRunner`, which prints the schedule and refuses to return a
record.

Order of work:

1. Fix the commit, the workspace, the dataset, the task count, the cache state
   and the power plan, and record the OS build and the logical processor count.
2. Build the schedule with a seed and record that seed here.
3. Run each slot, one variant at a time, in the scheduled order. Start each run
   only after the previous Job is empty, CPU and Commit are back to baseline,
   and the cap audit reports disabled.
4. Store one run record per run with evidence source `measured`.
5. Render the report and paste it below, exclusions and verdict included.

## Fixed conditions

| Field | Value |
| --- | --- |
| Commit | not recorded |
| OS build | not recorded |
| Logical processors (N) | not recorded |
| Power plan | not recorded |
| Cache state | not recorded |
| Thermal or power anomaly | not recorded |
| Order seed | not recorded |
| Pairs per scenario | plan section 11.3 requires at least 10 |

## Scenario coverage

Plan section 11.3 lists the workload shapes. None has been run.

| Scenario class | Scenario | Measured pairs | Evidence source |
| --- | --- | --- | --- |
| CPU contention | not run | 0 | none |
| I/O bound | not run | 0 | none |
| Memory heavy with a safe ceiling | not run | 0 | none |
| No pressure | not run | 0 | none |
| Unmanaged CPU pressure | not run | 0 | none |
| Mixed exempt, background and protected | not run | 0 | none |
| Mixed root and child durations | not run | 0 | none |

## Comparisons

| Comparison | What it may show | Verdict |
| --- | --- | --- |
| A0 to A1 | cost of the observer, the new launch path and the accounting change | NOT_MEASURED |
| A1 to B | the CPU control itself | NOT_MEASURED |
| A0 to B | whether the end user actually benefits; a veto | NOT_MEASURED |

Overall verdict: NOT_MEASURED.

A1 to B on its own is not enough. Plan section 11.3 requires all three, so that
infrastructure cost cannot be hidden behind a control win.

## Excluded runs

| Run id | Variant | Pair | Reasons |
| --- | --- | --- | --- |
| none | none | none | no runs exist |

Excluded runs are counted and listed here. A run whose precondition failed, or
was never checked, is never quietly folded into a result.

## Rendered report

Paste the output of the harness report renderer here, unedited. Until then:

```text
no report, no measured records exist
```

## Known gaps in the plan

These are places where plan section 11.3 states no number. The harness does not
invent one, so a human has to judge the outcome or the plan has to be amended.

- No numeric threshold for A0 to A1. The harness now applies clarification C1,
  which reuses the plan 11.3 neutral rule of 5 percent. See
  AB-THRESHOLD-CLARIFICATION.md.
- No tolerance for the A0 to B regression veto. The harness now applies
  clarification C2, which reads the veto with the plan's own scenario
  tolerances. See AB-THRESHOLD-CLARIFICATION.md. Both comparisons still report
  NOT_MEASURED, because no data has been collected.
- No threshold for the unmanaged CPU pressure, mixed role and mixed duration
  scenarios.
- "Minimum headroom" is listed without saying whether it is physical or commit.
  The schema carries one field and the report prints it as given.
- No sample size is named above which a statistical guarantee may be claimed, so
  every result is reported as a small sample.

One gap sits outside section 11.3 and blocks B before any measurement. Plan
section 7.4 clears the admission barrier only after five fresh uncapped samples,
and it does not say whose samples count once the capped Job is gone. The
implemented clear needs an active allocation and samples of that same Job, so a
Job that finishes first, or one finished by the orphan drain after its guardian
died, leaves the barrier at `RECOVERY_HOLD` with no path back to `NONE`. The code
fails closed and nothing was relaxed. The repository owner has to decide what
evidence clears the barrier for a finished Job before any canary runs. See
P3-GUARDIAN-CONTROL.md.

Update, 2026-09-22. The owner decided, and the clear for a finished Job is
implemented with portable test evidence only. The contract is in
[BARRIER-CLEAR-FINISHED-JOB.md](BARRIER-CLEAR-FINISHED-JOB.md). The orphan drain
calls it. No transport reaches the guardian side method yet, so a living
guardian that finishes its own capped Job still leaves the barrier held. That
part of the gap still blocks B.

## Sign off

Sign off is blocked. It stays blocked until measured A1 and B records exist, the
three comparisons are rendered here, and the verdict comes from measured data.

## G1：單組 shadow host、零受管 Job（2026-09-25）

狀態：**未量測**。在這個 Codex agent session 內，guardian 與 helper 都於原生能力預檢拒絕啟動，沒有存活 60 秒。這不是 P4 gate 或 A/B 的通過證據。執行 commit：25aa05bcdf3d074f8c3e7ae035af4ad8d431f09f。

本次使用獨立的 .local-adaptive/g1-20260925-0230/ 資料庫和由 config/adaptive.example.json 複製、僅將 mode 改為 shadow 的 profile。LifecycleStore 初始化資料庫後，managed_executions 筆數為 0；沒有掛受管 Job，也未改 production config 或 Scheduled Task。執行腳本與 profile 均留在該目錄。

透過 Resource Sentinel admission 執行的指令（HEAVY、P2、CPU 1、RAM 1 GiB、I/O 0；reservation 獲准）：

    powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\scripts\invoke-sentinel.ps1 -Command "powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230\run.ps1" -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0

腳本用 Start-Process 嘗試啟動的兩個現有 CLI，完整展開指令如下：

    C:\Python313\python.exe -m sentinel.adaptive.guardian_host --data-dir C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230 --journal-dir C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230\journal --guardian-epoch 9f86981ca20a45d5855be8dd442def11 --profile C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230\shadow-profile.json
    C:\Python313\python.exe -m sentinel.adaptive.helper_host --data-dir C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230 --profile C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g1-20260925-0230\shadow-profile.json --report-every 10

外部取樣是 run.ps1 中每秒一次的 Get-Process -Id <PID>，讀取累積 CPU 秒數與 PrivateMemorySize64。腳本於第 0 秒取到兩個 PID，第 1 秒兩者皆已退出，因此沒有 60 秒差值或 60 秒 private bytes 最大值。

| 程序 | 60 秒內 CPU 秒數 | 60 秒內 private bytes 最大值 | helper log 中 Set 呼叫次數 |
| --- | ---: | ---: | ---: |
| guardian | 未量測 | 未量測 | 不適用 |
| helper | 未量測 | 未量測 | 未量測；log 沒有 Set 事件，但 host 未啟動，不能將此視為 60 秒內的零 Set 證據 |

完整啟動錯誤字串（原樣取自各自 stderr log）：

    {"detail": null, "event": "guardian_host_refused", "reason": "host_foreign_parent_job"}
    {"detail": null, "event": "helper_host_refused", "reason": "host_foreign_parent_job"}

原始證據路徑：

- .local-adaptive/g1-20260925-0230/guardian.stderr.log
- .local-adaptive/g1-20260925-0230/helper.stderr.log
- .local-adaptive/g1-20260925-0230/samples.csv
- .local-adaptive/g1-20260925-0230/commands.txt
- .local-adaptive/g1-20260925-0230/wrapper.log
- .local-adaptive/g1-20260925-0230/run.ps1

兩個 PID 已退出。依 RECONSTRAINT-20260925.md 的 native stop rule，本輪停在 agent session 的 parent Job 預檢拒絕；未嘗試實作 bridge 或通過 p4_authenticated_daily_cohort_unavailable gate。

### G1 補測：使用者主控台執行（2026-09-25 02:37，Claude 記錄）

狀態：**已量測**。同一 commit 25aa05b。由使用者在 app 外的一般 PowerShell 主控台執行
`.local-adaptive/g1-20260925-0240/run2.ps1`，直接使用 `C:\Python313\python.exe`，不經 wrapper、不經 `py`。
兩個 host 的 capability 記錄都是 `in_parent_job: false`，預檢通過。

run2.ps1 與 Codex 的 run.ps1 只差一處：先起 guardian，每 0.5 秒查獨立 DB，等到 guardian 列已登記且
`policy_entry_nonce` 為 NULL 才起 helper（本次等了 0.5 秒）。原因是 02:32 第一次主控台執行時兩者相隔 20 ms 同時啟動，
helper 在 guardian 握著 POLICY scope 時進入 `prepare`，被拒 `helper_host_registry_unavailable / policy_scope_busy`。
該次證據在 `.local-adaptive/g1-20260925-0230/`（guardian 活到第 1 秒、DB 內 guardian 已登記、nonce 已釋放），
不是殘留 nonce。這是啟動順序問題，記為 Follow-up，本輪未改 source。

| 程序 | 60 秒內 CPU 秒數 | 60 秒內 private bytes 最大值 | Set 呼叫次數 |
| --- | ---: | ---: | ---: |
| guardian (pid 45960) | 0.516 | 28,499,968 (27.2 MiB) | 不適用 |
| helper (pid 25824) | 0.219 | 25,321,472 (24.1 MiB) | 0 |

Set 為 0 的依據：helper 自己的 `helper_host_metrics` 記錄 `ticks: 60, decisions: 59, would_apply: 0, mode: shadow, enrolled: 0`，
獨立 DB `adaptive_actions` 與 `adaptive_control_slot` 均為 0 列。helper 每 tick 平均 0.52 ms、最大 0.93 ms，
60 秒合計 31.0 ms tick 時間。guardian 每輪四個 RPC 都是 `pipe_timeout, served: false`，屬空轉正常。

外部取樣 `Get-Process` 每秒一次，122 列樣本，第 60 秒兩者皆存活。stdout log 為空是因為 60 秒後以 `Stop-Process -Force` 結束、緩衝未 flush；
事件與指標在 `adaptive-telemetry/*.jsonl`。

原始證據路徑：

- .local-adaptive/g1-20260925-0240/run2.ps1、probe.py、run-status.txt、samples.csv、commands.txt
- .local-adaptive/g1-20260925-0240/adaptive-telemetry/event-*.jsonl、aggregate-*.jsonl
- .local-adaptive/g1-20260925-0240/sentinel.db

## G2：受管 Job 成本腳本（2026-09-25）

狀態：**1 Job 已量測；10 與 50 Job 未量測**。在 .local-adaptive/g2-20260925/run3.ps1 增加 -Jobs 1、10、50 參數；沒有在 agent session 啟動 host 或 fixture，以下實機結果來自使用者一般 PowerShell 主控台。腳本沿用 G1 補測的獨立 DB、shadow profile、先等 guardian 登記及釋放 POLICY 再起 helper、Get-Process 每秒取樣 60 秒。1 與 10 使用既有 sentinel.adaptive.wrapper_host run-managed CLI，以 background/P2、每個 fixture 估計 CPU 1、RAM/Commit 各 0.25 GiB 申請正常 admission，並等 helper_host_metrics 的 enrolled 等於要求數量後才取樣。既有 tests/fixtures CPU fixture 需要預知 Job 名稱與 nonce，或其工作量完成時間不能保證維持 60 秒；腳本依 G2 指示在獨立目錄產生一行 PowerShell busy loop，最長 115 秒，結束取樣後用 stop 檔請它自行退出。wrapper 和受管 Job 收束確認前，腳本不強制結束 host。每次執行的原始 log、命令與 samples.csv 寫在 g2-20260925/jobs-N-時間戳/。

**-Jobs 50 無法滿足驗收條件，腳本會在啟動任何 host 前報錯。** 現有 contracts.MAX_ENROLLED_JOBS = 10；policy profile 驗證上限也是 10；LifecycleStore 第 11 個受管 Job 會拒絕 managed_job_limit_reached，helper enrollment 亦只取最多 10 個。這是現有契約與實作的上限，不是缺少另一條 CLI。要取得 helper_host_metrics.enrolled = 50，需另行決定並修改該上限及相關契約；本輪依指示未實作或放寬。

使用者主控台指令（必須從此工作樹執行；-Jobs 50 會直接報上述缺口）：

    powershell -NoProfile -ExecutionPolicy Bypass -File .local-adaptive\g2-20260925\run3.ps1 -Jobs 1
    powershell -NoProfile -ExecutionPolicy Bypass -File .local-adaptive\g2-20260925\run3.ps1 -Jobs 10
    powershell -NoProfile -ExecutionPolicy Bypass -File .local-adaptive\g2-20260925\run3.ps1 -Jobs 50

### G2 主控台首輪失敗與腳本修正（2026-09-25）

使用者在一般 PowerShell 主控台執行 -Jobs 1 與 -Jobs 10。兩次都只起到第一個 wrapper，沒有 fixture 命令被建立；wrapper 已通過 admission，接著以 wrapper_host_launch_unverified / pipe_io_failed 拒絕。guardian telemetry 同期記錄 guardian_launch_deadline_exceeded，稍後記錄 PrepareExecution 已服務，之後的 CancelBeforeStart 已服務；獨立 DB 的執行狀態均為 CANCELLED_BEFORE_START。兩次 run-status 的 cleanup_settled 均為 True，沒有 60 秒取樣或 enrolled=N。-Jobs 50 按現有 10 Job 上限於啟動前拒絕。

原始證據在 .local-adaptive/g2-20260925/jobs-1-20260925-025857/ 與 jobs-10-20260925-025901/，特別是 wrapper-1.stderr.log、adaptive-telemetry/*.jsonl、run-status.txt 與 sentinel.db。

腳本已作一項有依據的時限調整：guardian_host CLI 的 --rpc-timeout-ms 由預設 100 設為 250；wrapper_host CLI 明確設為現有上限 1000。這針對首輪觀察到的 guardian_launch_deadline_exceeded，不改 transport、契約或 admission。腳本亦在 wrapper 提前退出時帶出最後一筆 log，移除重複的 Write-Error。下述 -Jobs 1 補測成功；這只證明 1 Job 的啟動及取樣成功，沒有證明 10 Job 可用。

### G2 主控台補測：1 Job 成功，10 Job 在第 3 個啟動時停住（2026-09-25 03:08–03:10）

執行 commit：`25aa05bcdf3d074f8c3e7ae035af4ad8d431f09f`。使用者在一般 PowerShell 主控台執行上述 `run3.ps1 -Jobs 1` 與 `-Jobs 10`；每次的完整 host/wrapper 啟動指令在各自的 `commands.txt`。

`-Jobs 1` 在 helper log 記錄 `helper_host_metrics.enrolled=1` 後，完成第 0 至 60 秒各 1 次 `Get-Process` 取樣，共 61 個時點、每個 host 61 筆，`samples_complete=True`、`cleanup_settled=True`。CPU 為第 60 秒讀值減第 0 秒讀值；private bytes 是這 61 筆中的最大值。

| 程序 | 60 秒內 CPU 秒數 | private bytes 最大值 | helper log 的 Set 呼叫次數 |
| --- | ---: | ---: | ---: |
| guardian (pid 18928) | 2.46875 | 32,194,560 (30.7 MiB) | 不適用 |
| helper (pid 50764) | 0.59375 | 25,415,680 (24.2 MiB) | 0 |

helper 的 4 筆自身 telemetry 只有啟動與 3 筆 `helper_host_metrics`，沒有 Set 事件；60 tick 記錄為 `mode=shadow, enrolled=1, decisions=59, would_apply=0`。該次獨立 DB 的 `adaptive_actions`、`adaptive_control_slot` 均為 0 列。這是從 helper log 可數到的 Set 次數，不是對 native API 的外部攔截。原始證據：`.local-adaptive/g2-20260925/jobs-1-20260925-030804/` 下的 `run-status.txt`、`commands.txt`、`samples.csv`、`wrapper-1.stderr.log`、`adaptive-telemetry/*.jsonl`、`sentinel.db`。

`-Jobs 10` 的前 2 個 wrapper 已通過 admission、完成 PrepareExecution/ClaimLaunch/BindRoot，fixture 進入 RUNNING。第 3 個 wrapper（PID 28264）已通過 admission，PrepareExecution 也已服務；guardian 下一次 launch RPC 回 `launch_barrier_active`，再下一次記錄 `pipe_io_failed`。wrapper 最後報 `pipe_timeout`，沒有啟動第 3 個 fixture。使用者看到的完整失敗字串已保存在 `run-status.txt`：

```text
Managed wrapper exited before launch (PID 28264); last record: {"command_started": false, "detail": "pipe_timeout", "event": "wrapper_host_refused", "launch_state": "not_attempted", "reason": "wrapper_host_launch_unverified", "release": {"closed": true, "execution_id": "2d21819d-d8dd-481a-9d5a-940ae7352bbb", "guardian_handoff": false, "reason": "launcher_abandon_settled", "settled": true, "state": "CLOSED"}}; full log: C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\.local-adaptive\g2-20260925\jobs-10-20260925-030938\wrapper-3.stderr.log
```

第 10 Job 的獨立 DB 最後為 `adaptive_runtime.admission_barrier=RECOVERY_HOLD`、`mode=off`；`adaptive_control_slot` 與 `adaptive_actions` 都是空表。第 1、2 個 fixture 於腳本清理後為 FINISHED，第 3 個為 START_FAILED；`cleanup_settled=True`，沒有 `enrolled=10` 或 60 秒取樣。guardian 在第 2 個 BindRoot 同輪對第 1 個 Job 記錄一次 `PolicyBusy`；現有 lifecycle 對未完成 reconcile 可能進入 restore 路徑並設 RECOVERY_HOLD，但 telemetry 沒有逐筆 barrier 寫入歸因，這是依時序與程式路徑所作的推論。現有 CLI 沒有在這種無 control slot 的 hold 下繼續啟動其餘 Job 的安全操作；清除 barrier 需要另行處理實作與恢復證據，本輪不實作，也不手改 DB。原始證據：`.local-adaptive/g2-20260925/jobs-10-20260925-030938/` 下的 `run-status.txt`、`commands.txt`、`wrapper-1.stderr.log` 至 `wrapper-3.stderr.log`、`adaptive-telemetry/event-*.jsonl`、`sentinel.db`。

### G2 檢查：10 Job 停在 RECOVERY_HOLD 的原因（2026-09-25，Claude 記錄）

結論：1 Job 那列成立。10 Job 不是腳本節奏問題，是 source 的一條路徑：shadow mode 下任何一次暫時性的 reconcile 失敗都會把 admission_barrier 永久設成 RECOVERY_HOLD。50 Job 在現行 source 下不可能。

事件順序，取自 `jobs-10-20260925-030938/adaptive-telemetry/event-*.jsonl`，guardian pid 22816 依 sequence：

| seq | launch_rpc | reconcile 結果 |
| --- | --- | --- |
| 5 | BindRoot（Job 1） | Job 1 RUNNING |
| 8 | BindRoot（Job 2） | Job 2 RUNNING；Job 1 `reconcile_errors: PolicyBusy` |
| 9 | PrepareExecution（Job 3） | Job 1、Job 2 RUNNING |
| 10 | `launch_barrier_active` | 同上 |
| 12 | StartFailed（Job 3） | Job 1、Job 2 FINISHED，terminal_retirements complete=True |

程式路徑：

1. `guardian_lifecycle.reconcile()` 接到任何例外都呼叫 `retain_failure`，它第一行就是 `entry.restore_pending = True`（`guardian_restore.py` retain_failure）。seq 8 的 PolicyBusy 走了這條。
2. 下一輪 `_reconcile` 看到 `restore_pending` 就進 `_restorer.locked()`；該函式在做任何判斷前先呼叫 `record_recovery_hold`（`guardian_restore.py:298`），barrier 因此在 seq 9 變成 RECOVERY_HOLD。
3. seq 10 的 ClaimLaunch 在 `store.py` 檢查 `admission_barrier != "NONE"` 後丟 `launch_barrier_active`。
4. 所有清除 RECOVERY_HOLD 的路徑都要求該 execution 的 control slot 處於 RESTORED：`control_slot.clear_locked`、`clear_finished_locked`、`guardian_lifecycle.py:537` 的 `applicable_slot` 判斷、`guardian_control.py:1126`、`supervisor_reconcile.py:289`。shadow mode 的 Job 從未取得 slot（`adaptive_control_slot` 空表），所以連 Job 全部 FINISHED 之後 barrier 也不會清，DB 最終狀態即為證據。

seq 8 那次 PolicyBusy 是誰持有 POLICY nonce，telemetry 沒有記錄，無法歸因；同一輪內 launch RPC 與 reconcile 是循序執行，最可能是 helper 的 enrolment 掃描，但這是推測。

50 Job：`sentinel/adaptive/contracts.py:25` 寫死 `MAX_ENROLLED_JOBS = 10`，`helper_host.py:470` 與 `:655` 取 `min(profile.max_enrolled_jobs, MAX_ENROLLED_JOBS)`，改 profile 無效。記為未量測。

## G3：獨立帳本 25% canary 前置門（2026-09-25）

狀態：**未量測；evidence bundle 的原生前置門已拒絕**。執行 commit：`25aa05bcdf3d074f8c3e7ae035af4ad8d431f09f`。本輪沒有建立 G3 帳本、啟動 guardian/helper/fixture、施加 Set 或更動 production config。三段整機 CPU 與 Job CPU 均無數字：

| 階段 | 整機 CPU | 該 Job CPU | 原因 |
| --- | --- | --- | --- |
| 施加前 | 未量測 | 未量測 | native evidence bundle 不可產生 |
| hard cap 25% 穩定 30 秒 | 未量測 | 未量測 | 同上 |
| 解除後 30 秒 | 未量測 | 未量測 | 同上 |

repo 既有的 bundle 產生方式是 `tests.windows.adaptive_capability_runner.NativeEvidenceRun`：`publish_gate()` 將原生 gate artifact 寫成 `S1.json` 等檔案並更新 `bundle.json`；`isolated_canary` 的 guardian authority 必須驗證同一 bundle 內的 S1、S2、S3、P4。S1 的既有主控台入口是 `tests.windows.run_adaptive_s1`；其 `run_s1()` 依賴原生 daily provider。一般 `NativeEvidenceRun.run_gate()` 也先呼叫 `require_continuous_admission()`。P4 的 `produce_p4()` 另要求原 daily coverage owner 提供 `open_overhead_session`；缺少時 source 明定拒絕字串 `p4_authenticated_daily_cohort_unavailable`。不能以 G1/G2 的 shadow 取樣或手製 JSON 代替 bundle。

為確認目前前置門，僅在 agent session 執行以下**完整、無 host 啟動的檢查指令**（工作目錄 `C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation`）：

```powershell
& 'C:\Python313\python.exe' -c 'from tests.windows.adaptive_admission import require_continuous_admission; require_continuous_admission()'
```

exit code 1；**完整拒絕字串**：

```text
Traceback (most recent call last):
  File "<string>", line 1, in <module>
    from tests.windows.adaptive_admission import require_continuous_admission; require_continuous_admission()
                                                                               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\tests\windows\adaptive_admission.py", line 17, in require_continuous_admission
    raise ContinuousAdmissionUnavailable("continuous_admission_provider_unavailable")
tests.windows.adaptive_admission.ContinuousAdmissionUnavailable: continuous_admission_provider_unavailable
```

### G3 指令更正：Windows PowerShell 5

上述原指令依賴目前目錄為工作樹。使用者在 `C:\Users\stans\OneDrive - gapps.ntnu.edu.tw\桌面` 執行時得到 `ModuleNotFoundError: No module named 'tests'`，表示 Python 尚未找到 repo，**未到達前置門**。上一版試圖用 `sys.path.insert(0, r"...")` 做成單行指令；在使用者的 Windows PowerShell 主控台，傳入 Python `-c` 時內層引號遭移除，實際得到 `SyntaxError: invalid syntax`。該單行版不能交給使用者使用。

改成以下兩行，先切到本工作樹，再傳不含內層引號的 `-c` 程式；不改環境變數或 production 設定：

```powershell
Set-Location -LiteralPath 'C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation'
& 'C:\Python313\python.exe' -c 'from tests.windows.adaptive_admission import require_continuous_admission; require_continuous_admission()'
```

已以 `powershell.exe`（Windows PowerShell 5）從使用者當時的桌面目錄執行上述兩行驗證，exit code 1，完整輸出為：

```text
Traceback (most recent call last):
  File "<string>", line 1, in <module>
    from tests.windows.adaptive_admission import require_continuous_admission; require_continuous_admission()
                                                                               ~~~~~~~~~~~~~~~~~~~~~~~~~~~~^^
  File "C:\Users\stans\Projects\resource-sentinel\.worktrees\adaptive-scheduler-implementation\tests\windows\adaptive_admission.py", line 17, in require_continuous_admission
    raise ContinuousAdmissionUnavailable("continuous_admission_provider_unavailable")
tests.windows.adaptive_admission.ContinuousAdmissionUnavailable: continuous_admission_provider_unavailable
```

使用者隨後也在上述工作樹的一般 PowerShell 主控台執行第二行，回報相同的 `tests.windows.adaptive_admission.ContinuousAdmissionUnavailable: continuous_admission_provider_unavailable`，檔案位置為該工作樹的 `tests/windows/adaptive_admission.py:17`。這筆主控台輸出確認匯入已成功且前置門實際拒絕；沒有啟動 host，也沒有產生 G3 三段 CPU 數字。

因此沒有執行完整 S1/S2/S3/P4 native gate，亦未嘗試 `tests/fixtures/adaptive_recovery_host.py` 的 helper 分支。該分支在建構 `OperationalHelperControlHost` 前也會呼叫同一個 `require_continuous_admission()`，再要求 `assert_spike_covered`；這次拒絕不是單靠使用者主控台或加長 RPC timeout 就能解除。按本輪停損條件不實作 bridge、不繞過 preflight。因為目前沒有可安全執行的 canary 主控台步驟，本輪不交付會假裝進行量測的 `.local-adaptive/g3-20260925/run.ps1`。

若前置門日後由既有正式流程滿足，**只對新建 `.local-adaptive/g3-<日期>/attempt-<唯一值>/sentinel.db`** 的 `adaptive_runtime` 執行與 `tests/test_adaptive_control_authority.py` 相同的 SQL，才能設 canary；本輪未執行：

```sql
UPDATE adaptive_runtime SET mode='canary' WHERE singleton=1
```

該後續主控台腳本須每次建立新帳本，guardian 帶 `--control-purpose isolated_canary` 和已驗證 bundle，先等 `adaptive_infrastructure` 有 guardian 列且 `policy_entry_nonce IS NULL` 再起 helper；遇 `RECOVERY_HOLD` 停止且不清除、不重用帳本。

## Follow-ups

- guardian 與 helper 同時啟動會讓 helper 在 POLICY scope 上被拒 `policy_scope_busy`；helper 沒有重試，啟動端只能靠等待或順序保證。
- guardian 與 helper 收到強制結束時不會 flush stdout；正常停止訊號尚無（README 缺口 3）。
- 獨立 DB 的 `adaptive_runtime.mode` 仍是 `off`，helper 以 profile 的 `shadow` 執行；兩者關係未查。
- shadow mode 下任何暫時性 reconcile 例外（本次為 PolicyBusy）都會經 `retain_failure` 到 `_restorer.locked()` 寫入 RECOVERY_HOLD，而清除路徑全部要求 control slot RESTORED；從未取得 slot 的 Job 無法清除，之後所有新 Job 都被 `launch_barrier_active` 擋下。
- `contracts.py` 的 `MAX_ENROLLED_JOBS = 10` 是硬上限，G2 的 50 Job 在不改 source 的情況下無法量測。
- guardian telemetry 沒有記錄 barrier 的寫入者與 POLICY nonce 的持有者，暫時性 PolicyBusy 無法歸因。

## 結論（2026-09-25，使用者裁決：凍結）

四個階段在使用者主控台實跑後的結果：G1 空跑成本有數字且 Set 為 0；G2 只有 1 Job 一列成立，10 Job 被 shadow mode 的 RECOVERY_HOLD 路徑永久擋下，50 Job 受 `MAX_ENROLLED_JOBS = 10` 硬上限；G3 與 G4 未量測，因為所有能真正施加 hard cap 的路徑都先經過 `tests/windows/adaptive_admission.py` 裡無條件 raise 的 `require_continuous_admission()`，evidence bundle 產生不了。

這條分支目前在本機做不出一次 25% 限速，且原因在 source 設計，不在環境。使用者於 2026-09-25 決定：分支凍結在 `25aa05b`，不合併、不再補 provider 或 bridge；production adaptive 維持 off，config、Scheduled Task、啟動入口都不動。本文件與 STAGES-20260925.md、RECONSTRAINT-20260925.md 是這輪的正式紀錄。上方 Follow-ups 清單保留，若日後重啟，從那裡與 G2、G3 兩節的路徑分析開始，而不是從 README 的 checkpoint 敘事開始。
