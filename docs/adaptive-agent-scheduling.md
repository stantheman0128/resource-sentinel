# Agent 動態資源調度設計

日期：2026-09-19。狀態：研究與實作方案；尚未實作、尚未啟用新的控制器。
依據本機現行程式與 Apple、Microsoft、Linux、DRF、TCP congestion control 的原始資料。

## 目標與現況

目標是保留工作進度與桌面回應速度，依瓶頸逐步調整個別任務可取得的資源。
最佳化指標是互動延遲、完成時間、排隊時間及失敗率；工作管理員 RAM 數字下降不等於改善。

現行 `scripts/collect.ps1` 已分開 CPU 與 I/O 壓力，但會對辨識到的所有非豁免
agent 程序套用相同降優先權策略。CPU 使用 BelowNormal，I/O 使用原生優先權呼叫。
RAM 達 `ram_orange_pct`（本機 85%）會對 working set >= 300 MiB 的候選程序
呼叫 EmptyWorkingSet，同 PID 冷卻 600 秒。這不能保證只移除閒置頁、釋放 Commit、
立即釋放等量實體記憶體，或改善速度。事件 target_mb 也不是實測回收量。

`sentinel/pressure.py` 有按資源分離與恢復遲滯；`sentinel/coordinator.py` 是
優先級、FIFO 與容量可行性選擇，尚無等待老化或按 agent 公平份額。
共享桌面 app 的 process tree 不等於單一 task；現有 app owner 身分不足以隔離同 app 多任務。

## 可以借用的方法

| 方法 | 在 Sentinel 的用途 | 限制 |
| --- | --- | --- |
| macOS memory pressure 與壓力通知 | 結合容量、換頁活動、延遲；讓支援的工具減少併發、釋放可重建 cache | 不能要求任意第三方 app 釋放指定數量 RAM |
| Windows Job Objects CPU weight / rate control | 對 wrapper 啟動的獨立工作樹調整 CPU 份額或速率 | 權重不是固定百分比；須驗證巢狀 job、平台支援與子程序歸屬 |
| Linux PSI 的停滯觀念 | 評估是否因資源不足而停止有效進展 | Windows 無同等通用 PSI 介面，代理量測必須標示，不能冒稱 PSI |
| 加權 DRF | 多 agent 爭用時，同級優先考慮主要資源份額較低者 | 需可靠 task 身分與資源估計；實作若偏離模型，不宣稱理論公平性保證 |
| AIMD + 平滑 + 遲滯 | 壓力持續時按比例減少發送量，恢復後小步增加 | CPU 額度與離散併發量是不同控制量，不能假設都線性影響效能 |
| 等待老化與容量保留 | 避免大工作一直被小工作超車 | 提升排序不能創造容量；需有期限的容量累積，不能違反安全餘裕 |

DRF 的主要份額可用 `max(CPU需求/CPU預算, RAM需求/RAM預算)` 說明。
首版只在相同優先級內比較，並將同一 agent 的多個任務合併計帳，避免拆任務取得額外份額。
磁碟延遲是壓力訊號，不是可直接分配的容量；I/O 名額也不等於磁碟吞吐量。
正在執行的 RAM 不可任意搶回，公平分配先用於下一個命令的准入。

## 量測與控制流程

1. 沿用既有有時限的採集與程序快照，不再新增無期限的全機程序列舉。
2. 以 task UUID、PID/start time、獨立 job 身分追蹤命令；app 名稱僅作顯示。
3. CPU 用程序時間差；RAM 分開記錄 working set 與 private committed bytes，
   不把所有 working sets 加總當成整機實體用量；磁碟仍需整機延遲與佇列輔助判斷。
4. 新增系統 paging input/output 速率、可用 RAM、Commit 餘裕、任務進展與耗時。
   普通 Page Faults/sec 包含 soft faults，不能直接當 hard faults 或換頁量。
   hard faults 也可能來自檔案映射，單一計數高不足以判定記憶體不足。
5. 以平滑趨勢判斷一般壓力，容量安全底線獨立保留，不因平滑延後拒絕新預約。
6. 瓶頸發生時，選擇有明確歸屬且正在消耗該資源的背景任务，逐次調整一項控制量。
   若壓力來自非 agent 程序，不把它歸罪給某 agent；只限制新增需求並顯示原因。
7. 觀察效果後再調整；未改善或進展停滯時撤回無效的柔性限制，保留准入安全底線。

缺少新計數時，不增加可用額度、不宣稱取得新控制能力；保留既有准入與已驗證控制路徑。
未支援合作介面的工具，只能控制下一個命令、OS 排程或命令啟動參數，不能聲稱
已動態降低它內部的 worker pool。雲端模型推理亦不受本機 CPU rate control 控制。

## 控制順序與起始參數

以下是待驗證的起始方案，不是啟用設定，也不是官方建議數值。

- CPU：先調整獨立工作樹的權重；需要可預測降速時再採用 Job CPU rate。
  不把整個 Codex/Claude UI 與所有任務一同加入新的限制 job。
- RAM/Commit：先減少新命令與新 worker 的併發，允許既有批次完成，再於安全邊界縮小批次。
  支援合作協議的工具可釋放可重建 cache。CPU 降速本身不會釋放其已配置記憶體。
- 磁碟：減少平行掃描、測試或編譯，必要時調低相關任務 I/O 優先權。
- working-set trim 不適合作為一般閉環調節旋鈕；另行評估收窄成可觀測的例外措施。
  不用 Suspend/Resume 週期輪流凍結程序，不用縮小硬性記憶體上限來迫使工作釋放 RAM。

採分層週期，不能把現有完整 collect.ps1 直接改成每秒啟動：

- 快速感測：常駐輕量程序每 1 秒讀整機 CPU 差值、可用 RAM、Commit 餘裕與已追蹤
  job 的有限計數。一般壓力連續約 3 秒才觸發柔性降速；瞬時尖峰不立即減量。
  嚴重容量底線在下一次有效快取樣就阻止新增工作，不等三秒確認。
- 局部調整：每次 CPU 額度乘 0.8，兩次一般降量至少相隔 5 秒，先看效果再動。
- 恢復：連續 20–30 秒健康才開始恢復，每 10 秒增加基準額度的 5%，不超過原准入額度。
- 完整採集：維持每 30 秒更新全機程序歸屬、報告與較昂貴的統計；wrapper 新任務
  在啟動前註冊，不能等下一輪全機掃描才納管。
- 事件：新命令准入、工作結束與豁免變動即時重評；增加容量前仍需新鮮的必要量測。

快速計數有效期限與五分鐘的既有報表有效期限分開；快取樣逾期不得假裝仍有秒級保護。
同一資源只由一個控制器寫入，快慢層共享決策與豁免狀態，避免互相覆寫優先權。
控制器使用 monotonic clock 計算持續時間，設定每輪時間預算並禁止重疊；過載時略過
可選採集而非堆積執行。所有 API 支援、採集成本與實際反應延遲均須在本機驗證。
最低份額、互動優先級與進展保護必須同時生效；一秒採樣不是防止所有瞬間 OOM 的保證。
以上數值需要 trace replay 校準；五分鐘 CPU 平均不能單獨負責快速反應。
若控制量是併發數，採用整數步進（例如 4→3→2），不假裝得到精確 20% 降幅；
已有四個工作時，降低目標到三個表示等其中一個完成後不補位，不會中斷它。

實際可觀察的例子：背景測試有四個 worker，前景命令需要回應而 CPU 持續飽和。
先將該測試的 CPU 額度從基準 100% 降到 80%，其餘任務保持不變；若支援 worker 調整，
在下一個批次把目標併發改三個。壓力連續 20–30 秒健康後，以 85%、90% 小步恢復。
此百分比表示「原額度的比例」，不是整台電腦 CPU 使用率。
若瓶頸其實是 RAM，優先使用併發/批次調節；直接減 CPU 可能延長記憶體占用時間。

## 實作順序與驗收

1. 補量測、task 歸屬與只記錄決策的 shadow mode。記錄選到誰、原因、原額度、新額度、
   預期影響與缺失資訊；記錄不代表執行成功。
2. 在獨立 canary 工作上實作可恢復的 Windows Job CPU 控制，驗證實際 CPU 時間、
   完成時間與 child containment，再分批啟用。Assign/Set/Query 各步失敗須顯示，不能靜默報成功。
   不設定 kill-on-job-close；控制器故障後由獨立恢復路徑清除過期限制。
3. 實作同級公平准入、等待老化與合作併發控制。批次參數只在工具支援的時點生效。
4. 依實測校準控制週期與減量幅度，最後才考慮歷史峰值需求學習。
   P95 估計要加保守餘裕與超額偵測；不能為通過准入自動縮小申報值。

必要驗證包括尖峰不振盪、持續壓力能降量、恢復漸進、任務不飢餓、PID reuse 不誤傷、
共享 UI 不受影響、控制器重啟能恢復、拒絕/權限不足有紀錄、未知資料不擴額。
同一工作負載比較開關控制器前後的互動延遲、任務完成時間、排隊最長時間、換頁量與失敗率。
通過單元測試或成功呼叫 API 都不足以宣稱效能改善。

維持本機 58 GiB 准入預算、4 GiB 實體與 4 GiB Commit 餘裕、最多三個豁免租約。
豁免仍計入整機消耗，但不受新增降速措施影響；不修改或擴張其授權範圍。

## 原始資料

- [Apple: View memory usage](https://support.apple.com/guide/activity-monitor/view-memory-usage-actmntr1004/mac)
- [Apple: Memory pressure events](https://developer.apple.com/documentation/dispatch/dispatch_source_memorypressure_flags_t)
- [Microsoft: Job CPU rate control](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information)
- [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Microsoft: Working Set](https://learn.microsoft.com/en-us/windows/win32/memory/working-set)
- [Microsoft: Page Faults](https://techcommunity.microsoft.com/blog/askperf/the-basics-of-page-faults/373120)
- [Linux: Pressure Stall Information](https://docs.kernel.org/accounting/psi.html)
- [Ghodsi et al.: Dominant Resource Fairness, NSDI 2011](https://www.usenix.org/events/nsdi11/tech/full_papers/Ghodsi.pdf)
- [RFC 5681: TCP Congestion Control](https://www.rfc-editor.org/info/rfc5681/)
