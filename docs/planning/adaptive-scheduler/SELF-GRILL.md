# 自我質疑紀錄

這是同一位 agent 的自我審查，不是獨立審查或 GPT Pro 的結論。
日期：2026-09-19。每個回答都可以被後續證據推翻。

## G01：我們到底想優化什麼？

RAM 少一點不是目標；互動回應、有效工作進度、排隊與完成时间才是。
**修正**：plan 必須選能實測的互動負載或 latency proxy，並說明 proxy 不等同使用者感受。
尚未有可歸因的 A/B 數據，不能宣稱降速一定改善體驗。

## G02：每秒看一次就能每秒處理故障？

不能。sample interval、資料年齡、決策延遲、API 生效與應用恢復是不同時間。
**修正**：量每一段 p50/p95/max；健康紀錄必須表明 sample 與 applied 時間，
watchdog 還要驗證工作有效進展。OS 忙到 helper 得不到 CPU 時，一秒只是目標。

## G03：一秒 loop 的成本有證據嗎？

沒有。Python/PowerShell 的啟動、CIM、全機 enumerate、DB/fsync 都可能超出預算。
**暫定**：常駐、只查已註冊 job 的小量 counters、慢速枚舉、不每秒啟動外部工具；
需驗證 1/10/50 jobs 的成本與時間預算。這是新架構，不是修改 interval 就完成。

## G04：我們能找到「某一個 agent」嗎？

app 根 PID 不等於 task。現有 wrapper 會追到共享 app owner；雖有 tool_use_id，
command request identity/handoff 如何去重仍必須查清楚，不能直接當新 controller task ID。
**修正**：公平計帳的 session/agent principal、控制的 command job、UI 分開建模。
只對有可信註冊身分的工作承諾精準控制；其他維持量測/既有政策並明示覆蓋缺口。

## G05：命令先執行，再加入 job 會不會漏掉子程序？

會有競爭窗口。現有 wrapper 是准入後直接執行 cmd.exe，沒有 pre-launch containment。
**待決策**：建立初始 suspended child、assign job 後才 resume 等啟動協議的可行性。
這種啟動同步不等於用週期 Suspend/Resume 做降速；失敗必須清理尚未開始的 child。
也要保留 quoting、cwd、env、stdin/out/err、exit code、Ctrl-C、timeout 的既有使用體驗。

## G06：加入 Job Object 是完全可逆嗎？

不是。Microsoft 說 process 與 job 的關聯不能直接解除；能撤回資源限制，不等於移出 job。
關閉 handle 也不代表有活程序的 job 限制立即消失。
**修正**：只在新啟動的獨立命令試用；rollback 要明確定義解除哪些限額與殘留何種歸屬。
不能把「不用 kill-on-close」誤當成完整故障恢復。

## G07：controller 掛掉，誰幫工作解除限速？

原提案寫「独立恢復路徑」太模糊。若只有 controller 持有可用 handle，watchdog 未必能恢复。
**待決策**：job 命名/ACL、handle 所有權、desired/applied journal、lease expiry、獨立守護者、
重啟 epoch/fencing。必須用實際強制結束 controller 的 canary 驗證限速解除且工作完成。

## G08：快慢兩套控制器會不會打架？

現有 collector 每輪會修改 CPU/I/O priority，還可能 trim。新 helper 若只加在旁邊，
會疊加限制或互相恢復。**修正**：同一資源單一 writer；以明確 rollout mode 移交責任，
舊模式退場、受控範圍與 fallback 必須寫出狀態轉移，不能只靠不同檔案保存設定。

## G09：豁免剛核准，舊快照還能限速它嗎？

現有 resolver 有 PID/start/expiry 驗證，但 grant 後到下一次 snapshot 之間仍有新狀態。
**待決策**：grant/revoke/expiry 與 actuator mutation 的同步語義、版本與最大傳播延遲；
不能從「不在舊快照」推論當下沒有豁免。未知時不新施加限制；仍保留准入保護。
三豁免計數與新 controller lease 是不同東西，不能讓後者消耗或增加豁免名額。

## G10：CPU 降速能救記憶體嗎？

不一定，甚至使工作更久不退出、延長 RAM 占用。已配置的 private committed bytes
也不會因減 CPU 消失。**修正**：CPU、RAM/Commit、I/O 使用不同控制動作，首版 RAM
先做新工作准入；合作釋放 cache 與 worker resize 只有工具真實支援時才宣稱生效。

## G11：減到原額度 80%，等於效能剩 80%？

不是。weight 只有相對份額，rate 才有另一套百分比分母；nested job 的 rate 受 parent 影響。
CPU-bound 與 I/O-bound 的效能反應也不同。**修正**：定義 cpu_units、logical CPU、整機比例、
相對基準比例及 API CpuRate 的換算，明確選 weight 或 cap，不能混成一個「速度」欄位。

## G12：限速後 CPU 看起來空閒，是否可以放行更多工作？

不能無條件放行。這可能形成「降速→觀測下降→新增工作→更壅塞」的循環。
現有 admission 對短時間 pending reservation 做 grace 計帳；新控制器要重新檢查這個模型。
**待決策**：measured 與尚未實現 demand、已承諾資源及控制額度如何避免重複/漏算。
不能只修改 pressure.py，忽略 coordinator 和 local worker 的共同容量。

## G13：工作跑得比 lease 更久呢？

現有 wrapper 的生命週期是 wait→cmd→release；需查 long-running reservation 的 renew 語義。
**待決策**：wrapper/child 活著但 TTL 過期，或 wrapper 結束但 child 活著的帳與限額歸誰。
不要在 planning 中直接斷言所有這類路徑有 bug，但必須用案例證明是否有缺口。

## G14：所有 Job Objects 呼叫都能用嗎？

沒有本機 canary 證據。nested jobs、既有 sandbox/job、breakaway、權限、RDP DFSS 都可能影響。
**修正**：能力探測結果必須區分 supported/unsupported/unknown/failed，寫出 fallback；
不支援不能自動提權，API return success 也必須 query 與實測驗證。

## G15：挑誰降速，真的知道誰是背景嗎？

目前沒有可靠的 per-task foreground 對應。最耗 CPU 的工作也可能就是使用者正在等待的工作。
**暫定**：優先使用已存在的任務優先級與明確 task role，沒有資料就給中性預設；
不從 app 名稱推測重要性、不偷用滑鼠/鍵盘監控。Pro 需決定最低可用的互動保護方式。

## G16：採用 DRF 就自動公平嗎？

不是。需求模型、不可搶占 RAM、異質 I/O、可拆 task、strict priority 都破壞簡單套用。
**修正**：先定義公平的 principal 與時間窗，只在同級准入做有限公平；
aging 提升排序也不會讓大工作突然有容量，必須規劃有期限的 capacity accumulation。
首版可以明確延後 DRF，而不是宣稱已有其理論保證。

## G17：少開一個 worker 是減速還是取消？

對不支援動態 resize 的工具，只能等已啟動 worker 完成後不補位，或下次命令改參數。
**修正**：adapter 必須回報 requested/applied/unsupported；不能把寫入建議欄位當成執行證據。
雲端 LLM 推理速度也不受本機 Job CPU cap 控制。

## G18：恢復原值會不會蓋掉其他人的設定？

會，尤其只用 PID 當索引或無條件設成 Normal 時。**修正**：保存 identity、original、
last-applied、controller epoch，撤回前 compare-and-restore；第三方改動需明確衝突處理。
程序優先權的原值與 job cap 的原值不同，兩者不能共用簡化還原欄位。

## G19：單一瞬間 RAM 爆增，輪詢能保證不 OOM 嗎？

不能。容量成長可快於一秒；已豁免與未納管程序也會消耗記憶體。
**修正**：保守准入、安全餘裕、已知批次需求估計仍必要；不要宣称 hard real-time/OOM 保證。
全機壓力來自外部程序時要顯示此事，不能一律懲罰最大 agent。

## G20：缺資料時全部解除限制，還是全部鎖死？

兩者都可能有害。**待決策**：不新增容量與不新增懲罰是不同操作；已有限制則依有界
lease、身份證據與恢復責任處理。需定義 suspend/resume、counter reset、clock jump、
DB busy、遺漏事件的状态轉移，不能用單一 try/catch 吃掉所有錯誤。

## G21：怎樣證明更好，而不是只是更慢？

相同 workload 的 A/B，分開記錄 foreground proxy latency、背景完成時間、最長排隊、
進展、paging、失敗率與監控成本；穩定多輪，不靠一次 API 成功或一張 dashboard。
Pro 應給候選數值門檻與校準/否決規則，不能把本文例子當已測結果。

## G22：目前這包就夠讓另一個模型規劃嗎？

若只看 GitHub master，不夠。它落後本機 dirty tree。**修正**：本包有選定 source/test
文字快照與雜湊；相關測試本輪未重跑，快照不代表可執行 build。實作前仍要比較 live tree。

## 經自我質疑後，縮小首版範圍

先解決註冊/量測/恢復，再在獨立 canary job 驗證 CPU 控制；其他既有工作不批次搬入 job。
快採集和新准入可以合作，但必须以具體帳本規則連接。RAM 不做外部強制回收，
公平與工具 resize 可延後。未量測前不承諾 1 秒成本或固定性能改善幅度。

官方可行性資料（2026-09-19 查閱）：

- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
- [Windows CPU rate control](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information)
- 其他來源見[原提案](../../adaptive-agent-scheduling.md#原始資料)。
