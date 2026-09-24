# 重新約束：只做 P4 實機量測與 P5 canary

日期：2026-09-25。這份文件取代 README 開頭「收尾 checkpoint」之後的所有工作方向。

## Role

你是 `codex/adaptive-scheduler-implementation` 分支的實作者。已驗證 source 是 `2e5015f`，
從那裡開始，七個 WIP 草稿維持凍結。

## Goal

拿到 P4 的退出證據，然後做 P5 canary。兩者都是這台 Windows 主機上的實測數字，不是 source 或 fixture 證據。

- P4：1、10、50 個受管 Job 時 helper 與 guardian 的成本分布，shadow mode 下 Set 呼叫次數為零。
- P5：一個飽和 CPU worker 被壓到整機 25% 與 37.5%，disable 後恢復，wrapper、helper、guardian 各自崩潰一次後系統仍能 restore。

## Success criteria

- `docs/planning/adaptive-scheduler/ACCEPTANCE-RESULTS.md` 存在，裡面是實跑出來的數字表、跑的指令、跑的 commit。
- 每個數字都能用文件裡的指令在乾淨 checkout 重現。
- 動到的模組其既有測試仍全過。
- 沒拿到數字的項目，寫「未量測」和原因，不寫「已定義契約」。

## Constraints

- production adaptive 維持 off，不改 config、Scheduled Task、啟動入口。
- 不新增 `sentinel/adaptive/` 模組，不新增 contract 文件。判斷標準：如果沒有這個模組，量測就跑不出數字，才能加，並在 commit message 第一行寫明是哪個量測需要它。
- 發現的缺口如果不會讓量測跑不出數字，寫進 `ACCEPTANCE-RESULTS.md` 底部的 Follow-ups 清單，一行一個，然後繼續量測。不修、不寫測試、不寫文件。
- 不動 `sentinel/coordinator.py` 與 `scripts/sentinelctl.py`，它們帶著另一項任務的未提交修改。需要改它們就是停止條件。
- 預算：牆鐘 3 小時或 10 個 commit，先到者為準，到了就交回。
- Resource Sentinel 規則照常：非輕量指令走 `scripts/invoke-sentinel.ps1`，估計要準，不自行豁免。

## Tools

- `scripts/invoke-sentinel.ps1`：跑 unittest 與量測用。HEAVY、P2、CPU 1、RAM 1 GiB、I/O 0 是既有的可行組合。被排隊就等，不改估計。
- 實機 native 測試：`py` launcher 和 agent session 啟動的 python 都在 Job 裡，adaptive preflight 會拒絕。只有使用者自己的主控台能過。遇到 preflight 因 Job 拒絕，把完整指令寫進 `ACCEPTANCE-RESULTS.md` 交回，由使用者手動跑，不要為了繞過它再寫程式。
- `.local-adaptive/`：原始 log 放這裡，不入庫。

## Output

交回時一份短報告，中文。內容依序：數字表、指令、被什麼擋住、Follow-ups 清單。不要重述 source 架構，不要 checkpoint 敘事。

## Stop rules

以下任何一個發生就停止並交回：

- P4 三組數字都拿到了。
- 預算用完。
- 需要使用者主控台跑 native 步驟。
- 需要改 `coordinator.py` 或 `sentinelctl.py`。
- 你打算新增第二個模組或任何 contract 文件。
