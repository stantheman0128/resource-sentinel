# 給 GPT Pro：請先質疑，再產出可實作計畫

你是本次 Windows Resource Sentinel 動態調度的規劃者。請用繁體中文回覆。
使用者會把你的 plan 交回 Codex 實作；本輪只做 planning，不寫程式、不部署、不修改機器。

請先閱讀本資料夾 README、SELF-GRILL、EVIDENCE-AND-ACCEPTANCE、來源快照索引，以及
`docs/adaptive-agent-scheduling.md`。重要：本規劃分支根目錄程式是較舊的 committed baseline；
本機尚未提交的選定程式在 `source-snapshot/`，請以快照解讀現況並引用路徑/函式。
若你無法取得文件全文，列出缺少哪些資料，不要假裝已審查，也不要根據舊 master 設計新功能。

目標：多 coding agent 並行時，針對造成 CPU、RAM/Commit 或磁碟瓶頸的獨立工作，
做有界、可恢復的柔性調整，改善桌面互動與工作完成效率。不能只讓 RAM 數字好看。

固定約束：

- 保留本機 58 GiB 准入預算、4 GiB physical/4 GiB Commit reserve，以及最多三個
  原子化豁免租約。58 GiB 不是每個 agent 的額度。豁免是明確使用者授權，仍需計帳；
  不新增緊急情況下自動撤銷、忽略豁免或壓低已豁免工作的新規則。
- 不殺或週期 Suspend/Resume 已有工作，不用硬性 RAM cap 逼迫第三方程式回收記憶體。
- 精準控制優先限於 wrapper 管理的獨立命令。共享 app UI、雲端推理、未納管工具
  不可假裝能精準控制，也不可把同一個 app 的所有 task 當作一個 task。
- 不覆蓋未提交修改；不把規劃快照當成正式 source 安裝；runtime 保持現況直到實作階段。
- 一秒取樣不是硬即時保證，30 秒報表不具秒級有效性。資料缺失/過期不得擴額。
- 全域 agent 入口採「單一受管理區段 + 共用政策入口」。區段以
  `docs/agent-bootstrap.md` 為來源，正式政策在 `docs/agent-policy.md`。
  保留另一個 session 完成的去重，不要提議在各入口另加重複規則；需要政策變更時，
  規劃 canonical source 更新與冪等同步，runtime 參數留在實作/設計文件。

請先對既有提案做 hostile review：至少找出五個會使它無效、難以恢復、反而更卡
或無法驗收的地方。SELF-GRILL 的回答也只是待批判假設，不是標準答案。

再比較至少三個方案：

1. 只強化目前准入、任務註冊與 priority，不加常駐控制器。
2. 有界常駐 fast helper + 慢採集 + wrapper-scoped Job Objects。
3. 先做工具合作式併發/批次調節，OS 只提供有限保護。

按效益、覆蓋率、監控成本、實作複雜度、恢復能力選一個最小可用方案。
不要為使用 DRF/AIMD 而使用它們；明確說哪些延後、哪些不採用及原因。

你的最終文件必須包含：

1. **決策與非目標**：首版具體改善什麼；現階段無法保證什麼；拒絕哪些原提案。
2. **架構與所有權**：collector/helper/wrapper/coordinator/watchdog 的生命週期與唯一
   writer；既有 throttle/trim 的分工；CPU priority、Job cap 與豁免的決策優先順序。
3. **任務註冊和啟動協議**：task/session/app/job 身分、PID reuse、父子工作、巢狀 wrapper、
   啟動前納管、取消、命令結束但子程序仍活著、job nesting 不支援時的具體處置。
4. **資料契約**：建議 schema/欄位/單位、CPU denominator、版本、時鐘、freshness、
   counters reset、snapshot sequence、採集成本及錯誤類型。不要記錄私人 prompt/命令輸出。
5. **控制狀態機與偽碼**：觸發、選受控者、減量、最小份額、冷卻、恢復、豁免、資料未知、
   controller loss；選明確起始參數與校準方法，不把待測值寫成已驗證最佳值。
6. **記帳與一致性**：measured/pending/allocated/desired/applied 的差別；existing reservation
   grace/TTL、兩個 SQLite store 與 hook/wrapper handoff；不能因限速使觀測值降低就
   過度放行新工作。公平性如何防拆 task、如何處理大工作等待。
7. **Windows 可行性**：選用 API、權限、能力探測、nested jobs/RDP DFSS 等限制；
   工作啟動 race 與控制器崩潰後實際恢復路徑；不要假設關閉 handle 就解除 job 限速。
8. **故障矩陣**：helper/wrapper/collector 崩潰、DB locked、IPC 斷線、系統 sleep/resume、
   clock jump、PID reuse、豁免變更與控制動作競爭、API 成功但未生效。
9. **分階段實作表**：每階段列出要改/新增的檔案與函式、依賴、最小驗證、進入下一階段
   的證據。先完成可恢復的小範圍功能，不把公平、GPU、工具適配一次塞進 MVP。
10. **驗收與回滾**：給可量測的 pass/fail 建議值；區分演算法模擬、Windows canary、
    真實 agent 命令及桌面互動測量；設計小規模 A/B、失敗即回滾、舊控制器接回順序。
11. **風險與未決事項**：阻塞實作的未知必須轉成有界 capability spike；只問使用者
    真正無法由工程判斷解決的偏好，不把技術調查退回給使用者。

引用官方文件/原論文並區分來源事實、程式現況、推論和建議。目標是可以照著實作的
`IMPLEMENTATION-PLAN.md`，不是科普文章、演算法清單或泛泛的 roadmap。
