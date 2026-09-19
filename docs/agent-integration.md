# 各 agent 接入方式

告示板路徑固定：`C:\Users\stans\.resource-sentinel\status.md`（機器可讀版 `status.json`）。
任何能讀本機檔案的 agent 都能接入，不需要 MCP 或任何協定。

**使用者授權豁免適用於所有接入 Resource Sentinel 的 agent，不限 Codex。**
唯一共用規則來源是 [agent-policy.md](agent-policy.md)：採集器每輪將全文放進
`status.md`，Claude 的提示 hook 也直接載入同一份文字。Cursor、Grok 及其他原本會
讀取 Sentinel 狀態的 agent 因而使用相同規則；不需要為每個品牌建立不同的豁免邏輯。
自然語言授權由 agent 理解後呼叫 CLI 登記，並非每個應用程式自動解析聊天內容。

先分清兩個角色：agent session 是 Codex／Claude Code／Cursor 等控制端，負責理解任務、
修改與回報；execution worker 是實際跑 command 或 provider job 的本機／雲端環境。
session heartbeat 不能增加可用 RAM，worker probe 也不代表該 provider 能自動收任務。

## Claude Code / Claude Desktop（資源 admission 已自動接入）

`~/.claude/settings.json` 的 UserPromptSubmit 掛了 `sentinel-inject.py`：
安裝路徑下的三個 Sentinel hook 以薄 loader 執行本 repository 的同名檔，避免副本落後。

- 每輪對話自動注入一行狀態（燈號、RAM、CPU、GPU、C 槽、本 repo 歷史峰值）
- 黃燈追加降速建議、紅燈追加強制警告
- 同時把 session 的 agent 進程 pid 與 cwd 登記到 `sessions.json`，
  採集器據此把進程樹歸因到 repo（歷史帳本的資料來源）
- 新開的 session 才會生效（hook 設定變更不影響已開的 session）

## Codex CLI / Cursor（atomic wrapper 可用）

全域 `C:\Users\stans\.codex\AGENTS.md` 會先讀 status.md。真正需要原子 reservation
的重量級指令，應透過 wrapper 執行，而不是只先讀燈號：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 `
  -Command "npm run build" -Priority P2
```

wrapper 會排隊、原子取得 CPU/RAM/I/O reservation、執行命令，最後在 `finally`
釋放。Claude hook 能精準辨識這個 wrapper，避免內外重複 reservation。
`-ResourceClass AUTO` 仍是 bootstrap rule；`orchestratorctl.py profiles` 提供歷史 P50/P90/P95
供後續調整顯式需求，但尚未自動改寫 task request。

## 命令分類、等待與放棄單筆排隊請求

Hook 與 wrapper 的 bootstrap classifier 依實際執行的程式與動作分類。
`git show branch:app/build.gradle.kts`、`git add app/build.gradle.kts`、
`ls ~/.gradle/jdks`，以及只用 `cat`／`grep` 讀取或搜尋這些路徑，不會因為
檔名有 `gradle` 而成為 HEAVY。真正的 `gradle`／`gradlew`／`./gradlew.bat`、
`npm run build` 等工作仍需准入；`cmd /c`、`bash -c` 或 `&&` 串接也會檢查
其中實際執行的命令。不能靜態辨認的 script、動態 shell 語法與未知執行程式
保守視為 HEAVY；分類不是任意 shell 的完整解譯器。

`heavy_patterns` 改為比對執行簽章（例如 `gradlew`、`npm run build`），
不再掃描整段命令的檔案路徑／資料參數。格式不合法或不支援的規則不會放行工作。
本次不修改日常 config 的規則、資源門檻或豁免上限。

需要繼續的工作應留在佇列，使用 hook 提供的 exact `wait-existing` 命令等待。
確定放棄一筆請求時，替換下例的 request key 與 owner PID：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\sentinelctl.py `
  cancel --request-key RETURNED_REQUEST_KEY --owner-pid 12345
```

CLI 會驗證 owner 是呼叫程序本身或其真實祖先，並將 PID 與建立時間和 SQLite
queue row 精確比對；`--owner-pid` 不是可以冒用其他 session 的授權欄位。
同 PID 已換程序、建立時間未知（含舊資料的 0）、非本人祖先或不同 owner 均拒絕。
成功回傳 `ok=true, cancelled=1`；已經准入／不存在則 `cancelled=0`，可安全重試。
拒絕時回傳非零 exit code 與具體 reason，保留原請求。

此命令不操作 reservations、執行中的工作或 exemptions，不需要新增資源 reservation。
它不呼叫 cleanup，也不初始化缺少的資料庫。SQLite 中的刪除立即生效；
`queue.json` 是唯讀相容鏡像，由正常採集／發布稍後刷新，不能手動改鏡像假裝取消。
取消表示明確放棄這筆工作，應向使用者交代；不能為了結束回合就丟掉仍需要的請求。

同一 owner PID＋建立時間的所有排隊請求，共用最多三次 Stop 提醒；
換成下一筆或加入新請求不會重新獲得三次提醒。次數用完只停止攔截 Stop，
不再自動取消任何請求；全部 queue 清空後才開始新的提醒週期。
提醒計數使用 SQLite 短交易避免平行 subagents 相互覆寫；舊
`stop-blocks.json` 僅作一次性計數匯入。這不改變 PreToolUse 的准入保護。

## 使用者授權的暫時豁免

使用者在目前任務明確說「我給你最高權限，你可以不用理會 Resource Sentinel」
（或同義授權）時，agent 可以直接啟用以下豁免，不需要再問一次。沒有這項授權時，
不可因排隊、趕時間或紅燈自行啟用。這是同一 Windows 使用者下的操作約定，
`--user-authorized` 是授權聲明，不是密碼、身分驗證或 Windows 管理員權限。

多個任務共用 Codex／Cursor 桌面程序時，**優先用單次命令豁免**，避免影響其他任務：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File `
  C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 `
  -Command "npm run build" -Priority P2 `
  -UserAuthorizedExemption -ExemptionMinutes 60 `
  -ExemptionReason "User explicitly authorized this task to bypass Sentinel"
```

此模式以新建 wrapper 的 PID + 建立時間綁定它和子程序，命令完成（包含失敗）就撤銷。
即使 wrapper 被強制結束而未執行 finally，根程序消失或期限到達也會失效。
預設 60 分鐘，可指定 1–1440 分鐘；不會自動續期。任務仍有未完成的獨立命令時，
可在原授權的任務／時間範圍內分別使用此模式；不要把一次授權延伸到其他任務。
多次命令共享同一次授權的截止時間，後續只填剩餘分鐘數，不重置完整期限。

對已有的、確認獨立的 session 或程序樹，可手動授權（PID 範例需替換成即時核對的值）：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\sentinelctl.py `
  exemption-grant --pid 12345 --minutes 60 --user-authorized --reason "User authorized this process tree"
py C:\Users\stans\Projects\resource-sentinel\scripts\sentinelctl.py exemption-list
py C:\Users\stans\Projects\resource-sentinel\scripts\sentinelctl.py exemption-revoke --id RETURNED_ID
```

要先核對 PID、建立時間、程序用途和子樹範圍；不要把共享桌面 host／終端機根程序當成
單一 task。無法隔離 task 時用前述命令模式。若使用者明確要求整個 App 豁免，才選其根程序。
`exemption-list` 回傳 active／expired／revoked／process_exited、範圍、到期與授權原因；
原因只寫簡短操作描述，勿存原始私人對話或憑證。

有效豁免會略過本機 coordinator 的燈號、容量、佇列順序限制，但仍建立／釋放 reservation，
保留工作與負載紀錄。採集器略過該子樹的 CPU／I/O 降優先序與 working-set trim，並恢復
先前的降速；仍量測該子樹的使用量。現有程序的 CPU／I/O 豁免與撤銷在下一輪成功採集
生效（正常約 30 秒；監控延遲時可能更久）；已啟動工作不會在到期後被強制終止。
PID 重用、根程序退出、到期、撤銷都不會把授權轉移给另一個程序。新建子程序會在下次
採集時納入。故障／讀取失敗不能產生新豁免。

豁免不更動 Windows 權限、應用程式 sandbox、防毒或雲端配額；不跳過 orchestrator 的
workspace claim、worker capability、provider quota 等檢查。`P0` 仍只是一般佇列優先級，
不等於這項使用者豁免。

## 登記 agent session

要讓中央帳本看見一個 session，可在開始工作和活動期間送 heartbeat：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  session-heartbeat --session-id codex-example-01 --agent-kind codex `
  --owner-pid 12345 --repo C:\src\example --state IDLE
```

`session-id` 必須穩定且每個 session 唯一；`owner-pid` 是 agent 根進程，不要填 command
子進程。開始／結束 task 時更新 `--state` 與 `--current-task-id`。目前 heartbeat 是
registry 與觀測資料，不會接管既有互動對話，也不會把某個 session 的 context 複製給
另一個 provider。

採集器從 process tree 自動發現的 session 只是 inventory，預設 `accepts_tasks=false`。
只有上述顯式 `session-heartbeat` 完成 broker handshake 的 session 才能 `session-pull`；被指派
的 SESSION task 會和 WORKER task 一樣扣除 bound worker 的 RAM/CPU/disk/concurrency。

查看目前 registry：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py sessions
```

Cursor 全域 rule 仍需手動貼一次，但重活應呼叫相同 wrapper；只讀 status.md
不能防止兩個 agent 同時起跑。

Cursor 的全域規則存在它自己的設定裡，沒有可靠的檔案路徑可以直接寫入。
打開 Cursor：Settings、Rules for AI，貼上下面這段：

```
Before running anything heavy (builds, installs, full test suites), read
C:\Users\stans\.resource-sentinel\status.md. GREEN: proceed. YELLOW: run heavy
commands with low priority and avoid parallel heavy work. ORANGE: defer new
heavy tasks; if one must run, low priority and one at a time. RED: light
operations only; tell the user the machine is overloaded. If the file is older
than 5 minutes, monitoring is down; say so and ignore its contents.
The shared user-authorized exemption policy in status.md applies to this agent
too. Explicit user authorization may temporarily override Sentinel restrictions
within the named task/process and deadline; register the grant via the documented
wrapper/CLI. Do not self-authorize or apply it to unrelated tasks.
```

貼完之後 Cursor 的 session 就會在動手前自己去看告示板。

## 提交跨環境 task

task 應至少指定穩定 id、prompt 或 command、repo 及預計修改的 `path_scopes`。資源需求、
capability、trust domain 和執行偏好都放在 task，而不是寫死在 agent prompt：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py submit --task `
  '{"id":"example-fix-01","prompt":"Implement the fix","repo":"C:/src/example","base_sha":"0123456789abcdef0123456789abcdef01234567","path_scopes":["src","tests"],"priority":"P2","requirements":{"ram_gib":4,"cpu_units":2},"execution_preference":"CLOUD_PREFERRED","verification":{"command":"py -m pytest"}}'

py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py tick --limit 2
```

寫入 repo 的 task 必須同時提供不可變的 `base_sha` 與 `path_scopes`。dispatch 前會先取得
worker reservation 與 repo／base SHA／path scopes 的 workspace claim；本機 task 再建立或
安全重用 deterministic Git worktree，回傳的 `workspace.worktree_path` 才是工作目錄。
重疊範圍被其他 task 佔用時應等待，不要繞過 claim 在原 checkout 併寫。cloud phase
若有 `verification`，結果回收後會建立 `LOCAL_REQUIRED` 的 P1 子 task。

## Cloud provider 的預設行為

bootstrap 只讓本機 adapter 自動化。Cursor Cloud、Grok、Claude Web、Codex Cloud、
ChatGPT Work 和 GitHub runner 都是人工 probe 資料，預設 adapter 為 manual 且 disabled。
這表示我們知道一次觀測到的環境形狀，不表示已有可靠的 submit/status/cancel/result API。

人工 dispatch 的 task 會停在 `AWAITING_MANUAL`；在人類確實完成 provider 操作並取得
結果後再回報：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  complete-manual --task-id example-fix-01 --success --result '{"artifact":"commit-or-patch-id"}'
```

雲端 execution 通常是暫時 container／runner，不是永久電腦；不要依賴跨 job 的檔案、
登入狀態、IP 或背景程序。要啟用真正的 provider adapter，必須先逐項驗證 lifecycle 與
crash recovery。token、cookie、密碼不得寫入 task JSON、worker bootstrap、SQLite、log 或
Git；設定只保存環境變數名稱，值在執行時注入。本機 command 預設不繼承任意 parent
environment；需要的秘密用 `metadata.env_refs` 顯式列出。

provider submit 邊界若 crash，task 會停在 `dispatch_outcome_unknown`。不要直接重送；用：

```powershell
py C:\Users\stans\Projects\resource-sentinel\scripts\orchestratorctl.py `
  resolve-dispatch --task-id example-fix-01 --external-job-id <provider-job-id>
# 或在 provider 確認完全沒有送出後：--confirmed-not-submitted
```

## 之後新裝的任何本機 agent

只要它支援 system prompt、rules 檔或 AGENTS.md，把上面 Cursor 那段貼進去就接入了。
若只需要資源告示板，系統本身不用改任何東西；若要參與原子調度，再加 session heartbeat、
以 wrapper 執行重活，並用 orchestrator task／workspace claim 流程協調修改範圍。

完整架構與容量語義見 [`architecture.md`](architecture.md)。
