# Resource Sentinel 設計文件

日期：2026-08-12
狀態：設計已口頭核可，spec 待 Stan 書面確認
專案位置：`C:\Users\stans\Projects\resource-sentinel`
資料目錄：`C:\Users\stans\.resource-sentinel\`

## 1. 目標

讓本機所有 coding agent（Claude Code、Claude Desktop、Cursor、Codex CLI 等）在開工前與執行中，
不需人工提醒就能看到機器資源狀態與自身用量，據此自我調節（暫緩、降速、換做法、主動放棄），
避免多 session 併發把電腦拖到卡死。

### 非目標

- 不自動殺任何進程（mobile-oss watchdog 互殺迴圈的教訓）
- 不做硬性資源上限（不用 Job Object 沙箱）
- 不支援雲端網頁版 agent（chatgpt.com 等碰不到本機檔案）
- 不支援瀏覽器內 extension agent（第二期再評估）
- 不做即時儀表板 UI（60 秒粒度的告示板就夠）

## 2. 架構總覽

```
Task Scheduler（每 60 秒觸發，腳本跑完就退，零常駐）
  └─ collect.ps1
       ├─ 量測：全機 CPU / RAM / 磁碟剩餘、每個 agent 進程樹用量
       ├─ 歸因：每棵進程樹按其 cwd 對應到 repo
       ├─ 更新：status.md + status.json（覆寫）
       ├─ 更新：history.json（聚合統計）
       └─ 追加：samples.csv（7 天滾動，自動修剪）

讀取端（全部只讀檔案，不跑任何進程）：
  ├─ Claude Code：UserPromptSubmit hook 注入摘要（全自動）
  ├─ Cursor：.cursorrules 指示開工先讀 status.md
  ├─ Codex CLI：AGENTS.md 同樣指示
  └─ 任何其他本機 agent：system prompt 一行指示
```

設計核心：**固定路徑的狀態檔是唯一通用介面**。任何會讀檔的 agent 都能接入，
不依賴 MCP 或任何協定；採集器掛掉時檔案時間戳過期，讀取端自然知道監控失效，
整條鏈沒有互相依賴、沒有互殺空間。

## 3. 資料檔與保留策略

| 檔案 | 內容 | 成長方式 | 上限 |
|---|---|---|---|
| `status.md` | 人/agent 可讀告示板 | 每 60 秒覆寫 | 不成長，恆 ~2 KB |
| `status.json` | 同內容機器可讀版 | 每 60 秒覆寫 | 不成長 |
| `history.json` | 每 repo 聚合統計＋最近 20 次 session 摘要 | 每 repo 固定筆數 | ~100 KB 級 |
| `samples.csv` | 60 秒生樣本（debug 用） | 追加＋每日修剪 >7 天列 | ~2 MB |

log 堆積問題的解法就是**聚合**：預估只需要「這個 repo 歷史峰值多少」，
不需要保留每一筆原始樣本。生樣本僅供 debug 採集器本身，7 天自動丟。

## 4. 採集器（collect.ps1）

- 觸發：Task Scheduler，每 60 秒，`-WindowStyle Hidden`，跑完就退
  （依 `howto_crashproof_background_jobs_windows` 教訓：不用長駐 loop，
  用排程＋idempotent 收斂腳本，猝死一次下一分鐘自動復原）
- 量測內容：
  - 全機：CPU%（`\Processor(_Total)\% Processor Time`，不用 Win32_Processor.LoadPercentage——已實測不可靠）、
    RAM 已用/剩餘、各磁碟剩餘空間
  - 進程樹：以 claude.exe / Cursor.exe / codex.exe / node / python 等已知 agent 執行檔為根，
    向下彙總子樹的 RAM 與 CPU
  - 歸因：讀每棵樹根進程的 cwd（`Win32_Process`），對應到 `C:\Users\stans\Projects\<repo>`
- 執行成本：單次 1–2 秒，每分鐘一次，本身不構成負擔
- 失效顯示：status.md 首行帶產生時間戳；讀取端看到 >5 分鐘未更新即視為監控失效

## 5. 燈號定義

| 燈號 | 條件（任一成立） | 建議行為 |
|---|---|---|
| 綠 | RAM <75% 且 CPU 5 分鐘均 <60% 且系統碟剩 >50 GB | 正常跑 |
| 黃 | RAM 75–90% 或 CPU 均 60–85% 或系統碟剩 20–50 GB | 重量級動作降速跑或暫緩；不開新併發 |
| 紅 | RAM >90% 或 CPU 均 >85% 或系統碟剩 <20 GB | 只做輕量操作；重活等燈號回落 |

閾值寫在 `config.json`，可調。

## 6. 歷史帳本與「預估」

預估的唯一可靠來源是實測歷史，不憑空猜 GB 數：

- 採集器每輪把「repo → 進程樹 RAM/CPU」寫入當前 session 紀錄，session 結束（樹消失）時
  結算峰值，滾入該 repo 的統計：`peak_ram_mb`（歷史最大）、`typical_peak_mb`（近 20 次中位數）
- Agent 開工時拿到：「你在 quant，此 repo 近期 session 典型峰值 2.8 GB，
  現在全機剩 3.1 GB 餘裕 → 貼上限，建議降速模式」
- 冷啟動：沒歷史的 repo 只給全機燈號；跑過幾次後預估自動變準

## 7. Agent 端行為要求（寫進 hook 注入文字與各家規則檔）

開工前：
1. 先自我分類手上任務是輕量（讀檔、小改、問答）還是重量（build、安裝、大量檔案處理、跑測試全套、開 subagent）
2. 重量任務必查告示板：目前燈號＋本 repo 歷史峰值＋剩餘餘裕
3. 餘裕不足時先講，再選擇：暫緩／降速／換省資源做法

執行中（僅 Claude Code 有逐輪注入）：
- hook 每輪注入自身進程樹當前用量與增速（如「5 分鐘內 500 MB → 2 GB」）
- 增速異常時 agent 自主選擇：
  - 暫緩：先做輕量步驟等燈號回落
  - 降速：重指令改用 `Start-Process -Priority BelowNormal`（OS 層保證讓路，電腦不卡，只是慢）
  - 終止：放棄目前做法，換省資源路線

全程零自動殺進程；所有處置由 agent 帶著數據自行決定。

## 8. 各 agent 接入方式

| Agent | 機制 | 自動程度 |
|---|---|---|
| Claude Code | UserPromptSubmit hook 注入摘要；紅燈時注入強烈警告段 | 全自動，agent 必然看到 |
| Claude Desktop | 同上（共用 `~/.claude` hook 設定） | 全自動 |
| Cursor | `.cursorrules` / 全域 rules 加一行「開工前讀 status.md」 | 半自動（靠規則遵從） |
| Codex CLI | `AGENTS.md` 加同一行 | 半自動 |
| 其他本機 agent | system prompt 加同一行 | 半自動 |

hook 注入摘要格式（一行，恆常）：
`[sentinel] 綠｜RAM 62%｜CPU 18%｜C槽剩 228GB｜你的進程樹 740MB｜本repo典型峰值 1.2GB`

## 9. 失效模式

| 情況 | 表現 | 處理 |
|---|---|---|
| 採集器猝死一次 | 下一分鐘排程自動重跑 | 無需處理 |
| 採集器持續失敗 | status.md 時間戳過期 | hook 偵測 >5 分鐘過期時注入「監控失效」而非舊數據 |
| status 檔被鎖/半寫 | 寫入採 temp+rename 原子替換 | 讀取端永遠看到完整檔 |
| cwd 歸因失敗（進程無 cwd） | 該樹歸入 "unknown" | 不影響全機燈號 |

## 10. 實作步驟（尚未排程，待 Stan 核可後展開）

1. **採集器核心**：collect.ps1 量測＋status.md/json 原子寫入；手動跑通過驗證數字對得上工作管理員
2. **排程掛載**：Task Scheduler 註冊（含 schtasks 雷點處理），驗證連續 30 分鐘無跳窗、無殭屍
3. **Claude Code hook**：UserPromptSubmit 注入一行摘要；黃/紅升級警告；驗證注入內容出現在對話
4. **歷史帳本**：session 峰值結算＋history.json 聚合＋7 天樣本修剪；跑兩天驗證預估數字合理
5. **其他 agent 接入**：Cursor rules、Codex AGENTS.md 各加一行；實測至少一家會照做
6. **驗收**：模擬高負載（大 build），確認燈號轉黃/紅、Claude Code session 看得到並改變行為

每步獨立可驗證，做完一步 commit 一步。

## 11. 開放問題

- 專案/資料目錄命名用 `resource-sentinel`／`.resource-sentinel`，Stan 可改名
- Cursor/Codex 的規則遵從率未知，第 5 步實測後才知道半自動接入的實際效果
- CPU 增速歸因在多 session 同 repo 時會混在一起，v1 接受此粗糙度
