# Resource Sentinel

讓本機所有 coding agent 開工前就知道電腦還剩多少資源，自己決定要不要收斂，
不必人工盯場。零常駐進程，靠 Task Scheduler 每分鐘跑一次採集腳本。

## 為什麼做這個

多個 agent session 同時跑的時候，沒有誰知道整台機器的狀況。每個 session
都覺得自己可以開 build、裝依賴、跑測試，疊起來就把電腦拖到卡死。
這個工具給所有 agent 一張共用的「告示板」，開工前看一眼，超載就自己讓路。

## 架構

```
Task Scheduler（每 60 秒）
  └─ collect.ps1（跑完就退）
       ├─ 量測：CPU、RAM、GPU、磁碟、各 agent 進程樹用量
       ├─ 歸因：跨輪差分算出「上一分鐘誰寫了多少磁碟」
       └─ 產出：status.md（告示板）、status.json、dashboard.html 資料

讀取端（只讀檔案，零進程）：
  ├─ Claude Code：hook 每輪自動注入狀態，黃紅燈升級警告
  ├─ Codex CLI：AGENTS.md 指示開工前讀告示板
  ├─ Cursor：Rules for AI 同樣指示
  └─ 瀏覽器：開 dashboard.html 看儀表板（60 秒自動刷新）
```

## 主要能力

- 綠、黃、紅燈號：RAM、CPU 五分鐘均值、系統碟剩餘，三者取最嚴
- agent 進程樹用量：claude、cursor、codex 為根，往下彙總整棵樹
- 磁碟寫入歸因：每輪算出各進程寫入量，磁碟單輪變動超過 2 GB 就把
  當下的寫入排行榜存進 events.log，事後可查「昨晚磁碟怎麼爆的」
- 歷史帳本：每個 repo 的 session 峰值 RAM 統計，agent 開工前
  可以拿「這個 repo 上次吃多少」對照現在剩多少餘裕
- 儀表板：趨勢圖、agent 用量表、寫入排行、異動事件，單一 HTML 檔

## 安裝

1. Clone 到本機，跑一次採集器確認有輸出：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\collect.ps1
```

2. 掛排程（不需管理員權限）：

```powershell
schtasks /create /f /tn "ResourceSentinel" /sc minute /mo 1 /tr "conhost.exe --headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File <路徑>\scripts\collect.ps1"
```

3. 瀏覽器開 `%USERPROFILE%\.resource-sentinel\dashboard.html`，釘成書籤。

4. agent 接入方式見 `docs/agent-integration.md`。

## 資料檔與保留策略

| 檔案 | 內容 | 上限 |
|---|---|---|
| status.md / status.json | 當前狀態，每輪覆寫 | 不成長 |
| history.json | 每 repo 峰值統計，最近 20 筆 | ~100 KB |
| samples.csv | 60 秒生樣本 | 7 天滾動 |
| events.log | 磁碟異動事件 | 2 MB 自動修剪 |

## 中樞調控（v0.6）

觀測之上，兩層主動調控，仍然零常駐、零自動殺：

1. **重活槽位制（Claude Code）**：PreToolUse hook 攔截重量級指令
   （build、安裝、全套測試，pattern 在 config.json 可調）。
   全機同時只允許一個重活；橘燈起硬擋新重活、紅燈全擋。被擋的 session
   會收到訊息自己改做輕量步驟稍後重試。槽位帶 15 分鐘 TTL，
   佔槽進程死亡自動釋放，不會死鎖。
2. **OS 優先權降級（管所有 agent）**：橘/紅燈時採集器把所有 agent
   進程樹降到 BelowNormal，綠燈自動恢復。不管 agent 聽不聽話都有效，
   桌面與遠端連線永遠搶得到 CPU。恢復採自癒式：凡 agent 樹內
   BelowNormal 的進程在綠燈一律升回，名單遺失也不會卡死在低優先權。

## 設計原則

- 零常駐：排程腳本跑完就退，猝死一次下一分鐘自動復原
- 零自動殺：只提供資訊，處置由 agent 或人決定
- 檔案是唯一介面：不依賴 MCP，任何會讀檔的 agent 都能接
- 監控失效可偵測：狀態檔帶時間戳，超過 5 分鐘讀取端自動視為失效

設計文件：`docs/superpowers/specs/2026-08-12-resource-sentinel-design.md`
