# Changelog

## 0.7.0 - 2026-08-13

- Telegram 警報：紅燈連續 5 分鐘發警報、回綠發解除，冷卻 60 分鐘
  - 共用 mobile-oss bot，config 只存 .env 路徑，token 不進 repo
  - 實測發送成功（message_id=8）
- 已知限制：採集器本身掛掉就發不了警報（dead man's switch 需外部服務，未做）

## 0.6.0 - 2026-08-13

- 中樞調控上線（Stan 核可：槽數 1、黃軟/橘紅硬擋）
  - sentinel-gate.py：PreToolUse 攔重活申請槽位、PostToolUse 釋放；
    紅燈全擋、橘燈擋新重活、槽被佔排隊；TTL 15 分鐘＋死進程自動釋放
  - OS 優先權降級：橘/紅燈全 agent 樹降 BelowNormal、綠燈自癒式恢復
    （不依賴名單，任何 BelowNormal 的 agent 進程綠燈一律升回）
  - status.md/json 新增 Arbiter 區塊（槽位持有者、降級進程數）
- 驗證：gate 五路徑（放行/紅擋/橘擋/佔槽擋/釋放）、紅燈實降 201 進程、
  綠燈實測恢復 Normal

## 0.5.0 - 2026-08-13

- 四層燈號 GREEN/YELLOW/ORANGE/RED（Stan 需求：RAM/CPU 百分比、磁碟絕對 GB）
  - RAM 75/85/92%、CPU 5分均 60/75/88%、C槽剩 50/35/20 GB，舊 config 自動遷移
- hook/儀表板/Codex AGENTS.md/Cursor 貼文同步四層
- 推上 GitHub public：https://github.com/stantheman0128/resource-sentinel

## 0.4.0 - 2026-08-13

- Claude Code hook `sentinel-inject.py`（spec 第 3 步）：每輪注入一行狀態、黃/紅燈升級警告、
  監控失效偵測、session pid+cwd 登記（沿祖先鏈找 agent 進程，修 shell 隔層問題）
- 歷史帳本（spec 第 4 步）：session→repo 歸因、per-repo 峰值 RAM 統計（最近 20 筆＋中位數）、
  修 treeOf uint32/int32 型別 bug
- Codex 全域 AGENTS.md 接入＋Cursor 貼規則說明（spec 第 5 步，docs/agent-integration.md）
- README、儀表板樹標籤加 repo 名

## 0.3.0 - 2026-08-13

- 靜態儀表板 dashboard.html（spec 第 2 步收尾＋Stan 新需求）
  - 燈號、CPU/RAM/GPU/磁碟卡片、近 3 小時趨勢圖、agent 用量表、寫入排行、異動事件表
  - 零常駐：採集器每輪輸出 data.js，頁面 60 秒自動刷新；瀏覽器直接開 `~\.resource-sentinel\dashboard.html`
- Task Scheduler 排程 `ResourceSentinel` 每分鐘執行（conhost --headless 無窗模式，不用 VBS）
- 驗證：排程自主執行 Last Result=0、儀表板全區塊渲染實測通過

## 0.2.0 - 2026-08-13

- GPU 量測（nvidia-smi 主、效能計數器備援）
- 磁碟寫入歸因：跨輪差分 WriteTransferCount，agent 樹標記
- events.log：磁碟單輪變動 ≥2 GB 記錄事件＋寫入排行快照（2 MB 上限自動修剪）
- 實測首捕：SearchIndexer 單輪寫入 14.2 GB

## 0.1.0 - 2026-08-12

- collect.ps1 採集器核心（spec 第 1 步）
  - 全機 CPU（效能計數器，含 Get-Counter 失敗時的進程差分 fallback）、RAM、各磁碟
  - agent 進程樹偵測與彙總（claude/cursor/codex 為根，BFS 含循環防護）
  - 綠/黃/紅燈號判定（閾值在 config.json 可調）
  - status.md + status.json 原子寫入（temp + rename）
  - samples.csv 追加與 5 分鐘 CPU 均值；行數上限防爆
  - 驗證：同時點 RAM 對照誤差 0.2pp、5 分鐘均值手算相符、連跑三次覆寫正常
