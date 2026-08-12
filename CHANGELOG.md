# Changelog

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
