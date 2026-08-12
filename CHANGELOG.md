# Changelog

## 0.1.0 - 2026-08-12

- collect.ps1 採集器核心（spec 第 1 步）
  - 全機 CPU（效能計數器，含 Get-Counter 失敗時的進程差分 fallback）、RAM、各磁碟
  - agent 進程樹偵測與彙總（claude/cursor/codex 為根，BFS 含循環防護）
  - 綠/黃/紅燈號判定（閾值在 config.json 可調）
  - status.md + status.json 原子寫入（temp + rename）
  - samples.csv 追加與 5 分鐘 CPU 均值；行數上限防爆
  - 驗證：同時點 RAM 對照誤差 0.2pp、5 分鐘均值手算相符、連跑三次覆寫正常
