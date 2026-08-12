# 各 agent 接入方式

告示板路徑固定：`C:\Users\stans\.resource-sentinel\status.md`（機器可讀版 `status.json`）。
任何能讀本機檔案的 agent 都能接入，不需要 MCP 或任何協定。

## Claude Code / Claude Desktop（已接，全自動）

`~/.claude/settings.json` 的 UserPromptSubmit 掛了 `sentinel-inject.py`：

- 每輪對話自動注入一行狀態（燈號、RAM、CPU、GPU、C 槽、本 repo 歷史峰值）
- 黃燈追加降速建議、紅燈追加強制警告
- 同時把 session 的 agent 進程 pid 與 cwd 登記到 `sessions.json`，
  採集器據此把進程樹歸因到 repo（歷史帳本的資料來源）
- 新開的 session 才會生效（hook 設定變更不影響已開的 session）

## Codex CLI（已接，半自動）

全域 `C:\Users\stans\.codex\AGENTS.md` 已加入 Resource awareness 段落：
重量級指令前先讀 status.md，照燈號行動。

## Cursor（需要手動貼一次）

Cursor 的全域規則存在它自己的設定裡，沒有可靠的檔案路徑可以直接寫入。
打開 Cursor：Settings、Rules for AI，貼上下面這段：

```
Before running anything heavy (builds, installs, full test suites), read
C:\Users\stans\.resource-sentinel\status.md. GREEN: proceed. YELLOW: run heavy
commands with low priority and avoid parallel heavy work. ORANGE: defer new
heavy tasks; if one must run, low priority and one at a time. RED: light
operations only; tell the user the machine is overloaded. If the file is older
than 5 minutes, monitoring is down; say so and ignore its contents.
```

貼完之後 Cursor 的 session 就會在動手前自己去看告示板。

## 之後新裝的任何本機 agent

只要它支援 system prompt、rules 檔或 AGENTS.md，把上面 Cursor 那段貼進去就接入了。
系統本身不用改任何東西。
