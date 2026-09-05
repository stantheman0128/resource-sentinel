# 多 agent／多環境任務調度架構

Resource Sentinel 把「誰在思考與操作」和「工作實際在哪裡執行」分開管理。這個區分
很重要：一個 Codex、Claude Code 或 Cursor session 不是一台可合併記憶體的機器；
一個雲端 worker 也不是永久、可任意登入使用的個人電腦。

## 核心物件

| 物件 | 代表什麼 | 不代表什麼 |
|---|---|---|
| agent session | 一個正在工作的 agent 控制端；登記種類、PID、repo、目前任務與 heartbeat | 可供其他任務共享的 RAM 或 CPU |
| task | prompt／command、repo、base SHA、path scopes、資源與信任需求、優先級、相依性及驗證規則 | 已經在某個 provider 執行的 job |
| execution worker | 本機或 provider 提供的一次執行環境；有容量、能力、信任域、quota 狀態與 probe 時效 | 永久 VM，或多台機器的 shared memory |
| adapter | `submit`、`status`、`cancel`、`collect_result` 的 provider 邊界 | 僅因 UI 可操作就自動存在的官方 API |
| workspace claim | 對 repo＋base SHA＋path scopes 的原子編輯權 | Git merge 成功保證 |

agent session 可以提出或追蹤 task；maintainer 為 task 選 execution worker；adapter 才負責
把 task 轉成 provider job。兩者可以綁在一起，但資料模型不把它們混為同一個東西。

## 一次性 reconciliation

```text
agent / CLI
    │ submit task、session heartbeat
    ▼
SQLite（唯一事實來源）
    ├─ task / job / event ledger
    ├─ session registry
    ├─ worker / quota / reservation registry
    └─ workspace claims
    │
    ▼  orchestratorctl tick（短命程序，可由 Task Scheduler 重跑）
dependencies → route → reserve → claim → adapter submit
                                  │
                                  ├─ local：自動執行、poll、收結果
                                  └─ cloud：預設 AWAITING_MANUAL
```

調度器不是常駐 daemon。每次 `tick` 先 reconcile 既有 job，再依 P0–P3 和建立時間處理
有界數量的候選 task；中途重開機或程序終止時，下次 tick 仍能從 SQLite 繼續。reservation
與 claim 都有 heartbeat／TTL，終態會釋放；不能把 TTL 當成取消 provider job 的保證。

## Task lifecycle

主要路徑如下：

```text
QUEUED → ROUTING → WAITING_CAPACITY
                 ↘ RESERVED → SUBMITTED → RUNNING → DONE
                              ↘ AWAITING_MANUAL ─────┘
RUNNING / manual failure → RETRYABLE →（重試）→ FAILED
cloud phase DONE → VERIFYING → local verification child → DONE / FAILED
```

- 相依 task 尚未完成時，task 保持排隊；相依 task 失敗則停止後續工作。
- 取得 worker reservation 後，必須先取得 workspace claim 才能 dispatch，避免兩個
  agent 同時修改相同 repo／base SHA／路徑。
- WORKER 與顯式握手的 SESSION task 都走同一個 maintainer reservation。自動 process
  discovery 只建立不可接任務的 inventory；session lease 過期會把 assignment 轉成
  `RETRYABLE`／`FAILED` 並釋放容量與 claim。
- 本機寫入 task 會安全建立 deterministic Git worktree；既有 path／branch 若不完全匹配
  就 BLOCKED，不會 reset、delete、prune 或 force。remote adapter 則必須實作相同 base contract。
- cloud 結果若設定 verification，會建立 `LOCAL_REQUIRED` 的 P1 子 task；只有本機驗證
  通過，父 task 才是 `DONE`。
- `AWAITING_MANUAL` 表示系統已留下可追蹤紀錄，但還需要人在 provider UI 啟動或確認。
  完成後必須明確回報成功／失敗，不能把「已開頁面」當作 job 已完成。

## 容量、quota 與 failure domain

這三者各自回答不同問題，不能混用：

- `capacity_scope=SHARED_POOL`：多個 job 共用同一台長壽環境。RAM、CPU、disk reservation
  依 `capacity_pool` 加總；本機和目前量測到的 Grok shared cloud computer 屬於此類。
- `capacity_scope=PER_EXECUTION`：provider 每個 job 建立自己的執行環境。每個 task 仍須
  完整 fit 單一 job 的形狀，但不同 job 的 RAM 不相加；同時數由保守的
  `max_concurrency` 限制。
- `quota_domain`：帳號用量或併發配額的邊界；跨不同 capacity pool 的 active jobs 仍合併
  計數，`QUOTA_EXHAUSTED` 時不得 routing。
- `failure_domain`：會一起故障或受同一服務事件影響的範圍，只用於風險描述，不能拿來
  當 capacity pool。

bootstrap 的 `max_concurrency` 是安全起點，不是 provider 合約或購買方案的宣稱；只有
實測或 provider API 能持續觀測時才應提高。

## Adapter 真實性

預設安裝只有 `local` adapter 設為 `adapter_ready=true`、`enabled=true`。Cursor Cloud、
Grok、Claude Web、Codex Cloud、ChatGPT Work 與 GitHub runner 的人工 probe 只證明曾看見
某種環境，不證明我們擁有完整、穩定的 programmatic lifecycle。因此它們預設都是：

```json
{"adapter":"manual","adapter_ready":false,"enabled":false}
```

這些 worker 可保留作容量研究與人工 dispatch 記錄，但不得由「AVAILABLE」推論成可自動
送單。要啟用 provider，需另行配置並驗證 probe、submit、status、cancel、result collection
與 crash recovery；只做到其中一部分時仍不能標成 ready。

## 雲端環境不是永久電腦

provider 執行環境通常是按 task／job 建立的暫時 container 或 runner。檔案、IP、背景程序、
互動登入狀態或磁碟都可能在 job 結束、timeout、quota 用完或 provider 回收時消失。正確用法是：

- 原始碼和輸入從指定 repo／artifact 建立，結果以 patch、commit、log 或 artifact 回收；
- 每個 job 可重建、可重試、可驗證，不依賴上一次 container 的殘留狀態；
- 需要 browser state、local network、硬體或長期資料時，明確要求相應 capability；
- 不在不同 worker 間宣稱共享 RAM，也不把 provider UI 中看見 shell 當成公開漏洞。

## 安全邊界

- task、worker JSON、SQLite、log 與 Git 都不得保存 token、cookie 或密碼。
- adapter 設定只能記錄環境變數名稱；本機 child 使用最小基礎環境，秘密經 `env_refs`
  注入，結果與錯誤訊息不得回顯值。完整繼承 parent environment 必須明確 opt in。
- `trust_domain` 是 routing 的硬條件。私有 repo、個資、內網或既有瀏覽器登入狀態預設只在
  `local-private` 執行，除非 task 明確允許其他信任域。
- workspace claim 防止同範圍併寫，但不能取代 branch protection、code review、測試和 merge
  conflict 檢查。

## 已知 containment 邊界

目前 Windows 本機 runner 會追蹤 root＋descendants 的遙測，timeout/cancel 以 PID＋creation
identity 驗證後執行 tree termination；但尚未使用 Windows Job Object，因此「root 先結束、
刻意脫離的背景 child」與 WSL 內部 Linux process 仍屬 best effort。這套 MVP 適用可信任的
coding/build commands；在執行不可信任程式或宣稱強隔離前，仍需 Job Object kill-on-close、
WSL 專用 telemetry/cancellation，或真正 sandbox/container boundary。
