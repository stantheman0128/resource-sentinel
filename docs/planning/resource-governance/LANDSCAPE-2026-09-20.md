# 同題與相鄰工具研究：本機 Agent 工作負載治理

日期：2026-09-20（Asia/Taipei）  
由 GPT-6 Astra Pro 協助整理。  
研究範圍與 P3–P6 現況：[入口](README.md)。後續設計：[Learning and decision design](LEARNING-AND-DECISION-DESIGN.md)。

本文是文件／程式層的研究，不是安裝推薦清單、完整競品普查、效能排行榜或安全審計。沒有安裝或 benchmark 下列工具。列出相同功能，不代表它們在所有 OS、版本與 agent 上都能使用；採用前應核對 license、維護狀態、權限與自身環境。README 宣稱不等於 production 採用或商業需求證據。

## 1. 先分清問題，不把所有 agent framework 算成競品

Resource Sentinel 的主要問題：多個互不相識的 coding agents，在同一台有人操作的電腦啟動 build、test、browser、dependency install 等工作，合計負載造成前景延遲、記憶體與 I/O 爭用。希望以共享計帳、准入、優先權與可靠等待／續跑處理，而不是所有工作一律終止。

比較時分開看：

| 類型 | 主要回答的問題 | 與 Sentinel 的關係 |
|---|---|---|
| 本機 Agent-aware governor | 哪個受管工作現在可以開工、資源與子程序屬於誰？ | 最直接對照 |
| Agent-aware monitoring／cleanup | 哪個 session 漏記憶體、留下殘留、快取變大？ | 相同使用者痛點，但不必然有自動排隊與准入 |
| 通用 OS 程序治理 | 哪些程序應降低 CPU 優先序或受到配額限制？ | 強替代方案／底層元件 |
| Shell／batch queue | 哪些命令先執行、同時最多幾個？ | 必须比較的低複雜度 baseline |
| OS／container 隔離 | 怎麼把一組程序計帳、限制、隔離？ | 應利用的執行基礎，不必重新發明 |
| Server／cluster scheduler | 哪台機器執行哪個 job、租戶配額與公平性如何分配？ | 成熟相鄰市場，不代表需要新的通用 scheduler |
| Agent sandbox／workspace manager | 如何隔離執行環境、保存 workspace、恢復或清理？ | 可整合的 execution substrate，不等於保護本機前景體驗 |
| OOM／異常程序 recovery | 已出現壓力時應終止誰？ | 解決相近事故，但不符合 Sentinel 不任意殺工作的政策 |

同樣叫 resource 或 memory，不代表指實體 CPU/RAM：有些工具處理的是 context window、API token、模型 rate limit 或 agent 信任權限。這些可與硬體治理整合，但不能混成相同競品。

## 2. 直接或高度相關的本機工具

### Gatehold — 最值得逐項比較的直接同題專案

來源：[repo](https://github.com/pakales/gatehold)、[Product Contract](https://github.com/pakales/gatehold/blob/main/docs/PRODUCT-CONTRACT.md)。

文件描述的核心正是多個 coding agents 同時執行重型工作時的 host-capacity admission、FIFO 等待、lease/heartbeat、ownership 與 verified cleanup。主要支援 macOS，Linux 屬 best-effort。它明確定位為合作式 governor，而不是能約束任意未納管程序的安全沙箱。

工程判斷：這不是只和 Sentinel 名稱相近，而是問題、准入方式與生命週期都重疊。可借鑑「只管理自己能證明擁有的工作」「清理未知就不虛報釋放」的契約；不必照抄其 OS 實作。不能從專案存在、展示或測試數量推論大量付費用戶。

建議比較項目：跨入口原子准入、無 caller 時的 durable waiting、root exit/child survivor、lost ACK、cleanup unknown、前景 responsiveness、安裝成本與真實工具覆蓋。

### Agentinel — Agent 資源診斷與人核准清理

來源：[0x0funky/Agentinel](https://github.com/0x0funky/Agentinel)。注意與其他同名 security 工具不同。

README 描述 Windows/macOS 的本機 Agent 資源觀測、project/process tree 歸因、RAM/CPU/disk、leak/zombie/runaway cache 檢查與 AI 輔助清理建議，操作由使用者核准。所讀材料沒有把共享原子 reservation 與自動資源准入作為核心契約。

工程判斷：它和 Sentinel 爭取同一類使用者，但功能重心不同。「會認出 Claude/Codex/MCP」「有 Agent dashboard」不應單獨當差異化；Sentinel 更應證明等待／續跑與准入的增量價值。

### Process Lasso — 必須擊敗的通用 Windows 替代方案

來源：[官方產品頁](https://bitsum.com/)、[ProBalance 機制](https://bitsum.com/how-probalance-works/)。

ProBalance 透過動態優先序調整改善高 CPU 負載下的反應速度；產品另有 CPU limiter、CPU sets、instance balancing 等能力。這是程序治理，不是理解任務語意、持久化 Agent tool call 或保證恢復特定 session 的系統。

工程判斷：使用者在意的是卡不卡，不一定在意工具懂不懂 Agent。若固定並行數加 Process Lasso 已經足夠，Sentinel 必須以可重現結果證明额外價值。不能只因缺乏 AI 標籤就排除它。

### Process Governor — Windows Job Objects 執行元件參考

來源：[lowleveldesign/process-governor](https://github.com/lowleveldesign/process-governor)。

透過 Windows Job Objects 管理程序／群組的 CPU rate、affinity、committed memory、時間等限制。它提供執行限制能力，不等於已實作跨 provider 的 workload history、准入政策與 session continuation。

工程判斷：適合研究 native API 封裝與 launcher 行為，但記憶體 hard limit、時間限制或終止語意不可直接搬入 Sentinel。既有 plan 的禁止事項與恢复 gate 優先。

## 3. Queue 與 recovery：簡單但強的替代基線

| 專案 | 已查資料所描述的能力 | 不應混淆的界線／借鑑 |
|---|---|---|
| [Pueue](https://github.com/Nukesor/pueue) | 跨平台 shell task queue；分組、並行數、依賴、pause/resume、logs 與 queue 管理 | 「只允許少量重命令」可能已很有效；不等於依 Windows physical/Commit 預測動態准入，也不自動恢復任意 Agent 對話 |
| [GNU Parallel manual](https://manpages.debian.org/testing/parallel/parallel.1.en.html) | Shell job 並行；`--jobs`、load、memory、custom limit 等條件 | 此為 GNU 工具原始 manpage 的 Debian 發布副本；GNU 官網本輪抓取失敗。`--memfree` 的部分情況會終止較新工作並重排，不能當成無損 on-hold |
| [earlyoom](https://github.com/rfjakob/earlyoom) | Linux 上觀察 available memory/swap，提早終止程序以避免長時間不可操作 | 目標相近，手段接受犧牲工作；不應直接納入 Sentinel no-kill 控制路徑 |
| [claude-cpu-guard](https://github.com/yemreak/claude-cpu-guard) | README 描述 macOS Claude Code hook：已 stopped 卻持續高 CPU 時終止程序，提供 resume 指令 | 單一 provider 的異常修復，不是正常多 Agent 資源公平分配；作者對 TUI 原因的說法未在本輪獨立驗證 |
| [agent-resource-scheduler](https://github.com/Retsumdk/agent-resource-scheduler) | CPU/RAM/GPU/API token 資源池、priority/cost/latency 的 TypeScript 範例 | 已讀 [Scheduler.ts](https://github.com/Retsumdk/agent-resource-scheduler/blob/main/src/Scheduler.ts) 以 `setTimeout` 模擬完成；不能當成真實 OS 資源執行／隔離產品的證據 |

歷次搜尋也遇到 workspace／port／simulator pool 類工具，例如 `HN05/shoal`；本輪未能重新取得其頁面，因此只保留為後續查核候選，不在比較表宣稱現有平台支援或已驗證能力。

## 4. 商業伺服器早已有的機制

以下都與「有限資源中安排多個工作」相關，但層次不同，不是安裝任一項就會自動接管桌面上的全部 Agent。

| 工具／機制 | 已有能力與邊界 | 可借鑑的部分 |
|---|---|---|
| [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) | 群組程序計帳與控制；繼承、巢狀、外部 Job／brokered process 有具體限制 | 精確 ownership、launch、child lifetime、native restore；遵守原 P1/P3/P5 gates |
| [Linux cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) | 階層化的 CPU/memory/I/O 等控制器 | 若另做 Linux backend，利用 OS controller，不能把 Windows 行為直接套過去 |
| [systemd resource control](https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml) | 以 service/scope/slice 組織群組並設定資源控制，底層使用 cgroups | 不必另造 Linux process-group 管理模型；需要核對實際 delegation/權限 |
| [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/) | container CPU/memory 等設定；需要明確配置限制 | 容器化是執行邊界，不是整台 host 動態准入或 foreground policy 的替代 |
| [Kubernetes requests/limits](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) | requests 參與配置，limits 透過 runtime/OS 控制；CPU、memory 行為不同 | 明確分離需求宣告、placement、執行控制；不把 memory limit 當可平滑回收的權重 |
| [Kueue](https://kueue.sigs.k8s.io/docs/overview/) | Job admission、quota、queue、公平性與多 cluster 等能力 | 特別值得研究「先取得配額才執行」；不重寫 Kubernetes 已有層次 |
| [Nomad](https://developer.hashicorp.com/nomad/docs/job-specification/resources) | task CPU/memory/device 需求與資源配置 | 通用工作負載管理；不是任意 GUI session 自動接入 |
| [Slurm](https://slurm.schedmd.com/overview.html) | Cluster 資源分配、queue、工作執行與管理 | 批次工作、配額與 priority 的成熟設計；不是低安裝成本的桌機 Agent plugin |
| [Ray resource contract](https://github.com/ray-project/ray/blob/master/doc/source/ray-core/scheduling/resources.rst) | task/actor logical resources 控制調度與併行 | **logical CPU/RAM request 不是實體用量上限**；需包裝工作，不能假設自動隔離外部程序 |
| [Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) | Kubernetes 上 Agent sandbox 生命周期、持久化／身分、templates/claims/warm pools | 可成為遠端受管 execution 基礎；不是 Windows 前景流暢度 governor |

工程結論：商業系統需要資源治理，並不等於需要購買新的 Resource Sentinel。未來企業方向更合理的假設，是接在既有 execution/scheduler 之上的 Agent-aware 接入、預測、政策與 continuation，而不是立即挑戰所有 cluster schedulers。

## 5. 哪些地方值得做，哪些不能當成差異化？

### 比較有意義的組合（產品假設，尚未證明）

保留使用者既有 provider／IDE；以受管命令為單位接入；所有入口共享同一資源帳本；區分 session 與 execution；可靠等待後自動交付結果；用相似工作的歷史改善需求；以真实前景体验與完成效率驗收。

這些能力的組合與易用性可能有價值，但 Gatehold 已涵蓋多個相關契約，所以不能宣稱完全沒有同題專案。Windows 相容性可作早期切入點，不是永久護城河。

### 不足以單獨證明價值的功能

有 Agent 名稱的 dashboard、有更多統計圖、會呼叫 LLM、把 CPU 百分比降下來、設定工作數上限、README 宣稱自適應。真正要證明的是：相同工作與品質條件下，比簡單替代方案更少卡頓、失敗、人工干預或浪費等待。

### 最強反方

固定重工作併行數＋通用 Windows 程序工具，也許已解決多數症狀。若 Sentinel 的 hooks、wrapper、權限、恢復與模型維護更麻煩，增量工程不一定換到增量價值。重度多 Agent 使用者的規模、付費意願、升級硬體或移轉執行的偏好，本次没有足夠資料，不能估市場數字。

支持方向的最強論點：不同工具局部調節，未必能形成全機共用帳本與可靠續跑。如果 Sentinel 能讓使用者保留原習慣又顯著減少干預，這是值得實驗的差異。

## 6. 建議實驗與借鑑順序

原計畫 A0/A1/B 保持不動，以分离 native control 效果與 observer 成本；以下是另外的產品對照，不應合併為單一不受控測試。

| 對照 | 問題 |
|---|---|
| 無額外治理 | 問題在固定工作負載下是否可重現？ |
| 固定重工作並行限制 | 最簡單政策已經解決多少？ |
| 固定並行＋Process Lasso | 現成通用工具組合是否已足夠？ |
| Sentinel 統計預測／共同計帳 | 動態准入的額外收益是什麼？ |
| 相同 Sentinel＋小型 ML | 是否降低低估或不必要等待，而非只改漂亮的模型分數？ |
| 相同系統＋可選 Jev | 語意特徵／軟路由是否在實際成本與延遲後仍有收益？ |

先研究 Gatehold 的 ownership/cleanup 與 Pueue 的等待體驗，再核對 Job Objects 的 native 限制與恢復；把 Process Lasso 納入 benchmark。做 server 擴充時才深入 Kueue／Nomad／Agent Sandbox。不是一次整合全部，也不是自動選用所有工具。

所有效果報告應列：固定 commit、command、workspace、cache、輸入大小、前景模式、工具版本、控制範圍、未受管負載、每組重複結果與故障；不要把「更多等待」誤當「更好的資源效率」。沒有本機數據時，正確狀態是待驗證。
