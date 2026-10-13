#!/usr/bin/env python3
"""Guardian demo with a real Claude Code session: the whole CLI runs inside a Guardian session job.

Starts the Guardian daemon (instance onoff, cap up to 80%, optionally on fewer CPUs) if it is not running, then
opens Claude Code in its own console window through srun. The session works as an agent until someone presses Esc:
it runs scripts/guardian-demo-workload.py, logs each result to a file, and every few rounds reads the log back and
writes a summary comparing the rounds with control on and off. Every process the CLI starts lands in the same job,
so the toggle, cap, CPU count, pause and class on the dashboard apply to all of it. Dashboard: http://127.0.0.1:8767/
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import home_dir, ping, run  # noqa: E402

INSTANCE, PORT = "onoff", 8767
WORKLOAD = (ROOT / "scripts" / "guardian-demo-workload.py").as_posix()
DEMO_DIR = Path.home() / ".resource-sentinel" / "demo" / "heavy-loop"
PROMPT = ("這是 Guardian 資源控管的現場 demo。你是一個長時間工作的 agent，{length}"
          "每一輪：\n"
          "1. 用 Bash 執行這個指令，一次一個，不要平行，也不要改動： {cmd}\n"
          "2. 用 Read 讀 {log}，再用 Edit 在最後加一行：「第 N 輪」加上指令印出的那一行。\n"
          "3. 每 5 輪做一次分析：讀 {log}，依每輪的「優先權」分組（正常 = 那輪控管關閉，低於正常 = 控管開啟，"
          "有箭頭的是中途切換，不列入），算出各組的輪數、平均速度（MiB/s）和平均核數，用一個小表格覆寫 {summary}，"
          "再在畫面上用兩三句話說明差異。\n"
          "4. 其他輪在畫面上只回一行：「第 N 輪」加上指令印出的那一行。\n"
          "只碰 {log} 和 {summary} 這兩個檔案，不要讀或改其他檔案，不要載入 skill，不要做其他事。")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rounds", type=int, default=0, help="0 = keep going until someone presses Esc")
    ap.add_argument("--seconds", type=int, default=30, help="length of one workload round")
    ap.add_argument("--cpus", type=int, help="logical CPUs the agents may use (default: all)")
    ap.add_argument("--model", default="sonnet")
    ap.add_argument("--session", default="heavy-loop")
    ap.add_argument("--cls", default="normal", choices=["focus", "normal", "batch"])
    a = ap.parse_args()
    if not ping(INSTANCE):
        log = open(home_dir(INSTANCE).parent / f"{INSTANCE}-daemon.log", "w", encoding="utf-8")
        subprocess.Popen([sys.executable, "-I", str(ROOT / "scripts" / "guardian.py"), "--instance", INSTANCE,
                          "--port", str(PORT), "--initial-cap", "80", "--max-cap", "80"]
                         + (["--world-cpus", str(a.cpus)] if a.cpus else []),
                         stdout=log, stderr=log, creationflags=0x08000000)  # CREATE_NO_WINDOW
        for _ in range(100):
            if ping(INSTANCE):
                break
            time.sleep(0.1)
        else:
            raise SystemExit(f"Guardian did not start; see {log.name}")
    elif a.cpus:
        subprocess.run([sys.executable, "-I", str(ROOT / "scripts" / "guardctl.py"), "--instance", INSTANCE,
                        "world", str(a.cpus)], check=True)
    print(f"dashboard: http://127.0.0.1:{PORT}/", flush=True)
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log, summary = DEMO_DIR / f"log-{stamp}.md", DEMO_DIR / f"summary-{stamp}.md"
    log.write_text(f"# Guardian demo 紀錄 {stamp}（claude/{a.session}）\n\n", encoding="utf-8")
    length = f"共做 {a.rounds} 輪。" if a.rounds else "請一直做下去，不要停下來問我，直到有人按 Esc 中斷。"
    prompt = PROMPT.format(length=length, cmd=f"python -I {WORKLOAD} --seconds {a.seconds}",
                           log=log.as_posix(), summary=summary.as_posix())
    os.chdir(ROOT)  # the session's working directory, already trusted; srun passes it on
    print(f"Claude Code（{a.model}）會在另一個視窗開啟，session = claude/{a.session}，每輪約 {a.seconds} 秒，"
          f"{'共 ' + str(a.rounds) + ' 輪' if a.rounds else '一直跑到按 Esc'}。紀錄：{log}", flush=True)
    files = "~/.resource-sentinel/demo/heavy-loop/**"
    # --allowedTools takes a list, so it goes last: a prompt after it would be read as one more tool name
    code = run(["claude", prompt, "--model", a.model, "--add-dir", str(DEMO_DIR),
                "--allowedTools", f"Bash(python -I {WORKLOAD} *)", f"Read({files})", f"Edit({files})"],
               "claude", a.session, a.cls, 0.5, True, INSTANCE)
    print(f"Claude session 結束（exit {code}）。dashboard 還開著；關掉 Guardian："
          f"python -I scripts/guardctl.py --instance {INSTANCE} shutdown", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
