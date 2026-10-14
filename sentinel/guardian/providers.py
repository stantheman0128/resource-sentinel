"""The agent CLIs Guardian starts and adopts, and the desktop apps it must leave alone.

Four ways in. The first three end in the same job tree (AllAgents > provider > session):
  launch   scripts/gagent.py starts the CLI through srun, so the CLI and every tool command it runs start inside
           the session job.
  shim     a wrapper on PATH (scripts/guardian-install-shims.py) runs scripts/guardian-shim.py, which starts the CLI
           suspended in the same console, has the daemon assign it, then lets it run.
  adopt    a CLI started anywhere else runs hooks/guardian-adopt.py from its own hook (or Stan runs
           `guardctl adopt <pid>`); the daemon then assigns the running CLI and its children to a session job.
           Commands the CLI starts afterwards inherit the job.
  desktop  the CLI a desktop app runs for its agent sessions (Claude Code in the Claude app's Code tab, codex.exe
           under the Codex app) already sits in the app's own job, so it can only join a fresh job, which then nests
           under the app's job. The daemon finds these CLIs (desktop_targets) and puts each in a desktop job of its
           own, outside AllAgents.
A process that already belongs to a job outside Guardian's tree (for example a sandbox job of the CLI itself)
cannot be assigned; the daemon reports that instead of retrying.
"""
import os

# The desktop apps' own processes never go into a job: a cap on them would also slow their UI. Their built-in agents
# (Claude Code inside the Claude app, codex app-server inside the Codex app, language_server.exe inside Antigravity)
# use the same image names as the CLIs or run their own, so launch, shim and adopt refuse anything with a desktop app
# among its parents. The Claude app's and the Codex app's CLIs go into desktop jobs instead (desktop_targets). The
# Claude Code CLI is also claude.exe, so the Claude app is told apart by where Windows installed it.
APP_IMAGES = {"chatgpt.exe": "Codex app", "cursor.exe": "Cursor", "antigravity.exe": "Antigravity app"}
CLAUDE_APP_DIRS = ("\\windowsapps\\claude_", "\\anthropicclaude\\")


def protected_app(image, path):
    """Name of the desktop app this process belongs to, or None."""
    image, path = (image or "").lower(), (path or "").lower()
    if image in APP_IMAGES:
        return APP_IMAGES[image]
    if image == "claude.exe" and any(d in path for d in CLAUDE_APP_DIRS):
        return "Claude app"
    return None


class Provider:
    def __init__(self, name, command, images, path_hint=None):
        self.name = name
        self.command = command          # argv[0] for launching, resolved through PATH (PATHEXT finds .cmd shims)
        self.images = images            # image names of the long-lived CLI process, lowercase
        self.path_hint = path_hint      # substring its full path must contain, for generic images such as node.exe

    def is_cli(self, image, path):
        if (image or "").lower() not in self.images:
            return False
        return self.path_hint is None or self.path_hint in (path or "").lower()


PROVIDERS = {
    "claude": Provider("claude", "claude", {"claude.exe"}),
    "codex": Provider("codex", "codex", {"codex.exe"}),
    # npm installs: gemini.cmd -> node.exe .../@google/gemini-cli/dist/index.js
    "gemini": Provider("gemini", "gemini", {"node.exe"}),
    # cursor-agent.cmd -> powershell -> %LOCALAPPDATA%\cursor-agent\versions\<v>\node.exe index.js
    "cursor": Provider("cursor", "cursor-agent", {"node.exe"}, "\\cursor-agent\\"),
    "grok": Provider("grok", "grok", {"grok.exe"}),
    # Antigravity CLI 1.3.3 and 1.3.4: one Go binary that hosts its language server in the same process, runs hooks through
    # cmd.exe and starts a background updater (another agy.exe) as its own child
    "antigravity": Provider("antigravity", "agy", {"agy.exe"}),
}


def find_cli(provider, start_pid, table, image_path, max_depth=16):
    """Walk up from start_pid (normally the hook process) to the provider's CLI process. Returns (pid, reason).
    The whole parent chain is checked, not only the part below the CLI: a codex.exe under the Codex app is the
    app's agent, not a CLI Stan started."""
    p = PROVIDERS.get(provider)
    if p is None:
        return None, f"unknown provider {provider}"
    found, pid, depth = None, table.get(start_pid, (None,))[0], 0
    seen = {start_pid}
    while pid in table and pid not in seen and depth < max_depth:
        seen.add(pid)
        image, path = table[pid][1], image_path(pid)
        app = protected_app(image, path)
        if app:
            return None, f"the {app} is among the hook's parents"
        if found is None and p.is_cli(image, path):
            found = pid
        pid, depth = table[pid][0], depth + 1
    if found is None:
        return None, f"no {provider} CLI process ({', '.join(sorted(p.images))}) among the hook's parents"
    return found, ""


def app_among(pid, table, image_path, max_depth=16):
    """Name of a desktop app that is pid itself or one of its parents, or None."""
    seen, depth = set(), 0
    while pid in table and pid not in seen and depth <= max_depth:
        seen.add(pid)
        app = protected_app(table[pid][1], image_path(pid))
        if app:
            return app
        pid, depth = table[pid][0], depth + 1
    return None


# The CLIs the desktop apps run for their agent sessions, told apart by where the app installs them: the Claude app
# under %APPDATA%\Claude\claude-code\<version>\<hash>\, the Codex app under %LOCALAPPDATA%\OpenAI\Codex\bin\<hash>\.
# provider -> (image, path part, the app that must be among its parents)
DESKTOP_CLIS = {"claude": ("claude.exe", "\\claude\\claude-code\\", "Claude app"),
                "codex": ("codex.exe", "\\openai\\codex\\bin\\", "Codex app")}


def desktop_targets(table, image_path, max_depth=16):
    """The desktop apps' agent CLIs that belong in desktop jobs, as a list of (pid, provider): an image and install
    path from DESKTOP_CLIS with its own app among its parents. The apps' own processes never count, and a target
    under another target is left out, since it already inherits the outer one's job."""
    paths = {}

    def path(pid):
        if pid not in paths:
            paths[pid] = image_path(pid)
        return paths[pid]

    found = {}
    for pid, (ppid, image) in table.items():
        for provider, (img, part, app) in DESKTOP_CLIS.items():
            if (image or "").lower() == img and part in (path(pid) or "").lower() \
                    and not protected_app(image, path(pid)) and app_among(ppid, table, path, max_depth) == app:
                found[pid] = provider
    out = []
    for pid, provider in found.items():
        up, seen, depth = table[pid][0], {pid}, 0
        while up in table and up not in seen and up not in found and depth < max_depth:
            seen.add(up)
            up, depth = table[up][0], depth + 1
        if up not in found or up == pid:        # a reused parent pid can loop the chain back to pid itself
            out.append((pid, provider))
    return sorted(out)


def default_session(provider):
    """Session name when neither the launcher nor the CLI gives one."""
    return f"{provider}-{os.getpid()}"


# scripts/guardian-install-shims.py writes claude/codex/gemini/cursor-agent/grok/agy wrappers that run
# scripts/guardian-shim.py; every wrapper names that script, which is how it is told apart from the real CLI.
SHIM_MARK = b"guardian-shim"


def is_shim(path):
    """A Guardian wrapper: one of its first three lines is the guardian-shim note (`rem ` in a .cmd, `# ` else)."""
    try:
        with open(path, "rb") as f:
            head = f.read(4096).removeprefix(b"\xef\xbb\xbf").splitlines()[:3]
    except OSError:
        return False
    return any(x.startswith((b"rem " + SHIM_MARK + b":", b"# " + SHIM_MARK + b":")) for x in head)


def real_cli(command, path=None):
    """The CLI itself: the first match on PATH (default: this process's) that is not a Guardian wrapper, so a
    wrapper never ends up calling itself, whatever folder it sits in. Unlike shutil.which, the current folder only
    counts when PATH names it."""
    exts = [""] if os.path.splitext(command)[1] else \
        [x.lower() for x in os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";") if x]
    for d in (os.environ.get("PATH", "") if path is None else path).split(os.pathsep):
        d = os.path.expandvars(d.strip().strip('"'))
        for exe in (os.path.join(d, command + x) for x in exts) if d else ():
            if os.path.isfile(exe) and not is_shim(exe):
                return exe
    return None
