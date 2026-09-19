"""Bounded, non-executing bootstrap classification of shell command structure.

Unknown syntax and executable wrappers require admission.  Data arguments never
become commands merely because they mention a build tool.  This is a conservative
resource estimate, not a shell interpreter or a security sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from pathlib import Path
from typing import Iterable

_LEVELS = {"LIGHT": 0, "MEDIUM": 1, "HEAVY": 2, "EXTREME": 3}
_MAX_COMMAND = 16_384
_MAX_TOKENS = 512
_MAX_DEPTH = 8
_MAX_PATTERNS = 64
_MAX_PATTERN = 256
_SEPARATORS = {"&&", "||", ";", "|", "&", "\n"}
_LIGHT_COMMANDS = {
    "ls", "dir", "pwd", "cd", "chdir", "cat", "type", "head", "tail",
    "grep", "rg", "findstr", "select-string", "get-content", "get-childitem",
    "get-location", "set-location", "echo", "printf", "write-output", "true",
    "false", "test", "[", "wc", "stat", "file", "which", "where", "whereis",
    "whoami", "hostname", "date", "uname", "readlink", "realpath", "basename",
    "dirname", "du", "df", "sort", "uniq", "cut", "tr", "diff", "cmp", "od",
    "hexdump", "md5sum", "sha1sum", "sha256sum", "sha512sum", "get-filehash",
    "mkdir", "rmdir", "touch", "git-status",
}
_GIT_LIGHT = {
    "status", "show", "diff", "log", "add", "ls-files", "ls-tree", "rev-parse",
    "rev-list", "cat-file", "check-ignore", "check-attr", "describe", "name-rev",
    "merge-base", "for-each-ref", "show-ref", "reflog", "blame", "annotate",
    "shortlog", "remote", "config", "branch", "tag", "help", "version", "grep",
}
_BUILDERS = {"make", "cmake", "msbuild", "ninja", "gradle", "gradlew", "mvn", "tsc"}
_PACKAGE_MANAGERS = {"npm", "pnpm", "yarn", "bun"}
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


class _Unknown(ValueError):
    pass


@dataclass(frozen=True)
class _Token:
    text: str
    quoted: bool = False
    dynamic: bool = False
    raw: str = ""


def _name(value: str) -> str:
    name = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


def _lex(command: str, shell: str = "posix") -> list[_Token]:
    if shell not in {"posix", "cmd"}:
        raise _Unknown("unsupported shell dialect")
    if len(command) > _MAX_COMMAND or "\x00" in command:
        raise _Unknown("command size or encoding")
    result: list[_Token] = []
    word: list[str] = []
    quote = ""
    quoted = dynamic = started = False
    index = 0
    token_start = 0

    def flush() -> None:
        nonlocal word, quoted, dynamic, started
        if started:
            result.append(_Token("".join(word), quoted, dynamic, command[token_start:index]))
        word, quoted, dynamic, started = [], False, False, False
        if len(result) > _MAX_TOKENS:
            raise _Unknown("token budget")

    while index < len(command):
        if not started:
            token_start = index
        char = command[index]
        if quote == "'":
            if char == "'":
                quote = ""
            else:
                word.append(char)
            index += 1
            continue
        if (char == '"' or (shell == "posix" and char == "'")) and (not quote or char == quote):
            quote = "" if quote else char
            quoted = started = True
            index += 1
            continue
        if char in "$`" or (not quote and char in "(){}"):
            dynamic = True
        # Caret/backtick escaping and redirection differ across shells.  Do not
        # guess whether either has hidden another executable or command boundary.
        if char == "^" or char in "<>" or (shell == "cmd" and char in "%!"):
            dynamic = True
        if shell == "posix" and char == "\\" and index + 1 < len(command):
            following = command[index + 1]
            if following in "\"'" or following.isspace():
                word.append(following)
                started = True
                index += 2
                continue
            if following in ";&|$`(){}":
                dynamic = True
        if not quote and (char.isspace() or char in ";&|"):
            flush()
            if char in ";&|" or char == "\n":
                separator = char
                if char in "&|" and index + 1 < len(command) and command[index + 1] == char:
                    separator += char
                    index += 1
                result.append(_Token(separator))
            index += 1
            continue
        # Do not discard # comments: this classifier also receives raw cmd.exe
        # commands, where # is ordinary text and a later & still executes.
        word.append(char)
        started = True
        index += 1
    if quote:
        raise _Unknown("unclosed quote")
    flush()
    return result


def _patterns(patterns: Iterable[str] | None) -> list[re.Pattern[str]]:
    if patterns is None:
        return []
    if not isinstance(patterns, (list, tuple)) or len(patterns) > _MAX_PATTERNS:
        raise _Unknown("invalid heavy_patterns")
    compiled = []
    for pattern in patterns:
        if not isinstance(pattern, str) or len(pattern) > _MAX_PATTERN:
            raise _Unknown("invalid heavy pattern")
        # Restrict regex repetition to whitespace.  Nested/backtracking repeat
        # expressions must not hang a hook, even with locally edited config.
        bounded = re.sub(r"\\s[+*?]", " ", pattern)
        if any(char in bounded for char in "*+{?") or re.search(r"\\[1-9]|\(\?", bounded):
            raise _Unknown("unsupported heavy pattern complexity")
        compiled.append(re.compile(pattern, re.IGNORECASE))
    return compiled


def _higher(left: str, right: str) -> str:
    return max((left, right), key=_LEVELS.__getitem__)


def _configured(level: str, patterns: list[re.Pattern[str]], *semantic: str) -> str:
    # Only canonical executable/action signatures reach custom patterns, never
    # file paths, quoted descriptions, source text or arbitrary tool arguments.
    if any(pattern.search(subject) for pattern in patterns for subject in semantic if len(subject) <= 128):
        return _higher(level, "HEAVY")
    return level


def _classify(command: str, patterns: list[re.Pattern[str]], depth: int, shell: str = "posix") -> str:
    if depth > _MAX_DEPTH:
        raise _Unknown("wrapper depth")
    tokens = _lex(command, shell=shell)
    result = "LIGHT"
    segment: list[_Token] = []
    for token in tokens + [_Token(";")]:
        if not token.quoted and token.text in _SEPARATORS:
            if token.text == "&" and not segment:
                # PowerShell's direct call operator.  The target still has to
                # be a static executable; no arbitrary expression evaluation.
                continue
            if segment:
                result = _higher(result, _invocation(segment, patterns, depth, shell=shell))
                segment = []
        else:
            segment.append(token)
    return result


def _same_repo_script(value: str, filename: str) -> bool:
    try:
        candidate = Path(value)
        return candidate.is_absolute() and candidate.resolve() == (Path(__file__).resolve().parents[1] / "scripts" / filename).resolve()
    except (OSError, ValueError):
        return False


def _trusted_queue_cli(tokens: list[_Token]) -> bool:
    # Cancellation and waiting must stay available when admission is denied.
    # A same-named script elsewhere is not a bypass, and chain segments still
    # undergo normal classification.  The trusted CLI validates ownership.
    return bool(len(tokens) >= 2
                and _same_repo_script(tokens[0].text, "sentinelctl.py")
                and tokens[1].text in {"cancel", "wait-existing"})


def _trusted_waiter(tokens: list[_Token]) -> bool:
    index = 0
    while index < len(tokens):
        option = tokens[index].text.lower()
        if option == "-file":
            return index + 1 < len(tokens) and _same_repo_script(tokens[index + 1].text, "wait-slot.ps1")
        if option == "-executionpolicy":
            if index + 1 >= len(tokens) or tokens[index + 1].text.lower() != "bypass":
                return False
            index += 2
        elif option in {"-noprofile", "-noninteractive", "-nologo"}:
            index += 1
        else:
            return False
    return False


def _skip_options(arguments: list[str], value_options: set[str], flags: set[str]) -> list[str]:
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        option = arguments[index]
        name = option.split("=", 1)[0]
        if name in value_options:
            index += 1 if "=" in option else 2
        elif option in flags:
            index += 1
        else:
            return []
    return arguments[index:]


def _static_extreme(tokens: list[_Token]) -> bool:
    """Static executable/action evidence is a floor even with dynamic data."""
    if not tokens or tokens[0].dynamic:
        return False
    executable = _name(tokens[0].text)
    args = [token.text.lower() for token in tokens[1:]]
    if executable == "playwright":
        return any(arg in {"--project", "--workers"} or arg.startswith(("--project=", "--workers=")) for arg in args)
    if executable == "cargo":
        if args and args[0].startswith("+"):
            args = args[1:]
        args = _skip_options(args, {"--color", "--config"}, {"-v", "-vv", "--verbose", "-q", "--quiet", "--locked", "--offline", "--frozen"})
        return bool(args and args[0] == "build" and "--release" in args)
    if executable == "docker":
        args = _skip_options(args, {"--context", "-c", "--host", "-h", "--config", "--log-level", "-l"}, {"--debug", "-d", "--tls", "--tlsverify"})
        if not args or args[0] != "compose":
            return False
        args = _skip_options(args[1:], {"--project-name", "-p", "--file", "-f", "--project-directory", "--env-file", "--profile", "--parallel", "--ansi", "--progress"}, {"--dry-run", "--verbose", "--compatibility", "--all-resources"})
        return bool(args and args[0] == "up")
    return False


def _invocation(tokens: list[_Token], patterns: list[re.Pattern[str]], depth: int, shell: str = "posix") -> str:
    if depth > _MAX_DEPTH:
        raise _Unknown("wrapper depth")
    while tokens and _ASSIGNMENT.match(tokens[0].text):
        tokens = tokens[1:]
    if not tokens:
        return "LIGHT"
    extreme_floor = _static_extreme(tokens)
    if any(token.dynamic for token in tokens):
        return "EXTREME" if extreme_floor else "HEAVY"
    executable = _name(tokens[0].text)
    arguments = [token.text for token in tokens[1:]]
    lower = [arg.lower() for arg in arguments]
    if executable in _SHELLS:
        for index, arg in enumerate(lower):
            if arg in {"-c", "-lc", "-cl"}:
                if index + 1 >= len(arguments):
                    return "HEAVY"
                return _configured(_classify(arguments[index + 1], patterns, depth + 1), patterns, executable)
            if arg not in {"--noprofile", "--norc", "-l"}:
                return "HEAVY"
        return "HEAVY"
    if executable == "cmd":
        for index, arg in enumerate(lower):
            if arg in {"/c", "/k"}:
                payload = tokens[index + 2:]
                if not payload:
                    return "HEAVY"
                if len(payload) == 1 and payload[0].quoted:
                    # Outer /c quote pair carries the command string.  Inner
                    # single quotes are literal CMD text, not POSIX protection.
                    body = payload[0].text
                else:
                    # Preserve argument quote spelling until the CMD lexer has
                    # seen it; joining decoded text can erase command boundaries.
                    body = " ".join(token.raw or token.text for token in payload)
                level = _classify(body, patterns, depth + 1, shell="cmd")
                return _configured(level, patterns, executable)
            if arg not in {"/d", "/s", "/q", "/a", "/u", "/e:on", "/e:off", "/v:off"}:
                return "HEAVY"
        return "HEAVY"
    if executable in {"powershell", "pwsh"}:
        if _trusted_waiter(tokens[1:]):
            return _configured("LIGHT", patterns, executable, "wait-slot")
        for index, arg in enumerate(lower):
            if arg in {"-command", "-c"}:
                payload = tokens[index + 2:]
                if len(payload) == 1:
                    return _configured(_classify(payload[0].text, patterns, depth + 1), patterns, executable)
                return "HEAVY"
            if arg in {"-executionpolicy", "-ep"}:
                return "HEAVY"  # Policy/script/encoded forms are not parsed here.
            if arg not in {"-noprofile", "-nop", "-noninteractive", "-noni", "-nologo"}:
                return "HEAVY"
        return "HEAVY"
    if executable in {"env", "command", "exec", "nohup"}:
        rest = tokens[1:]
        if rest and rest[0].text == "--":
            rest = rest[1:]
        if not rest or rest[0].text.startswith("-"):
            return "HEAVY"
        return _configured(_invocation(rest, patterns, depth + 1, shell=shell), patterns, executable)
    if executable in {"python", "python3", "pythonw", "py", "python3.13"}:
        if _trusted_queue_cli(tokens[1:]):
            return _configured("LIGHT", patterns, executable, "sentinelctl cancel-or-wait-existing")
        for index, arg in enumerate(lower):
            if arg == "-m" and index + 1 < len(arguments):
                module = lower[index + 1]
                if module in {"pytest", "pip", "unittest", "build"}:
                    return _configured(
                        _invocation([_Token(module)] + tokens[index + 3:], patterns, depth + 1, shell=shell),
                        patterns, f"{executable} -m {module}",
                    )
                return "HEAVY"
            if arg not in {"-i", "-b", "-e", "-s", "-u", "-3", "-3.13", "-x", "utf8"}:
                return "HEAVY"
        return "HEAVY"
    if executable == "git":
        index = 0
        while index < len(lower):
            arg = lower[index]
            if arguments[index] != "-C" and (arg in {"-c", "--config-env", "--exec-path"} or arg.startswith(("-c", "--config-env=", "--exec-path="))):
                return "HEAVY"
            if arguments[index] == "-C":
                index += 2
            elif arg in {"--git-dir", "--work-tree", "--namespace"}:
                index += 2
            elif arg.startswith(("--git-dir=", "--work-tree=", "--namespace=")) or arg in {"--no-pager", "--paginate", "--literal-pathspecs", "--no-optional-locks"}:
                index += 1
            else:
                break
        verb = lower[index] if index < len(lower) else ""
        level = "LIGHT" if verb in _GIT_LIGHT or verb in {"--version", "--help"} else "HEAVY"
        option_arguments = arguments[index + 1:]
        if "--" in option_arguments:
            option_arguments = option_arguments[:option_arguments.index("--")]
        if verb == "grep" and any(
            arg == "-O" or arg.startswith("-O")
            or arg == "--open-files-in-pager" or arg.startswith("--open-files-in-pager=")
            for arg in option_arguments
        ):
            level = "HEAVY"
        # Explicit exec-capable options (external diff/textconv) need admission.
        if any(arg in {"--ext-diff", "--textconv"} for arg in lower):
            level = "HEAVY"
        return _configured(level, patterns, "git", f"git {verb}")
    if executable in _BUILDERS:
        return _configured("HEAVY", patterns, executable)
    if executable in _PACKAGE_MANAGERS:
        verb = lower[0] if lower else ""
        if verb in {"exec", "dlx"}:
            rest = tokens[2:]
            if rest and rest[0].text == "--":
                rest = rest[1:]
            return _higher("HEAVY", _invocation(rest, patterns, depth + 1, shell=shell)) if rest else "HEAVY"
        action = lower[1] if verb == "run" and len(lower) > 1 else verb
        if action in {"lint", "typecheck"}:
            level = "MEDIUM"
        elif verb in {"--version", "-v", "--help", "help", "list", "ls", "outdated", "view", "info"}:
            level = "LIGHT"
        else:
            level = "HEAVY"
        signature = f"{executable} run {action}" if verb == "run" else f"{executable} {verb}"
        return _configured(level, patterns, executable, signature)
    if executable in {"cargo", "go", "dotnet"}:
        verb = lower[0] if lower else ""
        level = "EXTREME" if extreme_floor else "HEAVY"
        if verb in {"version", "--version", "--info", "--help", "help"}:
            level = "LIGHT"
        return _configured(level, patterns, executable, f"{executable} {verb}")
    if executable == "docker":
        level = "EXTREME" if extreme_floor else "HEAVY"
        if lower and lower[0] in {"version", "--version", "ps", "images", "inspect", "logs", "info"}:
            level = "LIGHT"
        signature = "docker " + " ".join(lower[:2] if lower[:1] == ["compose"] else lower[:1])
        return _configured(level, patterns, "docker", signature)
    if executable == "pytest":
        selected = any("::" in arg for arg in arguments) or any(arg == "-k" or arg.startswith("-k=") for arg in arguments)
        return _configured("MEDIUM" if selected else "HEAVY", patterns, "pytest")
    if executable == "playwright":
        level = "EXTREME" if any(arg in {"--project", "--workers"} or arg.startswith(("--project=", "--workers=")) for arg in lower) else "HEAVY"
        return _configured(level, patterns, "playwright")
    if executable in {"jest", "vitest", "webpack", "vite", "next", "nuxt", "tsup", "esbuild", "pip", "pip3", "unittest", "build"}:
        return _configured("HEAVY", patterns, executable)
    if executable in {"npx", "pnpx"}:
        rest = tokens[1:]
        while rest and rest[0].text in {"--yes", "-y", "--no-install", "--"}:
            rest = rest[1:]
        if not rest or rest[0].text.startswith("-"):
            return "HEAVY"
        return _higher("HEAVY", _invocation(rest, patterns, depth + 1, shell=shell))
    if executable == "find":
        level = "HEAVY" if any(arg.startswith(("-exec", "-ok")) for arg in lower) else "LIGHT"
        return _configured(level, patterns, "find")
    if executable == "rg" and any(arg == "--pre" or arg.startswith("--pre=") for arg in lower):
        return "HEAVY"
    if executable == "sort" and any(arg == "--compress-program" or arg.startswith("--compress-program=") for arg in lower):
        return "HEAVY"
    if executable in _LIGHT_COMMANDS:
        return _configured("LIGHT", patterns, executable)
    return _configured("HEAVY", patterns, executable)


def classify_command(command: str, heavy_patterns: Iterable[str] | None = None, *, shell: str = "posix") -> str:
    """Estimate the highest resource class of statically identifiable commands.

    Invalid/unsupported shell syntax, dynamic execution, unknown executables and
    invalid custom patterns conservatively require HEAVY admission.  Configured
    patterns apply to executable/action signatures, never arbitrary argument text.
    Bash hooks use the default POSIX dialect.  Callers executing raw cmd.exe
    command strings must pass shell="cmd" so single quotes cannot hide execution.
    """
    if not isinstance(command, str):
        return "HEAVY"
    try:
        builtin = _classify(command, [], 0, shell=shell)
    except (ValueError, TypeError, RecursionError, re.error):
        builtin = "HEAVY"
    try:
        return _higher(builtin, _classify(command, _patterns(heavy_patterns), 0, shell=shell))
    except (ValueError, TypeError, RecursionError, re.error):
        return _higher(builtin, "HEAVY")


def is_single_static_command(command: str) -> bool:
    """Permit a trusted wrapper bypass only for one static outer invocation.

    The wrapper's quoted command is opaque here: it performs its own admission.
    Shell substitution or an outer chain must be classified normally instead.
    """
    if not isinstance(command, str):
        return False
    try:
        tokens = _lex(command)
        if tokens and tokens[0].text == "&" and not tokens[0].quoted:
            tokens = tokens[1:]
        return bool(tokens) and all(
            not token.dynamic and (token.quoted or token.text not in _SEPARATORS)
            for token in tokens
        )
    except (ValueError, TypeError, RecursionError):
        return False
