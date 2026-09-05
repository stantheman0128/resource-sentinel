"""Atomic repository claims and safe, deterministic Git worktrees.

Claims only plan worktrees.  :func:`materialize_worktree` is the explicit,
non-destructive boundary that may run Git: it creates the planned Sentinel
branch/worktree or proves that an existing one is the same workspace.  It never
uses a shell and never deletes, resets, prunes, or force-updates user state.
SQLite ``BEGIN IMMEDIATE`` transactions make overlap checks and lease
acquisition one atomic operation.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import sqlite3
import subprocess
import time
import unicodedata
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable


STATES = {
    "QUEUED",
    "CLAIMED",
    "RUNNING",
    "VERIFYING",
    "DONE",
    "FAILED",
    "RETRYABLE",
    "BLOCKED",
}

# Only these states own an exclusive path lease.  BLOCKED and RETRYABLE retain
# their worktree plan and history but release the scope so a crashed task cannot
# deadlock a repository forever.
LEASE_STATES = {"CLAIMED", "RUNNING", "VERIFYING"}
EXPIRING_STATES = LEASE_STATES | {"QUEUED"}
TERMINAL_STATES = {"DONE", "FAILED"}

ALLOWED_TRANSITIONS = {
    "QUEUED": {"CLAIMED", "RETRYABLE", "BLOCKED", "FAILED"},
    "CLAIMED": {"RUNNING", "QUEUED", "VERIFYING", "DONE", "FAILED", "RETRYABLE", "BLOCKED"},
    "RUNNING": {"VERIFYING", "DONE", "FAILED", "RETRYABLE", "BLOCKED"},
    "VERIFYING": {"RUNNING", "DONE", "FAILED", "RETRYABLE", "BLOCKED"},
    "RETRYABLE": {"QUEUED", "CLAIMED", "FAILED", "BLOCKED"},
    "BLOCKED": {"QUEUED", "CLAIMED", "FAILED", "RETRYABLE"},
    "FAILED": {"RETRYABLE", "QUEUED"},
    "DONE": set(),
}

_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_UNSAFE_SCOPE_RE = re.compile(r"[\x00\r\n*?\[\]]")


class WorktreeMaterializationError(RuntimeError):
    """A safe worktree could not be created without changing existing state."""

    def __init__(self, code: str, message: str, **details: Any):
        super().__init__(message)
        self.code = code
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), **self.details}


def _slug(value: str, fallback: str, limit: int = 32) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", ascii_value).strip(".-_").lower()
    slug = re.sub(r"[-_.]{2,}", "-", slug)
    return (slug or fallback)[:limit].rstrip(".-_") or fallback


def _canonical_repo(repo: str | os.PathLike[str]) -> tuple[str, str]:
    if not str(repo).strip():
        raise ValueError("repo is required")
    path = Path(repo).expanduser().resolve(strict=False)
    display = str(path)
    # normcase makes aliases such as C:\Repo and c:\repo conflict on Windows.
    return os.path.normcase(display), display


def _normalize_sha(base_sha: str) -> str:
    sha = str(base_sha).strip().lower()
    if not _SHA_RE.fullmatch(sha):
        raise ValueError("base_sha must be a 7-64 character hexadecimal Git object id")
    return sha


def normalize_scopes(paths: str | os.PathLike[str] | Iterable[str | os.PathLike[str]]) -> tuple[str, ...]:
    """Return minimal, repository-relative POSIX path scopes.

    Globs and parent traversal are rejected: treating an ambiguous pattern as a
    narrow claim would be less safe than rejecting it.
    """

    if isinstance(paths, (str, os.PathLike)):
        raw_paths = [paths]
    else:
        raw_paths = list(paths)
    if not raw_paths:
        raise ValueError("at least one path scope is required")

    normalized: list[str] = []
    for value in raw_paths:
        raw = str(value).strip().replace("\\", "/")
        if not raw:
            raise ValueError("path scopes cannot be empty")
        if raw.startswith("/") or _DRIVE_RE.match(raw):
            raise ValueError(f"path scope must be repository-relative: {value}")
        if _UNSAFE_SCOPE_RE.search(raw):
            raise ValueError(f"path scope contains an unsafe or ambiguous character: {value}")
        parts = raw.split("/")
        if ".." in parts:
            raise ValueError(f"path scope cannot traverse outside the repository: {value}")
        scope = posixpath.normpath(raw)
        if scope in {"", "."}:
            scope = "."
        if scope == ".." or scope.startswith("../"):
            raise ValueError(f"path scope cannot traverse outside the repository: {value}")
        first = scope.split("/", 1)[0].casefold()
        if first == ".git":
            raise ValueError("the .git administrative directory cannot be claimed")
        normalized.append(scope)

    # Remove duplicate/child scopes.  A claim on ``src`` already owns
    # ``src/api``.  Case-folding is intentionally conservative for the shared
    # Windows checkout while the original spelling remains visible in output.
    result: list[str] = []
    for scope in sorted(set(normalized), key=lambda item: (item.count("/"), len(item), item.casefold())):
        if any(_scope_contains(existing, scope) for existing in result):
            continue
        result.append(scope)
    return tuple(result)


def _scope_contains(parent: str, child: str) -> bool:
    p = parent.casefold().rstrip("/")
    c = child.casefold().rstrip("/")
    return p == "." or p == c or c.startswith(p + "/")


def scopes_overlap(left: Iterable[str], right: Iterable[str]) -> bool:
    return any(_scope_contains(a, b) or _scope_contains(b, a) for a in left for b in right)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def plan_worktree(
    repo: str | os.PathLike[str],
    task_id: str,
    worker_id: str,
    base_sha: str,
    paths: str | os.PathLike[str] | Iterable[str | os.PathLike[str]] = ".",
    *,
    worktrees_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Create a deterministic plan without touching the filesystem or Git."""

    repo_key, repo_path = _canonical_repo(repo)
    sha = _normalize_sha(base_sha)
    scopes = normalize_scopes(paths)
    if not str(task_id).strip() or not str(worker_id).strip():
        raise ValueError("task_id and worker_id are required")

    repo_obj = Path(repo_path)
    root = (
        Path(worktrees_root).expanduser().resolve(strict=False)
        if worktrees_root is not None
        else (repo_obj.parent / ".sentinel-worktrees").resolve(strict=False)
    )
    if root == repo_obj or _is_within(root, repo_obj):
        raise ValueError("worktrees_root must be outside the source repository")

    task_slug = _slug(str(task_id), "task")
    worker_slug = _slug(str(worker_id), "worker")
    repo_slug = _slug(repo_obj.name, "repo")
    identity = "\0".join((repo_key, sha, str(task_id), str(worker_id), *scopes))
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
    branch = f"sentinel/{worker_slug}/{task_slug}-{suffix}"
    worktree_path = root / repo_slug / f"{task_slug}-{suffix}"
    return {
        "repo_path": repo_path,
        "repo_key": repo_key,
        "base_sha": sha,
        "path_scopes": list(scopes),
        "branch_name": branch,
        "worktrees_root": str(root),
        "worktree_path": str(worktree_path),
    }


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _git(
    git_executable: str | os.PathLike[str],
    cwd: Path,
    args: list[str],
    timeout_sec: float,
) -> subprocess.CompletedProcess[str]:
    """Run Git without a shell and return its result for explicit handling."""

    try:
        return subprocess.run(
            [str(git_executable), "-C", str(cwd), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise WorktreeMaterializationError(
            "git_not_found", f"Git executable was not found: {git_executable}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise WorktreeMaterializationError(
            "git_timeout",
            f"Git command exceeded the {timeout_sec:g} second timeout",
            operation=args[:2],
        ) from exc
    except OSError as exc:
        raise WorktreeMaterializationError(
            "git_start_failed", f"Git could not be started: {exc}", operation=args[:2]
        ) from exc


def _git_failure(
    code: str,
    message: str,
    result: subprocess.CompletedProcess[str],
    *,
    operation: str,
    **details: Any,
) -> WorktreeMaterializationError:
    # Git diagnostics are useful, but cap them so a pathological hook cannot
    # inflate scheduler state or logs indefinitely.
    stderr = (result.stderr or "").strip()[-4000:]
    stdout = (result.stdout or "").strip()[-4000:]
    return WorktreeMaterializationError(
        code,
        message,
        operation=operation,
        returncode=result.returncode,
        stderr=stderr,
        stdout=stdout,
        **details,
    )


def _absolute_git_path(value: str, cwd: Path) -> Path:
    path = Path(value.strip())
    if not path.is_absolute():
        path = cwd / path
    return path.resolve(strict=False)


def _validated_materialization_plan(plan: dict[str, Any]) -> tuple[Path, Path, Path, str, str]:
    if not isinstance(plan, dict):
        raise ValueError("worktree plan must be a dictionary")
    required = ("repo_path", "base_sha", "branch_name", "worktrees_root", "worktree_path")
    missing = [field for field in required if not str(plan.get(field, "")).strip()]
    if missing:
        raise ValueError(f"worktree plan is missing required fields: {', '.join(missing)}")

    repo_raw = Path(str(plan["repo_path"])).expanduser()
    root_raw = Path(str(plan["worktrees_root"])).expanduser()
    target_raw = Path(str(plan["worktree_path"])).expanduser()
    if not repo_raw.is_absolute() or not root_raw.is_absolute() or not target_raw.is_absolute():
        raise ValueError("repo_path, worktrees_root, and worktree_path must be absolute")

    repo = repo_raw.resolve(strict=False)
    root = root_raw.resolve(strict=False)
    target = target_raw.resolve(strict=False)
    if _same_path(target, root) or not _is_within(target, root):
        raise ValueError("worktree_path must be a strict descendant of worktrees_root")
    if _same_path(target, repo) or _is_within(target, repo):
        raise ValueError("worktree_path must be outside and different from the source repository")
    if target_raw.is_symlink():
        raise WorktreeMaterializationError(
            "worktree_path_conflict", "planned worktree path is an existing symbolic link",
            worktree_path=str(target_raw),
        )

    sha = _normalize_sha(str(plan["base_sha"]))
    branch = str(plan["branch_name"]).strip()
    if not branch.startswith("sentinel/"):
        raise ValueError("materialized branch_name must be in the sentinel/ namespace")
    return repo, root, target, sha, branch


def _verify_existing_worktree(
    git_executable: str | os.PathLike[str],
    source_repo: Path,
    target: Path,
    branch: str,
    commit: str,
    timeout_sec: float,
) -> None:
    if not target.is_dir():
        raise WorktreeMaterializationError(
            "worktree_path_conflict",
            "planned worktree path already exists and is not a directory",
            worktree_path=str(target),
        )

    target_top = _git(git_executable, target, ["rev-parse", "--show-toplevel"], timeout_sec)
    if target_top.returncode != 0:
        raise WorktreeMaterializationError(
            "worktree_path_conflict",
            "planned worktree path already exists but is not a Git worktree",
            worktree_path=str(target),
        )
    actual_top = _absolute_git_path(target_top.stdout, target)
    if not _same_path(actual_top, target):
        raise WorktreeMaterializationError(
            "worktree_path_conflict",
            "planned path is inside another Git working tree rather than its root",
            worktree_path=str(target),
            actual_toplevel=str(actual_top),
        )

    source_common_result = _git(
        git_executable, source_repo, ["rev-parse", "--git-common-dir"], timeout_sec
    )
    target_common_result = _git(
        git_executable, target, ["rev-parse", "--git-common-dir"], timeout_sec
    )
    if source_common_result.returncode != 0 or target_common_result.returncode != 0:
        raise WorktreeMaterializationError(
            "worktree_verification_failed", "Git common directory could not be verified",
            worktree_path=str(target),
        )
    source_common = _absolute_git_path(source_common_result.stdout, source_repo)
    target_common = _absolute_git_path(target_common_result.stdout, target)
    if not _same_path(source_common, target_common):
        raise WorktreeMaterializationError(
            "worktree_path_conflict",
            "planned path belongs to a different Git repository",
            worktree_path=str(target),
        )

    branch_result = _git(
        git_executable, target, ["symbolic-ref", "--quiet", "--short", "HEAD"], timeout_sec
    )
    actual_branch = (branch_result.stdout or "").strip()
    if branch_result.returncode != 0 or actual_branch != branch:
        raise WorktreeMaterializationError(
            "worktree_branch_mismatch",
            "existing worktree is not checked out on the planned branch",
            worktree_path=str(target),
            expected_branch=branch,
            actual_branch=actual_branch,
        )

    head_result = _git(git_executable, target, ["rev-parse", "--verify", "HEAD^{commit}"], timeout_sec)
    actual_head = (head_result.stdout or "").strip().lower()
    if head_result.returncode != 0 or actual_head != commit:
        raise WorktreeMaterializationError(
            "worktree_base_mismatch",
            "existing worktree HEAD does not equal the planned base commit",
            worktree_path=str(target),
            expected_commit=commit,
            actual_commit=actual_head,
        )


def materialize_worktree(
    plan: dict[str, Any],
    *,
    git_executable: str | os.PathLike[str] = "git",
    timeout_sec: float = 30.0,
) -> dict[str, Any]:
    """Create or idempotently reuse the exact worktree described by ``plan``.

    The function is intentionally conservative.  Existing paths and branches
    are accepted only when they match the same repository, branch, and base
    commit.  Any mismatch raises :class:`WorktreeMaterializationError` and is
    left untouched.  Git is always invoked with an argv list and ``shell=False``.
    """

    if float(timeout_sec) <= 0:
        raise ValueError("timeout_sec must be positive")
    repo, root, target, sha, branch = _validated_materialization_plan(plan)
    timeout_sec = float(timeout_sec)

    if not repo.is_dir():
        raise WorktreeMaterializationError(
            "not_git_repository", "source repository path does not exist or is not a directory",
            repo_path=str(repo),
        )
    inside = _git(git_executable, repo, ["rev-parse", "--is-inside-work-tree"], timeout_sec)
    if inside.returncode != 0 or (inside.stdout or "").strip().lower() != "true":
        raise WorktreeMaterializationError(
            "not_git_repository", "source path is not a non-bare Git working tree",
            repo_path=str(repo),
        )
    top = _git(git_executable, repo, ["rev-parse", "--show-toplevel"], timeout_sec)
    if top.returncode != 0 or not _same_path(_absolute_git_path(top.stdout, repo), repo):
        raise WorktreeMaterializationError(
            "repo_not_toplevel", "repo_path must name the Git working-tree root",
            repo_path=str(repo),
        )

    valid_branch = _git(git_executable, repo, ["check-ref-format", "--branch", branch], timeout_sec)
    if valid_branch.returncode != 0:
        raise ValueError(f"invalid planned Git branch name: {branch}")

    base = _git(git_executable, repo, ["rev-parse", "--verify", f"{sha}^{{commit}}"], timeout_sec)
    if base.returncode != 0:
        raise _git_failure(
            "base_commit_not_found", "planned base commit does not exist in the repository",
            base, operation="resolve_base", base_sha=sha,
        )
    commit = (base.stdout or "").strip().lower()

    branch_ref = f"refs/heads/{branch}"
    # ``show-ref --verify`` without ``--quiet`` returns 128 (not 1) for a
    # missing ref on Git for Windows.  Quiet mode has the documented predicate
    # semantics, then rev-parse retrieves the object only when it exists.
    branch_result = _git(
        git_executable, repo, ["show-ref", "--verify", "--quiet", branch_ref], timeout_sec
    )
    if branch_result.returncode not in (0, 1):
        raise _git_failure(
            "branch_lookup_failed", "planned branch could not be inspected",
            branch_result, operation="inspect_branch", branch_name=branch,
        )
    branch_exists = branch_result.returncode == 0
    branch_commit = ""
    if branch_exists:
        branch_target = _git(
            git_executable, repo, ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"], timeout_sec
        )
        if branch_target.returncode != 0:
            raise _git_failure(
                "branch_lookup_failed", "planned branch target could not be resolved",
                branch_target, operation="inspect_branch", branch_name=branch,
            )
        branch_commit = (branch_target.stdout or "").strip().lower()
    if branch_exists and branch_commit != commit:
        raise WorktreeMaterializationError(
            "branch_base_mismatch",
            "planned branch already exists at a different commit; it was not changed",
            branch_name=branch,
            expected_commit=commit,
            actual_commit=branch_commit,
        )

    # Existing filesystem state is never removed or overwritten.  Only a fully
    # matching linked worktree is an idempotent success.
    if target.exists() or target.is_symlink():
        _verify_existing_worktree(git_executable, repo, target, branch, commit, timeout_sec)
        return {
            "ok": True,
            "created": False,
            "reused": True,
            "branch_created": False,
            "branch_reused": True,
            "repo_path": str(repo),
            "worktrees_root": str(root),
            "worktree_path": str(target),
            "branch_name": branch,
            "base_commit": commit,
        }

    # Resolve again after creating parents so a concurrently introduced
    # symlink/junction cannot redirect Git outside the planned root.
    target.parent.mkdir(parents=True, exist_ok=True)
    root_after = root.resolve(strict=False)
    target_after = target.resolve(strict=False)
    if _same_path(target_after, root_after) or not _is_within(target_after, root_after):
        raise WorktreeMaterializationError(
            "worktree_root_changed",
            "planned worktree parent now resolves outside worktrees_root",
            worktree_path=str(target),
        )
    if target.exists() or target.is_symlink():
        _verify_existing_worktree(git_executable, repo, target, branch, commit, timeout_sec)
        return {
            "ok": True, "created": False, "reused": True,
            "branch_created": False, "branch_reused": True,
            "repo_path": str(repo), "worktrees_root": str(root_after),
            "worktree_path": str(target), "branch_name": branch, "base_commit": commit,
        }

    branch_created = False
    if not branch_exists:
        create_branch = _git(git_executable, repo, ["branch", branch, commit], timeout_sec)
        if create_branch.returncode == 0:
            branch_created = True
        else:
            # Another materializer may have won the ref race.  Reuse it only
            # when it points at the identical immutable base.
            raced = _git(
                git_executable, repo, ["rev-parse", "--verify", f"{branch_ref}^{{commit}}"], timeout_sec
            )
            raced_commit = (raced.stdout or "").strip().lower()
            if raced.returncode != 0 or raced_commit != commit:
                raise _git_failure(
                    "branch_create_failed", "planned branch could not be created safely",
                    create_branch, operation="create_branch", branch_name=branch,
                )

    add = _git(git_executable, repo, ["worktree", "add", str(target), branch], timeout_sec)
    if add.returncode != 0:
        raise _git_failure(
            "worktree_add_failed",
            "Git could not add the planned worktree; existing state was left untouched",
            add,
            operation="worktree_add",
            branch_name=branch,
            worktree_path=str(target),
            branch_created=branch_created,
        )

    _verify_existing_worktree(git_executable, repo, target, branch, commit, timeout_sec)
    return {
        "ok": True,
        "created": True,
        "reused": False,
        "branch_created": branch_created,
        "branch_reused": not branch_created,
        "repo_path": str(repo),
        "worktrees_root": str(root_after),
        "worktree_path": str(target),
        "branch_name": branch,
        "base_commit": commit,
    }


class WorkspaceClaims:
    """SQLite-backed task lifecycle and exclusive repository path leases."""

    def __init__(self, data_dir: str | os.PathLike[str], *, db_path: str | os.PathLike[str] | None = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    @contextmanager
    def _db(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspace_claims (
                    claim_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL UNIQUE,
                    repo_key TEXT NOT NULL,
                    repo_path TEXT NOT NULL,
                    base_sha TEXT NOT NULL,
                    scopes_json TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    owner_pid INTEGER NOT NULL,
                    owner_started REAL NOT NULL,
                    worker_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    branch_name TEXT NOT NULL,
                    worktree_path TEXT NOT NULL,
                    ttl_sec REAL NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    last_reason TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_scope_lookup
                    ON workspace_claims(repo_key,base_sha,state,expires_at);
                CREATE INDEX IF NOT EXISTS idx_workspace_owner
                    ON workspace_claims(owner,worker_id,state);
                CREATE TABLE IF NOT EXISTS workspace_claim_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    claim_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    from_state TEXT,
                    to_state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    worker_id TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_events_task
                    ON workspace_claim_events(task_id,occurred_at);
                """
            )

    @staticmethod
    def _event(
        conn: sqlite3.Connection,
        row: sqlite3.Row | dict[str, Any],
        now: float,
        from_state: str | None,
        to_state: str,
        reason: str,
    ) -> None:
        conn.execute(
            """INSERT INTO workspace_claim_events
               (claim_id,task_id,occurred_at,from_state,to_state,reason,owner,worker_id)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                row["claim_id"], row["task_id"], now, from_state, to_state,
                reason, row["owner"], row["worker_id"],
            ),
        )

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["path_scopes"] = json.loads(item.pop("scopes_json") or "[]")
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        item["lease_active"] = item["state"] in LEASE_STATES
        worktree_path = Path(item["worktree_path"])
        item["plan"] = {
            "repo_path": item["repo_path"],
            "repo_key": item["repo_key"],
            "base_sha": item["base_sha"],
            "path_scopes": item["path_scopes"],
            "branch_name": item["branch_name"],
            # Plans always use ``root/repo-slug/task-slug``.  Keeping the root
            # in decoded historical rows preserves materializer compatibility
            # without a database migration.
            "worktrees_root": str(worktree_path.parent.parent),
            "worktree_path": item["worktree_path"],
        }
        return item

    @staticmethod
    def _conflicts_locked(
        conn: sqlite3.Connection,
        repo_key: str,
        base_sha: str,
        scopes: tuple[str, ...],
        now: float,
        *,
        exclude_claim_id: str = "",
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            """SELECT * FROM workspace_claims
               WHERE repo_key=? AND base_sha=?
                 AND state IN ('CLAIMED','RUNNING','VERIFYING')
                 AND expires_at>? AND claim_id<>?""",
            (repo_key, base_sha, now, exclude_claim_id),
        ).fetchall()
        conflicts = []
        for row in rows:
            other_scopes = tuple(json.loads(row["scopes_json"] or "[]"))
            if scopes_overlap(scopes, other_scopes):
                conflicts.append(
                    {
                        "claim_id": row["claim_id"],
                        "task_id": row["task_id"],
                        "state": row["state"],
                        "owner": row["owner"],
                        "worker_id": row["worker_id"],
                        "path_scopes": list(other_scopes),
                    }
                )
        return conflicts

    def claim(
        self,
        task_id: str,
        repo: str | os.PathLike[str],
        base_sha: str,
        paths: str | os.PathLike[str] | Iterable[str | os.PathLike[str]],
        owner: str,
        worker_id: str,
        ttl_sec: float = 3600,
        *,
        owner_pid: int = 0,
        owner_started: float = 0.0,
        queue_on_conflict: bool = True,
        worktrees_root: str | os.PathLike[str] | None = None,
        metadata: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Atomically acquire a scope lease or record the task as QUEUED."""

        if not str(task_id).strip() or not str(owner).strip() or not str(worker_id).strip():
            raise ValueError("task_id, owner, and worker_id are required")
        if float(ttl_sec) <= 0:
            raise ValueError("ttl_sec must be positive")
        now = time.time() if now is None else float(now)
        plan = plan_worktree(repo, task_id, worker_id, base_sha, paths, worktrees_root=worktrees_root)
        scopes = tuple(plan["path_scopes"])
        repo_key = plan["repo_key"]
        sha = plan["base_sha"]
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"), sort_keys=True)

        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, owner_alive=None)
            existing = conn.execute("SELECT * FROM workspace_claims WHERE task_id=?", (task_id,)).fetchone()
            if existing:
                existing_scopes = tuple(json.loads(existing["scopes_json"] or "[]"))
                if (
                    existing["repo_key"] != repo_key
                    or existing["base_sha"] != sha
                    or existing_scopes != scopes
                ):
                    conn.execute("COMMIT")
                    return {
                        "allowed": False,
                        "claim_id": existing["claim_id"],
                        "state": existing["state"],
                        "reason": "task_identity_mismatch",
                    }
                if existing["owner"] != owner:
                    conn.execute("COMMIT")
                    return {
                        "allowed": False,
                        "claim_id": existing["claim_id"],
                        "state": existing["state"],
                        "reason": "task_owner_mismatch",
                    }
                if existing["state"] in LEASE_STATES:
                    if existing["worker_id"] != worker_id:
                        conn.execute("COMMIT")
                        return {
                            "allowed": False,
                            "claim_id": existing["claim_id"],
                            "state": existing["state"],
                            "reason": "task_already_claimed",
                        }
                    conn.execute(
                        """UPDATE workspace_claims SET heartbeat_at=?,expires_at=?,updated_at=?,
                           ttl_sec=?,owner_pid=?,owner_started=? WHERE claim_id=?""",
                        (now, now + ttl_sec, now, ttl_sec, owner_pid, owner_started, existing["claim_id"]),
                    )
                    conn.execute("COMMIT")
                    return {
                        "allowed": True,
                        "claim_id": existing["claim_id"],
                        "state": existing["state"],
                        "reason": "reused",
                        "reused": True,
                        "plan": plan,
                    }
                if existing["state"] in TERMINAL_STATES:
                    conn.execute("COMMIT")
                    return {
                        "allowed": False,
                        "claim_id": existing["claim_id"],
                        "state": existing["state"],
                        "reason": "task_terminal",
                    }

            claim_id = existing["claim_id"] if existing else uuid.uuid4().hex
            conflicts = self._conflicts_locked(
                conn, repo_key, sha, scopes, now, exclude_claim_id=claim_id
            )
            if conflicts:
                if queue_on_conflict:
                    if existing:
                        previous = existing["state"]
                        conn.execute(
                            """UPDATE workspace_claims SET state='QUEUED',worker_id=?,branch_name=?,
                               worktree_path=?,owner_pid=?,owner_started=?,ttl_sec=?,updated_at=?,
                               heartbeat_at=?,expires_at=?,last_reason='path_conflict',metadata_json=?
                               WHERE claim_id=?""",
                            (
                                worker_id, plan["branch_name"], plan["worktree_path"], owner_pid,
                                owner_started, ttl_sec, now, now, now + ttl_sec, metadata_json, claim_id,
                            ),
                        )
                        if previous != "QUEUED":
                            queued_row = conn.execute(
                                "SELECT * FROM workspace_claims WHERE claim_id=?", (claim_id,)
                            ).fetchone()
                            self._event(conn, queued_row, now, previous, "QUEUED", "path_conflict")
                    else:
                        conn.execute(
                            """INSERT INTO workspace_claims
                               (claim_id,task_id,repo_key,repo_path,base_sha,scopes_json,owner,
                                owner_pid,owner_started,worker_id,state,branch_name,worktree_path,
                                ttl_sec,created_at,updated_at,heartbeat_at,expires_at,last_reason,metadata_json)
                               VALUES (?,?,?,?,?,?,?,?,?,?,'QUEUED',?,?,?,?,?,?,?,'path_conflict',?)""",
                            (
                                claim_id, task_id, repo_key, plan["repo_path"], sha,
                                json.dumps(scopes, separators=(",", ":")), owner, owner_pid,
                                owner_started, worker_id, plan["branch_name"], plan["worktree_path"],
                                ttl_sec, now, now, now, now + ttl_sec, metadata_json,
                            ),
                        )
                        queued_row = conn.execute(
                            "SELECT * FROM workspace_claims WHERE claim_id=?", (claim_id,)
                        ).fetchone()
                        self._event(conn, queued_row, now, None, "QUEUED", "path_conflict")
                conn.execute("COMMIT")
                return {
                    "allowed": False,
                    "claim_id": claim_id if queue_on_conflict else "",
                    "state": "QUEUED" if queue_on_conflict else "",
                    "queued": bool(queue_on_conflict),
                    "reason": "path_conflict",
                    "conflicts": conflicts,
                    "plan": plan,
                }

            if existing:
                previous = existing["state"]
                conn.execute(
                    """UPDATE workspace_claims SET state='CLAIMED',worker_id=?,branch_name=?,
                       worktree_path=?,owner_pid=?,owner_started=?,ttl_sec=?,updated_at=?,
                       heartbeat_at=?,expires_at=?,last_reason='',metadata_json=? WHERE claim_id=?""",
                    (
                        worker_id, plan["branch_name"], plan["worktree_path"], owner_pid,
                        owner_started, ttl_sec, now, now, now + ttl_sec, metadata_json, claim_id,
                    ),
                )
                claimed_row = conn.execute(
                    "SELECT * FROM workspace_claims WHERE claim_id=?", (claim_id,)
                ).fetchone()
                self._event(conn, claimed_row, now, previous, "CLAIMED", "claim_acquired")
            else:
                conn.execute(
                    """INSERT INTO workspace_claims
                       (claim_id,task_id,repo_key,repo_path,base_sha,scopes_json,owner,
                        owner_pid,owner_started,worker_id,state,branch_name,worktree_path,
                        ttl_sec,created_at,updated_at,heartbeat_at,expires_at,last_reason,metadata_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,'CLAIMED',?,?,?,?,?,?,?,'',?)""",
                    (
                        claim_id, task_id, repo_key, plan["repo_path"], sha,
                        json.dumps(scopes, separators=(",", ":")), owner, owner_pid,
                        owner_started, worker_id, plan["branch_name"], plan["worktree_path"],
                        ttl_sec, now, now, now, now + ttl_sec, metadata_json,
                    ),
                )
                claimed_row = conn.execute(
                    "SELECT * FROM workspace_claims WHERE claim_id=?", (claim_id,)
                ).fetchone()
                self._event(conn, claimed_row, now, None, "CLAIMED", "claim_acquired")
            conn.execute("COMMIT")

        return {
            "allowed": True,
            "claim_id": claim_id,
            "state": "CLAIMED",
            "reason": "claimed",
            "reused": False,
            "plan": plan,
        }

    def transition(
        self,
        task_id: str,
        new_state: str,
        *,
        expected_state: str = "",
        ttl_sec: float | None = None,
        reason: str = "",
        now: float | None = None,
    ) -> dict[str, Any]:
        target = str(new_state).upper()
        if target not in STATES:
            raise ValueError(f"unknown workspace state: {new_state}")
        now = time.time() if now is None else float(now)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, owner_alive=None)
            row = conn.execute("SELECT * FROM workspace_claims WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                conn.execute("COMMIT")
                return {"allowed": False, "reason": "task_not_found", "task_id": task_id}
            current = row["state"]
            if expected_state and current != expected_state.upper():
                conn.execute("COMMIT")
                return {
                    "allowed": False, "reason": "state_mismatch", "state": current,
                    "expected_state": expected_state.upper(), "claim_id": row["claim_id"],
                }
            if current == target:
                conn.execute("COMMIT")
                return {
                    "allowed": True, "reason": "already_in_state", "state": current,
                    "claim_id": row["claim_id"], "reused": True,
                }
            if target not in ALLOWED_TRANSITIONS[current]:
                conn.execute("COMMIT")
                return {
                    "allowed": False, "reason": "invalid_transition", "state": current,
                    "requested_state": target, "claim_id": row["claim_id"],
                }
            if target in LEASE_STATES and current not in LEASE_STATES:
                scopes = tuple(json.loads(row["scopes_json"] or "[]"))
                conflicts = self._conflicts_locked(
                    conn, row["repo_key"], row["base_sha"], scopes, now,
                    exclude_claim_id=row["claim_id"],
                )
                if conflicts:
                    conn.execute("COMMIT")
                    return {
                        "allowed": False, "reason": "path_conflict", "state": current,
                        "claim_id": row["claim_id"], "conflicts": conflicts,
                    }
            effective_ttl = float(ttl_sec if ttl_sec is not None else row["ttl_sec"])
            if effective_ttl <= 0:
                conn.execute("ROLLBACK")
                raise ValueError("ttl_sec must be positive")
            expires = now + effective_ttl if target in EXPIRING_STATES else now
            conn.execute(
                """UPDATE workspace_claims SET state=?,ttl_sec=?,updated_at=?,heartbeat_at=?,
                   expires_at=?,last_reason=? WHERE claim_id=?""",
                (target, effective_ttl, now, now, expires, reason, row["claim_id"]),
            )
            updated = conn.execute(
                "SELECT * FROM workspace_claims WHERE claim_id=?", (row["claim_id"],)
            ).fetchone()
            self._event(conn, updated, now, current, target, reason or "transition")
            conn.execute("COMMIT")
        return {
            "allowed": True, "reason": "transitioned", "state": target,
            "claim_id": row["claim_id"], "reused": False,
        }

    def heartbeat(
        self,
        task_id: str,
        *,
        ttl_sec: float | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        now = time.time() if now is None else float(now)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, owner_alive=None)
            row = conn.execute("SELECT * FROM workspace_claims WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                conn.execute("COMMIT")
                return {"renewed": False, "reason": "task_not_found", "task_id": task_id}
            if row["state"] not in EXPIRING_STATES:
                conn.execute("COMMIT")
                return {
                    "renewed": False, "reason": "lease_inactive", "state": row["state"],
                    "claim_id": row["claim_id"],
                }
            effective_ttl = float(ttl_sec if ttl_sec is not None else row["ttl_sec"])
            if effective_ttl <= 0:
                conn.execute("ROLLBACK")
                raise ValueError("ttl_sec must be positive")
            conn.execute(
                """UPDATE workspace_claims SET ttl_sec=?,heartbeat_at=?,expires_at=?,updated_at=?
                   WHERE claim_id=?""",
                (effective_ttl, now, now + effective_ttl, now, row["claim_id"]),
            )
            conn.execute("COMMIT")
        return {
            "renewed": True, "claim_id": row["claim_id"], "state": row["state"],
            "expires_at": now + effective_ttl,
        }

    def release(
        self,
        task_id: str,
        outcome: str = "done",
        *,
        now: float | None = None,
    ) -> dict[str, Any]:
        outcomes = {
            "DONE": "DONE", "SUCCESS": "DONE", "COMPLETED": "DONE",
            "FAILED": "FAILED", "FAILURE": "FAILED", "ERROR": "FAILED",
            "RETRYABLE": "RETRYABLE", "RETRY": "RETRYABLE", "STALE": "RETRYABLE",
            "BLOCKED": "BLOCKED", "CANCELLED": "FAILED", "CANCELED": "FAILED",
        }
        target = outcomes.get(str(outcome).upper())
        if not target:
            raise ValueError(f"unknown release outcome: {outcome}")
        now = time.time() if now is None else float(now)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM workspace_claims WHERE task_id=?", (task_id,)).fetchone()
            if not row:
                conn.execute("COMMIT")
                return {"released": False, "reason": "task_not_found", "task_id": task_id}
            current = row["state"]
            if current in TERMINAL_STATES and current != target:
                conn.execute("COMMIT")
                return {
                    "released": False, "reason": "task_terminal", "state": current,
                    "claim_id": row["claim_id"],
                }
            if current == target and current not in LEASE_STATES:
                conn.execute("COMMIT")
                return {
                    "released": False, "reason": "already_released", "state": current,
                    "claim_id": row["claim_id"],
                }
            conn.execute(
                """UPDATE workspace_claims SET state=?,updated_at=?,heartbeat_at=?,expires_at=?,
                   last_reason=? WHERE claim_id=?""",
                (target, now, now, now, str(outcome), row["claim_id"]),
            )
            updated = conn.execute(
                "SELECT * FROM workspace_claims WHERE claim_id=?", (row["claim_id"],)
            ).fetchone()
            self._event(conn, updated, now, current, target, str(outcome))
            conn.execute("COMMIT")
        return {
            "released": True, "reason": "released", "state": target,
            "claim_id": row["claim_id"],
        }

    def _cleanup_locked(
        self,
        conn: sqlite3.Connection,
        now: float,
        owner_alive: Callable[[int, float], bool] | None,
    ) -> list[dict[str, Any]]:
        rows = conn.execute(
            """SELECT * FROM workspace_claims
               WHERE state IN ('QUEUED','CLAIMED','RUNNING','VERIFYING')"""
        ).fetchall()
        removed: list[dict[str, Any]] = []
        for row in rows:
            reason = ""
            if float(row["expires_at"]) <= now:
                reason = "ttl_expired"
            elif owner_alive is not None and int(row["owner_pid"]) > 0:
                try:
                    alive = owner_alive(int(row["owner_pid"]), float(row["owner_started"]))
                except Exception:
                    alive = True  # Cleanup must fail safe when liveness is unknowable.
                if not alive:
                    reason = "owner_gone"
            if not reason:
                continue
            conn.execute(
                """UPDATE workspace_claims SET state='RETRYABLE',updated_at=?,heartbeat_at=?,
                   expires_at=?,last_reason=? WHERE claim_id=?""",
                (now, now, now, reason, row["claim_id"]),
            )
            updated = conn.execute(
                "SELECT * FROM workspace_claims WHERE claim_id=?", (row["claim_id"],)
            ).fetchone()
            self._event(conn, updated, now, row["state"], "RETRYABLE", reason)
            removed.append(
                {"claim_id": row["claim_id"], "task_id": row["task_id"], "reason": reason}
            )
        return removed

    def cleanup(
        self,
        *,
        now: float | None = None,
        owner_alive: Callable[[int, float], bool] | None = None,
    ) -> list[dict[str, Any]]:
        now = time.time() if now is None else float(now)
        checker = owner_alive if owner_alive is not None else _default_owner_alive
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            removed = self._cleanup_locked(conn, now, checker)
            conn.execute("COMMIT")
        return removed

    def snapshot(self, *, now: float | None = None, include_events: bool = False) -> dict[str, Any]:
        now = time.time() if now is None else float(now)
        # Expired leases are reconciled before callers make scheduling decisions.
        self.cleanup(now=now)
        with self._db() as conn:
            claims = [
                self._decode(row)
                for row in conn.execute("SELECT * FROM workspace_claims ORDER BY created_at,task_id")
            ]
            events = (
                [dict(row) for row in conn.execute(
                    "SELECT * FROM workspace_claim_events ORDER BY event_id"
                )]
                if include_events
                else []
            )
        result = {
            "claims": claims,
            "active": [item for item in claims if item["state"] in LEASE_STATES],
            "queued": [item for item in claims if item["state"] == "QUEUED"],
            "nonactive": [item for item in claims if item["state"] not in LEASE_STATES | {"QUEUED"}],
        }
        if include_events:
            result["events"] = events
        return result


def _default_owner_alive(pid: int, started_at: float) -> bool:
    """Best-effort PID + creation-time check; uncertainty preserves the lease."""

    if pid <= 0:
        return True
    try:
        import psutil

        process = psutil.Process(pid)
        if started_at > 0 and abs(float(process.create_time()) - started_at) > 2.0:
            return False
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except ImportError:
        pass
    except Exception as exc:
        # psutil's process exceptions do not consistently inherit the builtin
        # ProcessLookupError across versions, so inspect them only when psutil
        # was imported successfully.
        try:
            if isinstance(exc, (psutil.NoSuchProcess, psutil.ZombieProcess)):
                return False
        except Exception:
            pass
        # AccessDenied and platform-specific failures are not proof of death.
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except (PermissionError, OSError):
        return True


# Alias for callers that prefer the broader architectural name.
WorkspaceManager = WorkspaceClaims
