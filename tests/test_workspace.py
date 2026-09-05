import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from sentinel.workspace import (
    WorkspaceClaims,
    WorktreeMaterializationError,
    materialize_worktree,
    normalize_scopes,
    plan_worktree,
)


NOW = 2_000_000_000.0
SHA_A = "a" * 40
SHA_B = "b" * 40


class WorkspaceClaimsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "source-repo"
        self.manager = WorkspaceClaims(self.root / "state")

    def tearDown(self):
        self.tmp.cleanup()

    def claim(self, task, paths, **kwargs):
        return self.manager.claim(
            task,
            self.repo,
            kwargs.pop("base_sha", SHA_A),
            paths,
            kwargs.pop("owner", "orchestrator"),
            kwargs.pop("worker_id", "local-windows"),
            kwargs.pop("ttl_sec", 60),
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    def test_normalizes_and_minimizes_scopes(self):
        self.assertEqual(normalize_scopes(["src/api", "src", "README.md", "src"]), ("src", "README.md"))
        self.assertEqual(normalize_scopes("."), (".",))
        with self.assertRaises(ValueError):
            normalize_scopes("../outside")
        with self.assertRaises(ValueError):
            normalize_scopes("src/*.py")
        with self.assertRaises(ValueError):
            normalize_scopes(".git/config")

    def test_overlap_is_atomic_and_conflicting_task_is_queued(self):
        first = self.claim("one", "src")
        second = self.claim("two", "src/api/client.py")
        self.assertTrue(first["allowed"])
        self.assertFalse(second["allowed"])
        self.assertTrue(second["queued"])
        self.assertEqual(second["reason"], "path_conflict")
        self.assertEqual(second["conflicts"][0]["task_id"], "one")
        snapshot = self.manager.snapshot(now=NOW + 1)
        self.assertEqual([item["task_id"] for item in snapshot["active"]], ["one"])
        self.assertEqual([item["task_id"] for item in snapshot["queued"]], ["two"])

    def test_disjoint_paths_and_different_bases_can_run(self):
        self.assertTrue(self.claim("frontend", "web")["allowed"])
        self.assertTrue(self.claim("backend", "api")["allowed"])
        # Same scope on a distinct immutable base is a distinct workspace claim.
        self.assertTrue(self.claim("other-base", "web", base_sha=SHA_B)["allowed"])

    def test_concurrent_claims_have_exactly_one_winner(self):
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def run(task):
            try:
                barrier.wait(timeout=5)
                results.append(self.claim(task, "src/shared", queue_on_conflict=False))
            except Exception as exc:  # pragma: no cover - surfaced by assertion
                errors.append(exc)

        threads = [threading.Thread(target=run, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
        self.assertFalse(errors)
        self.assertEqual(sum(bool(result["allowed"]) for result in results), 1)
        self.assertEqual(sum(result["reason"] == "path_conflict" for result in results), 1)

    def test_queued_task_rechecks_conflict_before_claiming(self):
        self.claim("owner", "src")
        waiting = self.claim("waiting", "src/module.py")
        blocked = self.manager.transition("waiting", "CLAIMED", now=NOW + 1)
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["reason"], "path_conflict")

        self.manager.release("owner", "done", now=NOW + 2)
        admitted = self.manager.transition("waiting", "CLAIMED", now=NOW + 3)
        self.assertTrue(admitted["allowed"])
        self.assertEqual(admitted["state"], "CLAIMED")

    def test_lifecycle_release_and_event_history(self):
        self.claim("job", "src")
        self.assertTrue(self.manager.transition("job", "RUNNING", now=NOW + 1)["allowed"])
        self.assertTrue(self.manager.transition("job", "VERIFYING", now=NOW + 2)["allowed"])
        released = self.manager.release("job", "success", now=NOW + 3)
        self.assertTrue(released["released"])
        self.assertEqual(released["state"], "DONE")
        rewritten = self.manager.release("job", "failed", now=NOW + 3.5)
        self.assertFalse(rewritten["released"])
        self.assertEqual(rewritten["reason"], "task_terminal")
        invalid = self.manager.transition("job", "RUNNING", now=NOW + 4)
        self.assertFalse(invalid["allowed"])
        self.assertEqual(invalid["reason"], "invalid_transition")
        snapshot = self.manager.snapshot(now=NOW + 4, include_events=True)
        self.assertEqual(snapshot["claims"][0]["state"], "DONE")
        self.assertEqual([event["to_state"] for event in snapshot["events"]], [
            "CLAIMED", "RUNNING", "VERIFYING", "DONE"
        ])

    def test_heartbeat_renews_ttl_and_expiry_releases_scope(self):
        first = self.claim("first", "src", ttl_sec=10)
        renewed = self.manager.heartbeat("first", ttl_sec=20, now=NOW + 5)
        self.assertTrue(renewed["renewed"])
        self.assertEqual(renewed["expires_at"], NOW + 25)
        self.assertEqual(self.manager.cleanup(now=NOW + 24), [])
        stale = self.manager.cleanup(now=NOW + 26)
        self.assertEqual(stale[0]["reason"], "ttl_expired")
        self.assertTrue(self.claim("second", "src", now=NOW + 27)["allowed"])
        snapshot = self.manager.snapshot(now=NOW + 27)
        old = next(item for item in snapshot["claims"] if item["claim_id"] == first["claim_id"])
        self.assertEqual(old["state"], "RETRYABLE")
        self.assertFalse(old["lease_active"])

    def test_crash_cleanup_checks_pid_and_creation_identity(self):
        self.claim("crashed", "src", owner_pid=1234, owner_started=99.0)
        calls = []

        def dead(pid, started):
            calls.append((pid, started))
            return False

        cleaned = self.manager.cleanup(now=NOW + 1, owner_alive=dead)
        self.assertEqual(calls, [(1234, 99.0)])
        self.assertEqual(cleaned[0]["reason"], "owner_gone")
        self.assertEqual(self.manager.snapshot(now=NOW + 1)["claims"][0]["state"], "RETRYABLE")

    def test_task_identity_and_owner_cannot_be_silently_changed(self):
        original = self.claim("stable", "src")
        changed_scope = self.claim("stable", "other")
        changed_owner = self.claim("stable", "src", owner="other-owner")
        self.assertTrue(original["allowed"])
        self.assertEqual(changed_scope["reason"], "task_identity_mismatch")
        self.assertEqual(changed_owner["reason"], "task_owner_mismatch")

    def test_worktree_plan_is_safe_deterministic_and_non_mutating(self):
        plan_a = plan_worktree(
            self.repo, "../../Fix Weird Task", "Cursor Cloud", SHA_A, ["src", "tests"]
        )
        plan_b = plan_worktree(
            self.repo, "../../Fix Weird Task", "Cursor Cloud", SHA_A, ["src", "tests"]
        )
        self.assertEqual(plan_a, plan_b)
        self.assertRegex(plan_a["branch_name"], r"^sentinel/cursor-cloud/fix-weird-task-[0-9a-f]{12}$")
        worktree = Path(plan_a["worktree_path"])
        self.assertFalse(worktree.exists())
        self.assertNotEqual(worktree, self.repo)
        self.assertNotIn("..", worktree.name)
        self.assertEqual(Path(plan_a["worktrees_root"]), self.root / ".sentinel-worktrees")
        with self.assertRaises(ValueError):
            plan_worktree(
                self.repo, "bad-root", "local", SHA_A, ".", worktrees_root=self.repo / "tmp"
            )


@unittest.skipUnless(shutil.which("git"), "Git is required for worktree materialization tests")
class WorktreeMaterializationTests(unittest.TestCase):
    def setUp(self):
        # Keep the fixture outside this project's own Git checkout so a plain
        # directory below the fixture is genuinely not a repository.
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.repo = self.root / "source"
        self.repo.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.email", "sentinel-tests@example.invalid")
        self.git("config", "user.name", "Sentinel Tests")
        (self.repo / "tracked.txt").write_text("base\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "--quiet", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").stdout.strip()
        self.worktrees_root = self.root / "worktrees"

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *args, cwd=None, check=True):
        return subprocess.run(
            ["git", "-C", str(cwd or self.repo), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
            shell=False,
        )

    def plan(self, task="materialize"):
        return plan_worktree(
            self.repo,
            task,
            "local-windows",
            self.base,
            ".",
            worktrees_root=self.worktrees_root,
        )

    def test_claim_plan_creates_and_idempotently_reuses_real_worktree(self):
        manager = WorkspaceClaims(self.root / "state")
        claim = manager.claim(
            "claim-materialize",
            self.repo,
            self.base,
            ".",
            "orchestrator",
            "local-windows",
            worktrees_root=self.worktrees_root,
        )
        self.assertTrue(claim["allowed"])

        created = materialize_worktree(claim["plan"])
        self.assertTrue(created["created"])
        self.assertTrue(created["branch_created"])
        target = Path(created["worktree_path"])
        self.assertEqual(self.git("rev-parse", "HEAD", cwd=target).stdout.strip(), self.base)
        self.assertEqual(
            self.git("symbolic-ref", "--short", "HEAD", cwd=target).stdout.strip(),
            claim["plan"]["branch_name"],
        )

        reused = materialize_worktree(claim["plan"])
        self.assertFalse(reused["created"])
        self.assertTrue(reused["reused"])
        self.assertTrue(target.is_dir())

    def test_existing_matching_branch_is_reused_without_force_update(self):
        plan = self.plan("existing-branch")
        self.git("branch", plan["branch_name"], self.base)
        result = materialize_worktree(plan)
        self.assertTrue(result["created"])
        self.assertFalse(result["branch_created"])
        self.assertTrue(result["branch_reused"])

    def test_mismatched_existing_branch_is_rejected_and_unchanged(self):
        plan = self.plan("mismatched-branch")
        (self.repo / "tracked.txt").write_text("second\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.git("commit", "--quiet", "-m", "second")
        newer = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("branch", plan["branch_name"], newer)

        with self.assertRaises(WorktreeMaterializationError) as caught:
            materialize_worktree(plan)
        self.assertEqual(caught.exception.code, "branch_base_mismatch")
        after = self.git("rev-parse", "--verify", f"refs/heads/{plan['branch_name']}^{{commit}}")
        self.assertEqual(after.stdout.strip(), newer)
        self.assertFalse(Path(plan["worktree_path"]).exists())

    def test_existing_unrelated_path_is_rejected_and_preserved(self):
        plan = self.plan("occupied-path")
        target = Path(plan["worktree_path"])
        target.mkdir(parents=True)
        marker = target / "do-not-delete.txt"
        marker.write_text("owned by user\n", encoding="utf-8")

        with self.assertRaises(WorktreeMaterializationError) as caught:
            materialize_worktree(plan)
        self.assertEqual(caught.exception.code, "worktree_path_conflict")
        self.assertEqual(marker.read_text(encoding="utf-8"), "owned by user\n")
        branch = self.git(
            "show-ref", "--verify", "--quiet", f"refs/heads/{plan['branch_name']}", check=False
        )
        self.assertEqual(branch.returncode, 1)

    def test_non_git_repo_and_unknown_base_have_typed_errors(self):
        plain = self.root / "plain"
        plain.mkdir()
        plain_plan = plan_worktree(
            plain, "plain", "local", self.base, ".", worktrees_root=self.worktrees_root
        )
        with self.assertRaises(WorktreeMaterializationError) as not_git:
            materialize_worktree(plain_plan)
        self.assertEqual(not_git.exception.code, "not_git_repository")

        missing_plan = self.plan("missing-base")
        missing_plan["base_sha"] = "f" * 40
        with self.assertRaises(WorktreeMaterializationError) as missing:
            materialize_worktree(missing_plan)
        self.assertEqual(missing.exception.code, "base_commit_not_found")

    def test_tampered_path_outside_planned_root_is_rejected_without_git_mutation(self):
        plan = self.plan("outside")
        outside = self.root / "outside-worktree"
        plan["worktree_path"] = str(outside)
        with self.assertRaises(ValueError):
            materialize_worktree(plan)
        self.assertFalse(outside.exists())
        branch = self.git(
            "show-ref", "--verify", "--quiet", f"refs/heads/{plan['branch_name']}", check=False
        )
        self.assertEqual(branch.returncode, 1)


if __name__ == "__main__":
    unittest.main()
