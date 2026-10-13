"""guardian.sqlite3: runs, decisions, samples and reservations.

Kept apart from the collector's sentinel.db so the 1 Hz Guardian loop never waits on the collector's writes.
A run row is written before its process starts; a run found 'starting' or 'running' when the daemon starts
again is marked NEEDS_RECONCILIATION instead of being guessed.
"""
import json
import sqlite3
import threading
import time

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, provider TEXT, session TEXT, cls TEXT, fingerprint TEXT, cwd TEXT, label TEXT,
  state TEXT, reason TEXT, est_gib REAL, est_source TEXT, unprofiled INTEGER,
  t_request REAL, t_start REAL, t_end REAL, pid INTEGER, exit_code INTEGER,
  cpu_s REAL, peak_commit_bytes INTEGER, constrained INTEGER DEFAULT 0, coverage TEXT);
CREATE INDEX IF NOT EXISTS runs_fp ON runs(fingerprint, state);
CREATE TABLE IF NOT EXISTS decisions (
  id INTEGER PRIMARY KEY, t REAL, kind TEXT, target TEXT, before TEXT, requested TEXT, readback TEXT,
  error TEXT, reason TEXT, policy_version TEXT);
CREATE TABLE IF NOT EXISTS samples (
  t REAL PRIMARY KEY, mode TEXT, cap REAL, cpu_busy REAL, pool_cores REAL, available_gib REAL,
  commit_headroom_gib REAL, experience TEXT, probe TEXT, sessions TEXT, apps TEXT);
"""


class Ledger:
    def __init__(self, path, retention_s=24 * 3600):
        self.path, self.retention_s = str(path), retention_s
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=5)
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)
            self.db.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
        self._last_prune = 0.0

    def close(self):
        with self.lock:
            self.db.close()

    def _x(self, sql, args=()):
        with self.lock:
            return self.db.execute(sql, args).fetchall()

    def reconcile_on_start(self):
        rows = self._x("SELECT run_id FROM runs WHERE state IN ('starting', 'running', 'queued')")
        self._x("UPDATE runs SET state='NEEDS_RECONCILIATION', reason='daemon restarted while the run was open' "
                "WHERE state IN ('starting', 'running', 'queued')")
        return [r[0] for r in rows]

    def run_requested(self, r):
        self._x("INSERT INTO runs (run_id, provider, session, cls, fingerprint, cwd, label, state, reason, est_gib, "
                "est_source, unprofiled, t_request, coverage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (r["run_id"], r["provider"], r["session"], r["cls"], r["fingerprint"], r.get("cwd"), r.get("label"),
                 "queued", r.get("reason", ""), r["est_gib"], r["est_source"], int(r["unprofiled"]), r["t_request"],
                 r.get("coverage", "enforced")))

    def run_update(self, run_id, **kw):
        if kw:
            cols = ", ".join(f"{k}=?" for k in kw)
            self._x(f"UPDATE runs SET {cols} WHERE run_id=?", (*kw.values(), run_id))

    def profile(self, fingerprint, limit=20):
        """Peak commit (GiB) of earlier successful runs that no memory limit could have cut short."""
        rows = self._x("SELECT peak_commit_bytes FROM runs WHERE fingerprint=? AND state='done' AND exit_code=0 "
                       "AND constrained=0 AND peak_commit_bytes IS NOT NULL ORDER BY t_end DESC LIMIT ?",
                       (fingerprint, limit))
        return [r[0] / 2**30 for r in rows]

    def decision(self, kind, target, before=None, requested=None, readback=None, error=None, reason="",
                 policy_version=""):
        enc = lambda v: None if v is None else json.dumps(v, default=str)
        self._x("INSERT INTO decisions (t, kind, target, before, requested, readback, error, reason, policy_version) "
                "VALUES (?,?,?,?,?,?,?,?,?)", (time.time(), kind, target, enc(before), enc(requested), enc(readback),
                                               error, reason, policy_version))

    def sample(self, row):
        self._x("INSERT OR REPLACE INTO samples VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (row["t"], row["mode"], row["cap"], row.get("cpu_busy"), row.get("pool_cores"),
                 row.get("available_gib"), row.get("commit_headroom_gib"), row.get("experience"),
                 json.dumps(row.get("probe")), json.dumps(row.get("sessions")), json.dumps(row.get("apps"))))
        now = time.time()
        if now - self._last_prune > 600:
            self._last_prune = now
            self._x("DELETE FROM samples WHERE t < ?", (now - self.retention_s,))
            self._x("DELETE FROM decisions WHERE t < ?", (now - 30 * 86400,))

    def recent_decisions(self, n=40):
        rows = self._x("SELECT t, kind, target, before, requested, readback, error, reason FROM decisions "
                       "ORDER BY id DESC LIMIT ?", (n,))
        keys = ("t", "kind", "target", "before", "requested", "readback", "error", "reason")
        return [dict(zip(keys, r)) for r in rows]

    def recent_runs(self, n=30):
        rows = self._x("SELECT run_id, provider, session, cls, label, state, reason, est_gib, est_source, t_request, "
                       "t_start, t_end, exit_code, cpu_s, peak_commit_bytes FROM runs ORDER BY t_request DESC LIMIT ?",
                       (n,))
        keys = ("run_id", "provider", "session", "cls", "label", "state", "reason", "est_gib", "est_source",
                "t_request", "t_start", "t_end", "exit_code", "cpu_s", "peak_commit_bytes")
        return [dict(zip(keys, r)) for r in rows]

    def samples_since(self, t0):
        rows = self._x("SELECT t, mode, cap, cpu_busy, pool_cores, experience, probe, sessions FROM samples "
                       "WHERE t >= ? ORDER BY t", (t0,))
        return [{"t": r[0], "mode": r[1], "cap": r[2], "cpu_busy": r[3], "pool_cores": r[4], "experience": r[5],
                 "probe": json.loads(r[6] or "null"), "sessions": json.loads(r[7] or "null")} for r in rows]
