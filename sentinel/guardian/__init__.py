"""Guardian: foreground-first CPU and memory control for local agent work (Windows Job Objects).

Layout: winjob (ctypes), policy (pure decisions), ledger (SQLite), apps (read-only view of live agent
apps), daemon (job owner, launcher, control loop, dashboard API), client (srun entry point).
"""
