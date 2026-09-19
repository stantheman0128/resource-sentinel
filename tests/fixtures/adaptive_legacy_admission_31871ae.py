"""Frozen admission/retry algorithms from Coordinator at 31871ae8.

Only these two method bodies are copied verbatim from the committed baseline.
They reuse current DB/accounting helpers to test the legacy queue hash boundary;
this is not a full old-binary or Windows compatibility simulation.
Do not update this fixture when changing managed admission.
"""
import os
import sqlite3
import time
import uuid
from typing import Any

from sentinel.coordinator import (
    Coordinator, Exemptions, PRIORITY_RANK, ResourceRequest, allocation_is_bound,
    frame_from_status, redact_command, shared_admission_blockers,
)


class LegacyAdmissionCoordinator(Coordinator):
    def admit(
        self,
        request: ResourceRequest,
        status: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        req = request.normalized()
        cfg = self._config(config, local_host_id=self.local_host_id)
        now = time.time() if now is None else now
        v2 = cfg.get("admission_policy") == "resource-v2"
        frame = frame_from_status(status, cfg, now=now, logical_processors=os.cpu_count() or 1) if v2 else None
        metrics = ({"fresh": frame["fresh"], "light": status.get("light", "UNKNOWN")}
                   if v2 else self._status_metrics(status, cfg, now))
        observations = self._cleanup_observations()
        # Process ancestry and the other SQLite store must not run while the
        # capacity writer transaction is held. P2 does not add any cap writer;
        # its later grant/control linearization belongs to the policy mutex.
        exemption = None
        try:
            exemption = Exemptions(self.data_dir).match(req.owner_pid, req.owner_started, now=now)
        except (OSError, sqlite3.Error):
            pass  # unreadable exemption state never grants a bypass
        result: dict[str, Any]
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, cfg, observations)
            existing = conn.execute("SELECT * FROM reservations WHERE request_key=?", (req.request_key,)).fetchone()
            if existing:
                if allocation_is_bound(conn, "direct", existing["id"]):
                    conn.execute("COMMIT")
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "request_key": req.request_key, "reservation_id": existing["id"]}
                if existing["spec_hash"] != req.spec_hash:
                    conn.execute("COMMIT")
                    return {
                        "allowed": False, "reason": "request_spec_mismatch",
                        "request_key": req.request_key, "reservation_id": existing["id"],
                    }
                conn.execute(
                    "UPDATE reservations SET heartbeat_at=?,expires_at=?,tool_use_id=? WHERE id=?",
                    (now, now + float(cfg["reservation_ttl_min"]) * 60, req.tool_use_id, existing["id"]),
                )
                conn.execute("COMMIT")
                self._mirror()
                return {"allowed": True, "reservation_id": existing["id"], "reused": True, "request_key": req.request_key}
            handoffs = conn.execute(
                "SELECT * FROM reservations WHERE owner_pid=? AND command_signature=? AND tool_use_id='' ORDER BY created_at",
                (req.owner_pid, req.command_signature),
            ).fetchall()
            handoff = next((row for row in handoffs
                            if not allocation_is_bound(conn, "direct", row["id"])), None)
            if handoff and handoff["spec_hash"] == req.spec_hash:
                conn.execute("UPDATE reservations SET tool_use_id=?,heartbeat_at=? WHERE id=?", (req.tool_use_id, now, handoff["id"]))
                conn.execute("COMMIT")
                self._mirror()
                return {"allowed": True, "reservation_id": handoff["id"], "reused": True, "request_key": handoff["request_key"]}

            queued_existing = conn.execute(
                "SELECT spec_hash FROM queue WHERE request_key=?", (req.request_key,)
            ).fetchone()
            if queued_existing and queued_existing["spec_hash"] != req.spec_hash:
                conn.execute("COMMIT")
                return {
                    "allowed": False, "reason": "request_spec_mismatch",
                    "request_key": req.request_key,
                }

            conn.execute(
                """INSERT INTO queue
                (request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                 resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,
                 spec_hash,commit_bytes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(request_key) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,
                  tool_use_id=excluded.tool_use_id,priority=excluded.priority,
                  priority_rank=excluded.priority_rank""",
                (
                    req.request_key, req.owner_pid, req.owner_started, req.tool_use_id, req.repo,
                    req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                    PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                    req.spec_hash, req.commit_bytes,
                ),
            )
            ordered = conn.execute("SELECT request_key FROM queue ORDER BY priority_rank,queued_at,request_key").fetchall()
            position = next(i for i, row in enumerate(ordered, 1) if row["request_key"] == req.request_key)
            reason = "capacity"
            allowed = position == 1
            if not metrics["fresh"]:
                allowed = False
                reason = "status_stale"
            elif cfg.get("admission_policy") != "resource-v2" and metrics["light"] in {"ORANGE", "RED"}:
                allowed = False
                reason = f"light_{str(metrics['light']).lower()}"
            elif position != 1:
                allowed = False
                reason = "queue_order"

            if not v2:
                active = conn.execute("SELECT * FROM reservations").fetchall()
                grace = float(cfg["reservation_grace_sec"])
                pending_cpu = sum(float(r["cpu_units"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_ram = sum(float(r["ram_gib"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_commit = sum((r["commit_bytes"] / 2**30 if r["commit_bytes"] is not None else float(r["ram_gib"]))
                                     for r in active if now - float(r["created_at"]) <= grace)
                routed_cpu, routed_ram = self._routed_local_pending(conn, cfg, now)
                pending_cpu += routed_cpu
                pending_ram += routed_ram
                pending_commit += routed_ram
                used_io = sum(int(r["io_slots"]) for r in active)
                if allowed and float(metrics["actual_cpu"]) + pending_cpu + float(req.cpu_units) > float(cfg["local_allocatable_cpu"]):
                    allowed, reason = False, "cpu_capacity"
                if allowed and float(metrics["actual_ram"]) + pending_ram + float(req.ram_gib) > float(cfg["local_allocatable_ram_gib"]):
                    allowed, reason = False, "ram_capacity"
                commit_limit = float(metrics["commit_limit"])
                requested_commit = req.commit_bytes / 2**30 if req.commit_bytes is not None else float(req.ram_gib)
                if allowed and commit_limit and float(metrics["commit_used"]) + pending_commit + requested_commit > commit_limit - float(cfg["local_commit_headroom_gib"]):
                    allowed, reason = False, "commit_capacity"
                if allowed and used_io + int(req.io_slots) > int(cfg["heavy_io_slots"]):
                    allowed, reason = False, "io_capacity"

            details = []
            if v2:
                details = shared_admission_blockers(conn, req, frame, cfg, exempt=bool(exemption))
                if details:
                    allowed, reason = False, details[0]["reason"]
                else:
                    # First feasible request wins. A blocked CPU job must not hold
                    # an unrelated IO job behind it; feasible requests retain priority/FIFO.
                    eligible = None
                    for candidate in conn.execute("SELECT * FROM queue ORDER BY priority_rank,queued_at,request_key"):
                        shape = ResourceRequest(candidate["owner_pid"], candidate["owner_started"], candidate["repo"],
                                                candidate["command_text"], candidate["resource_class"], candidate["priority"],
                                                cpu_units=candidate["cpu_units"], ram_gib=candidate["ram_gib"], io_slots=candidate["io_slots"],
                                                commit_bytes=candidate["commit_bytes"])
                        if not shared_admission_blockers(conn, shape, frame, cfg):
                            eligible = candidate["request_key"]
                            break
                    allowed = eligible == req.request_key
                    reason = "resource_capacity" if allowed else "queue_order"

            # Explicit operator exemption bypasses load/order gates, but still
            # reserves and records usage so non-exempt callers see the pressure.
            if exemption and (not v2 or not details):
                allowed = True

            if allowed:
                reservation_id = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO reservations
                    (id,request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                     resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,created_at,
                     heartbeat_at,expires_at,spec_hash,commit_bytes)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        reservation_id, req.request_key, req.owner_pid, req.owner_started, req.tool_use_id,
                        req.repo, req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                        PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                        now + float(cfg["reservation_ttl_min"]) * 60, req.spec_hash, req.commit_bytes,
                    ),
                )
                conn.execute("DELETE FROM queue WHERE request_key=?", (req.request_key,))
                result = {"allowed": True, "reservation_id": reservation_id, "reused": False, "request_key": req.request_key}
                if exemption:
                    result.update(reason="user_exemption", exemption_id=exemption["id"], exemption_expires_at=exemption["expires_at"])
            else:
                result = {"allowed": False, "reason": reason, "position": position, "request_key": req.request_key}
                if cfg.get("admission_policy") == "resource-v2":
                    result.update(policy="resource-v2", blockers=details)
            conn.execute("COMMIT")
        self._mirror()
        return result

    def retry_queued(
        self,
        request_key: str,
        status: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM queue WHERE request_key=?", (request_key,)).fetchone()
        if row is None:
            with self._db() as conn:
                conn.execute("BEGIN")
                active = conn.execute("SELECT id FROM reservations WHERE request_key=?", (request_key,)).fetchone()
                bound = bool(active and allocation_is_bound(conn, "direct", active["id"]))
                conn.execute("COMMIT")
            if active:
                if bound:
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "reservation_id": active["id"], "request_key": request_key}
                return {"allowed": True, "reservation_id": active["id"], "reused": True, "request_key": request_key}
            return {"allowed": False, "reason": "request_missing", "request_key": request_key}
        request = ResourceRequest(
            owner_pid=row["owner_pid"], owner_started=row["owner_started"], repo=row["repo"],
            command=row["command_text"], resource_class=row["resource_class"], priority=row["priority"],
            tool_use_id=row["tool_use_id"] or "", cpu_units=row["cpu_units"],
            ram_gib=row["ram_gib"], io_slots=row["io_slots"], signature=row["command_signature"],
            commit_bytes=row["commit_bytes"],
        )
        result = self.admit(request, status, config=config, now=now)
        if result.get("allowed"):
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if allocation_is_bound(conn, "direct", result["reservation_id"]):
                    result = {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                              "reservation_id": result["reservation_id"], "request_key": request_key}
                else:
                    conn.execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (result["reservation_id"],))
                conn.execute("COMMIT")
            self._mirror()
        return result
