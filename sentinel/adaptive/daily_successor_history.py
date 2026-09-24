"""Bounded immutable succession data; never readiness or restart authority.

Appending is only one step of the future original-owner atomic transition. This
module neither commits nor replaces a generation, removes a freeze, installs a
capacity UDF, closes an owner or starts a process. A persisted archive cannot
reconstruct the original retirement operation needed by a successor.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import UUID

from . import daily_generation as generation
from .contracts import ProcessIdentity
from .daily_retirement_fence import OWNER_BINDING_FIELDS, read_retirement
from .policy import PolicyGuard


TABLE = "adaptive_generation_successions"
MAX_ROWS = 4096
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
_ROW_OVERHEAD = 64 + 36 * 3 + 8
_MAX_SCHEMA_BYTES = 65536
_FIELDS = ("ordinal", "transition_id", "predecessor_generation", "successor_generation", "record_json", "sha256")
_RECORD_FIELDS = {"schema_version", "transition_id", "predecessor", "retirement", "successor", "inventory_digest", "policy"}
_SCHEMA = f"""CREATE TABLE {TABLE} (
    ordinal INTEGER PRIMARY KEY CHECK(typeof(ordinal)='integer' AND ordinal>0),
    transition_id TEXT NOT NULL UNIQUE,
    predecessor_generation TEXT NOT NULL UNIQUE,
    successor_generation TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    sha256 TEXT NOT NULL
)"""
_TRIGGERS = {f"{TABLE}_{event.lower()}": f"CREATE TRIGGER {TABLE}_{event.lower()} "
    f"BEFORE {event} ON {TABLE} BEGIN SELECT RAISE(ABORT,'daily_successor_history_immutable'); END"
    for event in ("UPDATE", "DELETE")}
_DOMAIN = b"resource-sentinel.daily-succession.v1\x00"


class SuccessorHistoryError(RuntimeError):
    def __init__(self, reason):
        self.reason = "daily_successor_history_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise SuccessorHistoryError(reason)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail("invalid_json")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate_key")
        result[key] = value
    return result


def _decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: _fail("invalid_json"))
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise SuccessorHistoryError("invalid_json") from None


def _uuid(value):
    try:
        return type(value) is str and UUID(value).int != 0 and str(UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _generation(value, state):
    if type(value) is not dict or set(value) != generation._GENERATION_FIELDS:
        _fail("generation_invalid")
    if (type(value["singleton"]) is not int or value["singleton"] != 1 or
            type(value["schema_version"]) is not int or value["schema_version"] != 1 or
            value["state"] != state or not _uuid(value["generation"]) or
            not _uuid(value["readiness_instance_id"]) or not generation._digest(value["source_digest"]) or
            not generation._digest(value["config_digest"])):
        _fail("generation_invalid")
    bounds = {"source_manifest_json": 1024 * 1024, "source_root": 32768, "ledger_path": 32768,
              "owner_identity_json": 1024, "ledger_identity_json": 128}
    for key, maximum in bounds.items():
        if (type(value[key]) is not str or not 0 < len(value[key]) <= maximum or
                any(ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value[key]) or
                len(value[key].encode("utf-8")) > maximum):
            _fail("generation_invalid")
    if any(not Path(value[key]).is_absolute() or ".." in Path(value[key]).parts or
            str(Path(value[key])) != value[key] for key in ("source_root", "ledger_path")):
        _fail("generation_invalid")
    try:
        manifest = generation.SourceManifest.from_dict(_decode(value["source_manifest_json"]))
        identity = ProcessIdentity.from_dict(_decode(value["owner_identity_json"]))
    except (generation.DailyGenerationUnavailable, ValueError, TypeError, KeyError):
        raise SuccessorHistoryError("generation_invalid") from None
    ledger = _decode(value["ledger_identity_json"])
    if (manifest.digest != value["source_digest"] or type(ledger) is not list or len(ledger) != 2 or
            any(type(item) is not str or not item.isascii() or not item.isdecimal() or
                not 0 < len(item) <= 39 or str(int(item)) != item for item in ledger) or
            not 0 <= int(ledger[0]) < 1 << 128 or not 0 < int(ledger[1]) < 1 << 128 or
            _canonical(manifest.to_dict()).decode("ascii") != value["source_manifest_json"] or
            _canonical(identity.to_dict()).decode("ascii") != value["owner_identity_json"] or
            _canonical(ledger).decode("ascii") != value["ledger_identity_json"]):
        _fail("generation_invalid")
    return identity


def _record(value):
    from .daily_retirement_fence import _FIELDS as retirement_fields
    if (type(value) is not dict or set(value) != _RECORD_FIELDS or
            type(value["schema_version"]) is not int or value["schema_version"] != 1 or
            not _uuid(value["transition_id"]) or not generation._digest(value["inventory_digest"])):
        _fail("record_invalid")
    old, new, retirement, policy = (value[key] for key in ("predecessor", "successor", "retirement", "policy"))
    old_identity, new_identity = _generation(old, "DRAINING"), _generation(new, "ACTIVE")
    # This route preserves source/config/ledger and the same live process. The
    # fresh process handle, cohort and native cleanup are separately proved by
    # the original operation, never by these serialized values.
    immutable = generation._GENERATION_FIELDS - {"generation", "state", "readiness_instance_id"}
    if (any(old[key] != new[key] for key in immutable) or old_identity != new_identity or
            old["generation"] == new["generation"] or old["readiness_instance_id"] == new["readiness_instance_id"]):
        _fail("successor_binding_changed")
    if (type(retirement) is not dict or set(retirement) != set(retirement_fields) or
            type(retirement["singleton"]) is not int or retirement["singleton"] != 1 or
            type(retirement["schema_version"]) is not int or retirement["schema_version"] != 1 or
            retirement["phase"] != "SEALED" or not generation._digest(retirement["seal_digest"]) or
            any(retirement[key] != old[key] for key in OWNER_BINDING_FIELDS) or
            not _uuid(retirement["request_id"]) or not _uuid(retirement["freeze_policy_nonce"]) or
            type(retirement["freeze_registry_revision"]) is not int or
            not 0 <= retirement["freeze_registry_revision"] < 1 << 63):
        _fail("retirement_invalid")
    if (type(policy) is not dict or set(policy) != {"instance_id", "logon_id", "nonce"} or
            not _uuid(policy["instance_id"]) or not _uuid(policy["nonce"]) or
            policy["logon_id"] != old_identity.logon_id or
            retirement["policy_instance_id"] != policy["instance_id"] or
            retirement["policy_logon_id"] != policy["logon_id"] or
            policy["nonce"] == retirement["freeze_policy_nonce"]):
        _fail("policy_invalid")


def _normalized(sql):
    return " ".join(sql.split()) if type(sql) is str else ""


def _schema(conn):
    # SQLite bounds every returned variable field before Python receives it.
    # Include all attached objects and reserved names, including a differently
    # named trigger, a shadow object or an extra index. Never repair them.
    bounded = ("typeof(name)='text' AND length(CAST(name AS BLOB)) BETWEEN 1 AND 128 "
        "AND typeof(type)='text' AND length(CAST(type AS BLOB)) BETWEEN 1 AND 7 "
        "AND typeof(tbl_name)='text' AND length(CAST(tbl_name AS BLOB)) BETWEEN 1 AND 128 "
        f"AND (sql IS NULL OR (typeof(sql)='text' AND length(CAST(sql AS BLOB))<={_MAX_SCHEMA_BYTES}))")
    fields = ",".join(f"CASE WHEN {bounded} THEN {key} END" for key in ("name", "type", "tbl_name", "sql"))
    rows = conn.execute(f"SELECT {fields},CASE WHEN {bounded} THEN 1 ELSE 0 END "
        "FROM main.sqlite_master WHERE name=? OR tbl_name=? OR name GLOB ? LIMIT 7",
        (TABLE, TABLE, TABLE + "_*")).fetchall()
    if not rows:
        return False
    expected = {TABLE: ("table", TABLE, _normalized(_SCHEMA)),
        **{name: ("trigger", TABLE, _normalized(sql)) for name, sql in _TRIGGERS.items()},
        **{f"sqlite_autoindex_{TABLE}_{number}": ("index", TABLE, "") for number in (1, 2, 3)}}
    if (len(rows) != len(expected) or any(row[4] != 1 for row in rows) or
            {row[0]: (row[1], row[2], _normalized(row[3])) for row in rows} != expected or
            tuple(row[1] for row in conn.execute(f"PRAGMA main.table_info({TABLE})")) != _FIELDS):
        _fail("schema_invalid")
    return True


@dataclass(frozen=True)
class ArchivedSuccession:
    ordinal: int
    record: bytes
    sha256: str
    # Exact SQL cells for bounded aggregate inventory consumers. Data only;
    # never reconstruct an authority object or print this private preimage.
    _row: tuple = field(repr=False)


@dataclass(frozen=True)
class SuccessionHistory:
    entries: tuple[ArchivedSuccession, ...]
    bytes_used: int

    @property
    def rows_used(self):
        return len(self.entries)


def _budget(max_rows, max_bytes):
    if (type(max_rows) is not int or not 0 <= max_rows <= MAX_ROWS or
            type(max_bytes) is not int or not 0 <= max_bytes <= MAX_BYTES):
        _fail("budget_invalid")


def _transaction(conn):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _fail("transaction_required")


def _continues(previous, predecessor):
    return previous is None or dict(previous, state="DRAINING") == predecessor


def read_successor_history(conn, *, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    """Read complete bounded immutable data, with no authority or mutation."""
    _transaction(conn)
    _budget(max_rows, max_bytes)
    if not _schema(conn):
        return SuccessionHistory((), 0)
    # Bound every variable field before fetching payloads or decoding JSON.
    sizes = conn.execute("SELECT CASE WHEN typeof(ordinal)='integer' THEN ordinal END,"
        "typeof(record_json),length(CAST(record_json AS BLOB)),"
        "typeof(sha256),length(CAST(sha256 AS BLOB)),typeof(transition_id),length(CAST(transition_id AS BLOB)),"
        "typeof(predecessor_generation),length(CAST(predecessor_generation AS BLOB)),"
        f"typeof(successor_generation),length(CAST(successor_generation AS BLOB)) FROM main.{TABLE} ORDER BY ordinal LIMIT ?",
        (max_rows + 1,)).fetchall()
    if len(sizes) > max_rows:
        _fail("rows_exceeded")
    total = 0
    for expected, row in enumerate(sizes, 1):
        if (type(row[0]) is not int or row[0] != expected or row[1] != "text" or
                type(row[2]) is not int or not 0 < row[2] <= MAX_RECORD_BYTES or
                tuple(row[3:]) != ("text", 64, "text", 36, "text", 36, "text", 36)):
            _fail("row_invalid")
        total += row[2] + _ROW_OVERHEAD
        if total > max_bytes:
            _fail("bytes_exceeded")
    entries, previous, seen, transitions, readiness, requests, nonces = [], None, set(), set(), set(), set(), set()
    bounded = ("typeof(ordinal)='integer' AND ordinal>0 AND typeof(record_json)='text' "
        f"AND length(CAST(record_json AS BLOB)) BETWEEN 1 AND {MAX_RECORD_BYTES} AND " + " AND ".join(
            f"typeof({key})='text' AND length(CAST({key} AS BLOB))={length}"
            for key, length in (("sha256", 64), ("transition_id", 36),
                ("predecessor_generation", 36), ("successor_generation", 36))))
    projection = ",".join(f"CASE WHEN {bounded} THEN {key} END" for key in _FIELDS)
    for row in conn.execute(f"SELECT {projection},CASE WHEN {bounded} THEN 1 ELSE 0 END "
            f"FROM main.{TABLE} ORDER BY ordinal LIMIT ?", (max_rows + 1,)):
        if len(entries) >= len(sizes):
            _fail("history_changed")
        if row[6] != 1:
            _fail("history_changed")
        ordinal, transition, predecessor, successor, document, digest = row[:6]
        raw = document.encode("utf-8")
        if len(raw) != sizes[len(entries)][2] or ordinal != len(entries) + 1:
            _fail("history_changed")
        value = _decode(raw)
        _record(value)
        if (_canonical(value) != raw or digest != hashlib.sha256(_DOMAIN + raw).hexdigest() or
                transition != value["transition_id"] or predecessor != value["predecessor"]["generation"] or
                successor != value["successor"]["generation"] or transition in transitions or successor in seen or
                predecessor == successor or not _continues(previous, value["predecessor"]) or
                value["successor"]["readiness_instance_id"] in readiness or
                value["retirement"]["request_id"] in requests or value["policy"]["nonce"] in nonces):
            _fail("chain_invalid")
        seen.update((predecessor, successor))
        transitions.add(transition)
        readiness.update((value["predecessor"]["readiness_instance_id"], value["successor"]["readiness_instance_id"]))
        requests.add(value["retirement"]["request_id"])
        nonces.add(value["policy"]["nonce"])
        previous = value["successor"]
        entries.append(ArchivedSuccession(ordinal, raw, digest, tuple(row[:6])))
    if len(entries) != len(sizes):
        _fail("history_changed")
    return SuccessionHistory(tuple(entries), total)


def append_successor_history_locked(conn, *, retirement, successor_row, guard, transition_id,
                                    max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    """Archive exact data inside the caller's original transition transaction.

    The caller must also perform its reviewed live generation/fence replacement
    in this transaction, then positively settle and acknowledge it. This helper
    deliberately does none of those things and never commits. Replaying the same
    exact record returns the original row; a changed replay refuses.
    """
    from .daily_retirement import DailyRetirementOperation
    from .daily_retirement_inventory import retired_inventory_preimage
    _transaction(conn)
    _budget(max_rows, max_bytes)
    if type(retirement) is not DailyRetirementOperation or type(guard) is not PolicyGuard:
        _fail("original_retirement_required")
    retirement.assert_successor_predecessor()
    retired_inventory_preimage(retirement)  # Original registered snapshot, not the digest alone.
    if (guard is retirement._freeze_guard or guard is retirement._seal_guard or
            guard.nonce in {retirement._freeze_guard.nonce, retirement._seal_guard.nonce}):
        _fail("new_policy_guard_required")
    retirement.policy.assert_held(guard)
    if (not generation._ledger_matches(conn, retirement.owner.ledger_path) or
            generation._ledger_identity(retirement.owner.ledger_path) != retirement.owner.ledger_identity):
        _fail("original_transaction_required")
    runtime = retirement.policy.revalidate(conn, guard)
    predecessor = generation.read_generation(conn)
    sealed = read_retirement(conn)
    if (predecessor != dict(retirement._generation_row, state="DRAINING") or sealed != retirement._seal_row or
            runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE"):
        _fail("predecessor_changed")
    value = dict(schema_version=1, transition_id=transition_id, predecessor=predecessor,
        retirement=sealed, successor=successor_row, inventory_digest=retirement._seal_inventory_digest,
        policy=dict(instance_id=guard.binding.instance_id, logon_id=guard.binding.logon_id, nonce=guard.nonce))
    _record(value)
    raw = _canonical(value)
    if len(raw) > MAX_RECORD_BYTES:
        _fail("record_oversized")
    history = read_successor_history(conn, max_rows=max_rows, max_bytes=max_bytes)
    for entry in history.entries:
        old = _decode(entry.record)
        if old["transition_id"] == transition_id:
            if entry.record != raw:
                _fail("replay_changed")
            return entry
    if len(history.entries) >= max_rows or history.bytes_used + len(raw) + _ROW_OVERHEAD > max_bytes:
        _fail("budget_exceeded")
    if history.entries and not _continues(_decode(history.entries[-1].record)["successor"], predecessor):
        _fail("chain_invalid")
    if not _schema(conn):
        conn.execute(_SCHEMA)
        for sql in _TRIGGERS.values():
            conn.execute(sql)
    digest, ordinal = hashlib.sha256(_DOMAIN + raw).hexdigest(), len(history.entries) + 1
    conn.execute(f"INSERT INTO main.{TABLE} VALUES(?,?,?,?,?,?)", (ordinal, transition_id,
        predecessor["generation"], successor_row["generation"], raw.decode("ascii"), digest))
    return read_successor_history(conn, max_rows=max_rows, max_bytes=max_bytes).entries[-1]
