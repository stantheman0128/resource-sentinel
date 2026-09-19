"""Standalone, read-only exemption display; never changes grant authority.

Provenance: clean_metadata is the minimal prerequisite extracted from the
preexisting local attribution baseline captured in P0 (SHA256 d24c06356e081b05
13ea9b3fdd7e1805d6ad3c5bfd70e8c140214f54fd1a55c4). The bounded DB helpers and
lease projection are extracted from its dashboard baseline (SHA256
95f0c13ce9074e38e2b4a4c077a18d7da19217c4cef79d6b8b543d5983ac1f0b).
The native Claude lookup and three-lookup bound are the subsequent display fix.
No Coordinator, pressure policy, grant migration, or writable DB is imported.
The lookup budget below is an observation-cost bound, not a grant limit.
"""
from __future__ import annotations

import os
import json
import math
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

FIELDS = ('session_name', 'session_id', 'agent', 'project', 'attribution_source')
MAX_SESSION_REGISTRY_BYTES = 16 * 1024
FILETIME_UNIX_EPOCH = 116444736000000000


def clean_metadata(value):
    if not isinstance(value, dict):
        return {}
    result = {}
    for key in FIELDS:
        text = value.get(key)
        if not isinstance(text, str):
            continue
        text = ' '.join(text.split())
        if key == 'project':
            text = text.replace('\\', '/').rstrip('/').split('/')[-1]
        if text:
            result[key] = text[:160]
    return result


def legacy_psutil_epoch(filetime):
    """Reproduce psutil 7's stored double, without an identity tolerance.

    Its Windows _to_unix_time subtracts the epoch as an integer, casts that
    difference to double, then divides by 10,000,000. Changing that order can
    change the result. This compatibility value is for display lookup only;
    full native FILETIME still has to match the registry exactly.
    """
    return float(filetime - FILETIME_UNIX_EPOCH) / 10000000.0


@contextmanager
def native_process_identity(pid):
    """Hold one query-only Windows process handle across metadata validation.

    The yielded callable rechecks that same handle. No process enumeration,
    psutil fallback, command line, environment, or process mutation is used.
    """
    if os.name != 'nt':
        yield lambda: None
        return
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessId.argtypes = (wintypes.HANDLE,)
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x1000 | 0x100000, False, pid)  # QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    if not handle:
        yield lambda: None
        return
    try:
        def identity():
            # WAIT_TIMEOUT at timeout=0 means still alive, including processes
            # whose eventual exit code happens to equal STILL_ACTIVE (259).
            if kernel.WaitForSingleObject(handle, 0) != 258 or kernel.GetProcessId(handle) != pid:
                return None
            created, exited, system, user = (wintypes.FILETIME() for _ in range(4))
            if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                          ctypes.byref(system), ctypes.byref(user)):
                return None
            return (created.dwHighDateTime << 32) | created.dwLowDateTime
        yield identity
    finally:
        kernel.CloseHandle(handle)


def _registry_filetime(value):
    if isinstance(value, str) and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    if type(value) is not int or not FILETIME_UNIX_EPOCH < value < 2**64:
        return None
    return value


def _read_claude_registry(home, pid):
    # The PID is already a bounded integer. Never use a registry field as a
    # filename or search other sessions when this exact file is unavailable.
    home = Path(home).resolve(strict=True)
    directory = home / 'sessions'
    path = directory / f'{pid}.json'
    if directory.resolve(strict=True) != directory or path.resolve(strict=True) != path:
        return None  # reject observable symlink / junction redirection
    # This local display lookup is not a hostile same-user filesystem sandbox;
    # a concurrently replaced directory can still race these path checks.
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SESSION_REGISTRY_BYTES or
            getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        return None
    with path.open('rb') as stream:
        raw = stream.read(MAX_SESSION_REGISTRY_BYTES + 1)
    if len(raw) > MAX_SESSION_REGISTRY_BYTES:
        return None
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate registry field')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique_keys)
    return value if isinstance(value, dict) else None


def claude_session_metadata(pid, started, *, home=None, process_identity=None):
    """Read-only labels for one occupied legacy lease with no recorded labels.

    Registry PID and full creation FILETIME must match a held native handle;
    the legacy lease timestamp must also exactly match psutil's conversion.
    Failure returns no attribution and never changes the lease or its state.
    """
    if (type(pid) is not int or not 0 < pid <= 0xffffffff or isinstance(started, bool) or
            not isinstance(started, (int, float)) or not math.isfinite(started) or started <= 0):
        return {}
    process_identity = native_process_identity if process_identity is None else process_identity
    home = Path.home() / '.claude' if home is None else home
    try:
        with process_identity(pid) as identity:
            native = identity()
            if _registry_filetime(native) is None or started != legacy_psutil_epoch(native):
                return {}
            record = _read_claude_registry(home, pid)
            if (not record or type(record.get('pid')) is not int or record['pid'] != pid or
                    _registry_filetime(record.get('procStart')) != native):
                return {}
            if (not isinstance(record.get('sessionId'), str) or not record['sessionId'].strip() or
                    len(record['sessionId']) > 160 or not isinstance(record.get('name'), str) or
                    not record['name'].strip() or len(record['name']) > 1000):
                return {}
            metadata = clean_metadata(dict(session_name=record['name'], session_id=record['sessionId'],
                                           agent='Claude', project=record.get('cwd'),
                                           attribution_source='claude_session_registry'))
            # Keep the handle alive until all file reads are done, and reject
            # exit during the observation. The display can still go stale later.
            return metadata if identity() == native else {}
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        return {}


MAX_LABEL_LOOKUPS = 3
MAX_ROWS = 500

@contextmanager
def read_db(path):
    # URI mode=ro prevents implicit database creation, migrations and cleanup.
    connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=.1)
    connection.row_factory = sqlite3.Row
    deadline = time.monotonic() + .45
    connection.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        connection.execute('BEGIN')
        yield connection
    finally:
        connection.close()


def bounded_rows(conn, sql, params=()):
    rows = conn.execute(sql, params).fetchmany(MAX_ROWS + 1)
    if len(rows) > MAX_ROWS:
        raise ValueError('observation_row_limit')
    return [dict(row) for row in rows]


def exemption_leases(data_dir, nodes, now, *, limit=None, metadata_resolver=None):
    """Project lease facts without inferring enforcement in older installations.

    limit may be supplied from the installed grant implementation's public
    constant. None remains unknown. This reader never grants or renews leases.
    """
    if limit is not None and (type(limit) is not int or limit <= 0):
        raise ValueError('invalid_observed_limit')
    metadata_resolver = claude_session_metadata if metadata_resolver is None else metadata_resolver
    path = Path(data_dir) / 'exemptions.sqlite3'
    if not path.exists():
        return dict(state='ok', occupied=0, limit=limit, next_expiry=None, leases=[])
    with read_db(path) as conn:
        # Active leases plus recent history, without the private authorization reason.
        columns = {r[1] for r in conn.execute('PRAGMA table_info(exemptions)')}
        metadata_column = 'owner_metadata' if 'owner_metadata' in columns else "'{}' AS owner_metadata"
        rows = bounded_rows(conn, f'''SELECT id,root_pid,root_started,created_at,expires_at,revoked_at,{metadata_column}
            FROM exemptions WHERE (revoked_at IS NULL AND expires_at>?) OR created_at>?
            ORDER BY created_at DESC''', (now, now-86400))
    metadata_lookups = 0
    for row in rows:
        try:
            metadata = clean_metadata(json.loads(row.pop('owner_metadata')))
        except (ValueError, TypeError):
            metadata = {}
        row['occupies_slot'] = row['revoked_at'] is None and row['expires_at'] > now
        # Existing recorded metadata stays authoritative. Enrich only occupied
        # slots, after closing the read transaction; never scan historical PIDs.
        if not metadata and row['occupies_slot'] and metadata_lookups < MAX_LABEL_LOOKUPS:
            metadata_lookups += 1
            metadata = metadata_resolver(row['root_pid'], row['root_started'])
        row.update(metadata)
        row.setdefault('attribution_source', 'unrecorded')
        # A missing PID in a reused/possibly partial CIM observation cannot
        # establish exit: collection may lack access, or the grant may be newer.
        # Even a different birth identifies a mismatch, not an observed exit of
        # the held lease process. None of these display states releases its slot.
        row['state'] = ('revoked' if row['revoked_at'] is not None else 'expired' if row['expires_at'] <= now else
                        'identity_unknown' if nodes is None or row['root_pid'] not in nodes else 'active' if
                        abs(nodes[row['root_pid']]-row['root_started']) < .01 else 'identity_mismatch')
    occupied = [r for r in rows if r['occupies_slot']]
    return dict(state='ok' if all(r['state'] == 'active' for r in occupied) else 'unknown', occupied=len(occupied),
                limit=limit, next_expiry=min((r['expires_at'] for r in occupied), default=None), leases=rows)
