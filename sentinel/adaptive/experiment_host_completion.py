"""Original aggregate retirement; snapshots are bounded history, never authority.

Seal the original owner, consume its authenticated terminal host receipts, settle
actual CreationAttempts and transport custody, and archive exact daily rows.
Managed Jobs additionally require their actual isolated terminal/prelaunch custody
records. Bind/publication ACKs and actor exit cannot substitute for host cleanup.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading

from . import experiment_host_ledger as ledger, experiment_host_backing as backing
from .experiment_host_creation import CreationAttempt
from .experiment_host_roles import role_spec_from_dict
from .experiment_child_host import ChildRegistrationPublication
# Eager fixed data validators prevent cold source-import IO during a history
# reader's existing SQL transaction. These imports acquire no native owner.
from . import experiment_host_retirement_transport, terminal_receipt

DOMAIN = "sentinel-production-scope-completion-v1"
VERSION = 3  # distinct from the two existing S1 completion versions
HOST_VERSION = 4
HOST_DOMAIN = "sentinel-production-scope-completion-v2"
_TOKEN = object()
_ORIGINALS = {}
_COLLECTION_NAMES = ("_pending_members", "_published_actors", "_child_registrations",
    "_accepted_children", "_backing_publications", "_backing_members", "_job_publications",
    "_job_members", "_released_roles", "_role_release_data", "_registration_publications")


class ProductionCompletionError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = "production_completion_" + reason, owner
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise ProductionCompletionError(reason, owner)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


def digest_record(value):
    domain = HOST_DOMAIN if value.get("schema_version") == HOST_VERSION else DOMAIN
    return hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()


class ProductionScopeCompletion:
    """One retained original completion, registered before retirement begins."""
    def __init__(self, owner, *, _token=None):
        from .experiment_host_scope import ProductionExperimentScope
        if _token is not _TOKEN or type(owner) is not ProductionExperimentScope:
            _fail("original_factory_required")
        self.owner, self._owner = owner, owner
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._attempts = owner._attempts
        self._attempt_items = tuple(owner._attempts.items())
        self._collections = tuple((getattr(owner, name), tuple(getattr(owner, name).items()))
                                  for name in _COLLECTION_NAMES)
        self._record = self.digest = self._publication_pin = None
        self._dispatcher = getattr(owner, "_host_dispatcher", None)
        self._services = tuple(getattr(owner, name) for name in
            ("_transport_service", "_backing_service", "_job_service", "_retirement_service"))
        self._supervisor = owner._supervisor_host
        self._supervisor_integration = getattr(owner, "_supervisor_integration", None)
        self._receipts = None
        self._journals, self._manifests = {}, {}
        self._file_cleanup_unknown = False
        _ORIGINALS[id(self)] = self

    def __reduce__(self):
        raise TypeError("production_completion_not_serializable")

    def _original(self):
        from .experiment_host_scope import ProductionExperimentScope
        owner = self.owner
        if (type(self) is not ProductionScopeCompletion or self.owner is not self._owner or
                _ORIGINALS.get(id(self)) is not self or getattr(owner, "_completion", None) is not self or
                self._pid != os.getpid() or self._thread is not threading.current_thread() or
                owner._attempts is not self._attempts or
                tuple(owner._attempts.items()) != self._attempt_items):
            _fail("original_changed", owner)
        ProductionExperimentScope._assert_ledger_original(owner, owner.demand, owner.spec)
        if owner._sealed is not True or owner.demand._native_preparation_sealed is not True:
            _fail("seal_required", owner)
        for name, (original, items) in zip(_COLLECTION_NAMES, self._collections):
            current = getattr(owner, name)
            if current is not original or tuple(current.items()) != items:
                _fail("original_inventory_changed", owner)
        if (owner._active_sql is not None or owner._guard is not None or owner._guard_unknown or
                owner._scope_cleanup_error is not None or owner._creation_gate is not None or
                any(not item.closed or item.close_unknown or item.rollback_unknown
                    for item in owner._sql_attempts)):
            _fail("original_custody_pending", owner)
        if (getattr(owner, "_host_dispatcher", None) is not self._dispatcher or
                tuple(getattr(owner, name) for name in ("_transport_service", "_backing_service",
                    "_job_service", "_retirement_service")) != self._services or
                owner._supervisor_host is not self._supervisor or
                getattr(owner, "_supervisor_integration", None) is not self._supervisor_integration or
                self._file_cleanup_unknown):
            _fail("original_custody_changed", owner)
        if self._dispatcher is None and any(value is not None for value in self._services):
            _fail("original_transport_retirement_required", owner)
        if self._supervisor is not None and self._supervisor_integration is None:
            _fail("original_supervisor_retirement_required", owner)
        if self._receipts is not None:
            self._host_receipts()
        if self._record is not None and json.loads(self._record)["schema_version"] == HOST_VERSION:
            self._publication_originals()
        for member_id, publication in owner._registration_publications.items():
            original = owner._child_registrations.get(member_id)
            if (type(publication) is not ChildRegistrationPublication or original is None or
                    publication.registration is not original[1] or
                    publication.directory != owner.demand.directory):
                _fail("original_registration_retirement_required", owner)
            ChildRegistrationPublication._assert_original(publication)
        for _, attempt in self._attempt_items:
            CreationAttempt.assert_original(attempt, owner)

    def _host_receipts(self):
        from .experiment_host_retirement_transport import (AcceptedHostRetirement,
            retained_retirements)
        owner = self.owner
        if not owner._accepted_children:
            if owner._released_roles or owner._backing_publications or owner._job_publications:
                _fail("authenticated_host_retirement_required", owner)
            receipts = () if owner._retirement_service is None else retained_retirements(owner)
        else:
            if owner._retirement_service is None:
                _fail("authenticated_host_retirement_required", owner)
            receipts = retained_retirements(owner)
        if (len(receipts) != len(owner._accepted_children) or
                {id(item.registration) for item in receipts} !=
                {id(item) for item in owner._accepted_children.values()} or
                any(type(item) is not AcceptedHostRetirement for item in receipts)):
            _fail("authenticated_host_retirement_required", owner)
        if self._receipts is not None and (len(self._receipts) != len(receipts) or
                any(a is not b for a, b in zip(self._receipts, receipts))):
            _fail("original_retirement_changed", owner)
        for item in receipts:
            AcceptedHostRetirement.assert_original(item, owner)
        return receipts

    def _publication_originals(self):
        from .experiment_job_publication import _ParentPublication
        from .experiment_host_scope import _BackingPublication
        for entry in self.owner._job_publications.values():
            if type(entry) is not _ParentPublication:
                _fail("original_job_publication_required", self.owner)
            _ParentPublication.require(entry, entry.request, entry.registration)
        for entry in self.owner._backing_publications.values():
            if type(entry) is not _BackingPublication:
                _fail("original_backing_publication_required", self.owner)
            _BackingPublication.require(entry, entry.request, entry.registration)
            if entry.operation is None:
                _fail("original_backing_publication_required", self.owner)
            backing.ParentAdmissionBacking._original(entry.operation)

    def _closed(self):
        self._original()
        if self._receipts is None:
            _fail("authenticated_host_retirement_required", self.owner)
        if self._dispatcher is not None:
            from .experiment_host_dispatch import ProductionHostDispatcher
            if type(self._dispatcher) is not ProductionHostDispatcher:
                _fail("original_transport_retirement_required", self.owner)
            ProductionHostDispatcher.assert_closed(self._dispatcher)
        if self._supervisor_integration is not None:
            from .experiment_supervisor import ExperimentSupervisor
            if type(self._supervisor_integration) is not ExperimentSupervisor:
                _fail("original_supervisor_retirement_required", self.owner)
            ExperimentSupervisor.assert_closed(self._supervisor_integration)
        for publication in self.owner._registration_publications.values():
            ChildRegistrationPublication.assert_closed(publication)
        for _, attempt in self._attempt_items:
            if attempt.native_settled is not True:
                _fail("original_creation_unsettled", self.owner)
            if not attempt.never_created and (attempt._create_state != "created" or
                    attempt._dead is not True or attempt._process_closed is not True or
                    attempt._thread_closed is not True or attempt._process_close_unknown or
                    attempt._thread_close_unknown or attempt._duplicate_close_unknown or
                    (attempt.process is not None and (not attempt._duplicate_closed or
                        attempt.process._handle is not None or attempt.process._close_outcome_unknown))):
                _fail("original_native_cleanup_unverified", self.owner)

    def assert_original(self):
        self._closed()
        if (self._record is None or self._publication_pin != (self._record, self.digest) or
                self.digest != digest_record(json.loads(self._record))):
            _fail("completion_unsettled", self.owner)
        return self

    def snapshot(self):
        self.assert_original()
        return json.loads(self._record)

    def revalidate_isolated_history(self):
        """Observe isolated evidence before a new daily POLICY/SQL publication."""
        record = self.snapshot()
        if record["schema_version"] == HOST_VERSION:
            current = _isolated_custody(self, record["host_rows"], record["backing_rows"],
                                        record["host_retirements"])
            if current != record["isolated_custody"]:
                _fail("isolated_custody_changed", self.owner)
        return self


def retire(owner):
    """Seal and retire originals; never kill, loosen a cap or free capacity."""
    from .experiment_host_scope import ProductionExperimentScope
    if type(owner) is not ProductionExperimentScope:
        _fail("original_scope_required")
    with owner._lock:
        ProductionExperimentScope.seal_new_work(owner)
        result = getattr(owner, "_completion", None)
        if result is None:
            result = ProductionScopeCompletion(owner, _token=_TOKEN)
            owner._completion = result
        if type(result) is not ProductionScopeCompletion:
            _fail("original_completion_changed", owner)
        result._original()
        if result._record is not None:
            return result.assert_original()
        try:
            # Terminal ACKs must arrive while the original listener is still
            # open. Exit alone can never replace the child's actual host close.
            result._receipts = result._host_receipts()
            if result._supervisor_integration is not None:
                from .experiment_supervisor import ExperimentSupervisor
                if type(result._supervisor_integration) is not ExperimentSupervisor:
                    _fail("original_supervisor_retirement_required", owner)
                ExperimentSupervisor.close(result._supervisor_integration)
            for _, attempt in result._attempt_items:
                CreationAttempt.settle_native(attempt, owner)
            if result._dispatcher is not None:
                from .experiment_host_dispatch import ProductionHostDispatcher
                if type(result._dispatcher) is not ProductionHostDispatcher:
                    _fail("original_transport_retirement_required", owner)
                ProductionHostDispatcher.close(result._dispatcher)
            for publication in owner._registration_publications.values():
                ChildRegistrationPublication.close(publication)
            result._closed()
            with owner._operation() as guard:
                with owner._sql(owner.demand.ledger_path) as conn:
                    inventory, _, tables = ledger._inventory(conn, owner._daily_policy, guard)
                    rows = {table: list(tables.get(table, ())) for table in ledger.TABLES}
                    budget = ledger._Budget()
                    backing_rows = [row for row in backing.history_rows_locked(conn, budget=budget)
                                    if row["scope_id"] == owner.scope_id]
                    revision = owner._daily_policy.revalidate(conn, guard)["registry_revision"]
            result._closed()
            host_receipts = [item.snapshot() for item in result._receipts]
            full = bool(host_receipts or backing_rows or rows[ledger.JOBS_TABLE])
            custody = _isolated_custody(result, rows, backing_rows, host_receipts) if full else []
            scope_rows = rows[ledger.SCOPES_TABLE]
            if len(scope_rows) != 1 or scope_rows[0]["scope_id"] != owner.scope_id:
                _fail("original_registry_missing", owner)
            outcomes = []
            for member in owner.plan.members:
                if member.kind != "infrastructure":
                    continue
                attempt = owner._attempts.get(member.member_id)
                outcomes.append(dict(member_id=member.member_id,
                    outcome="never_entered" if attempt is None else
                        "never_created" if attempt.never_created else "exited_closed",
                    identity=None if attempt is None or attempt.process is None else
                        attempt.process.identity.to_dict()))
            record = dict(schema_version=HOST_VERSION if full else VERSION,
                domain=HOST_DOMAIN if full else DOMAIN, disposition="FINISHED",
                demand=owner.demand._completion_binding(), scope_id=owner.scope_id,
                declaration=owner.plan.to_dict(), host_rows=rows, actor_outcomes=outcomes,
                registration_custody=[dict(member_id=member_id,
                    request_id=publication.registration.manifest.request_id,
                    publication_sha256=hashlib.sha256(publication.raw).hexdigest(),
                    outcome="published_closed" if publication.published else
                        "failed_closed" if publication.started else "never_entered")
                    for member_id, publication in owner._registration_publications.items()],
                registry_revision=revision, reservation_id=scope_rows[0]["reservation_id"],
                daily_binding_sha256=scope_rows[0]["demand_binding_sha256"])
            if full:
                record.update(backing_rows=backing_rows, host_retirements=host_receipts,
                              isolated_custody=custody)
            validate_record(record)
            result._record, result.digest = _canonical(record), digest_record(record)
            result._publication_pin = (result._record, result.digest)
            return result.assert_original()
        except BaseException as error:
            owner._retain(error)
            raise


def _isolated_custody(completion, rows, backing_rows, receipts):
    """Verify authenticated original custody against actual isolated history.

    The read-only verifier borrows the existing store's schema routines with
    this explicit isolated connection. It never constructs a migration-owning
    store or turns a journal/SQL snapshot into native cleanup authority.
    """
    from . import terminal_receipt, prelaunch_receipt, experiment_local_backing as local_backing
    from .recovery_journal import RecoveryJournal
    from .experiment_host_roles import GuardianRoleSpec
    from .experiment_job_publication import _ParentPublication
    from .experiment_host_scope import _BackingPublication
    owner = completion.owner
    jobs = rows[ledger.JOBS_TABLE]
    if any(job["kind"] != "managed" for job in jobs):
        _fail("original_query_job_retirement_required", owner)
    claims = {}
    for receipt in receipts:
        if receipt["role"] == "guardian":
            for claim in receipt["closure"]["jobs"]:
                execution = claim["execution_id"]
                if execution in claims:
                    _fail("job_retirement_duplicate", owner)
                claims[execution] = (receipt, claim)
    wrappers = {receipt["actor_member_id"]: receipt for receipt in receipts if receipt["role"] == "wrapper"}
    unused = {row["isolated_execution_id"]: wrappers[row["wrapper_member_id"]]
              for row in backing_rows if row["wrapper_member_id"] in wrappers and
              "admission_retirement" in wrappers[row["wrapper_member_id"]]["closure"]}
    if ({job["isolated_execution_id"] for job in jobs} != set(claims) or set(claims) & set(unused) or
            {row["isolated_execution_id"] for row in backing_rows} != set(claims) | set(unused)):
        _fail("authenticated_job_retirement_required", owner)
    # A published SQL intent alone does not prove an original publication. Both
    # immutable parent objects must still be present in their original maps.
    if len(owner._job_members) != len(jobs) or len(owner._backing_members) != len(backing_rows):
        _fail("original_publication_missing", owner)
    for job in jobs:
        entry = owner._job_members.get(job["member_id"])
        if type(entry) is not _ParentPublication or not any(
                item is entry for item in owner._job_publications.values()):
            _fail("original_job_publication_required", owner)
        _ParentPublication.require(entry, entry.request, entry.registration)
        if any(getattr(entry.binding, key) != job[key] for key in ledger.JobBinding.__dataclass_fields__):
            _fail("original_job_publication_changed", owner)
    for row in backing_rows:
        entry = owner._backing_members.get(row["member_id"])
        if type(entry) is not _BackingPublication or not any(
                item is entry for item in owner._backing_publications.values()):
            _fail("original_backing_publication_required", owner)
        _BackingPublication.require(entry, entry.request, entry.registration)
        if entry.operation is None or entry.operation.binding != backing._binding(row):
            _fail("original_backing_publication_changed", owner)
        backing.ParentAdmissionBacking._original(entry.operation)
        wrapper = wrappers.get(row["wrapper_member_id"])
        if (wrapper is None or wrapper["closure"]["publication_request_id"] != entry.request.request_id or
                wrapper["closure"]["publication_sha256"] != entry.request.payload_sha256):
            _fail("original_wrapper_publication_changed", owner)
    # File reads occur before BEGIN. Any unknown file close remains retained
    # and cannot be retried into an apparently successful empty completion.
    try:
        for execution, (receipt, claim) in claims.items():
            roles = [role for role in owner.plan.roles if type(role) is GuardianRoleSpec and
                     role.member_id == receipt["actor_member_id"]]
            if len(roles) != 1:
                _fail("original_guardian_role_missing", owner)
            role = roles[0]
            journal = completion._journals.get(role.member_id)
            if journal is None:
                journal = RecoveryJournal(role.journal_dir)
                completion._journals[role.member_id] = journal
            manifest = journal.read(execution, creation_nonce=claim["job_nonce"])
            previous = completion._manifests.get(execution)
            if previous is not None and previous != manifest:
                _fail("original_terminal_manifest_changed", owner)
            completion._manifests[execution] = manifest
    except BaseException as error:
        if getattr(error, "_journal_cleanup_owner", None) is not None:
            completion._file_cleanup_unknown = True
        raise
    observed = []
    with owner._sql(owner.ledger_path) as conn:
        links = local_backing.read_inventory_locked(conn, max_rows=local_backing.MAX_ROWS,
                                                    max_bytes=local_backing.MAX_BYTES)
        local_rows = {value.to_dict()["execution_id"]: value.to_dict() for value in links.rows
                      if value.to_dict()["scope_id"] == owner.scope_id}
        admitted = set(claims) | {execution for execution, wrapper in unused.items()
                                  if wrapper["closure"]["admission_retirement"]["kind"] == "reserved_cancelled"}
        if set(local_rows) != admitted:
            _fail("isolated_partition_changed", owner)
        for row in backing_rows:
            execution = row["isolated_execution_id"]
            if execution in admitted:
                local = local_rows[execution]
                manifest = owner._backing_members[row["member_id"]].request.manifest
                binding = backing._binding(row)
                expected = dict(execution_id=execution, reservation_id=row["isolated_reservation_id"],
                    request_key=row["request_key"], request_spec_hash=row["request_spec_hash"],
                    spec_hash=row["spec_hash"], admission_binding_hash=row["admission_binding_hash"],
                    member_id=row["member_id"], wrapper_member_id=row["wrapper_member_id"],
                    daily_binding_sha256=row["binding_sha256"], daily_registered_revision=row["registered_revision"],
                    plan_sha256=owner._plan_hash, isolated_policy_instance_id=owner.spec.isolated_policy_instance_id,
                    scope_id=owner.scope_id, scope_nonce=manifest.scope_nonce,
                    source_generation=manifest.source_generation, source_digest=manifest.source_digest,
                    config_digest=manifest.config_digest, daily_ledger_path=manifest.daily_ledger_path,
                    daily_ledger_dev=str(manifest.daily_ledger_identity.st_dev),
                    daily_ledger_ino=str(manifest.daily_ledger_identity.st_ino),
                    daily_policy_instance_id=manifest.daily_policy_instance_id,
                    isolated_ledger_path=manifest.isolated_ledger_path,
                    isolated_ledger_dev=str(manifest.isolated_ledger_identity.st_dev),
                    isolated_ledger_ino=str(manifest.isolated_ledger_identity.st_ino),
                    wrapper_pid=binding.wrapper_identity.pid,
                    wrapper_created_filetime_100ns=str(binding.wrapper_identity.created_filetime_100ns),
                    logon_id=binding.wrapper_identity.logon_id, schema_version=1,
                    **binding.requested.to_dict())
                if any(local[key] != value for key, value in expected.items()):
                    _fail("isolated_partition_changed", owner)
            if execution in unused:
                item = _unused_admission_custody(conn, owner, row, unused[execution])
                item["local_link_sha256"] = local_rows[execution]["link_sha256"] if execution in admitted else None
                observed.append(item)
        for job in jobs:
            execution = job["isolated_execution_id"]
            receipt, claim = claims[execution]
            row = owner.daily_store._public(owner.daily_store._get(conn, execution))
            verifier = terminal_receipt if claim["evidence_kind"] == "guardian_terminal_custody_closed" else prelaunch_receipt
            body = verifier._verified_record(conn, owner.daily_store, row, completion._manifests[execution])
            if (terminal_receipt._digest(body) != claim["receipt_sha256"] or
                    body["manifest_hash"] != claim["manifest_hash"] or
                    body["guardian_identity"] != receipt["child_identity"] or
                    body["job_name"] != job["job_name"] or body["job_nonce"] != job["creation_nonce"] or
                    body["policy_instance_id"] != owner.spec.isolated_policy_instance_id):
                _fail("isolated_custody_changed", owner)
            observed.append(dict(member_id=job["member_id"], receipt=body,
                                 local_link_sha256=local_rows[execution]["link_sha256"]))
    completion._closed()
    return observed


def _unused_admission_custody(conn, owner, row, wrapper):
    """SQL observation paired with an authenticated original unused claim."""
    proof = wrapper["closure"]["admission_retirement"]
    binding = backing._binding(row)
    expected = dict(execution_id=binding.execution_id, reservation_id=binding.reservation_id,
        request_key=binding.request_key, spec_hash=binding.spec_hash,
        admission_binding_hash=binding.admission_binding_hash)
    if any(proof.get(key) != value for key, value in expected.items()):
        _fail("unused_admission_binding_changed", owner)
    execution, reservation, request_key = binding.execution_id, binding.reservation_id, binding.request_key
    for table, condition, parameters in (
            ("reservations", "id=? OR execution_id=? OR request_key=?", (reservation, execution, request_key)),
            ("worker_reservations", "execution_id=?", (execution,)),
            ("queue", "managed_execution_id=? OR request_key=?", (execution, request_key)),
            ("routed_executions", "reservation_id=?", (reservation,))):
        if conn.execute(f"SELECT 1 FROM {table} WHERE {condition} LIMIT 1", parameters).fetchone() is not None:
            _fail("unused_admission_obligation_remaining", owner)
    managed = conn.execute("SELECT * FROM managed_executions WHERE execution_id=? OR reservation_id=? LIMIT 2",
                           (execution, reservation)).fetchall()
    archives = conn.execute("SELECT * FROM executions WHERE reservation_id=? OR request_key=? LIMIT 2",
                            (reservation, request_key)).fetchall()
    result = dict(member_id=row["member_id"], admission_retirement=proof,
                  terminal_row_sha256=None, archive_sha256=None)
    if proof["kind"] == "never_admitted":
        if managed or archives:
            _fail("unused_admission_not_absent", owner)
        return result
    if proof["kind"] != "reserved_cancelled" or len(managed) != 1 or len(archives) != 1:
        _fail("unused_admission_terminal_missing", owner)
    actual, archive = dict(managed[0]), dict(archives[0])
    entry = owner._backing_members[row["member_id"]]
    snapshot = entry.snapshot
    # The parent holds credential-free observation metadata: its deliberately
    # empty attribution fields are not an original ManagedAdmission snapshot.
    # Compare precisely the fields authenticated by that observation; the
    # child's original unused-claim proof binds the omitted private identity.
    expected_row = dict(execution_id=execution, reservation_id=reservation,
        allocation_kind="direct", parent_execution_id=None, logon_id=binding.wrapper_identity.logon_id,
        spec_hash=binding.spec_hash, admission_binding_hash=binding.admission_binding_hash,
        wrapper_pid=binding.wrapper_identity.pid,
        wrapper_created_filetime_100ns=str(binding.wrapper_identity.created_filetime_100ns),
        role=snapshot.role.value, priority=snapshot.priority.value, coverage="unmanaged", job_name=None,
        job_nonce=None, guardian_epoch="", root_pid=None, root_created_filetime_100ns=None,
        root_outcome=None, launch_in_flight=0, hold_reason=None, state="CANCELLED_BEFORE_START",
        claim_consumed=1, launch_sealed=1, claim_token_hash="")
    expected_row.update({"requested_" + key: value for key, value in binding.requested.to_dict().items()})
    if any(actual.get(key) != value for key, value in expected_row.items()):
        _fail("unused_admission_terminal_changed", owner)
    request = snapshot.request
    expected_archive = dict(reservation_id=reservation, request_key=request_key,
        owner_pid=request.owner_pid, repo=request.repo, command_signature=request.command_signature,
        resource_class=request.resource_class, priority=request.priority, cpu_units=request.cpu_units,
        ram_gib=request.ram_gib, io_slots=request.io_slots, started_at=actual["created_at"],
        ended_at=actual["finished_at"], outcome="managed_cancelled_before_start")
    if (actual["state_revision"] != proof["state_revision"] or actual["claim_token_hash"] != "" or
            actual["job_nonce"] is not None or
            any(archive[key] != value for key, value in expected_archive.items())):
        _fail("unused_admission_terminal_changed", owner)
    result.update(terminal_row_sha256=terminal_receipt._digest(owner.daily_store._public(actual)),
                  archive_sha256=terminal_receipt._digest(archive))
    return result


def _validate_host_record(record, members, registered, outcomes):
    from . import experiment_history as history, terminal_receipt
    from .experiment_host_retirement_transport import validate_snapshot
    rows = record["host_rows"]
    scope = rows[ledger.SCOPES_TABLE][0]
    actors = {row["member_id"]: row for row in rows[ledger.ACTORS_TABLE]}
    receipts = record["host_retirements"]
    if type(receipts) is not list or len(receipts) > ledger.MAX_ACTORS:
        _fail("history_retirement_bound")
    closed, claims, requests = {}, {}, set()
    for receipt in receipts:
        validate_snapshot(receipt)
        member_id = receipt["actor_member_id"]
        member, actor, outcome = members.get(member_id), actors.get(member_id), outcomes.get(member_id)
        if (member is None or member.role != receipt["role"] or actor is None or outcome is None or
                member_id in closed or receipt["request_id"] in requests or
                outcome["outcome"] != "exited_closed" or
                outcome["identity"] != receipt["child_identity"] or
                actor["identity_json"] != _canonical(receipt["child_identity"])):
            _fail("history_host_retirement_changed")
        closed[member_id] = receipt
        requests.add(receipt["request_id"])
        if receipt["role"] == "guardian":
            for claim in receipt["closure"]["jobs"]:
                if claim["execution_id"] in claims:
                    _fail("history_job_duplicate")
                claims[claim["execution_id"]] = (receipt, claim)
    backings = record["backing_rows"]
    if type(backings) is not list or len(backings) > backing.MAX_BACKINGS:
        _fail("history_backing_bound")
    by_member, by_execution, wrapper_members = {}, {}, set()
    for row in backings:
        history._shape(row, backing.FIELDS)
        binding = backing._binding(row)
        member, wrapper = members.get(row["member_id"]), members.get(row["wrapper_member_id"])
        receipt = closed.get(row["wrapper_member_id"])
        if (type(row["schema_version"]) is not int or row["schema_version"] != 1 or
                type(row["registered_revision"]) is not int or
                not 0 <= row["registered_revision"] <= record["registry_revision"] or
                row["binding_sha256"] != ledger._digest({k: v for k, v in row.items() if k != "binding_sha256"}) or
                row["scope_id"] != scope["scope_id"] or
                row["scope_binding_sha256"] != scope["binding_sha256"] or
                row["isolated_ledger_identity_json"] != scope["isolated_ledger_identity_json"] or
                member is None or member.kind != "workload" or member.role != "workload" or
                member.member_id not in registered or row["requested_json"] != _canonical(member.requested.to_dict()) or
                wrapper is None or wrapper.role != "wrapper" or receipt is None or
                binding.wrapper_identity.to_dict() != receipt["child_identity"] or
                receipt["closure"]["execution_id"] != binding.execution_id or
                row["member_id"] in by_member or binding.execution_id in by_execution or
                row["wrapper_member_id"] in wrapper_members or
                binding.execution_id == scope["daily_execution_id"] or binding.reservation_id == scope["reservation_id"]):
            _fail("history_backing_changed")
        by_member[row["member_id"]] = row
        by_execution[binding.execution_id] = row
        wrapper_members.add(row["wrapper_member_id"])
    jobs = {}
    for row in rows[ledger.JOBS_TABLE]:
        job = ledger.JobBinding(**{key: row[key] for key in ledger.JobBinding.__dataclass_fields__})
        backing_row = by_member.get(job.member_id)
        guardian = closed.get(job.guardian_member_id)
        if (job.kind != "managed" or job.member_id in jobs or backing_row is None or guardian is None or
                guardian["role"] != "guardian" or
                any(getattr(job, key) != backing_row[key] for key in
                    ("member_id", "isolated_execution_id", "isolated_reservation_id", "wrapper_member_id")) or
                job.isolated_execution_id not in claims or
                claims[job.isolated_execution_id][0] is not guardian):
            _fail("history_job_changed")
        jobs[job.member_id] = job
    unused = {member_id: closed[row["wrapper_member_id"]]["closure"]["admission_retirement"]
              for member_id, row in by_member.items()
              if "admission_retirement" in closed[row["wrapper_member_id"]]["closure"]}
    if (set(jobs) & set(unused) or set(jobs) | set(unused) != set(by_member) or
            set(claims) != {job.isolated_execution_id for job in jobs.values()}):
        _fail("history_job_missing")
    custody = record["isolated_custody"]
    if type(custody) is not list or len(custody) != len(by_member):
        _fail("history_custody_bound")
    seen = set()
    common = {"schema_version", "evidence_kind", "execution_id", "state", "state_revision",
        "terminal_row_hash", "manifest_seq", "manifest_hash", "policy_instance_id", "policy_logon_id",
        "guardian_epoch", "registry_revision", "guardian_identity", "wrapper_identity", "root_identity",
        "job_name", "job_nonce", "reservation", "spec_hash", "allocated_floor", "closed_owners", "archive_hash"}
    for item in custody:
        if type(item) is dict and item.get("member_id") in unused:
            history._shape(item, {"member_id", "admission_retirement", "terminal_row_sha256", "archive_sha256", "local_link_sha256"})
            member_id, proof = item["member_id"], item["admission_retirement"]
            binding = backing._binding(by_member[member_id])
            expected = dict(execution_id=binding.execution_id, reservation_id=binding.reservation_id,
                request_key=binding.request_key, spec_hash=binding.spec_hash,
                admission_binding_hash=binding.admission_binding_hash)
            if (member_id in seen or proof != unused[member_id] or
                    any(proof.get(key) != value for key, value in expected.items())):
                _fail("history_unused_admission_changed")
            seen.add(member_id)
            if proof["kind"] == "never_admitted":
                if (item["terminal_row_sha256"] is not None or item["archive_sha256"] is not None or
                        item["local_link_sha256"] is not None):
                    _fail("history_unused_admission_changed")
            elif proof["kind"] == "reserved_cancelled":
                history._hash(item["terminal_row_sha256"])
                history._hash(item["archive_sha256"])
                history._hash(item["local_link_sha256"])
            else:
                _fail("history_unused_admission_changed")
            continue
        history._shape(item, {"member_id", "receipt", "local_link_sha256"})
        history._hash(item["local_link_sha256"])
        job, body = jobs.get(item["member_id"]), item["receipt"]
        if job is None or item["member_id"] in seen or type(body) is not dict:
            _fail("history_custody_changed")
        seen.add(item["member_id"])
        prelaunch = body.get("evidence_kind") == "guardian_prelaunch_custody_closed"
        history._shape(body, common | ({"root_disposition", "job_disposition", "retirement_hash"} if prelaunch else set()))
        guardian, claim = claims[job.isolated_execution_id]
        binding = backing._binding(by_member[job.member_id])
        if (type(body["schema_version"]) is not int or body["schema_version"] != 1 or
                terminal_receipt._digest(body) != claim["receipt_sha256"] or
                any(body[key] != claim[key] for key in
                    ("execution_id", "evidence_kind", "job_name", "job_nonce", "manifest_hash")) or
                body["execution_id"] != job.isolated_execution_id or
                body["job_name"] != job.job_name or body["job_nonce"] != job.creation_nonce or
                body["guardian_identity"] != guardian["child_identity"] or
                body["wrapper_identity"] != binding.wrapper_identity.to_dict() or
                body["policy_instance_id"] != scope["isolated_policy_instance_id"] or
                body["policy_logon_id"] != scope["logon_id"] or body["spec_hash"] != binding.spec_hash or
                body["reservation"] != {"kind": "direct", "id": binding.reservation_id}):
            _fail("history_custody_changed")
        for key in ("terminal_row_hash", "manifest_hash", "archive_hash", "spec_hash"):
            history._hash(body[key])
        for key in ("state_revision", "manifest_seq", "registry_revision"):
            history._integer(body[key])
        history._identity(body["guardian_identity"])
        history._identity(body["wrapper_identity"])
        floor = ledger.ResourceDemand.from_dict(body["allocated_floor"])
        if any(floor.to_dict()[key] < value for key, value in binding.requested.to_dict().items()):
            _fail("history_custody_floor_changed")
        if prelaunch:
            history._hash(body["retirement_hash"])
            if (body["state"] not in {"START_FAILED", "CANCELLED_BEFORE_START"} or
                    body["root_identity"] is not None or body["root_disposition"] != "never-created" or
                    body["job_disposition"] not in {"closed", "never-created"} or
                    body["closed_owners"] != (["job", "wrapper", "mutex"] if body["job_disposition"] == "closed"
                                             else ["wrapper", "mutex"])):
                _fail("history_custody_not_closed")
        elif (body["evidence_kind"] != "guardian_terminal_custody_closed" or body["state"] != "FINISHED" or
                body["root_identity"] is None or body["closed_owners"] != list(terminal_receipt._OWNERS)):
            _fail("history_custody_not_closed")
        else:
            history._identity(body["root_identity"])


def validate_record(record):
    """Strict bounded DATA validator. It never produces an original completion."""
    from . import experiment_history as history
    fields = {"schema_version", "domain", "disposition", "demand", "scope_id", "declaration",
              "host_rows", "actor_outcomes", "registry_revision", "reservation_id",
              "daily_binding_sha256", "registration_custody"}
    full = type(record) is dict and record.get("schema_version") == HOST_VERSION
    if full:
        fields |= {"backing_rows", "host_retirements", "isolated_custody"}
    history._shape(record, fields)
    if (type(record["schema_version"]) is not int or record["schema_version"] != (HOST_VERSION if full else VERSION) or
            record["domain"] != (HOST_DOMAIN if full else DOMAIN) or record["disposition"] != "FINISHED"):
        _fail("history_domain_invalid")
    history._validate_demand(record["demand"])
    history._uuid(record["scope_id"])
    history._integer(record["registry_revision"])
    history._hash(record["daily_binding_sha256"])
    history._text(record["reservation_id"])
    declaration, rows = record["declaration"], record["host_rows"]
    history._shape(declaration, {"domain", "scope", "members", "commands"} |
                   ({"roles"} if type(declaration) is dict and "roles" in declaration else set()))
    if declaration["domain"] != "sentinel-production-experiment-plan-v1":
        _fail("declaration_domain_invalid")
    history._shape(rows, ledger.TABLES)
    limits = (1, ledger.MAX_MEMBERS, ledger.MAX_ACTORS, ledger.MAX_MANAGED_JOBS + ledger.MAX_QUERY_JOBS)
    for table, limit in zip(ledger.TABLES, limits):
        if type(rows[table]) is not list or len(rows[table]) > limit:
            _fail("history_bound")
        for row in rows[table]:
            history._shape(row, ledger.FIELDS[table])
            if (type(row["schema_version"]) is not int or row["schema_version"] != 1 or
                    type(row["registered_revision"]) is not int or
                    not 0 <= row["registered_revision"] <= record["registry_revision"] or
                    row["binding_sha256"] != ledger._digest({k: v for k, v in row.items() if k != "binding_sha256"}) or
                    row["scope_id"] != record["scope_id"]):
                _fail("history_binding_invalid")
    if len(rows[ledger.SCOPES_TABLE]) != 1 or (not full and rows[ledger.JOBS_TABLE]):
        _fail("history_terminal_evidence_missing")
    scope = rows[ledger.SCOPES_TABLE][0]
    demand = record["demand"]
    expected_spec = dict(scope_id=scope["scope_id"], suite=scope["suite"],
        isolated_ledger_path=scope["isolated_ledger_path"],
        isolated_ledger_identity=json.loads(scope["isolated_ledger_identity_json"]),
        isolated_policy_instance_id=scope["isolated_policy_instance_id"])
    if (declaration["scope"] != expected_spec or scope["suite"] not in {"S2", "P4"} or
            hashlib.sha256(_canonical(declaration).encode("ascii")).hexdigest() != demand["scope_sha256"] or
            any(scope[key] != value for key, value in {
                "experiment_id": demand["experiment_id"], "daily_execution_id": demand["execution_id"],
                "reservation_id": record["reservation_id"], "suite": demand["suite"],
                "demand_binding_sha256": record["daily_binding_sha256"],
                "source_generation": demand["generation"]["generation"],
                "source_digest": demand["generation"]["source_digest"],
                "config_digest": demand["generation"]["config_digest"],
                "generation_binding_sha256": ledger._generation_digest(demand["generation_binding"]),
                "logon_id": demand["caller_identity"]["logon_id"]}.items())):
        _fail("history_declaration_changed")
    if (Path(scope["isolated_ledger_path"]).parent != Path(demand["scope_directory"]) or
            expected_spec["isolated_ledger_identity"] == demand["ledger_identity"] or
            scope["isolated_policy_instance_id"] == scope["daily_policy_instance_id"]):
        _fail("history_ledger_changed")
    history._uuid(scope["daily_policy_instance_id"])
    if type(declaration["members"]) is not list or not 1 <= len(declaration["members"]) <= ledger.MAX_MEMBERS:
        _fail("history_members_invalid")
    members = {}
    for item in declaration["members"]:
        history._shape(item, {"member_id", "kind", "role", "requested"})
        claim = ledger.MemberClaim(item["member_id"], item["kind"], item["role"],
                                  ledger.ResourceDemand.from_dict(item["requested"]))
        if claim.member_id in members:
            _fail("history_member_duplicate")
        members[claim.member_id] = claim
    if any(sum(item.requested.to_dict()[key] for item in members.values()) > value
           for key, value in demand["requested"].items()):
        _fail("history_demand_exceeded")
    from .experiment_host_scope import ProductionExperimentPlan
    from .experiment_host_creation import ChildCommand
    commands = declaration["commands"]
    roles = declaration.get("roles", [])
    if (type(commands) is not list or len(commands) > ledger.MAX_ACTORS or
            type(roles) is not list or len(roles) > ledger.MAX_ACTORS or
            ("roles" in declaration and not roles)):
        _fail("history_plan_bound")
    command_values = []
    for command in commands:
        history._shape(command, {"member_id", "executable", "arguments", "cwd"})
        if type(command["arguments"]) is not list:
            _fail("history_command_invalid")
        command_values.append((command["member_id"], ChildCommand(command["executable"],
            tuple(command["arguments"]), command["cwd"])))
    spec = ledger.HostScopeSpec(scope["scope_id"], scope["suite"], scope["isolated_ledger_path"],
        tuple(expected_spec["isolated_ledger_identity"]), scope["isolated_policy_instance_id"])
    reconstructed = ProductionExperimentPlan(spec, tuple(members.values()), tuple(command_values),
                                            tuple(role_spec_from_dict(value) for value in roles))
    if reconstructed.to_dict() != declaration:
        _fail("history_plan_changed")
    registered = {}
    for row in rows[ledger.MEMBERS_TABLE]:
        member = members.get(row["member_id"])
        if (member is None or row["member_id"] in registered or row["kind"] != member.kind or
                row["role"] != member.role or row["demand_json"] != _canonical(member.requested.to_dict())):
            _fail("history_member_changed")
        registered[member.member_id] = row
    outcomes = record["actor_outcomes"]
    if type(outcomes) is not list or len(outcomes) > ledger.MAX_ACTORS:
        _fail("history_actor_bound")
    by_member = {}
    for outcome in outcomes:
        history._shape(outcome, {"member_id", "outcome", "identity"})
        member = members.get(outcome["member_id"])
        if (member is None or member.kind != "infrastructure" or member.member_id in by_member or
                outcome["outcome"] not in {"never_entered", "never_created", "exited_closed"}):
            _fail("history_actor_invalid")
        if outcome["identity"] is not None:
            identity = history._identity(outcome["identity"])
            if outcome["outcome"] != "exited_closed" or identity.logon_id != scope["logon_id"]:
                _fail("history_actor_identity_changed")
        by_member[member.member_id] = outcome
    if set(by_member) != {key for key, member in members.items() if member.kind == "infrastructure"}:
        _fail("history_actor_missing")
    publications = record["registration_custody"]
    if type(publications) is not list or len(publications) > ledger.MAX_ACTORS:
        _fail("history_publication_bound")
    publication_members, publication_requests = set(), set()
    for publication in publications:
        history._shape(publication, {"member_id", "request_id", "publication_sha256", "outcome"})
        history._uuid(publication["request_id"])
        history._hash(publication["publication_sha256"])
        if (publication["member_id"] not in by_member or publication["member_id"] in publication_members or
                publication["request_id"] in publication_requests or publication["outcome"] not in
                {"published_closed", "failed_closed", "never_entered"}):
            _fail("history_publication_invalid")
        publication_members.add(publication["member_id"])
        publication_requests.add(publication["request_id"])
    for row in rows[ledger.ACTORS_TABLE]:
        outcome = by_member.get(row["member_id"])
        if (row["member_id"] not in registered or outcome is None or
                outcome["outcome"] != "exited_closed" or outcome["identity"] is None or
                row["identity_json"] != _canonical(outcome["identity"])):
            _fail("history_actor_not_retired")
    if full:
        _validate_host_record(record, members, registered, by_member)
    if len(_canonical(record).encode("ascii")) > history.MAX_RECEIPT_BYTES:
        _fail("history_bound")
    return record
