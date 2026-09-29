"""Original aggregate retirement; snapshots are bounded history, never authority.

The pre-release bootstrap path is concrete: seal the original owner, positively
settle its actual CreationAttempts, and archive the exact four daily inventories.
An accepted host/Job requires an authenticated terminal consumer. Bind/publication
ACKs and actor exit cannot stand in for that consumer; those paths remain charged.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import threading

from . import experiment_host_ledger as ledger
from .experiment_host_creation import CreationAttempt
from .experiment_host_roles import role_spec_from_dict
from .experiment_child_host import ChildRegistrationPublication

DOMAIN = "sentinel-production-scope-completion-v1"
VERSION = 3  # distinct from the two existing S1 completion versions
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
    return hashlib.sha256((DOMAIN + "\n" + _canonical(value)).encode("ascii")).hexdigest()


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
        # There is deliberately no callback, bool, JSON audit, or reopen-by-PID
        # alternative to the missing exact terminal transport capability.
        if (owner._accepted_children or owner._backing_publications or owner._backing_members or
                owner._job_publications or owner._job_members or owner._released_roles):
            _fail("authenticated_host_retirement_required", owner)
        if (owner._transport_service is not None or owner._backing_service is not None or
                owner._job_service is not None or owner._retirement_service is not None):
            _fail("original_transport_retirement_required", owner)
        if owner._supervisor_host is not None:
            _fail("original_supervisor_retirement_required", owner)
        for member_id, publication in owner._registration_publications.items():
            original = owner._child_registrations.get(member_id)
            if (type(publication) is not ChildRegistrationPublication or original is None or
                    publication.registration is not original[1] or
                    publication.directory != owner.demand.directory):
                _fail("original_registration_retirement_required", owner)
            ChildRegistrationPublication._assert_original(publication)
        for _, attempt in self._attempt_items:
            CreationAttempt.assert_original(attempt, owner)

    def _closed(self):
        self._original()
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


def retire(owner):
    """Seal and retire originals; never wait, kill, loosen a cap or free capacity."""
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
            for _, attempt in result._attempt_items:
                CreationAttempt.settle_native(attempt, owner)
            for publication in owner._registration_publications.values():
                ChildRegistrationPublication.close(publication)
            result._closed()
            with owner._operation() as guard:
                with owner._sql(owner.demand.ledger_path) as conn:
                    inventory, _, tables = ledger._inventory(conn, owner._daily_policy, guard)
                    if inventory.admission_backings:
                        _fail("original_partition_retirement_required", owner)
                    rows = {table: list(tables.get(table, ())) for table in ledger.TABLES}
                    revision = owner._daily_policy.revalidate(conn, guard)["registry_revision"]
            result._closed()
            if rows[ledger.JOBS_TABLE]:
                _fail("authenticated_job_retirement_required", owner)
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
            record = dict(schema_version=VERSION, domain=DOMAIN, disposition="FINISHED",
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
            validate_record(record)
            result._record, result.digest = _canonical(record), digest_record(record)
            result._publication_pin = (result._record, result.digest)
            return result.assert_original()
        except BaseException as error:
            owner._retain(error)
            raise


def validate_record(record):
    """Strict bounded DATA validator. It never produces an original completion."""
    from . import experiment_history as history
    fields = {"schema_version", "domain", "disposition", "demand", "scope_id", "declaration",
              "host_rows", "actor_outcomes", "registry_revision", "reservation_id",
              "daily_binding_sha256", "registration_custody"}
    history._shape(record, fields)
    if (type(record["schema_version"]) is not int or record["schema_version"] != VERSION or
            record["domain"] != DOMAIN or record["disposition"] != "FINISHED"):
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
    if len(rows[ledger.SCOPES_TABLE]) != 1 or rows[ledger.JOBS_TABLE]:
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
    if len(_canonical(record).encode("ascii")) > history.MAX_RECEIPT_BYTES:
        _fail("history_bound")
    return record
