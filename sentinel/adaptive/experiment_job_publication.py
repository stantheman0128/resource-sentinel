"""Original guardian Job intent, published before native Create through parent.

Wire data is neither admission nor native ownership. The existing authenticated
child binding names the actual guardian; the parent validates the exact daily
backing and isolated execution before publishing its original JobBinding. No
POLICY, per-Job mutex, or SQL transaction spans this fixed request/response.
Uncertain acknowledgement retains the pending entry and exact request forever;
only clean transport custody permits retrying that same publication.
"""
from dataclasses import dataclass
import hashlib
import hmac
import os
import threading

from . import experiment_host_backing as backing
from . import experiment_host_ledger as ledger
from . import experiment_host_transport as child
from . import experiment_local_backing as local
from .contracts import ProcessIdentity
from .identity import VerifiedProcess
from .ipc import _canonical, _hex, _identity, _live, _remaining, _shape, _uuid
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeRegistry
from .policy import PolicyCoordinator


MAX_ATTEMPTS = 8
_CREATE = object()


class ExperimentJobPublicationError(child.ExperimentChildError):
    pass


def _fail(reason):
    raise ExperimentJobPublicationError("experiment_job_publication_" + reason)


@dataclass(frozen=True)
class PublishExperimentJobRequest:
    manifest: child.ExperimentChildManifest
    request_id: str
    member_id: str
    wrapper_member_id: str
    execution_id: str
    reservation_id: str
    spec_hash: str
    guardian_epoch: str
    job_name: str
    creation_nonce: str
    launch_payload_sha256: str

    def __post_init__(self):
        from .contracts import _identifier
        if type(self.manifest) is not child.ExperimentChildManifest or self.manifest.role != "guardian":
            _fail("original_guardian_manifest_required")
        _uuid(self.request_id)
        _hex(self.spec_hash)
        _hex(self.launch_payload_sha256)
        _identifier(self.guardian_epoch, "guardian_epoch")
        if (self.request_id == self.manifest.request_id or
                self.member_id not in self.manifest.permitted_member_ids):
            _fail("request_binding_mismatch")
        self.job_binding()

    def job_binding(self):
        return ledger.JobBinding(self.member_id, "managed", self.job_name, self.creation_nonce,
            self.manifest.actor_member_id, self.wrapper_member_id, self.execution_id, self.reservation_id)

    def _payload(self):
        return {"manifest": self.manifest.to_dict(), **{key: getattr(self, key)
                for key in self.__dataclass_fields__ if key != "manifest"}}

    @property
    def payload_sha256(self):
        return hashlib.sha256(_canonical(dict(domain="ResourceSentinel/experiment-job-publication/v1",
                                              payload=self._payload()))).hexdigest()

    def to_dict(self):
        return dict(version=1, kind="PublishExperimentJob", **self._payload(), payload_sha256=self.payload_sha256)

    @classmethod
    def from_dict(cls, value):
        _shape(value, "PublishExperimentJob", {"manifest", "member_id", "wrapper_member_id", "execution_id",
            "reservation_id", "spec_hash", "guardian_epoch", "job_name", "creation_nonce",
            "launch_payload_sha256", "payload_sha256"})
        _hex(value["payload_sha256"])
        fields = {key: value[key] for key in cls.__dataclass_fields__ if key != "manifest"}
        result = cls(child.ExperimentChildManifest.from_dict(value["manifest"]), **fields)
        if not hmac.compare_digest(result.payload_sha256, value["payload_sha256"]):
            _fail("payload_digest_mismatch")
        return result


class _ParentPublication:
    def __init__(self, request, registration):
        self.request, self.registration = request, registration
        self.binding = request.job_binding()
        self.wire = _canonical(request.to_dict())
        self._fixed = (request, registration, self.binding, self.wire)

    def require(self, request, registration):
        original, registered, binding, wire = self._fixed
        if (self.request is not original or self.registration is not registered or registration is not registered or
                self.binding is not binding or self.wire != wire or _canonical(original.to_dict()) != wire or
                _canonical(request.to_dict()) != wire or binding != original.job_binding()):
            _fail("original_parent_publication_changed")


def retain_service(owner, service):
    if type(service) is not ExperimentJobService or service.owner is not owner:
        _fail("original_service_required")
    owner._assert_transport_original(service.endpoint)
    if owner._job_service is not None and owner._job_service is not service:
        _fail("original_service_changed")
    owner._job_service = service


def parent_registration(owner, request, peer):
    if type(request) is not PublishExperimentJobRequest or type(peer) is not VerifiedProcess:
        _fail("original_request_required")
    registration = owner._transport_child_registration(child.BindExperimentChildRequest(request.manifest), peer)
    manifest = registration.manifest
    if (not owner._prepared or owner._accepted_children.get(manifest.request_id) is not registration or
            manifest.role != "guardian" or request.member_id not in manifest.permitted_member_ids):
        _fail("accepted_guardian_required")
    retained = owner.registered_scope._backings.get(request.member_id)
    if type(retained) is not backing.ParentAdmissionBacking:
        _fail("original_backing_required")
    retained._original()
    binding = retained.binding
    if (retained.wrapper_member_id != request.wrapper_member_id or binding.execution_id != request.execution_id or
            binding.reservation_id != request.reservation_id or binding.spec_hash != request.spec_hash):
        _fail("backing_changed")
    return registration


def _isolated_before_publication(owner, request, *, committed=None):
    """Read exact partition provenance; existing intent grants no fresh work.

    ``committed`` comes only from the retained original daily row reader below.
    Reconciliation keeps all immutable identity/link checks, but may observe a
    HOLD or terminal isolated row: returning the earlier intent cannot Create,
    consume a claim or release an allocation.
    """
    with owner._sql(owner.ledger_path) as conn:
        runtime = PolicyCoordinator._runtime(conn)
        policy = PolicyCoordinator._binding(runtime, owner.process.identity.logon_id)
        if (policy.instance_id != owner.spec.isolated_policy_instance_id or
                committed is None and (runtime["mode"] not in {"off", "shadow"} or
                                       runtime["admission_barrier"] != "NONE")):
            _fail("isolated_policy_changed")
        observed = local.read_link_locked(conn, request.execution_id, max_rows=1, max_bytes=local.MAX_BYTES)
        if observed is None:
            _fail("isolated_backing_required")
        link = observed.to_dict()
        original = owner.registered_scope._backings[request.member_id]
        binding = original.binding
        manifest = request.manifest
        if (link["scope_id"] != manifest.scope_id or link["member_id"] != request.member_id or
                link["wrapper_member_id"] != request.wrapper_member_id or
                any(link[key] != getattr(manifest, key) for key in (
                    "scope_nonce", "plan_sha256", "source_generation", "source_digest", "config_digest",
                    "daily_ledger_path", "daily_policy_instance_id", "isolated_ledger_path", "isolated_policy_instance_id")) or
                (link["daily_ledger_dev"], link["daily_ledger_ino"]) !=
                    (str(manifest.daily_ledger_identity.st_dev), str(manifest.daily_ledger_identity.st_ino)) or
                (link["isolated_ledger_dev"], link["isolated_ledger_ino"]) !=
                    (str(manifest.isolated_ledger_identity.st_dev), str(manifest.isolated_ledger_identity.st_ino)) or
                any(link[key] != getattr(binding, key) for key in ("execution_id", "reservation_id", "request_key",
                    "request_spec_hash", "spec_hash", "admission_binding_hash")) or
                ProcessIdentity(link["wrapper_pid"], int(link["wrapper_created_filetime_100ns"]), link["logon_id"]) !=
                    binding.wrapper_identity or
                {key: link[key] for key in binding.requested.to_dict()} != binding.requested.to_dict()):
            _fail("isolated_backing_changed")
        if (original._row is None or link["daily_binding_sha256"] != original._row["binding_sha256"] or
                link["daily_registered_revision"] != original._row["registered_revision"]):
            _fail("original_backing_revision_changed")
        row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?", (request.execution_id,)).fetchone()
        if (row is None or row["spec_hash"] != request.spec_hash or
                row["reservation_id"] != request.reservation_id or
                committed is None and (row["state"] not in {"RESERVED", "PREPARED"} or row["claim_consumed"]) or
                (row["job_name"] is not None and (row["job_name"] != request.job_name or
                    row["job_nonce"] != request.creation_nonce or row["guardian_epoch"] != request.guardian_epoch))):
            _fail("isolated_execution_changed")
        if committed is None:
            owner.daily_store._require_authenticated_allocation(conn, row)


def _committed_original(owner, entry, guard):
    """Read-only exact replay proof; a matching name alone cannot recreate it."""
    with owner._sql(owner.demand.ledger_path) as conn:
        registered = owner.registered_scope
        _scope, _runtime, tables, _history = ledger._publication(conn, registered, owner._daily_policy, guard)
        original = registered._backings[entry.request.member_id]
        original._original()
        observed = backing.validate_backing_locked(conn, scope_id=registered.spec.scope_id,
            member_id=original.member_id, wrapper_member_id=original.wrapper_member_id,
            binding=original.binding, policy=owner._daily_policy, guard=guard)
        if (original._row is None or observed.binding_sha256 != original._row["binding_sha256"] or
                observed.registered_revision != original._row["registered_revision"]):
            _fail("original_backing_revision_changed")
        rows = [row for row in tables[ledger.JOBS_TABLE] if row["member_id"] == entry.request.member_id]
        if not rows:
            return None
        saved = registered._jobs.get(entry.request.member_id)
        if (saved is None or saved[0] is not entry.binding or rows != [saved[1]] or
                any(saved[1][key] != getattr(entry.binding, key) for key in ledger.JobBinding.__dataclass_fields__)):
            _fail("original_committed_job_changed")
        return dict(rows[0])


def publish_parent(owner, request, peer, registration):
    """Original parent, two sequential local ledgers, retained exact SQL intent."""
    with owner._lock:
        try:
            if parent_registration(owner, request, peer) is not registration:
                _fail("original_registration_changed")
            entry = owner._job_publications.get(request.request_id)
            if entry is None:
                if (owner._sealed or request.member_id in owner._job_members or
                        len(owner._job_publications) >= ledger.MAX_MANAGED_JOBS):
                    _fail("new_job_refused")
                entry = _ParentPublication(request, registration)
                owner._job_publications[request.request_id] = entry
                owner._job_members[request.member_id] = entry
            entry.require(request, registration)
            if owner._job_members.get(request.member_id) is not entry:
                _fail("original_member_changed")
            with owner._operation() as guard:
                # The parent never waits for its child while these locks exist.
                # All local SQL ends before the service writes any response.
                committed = _committed_original(owner, entry, guard)
                _isolated_before_publication(owner, request, committed=committed)
                if committed is not None:
                    # No writer transaction, UDF, revision change or fresh
                    # admission occurs for an already committed original.
                    result = _committed_original(owner, entry, guard)
                    if result != committed:
                        _fail("original_committed_job_changed")
                else:
                    with owner._sql(owner.demand.ledger_path, write=True) as conn:
                        result = ledger.publish_job_locked(conn, scope=owner.registered_scope,
                            binding=entry.binding, policy=owner._daily_policy, guard=guard)
            return _result(result, request)
        except BaseException as error:
            raise owner._retain(error)


def _result(value, request):
    required = {"scope_id", "member_id", "kind", "job_name", "creation_nonce", "guardian_member_id",
                "wrapper_member_id", "isolated_execution_id", "isolated_reservation_id", "registered_revision"}
    if (type(value) is not dict or not required <= set(value) or
            value["scope_id"] != request.manifest.scope_id or
            type(value["registered_revision"]) is not int or value["registered_revision"] < 1 or
            any(value[key] != getattr(request.job_binding(), key) for key in ledger.JobBinding.__dataclass_fields__)):
        _fail("result_invalid")
    return {key: value[key] for key in sorted(required)}


def _challenge(request):
    value = child._challenge(request)
    value["kind"] = "ExperimentJobChallenge"
    value["payload_sha256"] = request.payload_sha256
    return value


def _check_challenge(value, request):
    _shape(value, "ExperimentJobChallenge", {"nonce", "endpoint_id", "server", "client", "payload_sha256"})
    _hex(value["nonce"])
    if (value["request_id"] != request.request_id or value["payload_sha256"] != request.payload_sha256 or
            value["endpoint_id"] != request.manifest.endpoint.instance_id or
            _identity(value["server"]) != request.manifest.endpoint.server_identity or
            _identity(value["client"]) != request.manifest.child_identity):
        _fail("challenge_mismatch")


def _mac(key, purpose, request, challenge, result=None):
    if purpose not in {"proof", "result", "receipt"}:
        _fail("domain_invalid")
    transcript = dict(domain="ResourceSentinel/experiment-job-ipc/v1/" + purpose,
                      request=request.to_dict(), challenge=challenge)
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, _canonical(transcript), hashlib.sha256).hexdigest()


def _failure(error, owner, attempt):
    attempt.fail(error)
    failure = ExperimentJobPublicationError("experiment_job_publication_rpc_failed")
    failure.original_error, failure.transport_owner, failure.attempt = error, owner, attempt
    return failure


class ExperimentJobService:
    """Fixed authenticated publication service retained by the original parent."""
    def __init__(self, endpoint, owner):
        from .experiment_host_scope import ProductionExperimentScope
        if type(endpoint) is not NativePipeEndpoint or type(owner) is not ProductionExperimentScope:
            _fail("original_scope_required")
        self.endpoint, self.owner = endpoint, owner
        self._process = owner._assert_transport_original(endpoint)
        child._current(self._process, endpoint.server_identity)
        self._pin = child._NativePin(self._process)
        self._fixed = (endpoint, owner, self._process, self._pin)
        self._attempts = []
        owner._retain_job_transport(self)

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _original(self):
        endpoint, owner, process, pin = self._fixed
        if (self.endpoint is not endpoint or self.owner is not owner or self._process is not process or
                self._pin is not pin or owner._assert_transport_original(endpoint) is not process):
            _fail("original_service_changed")
        pin.check()
        child._current(process, endpoint.server_identity)

    def serve_once(self, listener, *, timeout_ms=1000):
        child._no_mutex()
        child._timeout(timeout_ms)
        self._original()
        if listener.endpoint != self.endpoint or len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
            _fail("listener_or_limit_invalid")
        attempt = child._Attempt()
        self._attempts.append(attempt)
        deadline = NativeDeadline.after_ms(timeout_ms)
        try:
            attempt.channel_origin, attempt.channel_started = listener, True
            with child._settled_scope(listener.accept(deadline), attempt, "channel") as connection:
                self._serve_connection(connection, deadline, attempt)
            _remaining(deadline)
            self._original()
            attempt.seal()
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_job_service, error.experiment_job_attempt = self, attempt
            raise

    def _serve_connection(self, connection, deadline, attempt, *, hello=None):
        if type(attempt) is not child._Attempt:
            _fail("original_attempt_required")
        if not any(original is attempt for original in self._attempts):
            if len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
                _fail("attempt_limit")
            self._attempts.append(attempt)
        self._original()
        if hello is None:
            hello = child._read(connection, deadline, limit=child.MAX_HELLO_BYTES)
        _shape(hello, "ExperimentJobHello", {"caller"})
        caller = _identity(hello["caller"])
        if caller.logon_id != self.endpoint.logon_id:
            _fail("peer_logon_mismatch")
        with child._settled_scope(connection.verified_peer(caller), attempt, "peer") as peer:
            if type(peer) is not VerifiedProcess:
                _fail("original_peer_required")
            _live(connection, peer, caller)
            request = PublishExperimentJobRequest.from_dict(child._read(connection, deadline))
            if (request.request_id != hello["request_id"] or request.manifest.child_identity != caller or
                    request.manifest.endpoint != self.endpoint):
                _fail("request_binding_mismatch")
            registration = self.owner._transport_job_registration(request, peer)
            if type(registration) is not child.ExperimentChildRegistration or registration.manifest != request.manifest:
                _fail("original_registration_required")
            self._original()
            child._no_mutex()
            _live(connection, peer, caller)
            challenge = _challenge(request)
            child._write(connection, challenge, deadline)
            proof = child._read(connection, deadline)
            child._correlated(proof, "ExperimentJobProof", request, challenge)
            if not hmac.compare_digest(proof["mac"], _mac(registration.auth_key, "proof", request, challenge)):
                _fail("authentication_failed")
            _live(connection, peer, caller)
            _remaining(deadline)
            attempt.accepted = True
            observed = self.owner._publish_transport_job(request, peer, registration)
            child._no_mutex()
            self._original()
            _live(connection, peer, caller)
            payload = _result(observed, request)
            response = child._envelope("ExperimentJobResult", request, challenge,
                _mac(registration.auth_key, "result", request, challenge, payload))
            response["result"] = payload
            child._write(connection, response, deadline)
            receipt = child._read(connection, deadline)
            child._correlated(receipt, "ExperimentJobReceipt", request, challenge)
            if not hmac.compare_digest(receipt["mac"],
                    _mac(registration.auth_key, "receipt", request, challenge, payload)):
                _fail("receipt_invalid")
            _live(connection, peer, caller)
            _remaining(deadline)
            attempt.exchange_complete = True


class ExperimentJobPublication:
    """One guardian pending execution and one immutable parent publication."""
    def __init__(self, *, _key=None):
        if _key is not _CREATE or type(self) is not ExperimentJobPublication:
            _fail("original_factory_required")

    def __reduce__(self):
        raise TypeError("experiment_job_publication_not_serializable")

    @classmethod
    def prepare(cls, binding, entry, launch_request):
        from .guardian import _PendingExecution
        from . import experiment_host_authority as authorities
        from .experiment_host_authority import ExperimentBackedHostAuthority
        from .launch_transport import PrepareExecutionRequest
        child._no_mutex()
        if (cls is not ExperimentJobPublication or type(binding) is not child.ExperimentChildBinding or
                type(entry) is not _PendingExecution or type(launch_request) is not PrepareExecutionRequest or
                type(entry.owner.authority) is not ExperimentBackedHostAuthority or
                entry.owner.authority.child_binding is not binding or entry.create_attempted or entry.job is not None or
                entry.owner._pending.get(entry.execution_id) is not entry or entry.experiment_job_publication is not None):
            _fail("original_pending_entry_required")
        authority = entry.owner.authority
        authority._original()
        if authority._active is not None:
            _fail("outer_scope_required")
        # Original local link comes from one short isolated read, before any
        # RPC/native wait. It supplies DATA; parent independently checks it.
        authority._cleanup_observed()
        with authorities.daily_generation.readiness_scopes((authority.daily_path, authority.isolated_path),
                                                           absent_paths=(authority.isolated_path,)):
            link, row, allocation = authority._local_view(entry.execution_id)
        entry.owner._check_entry(entry, row)
        manifest = binding.manifest
        binding.revalidate(manifest, role="guardian", member_id=link["member_id"])
        request = PublishExperimentJobRequest(manifest, launch_request.request_id,
            link["member_id"], link["wrapper_member_id"], entry.execution_id, entry.reservation.id,
            entry.spec_hash, entry.owner.guardian_epoch, entry.job_name, entry.creation_nonce,
            launch_request.payload_hash())
        value = cls(_key=_CREATE)
        value.binding, value.entry, value.request = binding, entry, request
        value._registry, value._attempts = NativePipeRegistry(max_resources=1), []
        value._wire = _canonical(request.to_dict())
        value._thread, value._pid = threading.current_thread(), os.getpid()
        value._fixed = (binding, entry, request, value._registry, value._wire, value._thread, value._pid)
        value._pending_pin = (entry.owner, entry.wrapper, entry.auth, child._NativePin(entry.wrapper))
        value._result = None
        entry.experiment_job_publication = value
        return value

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _original(self):
        binding, entry, request, registry, wire, thread, pid = self._fixed
        owner, wrapper, auth, native = self._pending_pin
        if (self.binding is not binding or self.entry is not entry or self.request is not request or
                self._registry is not registry or self._wire != wire or _canonical(request.to_dict()) != wire or
                self._thread is not thread or self._pid != pid or threading.current_thread() is not thread or
                os.getpid() != pid or entry.experiment_job_publication is not self or
                entry.owner._pending.get(entry.execution_id) is not entry or
                entry.job_name != request.job_name or entry.creation_nonce != request.creation_nonce or
                entry.spec_hash != request.spec_hash or entry.reservation.id != request.reservation_id or
                entry.owner.guardian_epoch != request.guardian_epoch or entry.retirement_sealed):
            _fail("original_publication_changed")
        if entry.owner is not owner or entry.wrapper is not wrapper or entry.auth is not auth:
            _fail("original_pending_custody_changed")
        native.check()
        binding.revalidate(request.manifest, role="guardian", member_id=request.member_id)
        entry.owner.authority._original()
        if (entry.owner.authority._active is not None or entry.owner.store._policy.current_guard() is not None or
                entry.owner.authority._daily_policy.current_guard() is not None):
            _fail("outer_scope_required")

    def require_request(self, request):
        self._original()
        if (request.request_id != self.request.request_id or request.payload_hash() != self.request.launch_payload_sha256):
            _fail("original_launch_request_changed")

    def publish(self, *, timeout_ms=1000):
        child._no_mutex()
        child._timeout(timeout_ms)
        self._original()
        if any(value.cleanup_pending for value in self._attempts) or self._registry.status().resources:
            _fail("original_cleanup_pending")
        if self._result is not None:
            return self._result
        if self.entry.create_attempted or self.entry.job is not None or len(self._attempts) >= MAX_ATTEMPTS:
            _fail("attempt_limit_or_creation_entered")
        attempt = child._Attempt()
        self._attempts.append(attempt)
        request, endpoint = self.request, self.request.manifest.endpoint
        deadline = NativeDeadline.after_ms(timeout_ms)
        try:
            attempt.channel_origin, attempt.channel_started = self._registry, True
            with child._settled_scope(NativePipeConnection.connect(endpoint, deadline, registry=self._registry),
                                      attempt, "channel") as connection:
                with child._settled_scope(connection.verified_peer(endpoint.server_identity), attempt, "peer") as peer:
                    if type(peer) is not VerifiedProcess:
                        _fail("original_peer_required")
                    _live(connection, peer, endpoint.server_identity)
                    self._original()
                    child._write(connection, dict(version=1, kind="ExperimentJobHello", request_id=request.request_id,
                        caller=request.manifest.child_identity.to_dict()), deadline, limit=child.MAX_HELLO_BYTES)
                    child._write(connection, request.to_dict(), deadline)
                    challenge = child._read(connection, deadline)
                    _check_challenge(challenge, request)
                    _live(connection, peer, endpoint.server_identity)
                    key = self.binding._client.registration.auth_key
                    attempt.accepted = True
                    child._write(connection, child._envelope("ExperimentJobProof", request, challenge,
                        _mac(key, "proof", request, challenge)), deadline)
                    response = child._read(connection, deadline)
                    child._correlated(response, "ExperimentJobResult", request, challenge, result=True)
                    payload = response["result"]
                    if not hmac.compare_digest(response["mac"], _mac(key, "result", request, challenge, payload)):
                        _fail("result_authentication_failed")
                    observed = _result(payload, request)
                    if observed != payload:
                        _fail("result_shape_changed")
                    _live(connection, peer, endpoint.server_identity)
                    self._original()
                    child._write(connection, child._envelope("ExperimentJobReceipt", request, challenge,
                        _mac(key, "receipt", request, challenge, payload)), deadline)
                    attempt.exchange_complete = True
            _remaining(deadline)
            self._original()
            self._result = observed
            attempt.seal()
            return observed
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_job_publication, error.experiment_job_attempt = self, attempt
            raise
