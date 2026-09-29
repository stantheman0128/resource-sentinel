"""Real plan/parent SQL/role-release protocol; explicit portable native fixtures.

Original daily demand, scope, CreationAttempt, actor publication, authenticated
parent acceptance and child binding consumption are exercised together. The
native creation, readiness and completed pipe transfers reuse existing fixture
providers; they do not prove real process dispatch or any Windows gate.
"""
from contextlib import closing
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import experiment_host_transport as transport
from sentinel.adaptive import identity
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand
from sentinel.adaptive.identity import VerifiedProcess
from tests import test_adaptive_experiment_host_creation as creation_fixture
from tests import test_adaptive_experiment_host_roles as role_fixture
from tests import test_adaptive_experiment_host_scope as scope_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests.test_adaptive_ipc import Clock, Listener, canonical, wire_frame


class _RoleFixture:
    WITH_ROLES = True

    def setUp(self):
        self.host = scope_fixture.ProductionExperimentScopeTests()
        self.host.MEMBER_ROLES = ("guardian", "wrapper", "workload")
        self.host.MEMBER_DEMAND = ResourceDemand(.1, 64 << 20, 64 << 20, 0)
        self.addCleanup(self.host.doCleanups)
        original_plan = scopes.ProductionExperimentPlan
        def plan(spec, members):
            guardian, wrapper, workload = members
            directory = str(Path(spec.isolated_ledger_path).parent)
            self.guardian_role = replace(role_fixture.guardian(), member_id=guardian.member_id,
                data_dir=directory, policy_instance_id=spec.isolated_policy_instance_id)
            base = role_fixture.wrapper()
            self.wrapper_role = replace(base, member_id=wrapper.member_id, data_dir=directory,
                workload_member_id=workload.member_id, guardian_member_id=guardian.member_id,
                launch_spec=replace(base.launch_spec, requested=workload.requested))
            return original_plan(spec, members,
                roles=(self.guardian_role, self.wrapper_role) if self.WITH_ROLES else ())
        # Include roles before the real original declaration is hashed/captured;
        # restore the exact production class before constructing the parent.
        with patch.object(scopes, "ProductionExperimentPlan", side_effect=plan):
            self.host.setUp()
        self.host.proof.revalidate_scoped_readiness.return_value = None
        self.owner = self.host.prepare()
        self.guardian, self.wrapper, self.workload = self.host.members
        self.owner.reserve_member(self.workload)
        self.children = {}
        self.native_creates = []
        for index, member in enumerate((self.guardian, self.wrapper), 1):
            self.create_actor(member, index)
        self.endpoint = self.children[self.guardian.member_id][1].manifest.endpoint
        self.io_events = []
        for override in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()),
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False)):
            override.start()
            self.addCleanup(override.stop)
        self.service = transport.ExperimentChildService(self.endpoint, self.owner)

    def create_actor(self, member, index):
        parent = self.owner.process.identity
        actor = ProcessIdentity(parent.pid + 30 + index,
            parent.created_filetime_100ns + 100 + index, parent.logon_id)
        backend = creation_fixture.IdentityBackend()
        backend.value = actor
        def create(*arguments):
            attempt = self.owner._attempts[member.member_id]
            self.assertIs(arguments[-1]._obj, attempt._info_original)
            self.assertIs(arguments[1], attempt._buffer_original)
            self.native_creates.append(attempt)
            output = arguments[-1]._obj
            output.hProcess, output.hThread = 800 + index * 2, 801 + index * 2
            output.dwProcessId, output.dwThreadId = actor.pid, 902 + index
            return 1
        def native_init(value):
            value.kernel = SimpleNamespace(CreateProcessW=create)
        command = creation.ChildCommand(str(Path(sys._base_executable).resolve()),
            ("-I", "fixture-inert-child.py"), str(self.host.fixture.scope))
        with patch.object(self.owner, "_inert_command", return_value=command), \
                patch.object(creation._NativeCreation, "__init__", native_init), \
                patch.object(identity, "_backend", return_value=backend):
            attempt = self.owner.create_actor(member)
        self.addCleanup(attempt.process.close)
        allowed = (self.workload.member_id,)
        registration = self.owner.child_registration(attempt, permitted_member_ids=allowed)
        peer = VerifiedProcess(pipe_fixture.Backend(actor), 61 + index, actor)
        self.addCleanup(peer.close)
        self.children[member.member_id] = (attempt, registration, peer)

    def assert_settled(self):
        self.assertIsNone(self.owner._active_sql)
        self.assertIsNone(self.owner._guard)
        self.assertFalse(self.owner._guard_unknown)
        self.assertFalse(self.host.fixture.fixture.policy.active)

    def original_request(self, member):
        attempt, registration, peer = self.children[member.member_id]
        return transport.BindExperimentChildRequest(registration.manifest), registration, peer

    def accept(self, member):
        request, registration, peer = self.original_request(member)
        self.owner._accept_transport_child(request, peer, registration)
        return request, registration, peer

    def release(self, member, *, accept=True):
        args = self.accept(member) if accept else self.original_request(member)
        return self.owner._release_transport_child(args[0], args[2], args[1])

    def exchange(self, member, *, invalid_proof=False, change_request=None):
        request, registration, peer = self.original_request(member)
        if change_request is not None:
            request = change_request(request)
        state = {}
        def digest(purpose, result=None):
            value = dict(domain="ResourceSentinel/experiment-child-ipc/v1/" + purpose,
                         request=request.to_dict(), challenge=state["challenge"])
            if purpose != "proof":
                value["result"] = result
            return hmac.new(registration.auth_key, canonical(value), hashlib.sha256).hexdigest()
        def write(connection, message):
            self.assert_settled()
            self.io_events.append(message["kind"])
            if message["kind"] == "ExperimentChildChallenge":
                state["challenge"] = message
                connection.enqueue(dict(version=1, kind="ExperimentChildProof", request_id=request.request_id,
                    nonce=message["nonce"], mac="0" * 64 if invalid_proof else digest("proof")))
            elif message["kind"] == "ExperimentChildResult":
                state["response"] = message
                self.assertEqual(message["mac"], digest("result", message["result"]))
                connection.enqueue(dict(version=1, kind="ExperimentChildReceipt", request_id=request.request_id,
                    nonce=message["nonce"], mac=digest("receipt", message["result"])))
        hello = dict(version=1, kind="ExperimentChildHello", request_id=request.request_id,
                     caller=registration.manifest.child_identity.to_dict())
        pipe = pipe_fixture.Pipe(registration.manifest.child_identity,
            wire_frame(hello) + wire_frame(request.to_dict()), on_write=write,
            on_read=lambda conn, size: self.assert_settled())
        self.service.serve_once(Listener(self.endpoint, pipe))
        self.assertTrue(pipe.closed)
        self.assert_settled()
        return state

    def consume(self, member, exchange, *, mutate=None, resign=False, close_error=None):
        attempt, registration, peer = self.children[member.member_id]
        request = transport.BindExperimentChildRequest(registration.manifest)
        response = json.loads(json.dumps(exchange["response"]))
        if mutate is not None:
            mutate(response["result"])
        if resign:
            transcript = dict(domain="ResourceSentinel/experiment-child-ipc/v1/result",
                request=request.to_dict(), challenge=exchange["challenge"], result=response["result"])
            response["mac"] = hmac.new(registration.auth_key, canonical(transcript), hashlib.sha256).hexdigest()
        pipe = pipe_fixture.Pipe(self.endpoint.server_identity,
            wire_frame(exchange["challenge"]) + wire_frame(response))
        pipe.channel_error = close_error
        pid = attempt.process.identity.pid
        with patch.object(transport.os, "getpid", return_value=pid):
            client = transport.ExperimentChildClient(registration, attempt.process)
            self.addCleanup(transport._ORIGINAL_CLIENTS.pop, client._request_key, None)
            self.last_client = client
            with patch.object(transport.NativePipeConnection, "connect", return_value=pipe):
                binding = client.bind()
            self.assertIs(binding._client, client)
        def close():
            with patch.object(transport.os, "getpid", return_value=pid):
                binding.close()
        self.addCleanup(close)
        return binding

    def mutate_daily_actor(self, member, actor):
        # Model digest-valid on-disk corruption and restore the exact guard
        # schema before release; schema failure alone must not be the oracle.
        path = self.owner.demand.ledger_path
        with closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            row = dict(conn.execute("SELECT * FROM " + ledger.ACTORS_TABLE + " WHERE member_id=?",
                                    (member.member_id,)).fetchone())
            row["identity_json"] = ledger._canonical(actor.to_dict())
            row["binding_sha256"] = ledger._digest({key: value for key, value in row.items()
                                                   if key != "binding_sha256"})
            guards = [(name, sql) for name, sql in ledger.GUARDS.items()
                      if " BEFORE UPDATE ON " + ledger.ACTORS_TABLE + " " in sql]
            self.assertEqual(len(guards), 1)
            name, sql = guards[0]
            conn.execute("DROP TRIGGER " + name)
            conn.execute("UPDATE " + ledger.ACTORS_TABLE + " SET identity_json=?,binding_sha256=? WHERE member_id=?",
                         (row["identity_json"], row["binding_sha256"], member.member_id))
            conn.execute(sql)
            conn.commit()


class ExperimentRoleReleaseTests(_RoleFixture, unittest.TestCase):
    def test_role_payload_is_bound_to_plan_hash_and_exact_member_partition(self):
        plan = self.host.plan
        changed = replace(self.guardian_role, rpc_timeout_ms=self.guardian_role.rpc_timeout_ms + 1)
        self.assertNotEqual(replace(plan, roles=(changed, self.wrapper_role)).sha256, plan.sha256)
        self.assertEqual(self.host.demand.declaration.scope_sha256, plan.sha256)
        alterations = (
            replace(self.guardian_role, member_id=self.wrapper.member_id),
            replace(self.wrapper_role, workload_member_id=role_fixture.uid(997)),
            replace(self.wrapper_role, guardian_member_id=role_fixture.uid(998)),
            replace(self.wrapper_role, launch_spec=replace(self.wrapper_role.launch_spec,
                requested=ResourceDemand(.2, 64 << 20, 64 << 20, 0))),
        )
        for altered in alterations:
            roles = ((altered, self.wrapper_role) if altered.role == "guardian" else
                     (self.guardian_role, altered))
            with self.subTest(role=altered.role), self.assertRaises(scopes.ProductionScopeError):
                replace(plan, roles=roles)

    def test_release_requires_original_acceptance_and_actor_publication(self):
        with self.assertRaisesRegex(scopes.ProductionScopeError, "accepted_original_child_required"):
            self.release(self.guardian, accept=False)
        self.accept(self.guardian)
        original = self.owner._published_actors.pop(self.guardian.member_id)
        try:
            with self.assertRaises(scopes.ProductionScopeError):
                self.release(self.guardian, accept=False)
        finally:
            self.owner._published_actors[self.guardian.member_id] = original
        self.assertEqual(self.owner._released_roles, {})

    def test_sealed_parent_denies_first_release_without_releasing_daily_capacity(self):
        self.accept(self.guardian)
        before = self.host.fixture.assert_retained(self.host.demand)
        self.owner.seal_new_work()
        with self.assertRaisesRegex(scopes.ProductionScopeError, "new_work_sealed"):
            self.release(self.guardian, accept=False)
        self.assertEqual(self.owner._released_roles, {})
        self.assertEqual(self.host.fixture.assert_retained(self.host.demand), before)

    def test_guardian_then_wrapper_release_uses_original_created_guardian(self):
        with self.assertRaisesRegex(scopes.ProductionScopeError, "released_original_guardian_required"):
            self.release(self.wrapper)
        guardian_exchange = self.exchange(self.guardian)
        guardian_binding = self.consume(self.guardian, guardian_exchange)
        wrapper_exchange = self.exchange(self.wrapper)
        wrapper_binding = self.consume(self.wrapper, wrapper_exchange)
        for member, binding, role in ((self.guardian, guardian_binding, self.guardian_role),
                                      (self.wrapper, wrapper_binding, self.wrapper_role)):
            with patch.object(transport.os, "getpid", return_value=binding._process.identity.pid):
                self.assertIs(binding.released_role, role)
                self.assertIsNone(binding.require_role_release(role))
        with patch.object(transport.os, "getpid", return_value=wrapper_binding._process.identity.pid):
            context = wrapper_binding.role_release_context(self.wrapper_role)
            guardian = self.children[self.guardian.member_id][0].process.identity
            self.assertEqual(context["endpoint"].server_identity, guardian)
            self.assertEqual(context["endpoint"].instance_id, self.guardian_role.launch_instance_id)
            self.assertEqual(context["guardian_epoch"], self.guardian_role.guardian_epoch)
            context["guardian_epoch"] = "copied-value"
            self.assertEqual(wrapper_binding.role_release_context(self.wrapper_role)["guardian_epoch"],
                             self.guardian_role.guardian_epoch)
        self.assertEqual(len(self.native_creates), 2)
        self.host.fixture.assert_retained(self.host.demand)

    def test_digest_valid_daily_actor_mutation_denies_original_role_release(self):
        self.accept(self.guardian)
        original = self.children[self.guardian.member_id][0].process.identity
        self.mutate_daily_actor(self.guardian, replace(original, pid=original.pid + 100))
        with self.assertRaises(scopes.ProductionScopeError):
            self.release(self.guardian, accept=False)
        self.assertEqual(self.owner._released_roles, {})

    def test_changed_prerequisite_guardian_daily_actor_cannot_release_wrapper(self):
        self.release(self.guardian)
        self.accept(self.wrapper)
        original = self.children[self.guardian.member_id][0].process.identity
        self.mutate_daily_actor(self.guardian, replace(original, pid=original.pid + 100))
        with self.assertRaises(scopes.ProductionScopeError):
            self.release(self.wrapper, accept=False)
        self.assertNotIn(self.wrapper.member_id, self.owner._released_roles)

    def test_changed_source_generation_refuses_dispatch_release(self):
        self.accept(self.guardian)
        self.host.fixture.generation["source_digest"] = "f" * 64
        with self.assertRaises((scopes.ProductionScopeError, RuntimeError, ValueError)):
            self.release(self.guardian, accept=False)
        self.assertEqual(self.owner._released_roles, {})

    def test_bad_mac_and_changed_plan_never_accept_or_release_child(self):
        for kwargs in (dict(invalid_proof=True), dict(change_request=lambda request:
                replace(request, manifest=replace(request.manifest, plan_sha256="f" * 64)))):
            with self.subTest(case=tuple(kwargs)), self.assertRaises(transport.ExperimentChildError):
                self.exchange(self.guardian, **kwargs)
        self.assertEqual(self.owner._accepted_children, {})
        self.assertEqual(self.owner._released_roles, {})

    def test_role_payload_tamper_and_valid_mac_wrong_plan_never_issue_binding(self):
        exchange = self.exchange(self.guardian)
        mutations = (
            (lambda result: result["role_release"]["role_spec"].update(guardian_epoch="tampered"), False),
            (lambda result: result["role_release"].update(plan_sha256="f" * 64), True),
        )
        for mutate, resign in mutations:
            with self.subTest(resign=resign), self.assertRaises(transport.ExperimentChildError):
                self.consume(self.guardian, exchange, mutate=mutate, resign=resign)
            client = self.last_client
            with patch.object(transport.os, "getpid", return_value=client.current_process.identity.pid):
                self.assertFalse(client._binding._issued)
                with self.assertRaises(transport.ExperimentChildError):
                    client._binding.require_role_release(self.guardian_role)
            transport._ORIGINAL_CLIENTS.pop(client._request_key, None)

    def test_channel_close_failure_cannot_issue_already_authenticated_role(self):
        exchange = self.exchange(self.guardian)
        with self.assertRaises(transport.ExperimentChildError):
            self.consume(self.guardian, exchange, close_error=OSError("fixture_channel_close_unknown"))
        binding = self.last_client._binding
        self.assertIsNotNone(binding._role_release_wire)
        self.assertFalse(binding._issued)
        with patch.object(transport.os, "getpid", return_value=binding._process.identity.pid):
            with self.assertRaises(transport.ExperimentChildError):
                binding.require_role_release(self.guardian_role)

    def test_copied_spec_or_binding_and_release_dictionary_cannot_mint_witness(self):
        exchange = self.exchange(self.guardian)
        binding = self.consume(self.guardian, exchange)
        with patch.object(transport.os, "getpid", return_value=binding._process.identity.pid):
            with self.assertRaises(transport.ExperimentChildError):
                binding.require_role_release(replace(self.guardian_role))
            copied = object.__new__(transport.ExperimentChildBinding)
            copied.__dict__.update(binding.__dict__)
            with self.assertRaises(transport.ExperimentChildError):
                copied.require_role_release(self.guardian_role)
            exchange["response"]["result"]["role_release"]["role_spec"]["guardian_epoch"] = "copy-mutation"
            self.assertIs(binding.released_role, self.guardian_role)
            with self.assertRaises(transport.ExperimentChildError):
                transport.ExperimentChildBinding(self.last_client)


class LegacyRoleReleaseTests(_RoleFixture, unittest.TestCase):
    WITH_ROLES = False

    def test_metadata_only_plan_and_successful_binding_grant_no_role_dispatch(self):
        self.assertNotIn("roles", self.host.plan.to_dict())
        exchange = self.exchange(self.guardian)
        self.assertNotIn("role_release", exchange["response"]["result"])
        binding = self.consume(self.guardian, exchange)
        with patch.object(transport.os, "getpid", return_value=binding._process.identity.pid):
            with self.assertRaises(transport.ExperimentChildError):
                binding.released_role
            with self.assertRaises(transport.ExperimentChildError):
                binding.require_role_release(self.guardian_role)
        self.assertEqual(self.owner._released_roles, {})
