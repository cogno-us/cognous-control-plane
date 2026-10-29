"""F5 per-class `on_unreadable` oracles: Registry-governed `ActionClass.on_unreadable` (Registry `r08-v5`, family `f5-action-class-unreadable-policy`) reaching the real
`BoundedAuthorizationWorkflow` cached-grant branch through an EFFECTIVE profile that `approval_commitment` already hashes, with every governing selection re-validated at the
construction, decision, effect-entry and effect-commit boundaries, optionally together with the Registry-governed class status age (the M12 family). BUILDER_TESTED developer
evidence. NOT independently qualified. NOT an authorization mechanism. Excludes clock tolerance, identity/mandate ages, the F4 scalars and every other class field.

Needs a Registry checkout at the exact `PIN` in `OCS_REGISTRY_PIN_DIR` and PyNaCl. When `OCS_REQUIRE_REGISTRY_PIN=1` (set by CI) a missing pin, wrong pin or missing
PyNaCl is a FAILURE, never a skip. Without it the module is reported NOT RUN (skipped with a reason), never passed with a double. Real synthetic Ed25519 only.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import inspect
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

PIN = "6c3e5e4037d34bd2b31371461bfc872c762026b9"  # Registry commit that contains r08-v5 (the Registry implementation PR head); the r08-v2 F5 composer in it is byte-identical to 6f600ab
PIN_V6 = "42a666328b974a7581013358bcf8bc7b9eac7761"  # Registry commit that contains r08-v6 (the Registry revocation-families head). It also contains r08-v1..r08-v5 byte-identical, so the same builders run against it.
PIN_V7 = "b73c59e6769acd5af7263397e81dfc6fa4561f38"  # Registry commit that contains r08-v7 (the unified-engine head); the final value set by the lead. It contains r08-v1..r08-v6 byte-identical.
ACCEPTED_PINS = (PIN, PIN_V6, PIN_V7)
_REQUIRED = os.environ.get("OCS_REQUIRE_REGISTRY_PIN") == "1"


def _unavailable(reason: str):
    if _REQUIRED:
        pytest.fail("OCS_REQUIRE_REGISTRY_PIN=1 but " + reason, pytrace=False)
    pytest.skip("NOT RUN: " + reason, allow_module_level=True)


PIN_DIR = os.environ.get("OCS_REGISTRY_PIN_DIR")
if not PIN_DIR or not (Path(PIN_DIR) / "registry_successor").is_dir():
    _unavailable("OCS_REGISTRY_PIN_DIR is not set to a Registry checkout")
PIN_DIR = str(Path(PIN_DIR).resolve())
_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PIN_DIR, capture_output=True, text=True).stdout.strip()
if _head not in ACCEPTED_PINS:
    _unavailable(f"Registry checkout is {_head!r}, expected the r08-v5 pin {PIN}, the r08-v6 pin {PIN_V6} or the r08-v7 pin {PIN_V7}")
sys.path.insert(0, PIN_DIR)
sys.path.insert(0, str(Path(PIN_DIR) / "tests"))
try:
    import nacl.bindings as nb
except ImportError:
    _unavailable("PyNaCl (Registry requirements-ed25519.lock.txt) is not installed")

import r08_support as r  # noqa: E402  (Registry test builders, reused)
import s01_support as s  # noqa: E402
from registry_adapters import ed25519_verifier as ev  # noqa: E402
from registry_successor import common as c  # noqa: E402
from registry_successor import v2_age_bounds as ab  # noqa: E402
from registry_successor import v2_policy_identity as v2i  # noqa: E402
from registry_successor import v5_class_unreadable as v5f  # noqa: E402
from registry_successor import v5_policy_identity as v5i  # noqa: E402
from registry_successor import verify as v  # noqa: E402

from agent_control_plane import registry_f4_age_governance as f4gov  # noqa: E402
from agent_control_plane import registry_f5_class_age_governance as agegov  # noqa: E402
from agent_control_plane import registry_f5_class_unreadable_governance as gov  # noqa: E402
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, BoundedRecordStore, LocalRefundDestination, ObservationPolicy, commitment  # noqa: E402
from agent_control_plane.freshness import FreshnessProfile  # noqa: E402
from agent_control_plane.registry_f4_age_governance import GovernedAgeWorkflow, GovernedScope, SelectionMaterial  # noqa: E402
from agent_control_plane.registry_f5_class_age_governance import GovernedClassAgeWorkflow, RegistryClassAgeRefused  # noqa: E402
from agent_control_plane.registry_f5_class_unreadable_governance import GovernedClassUnreadableWorkflow, RegistryClassUnreadableRefused  # noqa: E402
from agent_control_plane.reversibility import ReversibilityProfile  # noqa: E402
from agent_control_plane.runtime_authority import ActionClass, PurposeStatus, RuntimeAuthorityProfile, approval_commitment  # noqa: E402
from tests.test_bounded_authorization import INSTITUTION as MANIFEST_INSTITUTION  # noqa: E402,F401
from tests.test_bounded_authorization import NOW, PROFILE, manifest, tenant_proposal, tenant_resolver_for, TENANT  # noqa: E402
import tests.test_bounded_authorization as tba  # noqa: E402
from tests.test_runtime_authority import MEMBERS, PUBLIC, bind_approval, sign_evidence  # noqa: E402

REG_NOW = NOW  # one clock: the Registry verdict is judged at the Control Plane evaluation time
PK, SK = nb.crypto_sign_seed_keypair(bytes(range(32)))
OTHER_PK, OTHER_SK = nb.crypto_sign_seed_keypair(bytes(range(1, 33)))
V5_DOMAIN = b"ocs-reg/r08-v5/selection\n"
R_, B_ = "refuse", "bounded_tolerance"
CLASS_T1, CLASS_T2 = "synthetic-reversible", "synthetic-irreversible"
T2_ACTION = "urn:cognous:action:refund-issue-high-v1"
SRC = Path(gov.__file__).resolve().parent
MAXV = 2147483647


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    monkeypatch.setattr(gov, "_now", lambda: NOW)
    monkeypatch.setattr(agegov, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- Registry-side builders
def _sign(stmt, sk=None, domain=None):
    return base64.b64encode(nb.crypto_sign((domain or V5_DOMAIN) + c.canonical_bytes(stmt), sk or SK)[:64]).decode("ascii")


def umap(t1=None, t2=None, **more):
    out = {}
    if t1 is not None:
        out[CLASS_T1] = t1
    if t2 is not None:
        out[CLASS_T2] = t2
    out.update(more)
    return {k: out[k] for k in sorted(out)}


def urecord(m=None, *, family=None, contract="r08-v5", payload=None, **over):
    body = dict(r.make_record(), contract_version=contract, family=family or v5f.FAMILY_F5U, record_id="f5u-record",
                payload=payload if payload is not None else {v5f.F5U_FIELD: m if m is not None else umap(t1=R_)})
    body.update(over)
    return r.seal_record(body)


def arecord(m=None, *, family=None, contract="r08-v2", payload=None, **over):
    body = dict(r.make_record(), contract_version=contract, family=family or ab.FAMILY_F5, record_id="f5-age-record",
                payload=payload if payload is not None else {ab.F5_FIELD: m if m is not None else {CLASS_T1: 10}})
    body.update(over)
    return r.seal_record(body)


def trust_for(op, version=1, valid_until="2026-10-07T00:00:00Z", grant=None, **kw):
    grant = grant or v.AuthorityGrant("consumer-test", TENANT.lower(), INSTITUTION, DOMAIN, op)
    return v.TrustSnapshot("snap-test-1", version, valid_until, (v.IssuerEntry(s.KEY_ID, "issuer-test-1", "ed25519", PK, (grant,)),), **kw)


ACTION_ID = [a for a in manifest()["actions"]][0]["action_id"]
_AUTH = [a for a in manifest()["actions"]][0]["authority_context"]
INSTITUTION, DOMAIN = _AUTH["institution_id"], _AUTH["authority_domain"]
OP_U, OP_A = "refund-issue-unreadable", "refund-issue-routine"
SCOPE = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_U)
SCOPE_A = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_A)
EFFECTIVE = {"valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-06T00:00:00Z"}
STMT_SCOPE = {"tenant": TENANT.lower(), "institution": INSTITUTION, "authority_domain": DOMAIN}


def _material(rec, *, op, contract, domain, family, sk=None, trust=None, record_text=None, stmt_over=None):
    over = dict(consumer_id="consumer-test", scope=STMT_SCOPE, operation=op, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z", family=family)
    over.update(stmt_over or {})
    stmt = r.make_statement_v2(rec, **over)
    if trust is None:
        sc = over["scope"]
        trust = trust_for(op, grant=v.AuthorityGrant(over["consumer_id"], sc["tenant"], sc["institution"], sc["authority_domain"], over["operation"]))
    sel = r.dumps(s.envelope(stmt, domain=domain, contract=contract, signature=_sign(stmt, sk, domain), pub=PK))
    return SelectionMaterial(record_text if record_text is not None else r.dumps(rec), sel, trust)


def mat(m=None, *, rec=None, contract="r08-v5", domain=None, **kw):
    """on_unreadable (r08-v5) selection material."""
    rec = rec or urecord(m)
    stmt_over = dict(kw.pop("stmt_over", {}))
    stmt_over.setdefault("operation", OP_U)
    stmt_over["family"] = stmt_over.get("family", rec.get("family", v5f.FAMILY_F5U))
    return _material(rec, op=stmt_over.pop("operation"), contract=contract, domain=domain or V5_DOMAIN, family=stmt_over.pop("family"),
                     stmt_over=stmt_over, **kw)


def amat(m=None, *, rec=None, contract="r08-v2", domain=None, **kw):
    """Class status-age (r08-v2 F5) selection material, for the joint workflow."""
    rec = rec or arecord(m)
    stmt_over = dict(kw.pop("stmt_over", {}))
    stmt_over.setdefault("operation", OP_A)
    stmt_over["family"] = stmt_over.get("family", rec.get("family", ab.FAMILY_F5))
    return _material(rec, op=stmt_over.pop("operation"), contract=contract, domain=domain or s.V2_DOMAIN, family=stmt_over.pop("family"),
                     stmt_over=stmt_over, **kw)


def revoked(factory, *a, op=OP_U, **k):
    return factory(*a, trust=trust_for(op, revoked_selections=frozenset({("sel-test-1", 1)})), **k)


def withdrawn(factory_rec, factory, op, domain, contract, family):
    rec = factory_rec()
    stmt = r.make_statement_v2(rec, family=family, consumer_id="consumer-test", scope=STMT_SCOPE, operation=op, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    wd = s.withdraw_statement(stmt)
    return SelectionMaterial(r.dumps(rec), r.dumps(s.envelope(wd, domain=domain, contract=contract, signature=_sign(wd, domain=domain), pub=PK)), trust_for(op))


class Source:
    """A host selection source whose material can change between boundaries."""
    def __init__(self, material):
        self.mat, self.calls, self.fail = material, 0, False
        self.after = None  # (call number, material): from that call on the source serves the other material

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("source down")
        if self.after is not None and self.calls >= self.after[0]:
            return self.after[1]
        return self.mat


# --------------------------------------------------------------------------------------------------------------- Control Plane fixtures
def host_profile(p, *, t1=B_, t2=R_, t1_irrev=False, t2_irrev=True, age1=60, age2=120, freshness=None, shared=None, extra_actions=None, reversibility=None, **over):
    """A HOST profile with two classes: the scoped action (class T1, reversible, bounded_tolerance by default) and the T2 action (class T2, irreversible, refuse).
    `shared` gives the T2 action the T1 class id (and the value `shared`)."""
    actions = {p.action_id: ActionClass(class_id=CLASS_T1, irreversible=t1_irrev, max_status_age_seconds=age1, on_unreadable=t1),
               T2_ACTION: ActionClass(class_id=CLASS_T1 if shared else CLASS_T2, irreversible=t2_irrev, max_status_age_seconds=age1 if shared else age2,
                                      on_unreadable=shared if shared else t2)}
    actions.update(extra_actions or {})
    extra = dict(over)
    if freshness:
        extra["freshness"] = freshness
    if reversibility:
        extra["reversibility"] = reversibility
    return RuntimeAuthorityProfile(catalogue_version="synthetic-catalogue/1", actions=actions, producer_keys={"synthetic-validator": PUBLIC},
                                   allow_synthetic_resolver=True, **extra)


def prepared(tmp_path, *, purpose=False, **profile_kw):
    """(proposal, resolver, HOST profile) with the runtime-authority context built exactly as tests/test_runtime_authority.setup_flow does, tenant-aware."""
    p = tenant_proposal()
    res = tenant_resolver_for(p)
    cfg = host_profile(p, **profile_kw)
    base = tba.tenant_workflow(tmp_path / "baseline", p, resolver=res).decide(p, now=NOW)
    required = sorted([{"input_type": x.input_type, "input_id": x.input_id} for x in base.resolution_inputs], key=lambda x: (x["input_type"], x["input_id"]))
    context, criteria = res.contexts[PROFILE], {}
    for ob in context["requirement"]["evidence"]:
        if ob["required"] and ob["kind"] == "authorization":
            criteria[ob["obligation_id"]] = {"kind": "exact_members", "producer_id": "synthetic-validator", "subject_digest": commitment(MEMBERS),
                                             "minimum_count": 40, "members": MEMBERS}
            sign_evidence(res.evidence[ob["obligation_id"]], tenant_id=TENANT)
    context["runtime_authority"] = {"profile": "runtime-authority/0.1", "required_inputs": required, "required_inputs_digest": commitment(required),
                                    "evidence_criteria": criteria}
    if purpose:
        context["grant"]["purpose_ref"] = {"system": "synthetic-cases", "record_id": "case-1", "epoch": "epoch-1"}
        res.purpose = PurposeStatus(system="synthetic-cases", record_id="case-1", epoch="epoch-1", institution_id=MANIFEST_INSTITUTION,
                                    authority_domain="customer-refunds", tenant_id=TENANT, state="open", observed_at=NOW.isoformat(), epoch_capability="authoritative")
        res.purpose_status = lambda ref: res.purpose.model_dump()
    return p, res, cfg


def kwargs(tmp_path, res, **kw):
    return dict(allow_test_time=True, manifest=manifest(), resolver=res, destination=kw.pop("destination", None) or LocalRefundDestination(tmp_path / "destination.json"),
                records=BoundedRecordStore(tmp_path / "run.json", "run-1"), observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def gbuild(tmp_path, source, res, cfg, *, age=None, **kw):
    """Governed workflow. `age` is the optional class-age Source (joint workflow)."""
    joint = {"class_age_scope": kw.pop("age_scope", SCOPE_A), "class_age_selection_source": age} if age is not None else {}
    return GovernedClassUnreadableWorkflow(scope=kw.pop("scope", SCOPE), selection_source=source, verifier=kw.pop("verifier", ev.Ed25519Verifier()),
                                           runtime_authority_profile=kw.pop("profile", cfg), construction_time=kw.pop("construction_time", REG_NOW),
                                           **joint, **kwargs(tmp_path, res, **kw))


def ready(tmp_path, m=None, *, source=None, age_m=None, age_source=None, purpose=False, bind=True, **profile_kw):
    """Governed workflow with approvals issued against its EFFECTIVE profile. Returns (proposal, resolver, host profile, source, flow)."""
    p, res, cfg = prepared(tmp_path, purpose=purpose, **profile_kw)
    src = source or Source(mat(m if m is not None else umap(t1=R_)))
    asrc = age_source if age_source is not None else (Source(amat(age_m)) if age_m is not None else None)
    flow = gbuild(tmp_path, src, res, cfg, age=asrc)
    flow.test_age_source = asrc
    if bind:
        bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, src, flow


def plain(tmp_path, res, profile, **kw):
    """The existing workflow built directly with `profile` (the oracle for equivalence)."""
    return BoundedAuthorizationWorkflow(runtime_authority_profile=profile, **kwargs(tmp_path, res, **kw))


def unreadable(res, cached=True, age=1):
    """The grant status cannot be read; a trusted cached positive exists (the outage case the parameter governs)."""
    status = next(iter(res.statuses.values())).model_copy(deep=True)
    status.observed_at = (NOW - timedelta(seconds=age)).isoformat()
    res.grant_status = lambda ref: None
    res.cached_grant_status = lambda ref: status if cached else None


def age_status(res, seconds):
    ctx = res.contexts[PROFILE]
    res.statuses[ctx["grant"]["grant_id"]].observed_at = (NOW - timedelta(seconds=seconds)).isoformat()


def file_state(tmp_path, flow):
    return (sorted((x.name, x.read_bytes()) for x in tmp_path.glob("*.json")), flow.destination.snapshot())


def refused(exc, code=None, registry_code=None, boundary=None):
    e = exc.value
    assert isinstance(e, PermissionError) and isinstance(e, RegistryClassUnreadableRefused) and e.refusal.non_authorizing is True
    if code:
        assert e.refusal.code == code, e.refusal
    if registry_code:
        assert e.refusal.registry_code == registry_code, e.refusal
    if boundary:
        assert e.boundary == boundary
    return e


def uvals(profile):
    return {a.class_id: a.on_unreadable for a in profile.actions.values()}


def ages(profile):
    return {a.class_id: a.max_status_age_seconds for a in profile.actions.values()}


def dump_without(profile, field):
    doc = profile.model_dump(mode="json")
    for a in doc["actions"].values():
        a.pop(field, None)
    return doc


# =============================================================================================================== construction
def test_g01_valid_selection_narrows_bounded_tolerance_to_refuse_and_carries_identity(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    prof = flow.runtime_authority_profile
    assert uvals(prof) == {CLASS_T1: R_, CLASS_T2: R_} and uvals(cfg) == {CLASS_T1: B_, CLASS_T2: R_}  # the host profile object is untouched
    assert prof.actions[p.action_id].on_unreadable == R_
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds, flow.identity_max_age_seconds, flow.mandate_max_age_seconds,
            flow.clock_tolerance_seconds) == (60, 60, 60, 60, 5)  # excluded values untouched
    assert ages(prof) == ages(cfg)
    ident = flow.registry_f5_unreadable_policy_identity
    assert ident["contract_version"] == "r08-v5" and ident["family"] == v5f.FAMILY_F5U and ident["effective"] == {CLASS_T1: R_, CLASS_T2: R_}
    assert ident["effective_policy_digest"] == v5i.effective_policy_digest(v5f.FAMILY_F5U, {v5f.F5U_FIELD: ident["effective"]})
    assert ident["effective_profile_digest"] == agegov.profile_digest(prof) and ident["host"] == {CLASS_T1: B_, CLASS_T2: R_} and ident["class_age"] is None
    assert ident["scope"] == {"consumer_id": "consumer-test", "tenant_id": TENANT.lower(), "action_id": ACTION_ID, "operation_id": OP_U}


@pytest.mark.parametrize("host,reg", [(B_, R_), (B_, B_), (R_, R_), (R_, B_)])
def test_g02_the_four_value_pairs_never_widen_and_the_unnamed_class_keeps_its_host_value(tmp_path, host, reg):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=reg), t1=host)
    got = flow.runtime_authority_profile.actions[p.action_id].on_unreadable
    assert got == (R_ if R_ in (host, reg) else B_) and v5f._RANK[got] <= v5f._RANK[host]
    assert uvals(flow.runtime_authority_profile)[CLASS_T2] == R_  # T2 is not named by the record


@pytest.mark.parametrize("host,reg", [(B_, B_), (R_, R_), (R_, B_)])
def test_g03_a_registry_value_that_narrows_nothing_leaves_the_profile_and_every_existing_approval_unchanged(tmp_path, host, reg):
    p, res, cfg = prepared(tmp_path, t1=host)
    bind_approval(res, cfg)  # approval issued against the HOST profile, before any Registry involvement
    flow = gbuild(tmp_path, Source(mat(umap(t1=reg))), res, cfg)
    assert flow.runtime_authority_profile.model_dump(mode="json") == cfg.model_dump(mode="json")
    ctx = res.contexts[PROFILE]
    assert approval_commitment(flow.runtime_authority_profile, ctx) == approval_commitment(cfg, ctx)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_g04_a_narrowing_selection_changes_the_commitment_and_an_old_approval_must_be_reissued(tmp_path):
    p, res, cfg = prepared(tmp_path)
    ctx = res.contexts[PROFILE]
    bind_approval(res, cfg)  # issued for the host profile
    flow = gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts
    bind_approval(res, flow.runtime_authority_profile)  # a NEW approval over the effective profile
    d2 = flow.decide(p, now=NOW)
    assert d2.result == "authorized", d2.reasons
    attempt, observed = flow.execute(p, d2, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_g05_multiple_classes_each_use_their_own_value(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_, t2=B_), t1=B_, t2=R_)
    assert uvals(flow.runtime_authority_profile) == {CLASS_T1: R_, CLASS_T2: R_}  # T2: a looser Registry value never widens the host refuse


def test_g06_a_registry_class_unknown_to_the_host_is_refused_not_created(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t1=R_, **{"synthetic-unknown": R_}))), res, cfg)
    refused(e, "registry_not_applied", "composition_record_invalid", "construction")


def test_g07_a_record_silent_about_the_scoped_class_governs_nothing_and_is_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t2=R_))), res, cfg)
    refused(e, "scoped_class_not_governed", boundary="construction")


def test_g08_two_actions_sharing_a_class_need_one_host_value_and_both_get_the_narrowed_value(tmp_path):
    p, res, cfg = prepared(tmp_path, shared=B_, t2_irrev=False)
    flow = gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)
    assert {a.on_unreadable for a in flow.runtime_authority_profile.actions.values()} == {R_}
    p, res, cfg = prepared(tmp_path / "b", shared=R_, t2_irrev=False)  # same class id, a different host value: ambiguous, fail closed
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "b", Source(mat(umap(t1=R_))), res, cfg)
    refused(e, "class_unreadable_ambiguous", boundary="construction")


def test_g09_construction_inputs_are_validated(tmp_path):
    p, res, cfg = prepared(tmp_path)
    for name, kw, code in (("none", dict(profile=None), "runtime_authority_profile_required"),
                           ("garbage", dict(profile={"nonsense": 1}), "host_profile_invalid"),
                           ("scope", dict(scope=GovernedScope("", TENANT, ACTION_ID, OP_U)), "scope_invalid"),
                           ("unknown_action", dict(scope=GovernedScope("consumer-test", TENANT, "no.such.action", OP_U)), "action_class_unknown")):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path / name, Source(mat()), res, cfg, **kw)
        refused(e, code, boundary="construction")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "src", "not callable", res, cfg)
    refused(e, "selection_source_invalid")
    extra = "urn:cognous:action:in-profile-not-in-manifest"
    with pytest.raises(RegistryClassUnreadableRefused) as e:  # in the host profile but not declared by the manifest: no authority context to scope the Registry call
        gbuild(tmp_path / "undeclared", Source(mat()), res, cfg, scope=GovernedScope("consumer-test", TENANT, extra, OP_U),
               profile=host_profile(p, extra_actions={extra: ActionClass(class_id=CLASS_T1, irreversible=False, max_status_age_seconds=60, on_unreadable=B_)}))
    refused(e, "manifest_action_undeclared", boundary="construction")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "naive", Source(mat()), res, cfg, construction_time=datetime(2026, 10, 5, 19, 0))
    refused(e, "time_invalid")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "nodest", Source(mat()), res, cfg, destination=None) if False else GovernedClassUnreadableWorkflow(
            scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
            allow_test_time=True, manifest=manifest(), resolver=res, records=BoundedRecordStore(tmp_path / "nd.json", "run-1"))
    refused(e, "destination_invalid")


def test_g10_a_profile_that_already_carries_an_approval_generation_binding_is_refused(tmp_path):
    from agent_control_plane.policy_binding import PolicyBinding
    p, res, cfg = prepared(tmp_path)
    binding = PolicyBinding(binding_digest="sha256:" + "1" * 64, selection_epoch=1, activation_ref="sha256:" + "2" * 64, policy_generation=1, disposition="selected")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg, profile=host_profile(p, policy_binding=binding))
    refused(e, "policy_binding_unsupported", boundary="construction")


@pytest.mark.parametrize("pl", [{}, {"other": {CLASS_T1: R_}}, {v5f.F5U_FIELD: {CLASS_T1: R_}, "x": 1}, {v5f.F5U_FIELD: {}}, {v5f.F5U_FIELD: [R_]},
                                {v5f.F5U_FIELD: {CLASS_T1: True}}, {v5f.F5U_FIELD: {CLASS_T1: 1}}, {v5f.F5U_FIELD: {CLASS_T1: 1.5}}, {v5f.F5U_FIELD: {CLASS_T1: None}},
                                {v5f.F5U_FIELD: {CLASS_T1: "tolerate"}}, {v5f.F5U_FIELD: {CLASS_T1: "Refuse"}}, {v5f.F5U_FIELD: {CLASS_T1: "REFUSE"}},
                                {v5f.F5U_FIELD: {CLASS_T1: "bounded-tolerance"}}, {v5f.F5U_FIELD: {CLASS_T1: ""}}, {v5f.F5U_FIELD: {CLASS_T1: "allow"}},
                                {v5f.F5U_FIELD: {"bad class": R_}}, {v5f.F5U_FIELD: {"": R_}}, {v5f.F5U_FIELD: {CLASS_T1 + "*": R_}},
                                {"class_status_max_age_seconds": {CLASS_T1: 10}}, {"clock_tolerance_seconds": 5}])
def test_g11_missing_or_malformed_records_and_unknown_enum_values_are_refused(tmp_path, pl):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(rec=urecord(payload=pl))), res, cfg)
    refused(e, "registry_not_applied", boundary="construction")


def test_g12_invalid_record_text_and_material_types(tmp_path):
    p, res, cfg = prepared(tmp_path)
    for bad in (SelectionMaterial("{}", mat().selection_text, trust_for(OP_U)), SelectionMaterial("not json", mat().selection_text, trust_for(OP_U))):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path, Source(bad), res, cfg)
        refused(e, "registry_not_applied")
    for bad in (None, "x", object(), SelectionMaterial(None, "x", None), SelectionMaterial("x", b"x", None)):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path, Source(bad), res, cfg)
        refused(e, "material_invalid")


def test_g13_wrong_contract_family_signature_and_domain(tmp_path):
    p, res, cfg = prepared(tmp_path)
    base = urecord()
    for label in ("r08-v1", "r08-v2", "r08-v3", "r08-v4", "r08-v6", "R08-V5", ""):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path / ("c" + label), Source(mat(rec=base, contract=label)), res, cfg)
        refused(e, "registry_not_applied")
    age_rec = arecord()  # the class-AGE family is never consumed as the on_unreadable policy (and its r08-v2 contract is refused by the r08-v5 entry point)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "age", Source(amat(rec=age_rec, stmt_over={"operation": OP_U}, trust=trust_for(OP_U))), res, cfg)
    refused(e, "registry_not_applied", "contract_unsupported")
    age_in_v5 = urecord(family=ab.FAMILY_F5, payload={ab.F5_FIELD: {CLASS_T1: 10}})
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "age5", Source(mat(rec=age_in_v5)), res, cfg)
    refused(e, "registry_not_applied", "family_unsupported")
    for fam in ("f4-control-plane-age-bounds", "f1abcd-local-execution-limits", "f4t-control-plane-clock-tolerance", "unknown-family"):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path / ("f" + fam[:6]), Source(mat(rec=urecord(family=fam), stmt_over={"family": fam})), res, cfg)
        refused(e, "registry_not_applied")
    for i, kw in enumerate(({"sk": OTHER_SK}, {"domain": b"ocs-reg/r08-v4/selection\n"}, {"domain": s.V2_DOMAIN})):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path / f"s{i}", Source(mat(**kw)), res, cfg)
        refused(e, "registry_not_applied", "signature_invalid")


@pytest.mark.parametrize("over,code", [({"consumer_id": "other-consumer"}, "selection_consumer_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, tenant="tenant-other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, institution="urn:cognous:institution:other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, authority_domain="other-domain")}, "selection_scope_mismatch"),
                                       ({"operation": "other.action"}, "selection_operation_mismatch")])
def test_g14_wrong_authority_scope_tenant_or_operation(tmp_path, over, code):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(stmt_over=over)), res, cfg)
    refused(e, "registry_not_applied", code)


def test_g15_expired_stale_trust_revoked_and_withdrawn_at_construction(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "a", Source(mat()), res, cfg, construction_time=REG_NOW + timedelta(hours=6))
    refused(e, "registry_not_applied", "selection_expired")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "b", Source(mat(trust=trust_for(OP_U, valid_until="2026-10-04T00:00:00Z"))), res, cfg)
    refused(e, "registry_not_applied", "trust_snapshot_expired")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "c", Source(revoked(mat)), res, cfg)
    refused(e, "registry_not_applied", "selection_revoked")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "d", Source(_wd_u()), res, cfg)
    refused(e, "registry_not_applied", "selection_withdrawn")
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "e", Source(mat(trust=trust_for(OP_U, min_epochs=(("sel-test-1", 2),)))), res, cfg)
    refused(e, "registry_not_applied", "selection_epoch_stale")


def _wd_u():
    return withdrawn(urecord, mat, OP_U, V5_DOMAIN, "r08-v5", v5f.FAMILY_F5U)


def _wd_a():
    return withdrawn(arecord, amat, OP_A, s.V2_DOMAIN, "r08-v2", ab.FAMILY_F5)


def test_g16_optional_participation_and_non_admitted_verifiers_are_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "a", Source(mat(stmt_over={"participation": "optional"})), res, cfg)
    refused(e, "registry_not_applied")
    for i, vf in enumerate((object(), None, ev.Ed25519Verifier, type("Sub", (ev.Ed25519Verifier,), {})())):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            gbuild(tmp_path / f"v{i}", Source(mat()), res, cfg, verifier=vf)
        refused(e, "verifier_not_admitted")


def test_g17_a_host_class_id_the_registry_cannot_govern_fails_closed(tmp_path):
    p, res, cfg = prepared(tmp_path)
    odd = host_profile(p, extra_actions={"urn:cognous:action:odd": ActionClass(class_id="not a token", irreversible=False, max_status_age_seconds=5, on_unreadable=B_)})
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "odd", Source(mat()), res, cfg, profile=odd)
    refused(e, "registry_not_applied", "composition_caller_invalid")


def test_g18_a_refused_construction_writes_nothing(tmp_path):
    p, res, cfg = prepared(tmp_path / "prep")
    (tmp_path / "w").mkdir()
    dest, store = LocalRefundDestination(tmp_path / "w" / "destination.json"), BoundedRecordStore(tmp_path / "w" / "run.json", "run-1")
    listing = sorted(x.name for x in (tmp_path / "w").glob("*"))
    with pytest.raises(RegistryClassUnreadableRefused):
        GovernedClassUnreadableWorkflow(scope=SCOPE, selection_source=Source(mat(sk=OTHER_SK)), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, allow_test_time=True,
                                        manifest=manifest(), resolver=res, destination=dest, records=store)
    assert sorted(x.name for x in (tmp_path / "w").glob("*")) == listing and dest.snapshot()["effects"] == {}


def test_g19_the_class_age_pair_is_all_or_nothing_and_scope_bound(tmp_path):
    p, res, cfg = prepared(tmp_path)
    common = dict(scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW)
    for i, extra in enumerate(({"class_age_scope": SCOPE_A}, {"class_age_selection_source": Source(amat())}, {"class_age_scope": SCOPE_A, "class_age_selection_source": "x"},
                               {"class_age_scope": "x", "class_age_selection_source": Source(amat())})):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            GovernedClassUnreadableWorkflow(**common, **extra, **kwargs(tmp_path / f"p{i}", res))
        refused(e, "class_age_configuration_invalid", boundary="construction")
    for i, other in enumerate((GovernedScope("other-consumer", TENANT.lower(), ACTION_ID, OP_A), GovernedScope("consumer-test", "tenant-other", ACTION_ID, OP_A),
                               GovernedScope("consumer-test", TENANT.lower(), T2_ACTION, OP_A))):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            GovernedClassUnreadableWorkflow(**common, class_age_scope=other, class_age_selection_source=Source(amat()), **kwargs(tmp_path / f"m{i}", res))
        refused(e, "class_age_scope_mismatch", boundary="construction")


# =============================================================================================================== irreversibility and the invalid-class (heal) guard
def test_i01_a_valid_irreversible_class_is_already_refuse_a_registry_value_changes_nothing(tmp_path):
    p, res, cfg = prepared(tmp_path, t1=R_, t1_irrev=True)
    bind_approval(res, cfg)
    for reg in (R_, B_):
        flow = gbuild(tmp_path / reg, Source(mat(umap(t1=reg))), res, cfg)
        assert flow.runtime_authority_profile.model_dump(mode="json") == cfg.model_dump(mode="json")
        assert flow.decide(p, now=NOW).result == "authorized"


def test_i02_an_invalid_host_declaration_is_refused_before_any_registry_call_never_repaired_by_a_refuse(tmp_path):
    p, res, cfg = prepared(tmp_path, t1=B_, t1_irrev=True)
    bind_approval(res, cfg)
    oracle = plain(tmp_path / "plain", res, cfg)
    d = oracle.decide(p, now=NOW)
    assert d.result == "hold" and "action_class_invalid" in d.reasons  # the unmodified workflow: every action of the class refuses
    src = Source(mat(umap(t1=R_)))
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "g", src, res, cfg)
    refused(e, "host_class_invalid", boundary="construction")
    assert src.calls == 0  # validated BEFORE the selection source / Registry is consulted


def test_i03_a_registry_bounded_tolerance_does_not_make_an_invalid_host_admissible_either(tmp_path):
    p, res, cfg = prepared(tmp_path, t1=B_, t1_irrev=True)
    src = Source(mat(umap(t1=B_)))
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, src, res, cfg)  # the defect is surfaced, not carried into a workflow that would silently hold
    refused(e, "host_class_invalid", boundary="construction")
    assert src.calls == 0


def test_i04_an_invalid_irreversible_action_sharing_a_class_with_the_scoped_one_refuses_the_whole_profile(tmp_path):
    p, res, cfg = prepared(tmp_path, shared=B_, t2_irrev=True)  # the T2 action shares the scoped class, is irreversible and (invalidly) tolerant
    src = Source(mat(umap(t1=R_)))
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, src, res, cfg)
    refused(e, "host_class_invalid", boundary="construction")
    assert src.calls == 0


def test_i04b_the_invalid_host_is_refused_in_the_joint_workflow_before_either_source_is_read(tmp_path):
    p, res, cfg = prepared(tmp_path, t1=B_, t1_irrev=True)
    usrc, asrc = Source(mat(umap(t1=R_))), Source(amat(AGE_M))
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, usrc, res, cfg, age=asrc)
    refused(e, "host_class_invalid", boundary="construction")
    assert usrc.calls == 0 and asrc.calls == 0


def test_i04c_a_valid_host_is_unaffected_and_the_defect_check_is_exact(tmp_path):
    for t1, irrev, defect in ((B_, False, None), (R_, False, None), (R_, True, None), (B_, True, "host_class_invalid")):
        p, res, cfg = prepared(tmp_path / f"{t1}{irrev}", t1=t1, t1_irrev=irrev)
        assert gov.host_class_defect(cfg) == defect


def test_i04d_defence_in_depth_direct_derive_still_refuses_a_healing_narrowing(tmp_path):
    """`derive_unreadable` called directly with an invalid host (bypassing the constructor) still refuses to heal it."""
    p, res, cfg = prepared(tmp_path, t1=B_, t1_irrev=True)
    host_values, _ = gov.host_class_unreadable(cfg)
    got, refusal = gov.derive_unreadable(scope=SCOPE, institution_id=INSTITUTION, authority_domain=DOMAIN, host=cfg, host_values=host_values, material=mat(umap(t1=R_)),
                                         verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and refusal.code == "registry_would_heal_invalid_class"


def test_i05_reversibility_members_survive_composition_and_only_on_unreadable_changes(tmp_path):
    until = (NOW + timedelta(seconds=40)).isoformat()
    cls = ActionClass(class_id=CLASS_T1, reversibility="reversible_until", reversible_until=until, max_status_age_seconds=60, on_unreadable=B_)
    p, res, cfg = prepared(tmp_path, reversibility=ReversibilityProfile())
    cfg = host_profile(p, reversibility=ReversibilityProfile(), extra_actions={p.action_id: cls})
    assert cfg.actions[p.action_id].reversibility == "reversible_until"
    flow = gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)
    eff = flow.runtime_authority_profile
    assert eff.actions[p.action_id].on_unreadable == R_ and eff.actions[p.action_id].reversibility == "reversible_until" and eff.actions[p.action_id].reversible_until == until
    assert dump_without(eff, "on_unreadable") == dump_without(cfg, "on_unreadable")


# =============================================================================================================== real enforcement
def test_e01_the_ungoverned_host_baseline_tolerates_an_unreadable_grant_through_the_cached_positive(tmp_path):
    p, res, cfg = prepared(tmp_path)
    bind_approval(res, cfg)
    unreadable(res)
    d = plain(tmp_path / "plain", res, cfg).decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert any(x.input_type == "grant" and x.read_state == "cached_positive" for x in d.resolution_inputs)


def test_e02_a_registry_refuse_turns_the_same_outage_into_a_refusal_without_effects(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    unreadable(res)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "status_unreadable" in d.reasons
    assert not any(x.read_state == "cached_positive" for x in d.resolution_inputs)
    assert flow.destination.snapshot()["effects"] == {}
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)  # a hold cannot be executed
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts


@pytest.mark.parametrize("host,reg,cache,age", [(B_, R_, True, 1), (B_, B_, True, 1), (R_, R_, True, 1), (R_, B_, True, 1), (B_, B_, False, 1), (B_, B_, True, 61), (B_, R_, False, 1)])
def test_e03_governed_decisions_equal_the_existing_workflow_built_with_the_effective_profile(tmp_path, host, reg, cache, age):
    p, res, cfg, src, flow = ready(tmp_path / "g", umap(t1=reg), t1=host)
    unreadable(res, cached=cache, age=age)
    oracle = plain(tmp_path / "p", res, flow.runtime_authority_profile)
    got, want = flow.decide(p, now=NOW), oracle.decide(p, now=NOW)
    assert (got.result, got.reasons) == (want.result, want.reasons), (host, reg, cache, age)
    assert (got.result == "authorized") == (host == B_ and reg == B_ and cache and age <= 60)  # only the tolerant, cached, in-bound case passes


@pytest.mark.parametrize("reg", [R_, B_])
def test_e04_readable_evidence_behaves_exactly_as_before(tmp_path, reg):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=reg))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert not any(x.read_state == "cached_positive" for x in d.resolution_inputs)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    p2, res2, cfg2, src2, flow2 = ready(tmp_path / "stale", umap(t1=reg))
    age_status(res2, 61)
    assert "grant_status_stale_or_future" in flow2.decide(p2, now=NOW).reasons  # the age bound is untouched


def test_e05_refuse_stays_refuse_and_a_registry_bounded_tolerance_never_enables_the_cached_positive(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=B_), t1=R_)
    unreadable(res)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "status_unreadable" in d.reasons and uvals(flow.runtime_authority_profile)[CLASS_T1] == R_


def test_e06_a_recorded_denial_still_overrides_a_tolerated_cache_unchanged(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=B_), t1=B_)
    status = next(iter(res.statuses.values()))
    old = status.model_copy(deep=True)
    status.status = "revoked"
    d = flow.decide(p, now=NOW)
    assert "grant_revoked" in d.reasons
    res.grant_status = lambda ref: None
    res.cached_grant_status = lambda ref: old
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "status_unreadable" in d.reasons


def test_e07_full_flow_executes_when_selection_stays_valid_with_four_source_calls(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=B_))
    assert src.calls == 1
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and src.calls == 4  # construction, decision, effect entry, commit gate


def test_e08_the_parameter_governs_only_the_cached_grant_branch_and_a_source_change_would_need_re_review():
    """Pin of the documented limit: the evaluator reads `on_unreadable` in exactly these two places; the cached-purpose path never does."""
    import agent_control_plane.bounded as bounded
    import agent_control_plane.reversibility as rev
    text = (SRC / "bounded.py").read_text()
    assert text.count("on_unreadable") == 2
    assert 'action_class.irreversible and action_class.on_unreadable != "refuse"' in text and 'cl.on_unreadable == "bounded_tolerance" and cached' in text
    assert "on_unreadable" not in inspect.getsource(bounded.BoundedAuthorizationWorkflow._cached_purpose)
    assert "on_unreadable" not in inspect.getsource(rev.judge_cached_purpose) and "on_unreadable" not in inspect.getsource(rev.effective_reversibility)
    other = {p.name for p in SRC.glob("*.py") if "on_unreadable" in p.read_text() and p.name not in ("bounded.py", "runtime_authority.py", Path(gov.__file__).name, "registry_governed_policy.py", "registry_irreversibility_governance.py")}  # the composed workflow validates the final composition of this field
    assert other == set(), other


def test_e09_cached_purpose_behaviour_is_unchanged_by_a_registry_refuse(tmp_path):
    """The cached-PURPOSE snapshot path (reversibility/0.1) never reads on_unreadable: with a purpose outage the same reversible class proceeds on the cached open snapshot whether the
    class value is the host `bounded_tolerance` (existing workflow) or the Registry-narrowed `refuse` (governed). Documented limit; a protected-evaluator change would be needed to wire it."""
    outcomes = {}
    for label, governed in (("plain", False), ("governed", True)):
        d_ = tmp_path / label
        until = (NOW + timedelta(seconds=300)).isoformat()
        cls_ = ActionClass(class_id=CLASS_T1, reversibility="reversible_until", reversible_until=until, max_status_age_seconds=60, on_unreadable=B_)
        p, res, cfg = prepared(d_, purpose=True, reversibility=ReversibilityProfile())
        cfg = host_profile(p, reversibility=ReversibilityProfile(), extra_actions={p.action_id: cls_})
        flow = gbuild(d_, Source(mat(umap(t1=R_))), res, cfg) if governed else plain(d_, res, cfg)
        assert flow.runtime_authority_profile.actions[p.action_id].on_unreadable == (R_ if governed else B_)
        bind_approval(res, flow.runtime_authority_profile)
        res.cached = res.purpose.model_copy()
        res.cached_purpose_status = lambda ref: res.cached.model_dump()
        d = flow.decide(p, now=NOW)
        assert d.result == "authorized", d.reasons

        def broken(ref):
            raise TimeoutError("purpose store unavailable")
        res.purpose_status = broken
        attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW + timedelta(seconds=30))
        (use,) = flow.records.load().snapshot_uses
        outcomes[label] = (attempt.status, use.accepted, use.basis, use.effective_status, use.age_seconds)
    assert outcomes["plain"] == outcomes["governed"] == ("acknowledged", True, "cached_snapshot", "open", 30)


# =============================================================================================================== commitment binding
def test_m01_the_commitment_and_the_persisted_binding_carry_the_effective_value(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    ext = d.binding.runtime_authority
    assert ext["approval_commitment"] == approval_commitment(flow.runtime_authority_profile, res.contexts[PROFILE])
    assert ext["catalogue_digest"] == agegov.profile_digest(flow.runtime_authority_profile) == flow.registry_f5_unreadable_policy_identity["effective_profile_digest"]
    assert ext["approval_commitment"] != approval_commitment(cfg, res.contexts[PROFILE]) and ext["catalogue_digest"] != agegov.profile_digest(cfg)


@pytest.mark.parametrize("host,reg,changes", [(B_, R_, True), (B_, B_, False), (R_, R_, False), (R_, B_, False)])
def test_m02_the_commitment_changes_if_and_only_if_the_value_narrows(tmp_path, host, reg, changes):
    p, res, cfg = prepared(tmp_path, t1=host)
    flow = gbuild(tmp_path, Source(mat(umap(t1=reg))), res, cfg)
    ctx = res.contexts[PROFILE]
    assert (approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)) is changes


def test_m03_a_different_effective_policy_cannot_ride_an_approval_issued_for_another(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_, t2=R_), t1=B_, t2=R_)  # approval A over the effective profile
    src.mat = mat(umap(t1=B_), stmt_over={"selection_id": "sel-test-2", "epoch": 2})  # replaced by a selection that narrows nothing
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)  # the running workflow refuses the changed selection ...
    refused(e, "selection_changed", boundary="decision")
    flow2 = gbuild(tmp_path / "rebuilt", src, res, cfg)  # ... and a rebuilt workflow under the new selection does not honour approval A
    d = flow2.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow2.runtime_authority_profile)
    assert flow2.decide(p, now=NOW).result == "authorized"


def test_m04_selection_replaced_after_decision_blocks_the_effect_and_a_rebuilt_workflow_cannot_execute_the_old_decision(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    src.mat = mat(umap(t1=B_), stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    before = file_state(tmp_path, flow)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_changed", boundary="effect")
    assert file_state(tmp_path, flow) == before
    flow2 = GovernedClassUnreadableWorkflow(scope=SCOPE, selection_source=src, verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                                            **kwargs(tmp_path, res))  # same record store, new effective profile (nothing narrowed)
    bind_approval(res, flow2.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow2.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow2.destination.snapshot()["effects"] == {}


def test_m05_editing_the_held_profile_to_widen_or_swap_a_class_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    held = flow.runtime_authority_profile
    widened = {p.action_id: held.actions[p.action_id].model_copy(update={"on_unreadable": B_}), T2_ACTION: held.actions[T2_ACTION]}
    swapped = {p.action_id: held.actions[p.action_id].model_copy(update={"class_id": CLASS_T2}), T2_ACTION: held.actions[T2_ACTION].model_copy(update={"class_id": CLASS_T1})}
    aged = {p.action_id: held.actions[p.action_id].model_copy(update={"max_status_age_seconds": 3600}), T2_ACTION: held.actions[T2_ACTION]}
    for name, actions in (("widened", widened), ("swapped", swapped), ("aged", aged)):
        flow.runtime_authority_profile = held.model_copy(update={"actions": actions})  # model_copy skips validators, as a hostile edit would
        before, calls = file_state(tmp_path, flow), src.calls
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "profile_modified", boundary="decision")
        assert file_state(tmp_path, flow) == before and src.calls == calls  # refused BEFORE any selection-source read
    flow.runtime_authority_profile = held
    assert flow.decide(p, now=NOW).result == "authorized"


def test_m06_replacing_the_profile_with_the_host_profile_or_dropping_it_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    d = flow.decide(p, now=NOW)
    for replacement in (cfg, cfg.snapshot(), None, {"actions": {}}):
        flow.runtime_authority_profile = replacement
        for call in (lambda: flow.decide(p, now=NOW), lambda: flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)):
            with pytest.raises(RegistryClassUnreadableRefused) as e:
                call()
            refused(e, "profile_modified")
    assert flow.destination.snapshot()["effects"] == {}


def test_m07_an_approval_for_the_wrong_commitment_or_with_a_forged_spec_does_not_authorize(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    for a in res.approvals.values():
        a.runtime_authority_commitment = "sha256:" + "0" * 64
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow.runtime_authority_profile)
    res.contexts[PROFILE]["runtime_authority"]["policy_generation"] = 1  # fields of another mechanism are unsupported without a binding
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_field_unsupported" in d.reasons


def test_m08_no_other_action_class_property_or_profile_member_is_widened_or_changed(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_, t2=R_), freshness=FreshnessProfile())
    eff = flow.runtime_authority_profile
    assert dump_without(eff, "on_unreadable") == dump_without(cfg, "on_unreadable")  # everything but the one field is byte-identical
    assert {a: eff.actions[a].model_dump(exclude={"on_unreadable"}) for a in eff.actions} == {a: cfg.actions[a].model_dump(exclude={"on_unreadable"}) for a in cfg.actions}
    assert eff.freshness == cfg.freshness and eff.catalogue_version == cfg.catalogue_version and eff.producer_keys == cfg.producer_keys
    assert all(eff.actions[a].irreversible == cfg.actions[a].irreversible and eff.actions[a].class_id == cfg.actions[a].class_id for a in eff.actions)


# =============================================================================================================== lifecycle
def test_l01_revoked_after_construction_blocks_the_next_decision_without_state_change(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    before = file_state(tmp_path, flow)
    src.mat = revoked(mat)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "decision")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


def test_l02_revoked_between_decision_and_effect_blocks_the_effect(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    before = file_state(tmp_path, flow)
    src.mat = revoked(mat, umap(t1=R_))
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "effect")
    assert file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


def test_l03_withdrawn_expired_and_stale_trust_after_construction(tmp_path):
    for i, (new, code) in enumerate(((_wd_u(), "selection_withdrawn"), (mat(trust=trust_for(OP_U, valid_until="2026-10-04T00:00:00Z")), "trust_snapshot_expired"),
                                     (mat(trust=trust_for(OP_U, min_epochs=(("sel-test-1", 2),))), "selection_epoch_stale"))):
        p, res, cfg, src, flow = ready(tmp_path / str(i))
        src.mat = new
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "registry_not_applied", code, "decision")


def test_l04_superseded_or_changed_selection_is_refused_and_never_widens(tmp_path):
    for i, new_vals in enumerate((umap(t1=B_), umap(t2=R_))):  # effective {B,R} differs; and the scoped class is not governed at all
        p, res, cfg, src, flow = ready(tmp_path / str(i), umap(t1=R_))
        src.mat = mat(new_vals, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(p, now=NOW)
        assert e.value.refusal.code in ("selection_changed", "scoped_class_not_governed") and e.value.boundary == "decision"
    for i, same in enumerate((umap(t1=R_, t2=R_), umap(t1=R_, t2=B_))):  # same EFFECTIVE profile (a looser value for an already-refuse class narrows nothing): identity equal
        p, res, cfg, src, flow = ready(tmp_path / ("s" + str(i)), umap(t1=R_))
        src.mat = mat(same, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
        assert flow.decide(p, now=NOW).result == "authorized"


def test_l05_an_equal_replacement_selection_is_accepted_and_existing_approvals_stay_valid(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    src.mat = mat(umap(t1=R_), stmt_over={"selection_id": "sel-test-2", "epoch": 2})  # same effective policy identity
    assert flow.decide(p, now=NOW).result == "authorized"


def test_l06_source_failure_or_garbage_after_construction_blocks(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    src.fail = True
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", boundary="decision")
    src.fail, src.mat = False, "garbage"
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "material_invalid")


def test_l07_proposals_outside_the_host_fixed_scope_are_refused_before_registry(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    calls = src.calls
    other_action = tenant_proposal().model_copy(update={"action_id": T2_ACTION})
    for q in (tenant_proposal("tenant-other"), tba.proposal(), other_action):
        before = file_state(tmp_path, flow)
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(q, now=NOW)
        refused(e, "proposal_out_of_scope", boundary="decision")
        assert file_state(tmp_path, flow) == before
    assert src.calls == calls


def test_l08_manifest_authority_change_after_construction_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    flow.manifest["actions"][0]["authority_context"]["authority_domain"] = "changed-domain"
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "manifest_authority_changed")


def test_l09_cross_family_selection_supplied_later_is_refused_and_identity_is_unchanged(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    ident = flow.registry_f5_unreadable_policy_identity
    src.mat = amat({CLASS_T1: 10}, stmt_over={"operation": OP_U}, trust=trust_for(OP_U))  # the class-AGE selection offered as the on_unreadable policy
    with pytest.raises(RegistryClassUnreadableRefused):
        flow.decide(p, now=NOW)
    src.mat = mat(rec=urecord(family="f4-control-plane-age-bounds", payload={"status_max_age_seconds": 10, "approval_max_age_seconds": 10}),
                  stmt_over={"family": "f4-control-plane-age-bounds"})
    with pytest.raises(RegistryClassUnreadableRefused):
        flow.decide(p, now=NOW)
    assert flow.registry_f5_unreadable_policy_identity == ident and flow.clock_tolerance_seconds == 5 and flow.status_max_age_seconds == 60


def test_l10_restart_recovery_same_selection_resumes_a_persisted_decision_and_a_changed_one_cannot(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    restarted = GovernedClassUnreadableWorkflow(scope=SCOPE, selection_source=src, verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                                                **kwargs(tmp_path, res))  # a new process: same host config, same record store, same selection
    assert restarted.records.decision(d.decision_id) == d
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    # a different selection after the restart: the persisted decision is refused and nothing more is dispatched
    p2, res2, cfg2, src2, flow2 = ready(tmp_path / "second", umap(t1=R_))
    d2 = flow2.decide(p2, now=NOW)
    changed = GovernedClassUnreadableWorkflow(scope=SCOPE, selection_source=Source(mat(umap(t1=B_))), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg2,
                                              construction_time=REG_NOW, **kwargs(tmp_path / "second", res2))
    bind_approval(res2, changed.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        changed.execute(p2, d2, adapter_id=p2.adapter_id, now=NOW)
    assert changed.destination.snapshot()["effects"] == {}


# =============================================================================================================== effect commit boundary
class SpyDestination(LocalRefundDestination):
    """Counts the calls that reach the real destination."""
    applies = 0

    def apply(self, *a, **k):
        type(self).applies += 1
        return super().apply(*a, **k)


def _authorized(tmp_path, m=None, **kw):
    p, res, cfg, src, flow = ready(tmp_path, m if m is not None else umap(t1=R_), **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, flow, d, src


def test_c01_revoked_after_execute_entry_verification_but_before_the_effect_boundary(tmp_path):
    """Deterministic TOCTOU case: call 1 construction, 2 decision, 3 execute entry (still valid); call 4 is the commit gate and the source now serves a revoked selection.
    The destination must not be touched, the attempt is a definitive rejection, and no effect exists."""
    p, flow, d, src = _authorized(tmp_path)
    src.after = (4, revoked(mat, umap(t1=R_)))
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert src.calls == 4
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.fu_last_commit_refusal.registry_code == "selection_revoked" and flow.fu_last_commit_refusal.code == "registry_not_applied"
    persisted = [a for a in flow.records.load().attempts if a.effect_id == d.effect_id]
    assert persisted[-1].status == "failed" and persisted[-1].error == gov.REJECTION_CODE and not any(a.status == "acknowledged" for a in persisted)


@pytest.mark.parametrize("late,code", [("withdrawn", "selection_withdrawn"), ("expired_trust", "trust_snapshot_expired"), ("stale_epoch", "selection_epoch_stale"),
                                       ("changed_value", None), ("wrong_scope", "selection_scope_mismatch")])
def test_c02_other_late_invalidations_are_refused_at_the_commit_gate(tmp_path, late, code):
    p, flow, d, src = _authorized(tmp_path)
    new = {"withdrawn": _wd_u(), "expired_trust": mat(umap(t1=R_), trust=trust_for(OP_U, valid_until="2026-10-04T00:00:00Z")),
           "stale_epoch": mat(umap(t1=R_), trust=trust_for(OP_U, min_epochs=(("sel-test-1", 2),))),
           "changed_value": mat(umap(t1=B_), stmt_over={"selection_id": "sel-test-2", "epoch": 2}),
           "wrong_scope": mat(umap(t1=R_), stmt_over={"scope": dict(STMT_SCOPE, tenant="tenant-other")})}[late]
    src.after = (4, new)
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert (flow.fu_last_commit_refusal.registry_code == code) if code else (flow.fu_last_commit_refusal.code == "selection_changed")


def test_c03_source_failure_at_the_commit_gate_blocks_the_effect(tmp_path):
    p, flow, d, src = _authorized(tmp_path)
    original = src.__call__

    def flaky():
        if src.calls == 3:
            src.fail = True
        return original()
    flow._fu_source = flaky
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.fu_last_commit_refusal.code == "selection_source_failed"
    assert flow.destination.snapshot()["effects"] == {}


def test_c04_a_commit_gate_refusal_blocks_an_automatic_retry_of_the_same_effect(tmp_path):
    p, flow, d, src = _authorized(tmp_path)
    src.after = (4, revoked(mat, umap(t1=R_)))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed"
    src.after = None
    src.mat = mat(umap(t1=R_))  # the selection is valid again, but the failed attempt stands
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


def test_c05_the_gate_is_the_last_step_before_apply_and_the_destination_is_transparent(tmp_path):
    p, flow, d, src = _authorized(tmp_path)
    dest = flow.destination
    assert dest.snapshot() == dest._inner.snapshot() and type(dest._inner) is LocalRefundDestination
    order = []
    inner_apply = dest._inner.apply
    dest._inner.apply = lambda *a, **k: (order.append("apply"), inner_apply(*a, **k))[1]
    original_gate = dest._gate
    object.__setattr__(dest, "_gate", lambda: (order.append("gate"), original_gate())[1])
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and order == ["gate", "apply"]


def test_c06_destination_must_be_a_plain_host_destination(tmp_path):
    p, res, cfg = prepared(tmp_path)
    flow = gbuild(tmp_path / "a", Source(mat()), res, cfg)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        GovernedClassUnreadableWorkflow(scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                                        **kwargs(tmp_path / "b", res, destination=flow.destination))  # an already gated destination cannot be wrapped again
    refused(e, "destination_invalid")


def test_c07_every_boundary_including_the_commit_gate_is_judged_at_the_execute_entry_time(tmp_path, monkeypatch):
    p, flow, d, src = _authorized(tmp_path)
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW + timedelta(seconds=1))  # the wall clock differs slightly from the execute-entry time
    seen = []
    real = gov.derive_governed

    def spy(**kw):
        seen.append(kw["now"])
        return real(**kw)
    monkeypatch.setattr(gov, "derive_governed", spy)
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert seen == [NOW, NOW]  # effect entry and commit gate


def test_c08_a_profile_edited_between_execute_entry_and_the_commit_gate_is_refused_without_dispatch(tmp_path):
    p, flow, d, src = _authorized(tmp_path)
    held = flow.runtime_authority_profile
    original = src.__call__

    def tamper():
        if src.calls == 3:  # the call made by the commit gate: widen the held class value first
            flow.runtime_authority_profile = held.model_copy(update={"actions": {p.action_id: held.actions[p.action_id].model_copy(update={"on_unreadable": B_}),
                                                                                  T2_ACTION: held.actions[T2_ACTION]}})
        return original()
    flow._fu_source = tamper
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.fu_last_commit_refusal.code == "profile_modified"
    assert flow.destination.snapshot()["effects"] == {}


def test_c09_the_real_destination_is_never_invoked_after_a_gate_refusal(tmp_path):
    SpyDestination.applies = 0
    p, res, cfg = prepared(tmp_path)
    src = Source(mat(umap(t1=R_)))
    flow = gbuild(tmp_path, src, res, cfg, destination=SpyDestination(tmp_path / "spy.json"))
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    src.after = (4, revoked(mat, umap(t1=R_)))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and SpyDestination.applies == 0
    p2, res2, cfg2 = prepared(tmp_path / "ok")  # control: without the late revocation the same wiring does reach the destination exactly once
    flow2 = gbuild(tmp_path / "ok", Source(mat(umap(t1=R_))), res2, cfg2, destination=SpyDestination(tmp_path / "ok" / "spy.json"))
    bind_approval(res2, flow2.runtime_authority_profile)
    d2 = flow2.decide(p2, now=NOW)
    flow2.execute(p2, d2, adapter_id=p2.adapter_id, now=NOW)
    assert SpyDestination.applies == 1


# =============================================================================================================== composition with the class status age (one workflow, one bound identity)
AGE_M = {CLASS_T1: 20}


def _joint(tmp_path, u_m=None, a_m=None, **kw):
    p, res, cfg, usrc, flow = ready(tmp_path, u_m if u_m is not None else umap(t1=R_), age_m=a_m if a_m is not None else AGE_M, **kw)
    return p, res, cfg, usrc, flow.test_age_source, flow


def test_j01_both_selections_narrow_one_effective_profile_and_one_bound_identity(tmp_path):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    eff = flow.runtime_authority_profile
    assert uvals(eff) == {CLASS_T1: R_, CLASS_T2: R_} and ages(eff) == {CLASS_T1: 20, CLASS_T2: 120}
    ident = flow.registry_f5_unreadable_policy_identity
    assert ident["class_age"]["effective"] == {CLASS_T1: 20, CLASS_T2: 120} and ident["class_age"]["host"] == {CLASS_T1: 60, CLASS_T2: 120}
    assert ident["class_age"]["effective_policy_digest"] == v2i.effective_policy_digest(ab.FAMILY_F5, {ab.F5_FIELD: ident["class_age"]["effective"]})
    assert ident["effective_profile_digest"] == agegov.profile_digest(eff) != ident["class_age"]["effective_profile_digest"]  # the final digest covers both values
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert d.binding.runtime_authority["catalogue_digest"] == ident["effective_profile_digest"]
    assert d.binding.runtime_authority["approval_commitment"] == approval_commitment(eff, res.contexts[PROFILE])


def test_j02_the_joint_profile_equals_the_class_age_workflow_profile_with_the_unreadable_value_composed_over_it(tmp_path):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    age_only = GovernedClassAgeWorkflow(scope=SCOPE_A, selection_source=Source(amat(AGE_M)), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                                        construction_time=REG_NOW, **kwargs(tmp_path / "age", res))
    expected = gov.compose_unreadable(age_only.runtime_authority_profile, {CLASS_T1: R_, CLASS_T2: R_})
    assert flow.runtime_authority_profile.model_dump(mode="json") == expected.model_dump(mode="json")
    assert dump_without(flow.runtime_authority_profile, "on_unreadable") == dump_without(age_only.runtime_authority_profile, "on_unreadable")  # age untouched by this value


def test_j03_the_unreadable_only_workflow_leaves_the_age_field_alone_and_the_joint_one_leaves_the_unreadable_field_to_this_family(tmp_path):
    p, res, cfg, usrc, flow = ready(tmp_path, umap(t1=R_))
    assert ages(flow.runtime_authority_profile) == ages(cfg)
    p2, res2, cfg2, usrc2, asrc2, flow2 = _joint(tmp_path / "j", umap(t1=B_), AGE_M)  # the on_unreadable record narrows nothing: only the age differs from the host
    assert uvals(flow2.runtime_authority_profile) == uvals(cfg2) and ages(flow2.runtime_authority_profile)[CLASS_T1] == 20


@pytest.mark.parametrize("which", ["unreadable", "age"])
def test_j04_either_selection_changing_refuses_at_every_boundary(tmp_path, which):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    if which == "unreadable":
        usrc.mat = mat(umap(t1=B_), stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    else:
        asrc.mat = amat({CLASS_T1: 15}, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    before = file_state(tmp_path, flow)
    for call, boundary in ((lambda: flow.decide(p, now=NOW), "decision"), (lambda: flow.execute(p, d, adapter_id=p.adapter_id, now=NOW), "effect")):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            call()
        refused(e, "selection_changed", boundary=boundary)
    assert file_state(tmp_path, flow) == before


@pytest.mark.parametrize("which", ["unreadable", "age"])
def test_j05_either_selection_revoked_after_execute_entry_blocks_the_effect_at_the_commit_gate(tmp_path, which):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    if which == "unreadable":
        usrc.after = (4, revoked(mat, umap(t1=R_)))
    else:
        asrc.after = (4, revoked(amat, AGE_M, op=OP_A))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    code = flow.fu_last_commit_refusal.code
    assert (code == "class_age:registry_not_applied") if which == "age" else (code == "registry_not_applied")
    assert flow.fu_last_commit_refusal.registry_code == "selection_revoked"
    assert usrc.calls == 4 and asrc.calls == 4  # both sources are consulted at each of the four boundaries


def test_j06_either_source_failing_or_withdrawn_refuses_there_is_no_fallback_to_either_family_alone(tmp_path):
    for i, which in enumerate(("unreadable", "age")):
        p, res, cfg, usrc, asrc, flow = _joint(tmp_path / str(i))
        (usrc if which == "unreadable" else asrc).fail = True
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "selection_source_failed", boundary="decision")
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path / "w")
    asrc.mat = _wd_a()
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "class_age:registry_not_applied", "selection_withdrawn", "decision")
    p, res, cfg = prepared(tmp_path / "c")  # at construction: a refused age selection refuses the whole workflow (never an unreadable-only workflow)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "c", Source(mat()), res, cfg, age=Source(revoked(amat, AGE_M, op=OP_A)))
    refused(e, "class_age:registry_not_applied", "selection_revoked", "construction")


def test_j07_cross_wired_sources_are_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:  # the age selection offered as the on_unreadable source
        gbuild(tmp_path / "a", Source(amat(AGE_M, stmt_over={"operation": OP_U}, trust=trust_for(OP_U))), res, cfg, age=Source(amat(AGE_M)))
    refused(e, "registry_not_applied")
    with pytest.raises(RegistryClassUnreadableRefused) as e:  # the on_unreadable selection offered as the age source
        gbuild(tmp_path / "b", Source(mat()), res, cfg, age=Source(mat(stmt_over={"operation": OP_A}, trust=trust_for(OP_A))))
    refused(e, "class_age:registry_not_applied")


def test_j08_the_outage_extension_composition_of_the_age_family_still_applies_in_the_joint_workflow(tmp_path):
    fr = FreshnessProfile(max_age_extension_seconds=300) if "max_age_extension_seconds" in FreshnessProfile.model_fields else None
    if fr is None:
        pytest.skip("freshness profile has no extension member")
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path, umap(t1=R_), {CLASS_T1: 90}, freshness=fr)
    age_only = GovernedClassAgeWorkflow(scope=SCOPE_A, selection_source=Source(amat({CLASS_T1: 90})), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                                        construction_time=REG_NOW, **kwargs(tmp_path / "age", res))
    assert flow.runtime_authority_profile.freshness == age_only.runtime_authority_profile.freshness


def test_j09_the_class_age_clock_and_scope_are_independent_but_bound_to_the_same_action(tmp_path):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    for q in (tenant_proposal("tenant-other"), tba.proposal()):
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(q, now=NOW)
        refused(e, "proposal_out_of_scope", boundary="decision")
    assert usrc.calls == 1 and asrc.calls == 1  # refused before any Registry call


def test_j10_restart_with_the_pair_resumes_and_a_dropped_age_component_cannot_execute_the_persisted_decision(tmp_path):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    restarted = gbuild(tmp_path, usrc, res, cfg, age=asrc)
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    p2, res2, cfg2, usrc2, asrc2, flow2 = _joint(tmp_path / "second")
    d2 = flow2.decide(p2, now=NOW)
    alone = gbuild(tmp_path / "second", usrc2, res2, cfg2)  # the same on_unreadable selection WITHOUT the age component: a different effective profile
    bind_approval(res2, alone.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        alone.execute(p2, d2, adapter_id=p2.adapter_id, now=NOW)
    assert alone.destination.snapshot()["effects"] == {}


# =============================================================================================================== no widening, scope, protected code, dependency
def _stub_registry(monkeypatch, mutate=None, exc=None):
    base = importlib.import_module("registry_successor.decision")
    v5d = importlib.import_module("registry_successor.v5_decision")
    real = v5d.verify_and_decide_v5

    def fake(*a, **k):
        if exc:
            raise exc
        out = real(*a, **k)
        return mutate(out, base) if mutate else out
    monkeypatch.setattr(v5d, "verify_and_decide_v5", fake)


def test_n01_defence_in_depth_refuses_a_registry_result_wider_than_the_host(tmp_path, monkeypatch):
    base = importlib.import_module("registry_successor.decision")
    _stub_registry(monkeypatch, lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: B_, CLASS_T2: R_}}, False, (), None, "", False))
    p, res, cfg = prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)
    refused(e, "effective_policy_widens_host")


def test_n02_a_registry_result_that_disagrees_with_the_record_minimum_is_refused(tmp_path, monkeypatch):
    _stub_registry(monkeypatch, lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: B_, CLASS_T2: R_}}, False, (), None, "", False))
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)  # the record says refuse; the (stubbed) result keeps tolerance
    refused(e, "effective_policy_invalid")


@pytest.mark.parametrize("part,idx", [("effective", 0), ("digest", 1)])
def test_n03_each_component_of_the_bound_identity_is_compared_on_its_own(tmp_path, monkeypatch, part, idx):
    p, res, cfg, src, flow = ready(tmp_path, umap(t1=R_))
    real = gov.derive_governed

    def altered(**kw):
        got, refusal = real(**kw)
        if refusal is not None:
            return got, refusal
        profile, effective, digest, age_part = got
        if part == "effective":
            effective = dict(effective, **{CLASS_T2: R_ if effective[CLASS_T2] == B_ else B_})
        else:
            digest = "sha256:" + "0" * 64
        return (profile, effective, digest, age_part), None
    monkeypatch.setattr(gov, "derive_governed", altered)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed")


def test_n04_the_final_profile_digest_and_the_age_part_are_compared_on_their_own(tmp_path, monkeypatch):
    p, res, cfg, usrc, asrc, flow = _joint(tmp_path)
    real = gov.derive_governed
    for mode in ("profile", "age"):
        def altered(mode=mode, **kw):
            got, refusal = real(**kw)
            profile, effective, digest, age_part = got
            if mode == "profile":
                profile = gov.compose_unreadable(profile, {CLASS_T1: R_, CLASS_T2: R_}).model_copy(update={"catalogue_version": "synthetic-catalogue/2"})
            else:
                age_part = (age_part[0], age_part[1], "sha256:" + "1" * 64)
            return (profile, effective, digest, age_part), None
        monkeypatch.setattr(gov, "derive_governed", altered)
        with pytest.raises(RegistryClassUnreadableRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "selection_changed")
    monkeypatch.setattr(gov, "derive_governed", real)
    assert flow.decide(p, now=NOW).result == "authorized"


@pytest.mark.parametrize("mutate,code", [
    (lambda out, b: b.PolicyDecision("applied_deny_all", out.effective, True, ("x",), None, "", False), "registry_decision_invalid"),
    (lambda out, b: b.PolicyDecision(out.kind, out.effective, False, (), None, "", False, operationally_authorized=True), "registry_decision_invalid"),
    (lambda out, b: b.PolicyDecision(out.kind, out.effective, True, ("x",), None, "", False), "registry_decision_invalid"),  # kind stays "applied" but deny_all is set
    (lambda out, b: b.PolicyDecision("weird", out.effective, False, (), None, "", False), "registry_decision_invalid"),
    (lambda out, b: b.PolicyDecision(out.kind, None, False, (), None, "", False), "effective_policy_invalid"),
    (lambda out, b: b.PolicyDecision(out.kind, {"x": {}}, False, (), None, "", False), "effective_policy_invalid"),
    (lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: R_}}, False, (), None, "", False), "effective_policy_invalid"),  # missing a host class
    (lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: "maybe", CLASS_T2: R_}}, False, (), None, "", False), "effective_policy_invalid"),
    (lambda out, b: "not a decision", "registry_decision_invalid"),
])
def test_n05_an_unexpected_registry_decision_shape_is_refused(tmp_path, monkeypatch, mutate, code):
    _stub_registry(monkeypatch, mutate)
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg)
    refused(e, code)


def test_n05b_a_registry_result_that_changes_a_class_the_record_does_not_name_is_refused(tmp_path, monkeypatch):
    """The real composer returns the caller value for an unnamed class; a (stubbed) result that NARROWS an unnamed class is not what the record said and is refused (defence in depth)."""
    _stub_registry(monkeypatch, lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: R_, CLASS_T2: B_}}, False, (), None, "", False))
    p, res, cfg = prepared(tmp_path, t2=R_, t2_irrev=False)  # the host T2 value is refuse; the stub raises it to bounded_tolerance (a widening, caught by the widening guard)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t1=R_))), res, cfg)
    refused(e, "effective_policy_widens_host")
    _stub_registry(monkeypatch, lambda out, b: b.PolicyDecision(out.kind, {v5f.F5U_FIELD: {CLASS_T1: R_, CLASS_T2: R_}}, False, (), None, "", False))
    p, res, cfg = prepared(tmp_path / "n", t2=B_, t2_irrev=False)  # host T2 is bounded_tolerance; the stub narrows it to refuse although the record names only T1
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path / "n", Source(mat(umap(t1=R_))), res, cfg)
    refused(e, "effective_policy_invalid")


def test_n05c_host_class_vocabulary_is_checked_exactly_on_the_host_side():
    """`host_class_unreadable` is public: a class value outside the closed vocabulary (or a non-str) fails closed. (The pydantic Literal already prevents it for a real profile.)"""
    from types import SimpleNamespace as NS

    def prof(*vals):
        return NS(actions={f"a{i}": NS(class_id=f"c{i}", on_unreadable=v) for i, v in enumerate(vals)})
    assert gov.host_class_unreadable(prof(R_, B_)) == ({"c0": R_, "c1": B_}, None)
    for bad in ("tolerate", "Refuse", "", None, 1, True, ("refuse",)):
        assert gov.host_class_unreadable(prof(R_, bad)) == (None, "host_class_unreadable_invalid"), bad


def test_n05d_a_record_class_unknown_to_the_host_is_refused_even_if_a_registry_result_looks_valid(tmp_path, monkeypatch):
    """Defence in depth: the real Registry refuses an unknown record class (g06). If a (stubbed) Registry result were nevertheless `applied` and well-shaped, the adapter's own
    parse of the verified record still refuses a class the host does not define."""
    _stub_registry(monkeypatch, lambda out, b: b.PolicyDecision("applied", {v5f.F5U_FIELD: {CLASS_T1: R_, CLASS_T2: R_}}, False, (), None, "", False))
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat(umap(t1=R_, **{"synthetic-unknown": R_}))), res, cfg)
    refused(e, "effective_policy_invalid")


def test_n06_a_registry_call_failure_is_a_refusal(tmp_path, monkeypatch):
    _stub_registry(monkeypatch, exc=RuntimeError("boom"))
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg)
    refused(e, "registry_call_failed")


def test_n07_a_missing_registry_dependency_or_an_older_registry_without_r08_v5_is_a_refusal(tmp_path, monkeypatch):
    p, res, cfg = prepared(tmp_path)
    real_import = importlib.import_module

    def broken(name, *a, **k):
        if name in ("registry_successor.v5_decision", "registry_successor.v5_policy_identity"):
            raise ImportError(name)
        return real_import(name, *a, **k)
    monkeypatch.setattr(gov.importlib, "import_module", broken)
    with pytest.raises(RegistryClassUnreadableRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg)
    refused(e, "registry_unavailable", boundary="construction")
    monkeypatch.setattr(gov.importlib, "import_module", real_import)
    flow = gbuild(tmp_path / "ok", Source(mat()), res, cfg)
    monkeypatch.setattr(gov.importlib, "import_module", broken)
    with pytest.raises(RegistryClassUnreadableRefused) as e:  # and a dependency that disappears later blocks the decision
        flow.decide(p, now=NOW)
    refused(e, "registry_unavailable", boundary="decision")


def test_n08_the_record_class_map_parser_is_strict():
    good = json.dumps({"payload": {v5f.F5U_FIELD: {"a": R_, "b": B_}}})
    assert gov.registry_unreadable_map(good) == {"a": R_, "b": B_}
    for bad in ('{"payload": {"class_on_unreadable": {"a": "refuse", "a": "refuse"}}}', '{"payload": {"class_on_unreadable": {"a": 1}}}',
                '{"payload": {"class_on_unreadable": {"a": "x"}}}', '{"payload": {"class_on_unreadable": {}}}', '{"payload": {"class_on_unreadable": {"a": "refuse"}, "z": 1}}',
                '{"payload": {"class_on_unreadable": {"a": NaN}}}', '{"payload": []}', '[]', "not json", '{"payload": {"class_on_unreadable": {"a": 1.5}}}'):
        assert gov.registry_unreadable_map(bad) is None, bad


def test_n09_the_vocabulary_is_the_control_plane_literal_in_both_repositories():
    assert tuple(ActionClass.model_fields["on_unreadable"].annotation.__args__) == gov.VALUES == v5f.VALUES == (R_, B_)
    assert gov.FAMILY == v5f.FAMILY_F5U and gov.FIELD == v5f.F5U_FIELD and gov.CONTRACT_V5 == "r08-v5"


def test_n10_the_module_governs_one_field_only_and_excludes_every_other_parameter():
    text = Path(gov.__file__).read_text()
    import ast
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant) and isinstance(node.body[0].value.value, str):
            node.body[0].value.value = ""
    code = ast.unparse(tree)
    assert code.count("action['on_unreadable'] =") == 1
    for forbidden in ("['max_status_age_seconds'] =", "['irreversible'] =", "['class_id'] =", "requires_revocation_assurance'] =", "reversibility'] =", "clock_tolerance_seconds=",
                      "identity_max_age_seconds=", "mandate_max_age_seconds=", "anchor_deadline_to_inputs", "terminal_revocation", "observation_policy ="):
        assert forbidden not in code, forbidden


# protected files: the evaluators, the F4 consumer and the M12 class-age consumer are unmodified by this increment
# Consolidation (shared governed lifecycle): the F4 and F5 class-age consumers are deliberately re-based on registry_governed_lifecycle.py; their pins are the consolidated hashes
# (were 50cccf5f / 9f765492 at Control Plane 5f11e0f). The protected evaluators below are byte-identical to that baseline.
PROTECTED = {
    "bounded.py": "c219f8825a8ddf9da1fe6771ae575af0a9069ac8a04eadd40f093a9adb13655b",
    "runtime_authority.py": "a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66",
    "freshness.py": "3f146ee11a3424d816c6f35ba07259833612a985901b4a96c0275395f05d51c0",
    "policy_binding.py": "defdfac5fd60cf5be707a76204a12513f2f289b0620ec56d063b56dac4081a35",
    "rule_revision.py": "a3833f49e96db52e0665b9816daee2654f74f7784faad5101252b4c8722415a5",
    "reversibility.py": "5edbadebb3aa777fba7f652c10c8da3c5e9ee1766b71866ed55dc25b319477d1",
    "registry_f4_age_governance.py": "9d6d88213befe60023e6ac7f3528762be466f3c577ce172d56125c4cb30325b3",
    "registry_f5_class_age_governance.py": "fd4fb025ecf37d6dd20031881a36b2eb953a726dc6ecf5137ee8c1567b486497",
}


@pytest.mark.parametrize("name", sorted(PROTECTED))
def test_s01_protected_evaluators_and_the_earlier_consumers_are_unmodified_by_this_increment(name):
    assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == PROTECTED[name], name


def test_s02_existing_f4_and_f5_class_age_behaviour_is_unchanged(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(f4gov.RegistrySelectionRefused) as e:  # F4 still refuses a runtime-authority profile and keeps its vocabulary
        GovernedAgeWorkflow(scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                            **kwargs(tmp_path / "f4", res))
    assert e.value.refusal.code == "runtime_authority_profile_unsupported" and not isinstance(e.value, RegistryClassUnreadableRefused)
    assert f4gov.REJECTION_CODE == "registry_f4_selection_invalid" and agegov.REJECTION_CODE == "registry_f5_selection_invalid"
    assert gov.REJECTION_CODE == "registry_f5_unreadable_selection_invalid" and str(e.value).startswith("registry_f4_selection_refused:")
    # the M12 class-age workflow, alone, still narrows the age and does not touch on_unreadable
    flow = GovernedClassAgeWorkflow(scope=SCOPE_A, selection_source=Source(amat({CLASS_T1: 10})), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                                    construction_time=REG_NOW, **kwargs(tmp_path / "age", res))
    assert ages(flow.runtime_authority_profile)[CLASS_T1] == 10 and uvals(flow.runtime_authority_profile) == uvals(cfg)
    with pytest.raises(RegistryClassAgeRefused):  # and it still refuses the on_unreadable record as its own policy
        GovernedClassAgeWorkflow(scope=SCOPE_A, selection_source=Source(mat(stmt_over={"operation": OP_A}, trust=trust_for(OP_A))), verifier=ev.Ed25519Verifier(),
                                 runtime_authority_profile=cfg, construction_time=REG_NOW, **kwargs(tmp_path / "age2", res))
