"""F5 per-class status-age oracles: Registry-governed `ActionClass.max_status_age_seconds` reaching the real `BoundedAuthorizationWorkflow` checks through an EFFECTIVE
profile that `approval_commitment` already hashes, with the selection re-validated at the decision, effect and commit boundaries. BUILDER_TESTED developer evidence.
NOT independently qualified. NOT an authorization mechanism. Excludes clock tolerance (r08-v5), identity/mandate ages, the F4 scalars and every other class field.

Needs a Registry checkout at the exact `PIN` in `OCS_REGISTRY_PIN_DIR` and PyNaCl. When `OCS_REQUIRE_REGISTRY_PIN=1` (set by CI) a missing pin, wrong pin or missing
PyNaCl is a FAILURE, never a skip. Without it the module is reported NOT RUN (skipped with a reason), never passed with a double. Real synthetic Ed25519 only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PIN = "6f600ab1150f00ef3d96834159b1807e866a78b6"  # Registry main at the Plan v1.1 adoption merge; contains the r08-v2 F5 composer (no later Registry code is used)
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
if _head != PIN:
    pytest.fail(f"Registry checkout is {_head!r}, expected the pin {PIN}", pytrace=False)
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
from registry_successor import verify as v  # noqa: E402

from agent_control_plane import registry_f4_age_governance as f4gov  # noqa: E402
from agent_control_plane import registry_f5_class_age_governance as gov  # noqa: E402
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, BoundedRecordStore, LocalRefundDestination, ObservationPolicy, commitment  # noqa: E402
from agent_control_plane.freshness import AgeExtensionRefused, FreshnessProfile  # noqa: E402
from agent_control_plane.registry_f4_age_governance import GovernedAgeWorkflow, GovernedScope, SelectionMaterial  # noqa: E402
from agent_control_plane.registry_f5_class_age_governance import GovernedClassAgeWorkflow, RegistryClassAgeRefused  # noqa: E402
from agent_control_plane.rule_revision import RuleRevisionProfile  # noqa: E402
from agent_control_plane.runtime_authority import ActionClass, PurposeStatus, RuntimeAuthorityProfile, approval_commitment  # noqa: E402
from tests.test_bounded_authorization import INSTITUTION as MANIFEST_INSTITUTION  # noqa: E402,F401
from tests.test_bounded_authorization import NOW, PROFILE, manifest, tenant_proposal, tenant_resolver_for, TENANT  # noqa: E402
import tests.test_bounded_authorization as tba  # noqa: E402
from tests.test_runtime_authority import MEMBERS, PUBLIC, bind_approval, sign_evidence  # noqa: E402

REG_NOW = NOW  # one clock: the Registry verdict is judged at the Control Plane evaluation time
PK, SK = nb.crypto_sign_seed_keypair(bytes(range(32)))
OTHER_PK, OTHER_SK = nb.crypto_sign_seed_keypair(bytes(range(1, 33)))
MAXV = 2147483647
CLASS_T1, CLASS_T2 = "synthetic-irreversible", "synthetic-high"
T2_ACTION = "urn:cognous:action:refund-issue-high-v1"
SRC = Path(gov.__file__).resolve().parent


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    monkeypatch.setattr(gov, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- Registry-side builders
def _sign(stmt, sk=None, domain=None):
    return base64.b64encode(nb.crypto_sign((domain or s.V2_DOMAIN) + c.canonical_bytes(stmt), sk or SK)[:64]).decode("ascii")


def classes(t1=None, t2=None, **more):
    out = {}
    if t1 is not None:
        out[CLASS_T1] = t1
    if t2 is not None:
        out[CLASS_T2] = t2
    out.update(more)
    return {k: out[k] for k in sorted(out)}


def record(m=None, *, family=None, contract="r08-v2", payload=None, **over):
    body = dict(r.make_record(), contract_version=contract, family=family or ab.FAMILY_F5, record_id="f5-age-record",
                payload=payload if payload is not None else {ab.F5_FIELD: m if m is not None else classes(t1=10)})
    body.update(over)
    return r.seal_record(body)


def trust_for(version=1, valid_until="2026-10-07T00:00:00Z", grant=None, **kw):
    grant = grant or v.AuthorityGrant("consumer-test", TENANT.lower(), INSTITUTION, DOMAIN, OPERATION)
    return v.TrustSnapshot("snap-test-1", version, valid_until, (v.IssuerEntry(s.KEY_ID, "issuer-test-1", "ed25519", PK, (grant,)),), **kw)


def material(rec=None, *, stmt=None, sk=None, trust=None, contract="r08-v2", domain=None, record_text=None, **stmt_over):
    rec = rec if rec is not None else record()
    stmt_over.setdefault("family", rec.get("family", ab.FAMILY_F5))
    stmt = stmt if stmt is not None else r.make_statement_v2(rec, **stmt_over)
    sel = r.dumps(s.envelope(stmt, domain=domain or s.V2_DOMAIN, contract=contract, signature=_sign(stmt, sk, domain), pub=PK))
    return SelectionMaterial(record_text if record_text is not None else r.dumps(rec), sel, trust or trust_for())


class Source:
    """A host selection source whose material can change between boundaries."""
    def __init__(self, mat):
        self.mat, self.calls, self.fail = mat, 0, False
        self.after = None  # (call number, material): from that call on the source serves the other material

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("source down")
        if self.after is not None and self.calls >= self.after[0]:
            return self.after[1]
        return self.mat


ACTION_ID = [a for a in manifest()["actions"]][0]["action_id"]
_AUTH = [a for a in manifest()["actions"]][0]["authority_context"]
INSTITUTION, DOMAIN = _AUTH["institution_id"], _AUTH["authority_domain"]
OPERATION = "refund-issue-routine"
SCOPE = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OPERATION)
EFFECTIVE = {"valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-06T00:00:00Z"}
STMT_SCOPE = {"tenant": TENANT.lower(), "institution": INSTITUTION, "authority_domain": DOMAIN}


def mat(m=None, **kw):
    rec = kw.pop("rec", None) or record(m)
    over = dict(consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    over.update(kw.pop("stmt_over", {}))
    if "trust" not in kw and any(k in over for k in ("consumer_id", "scope", "operation")):
        sc = over["scope"]
        kw["trust"] = trust_for(grant=v.AuthorityGrant(over["consumer_id"], sc["tenant"], sc["institution"], sc["authority_domain"], over["operation"]))
    return material(rec, **over, **kw)


REVOKED = lambda *a, **k: mat(*a, trust=trust_for(revoked_selections=frozenset({("sel-test-1", 1)})), **k)  # noqa: E731


# --------------------------------------------------------------------------------------------------------------- Control Plane fixtures
def host_profile(p, *, t1=60, t2=120, freshness=None, shared=None, extra_actions=None, **over):
    """A HOST profile with two classes: the scoped T1 action (class T1) and the T2 action (class T2). `shared` gives T2's action the T1 class id."""
    actions = {p.action_id: ActionClass(class_id=CLASS_T1, irreversible=True, max_status_age_seconds=t1),
               T2_ACTION: ActionClass(class_id=CLASS_T1 if shared else CLASS_T2, irreversible=True, max_status_age_seconds=shared if shared else t2)}
    actions.update(extra_actions or {})
    return RuntimeAuthorityProfile(catalogue_version="synthetic-catalogue/1", actions=actions, producer_keys={"synthetic-validator": PUBLIC},
                                   allow_synthetic_resolver=True, **({"freshness": freshness} if freshness else {}), **over)


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
    return dict(allow_test_time=True, manifest=manifest(), resolver=res, destination=LocalRefundDestination(tmp_path / "destination.json"),
                records=BoundedRecordStore(tmp_path / "run.json", "run-1"), observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def gbuild(tmp_path, source, res, cfg, **kw):
    return GovernedClassAgeWorkflow(scope=kw.pop("scope", SCOPE), selection_source=source, verifier=kw.pop("verifier", ev.Ed25519Verifier()),
                                    runtime_authority_profile=kw.pop("profile", cfg), construction_time=kw.pop("construction_time", REG_NOW),
                                    **kwargs(tmp_path, res, **kw))


def ready(tmp_path, m=None, *, source=None, purpose=False, bind=True, **profile_kw):
    """Governed workflow with approvals issued against its EFFECTIVE profile. Returns (proposal, resolver, host profile, source, flow)."""
    p, res, cfg = prepared(tmp_path, purpose=purpose, **profile_kw)
    src = source or Source(mat(m if m is not None else classes(t1=10)))
    flow = gbuild(tmp_path, src, res, cfg)
    if bind:
        bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, src, flow


def plain(tmp_path, res, profile, **kw):
    """The existing workflow built directly with `profile` (the oracle for equivalence)."""
    return BoundedAuthorizationWorkflow(runtime_authority_profile=profile, **kwargs(tmp_path, res, **kw))


def age_status(res, seconds):
    ctx = res.contexts[PROFILE]
    res.statuses[ctx["grant"]["grant_id"]].observed_at = (NOW - timedelta(seconds=seconds)).isoformat()


def file_state(tmp_path, flow):
    return (sorted((x.name, x.read_bytes()) for x in tmp_path.glob("*.json")), flow.destination.snapshot())


def refused(exc, code=None, registry_code=None, boundary=None):
    e = exc.value
    assert isinstance(e, PermissionError) and isinstance(e, RegistryClassAgeRefused) and e.refusal.non_authorizing is True
    if code:
        assert e.refusal.code == code, e.refusal
    if registry_code:
        assert e.refusal.registry_code == registry_code, e.refusal
    if boundary:
        assert e.boundary == boundary
    return e


def class_ages(profile):
    return {a.class_id: a.max_status_age_seconds for a in profile.actions.values()}


# =============================================================================================================== construction
def test_g01_valid_selection_narrows_the_effective_profile_and_carries_identity(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=10, t2=90))
    prof = flow.runtime_authority_profile
    assert class_ages(prof) == {CLASS_T1: 10, CLASS_T2: 90} and class_ages(cfg) == {CLASS_T1: 60, CLASS_T2: 120}  # host profile object is untouched
    assert prof.actions[p.action_id].max_status_age_seconds == 10 and flow._class_age_bound(p.action_id, NOW)[0] == 10
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds, flow.identity_max_age_seconds, flow.mandate_max_age_seconds,
            flow.clock_tolerance_seconds) == (60, 60, 60, 60, 5)  # excluded values untouched
    ident = flow.registry_f5_policy_identity
    assert ident["contract_version"] == "r08-v2" and ident["family"] == ab.FAMILY_F5 and ident["effective"] == {CLASS_T1: 10, CLASS_T2: 90}
    assert ident["effective_policy_digest"] == v2i.effective_policy_digest(ab.FAMILY_F5, {ab.F5_FIELD: ident["effective"]})
    assert ident["effective_profile_digest"] == gov.profile_digest(prof) and ident["host"] == {CLASS_T1: 60, CLASS_T2: 120}
    assert ident["scope"] == {"consumer_id": "consumer-test", "tenant_id": TENANT.lower(), "action_id": ACTION_ID, "operation_id": OPERATION}


@pytest.mark.parametrize("reg,host,expect", [(10, 60, 10), (60, 60, 60), (90, 60, 60), (1, 60, 1), (MAXV, MAXV, MAXV), (5, 0, 0), (1, 1, 1), (MAXV, 60, 60)])
def test_g02_below_equal_above_and_boundaries_never_widen(tmp_path, reg, host, expect):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=reg), t1=host)
    assert flow.runtime_authority_profile.actions[p.action_id].max_status_age_seconds == expect and expect <= host
    assert class_ages(flow.runtime_authority_profile)[CLASS_T2] == 120  # a class the record does not name keeps its host value


@pytest.mark.parametrize("reg", [60, 61, 9999, MAXV])
def test_g03_registry_equal_or_above_leaves_the_profile_and_every_existing_approval_unchanged(tmp_path, reg):
    p, res, cfg = prepared(tmp_path)
    bind_approval(res, cfg)  # approval issued against the HOST profile, before any Registry involvement
    flow = gbuild(tmp_path, Source(mat(classes(t1=reg))), res, cfg)
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
    flow = gbuild(tmp_path, Source(mat(classes(t1=30))), res, cfg)
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts
    bind_approval(res, flow.runtime_authority_profile)  # a NEW approval over the effective profile
    d2 = flow.decide(p, now=NOW)
    assert d2.result == "authorized", d2.reasons
    attempt, observed = flow.execute(p, d2, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_g05_multiple_classes_with_distinct_bounds_each_use_their_own_bound(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20, t2=90), t1=60, t2=120)
    assert class_ages(flow.runtime_authority_profile) == {CLASS_T1: 20, CLASS_T2: 90}
    age_status(res, 25)  # inside the T2 bound (90) and the host T1 bound (60), outside the narrowed T1 bound (20)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons  # class substitution: T2's bound never loosens the scoped T1 class
    age_status(res, 15)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_g06_a_registry_class_unknown_to_the_host_is_refused_not_created(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat(classes(t1=10, **{"synthetic-unknown": 5}))), res, cfg)
    refused(e, "registry_not_applied", "composition_record_invalid", "construction")


def test_g07_a_record_silent_about_the_scoped_class_governs_nothing_and_is_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat(classes(t2=10))), res, cfg)
    refused(e, "scoped_class_not_governed", boundary="construction")


def test_g08_two_actions_sharing_a_class_need_one_host_age_and_both_get_the_narrowed_value(tmp_path):
    p, res, cfg = prepared(tmp_path, shared=60)
    flow = gbuild(tmp_path, Source(mat(classes(t1=10))), res, cfg)
    assert {a.max_status_age_seconds for a in flow.runtime_authority_profile.actions.values()} == {10}
    p, res, cfg = prepared(tmp_path / "b", shared=45)  # same class id, a different host age: ambiguous, fail closed
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "b", Source(mat(classes(t1=10))), res, cfg)
    refused(e, "class_age_ambiguous", boundary="construction")


def test_g09_construction_inputs_are_validated(tmp_path):
    p, res, cfg = prepared(tmp_path)
    for name, kw, code in (("none", dict(profile=None), "runtime_authority_profile_required"),
                           ("garbage", dict(profile={"nonsense": 1}), "host_profile_invalid"),
                           ("scope", dict(scope=GovernedScope("", TENANT, ACTION_ID, OPERATION)), "scope_invalid"),
                           ("unknown_action", dict(scope=GovernedScope("consumer-test", TENANT, "no.such.action", OPERATION)), "action_class_unknown")):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path / name, Source(mat()), res, cfg, **kw)
        refused(e, code, boundary="construction")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "src", "not callable", res, cfg)
    refused(e, "selection_source_invalid")
    extra = "urn:cognous:action:in-profile-not-in-manifest"
    with pytest.raises(RegistryClassAgeRefused) as e:  # in the host profile but not declared by the manifest: no authority context to scope the Registry call
        gbuild(tmp_path / "undeclared", Source(mat()), res, cfg, scope=GovernedScope("consumer-test", TENANT, extra, OPERATION),
               profile=host_profile(p, extra_actions={extra: ActionClass(class_id=CLASS_T1, irreversible=True, max_status_age_seconds=60)}))
    refused(e, "manifest_action_undeclared", boundary="construction")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "naive", Source(mat()), res, cfg, construction_time=datetime(2026, 10, 5, 19, 0))
    refused(e, "time_invalid")


def test_g10_a_profile_that_already_carries_an_approval_generation_binding_is_refused(tmp_path):
    from agent_control_plane.policy_binding import PolicyBinding
    p, res, cfg = prepared(tmp_path)
    binding = PolicyBinding(binding_digest="sha256:" + "1" * 64, selection_epoch=1, activation_ref="sha256:" + "2" * 64, policy_generation=1, disposition="selected")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg, profile=host_profile(p, policy_binding=binding))
    refused(e, "policy_binding_unsupported", boundary="construction")


@pytest.mark.parametrize("pl", [{}, {"other": {CLASS_T1: 1}}, {ab.F5_FIELD: {CLASS_T1: 1}, "x": 1}, {ab.F5_FIELD: {}}, {ab.F5_FIELD: [1]}, {ab.F5_FIELD: {CLASS_T1: True}},
                                {ab.F5_FIELD: {CLASS_T1: 1.5}}, {ab.F5_FIELD: {CLASS_T1: "10"}}, {ab.F5_FIELD: {CLASS_T1: None}}, {ab.F5_FIELD: {CLASS_T1: 0}},
                                {ab.F5_FIELD: {CLASS_T1: -1}}, {ab.F5_FIELD: {CLASS_T1: MAXV + 1}},
                                {ab.F5_FIELD: {"bad class": 5}}, {ab.F5_FIELD: {"": 5}}, {ab.F5_FIELD: {CLASS_T1 + "*": 5}},
                                {"status_max_age_seconds": 10, "approval_max_age_seconds": 10}, {"clock_tolerance_seconds": 5}])
def test_g11_missing_or_malformed_class_records_are_refused(tmp_path, pl):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat(rec=record(payload=pl))), res, cfg)
    refused(e, "registry_not_applied", boundary="construction")


def test_g12_invalid_record_text_and_material_types(tmp_path):
    p, res, cfg = prepared(tmp_path)
    for bad in (SelectionMaterial("{}", mat().selection_text, trust_for()), SelectionMaterial("not json", mat().selection_text, trust_for())):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path, Source(bad), res, cfg)
        refused(e, "registry_not_applied")
    for bad in (None, "x", object(), SelectionMaterial(None, "x", None), SelectionMaterial("x", b"x", None)):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path, Source(bad), res, cfg)
        refused(e, "material_invalid")


def test_g13_wrong_contract_family_signature_and_domain(tmp_path):
    p, res, cfg = prepared(tmp_path)
    base = record()
    for label in ("r08-v1", "r08-v3", "r08-v4", "r08-v5", "r08-v6", ""):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path / ("c" + label), Source(mat(rec=base, contract=label)), res, cfg)
        refused(e, "registry_not_applied")
    f4rec = record(family=ab.FAMILY_F4, payload={"status_max_age_seconds": 10, "approval_max_age_seconds": 10})  # the F4 scalar family is never consumed here
    for fam, rec in ((ab.FAMILY_F4, f4rec), ("f1ab-local-execution-limits", record(family="f1ab-local-execution-limits")), ("f4t-control-plane-clock-tolerance", None)):
        rec = rec or record(family=fam, contract="r08-v5", payload={"clock_tolerance_seconds": 1})
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path / ("f" + fam[:6]), Source(mat(rec=rec, stmt_over={"family": fam})), res, cfg)
        refused(e, "registry_not_applied")
    for kw in ({"sk": OTHER_SK}, {"domain": b"ocs-reg/r08-v4/selection\n"}):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path / ("s" + str(len(kw["sk"] if "sk" in kw else kw["domain"]))), Source(mat(**kw)), res, cfg)
        refused(e, "registry_not_applied", "signature_invalid")


@pytest.mark.parametrize("over,code", [({"consumer_id": "other-consumer"}, "selection_consumer_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, tenant="tenant-other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, institution="urn:cognous:institution:other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, authority_domain="other-domain")}, "selection_scope_mismatch"),
                                       ({"operation": "other.action"}, "selection_operation_mismatch")])
def test_g14_wrong_authority_scope_tenant_or_operation(tmp_path, over, code):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat(stmt_over=over)), res, cfg)
    refused(e, "registry_not_applied", code)


def test_g15_expired_stale_trust_revoked_and_withdrawn_at_construction(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "a", Source(mat()), res, cfg, construction_time=REG_NOW + timedelta(hours=6))
    refused(e, "registry_not_applied", "selection_expired")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "b", Source(mat(trust=trust_for(valid_until="2026-10-04T00:00:00Z"))), res, cfg)
    refused(e, "registry_not_applied", "trust_snapshot_expired")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "c", Source(REVOKED()), res, cfg)
    refused(e, "registry_not_applied", "selection_revoked")
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "d", Source(_withdrawn()), res, cfg)
    refused(e, "registry_not_applied")


def _withdrawn():
    rec = record()
    stmt = r.make_statement_v2(rec, family=ab.FAMILY_F5, consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    wd = s.withdraw_statement(stmt)
    return SelectionMaterial(r.dumps(rec), r.dumps(s.envelope(wd, signature=_sign(wd), pub=PK)), trust_for())


def test_g16_optional_participation_and_non_admitted_verifiers_are_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "a", Source(mat(stmt_over={"participation": "optional"})), res, cfg)
    refused(e, "registry_not_applied")
    for i, vf in enumerate((object(), None, ev.Ed25519Verifier, type("Sub", (ev.Ed25519Verifier,), {})())):
        with pytest.raises(RegistryClassAgeRefused) as e:
            gbuild(tmp_path / f"v{i}", Source(mat()), res, cfg, verifier=vf)
        refused(e, "verifier_not_admitted")


def test_g17_hostile_host_values_fail_closed_before_any_effective_profile_exists(tmp_path):
    p, res, cfg = prepared(tmp_path)
    big = host_profile(p, t1=MAXV + 1)  # a host class age above the Registry domain: Registry refuses the whole caller policy, never clamps it
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "big", Source(mat()), res, cfg, profile=big)
    assert e.value.refusal.code in ("host_class_age_invalid", "registry_not_applied")
    odd = host_profile(p, extra_actions={"urn:cognous:action:odd": ActionClass(class_id="not a token", irreversible=True, max_status_age_seconds=5)})
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path / "odd", Source(mat()), res, cfg, profile=odd)
    refused(e, "registry_not_applied", "composition_caller_invalid")


def test_g18_a_refused_construction_writes_nothing(tmp_path):
    p, res, cfg = prepared(tmp_path / "prep")
    (tmp_path / "w").mkdir()
    dest, store = LocalRefundDestination(tmp_path / "w" / "destination.json"), BoundedRecordStore(tmp_path / "w" / "run.json", "run-1")
    listing = sorted(x.name for x in (tmp_path / "w").glob("*"))
    with pytest.raises(RegistryClassAgeRefused):
        GovernedClassAgeWorkflow(scope=SCOPE, selection_source=Source(mat(sk=OTHER_SK)), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, allow_test_time=True,
                                 manifest=manifest(), resolver=res, destination=dest, records=store)
    assert sorted(x.name for x in (tmp_path / "w").glob("*")) == listing and dest.snapshot()["effects"] == {}


# =============================================================================================================== real enforcement
@pytest.mark.parametrize("bound,age,ok", [(30, 30, True), (30, 31, False), (1, 1, True), (1, 2, False), (60, 60, True), (60, 61, False)])
def test_e01_boundary_equality_uses_the_existing_inclusive_comparison(tmp_path, bound, age, ok):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=bound))
    age_status(res, age)
    assert (flow.decide(p, now=NOW).result == "authorized") is ok


def test_e02_governed_decisions_equal_the_existing_workflow_built_with_the_effective_profile(tmp_path):
    for i, (reg, age) in enumerate(((10, 0), (10, 9), (10, 10), (10, 11), (30, 29), (30, 45), (60, 59), (60, 61), (500, 61))):
        p, res, cfg, src, flow = ready(tmp_path / f"g{i}", classes(t1=reg))
        age_status(res, age)
        oracle = plain(tmp_path / f"p{i}", res, flow.runtime_authority_profile)
        got, want = flow.decide(p, now=NOW), oracle.decide(p, now=NOW)
        assert (got.result, got.reasons) == (want.result, want.reasons), (reg, age)


def test_e03_a_narrower_class_bound_changes_the_real_decision_without_effects(tmp_path):
    p, res, cfg = prepared(tmp_path)
    age_status(res, 30)
    bind_approval(res, cfg)
    assert plain(tmp_path / "p", res, cfg).decide(p, now=NOW).result == "authorized"  # ungoverned host bound (60): fine
    flow = gbuild(tmp_path / "g", Source(mat(classes(t1=10))), res, cfg)
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons and flow.destination.snapshot()["effects"] == {}
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)  # a hold cannot be executed
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts


def test_e04_the_purpose_status_age_uses_the_same_narrowed_class_bound(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=10), purpose=True)
    res.purpose.observed_at = (NOW - timedelta(seconds=30)).isoformat()
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and d.reasons == ["purpose_unreadable"]
    res.purpose.observed_at = (NOW - timedelta(seconds=5)).isoformat()
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons


def test_e05_registry_above_the_host_leaves_the_host_bound(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=9999))
    age_status(res, 61)
    assert flow.runtime_authority_profile.actions[p.action_id].max_status_age_seconds == 60
    assert "grant_status_stale_or_future" in flow.decide(p, now=NOW).reasons


def test_e06_a_host_bound_of_zero_is_a_floor_the_registry_cannot_raise_and_future_statuses_stay_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=5), t1=0)
    assert flow.runtime_authority_profile.actions[p.action_id].max_status_age_seconds == 0
    age_status(res, 1)
    assert "grant_status_stale_or_future" in flow.decide(p, now=NOW).reasons
    age_status(res, -3600)  # an observation an hour in the future
    assert "grant_status_stale_or_future" in flow.decide(p, now=NOW).reasons


def test_e07_full_flow_executes_when_selection_stays_valid(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=60))
    assert src.calls == 1
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and src.calls == 4  # construction, decision, effect entry, commit gate


# =============================================================================================================== commitment binding
def test_m01_the_commitment_and_the_persisted_binding_carry_the_effective_class_age(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    ext = d.binding.runtime_authority
    assert ext["approval_commitment"] == approval_commitment(flow.runtime_authority_profile, res.contexts[PROFILE])
    assert ext["catalogue_digest"] == gov.profile_digest(flow.runtime_authority_profile) == flow.registry_f5_policy_identity["effective_profile_digest"]
    assert ext["approval_commitment"] != approval_commitment(cfg, res.contexts[PROFILE]) and ext["catalogue_digest"] != gov.profile_digest(cfg)


def test_m02_a_different_effective_policy_cannot_ride_an_approval_issued_for_another(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))  # approval A over effective profile (20)
    src.mat = mat(classes(t1=10), stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)  # the running workflow refuses the changed selection ...
    refused(e, "selection_changed", boundary="decision")
    flow2 = gbuild(tmp_path / "rebuilt", src, res, cfg)  # ... and a rebuilt workflow under the new selection does not honour approval A
    d = flow2.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow2.runtime_authority_profile)
    assert flow2.decide(p, now=NOW).result == "authorized"


def test_m03_selection_replaced_after_decision_blocks_the_effect_and_a_rebuilt_workflow_cannot_execute_the_old_decision(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    src.mat = mat(classes(t1=15), stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    before = file_state(tmp_path, flow)
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_changed", boundary="effect")
    assert file_state(tmp_path, flow) == before
    flow2 = GovernedClassAgeWorkflow(scope=SCOPE, selection_source=src, verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                                     **kwargs(tmp_path, res))  # same record store, new effective profile (15)
    bind_approval(res, flow2.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow2.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow2.destination.snapshot()["effects"] == {}


def test_m04_class_substitution_by_editing_the_held_profile_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20, t2=90))
    held = flow.runtime_authority_profile
    swapped = {p.action_id: held.actions[p.action_id].model_copy(update={"class_id": CLASS_T2}), T2_ACTION: held.actions[T2_ACTION].model_copy(update={"class_id": CLASS_T1})}
    widened = {p.action_id: held.actions[p.action_id].model_copy(update={"max_status_age_seconds": 60}), T2_ACTION: held.actions[T2_ACTION]}
    for name, actions in (("swapped", swapped), ("widened", widened)):
        flow.runtime_authority_profile = held.model_copy(update={"actions": actions})  # model_copy skips validators, as a hostile edit would
        before = file_state(tmp_path, flow)
        with pytest.raises(RegistryClassAgeRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "profile_modified", boundary="decision")
        assert file_state(tmp_path, flow) == before
    flow.runtime_authority_profile = held
    assert flow.decide(p, now=NOW).result == "authorized"


def test_m05_replacing_the_profile_with_the_host_profile_or_dropping_it_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))
    d = flow.decide(p, now=NOW)
    for replacement in (cfg, cfg.snapshot(), None, {"actions": {}}):
        flow.runtime_authority_profile = replacement
        for call in (lambda: flow.decide(p, now=NOW), lambda: flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)):
            with pytest.raises(RegistryClassAgeRefused) as e:
                call()
            refused(e, "profile_modified")
    assert flow.destination.snapshot()["effects"] == {}


def test_m06_an_approval_for_the_wrong_commitment_or_with_a_forged_spec_does_not_authorize(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))
    for a in res.approvals.values():
        a.runtime_authority_commitment = "sha256:" + "0" * 64
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow.runtime_authority_profile)
    res.contexts[PROFILE]["runtime_authority"]["policy_generation"] = 1  # fields of another mechanism are unsupported without a binding
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_field_unsupported" in d.reasons


# =============================================================================================================== outage extensions (DR-CP-AGE-1 decision 5)
def _ext(flow, class_id, to, *, now=NOW):
    return flow.record_age_extension(class_id=class_id, to_max_age_seconds=to, not_before=now.isoformat(), expires_at=(now + timedelta(hours=1)).isoformat(),
                                     outage_ref="outage-1", requested_by="urn:cognous:principal:requester", signer="urn:cognous:principal:signer", now=now)


def _fresh(tmp_path, m, *, limit=300, **kw):
    p, res, cfg = prepared(tmp_path, freshness=FreshnessProfile(max_age_extension_seconds=limit), **kw)
    flow = gbuild(tmp_path, Source(mat(m)), res, cfg, rule_revision_profile=RuleRevisionProfile(signers=["urn:cognous:principal:signer"]))
    return p, res, cfg, flow


def test_x01_the_uncomposed_gap_exists_and_the_composed_limit_closes_it(tmp_path):
    p, res, cfg = prepared(tmp_path / "u", freshness=FreshnessProfile(max_age_extension_seconds=300))
    narrowed_only = gov.compose_profile(cfg, {CLASS_T1: 30, CLASS_T2: 120}, {CLASS_T1: 30})
    assert narrowed_only.freshness.max_age_extension_seconds == 0  # composed
    doc = cfg.model_dump(mode="json")
    for a in doc["actions"].values():
        if a["class_id"] == CLASS_T1:
            a["max_status_age_seconds"] = 30
    control = plain(tmp_path / "ctl", res, RuntimeAuthorityProfile.model_validate(doc), rule_revision_profile=RuleRevisionProfile(signers=["urn:cognous:principal:signer"]))
    assert _ext(control, CLASS_T1, 330).to_max_age_seconds == 330  # base narrowed to 30 alone: the extension still reaches 330 (above the Registry value)
    p, res, cfg, flow = _fresh(tmp_path / "g", classes(t1=30))
    assert flow.runtime_authority_profile.freshness.max_age_extension_seconds == 0
    with pytest.raises(AgeExtensionRefused) as e:
        _ext(flow, CLASS_T1, 31)
    assert "age_extension_exceeds_limit" in e.value.reasons


def test_x02_base_plus_extension_never_exceeds_a_registry_value_above_the_host_base(tmp_path):
    p, res, cfg, flow = _fresh(tmp_path, classes(t1=90))  # host 60, Registry 90: room 30
    assert flow.runtime_authority_profile.freshness.max_age_extension_seconds == 30
    assert _ext(flow, CLASS_T1, 90).to_max_age_seconds == 90
    with pytest.raises(AgeExtensionRefused):
        _ext(flow, CLASS_T1, 91)


def test_x03_the_limit_is_the_minimum_over_every_governed_class_and_never_above_the_host_limit(tmp_path):
    p, res, cfg, flow = _fresh(tmp_path, classes(t1=70, t2=150), limit=300)  # rooms: 10 and 30
    assert flow.runtime_authority_profile.freshness.max_age_extension_seconds == 10
    p, res, cfg, flow = _fresh(tmp_path / "b", classes(t1=70, t2=150), limit=5)
    assert flow.runtime_authority_profile.freshness.max_age_extension_seconds == 5  # never raised above the host's own limit


def test_x07_a_registry_value_equal_to_the_host_value_removes_the_outage_extension_and_is_visible_in_the_commitment(tmp_path):
    p, res, cfg, flow = _fresh(tmp_path, classes(t1=60), limit=300)  # documented consequence of DR-CP-AGE-1 decision 5: base + extension may not exceed the Registry value
    assert flow.runtime_authority_profile.freshness.max_age_extension_seconds == 0
    assert class_ages(flow.runtime_authority_profile) == class_ages(cfg)
    ctx = res.contexts[PROFILE]
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)  # so an approval issued for the host profile must be reissued


def test_x04_no_extension_configured_means_the_freshness_member_is_untouched(tmp_path):
    p, res, cfg = prepared(tmp_path, freshness=FreshnessProfile(max_age_extension_seconds=0))
    flow = gbuild(tmp_path, Source(mat(classes(t1=90))), res, cfg)
    assert flow.runtime_authority_profile.freshness == cfg.freshness
    assert flow.runtime_authority_profile.model_dump(mode="json") == cfg.model_dump(mode="json")


def test_x05_an_extension_recorded_against_the_old_base_no_longer_counts_after_narrowing(tmp_path):
    p, res, cfg = prepared(tmp_path, freshness=FreshnessProfile(max_age_extension_seconds=300))
    host_flow = plain(tmp_path, res, cfg, rule_revision_profile=RuleRevisionProfile(signers=["urn:cognous:principal:signer"]))
    assert _ext(host_flow, CLASS_T1, 120).from_max_age_seconds == 60  # recorded for the host base 60
    flow = gbuild(tmp_path, Source(mat(classes(t1=30))), res, cfg, rule_revision_profile=RuleRevisionProfile(signers=["urn:cognous:principal:signer"]))
    bound, used, defects = flow._class_age_bound(p.action_id, NOW)
    assert bound == 30 and used is None and "age_extension_invalid" in defects


def test_x06_the_composed_limit_enters_the_commitment_and_a_changed_record_changes_it(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=90), freshness=FreshnessProfile(max_age_extension_seconds=300))
    first = flow.registry_f5_policy_identity["effective_profile_digest"]
    src.mat = mat(classes(t1=200), stmt_over={"selection_id": "sel-test-2", "epoch": 2})  # the same effective ages (host 60) but a different extension room
    assert flow.registry_f5_policy_identity["effective_profile_digest"] == first
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", boundary="decision")


# =============================================================================================================== lifecycle
def test_l01_revoked_after_construction_blocks_the_next_decision_without_state_change(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    before = file_state(tmp_path, flow)
    src.mat = REVOKED()
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "decision")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


def test_l02_revoked_between_decision_and_effect_blocks_the_effect(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=60))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    before = file_state(tmp_path, flow)
    src.mat = REVOKED(classes(t1=60))
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "effect")
    assert file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


def test_l03_withdrawn_expired_and_stale_trust_after_construction(tmp_path):
    for i, (new, code) in enumerate(((_withdrawn(), None), (mat(trust=trust_for(valid_until="2026-10-04T00:00:00Z")), "trust_snapshot_expired"))):
        p, res, cfg, src, flow = ready(tmp_path / str(i))
        src.mat = new
        with pytest.raises(RegistryClassAgeRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "registry_not_applied", code, "decision")


def test_l04_superseded_or_changed_selection_is_refused_and_never_widens(tmp_path):
    for i, new_vals in enumerate((classes(t1=5), classes(t1=60), classes(t1=10, t2=30), classes(t1=10, t2=119))):
        p, res, cfg, src, flow = ready(tmp_path / str(i), classes(t1=10, t2=118))
        src.mat = mat(new_vals, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
        with pytest.raises(RegistryClassAgeRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "selection_changed", boundary="decision")


def test_l05_an_equal_replacement_selection_is_accepted_and_existing_approvals_stay_valid(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=10))
    src.mat = mat(classes(t1=10), stmt_over={"selection_id": "sel-test-2", "epoch": 2})  # same effective policy identity
    age_status(res, 5)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_l06_source_failure_or_garbage_after_construction_blocks(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    src.fail = True
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", boundary="decision")
    src.fail, src.mat = False, "garbage"
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "material_invalid")


def test_l07_proposals_outside_the_host_fixed_scope_are_refused_before_registry(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    calls = src.calls
    other_action = tenant_proposal().model_copy(update={"action_id": T2_ACTION})
    for q in (tenant_proposal("tenant-other"), tba.proposal(), other_action):
        before = file_state(tmp_path, flow)
        with pytest.raises(RegistryClassAgeRefused) as e:
            flow.decide(q, now=NOW)
        refused(e, "proposal_out_of_scope", boundary="decision")
        assert file_state(tmp_path, flow) == before
    assert src.calls == calls


def test_l08_manifest_authority_change_after_construction_is_refused(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    flow.manifest["actions"][0]["authority_context"]["authority_domain"] = "changed-domain"
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "manifest_authority_changed")


def test_l09_cross_family_selection_supplied_later_is_refused_and_identity_is_unchanged(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=10))
    ident = flow.registry_f5_policy_identity
    src.mat = mat(rec=record(family=ab.FAMILY_F4, payload={"status_max_age_seconds": 10, "approval_max_age_seconds": 10}), stmt_over={"family": ab.FAMILY_F4})
    with pytest.raises(RegistryClassAgeRefused):
        flow.decide(p, now=NOW)
    src.mat = mat(rec=record(family="f4t-control-plane-clock-tolerance", contract="r08-v5", payload={"clock_tolerance_seconds": 1}), contract="r08-v5",
                  stmt_over={"family": "f4t-control-plane-clock-tolerance"})
    with pytest.raises(RegistryClassAgeRefused):
        flow.decide(p, now=NOW)
    assert flow.registry_f5_policy_identity == ident and flow.clock_tolerance_seconds == 5 and flow.status_max_age_seconds == 60


def test_l10_restart_recovery_same_selection_resumes_a_persisted_decision_and_a_changed_one_cannot(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=20))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    restarted = GovernedClassAgeWorkflow(scope=SCOPE, selection_source=src, verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                                         **kwargs(tmp_path, res))  # a new process: same host config, same record store, same selection
    assert restarted.records.decision(d.decision_id) == d
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    # a different selection after the restart: the persisted decision is refused and nothing more is dispatched
    p2, res2, cfg2, src2, flow2 = ready(tmp_path / "second", classes(t1=20))
    d2 = flow2.decide(p2, now=NOW)
    changed = GovernedClassAgeWorkflow(scope=SCOPE, selection_source=Source(mat(classes(t1=19))), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg2,
                                       construction_time=REG_NOW, **kwargs(tmp_path / "second", res2))
    bind_approval(res2, changed.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        changed.execute(p2, d2, adapter_id=p2.adapter_id, now=NOW)
    assert changed.destination.snapshot()["effects"] == {}


# =============================================================================================================== effect commit boundary
def _authorized(tmp_path, m=None):
    src = Source(mat(m if m is not None else classes(t1=60)))
    p, res, cfg, src, flow = ready(tmp_path, source=src)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, flow, d, src


def test_c01_revoked_after_execute_entry_verification_but_before_the_effect_boundary(tmp_path):
    """Deterministic TOCTOU case: call 1 construction, 2 decision, 3 execute entry (still valid); call 4 is the commit gate and the source now serves a
    revoked selection. The destination must not be touched, the attempt is a definitive rejection, and no effect exists."""
    p, flow, d, src = _authorized(tmp_path)
    src.after = (4, REVOKED(classes(t1=60)))
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert src.calls == 4
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.f5_last_commit_refusal.registry_code == "selection_revoked" and flow.f5_last_commit_refusal.code == "registry_not_applied"
    persisted = [a for a in flow.records.load().attempts if a.effect_id == d.effect_id]
    assert persisted[-1].status == "failed" and persisted[-1].error == gov.REJECTION_CODE and not any(a.status == "acknowledged" for a in persisted)


@pytest.mark.parametrize("late,code", [
    (lambda: mat(classes(t1=60), trust=trust_for(valid_until="2026-10-04T00:00:00Z")), "trust_snapshot_expired"),
    (lambda: mat(classes(t1=30), stmt_over={"selection_id": "sel-test-2", "epoch": 2}), None),
    (lambda: mat(classes(t1=60), sk=OTHER_SK), "signature_invalid"),
    (lambda: mat(classes(t1=60), stmt_over={"scope": dict(STMT_SCOPE, tenant="tenant-other")}), None)])
def test_c02_other_late_invalidations_are_refused_at_the_commit_gate(tmp_path, late, code):
    p, flow, d, src = _authorized(tmp_path)
    src.after = (4, late())
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    if code:
        assert flow.f5_last_commit_refusal.registry_code == code
    else:
        assert flow.f5_last_commit_refusal is not None


def test_c03_source_failure_at_the_commit_gate_blocks_the_effect(tmp_path):
    class Dies(Source):
        def __call__(self):
            self.calls += 1
            if self.calls >= 4:
                raise RuntimeError("down")
            return self.mat
    p, res, cfg, src, flow = ready(tmp_path, source=Dies(mat(classes(t1=60))))
    d = flow.decide(p, now=NOW)
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and flow.destination.snapshot()["effects"] == {} and flow.f5_last_commit_refusal.code == "selection_source_failed"


def test_c04_a_commit_gate_refusal_blocks_an_automatic_retry_of_the_same_effect(tmp_path):
    p, flow, d, src = _authorized(tmp_path)
    src.after = (4, REVOKED(classes(t1=60)))
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    src.after = None
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)  # the failed attempt is existing evidence that blocks automatic retry
    assert flow.destination.snapshot()["effects"] == {}


def test_c05_the_gate_is_the_last_step_before_apply_and_the_destination_is_transparent(tmp_path):
    order = []
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=60))
    inner = flow.destination._inner
    real_apply, real_gate = inner.apply, flow._f5_commit_gate
    inner.apply = lambda **kw: (order.append("apply"), real_apply(**kw))[1]
    object.__setattr__(flow.destination, "_gate", lambda: (order.append("gate"), real_gate())[1])
    d = flow.decide(p, now=NOW)
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert order == ["gate", "apply"]
    assert flow.destination.snapshot()["effects"] and flow.destination.snapshot() == inner.snapshot()


def test_c06_destination_must_be_a_plain_host_destination(tmp_path):
    p, res, cfg = prepared(tmp_path)
    kw = dict(scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, allow_test_time=True, construction_time=REG_NOW,
              manifest=manifest(), resolver=res, records=BoundedRecordStore(tmp_path / "r.json", "run-1"))
    with pytest.raises(RegistryClassAgeRefused) as e:
        GovernedClassAgeWorkflow(**kw)
    refused(e, "destination_invalid")
    first = gbuild(tmp_path / "a", Source(mat()), res, cfg)
    with pytest.raises(RegistryClassAgeRefused) as e:
        GovernedClassAgeWorkflow(destination=first.destination, **kw)
    refused(e, "destination_invalid")


def test_c07_every_boundary_including_the_commit_gate_is_judged_at_the_execute_entry_time(tmp_path, monkeypatch):
    seen = []
    real = gov.derive_effective

    def spy(**kw):
        seen.append(kw["now"])
        return real(**kw)
    monkeypatch.setattr(gov, "derive_effective", spy)
    p, flow, d, src = _authorized(tmp_path)
    seen.clear()
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW + timedelta(seconds=1))
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    assert seen == [NOW, NOW]


def test_c08_a_profile_edited_between_execute_entry_and_the_commit_gate_is_refused_without_dispatch(tmp_path):
    p, flow, d, src = _authorized(tmp_path, classes(t1=20))
    held, hostile = flow.runtime_authority_profile, None
    hostile = held.model_copy(update={"actions": {k: a.model_copy(update={"max_status_age_seconds": 3600}) for k, a in held.actions.items()}})
    real_gate = flow._f5_commit_gate
    object.__setattr__(flow.destination, "_gate", lambda: (setattr(flow, "runtime_authority_profile", hostile), real_gate())[1])
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.f5_last_commit_refusal.code == "profile_modified"


# =============================================================================================================== no widening, scope, protected code
def test_n01_defence_in_depth_refuses_a_registry_result_wider_than_the_host(tmp_path, monkeypatch):
    import registry_successor.decision as dec
    real = dec.verify_and_decide_v2

    def widened(*a, **k):
        d = real(*a, **k)
        return type(d)(d.kind, {ab.F5_FIELD: {CLASS_T1: 9999, CLASS_T2: 9999}}, d.deny_all, d.deny_all_fields, d.code, d.detail, d.caller_unchanged, d.operationally_authorized)
    monkeypatch.setattr(dec, "verify_and_decide_v2", widened)
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg)
    refused(e, "effective_policy_widens_host")


def test_n02_a_registry_result_that_disagrees_with_the_record_minimum_is_refused(tmp_path, monkeypatch):
    import registry_successor.decision as dec
    real = dec.verify_and_decide_v2

    def lower(*a, **k):
        d = real(*a, **k)
        return type(d)(d.kind, {ab.F5_FIELD: {CLASS_T1: 1, CLASS_T2: 120}}, d.deny_all, d.deny_all_fields, d.code, d.detail, d.caller_unchanged, d.operationally_authorized)
    monkeypatch.setattr(dec, "verify_and_decide_v2", lower)
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat(classes(t1=10))), res, cfg)
    refused(e, "effective_policy_invalid")


@pytest.mark.parametrize("part,idx", [("effective map", 1), ("registry policy digest", 2), ("effective profile digest", 3)])
def test_n05_each_component_of_the_bound_identity_is_compared_on_its_own(tmp_path, monkeypatch, part, idx):
    """The three comparisons are redundant by construction (the profile digest covers the class map, and the policy digest is derived from it); each is still
    checked on its own so removing any one is caught."""
    p, res, cfg, src, flow = ready(tmp_path, classes(t1=10))
    real = gov.derive_effective

    def tampered(**kw):
        got, refusal = real(**kw)
        if refusal is not None:
            return got, refusal
        got = list(got)
        got[idx] = dict(got[idx], **{CLASS_T2: 1}) if idx == 1 else got[idx] + "0"
        return tuple(got), None
    monkeypatch.setattr(gov, "derive_effective", tampered)
    with pytest.raises(RegistryClassAgeRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", boundary="decision")


@pytest.mark.parametrize("mutate,code", [(lambda d: ("weird_kind", d.deny_all, d.operationally_authorized), "registry_decision_invalid"),
                                         (lambda d: (d.kind, True, d.operationally_authorized), "registry_decision_invalid"),
                                         (lambda d: (d.kind, d.deny_all, True), "registry_decision_invalid")])
def test_n06_an_unexpected_registry_decision_shape_is_refused(tmp_path, monkeypatch, mutate, code):
    import registry_successor.decision as dec
    real = dec.verify_and_decide_v2

    def odd(*a, **k):
        d = real(*a, **k)
        kind, deny, authorized = mutate(d)
        return type(d)(kind, d.effective, deny, d.deny_all_fields, d.code, d.detail, d.caller_unchanged, authorized)
    monkeypatch.setattr(dec, "verify_and_decide_v2", odd)
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryClassAgeRefused) as e:
        gbuild(tmp_path, Source(mat()), res, cfg)
    refused(e, code, boundary="construction")


def test_n03_the_record_class_map_parser_is_strict(tmp_path):
    ok = r.dumps(record(classes(t1=10)))
    assert gov.registry_class_map(ok) == {CLASS_T1: 10}
    dup = '{"payload": {"class_status_max_age_seconds": {"a": 1, "a": 2}}}'
    for bad in (dup, '{"payload": {"class_status_max_age_seconds": {"a": 1.0}}}', '{"payload": {"class_status_max_age_seconds": {"a": NaN}}}', '{"payload": 1}', "x",
                '{"payload": {"class_status_max_age_seconds": {}}}', '{"payload": {"class_status_max_age_seconds": {"a": true}}}',
                '{"payload": {"class_status_max_age_seconds": {"a": 1}, "extra": 1}}'):
        assert gov.registry_class_map(bad) is None, bad


def test_n04_the_module_excludes_clock_tolerance_other_families_and_every_other_class_field():
    text = (SRC / "registry_f5_class_age_governance.py").read_text().replace('"""', "")
    for banned in ("v5_", "f4t", "verify_and_decide_v5", "identity_max_age_seconds=", "mandate_max_age_seconds=", "clock_tolerance_seconds=", "on_unreadable", "requires_revocation_assurance",
                   "reversibility=", "anchor_deadline_to_inputs=", "terminal_revocation", "observation_policy", "age_ceilings"):
        assert banned not in text.split("Registry is resolved lazily", 1)[1], banned


#: sha256 of the protected evaluator modules and of the unchanged F4 consumer at Control Plane main 673ef092cf083b235b2c99e3cd4a6ad8361f2973. Computed from bytes (no git history), so it
#: runs in shallow CI. A change to any of them in this increment fails the test.
PROTECTED = {
    "bounded.py": "c219f8825a8ddf9da1fe6771ae575af0a9069ac8a04eadd40f093a9adb13655b",
    "runtime_authority.py": "a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66",
    "freshness.py": "3f146ee11a3424d816c6f35ba07259833612a985901b4a96c0275395f05d51c0",
    "policy_binding.py": "defdfac5fd60cf5be707a76204a12513f2f289b0620ec56d063b56dac4081a35",
    "rule_revision.py": "a3833f49e96db52e0665b9816daee2654f74f7784faad5101252b4c8722415a5",
    "registry_f4_age_governance.py": "fdf3c17d14337b37590fe07c02212eaccce8c5dccf554b671f622e38485e0b3a",  # D-06 follow-up (OCS-REG-FINAL3 gap 1): +legacy_cutoff and the shared binding hook; was 9d6d8821 (consolidation, was 50cccf5f)
}


@pytest.mark.parametrize("name", sorted(PROTECTED))
def test_s01_protected_evaluators_and_the_f4_consumer_are_unmodified_by_this_increment(name):
    assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == PROTECTED[name], name


def test_s02_existing_f4_behaviour_is_unchanged_it_still_refuses_a_profile_and_keeps_its_vocabulary(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(f4gov.RegistrySelectionRefused) as e:
        GovernedAgeWorkflow(scope=SCOPE, selection_source=Source(mat()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                            construction_time=REG_NOW, **kwargs(tmp_path, res))
    assert e.value.refusal.code == "runtime_authority_profile_unsupported" and not isinstance(e.value, RegistryClassAgeRefused)
    assert f4gov.REJECTION_CODE == "registry_f4_selection_invalid" and gov.REJECTION_CODE == "registry_f5_selection_invalid"
    assert str(e.value).startswith("registry_f4_selection_refused:")
