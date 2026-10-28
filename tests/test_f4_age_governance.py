"""F4 ages-only oracles: Registry-governed `status_max_age_seconds` and `approval_max_age_seconds` reaching the real `BoundedAuthorizationWorkflow` checks,
with the selection re-validated at the decision and effect boundaries. BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization
mechanism. Excludes RG-C-006 (constructor clock tolerance, r08-v5), identity/mandate ages and the F5 class bound.

Needs a Registry checkout at the exact `PIN` in `OCS_REGISTRY_PIN_DIR` and PyNaCl. When `OCS_REQUIRE_REGISTRY_PIN=1` (set by CI) a missing pin, wrong pin or missing
PyNaCl is a FAILURE, never a skip. Without it the module is reported NOT RUN (skipped with a reason), never passed with a double. Real synthetic Ed25519 only.
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

PIN = "6f600ab1150f00ef3d96834159b1807e866a78b6"  # Registry main at the Plan v1.1 adoption merge; contains r08-v2 F4 (no r08-v5 code is used)
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
from registry_successor import v2_age_bounds as f4  # noqa: E402
from registry_successor import verify as v  # noqa: E402

from agent_control_plane import registry_f4_age_governance as gov  # noqa: E402
from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination, ObservationPolicy  # noqa: E402
from agent_control_plane.registry_f4_age_governance import GovernedAgeWorkflow, GovernedScope, RegistrySelectionRefused, SelectionMaterial  # noqa: E402
from tests.test_bounded_authorization import NOW, PROFILE, manifest, resolver_for, tenant_proposal, tenant_resolver_for, TENANT  # noqa: E402,F401
import tests.test_bounded_authorization as tba  # noqa: E402

REG_NOW = NOW  # one clock: the Registry verdict is judged at the Control Plane evaluation time
PK, SK = nb.crypto_sign_seed_keypair(bytes(range(32)))
OTHER_PK, OTHER_SK = nb.crypto_sign_seed_keypair(bytes(range(1, 33)))
MAXV = 2147483647


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    monkeypatch.setattr(gov, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- Registry-side builders
def _sign(stmt, sk=None, domain=None):
    return base64.b64encode(nb.crypto_sign((domain or s.V2_DOMAIN) + c.canonical_bytes(stmt), sk or SK)[:64]).decode("ascii")


def record(status=10, approval=10, *, family=None, contract="r08-v2", payload=None, **over):
    body = dict(r.make_record(), contract_version=contract, family=family or f4.FAMILY_F4, record_id="f4-age-record",
                payload=payload if payload is not None else {"status_max_age_seconds": status, "approval_max_age_seconds": approval})
    body.update(over)
    return r.seal_record(body)


def trust_for(version=1, valid_until="2026-10-07T00:00:00Z", grant=None, **kw):
    """A trust snapshot whose issuer is authorised for exactly the derived scope (consumer, tenant, manifest institution/domain, operation)."""
    grant = grant or v.AuthorityGrant("consumer-test", TENANT, INSTITUTION, DOMAIN, OPERATION)
    return v.TrustSnapshot("snap-test-1", version, valid_until, (v.IssuerEntry(s.KEY_ID, "issuer-test-1", "ed25519", PK, (grant,)),), **kw)


def material(rec=None, *, stmt=None, sk=None, trust=None, contract="r08-v2", domain=None, record_text=None, **stmt_over):
    rec = rec if rec is not None else record()
    stmt_over.setdefault("family", rec.get("family", f4.FAMILY_F4))
    stmt = stmt if stmt is not None else r.make_statement_v2(rec, **stmt_over)
    sel = r.dumps(s.envelope(stmt, domain=domain or s.V2_DOMAIN, contract=contract, signature=_sign(stmt, sk, domain), pub=PK))
    return SelectionMaterial(record_text if record_text is not None else r.dumps(rec), sel, trust or trust_for())


class Source:
    """A host selection source whose material can change between boundaries."""
    def __init__(self, mat):
        self.mat, self.calls, self.fail = mat, 0, False

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("source down")
        return self.mat


def _scope_for_manifest():
    """The Registry scope the Control Plane derives: tenant from the proposal, operation = action_id, institution/domain from the manifest."""
    action = [a for a in manifest()["actions"]][0]
    auth = action["authority_context"]
    return action["action_id"], auth["institution_id"], auth["authority_domain"]


ACTION_ID, INSTITUTION, DOMAIN = _scope_for_manifest()
OPERATION = "refund-issue-routine"
SCOPE = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OPERATION)
CTX = c.ExpectedContext("consumer-test", TENANT.lower(), INSTITUTION, DOMAIN, OPERATION)
EFFECTIVE = {"valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-06T00:00:00Z"}
STMT_SCOPE = {"tenant": TENANT.lower(), "institution": INSTITUTION, "authority_domain": DOMAIN}


def mat(status=10, approval=10, **kw):
    rec = kw.pop("rec", None) or record(status, approval)
    over = dict(consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    over.update(kw.pop("stmt_over", {}))
    if "trust" not in kw and any(k in over for k in ("consumer_id", "scope", "operation")):  # an issuer authorised for exactly the (possibly wrong) statement scope
        sc = over["scope"]
        kw["trust"] = trust_for(grant=v.AuthorityGrant(over["consumer_id"], sc["tenant"], sc["institution"], sc["authority_domain"], over["operation"]))
    return material(rec, **over, **kw)


def build(tmp_path, source, **kw):
    p = tenant_proposal()
    kw.setdefault("resolver", tenant_resolver_for(p))
    return GovernedAgeWorkflow(scope=kw.pop("scope", SCOPE), selection_source=source, verifier=kw.pop("verifier", ev.Ed25519Verifier()), allow_test_time=True,
                               construction_time=kw.pop("construction_time", REG_NOW), manifest=manifest(),
                               destination=LocalRefundDestination(tmp_path / "destination.json"), records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
                               observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def plain(tmp_path, resolver=None, **kw):
    p = tenant_proposal()
    return tba.BoundedAuthorizationWorkflow(allow_test_time=True, manifest=manifest(), resolver=resolver or tenant_resolver_for(p),
                                            destination=LocalRefundDestination(tmp_path / "pdest.json"), records=BoundedRecordStore(tmp_path / "prun.json", "run-p"),
                                            observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def aged(p, seconds, which):
    rr = tenant_resolver_for(p)
    ctx = rr.contexts[PROFILE]
    stamp = (NOW - timedelta(seconds=seconds)).isoformat()
    if which == "status":
        rr.statuses[ctx["grant"]["grant_id"]].observed_at = stamp
    elif which == "approval":
        rr.approvals[ctx["grant"]["approval_refs"][0]].observed_at = stamp
    elif which == "policy":
        for pol in rr.policies.values():
            pol.observed_at = stamp
    return rr


def file_state(tmp_path, flow):
    return (sorted((x.name, x.read_bytes()) for x in tmp_path.glob("*.json")), flow.destination.snapshot())


def refused(exc, code=None, registry_code=None, boundary=None):
    e = exc.value
    assert isinstance(e, PermissionError) and e.refusal.non_authorizing is True
    if code:
        assert e.refusal.code == code, e.refusal
    if registry_code:
        assert e.refusal.registry_code == registry_code, e.refusal
    if boundary:
        assert e.boundary == boundary
    return e


# =============================================================================================================== construction + scalars
def test_g01_scope_derivation_is_the_registry_context_and_a_valid_selection_applies(tmp_path):
    flow = build(tmp_path, Source(mat(10, 20)))
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (10, 20)
    assert (flow.identity_max_age_seconds, flow.mandate_max_age_seconds, flow.clock_tolerance_seconds) == (60, 60, 5)  # excluded values untouched
    ident = flow.registry_f4_policy_identity
    assert ident["contract_version"] == "r08-v2" and ident["family"] == f4.FAMILY_F4 and ident["effective"] == {"status_max_age_seconds": 10, "approval_max_age_seconds": 20}
    from registry_successor import v2_policy_identity as v2i
    assert ident["effective_policy_digest"] == v2i.effective_policy_digest(f4.FAMILY_F4, ident["effective"]) and ident["host"] == {
        "status_max_age_seconds": 60, "approval_max_age_seconds": 60}


@pytest.mark.parametrize("reg,host,expect", [(10, 60, 10), (60, 60, 60), (90, 60, 60), (1, 60, 1), (MAXV, MAXV, MAXV), (5, 0, 0), (1, 1, 1), (MAXV, 60, 60)])
def test_g02_below_equal_above_and_boundaries_never_widen(tmp_path, reg, host, expect):
    flow = build(tmp_path, Source(mat(reg, reg)), status_max_age_seconds=host, approval_max_age_seconds=host)
    assert flow.status_max_age_seconds == flow.approval_max_age_seconds == expect and expect <= host
    assert flow.registry_f4_policy_identity["host"] == {"status_max_age_seconds": host, "approval_max_age_seconds": host}


@pytest.mark.parametrize("bad", [True, 1.5, "60", None, -1, MAXV + 1])
def test_g03_host_scalars_must_be_exact_ints_in_range(tmp_path, bad):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat()), status_max_age_seconds=bad)
    refused(e, "host_scalar_invalid", boundary="construction")
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "b", Source(mat()), approval_max_age_seconds=bad)
    refused(e, "host_scalar_invalid")


@pytest.mark.parametrize("pl", [{}, {"status_max_age_seconds": 10}, {"approval_max_age_seconds": 10}, {"status_max_age_seconds": 10, "approval_max_age_seconds": 10, "x": 1},
                                {"status_max_age_seconds": 10.0, "approval_max_age_seconds": 10}, {"status_max_age_seconds": True, "approval_max_age_seconds": 10},
                                {"status_max_age_seconds": 0, "approval_max_age_seconds": 10}, {"status_max_age_seconds": MAXV + 1, "approval_max_age_seconds": 10},
                                {"status_max_age_seconds": "10", "approval_max_age_seconds": 10}, {"clock_tolerance_seconds": 5}])
def test_g04_missing_or_malformed_age_records_are_refused(tmp_path, pl):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat(rec=record(payload=pl))))
    refused(e, "registry_not_applied", boundary="construction")


def test_g05_invalid_record_text_and_material_types(tmp_path):
    for bad in (SelectionMaterial("{}", mat().selection_text, trust_for()), SelectionMaterial("not json", mat().selection_text, trust_for())):
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path, Source(bad))
        refused(e, "registry_not_applied")
    for bad in (None, "x", object(), SelectionMaterial(None, "x", None), SelectionMaterial("x", b"x", None)):
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path, Source(bad))
        refused(e, "material_invalid")


def test_g06_wrong_contract_family_and_cross_family(tmp_path):
    base = record()
    for label in ("r08-v1", "r08-v3", "r08-v4", "r08-v5", "r08-v6", ""):  # an r08-v5 (clock tolerance) envelope is never consumed here
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path / label.replace("-", "_") or tmp_path / "empty", Source(mat(rec=base, contract=label)))
        refused(e, "registry_not_applied")
    for fam in (f4.FAMILY_F5, "f1ab-local-execution-limits", "f4t-control-plane-clock-tolerance"):
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path / ("fam" + str(abs(hash(fam)))), Source(mat(rec=record(family=fam, payload={"status_max_age_seconds": 10, "approval_max_age_seconds": 10}),
                                                              stmt_over={"family": fam})))
        refused(e, "registry_not_applied")


def test_g07_invalid_signature_wrong_key_domain(tmp_path):
    for kw in ({"sk": OTHER_SK}, {"domain": b"ocs-reg/r08-v4/selection\n"}):
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path / str(len(kw)) / str(list(kw.values())[0])[:6], Source(mat(**kw)))
        refused(e, "registry_not_applied", "signature_invalid")


@pytest.mark.parametrize("over,code", [({"consumer_id": "other-consumer"}, "selection_consumer_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, tenant="tenant-other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, institution="urn:cognous:institution:other")}, "selection_scope_mismatch"),
                                       ({"scope": dict(STMT_SCOPE, authority_domain="other-domain")}, "selection_scope_mismatch"),
                                       ({"operation": "other.action"}, "selection_operation_mismatch")])
def test_g08_wrong_authority_scope_tenant_or_operation(tmp_path, over, code):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat(stmt_over=over)))
    refused(e, "registry_not_applied", code)


def test_g09_expired_stale_trust_revoked_and_withdrawn_at_construction(tmp_path):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "a", Source(mat()), construction_time=REG_NOW + timedelta(hours=6))
    refused(e, "registry_not_applied", "selection_expired")
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "b", Source(mat(trust=trust_for(valid_until="2026-10-04T00:00:00Z"))))
    refused(e, "registry_not_applied", "trust_snapshot_expired")
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "c", Source(mat(trust=trust_for(revoked_selections=frozenset({("sel-test-1", 1)})))))
    refused(e, "registry_not_applied", "selection_revoked")
    rec = record()
    sel_stmt = r.make_statement_v2(rec, family=f4.FAMILY_F4, consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    wd = s.withdraw_statement(sel_stmt)
    wmat = SelectionMaterial(r.dumps(rec), r.dumps(s.envelope(wd, signature=_sign(wd), pub=PK)), trust_for())
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "d", Source(wmat))
    refused(e, "registry_not_applied")


def test_g10_optional_participation_and_nonadmitted_verifier_and_profile(tmp_path):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "a", Source(mat(stmt_over={"participation": "optional"})))
    refused(e, "registry_not_applied")
    for v in (object(), None, ev.Ed25519Verifier, type("Sub", (ev.Ed25519Verifier,), {})()):
        with pytest.raises(RegistrySelectionRefused) as e:
            build(tmp_path / ("v" + str(id(v))), Source(mat()), verifier=v)
        refused(e, "verifier_not_admitted")
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "p", Source(mat()), runtime_authority_profile={"anything": 1})
    refused(e, "runtime_authority_profile_unsupported")


@pytest.mark.parametrize("scope", [None, GovernedScope("", TENANT, ACTION_ID, OPERATION), GovernedScope("c", "", ACTION_ID, OPERATION), GovernedScope("c", TENANT, 5, OPERATION), GovernedScope("c", TENANT, ACTION_ID, "")])
def test_g11_scope_must_be_host_fixed_nonempty_strings(tmp_path, scope):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat()), scope=scope)
    refused(e, "scope_invalid")


def test_g12_undeclared_action_source_failure_and_no_files_created(tmp_path):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "a", Source(mat()), scope=GovernedScope("consumer-test", TENANT, "no.such.action", OPERATION))
    refused(e, "manifest_action_undeclared")
    src = Source(mat())
    src.fail = True
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path / "b", src)
    refused(e, "selection_source_failed")
    (tmp_path / "c").mkdir()
    dest, store = LocalRefundDestination(tmp_path / "c" / "destination.json"), BoundedRecordStore(tmp_path / "c" / "run.json", "run-1")
    listing = sorted(x.name for x in (tmp_path / "c").glob("*"))
    with pytest.raises(RegistrySelectionRefused):
        GovernedAgeWorkflow(scope=SCOPE, selection_source=Source(mat(sk=OTHER_SK)), verifier=ev.Ed25519Verifier(), allow_test_time=True, manifest=manifest(),
                            resolver=tenant_resolver_for(tenant_proposal()), destination=dest, records=store)
    assert sorted(x.name for x in (tmp_path / "c").glob("*")) == listing and dest.snapshot()["effects"] == {}  # a refused construction writes nothing


# =============================================================================================================== real enforcement
def test_e01_existing_behaviour_is_equivalent_when_the_registry_value_does_not_narrow(tmp_path):
    for which, seconds in (("status", 0), ("status", 30), ("status", 59), ("status", 61), ("approval", 30), ("approval", 61), ("policy", 30), ("policy", 61)):
        p = tenant_proposal()
        base = plain(tmp_path / f"p-{which}-{seconds}", resolver=aged(p, seconds, which)).decide(p, now=NOW)
        flow = build(tmp_path / f"g-{which}-{seconds}", Source(mat(90, 90)), resolver=aged(p, seconds, which))
        got = flow.decide(p, now=NOW)
        assert (got.result, got.reasons) == (base.result, base.reasons), (which, seconds)


def test_e02_narrower_status_age_changes_the_real_decision(tmp_path):
    p = tenant_proposal()
    assert plain(tmp_path / "p", resolver=aged(p, 30, "status")).decide(p, now=NOW).result == "authorized"
    flow = build(tmp_path / "g", Source(mat(10, 60)), resolver=aged(p, 30, "status"))
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons and flow.destination.snapshot()["effects"] == {}


def test_e03_narrower_approval_age_changes_the_real_decision(tmp_path):
    p = tenant_proposal()
    assert plain(tmp_path / "p", resolver=aged(p, 30, "approval")).decide(p, now=NOW).result == "authorized"
    flow = build(tmp_path / "g", Source(mat(60, 10)), resolver=aged(p, 30, "approval"))
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "approval_status_stale_or_future" in d.reasons


def test_e04_registry_wider_than_host_leaves_the_host_bound(tmp_path):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(9999, 9999)), resolver=aged(p, 61, "status"))
    assert flow.status_max_age_seconds == 60
    assert "grant_status_stale_or_future" in flow.decide(p, now=NOW).reasons  # still refused at the host's 60 s


@pytest.mark.parametrize("bound,age,ok", [(30, 30, True), (30, 31, False), (1, 1, True), (1, 2, False)])
def test_e05_boundary_equality_uses_the_existing_inclusive_comparison(tmp_path, bound, age, ok):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(bound, bound)), resolver=aged(p, age, "status"))
    assert (flow.decide(p, now=NOW).result == "authorized") is ok


def test_e06_narrowed_policy_status_and_conflict_ages_use_the_same_scalar(tmp_path):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(10, 60)), resolver=aged(p, 30, "policy"))
    assert "policy_status_stale_or_future" in flow.decide(p, now=NOW).reasons


def test_e07_full_flow_executes_when_selection_stays_valid(tmp_path):
    p = tenant_proposal()
    src = Source(mat(60, 60))
    flow = build(tmp_path, src)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and src.calls == 3  # construction, decision, effect


# =============================================================================================================== lifecycle
def test_l01_revoked_after_construction_blocks_the_next_decision_without_state_change(tmp_path):
    p = tenant_proposal()
    src = Source(mat())
    flow = build(tmp_path, src)
    before = file_state(tmp_path, flow)
    src.mat = mat(trust=trust_for(revoked_selections=frozenset({("sel-test-1", 1)})))
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "decision")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


def test_l02_revoked_between_decision_and_effect_blocks_the_effect(tmp_path):
    p = tenant_proposal()
    src = Source(mat(60, 60))
    flow = build(tmp_path, src)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"
    before = file_state(tmp_path, flow)
    src.mat = mat(60, 60, trust=trust_for(revoked_selections=frozenset({("sel-test-1", 1)})))
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "registry_not_applied", "selection_revoked", "effect")
    assert file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


def test_l03_withdrawn_expired_and_stale_trust_after_construction(tmp_path):
    p = tenant_proposal()
    rec = record()
    sel_stmt = r.make_statement_v2(rec, family=f4.FAMILY_F4, consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z")
    wd = s.withdraw_statement(sel_stmt)
    wmat = SelectionMaterial(r.dumps(rec), r.dumps(s.envelope(wd, signature=_sign(wd), pub=PK)), trust_for())
    for new, code in ((wmat, None), (mat(trust=trust_for(valid_until="2026-10-04T00:00:00Z")), "trust_snapshot_expired")):
        src = Source(mat())
        flow = build(tmp_path / ("x" + str(id(new))), src)
        src.mat = new
        with pytest.raises(RegistrySelectionRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "registry_not_applied", code, "decision")


def test_l04_superseded_or_changed_selection_is_refused_and_never_widens(tmp_path):
    p = tenant_proposal()
    for new_vals in ((5, 5), (60, 60), (30, 10)):  # narrower, wider, mixed: any change needs a rebuild
        src = Source(mat(10, 10))
        flow = build(tmp_path / str(new_vals), src)
        src.mat = mat(*new_vals, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
        with pytest.raises(RegistrySelectionRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "selection_changed", boundary="decision")


def test_l05_an_equal_replacement_selection_is_accepted_but_never_a_different_policy(tmp_path):
    p = tenant_proposal()
    src = Source(mat(10, 10))
    flow = build(tmp_path, src)
    src.mat = mat(10, 10, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    assert flow.decide(p, now=NOW).result in ("authorized", "hold")  # same effective policy identity: allowed to proceed


def test_l06_source_failure_or_garbage_after_construction_blocks(tmp_path):
    p = tenant_proposal()
    src = Source(mat())
    flow = build(tmp_path, src)
    src.fail = True
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", boundary="decision")
    src.fail, src.mat = False, "garbage"
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "material_invalid")


def test_l07_attribute_edits_cannot_widen_the_bound_values(tmp_path):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(10, 10)))
    flow.status_max_age_seconds = 60
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "scalars_modified")
    flow.status_max_age_seconds = 10
    flow.approval_max_age_seconds = 9999
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "scalars_modified")


def test_l08_proposals_outside_the_host_fixed_scope_are_refused_before_registry(tmp_path):
    src = Source(mat())
    flow = build(tmp_path, src)
    calls = src.calls
    other_tenant = tenant_proposal("tenant-other")
    legacy = tba.proposal()
    other_action = tenant_proposal().model_copy(update={"action_id": "other.action"})
    for p in (other_tenant, legacy, other_action):
        before = file_state(tmp_path, flow)
        with pytest.raises(RegistrySelectionRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "proposal_out_of_scope", boundary="decision")
        assert file_state(tmp_path, flow) == before
    assert src.calls == calls  # no Registry material was even requested


def test_l09_manifest_authority_change_after_construction_is_refused(tmp_path):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat()))
    flow.manifest["actions"][0]["authority_context"]["authority_domain"] = "changed-domain"
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "manifest_authority_changed")


def test_l10_cross_family_partial_selection_cannot_widen_or_split_identity(tmp_path):
    """F4 is one record carrying both ages (atomic per selection). A tolerance (r08-v5/F4T) or class (F5) selection supplied in its place is refused at the
    construction AND every later boundary; there is no path by which one family's presence changes the other's values."""
    p = tenant_proposal()
    src = Source(mat(10, 10))
    flow = build(tmp_path, src)
    ident = flow.registry_f4_policy_identity
    src.mat = mat(rec=record(family="f4t-control-plane-clock-tolerance", contract="r08-v5", payload={"clock_tolerance_seconds": 1}), contract="r08-v5",
                  stmt_over={"family": "f4t-control-plane-clock-tolerance"})
    with pytest.raises(RegistrySelectionRefused):
        flow.decide(p, now=NOW)
    src.mat = mat(rec=record(family=f4.FAMILY_F5, payload={"class_status_max_age_seconds": {"x": 1}}), stmt_over={"family": f4.FAMILY_F5})
    with pytest.raises(RegistrySelectionRefused):
        flow.decide(p, now=NOW)
    assert flow.registry_f4_policy_identity == ident and flow.clock_tolerance_seconds == 5


def test_s01_module_excludes_clock_tolerance_and_other_families():
    text = Path(gov.__file__).read_text()
    for banned in ("v5_", "f4t", "verify_and_decide_v5", "class_status_max_age", "identity_max_age_seconds=", "mandate_max_age_seconds=", "clock_tolerance_seconds="):
        assert banned not in text.replace('"""', ""), banned


def test_s02_bounded_module_is_unmodified_by_this_increment():
    base = subprocess.run(["git", "show", "d66ae07fa240510efdcc11ed4b3e1189dcefc822:src/agent_control_plane/bounded.py"], capture_output=True, text=True,
                          cwd=Path(__file__).resolve().parent.parent)
    if base.returncode != 0:
        pytest.skip("NOT RUN: base revision d66ae07 not present in this checkout")
    assert (Path(__file__).resolve().parent.parent / "src/agent_control_plane/bounded.py").read_text() == base.stdout


def test_d01_defence_in_depth_refuses_a_registry_result_wider_than_the_host(tmp_path, monkeypatch):
    """A correct Registry never returns a value above the host's; if one ever did, the module refuses (mutation-checked)."""
    import registry_successor.decision as dec
    real = dec.verify_and_decide_v2

    def widened(*a, **k):
        d = real(*a, **k)
        return type(d)(d.kind, {"status_max_age_seconds": 9999, "approval_max_age_seconds": 9999}, d.deny_all, d.deny_all_fields, d.code, d.detail,
                       d.caller_unchanged, d.operationally_authorized)
    monkeypatch.setattr(dec, "verify_and_decide_v2", widened)
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat()))
    refused(e, "effective_policy_widens_host")
