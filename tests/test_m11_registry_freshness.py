"""M11 PR-2 oracles: Registry-governed Control Plane freshness scalars (RG-C-003 `status_max_age_seconds`, RG-C-004 `approval_max_age_seconds`,
RG-C-006 `clock_tolerance_seconds`) reaching the real `BoundedAuthorizationWorkflow._fresh` enforcement path. BUILDER_TESTED developer evidence. NOT
independently qualified. NOT an authorization mechanism.

Needs `OCS_REGISTRY_PIN_DIR` at the pinned Registry commit and PyNaCl; otherwise this module is reported NOT RUN (skipped with a reason), never passed
with a double. Every selection is signed with a real synthetic Ed25519 key.

  R   requirements  Registry below/equal/above caller; min/max boundaries; wrong type; missing field; invalid record; wrong contract/family;
                    invalid signature; wrong scope/tenant; revocation(withdrawal)/staleness; no-widening; refusal without state change
  E   enforcement   the narrowed scalars change the real decide() outcome; the existing default path is byte-for-byte unchanged
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest

PIN = "1a67d5396a3cf81512fdfa98c5cea9c6db70aede"  # M11 PR-1 head (Registry PR #58, r08-v5; UNMERGED at the time of this PR: re-pin to the merge commit after review)
PIN_DIR = os.environ.get("OCS_REGISTRY_PIN_DIR")
if not PIN_DIR or not (Path(PIN_DIR) / "registry_successor").is_dir():
    pytest.skip("NOT RUN: OCS_REGISTRY_PIN_DIR is not set to a Registry checkout at the pin", allow_module_level=True)
PIN_DIR = str(Path(PIN_DIR).resolve())
_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PIN_DIR, capture_output=True, text=True).stdout.strip()
if _head != PIN:
    pytest.fail(f"Registry checkout is {_head!r}, expected the pin {PIN}", pytrace=False)
sys.path.insert(0, PIN_DIR)
sys.path.insert(0, str(Path(PIN_DIR) / "tests"))
try:
    import nacl.bindings as nb
except ImportError:
    pytest.skip("NOT RUN: PyNaCl (Registry requirements-ed25519.lock.txt) is not installed", allow_module_level=True)

import r08_support as r  # noqa: E402  (Registry test builders, reused)
import s01_support as s  # noqa: E402
from registry_adapters import ed25519_verifier as ev  # noqa: E402
from registry_successor import common as c  # noqa: E402
from registry_successor import v2_age_bounds as f4  # noqa: E402
from registry_successor import v5_f4t as f4t  # noqa: E402

from agent_control_plane import registry_freshness_narrowing as adapter  # noqa: E402
from agent_control_plane.registry_freshness_narrowing import GovernedInput  # noqa: E402
from tests.test_bounded_authorization import NOW, authority_context, manifest, proposal, resolver_for  # noqa: E402,F401
from tests.test_bounded_authorization import PROFILE, workflow as plain_workflow  # noqa: E402
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, BoundedRecordStore, LocalRefundDestination, ObservationPolicy  # noqa: E402

@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)


PK, SK = nb.crypto_sign_seed_keypair(bytes(range(32)))
OTHER_PK, OTHER_SK = nb.crypto_sign_seed_keypair(bytes(range(1, 33)))
V5_DOMAIN = b"ocs-reg/r08-v5/selection\n"
MAXV = 2147483647


# ------------------------------------------------------------------------------------------------------------------------ builders
def _sign(stmt, domain, sk=None):
    return base64.b64encode(nb.crypto_sign(domain + c.canonical_bytes(stmt), sk or SK)[:64]).decode("ascii")


def _record(family, contract, pl, **over):
    body = dict(r.make_record(), contract_version=contract, family=family, record_id=f"{contract}-test-record", payload=pl)
    body.update(over)
    return r.seal_record(body)


def gi_ages(status=10, approval=20, *, sk=None, ctx=None, trust=None, now=None, record=None, text=None, family=None, contract="r08-v2", sel_contract="r08-v2",
            domain=None, **stmt_over):
    rec = record if record is not None else _record(family or f4.FAMILY_F4, contract, {"status_max_age_seconds": status, "approval_max_age_seconds": approval})
    stmt = r.make_statement_v2(rec, family=family or f4.FAMILY_F4, **stmt_over)
    sel = r.dumps(s.envelope(stmt, domain=domain or s.V2_DOMAIN, contract=sel_contract, signature=_sign(stmt, domain or s.V2_DOMAIN, sk), pub=PK))
    return GovernedInput(text if text is not None else r.dumps(rec), sel, ctx or s.CTX, trust or s.trust(pub=PK), now or r.NOW)


def gi_tol(tol=2, *, sk=None, ctx=None, trust=None, now=None, record=None, text=None, family=None, contract="r08-v5", sel_contract="r08-v5", domain=None,
           pl=None, **stmt_over):
    rec = record if record is not None else _record(family or f4t.FAMILY_F4T, contract, pl if pl is not None else {"clock_tolerance_seconds": tol})
    stmt = r.make_statement_v2(rec, family=family or f4t.FAMILY_F4T, **stmt_over)
    sel = r.dumps(s.envelope(stmt, domain=domain or V5_DOMAIN, contract=sel_contract, signature=_sign(stmt, domain or V5_DOMAIN, sk), pub=PK))
    return GovernedInput(text if text is not None else r.dumps(rec), sel, ctx or s.CTX, trust or s.trust(pub=PK), now or r.NOW)


def resolve(ages=None, tol=None, *, status=60, approval=60, tolerance=5, verifier=None):
    return adapter.resolve_governed_freshness(status_max_age_seconds=status, approval_max_age_seconds=approval, clock_tolerance_seconds=tolerance,
                                              verifier=verifier or ev.Ed25519Verifier(), ages=ages, tolerance=tol)


def refused(res, code=None, registry_code=None):
    assert res.ok is False and res.values is None and res.effective_policy_digests is None and res.non_authorizing is True
    if code:
        assert res.adapter_refusal == code, res
    if registry_code:
        assert res.registry_code == registry_code, res
    return res


# ================================================================================================================== R: requirements
@pytest.mark.parametrize("reg,caller,expect", [(10, 60, 10), (60, 60, 60), (90, 60, 60), (1, 60, 1), (MAXV, MAXV, MAXV), (5, 0, 0), (1, 1, 1)])
def test_r01_ages_below_equal_above_and_boundaries_never_widen(reg, caller, expect):
    res = resolve(gi_ages(reg, reg), status=caller, approval=caller)
    assert res.ok and res.values["status_max_age_seconds"] == expect == res.values["approval_max_age_seconds"] and expect <= caller
    assert res.values["clock_tolerance_seconds"] == 5 and res.registry_kind == "applied" and set(res.effective_policy_digests) == {"f4"}


@pytest.mark.parametrize("reg,caller,expect", [(2, 5, 2), (5, 5, 5), (9, 5, 5), (0, 5, 0), (MAXV, MAXV, MAXV), (3, 0, 0)])
def test_r02_tolerance_below_equal_above_and_boundaries_never_widen(reg, caller, expect):
    res = resolve(None, gi_tol(reg), tolerance=caller)
    assert res.ok and res.values["clock_tolerance_seconds"] == expect <= caller and set(res.effective_policy_digests) == {"f4t"}
    assert res.values["status_max_age_seconds"] == 60 and res.values["approval_max_age_seconds"] == 60  # ungoverned groups keep the caller value


def test_r03_each_age_is_composed_independently():
    res = resolve(gi_ages(10, 90), status=60, approval=60)
    assert res.ok and (res.values["status_max_age_seconds"], res.values["approval_max_age_seconds"]) == (10, 60)


@pytest.mark.parametrize("bad", [True, False, 5.0, "5", None, -1, MAXV + 1, [5]])
@pytest.mark.parametrize("which", ["status", "approval", "tolerance"])
def test_r04_wrong_type_or_range_caller_scalar_is_refused_before_registry(which, bad):
    kw = {"status": 60, "approval": 60, "tolerance": 5}
    kw[which] = bad
    refused(resolve(gi_ages(), gi_tol(), **kw), "caller_scalar_invalid")


@pytest.mark.parametrize("pl", [{}, {"status_max_age_seconds": 10}, {"approval_max_age_seconds": 10}, {"status_max_age_seconds": 10, "approval_max_age_seconds": 20, "x": 1},
                                {"status_max_age_seconds": 10.0, "approval_max_age_seconds": 20}, {"status_max_age_seconds": True, "approval_max_age_seconds": 20},
                                {"status_max_age_seconds": 0, "approval_max_age_seconds": 20}, {"status_max_age_seconds": MAXV + 1, "approval_max_age_seconds": 20},
                                {"status_max_age_seconds": "10", "approval_max_age_seconds": 20}])
def test_r05_malformed_age_record_is_refused(pl):
    refused(resolve(gi_ages(record=_record(f4.FAMILY_F4, "r08-v2", pl))), "registry_not_applied")


@pytest.mark.parametrize("pl", [{}, {"clock_tolerance_seconds": 2, "x": 1}, {"clock_tolerance_seconds": 2.0}, {"clock_tolerance_seconds": True}, {"clock_tolerance_seconds": -1},
                                {"clock_tolerance_seconds": MAXV + 1}, {"clock_tolerance_seconds": "2"}, {"clock_tolerance_seconds": None}])
def test_r06_malformed_tolerance_record_is_refused(pl):
    refused(resolve(None, gi_tol(record=_record(f4t.FAMILY_F4T, "r08-v5", pl))), "registry_not_applied")


def test_r07_missing_field_and_invalid_record_text_are_refused():
    refused(resolve(gi_ages(text="{}")), "registry_not_applied")
    refused(resolve(None, gi_tol(text="not json")), "registry_not_applied")
    refused(resolve(GovernedInput(None, "x", s.CTX, s.trust(pub=PK), r.NOW)), "input_invalid")
    refused(resolve(None, GovernedInput("x", b"x", s.CTX, s.trust(pub=PK), r.NOW)), "input_invalid")
    refused(resolve(object()), "input_invalid")


def test_r08_wrong_contract_or_family_is_refused():
    # the tolerance family under the ages entry point and the reverse; and each family under the wrong contract label
    refused(resolve(gi_ages(family=f4t.FAMILY_F4T, contract="r08-v5", sel_contract="r08-v5", domain=V5_DOMAIN)), "registry_not_applied")
    refused(resolve(None, gi_tol(family=f4.FAMILY_F4, contract="r08-v2", sel_contract="r08-v2", domain=s.V2_DOMAIN)), "registry_not_applied")
    for bad in ("r08-v4", "r08-v3", "r08-v1", "r08-v6"):
        refused(resolve(None, gi_tol(sel_contract=bad)), "registry_not_applied")
        refused(resolve(gi_ages(sel_contract=bad)), "registry_not_applied")
    refused(resolve(gi_ages(domain=V5_DOMAIN)), "registry_not_applied", "signature_invalid")  # a v5 signature never verifies an r08-v2 statement
    refused(resolve(None, gi_tol(domain=s.V2_DOMAIN)), "registry_not_applied", "signature_invalid")


def test_r09_invalid_signature_and_wrong_key_are_refused():
    refused(resolve(gi_ages(sk=OTHER_SK)), "registry_not_applied", "signature_invalid")
    refused(resolve(None, gi_tol(sk=OTHER_SK)), "registry_not_applied", "signature_invalid")
    g = gi_tol()
    forged = GovernedInput(g.record_text, g.selection_text.replace('"epoch": 1', '"epoch": 2'), g.context, g.trust, g.now)
    assert forged.selection_text != g.selection_text
    assert resolve(None, forged).ok is False


@pytest.mark.parametrize("ctx,code", [(c.ExpectedContext("other-consumer", "tenant-a", "inst-a", "domain-a", "op-test"), "selection_consumer_mismatch"),
                                      (c.ExpectedContext("consumer-test", "tenant-b", "inst-a", "domain-a", "op-test"), "selection_scope_mismatch"),
                                      (c.ExpectedContext("consumer-test", "tenant-a", "inst-b", "domain-a", "op-test"), "selection_scope_mismatch"),
                                      (c.ExpectedContext("consumer-test", "tenant-a", "inst-a", "domain-b", "op-test"), "selection_scope_mismatch"),
                                      (c.ExpectedContext("consumer-test", "tenant-a", "inst-a", "domain-a", "op-other"), "selection_operation_mismatch")])
def test_r10_wrong_scope_tenant_or_operation_is_refused(ctx, code):
    refused(resolve(gi_ages(ctx=ctx)), "registry_not_applied", code)
    refused(resolve(None, gi_tol(ctx=ctx)), "registry_not_applied", code)


def test_r11_withdrawn_expired_and_stale_trust_are_refused():
    import datetime
    late = r.NOW + datetime.timedelta(hours=13)  # after the selection window (2026-10-26T00:00Z), inside the trust snapshot
    refused(resolve(gi_ages(now=late)), "registry_not_applied", "selection_expired")
    refused(resolve(None, gi_tol(now=late)), "registry_not_applied", "selection_expired")
    stale_trust = s.trust(pub=PK, valid_until="2026-10-25T06:00:00Z")
    refused(resolve(gi_ages(trust=stale_trust)), "registry_not_applied", "trust_snapshot_expired")
    refused(resolve(None, gi_tol(trust=stale_trust)), "registry_not_applied", "trust_snapshot_expired")
    # a signed withdrawal for the same selection is never an application
    for build, dom in ((gi_ages, s.V2_DOMAIN), (gi_tol, V5_DOMAIN)):
        g = build()
        import json
        sel = json.loads(g.selection_text)
        wd = dict(sel["statement"], disposition="withdraw")
        env = s.envelope(wd, domain=dom, contract=sel["contract_version"], signature=_sign(wd, dom), pub=PK)
        res = resolve(GovernedInput(g.record_text, r.dumps(env), g.context, g.trust, g.now)) if build is gi_ages else \
            resolve(None, GovernedInput(g.record_text, r.dumps(env), g.context, g.trust, g.now))
        refused(res, "registry_not_applied")


def test_r12_optional_participation_is_refused_never_skipped():
    refused(resolve(gi_ages(participation="optional")), "registry_not_applied")
    refused(resolve(None, gi_tol(participation="optional")), "registry_not_applied")


def test_r13_verifier_must_be_the_registry_ed25519_verifier():
    class Fake:
        def __getattr__(self, name):
            raise AssertionError("a non-Registry verifier must never be consulted")
    refused(resolve(gi_ages(), verifier=Fake()), "verifier_not_admitted")
    refused(resolve(None, gi_tol(), verifier=object()), "verifier_not_admitted")
    refused(resolve(None, gi_tol(), verifier=ev.Ed25519Verifier), "verifier_not_admitted")  # the class, not an instance
    sub = type("Sub", (ev.Ed25519Verifier,), {})
    refused(resolve(gi_ages(), verifier=sub()), "verifier_not_admitted")


def test_r14_no_governed_input_is_refused_and_both_inputs_must_each_apply():
    refused(resolve(None, None), "no_governed_input")
    good = resolve(gi_ages(10, 20), gi_tol(2))
    assert good.ok and good.values == {"status_max_age_seconds": 10, "approval_max_age_seconds": 20, "clock_tolerance_seconds": 2}
    assert set(good.effective_policy_digests) == {"f4", "f4t"} and good.effective_policy_digests["f4"] != good.effective_policy_digests["f4t"]
    refused(resolve(gi_ages(10, 20), gi_tol(sk=OTHER_SK)), "registry_not_applied")  # one bad input refuses everything; no partial result
    refused(resolve(gi_ages(sk=OTHER_SK), gi_tol(2)), "registry_not_applied")


def test_r15_effective_policy_identity_is_bound_to_the_values_used():
    from registry_successor import v2_policy_identity as v2i, v5_policy_identity as v5i
    res = resolve(gi_ages(10, 20), gi_tol(2))
    assert res.effective_policy_digests["f4"] == v2i.effective_policy_digest(f4.FAMILY_F4, {"status_max_age_seconds": 10, "approval_max_age_seconds": 20})
    assert res.effective_policy_digests["f4t"] == v5i.effective_policy_digest(f4t.FAMILY_F4T, {"clock_tolerance_seconds": 2})
    other = resolve(gi_ages(11, 20), gi_tol(3))
    assert other.effective_policy_digests["f4"] != res.effective_policy_digests["f4"] and other.effective_policy_digests["f4t"] != res.effective_policy_digests["f4t"]


def test_r16_adapter_defends_against_a_widening_registry_result(monkeypatch):
    """Defence in depth: even if Registry returned a value above the caller's, the adapter refuses (not exercised by a correct Registry)."""
    import registry_successor.decision as dec
    real = dec.verify_and_decide_v2

    def widened(*a, **k):
        d = real(*a, **k)
        return type(d)(d.kind, {"status_max_age_seconds": 9999, "approval_max_age_seconds": 9999}, d.deny_all, d.deny_all_fields, d.code, d.detail,
                       d.caller_unchanged, d.operationally_authorized)
    monkeypatch.setattr(dec, "verify_and_decide_v2", widened)
    refused(resolve(gi_ages(10, 20)), "effective_policy_widens_caller")


def test_r17_registry_unavailable_is_a_refusal(monkeypatch):
    import importlib
    real = importlib.import_module

    def boom(name, *a, **k):
        if name.startswith("registry_"):
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(adapter.importlib, "import_module", boom)
    refused(resolve(gi_ages()), "registry_unavailable")


# ================================================================================================================== E: enforcement
def build(tmp_path, p, resolver, **kw):
    return adapter.build_governed_workflow(allow_test_time=True, manifest=manifest(), resolver=resolver,
                                           destination=LocalRefundDestination(tmp_path / "destination.json"),
                                           records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
                                           observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
                                           verifier=ev.Ed25519Verifier(), **kw)


def _aged_resolver(p, seconds, which):
    rr = resolver_for(p)
    grant = rr.contexts[PROFILE]["grant"]
    stamp = (NOW - timedelta(seconds=seconds)).isoformat()
    if which == "status":
        rr.statuses[grant["grant_id"]].observed_at = stamp
    else:
        rr.approvals[grant["approval_refs"][0]].observed_at = stamp
    return rr


def test_e01_default_path_is_unchanged_and_ungoverned_values_keep_caller_behaviour(tmp_path):
    p = proposal()
    flow = plain_workflow(tmp_path, p, resolver=_aged_resolver(proposal(), 30, "status"))
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds, flow.clock_tolerance_seconds) == (60, 60, 5)
    assert flow.decide(p, now=NOW).result == "authorized"
    assert not hasattr(flow, "registry_effective_policy_digests")


def test_e02_registry_status_age_narrows_the_real_decision(tmp_path):
    p = proposal()
    r_ = _aged_resolver(p, 30, "status")
    # caller-only (60s): a 30s-old status is fresh
    assert plain_workflow(tmp_path / "plain", p, resolver=r_).decide(p, now=NOW).result == "authorized"
    flow, res = build(tmp_path / "gov", p, _aged_resolver(p, 30, "status"), ages=gi_ages(10, 60))
    assert res.ok and flow.status_max_age_seconds == 10
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_e03_registry_approval_age_narrows_the_real_decision(tmp_path):
    p = proposal()
    assert plain_workflow(tmp_path / "plain", p, resolver=_aged_resolver(p, 30, "approval")).decide(p, now=NOW).result == "authorized"
    flow, res = build(tmp_path / "gov", p, _aged_resolver(p, 30, "approval"), ages=gi_ages(60, 10))
    assert res.ok and flow.approval_max_age_seconds == 10
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "approval_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_e04_registry_clock_tolerance_narrows_the_real_decision(tmp_path):
    p = proposal()
    rr = resolver_for(p)
    rr.statuses[rr.contexts[PROFILE]["grant"]["grant_id"]].observed_at = (NOW + timedelta(seconds=3)).isoformat()
    assert plain_workflow(tmp_path / "plain", p, resolver=rr).decide(p, now=NOW).result == "authorized"  # 3s ahead is inside the 5s default
    rr2 = resolver_for(p)
    rr2.statuses[rr2.contexts[PROFILE]["grant"]["grant_id"]].observed_at = (NOW + timedelta(seconds=3)).isoformat()
    flow, res = build(tmp_path / "gov", p, rr2, tolerance=gi_tol(1))
    assert res.ok and flow.clock_tolerance_seconds == 1
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_e05_governed_equal_or_wider_values_preserve_existing_behaviour_and_bind_identity(tmp_path):
    p = proposal()
    flow, res = build(tmp_path, p, _aged_resolver(p, 30, "status"), ages=gi_ages(90, 90), tolerance=gi_tol(9))
    assert res.ok and (flow.status_max_age_seconds, flow.approval_max_age_seconds, flow.clock_tolerance_seconds) == (60, 60, 5)
    assert flow.registry_effective_policy_digests == dict(res.effective_policy_digests) and set(flow.registry_effective_policy_digests) == {"f4", "f4t"}
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"
    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_e06_identity_and_mandate_ages_stay_host_owned(tmp_path):
    p = proposal()
    flow, _ = build(tmp_path, p, resolver_for(p), ages=gi_ages(10, 10), tolerance=gi_tol(1), identity_max_age_seconds=77, mandate_max_age_seconds=88)
    assert (flow.identity_max_age_seconds, flow.mandate_max_age_seconds) == (77, 88)


def test_e07_explicit_caller_scalars_are_the_ceiling_and_cannot_be_exceeded(tmp_path):
    p = proposal()
    flow, res = build(tmp_path, p, resolver_for(p), ages=gi_ages(40, 40), tolerance=gi_tol(9), status_max_age_seconds=5, approval_max_age_seconds=6,
                      clock_tolerance_seconds=2)
    assert res.ok and (flow.status_max_age_seconds, flow.approval_max_age_seconds, flow.clock_tolerance_seconds) == (5, 6, 2)
    flow, res = build(tmp_path / "bad", p, resolver_for(p), ages=gi_ages(40, 40), status_max_age_seconds=True)
    assert flow is None and res.adapter_refusal == "caller_scalar_invalid"


@pytest.mark.parametrize("which", ["ages", "tolerance"])
def test_e08_refusal_builds_no_workflow_and_changes_no_state(tmp_path, which):
    p = proposal()
    dest, store = LocalRefundDestination(tmp_path / "destination.json"), BoundedRecordStore(tmp_path / "run.json", "run-1")
    snap = lambda: (sorted(x.name for x in tmp_path.rglob("*")), dest.snapshot())  # noqa: E731
    before = snap()
    kw = {"ages": gi_ages(sk=OTHER_SK)} if which == "ages" else {"tolerance": gi_tol(sk=OTHER_SK)}
    flow, res = adapter.build_governed_workflow(allow_test_time=True, manifest=manifest(), resolver=resolver_for(p), destination=dest, records=store,
                                                verifier=ev.Ed25519Verifier(), **kw)
    assert flow is None and res.ok is False and res.values is None
    assert snap() == before and dest.snapshot()["effects"] == {}


def test_e09_no_fallback_to_the_caller_value_after_a_governed_input_fails(tmp_path):
    p = proposal()
    flow, res = build(tmp_path, p, resolver_for(p), ages=gi_ages(10, 10), tolerance=gi_tol(sk=OTHER_SK))
    assert flow is None and res.adapter_refusal == "registry_not_applied"


def test_e10_existing_default_constructor_signature_is_unchanged():
    import inspect
    params = inspect.signature(BoundedAuthorizationWorkflow.__init__).parameters
    assert (params["status_max_age_seconds"].default, params["identity_max_age_seconds"].default, params["mandate_max_age_seconds"].default,
            params["approval_max_age_seconds"].default, params["clock_tolerance_seconds"].default) == (60, 60, 60, 60, 5)
