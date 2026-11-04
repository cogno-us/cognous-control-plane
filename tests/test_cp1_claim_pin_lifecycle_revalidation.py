"""CP-1 (csf_38c4d7dd23b434d7cabe0192): Registry lifecycle revalidation at the claim / pin handoff boundary.

Before: `provision_local_execution_claim`, `materialize_local_execution_claim` and `assess_authorization_pin` resolved the persisted decision but never re-verified the Registry
selection, so a revoked / expired / stale / changed selection still provisioned a claim and produced an ACTIVE pin payload while `decide` / `execute` refused the same state.
After: a Registry-governed workflow re-verifies INSIDE the resolver handoff, after the private R1-A copies and before the resolution, claim construction, `provision()` callback
or pin payload, by the SAME canonical path as decide / execute (`GovernedLifecycle._gl_claim_revalidate` -> `_gl_revalidate` -> `_gl_reverify`). A claim refusal is the workflow's
existing refusal (boundary `claim`); a pin on a no-longer-current Registry state is a non-active `unknown`.

BUILDER_TESTED developer evidence. NOT independently qualified. Needs the Registry r08-v8 pin (`OCS_REGISTRY_PIN_DIR`, `OCS_REQUIRE_REGISTRY_PIN=1`) like the other governed suites.
"""
from __future__ import annotations

import pytest

from tests import d06_support as S  # noqa: E402  (enforces the Registry pin and PyNaCl)
from agent_control_plane import registry_governed_lifecycle as life  # noqa: E402
from agent_control_plane.authorization_pin_export import assess_authorization_pin  # noqa: E402
from agent_control_plane.local_authority_effect import (  # noqa: E402
    materialize_local_execution_claim,
    provision_local_execution_claim,
    verify_local_execution_claim,
)
from agent_control_plane.registry_governed_policy import RegistryGovernedPolicyRefused  # noqa: E402

T = S.T
NOW = S.NOW
FAMILIES = ["f", "a", "u"]
EXPIRED_AT = "2026-10-04T00:00:00Z"
FLOOR = (("sel-test-1", 2),)  # the trusted selection-epoch floor is above the selection's epoch 1
OPS = {"f": lambda: T.OP_F, "a": lambda: T.OP_A, "u": lambda: T.base.OP_U}


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    S.patch_clock(monkeypatch)


def _revoked(k):
    return T.revoked_for(k)


def _expired(k):
    return {"f": lambda: T.fmat(trust=T.trust_for(T.OP_F, valid_until=EXPIRED_AT)),
            "a": lambda: T.amat(T.AGE_M, trust=T.trust_for(T.OP_A, valid_until=EXPIRED_AT)),
            "u": lambda: T.mat(T.umap(t1=T.R_), trust=T.trust_for(T.base.OP_U, valid_until=EXPIRED_AT))}[k]()


def _stale_epoch(k):
    return {"f": lambda: T.fmat(trust=T.trust_for(T.OP_F, min_epochs=FLOOR)),
            "a": lambda: T.amat(T.AGE_M, trust=T.trust_for(T.OP_A, min_epochs=FLOOR)),
            "u": lambda: T.mat(T.umap(t1=T.R_), trust=T.trust_for(T.base.OP_U, min_epochs=FLOOR))}[k]()


def _changed(k):
    return {"f": lambda: T.fmat(status=20), "a": lambda: T.amat({T.CLASS_T1: 10}), "u": lambda: T.mat(T.umap(t1=T.base.B_))}[k]()


# kind -> (material builder, expected refusal-code suffix)
MUT = {"revoked": (_revoked, "registry_not_applied"), "expired": (_expired, "registry_not_applied"),
       "stale_epoch": (_stale_epoch, "registry_not_applied"), "changed": (_changed, "selection_changed")}
KINDS = list(MUT)
PREFIX = {"f": "f4_ages", "a": "class_age", "u": "class_unreadable"}


class Sink:
    def __init__(self):
        self.claims = []

    def __call__(self, claim):
        self.claims.append(claim)


def _code(k, suffix):
    """A family refusal is prefixed with its slot; the composed bound-identity comparison (`selection_changed`) is not."""
    return suffix if suffix == "selection_changed" else f"{PREFIX[k]}:{suffix}"


def _refused(exc, k, suffix, boundary="claim"):
    e = exc.value
    assert isinstance(e, RegistryGovernedPolicyRefused) and isinstance(e, PermissionError) and e.refusal.non_authorizing is True
    assert e.boundary == boundary and e.refusal.code == _code(k, suffix), e.refusal


def _spy_resolve(flow, monkeypatch):
    """Count resolutions: after a failed revalidation `_resolve` (and thus any claim construction) must never be reached."""
    calls = []
    real = type(flow)._resolve

    def spy(self, *a, **kw):
        calls.append(kw.get("stage", "decision"))
        return real(self, *a, **kw)

    monkeypatch.setattr(type(flow), "_resolve", spy)
    return calls


# ------------------------------------------------------------------------------------------------------------------------------ valid current selection
def test_v01_valid_current_selection_still_provisions_materializes_and_revalidates_at_the_boundary(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    before = {k: s.calls for k, s in srcs.items() if s is not None}
    sink = Sink()
    claim = provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    assert sink.claims == [claim] and verify_local_execution_claim(claim) is True
    after = {k: s.calls for k, s in srcs.items() if s is not None}
    assert all(after[k] > before[k] for k in before), "every declared family source must be read at the claim boundary"
    mat = materialize_local_execution_claim(flow, p, stored, now=NOW, claim_id="c1")
    assert mat.claim_commitment == claim.claim_commitment  # same effective configuration, same bytes


def test_v02_claim_bytes_with_revalidation_equal_claim_bytes_without_it(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    with_hook = materialize_local_execution_claim(flow, p, stored, now=NOW, claim_id="c1")
    monkeypatch.setattr(life.GovernedLifecycle, "_gl_claim_revalidate", None)  # a workflow without the hook: the pre-CP-1 path
    without_hook = materialize_local_execution_claim(flow, p, stored, now=NOW, claim_id="c1")
    assert with_hook.model_dump(mode="json") == without_hook.model_dump(mode="json")


def test_v03_valid_pin_is_active_with_the_unchanged_payload(tmp_path):
    p, res, profile, binding = S.pin_prepared(tmp_path / "work")
    store = tmp_path / "store"; store.mkdir()
    flow = S.pin_governed(store, res, profile)
    d = flow.decide(p, now=NOW)
    holder = flow._gp_families.f4_ages.selection_source
    calls = holder.calls
    out = assess_authorization_pin(flow, p, flow.records.decision(d.decision_id), now=NOW, host_policy_binding=binding)
    assert out["state"] == "active" and out["payload"] is not None and holder.calls > calls
    from agent_control_plane.authorization_pin_export import PAYLOAD_MEMBERS
    assert tuple(out["payload"]) == PAYLOAD_MEMBERS


# ------------------------------------------------------------------------------------------------------------------------------ provision: refuse before the callback
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("k", FAMILIES)
def test_p01_provision_refuses_a_non_current_registry_selection_before_the_callback(tmp_path, monkeypatch, k, kind):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    srcs[k].mat = MUT[kind][0](k)
    before = T.file_state(tmp_path, flow)
    resolves = _spy_resolve(flow, monkeypatch)
    sink = Sink()
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    _refused(e, k, MUT[kind][1])
    assert sink.claims == [], "provision() must not be reached"
    assert resolves == [], "no resolution (and so no claim construction or journal write) after a failed revalidation"
    assert T.file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("k", FAMILIES)
def test_p02_materialize_also_revalidates(tmp_path, monkeypatch, k, kind):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    srcs[k].mat = MUT[kind][0](k)
    resolves = _spy_resolve(flow, monkeypatch)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        materialize_local_execution_claim(flow, p, stored, now=NOW, claim_id="c1")
    _refused(e, k, MUT[kind][1])
    assert resolves == []


@pytest.mark.parametrize("k", FAMILIES)
def test_p03_a_malformed_or_unavailable_source_refuses_with_the_existing_exception(tmp_path, k):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    sink = Sink()
    srcs[k].fail = True  # unavailable
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    assert e.value.refusal.code == "selection_source_failed" and e.value.boundary == "claim"
    srcs[k].fail = False
    srcs[k].mat = "not-a-selection-material"  # malformed verifier/source result
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    assert e.value.refusal.code.endswith("material_invalid") and e.value.boundary == "claim"
    assert sink.claims == []


def test_p04_effective_configuration_mismatch_is_refused_and_the_bound_configuration_is_what_is_claimed(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    flow.status_max_age_seconds = flow.status_max_age_seconds + 1  # the live configuration drifts from the bound one
    sink = Sink()
    with pytest.raises(PermissionError):
        provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    assert sink.claims == []


def test_p05_a_proposal_outside_the_workflow_scope_is_refused(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    other = p.model_copy(deep=True)
    other.tenant_id = "tenant-other"
    sink = Sink()
    with pytest.raises(PermissionError):
        provision_local_execution_claim(flow, other, stored, now=NOW, provision=sink, claim_id="c1")
    assert sink.claims == []


# ------------------------------------------------------------------------------------------------------------------------------ R1-A ordering: after the private copies
def test_r01_a_hostile_registry_source_cannot_change_what_is_claimed(tmp_path):
    """The Registry source is host code that now runs inside the handoff. It mutates the caller's proposal AND decision; the claim still derives from the private copies."""
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    stored = flow.records.decision(d.decision_id)
    snapshot = p.model_copy(deep=True)
    real = srcs["f"].__class__.__call__

    def scribble(self):
        p.amount, p.target, p.effects, p.actor = 99.0, "acct:EVIL", 7, "urn:attacker"
        p.payload["reason"] = "tampered"
        p.requested_permissions.append("admin.everything")
        return real(self)

    srcs["f"].__class__.__call__ = scribble
    try:
        sink = Sink()
        claim = provision_local_execution_claim(flow, p, stored, now=NOW, provision=sink, claim_id="c1")
    finally:
        srcs["f"].__class__.__call__ = real
    assert p.target == "acct:EVIL"  # the caller's object really was mutated during the source read
    assert (claim.target, claim.amount, claim.effects, claim.actor) == (snapshot.target, snapshot.amount, snapshot.effects, snapshot.actor)
    assert claim.requested_permissions == snapshot.requested_permissions and verify_local_execution_claim(claim) is True


# ------------------------------------------------------------------------------------------------------------------------------ pin: non-active unknown, no active payload
def _pin_flow(tmp_path):
    p, res, profile, binding = S.pin_prepared(tmp_path / "work")
    store = tmp_path / "store"; store.mkdir()
    flow = S.pin_governed(store, res, profile)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, flow, d, binding, flow._gp_families.f4_ages.selection_source


@pytest.mark.parametrize("kind", KINDS)
def test_n01_pin_on_a_non_current_registry_selection_is_unknown_with_no_payload(tmp_path, monkeypatch, kind):
    p, flow, d, binding, holder = _pin_flow(tmp_path)
    stored = flow.records.decision(d.decision_id)
    holder.mat = MUT[kind][0]("f")
    resolves = _spy_resolve(flow, monkeypatch)
    out = assess_authorization_pin(flow, p, stored, now=NOW, host_policy_binding=binding)
    assert out["state"] == "unknown" and out["payload"] is None and out["terminal_status"] is None, out
    assert MUT[kind][1] in out["reason"] and out["decision_id"] == d.decision_id
    assert resolves == [], "the pin payload path (resolution) must not be reached"


def test_n02_pin_with_a_malformed_or_unavailable_source_keeps_the_exceptional_behavior(tmp_path):
    p, flow, d, binding, holder = _pin_flow(tmp_path)
    stored = flow.records.decision(d.decision_id)
    holder.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        assess_authorization_pin(flow, p, stored, now=NOW, host_policy_binding=binding)
    assert e.value.refusal.code == "selection_source_failed"
    holder.fail = False
    holder.mat = "not-a-selection-material"
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        assess_authorization_pin(flow, p, stored, now=NOW, host_policy_binding=binding)
    assert e.value.refusal.code.endswith("material_invalid")


def test_n03_pin_with_a_drifted_effective_configuration_is_not_active(tmp_path):
    p, flow, d, binding, holder = _pin_flow(tmp_path)
    stored = flow.records.decision(d.decision_id)
    flow.status_max_age_seconds = flow.status_max_age_seconds + 1
    out = assess_authorization_pin(flow, p, stored, now=NOW, host_policy_binding=binding)
    assert out["state"] == "unknown" and out["payload"] is None


# ------------------------------------------------------------------------------------------------------------------------------ decide / execute unchanged
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("k", FAMILIES)
def test_x01_execute_and_decide_still_refuse_the_same_state_at_their_own_boundaries(tmp_path, k, kind):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    srcs[k].mat = MUT[kind][0](k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert e.value.boundary == "effect" and e.value.refusal.code == _code(k, MUT[kind][1])
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    assert e.value.boundary == "decision" and flow.destination.snapshot()["effects"] == {}


def test_x02_the_hook_is_the_canonical_path_not_a_copy():
    import inspect
    src = inspect.getsource(life.GovernedLifecycle._gl_claim_revalidate)
    assert "self._gl_revalidate(proposal, \"claim\", now)" in src
