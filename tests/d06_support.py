"""Shared builders for the D-06 effective-configuration binding tests (and for the cross-process worker `tests/d06_worker.py`).

BUILDER_TESTED developer evidence. NOT independently qualified. Not collected by pytest (no `test_` prefix). Reuses the composed-workflow fixtures of
`tests/test_governed_policy_composition.py` (real synthetic Ed25519 Registry material; the Registry pin is enforced by the module it imports).
"""
from __future__ import annotations

import json
from pathlib import Path

import tests.test_governed_policy_composition as T  # noqa: E402  (enforces the Registry pin and PyNaCl)
from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination, ObservationPolicy, commitment  # noqa: E402
from agent_control_plane.policy_binding import APPROVAL_COMMITMENT_V2  # noqa: E402
from agent_control_plane.registry_governed_policy import GovernedPolicyWorkflow  # noqa: E402
from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile  # noqa: E402
from tests import v02_support as v02  # noqa: E402
from tests.test_bounded_authorization import manifest as _manifest, tenant_proposal, tenant_resolver_for, workflow  # noqa: E402
from tests.test_runtime_authority import MEMBERS, PUBLIC, bind_approval, sign_evidence  # noqa: E402

base = T.base
NOW, REG_NOW, KEEP = T.NOW, T.REG_NOW, object()
ev = T.ev


def patch_clock(mp) -> None:
    """The synthetic fixed clock every governed test module uses (a `pytest.MonkeyPatch`)."""
    import agent_control_plane.bounded as bounded_module
    mp.setattr(bounded_module, "_now", lambda: NOW)
    for m in (T.pol, T.ugov, T.agegov, T.f4gov):
        mp.setattr(m, "_now", lambda: NOW)


def mk(tmp_path, res, cfg, fams, *, obs=KEEP, **top):
    """A composed governed workflow over the store/destination under `tmp_path`. `top` may carry any workflow keyword (scalars, legacy_cutoff, ...)."""
    kw = T.kwargs(tmp_path, res)
    if obs is not KEEP:
        kw["observation_policy"] = obs
    for k in ("clock_tolerance_seconds", "identity_max_age_seconds", "mandate_max_age_seconds"):
        if k in top:
            kw[k] = top.pop(k)
    return GovernedPolicyWorkflow(families=fams, verifier=ev.Ed25519Verifier(), runtime_authority_profile=top.pop("profile", cfg), construction_time=REG_NOW, **top, **kw)


def sources(f=False, a=True, u=True):
    return {"f": T.fsrc() if f else None, "a": T.asrc() if a else None, "u": T.usrc() if u else None}


def ready(tmp_path, *, f=False, a=True, u=True, **top):
    """(proposal, resolver, host profile, sources, workflow) with approvals issued against the FINAL effective profile. F4 is NOT declared by default so the F4 scalars are host values."""
    p, res, cfg = T.prepared(tmp_path)
    srcs = sources(f, a, u)
    flow = mk(tmp_path, res, cfg, T.families(srcs["f"], srcs["a"], srcs["u"]), **top)
    bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, srcs, flow


def authorized(tmp_path, **kw):
    p, res, cfg, srcs, flow = ready(tmp_path, **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, srcs, flow, d


# ---------------------------------------------------------------------------------------------------------------- pin-export capable governed fixture
def pin_prepared(work):
    """(proposal, resolver, profile-with-policy-binding, canonical host binding): the `v02_support.tenant_flow` fixture up to, not including, the workflow."""
    binding = v02.canonical_binding()
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    pb = v02.profile_for(binding)
    cl = ActionClass(class_id="synthetic-irreversible", irreversible=True, max_status_age_seconds=60, on_unreadable="refuse")
    cfg = RuntimeAuthorityProfile(catalogue_version="synthetic-catalogue/1", actions={p.action_id: cl}, producer_keys={"synthetic-validator": PUBLIC},
                                  allow_synthetic_resolver=True, policy_binding=pb)
    first = workflow(Path(work) / "baseline", p, resolver=r).decide(p, now=NOW)
    required = sorted([{"input_type": x.input_type, "input_id": x.input_id} for x in first.resolution_inputs], key=lambda x: (x["input_type"], x["input_id"]))
    context, criteria = r.contexts[v02.PROFILE], {}
    for ob in context["requirement"]["evidence"]:
        if ob["required"] and ob["kind"] == "authorization":
            criteria[ob["obligation_id"]] = {"kind": "exact_members", "producer_id": "synthetic-validator", "subject_digest": commitment(MEMBERS),
                                             "minimum_count": 40, "members": MEMBERS}
            sign_evidence(r.evidence[ob["obligation_id"]], tenant_id=v02.TENANT)
    context["runtime_authority"] = {"profile": "runtime-authority/0.1", "required_inputs": required, "required_inputs_digest": commitment(required), "evidence_criteria": criteria,
                                    "approval_commitment_version": APPROVAL_COMMITMENT_V2, "policy_generation": pb.policy_generation, "policy_activation_ref": pb.activation_ref}
    bind_approval(r, cfg)
    return p, r, cfg, binding


def pin_governed(store_dir, res, cfg, *, obs=KEEP, **top):
    """F4-only governed workflow (a profile carrying `policy_binding` is refused for the profile-bearing families, so F4 is the one family that reaches the pin export)."""
    kw = dict(allow_test_time=True, manifest=_manifest(), resolver=res, destination=LocalRefundDestination(Path(store_dir) / "destination.json"),
              records=BoundedRecordStore(Path(store_dir) / "run.json", "run-1"), observation_policy=ObservationPolicy(max_age_seconds=300))
    if obs is not KEEP:
        kw["observation_policy"] = obs
    for k in ("clock_tolerance_seconds", "identity_max_age_seconds", "mandate_max_age_seconds"):
        if k in top:
            kw[k] = top.pop(k)
    return GovernedPolicyWorkflow(families=T.families(f=T.fsrc()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW, **top, **kw)


def read_doc(store_dir) -> dict:
    return json.loads((Path(store_dir) / "run.json").read_text())


def write_doc(store_dir, doc: dict) -> None:
    (Path(store_dir) / "run.json").write_text(json.dumps(doc))


def rewrite_member(store_dir, decision_id, mutate) -> None:
    """Test-only: alter the persisted `runtime_authority` of one decision on disk (the store is unsigned local JSON)."""
    doc = read_doc(store_dir)
    for item in doc["decisions"]:
        if item["decision_id"] == decision_id:
            mutate(item["binding"])
    write_doc(store_dir, doc)
