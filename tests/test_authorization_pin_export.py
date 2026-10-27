"""Authorization pin export (Registry r08-v2 Amendment 4 section 3.2). Synthetic fixtures; builder-authored, not independent qualification.

Every refusal test asserts the refusal itself (PermissionError, or a non-active result with no payload), never only the absence of success.
"""
import copy
import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pytest

import agent_control_plane.authorization_pin_export as export
from agent_control_plane.authorization_pin_export import PAYLOAD_MEMBERS, PIN_EXPORT_PROFILE, assess_authorization_pin
from agent_control_plane.bounded import BoundedRecordStore, commitment
from agent_control_plane.policy_binding import PolicyBinding
from tests import v02_support as v02
from tests.test_bounded_authorization import NOW, PROFILE, TENANT  # noqa: F401  (NOW pinned by the autouse clock below)
from tests.test_bounded_authorization import _fixed_synthetic_clock  # noqa: F401  (autouse fixture)

FORMAT_PATH = Path("/home/claude/wt/runtime-installer/engine/authorization_pin_format.py")


def flow(tmp_path, binding=None, **kw):
    binding = binding or v02.canonical_binding()
    p, r, f, d, cfg = v02.tenant_flow(tmp_path, binding, **kw)
    return p, r, f, d, cfg, binding


def active(f, p, d, binding, **kw):
    return assess_authorization_pin(f, p, d, now=NOW, host_policy_binding=binding, **kw)


def refused(f, p, d, binding):
    """True refusal: PermissionError, or a non-active result that carries no payload."""
    try:
        out = active(f, p, d, binding)
    except PermissionError:
        return "PermissionError"
    assert out["state"] != "active" and out["payload"] is None
    return out


def test_honest_flow_is_active_with_exactly_the_17_members(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    out = active(f, p, d, b)
    assert out["profile"] == PIN_EXPORT_PROFILE == "ocs-s4/authorization-pin-export/0.1"
    assert out["state"] == "active" and out["terminal_status"] is None and out["decision_id"] == d.decision_id
    pay = out["payload"]
    assert tuple(pay) == PAYLOAD_MEMBERS and len(pay) == 17
    ra = d.binding.runtime_authority
    assert pay == {
        "tenant_id": d.binding.tenant_id, "institution_id": b["scope"]["institution"], "authority_domain": b["scope"]["authority_domain"],
        "consumer_id": b["consumer_id"], "operation": b["operation"],
        "decision_id": d.decision_id, "effect_id": d.effect_id, "action_id": d.binding.action_id,
        "grant_id": d.binding.grant_id, "grant_revision": d.binding.grant_revision,
        "approval_commitment": ra["approval_commitment"], "binding_digest": cfg.policy_binding.binding_digest,
        "selection_epoch": cfg.policy_binding.selection_epoch, "activation_ref": cfg.policy_binding.activation_ref,
        "policy_generation": ra["policy_generation"],
        "not_before": pay["not_before"], "expires_at": pay["expires_at"],
    }
    assert pay["binding_digest"] == v02.reference_binding_digest(b)
    assert pay["not_before"] < pay["expires_at"]
    json.dumps(out)


def test_payload_passes_the_runtime_format_module_when_available(tmp_path):
    if not FORMAT_PATH.exists():
        pytest.skip("Runtime format module not present in this environment (INCONCLUSIVE, not a pass)")
    spec = importlib.util.spec_from_file_location("pin_format_for_test", FORMAT_PATH)
    fmt = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fmt
    try:
        spec.loader.exec_module(fmt)
    finally:
        sys.modules.pop(spec.name, None)
    p, r, f, d, cfg, b = flow(tmp_path)
    assert fmt.payload_defect(active(f, p, d, b)["payload"]) is None
    assert tuple(fmt.PAYLOAD_MEMBERS) == PAYLOAD_MEMBERS


def test_signature_has_no_claim_or_expected_parameter():
    params = inspect.signature(assess_authorization_pin).parameters
    assert list(params) == ["workflow", "proposal", "decision", "now", "host_policy_binding"]
    assert all(params[n].kind is inspect.Parameter.KEYWORD_ONLY for n in ("now", "host_policy_binding"))
    for forbidden in ("claim", "expected_consumer_id", "expected_operation", "policy_binding", "expires_at", "claim_id"):
        assert forbidden not in params
    p = None
    with pytest.raises(TypeError):
        assess_authorization_pin(None, p, None, now=NOW, host_policy_binding={}, expected_operation="x")
    with pytest.raises(TypeError):
        assess_authorization_pin(None, p, None, now=NOW, host_policy_binding={}, claim={})


def test_tampered_decision_object_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    forged = d.model_copy(deep=True)
    forged.binding.grant_revision = "forged-revision"
    with pytest.raises(PermissionError, match="persisted decision"):
        active(f, p, forged, b)
    other = d.model_copy(update={"effect_id": "other-effect"})
    with pytest.raises(PermissionError, match="persisted decision"):
        active(f, p, other, b)
    unpersisted = d.model_copy(update={"decision_id": "never-persisted"})
    with pytest.raises(PermissionError, match="persisted decision"):
        active(f, p, unpersisted, b)


def test_non_authorized_persisted_decision_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    held = d.model_copy(update={"result": "hold"})
    with pytest.raises(PermissionError):
        active(f, p, held, b)  # also differs from the persisted authorized decision


def test_host_binding_body_with_different_digest_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    for field, value in (("record_version", 9), ("record_id", "rec-other"), ("effective_policy_digest", "sha256:" + "9" * 64)):
        body = copy.deepcopy(b)
        body[field] = value
        assert v02.reference_binding_digest(body) != cfg.policy_binding.binding_digest
        with pytest.raises(PermissionError, match="digest"):
            active(f, p, d, body)


def test_swapped_operation_or_consumer_in_host_body_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    for field, value in (("operation", "op-other"), ("consumer_id", "other-consumer")):
        body = copy.deepcopy(b)
        body[field] = value
        with pytest.raises(PermissionError):
            active(f, p, d, body)


def test_wrong_selection_epoch_or_activation_ref_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    for field, value in (("selection_epoch", b["selection_epoch"] + 1), ("activation_ref", "sha256:" + "7" * 64)):
        body = copy.deepcopy(b)
        body[field] = value
        with pytest.raises(PermissionError):
            active(f, p, d, body)
    # and from the profile side: a profile whose epoch differs from the host body
    f.runtime_authority_profile = cfg.model_copy(update={"policy_binding": cfg.policy_binding.model_copy(update={"selection_epoch": 99})}).snapshot()
    with pytest.raises(PermissionError):
        active(f, p, d, b)


def test_invalid_host_binding_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    for bad in (None, {}, {**b, "extra": 1}, {k: v for k, v in b.items() if k != "scope"}):
        with pytest.raises((PermissionError, TypeError)):
            active(f, p, d, bad)


def test_profile_altered_after_the_decision_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    altered = cfg.model_copy(update={"catalogue_version": "synthetic-catalogue/2"}).snapshot()
    assert commitment(altered.model_dump(mode="json")) != d.binding.runtime_authority["catalogue_digest"]
    f.runtime_authority_profile = altered
    with pytest.raises(PermissionError, match="profile differs"):
        active(f, p, d, b)


def test_persisted_catalogue_digest_mismatch_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    _rewrite_persisted(f, d, lambda x: x["binding"]["runtime_authority"].__setitem__("catalogue_digest", "sha256:" + "5" * 64))
    tampered = f.records.decision(d.decision_id)
    assert tampered.binding.runtime_authority["catalogue_digest"] == "sha256:" + "5" * 64
    with pytest.raises(PermissionError, match="profile differs"):
        active(f, p, tampered, b)


def test_approval_commitment_mismatch_is_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    _rewrite_persisted(f, d, lambda x: x["binding"]["runtime_authority"].__setitem__("approval_commitment", "sha256:" + "6" * 64))
    tampered = f.records.decision(d.decision_id)
    out = refused(f, p, tampered, b)
    assert out == "PermissionError" or out["state"] == "unknown"


def test_recomputed_approval_commitment_mismatch_is_refused(tmp_path):
    """The context the handoff reads no longer reproduces the persisted commitment (while resolver reasons are clean)."""
    p, r, f, d, cfg, b = flow(tmp_path)
    original = export._approval_commitment
    export._approval_commitment = lambda profile, context: "sha256:" + "4" * 64
    try:
        with pytest.raises(PermissionError, match="approval commitment"):
            active(f, p, d, b)
    finally:
        export._approval_commitment = original
    assert active(f, p, d, b)["state"] == "active"


def test_revoked_grant_is_terminal_revoked(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    gid = d.binding.grant_id
    r.statuses[gid] = r.statuses[gid].model_copy(update={"status": "revoked"})
    out = active(f, p, d, b)
    assert (out["state"], out["terminal_status"], out["payload"]) == ("terminal", "revoked", None)


def test_revoked_approval_is_terminal_revoked(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    ref = next(iter(r.approvals))
    r.approvals[ref] = r.approvals[ref].model_copy(update={"status": "revoked"})
    out = active(f, p, d, b)
    assert (out["state"], out["terminal_status"], out["payload"]) == ("terminal", "revoked", None)


def test_unknown_approval_status_is_not_guessed_terminal(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    ref = next(iter(r.approvals))
    r.approvals[ref] = r.approvals[ref].model_copy(update={"status": "unknown"})
    out = active(f, p, d, b)
    assert out["state"] == "unknown" and out["terminal_status"] is None and out["payload"] is None


def test_stale_grant_revision_is_terminal_superseded(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    gid = d.binding.grant_id
    r.statuses[gid] = r.statuses[gid].model_copy(update={"revision": "revision-newer"})
    out = active(f, p, d, b)
    assert (out["state"], out["terminal_status"], out["payload"]) == ("terminal", "superseded", None)


def test_superseded_policy_is_terminal_superseded(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    key = next(iter(r.policies))
    r.policies[key] = r.policies[key].model_copy(update={"status": "superseded"})
    out = active(f, p, d, b)
    assert (out["state"], out["terminal_status"], out["payload"]) == ("terminal", "superseded", None)


def test_withdrawn_binding_disposition_is_terminal_withdrawn(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    w = PolicyBinding(selection_epoch=cfg.policy_binding.selection_epoch + 1, activation_ref="sha256:" + "8" * 64,
                      policy_generation=cfg.policy_binding.policy_generation + 1, disposition="withdrawn")
    f.runtime_authority_profile = cfg.model_copy(update={"policy_binding": w}).snapshot()
    out = active(f, p, d, b)
    assert (out["state"], out["terminal_status"], out["payload"]) == ("terminal", "withdrawn", None)
    # a host body that does not name the activation the persisted decision committed to is refused, not guessed
    body = copy.deepcopy(b)
    body["activation_ref"] = "sha256:" + "3" * 64
    with pytest.raises(PermissionError, match="activation"):
        active(f, p, d, body)


def test_expiry_is_not_terminal(tmp_path):
    from datetime import timedelta
    p, r, f, d, cfg, b = flow(tmp_path)
    out = assess_authorization_pin(f, p, d, now=NOW + timedelta(days=3650), host_policy_binding=b)
    assert out["state"] == "unknown" and out["terminal_status"] is None and out["payload"] is None


def test_unreadable_status_is_unknown_or_refused(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    gid = d.binding.grant_id
    del r.statuses[gid]
    out = refused(f, p, d, b)
    assert out == "PermissionError" or (out["state"] == "unknown" and out["terminal_status"] is None)


def test_mixed_terminal_reasons_are_not_guessed(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    gid = d.binding.grant_id
    r.statuses[gid] = r.statuses[gid].model_copy(update={"status": "revoked", "revision": "revision-newer"})
    out = active(f, p, d, b)
    assert out["state"] == "unknown" and out["terminal_status"] is None and out["payload"] is None


def test_classifier_never_maps_unlisted_reasons():
    assert export._classify(["grant_revoked"], False) == "revoked"
    assert export._classify(["grant_revoked", "identity_or_delegation_invalid"], False) is None
    assert export._classify(["approval_not_active"], False) is None
    assert export._classify(["approval_not_active"], True) == "revoked"
    assert export._classify(["grant_revoked", "grant_revision_stale"], False) is None
    assert export._classify([], False) is None
    assert export._classify(["policy_stale_or_changed"], False) is None
    assert export._classify(["policy_stale_or_changed", "policy_superseded"], False) == "superseded"


def test_output_has_no_aliasing_with_inputs(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    b_before = copy.deepcopy(b)
    d_before = d.model_copy(deep=True)
    out = active(f, p, d, b)
    out["payload"]["tenant_id"] = "mutated"
    out["payload"]["operation"] = "mutated"
    assert b == b_before and d == d_before
    again = active(f, p, d, b)
    assert again["payload"]["tenant_id"] != "mutated" and again["payload"]["operation"] == b["operation"]
    # mutating the caller's binding afterwards cannot change an already returned result
    first = active(f, p, d, b)
    snapshot = copy.deepcopy(first)
    b["operation"] = "changed-after"
    b["scope"]["tenant"] = "changed-after"
    assert first == snapshot


def test_export_creates_no_claim_decision_or_policy_record(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    before = f.records.load()
    n_decisions, n_attempts = len(before.decisions), len(before.attempts)
    active(f, p, d, b)
    after = f.records.load()
    assert (len(after.decisions), len(after.attempts)) == (n_decisions, n_attempts)
    assert after.decisions == before.decisions


def test_persisted_state_not_caller_object_is_the_source(tmp_path):
    p, r, f, d, cfg, b = flow(tmp_path)
    forged_proposal = p.model_copy(update={"action_id": "other-action"})
    out = refused(f, forged_proposal, d, b)  # a proposal that does not match the persisted binding cannot yield an active pin
    assert out == "PermissionError" or out["state"] != "active"


def test_claim_issuance_bytes_unchanged_by_the_module(tmp_path):
    """The export imports private helpers but changes none: the frozen legacy claim vectors still reproduce."""
    from tests import test_policy_binding_approval_generation  # noqa: F401  (import only: collected separately)
    vectors = json.loads(v02.VECTORS.read_text())
    with __import__("tempfile").TemporaryDirectory() as tmp, v02.deterministic_uuids():
        from agent_control_plane.local_authority_effect import materialize_local_execution_claim
        pp, _, ff, dd, _cfg = v02.tenant_flow(Path(tmp), None, profile_binding=None)
        claim = materialize_local_execution_claim(ff, pp, dd, now=NOW, claim_id="claim-v02-legacy-tenant")
        assert claim.model_dump_json() == vectors["tenant"]["claim_json"]
        assert claim.claim_commitment == vectors["tenant"]["claim_commitment"]


def _rewrite_persisted(f, d, mutate):
    """Test-only: alter the persisted decision on disk (simulates a tampered or altered Control Plane store)."""
    store: BoundedRecordStore = f.records
    path = Path(store.path)
    doc = json.loads(path.read_text())
    for item in doc["decisions"]:
        if item["decision_id"] == d.decision_id:
            mutate(item)
    path.write_text(json.dumps(doc))
