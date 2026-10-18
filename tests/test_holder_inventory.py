"""holder-inventory/0.1: opt-in enumerated authority holders; a flagged class holds until an inventory exists.

The probe over holders (routed and self-credentialed) is a qualification scenario (suites/outside-holder). Synthetic data only.
"""
import json
import pathlib

import pytest

from agent_control_plane.holder_inventory import (
    AuthorityHolder, CLASSIFICATION_UNKNOWN, CLASSIFICATION_WITNESSED, HolderInventory, classify_holders,
)
from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile
from tests.test_bounded_authorization import NOW
from tests.test_runtime_authority import bind_approval, setup_flow

REGISTRY = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas" / "runtime_authority_reasons_0_1.json").read_text(encoding="utf-8"))


def inventory(*holders):
    return HolderInventory(inventory_id="inv-1", recorded_by="urn:cognous:principal:inventory-owner", recorded_at=NOW.isoformat(),
                           holders=list(holders))


ROUTED = AuthorityHolder(holder_id="h-routed", kind="routed", enforcement_point="control plane effect check")
SELF = AuthorityHolder(holder_id="h-self", kind="self_credentialed", enforcement_point="destination credential")


def configure(r, f, cfg, *, flag, inv):
    actions = {k: v.model_copy(update={"requires_revocation_assurance": flag}) for k, v in cfg.actions.items()}
    cfg2 = cfg.model_copy(update={"actions": actions, "holder_inventory": inv})
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    return cfg2


def test_default_profile_is_byte_identical():
    cl = ActionClass(class_id="c")
    assert "requires_revocation_assurance" not in cl.model_dump(mode="json")
    profile = RuntimeAuthorityProfile(catalogue_version="v", actions={"a": cl})
    assert "holder_inventory" not in profile.model_dump(mode="json")
    assert ActionClass(class_id="c", requires_revocation_assurance=True).model_dump(mode="json")["requires_revocation_assurance"] is True


def test_flagged_class_holds_until_an_inventory_enumerating_a_holder_exists(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    assert f.decide(p, now=NOW).result == "authorized"                       # default path: no flag, no inventory
    for inv in (None, inventory()):                                          # missing, or enumerating nobody
        configure(r, f, cfg, flag=True, inv=inv)
        decision = f.decide(p, now=NOW)
        assert decision.result == "hold" and "holder_inventory_missing" in decision.reasons
        assert f.destination.snapshot()["effects"] == {}
    configure(r, f, cfg, flag=True, inv=inventory(ROUTED, SELF))
    assert f.decide(p, now=NOW).result == "authorized"                       # positive control: the same call with an inventory
    configure(r, f, cfg, flag=False, inv=None)
    assert f.decide(p, now=NOW).result == "authorized"                       # unflagged class: inventory irrelevant


def test_inventory_does_not_hold_an_unflagged_class_and_is_covered_by_the_approval_commitment(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    cfg2 = cfg.model_copy(update={"holder_inventory": inventory(ROUTED)})
    # not re-bound: the approval was issued over the profile without the inventory, so the changed profile is refused
    f.runtime_authority_profile = cfg2.snapshot()
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons


def test_inventory_members_are_closed_and_kind_is_a_closed_set():
    with pytest.raises(ValueError):
        AuthorityHolder(holder_id="h", kind="expired", enforcement_point="x")
    with pytest.raises(ValueError):
        AuthorityHolder(holder_id="h", kind="routed", enforcement_point="x", secret="s")


def test_reason_code_is_registered_typed_only():
    assert REGISTRY["codes"]["holder_inventory_missing"]["reason_kind"] == "typed_only"


def test_classify_holders_reports_two_lists_and_never_says_expired():
    rows = [{"refusal_id": "r1", "effect_id": "e1", "reasons": ["grant_revoked"], "changed_inputs": [{"input_id": "g"}]}]
    report = classify_holders([{"holder_id": "h-routed", "kind": "routed", "effect_ids": ["e1"]},
                               {"holder_id": "h-self", "kind": "self_credentialed", "effect_ids": ["e2"]}], rows)
    assert [h["holder_id"] for h in report["witnessed_refusals"]] == ["h-routed"]
    assert report["witnessed_refusals"][0]["classification"] == CLASSIFICATION_WITNESSED
    unknown = report["unenumerated_authority_needing_containment"]
    assert [h["holder_id"] for h in unknown] == ["h-self"] and unknown[0]["classification"] == CLASSIFICATION_UNKNOWN == "coverage_unknown"
    text = json.dumps(unknown).lower()
    assert not any(word in text for word in ("expired", "revoked", "lapsed", "inactive"))
    assert classify_holders([{"holder_id": "h"}], [])["witnessed_refusals"] == []
