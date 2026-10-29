"""policy-binding/0.1: local approval-generation binding, approval-commitment/0.2 and registry freshness ceilings (R6).

Scope: LOCAL comparison against the TRUSTED profile only. These tests prove that an approval is valid for exactly one binding as the
profile states it, and that registry freshness ceilings are source-enforced. They do NOT prove durable anti-rollback enforcement:
the two NEGATIVE CONTROLS at the end pin what this module cannot prevent (an older generation presented with an identical binding
revives the older approval; a dropped binding revives the legacy approval). Those are obligations of the enforcing consumer (a durable
``scope_required`` ratchet and atomic effect-time verification, EXT-S4), which this change does not implement.

Synthetic fixtures only. Builder-authored, not independent qualification.
"""
from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent_control_plane.freshness import AgeExtensionRefused, FreshnessProfile
from agent_control_plane.policy_binding import APPROVAL_COMMITMENT_V2, NEW_CODES, PolicyBinding, ZERO_DIGEST
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile, approval_commitment
from tests.test_bounded_authorization import NOW, PROFILE
from tests.test_freshness import authority, clock, execute, request, stale_grant, stall_before_dispatch  # noqa: F401  (clock is a fixture)
from tests.test_runtime_authority import bind_approval, setup_flow

D1, D2 = "sha256:" + "a1" * 32, "sha256:" + "b2" * 32
A1, A2, A3 = "sha256:" + "c1" * 32, "sha256:" + "c2" * 32, "sha256:" + "c3" * 32

#: Golden literals of the legacy (no binding) commitment, computed on the unmodified base 7a4bcd40 with the same fixtures.
GOLDEN = {
    "default": "sha256:70862ca5d40738a0112f14dc06ae9f5105fec525333ca6e9f7fb490a53ead09b",
    "fresh0": "sha256:fe36ea34cd07579b9928a1fb76c0cf694067753765afe88cb68cedae51198814",
    "fresh300": "sha256:7912bc257b64a4dd19b56d1266c694c8d3e7cec07cea4185943a7c0a40aeba0c",
    "fresh300_anchored": "sha256:eabc0a95b1d8b77e50322d6421f15f608135121f923b495ec3588068d8250e1c",
}


def binding(**o):
    base = dict(binding_digest=D1, selection_epoch=1, activation_ref=A1, policy_generation=1, disposition="selected")
    base.update(o)
    return PolicyBinding(**base)


def withdrawn(**o):
    base = dict(selection_epoch=2, activation_ref=A2, policy_generation=2, disposition="withdrawn")
    base.update(o)
    return PolicyBinding(**base)


def adopt(r, f, cfg, new_binding, *, freshness=None, issue=True):
    """Switch the workflow to a trusted profile carrying ``new_binding``; ``issue`` mints an approval carrying its generation members."""
    update = {"policy_binding": new_binding}
    if freshness is not None:
        update["freshness"] = freshness
    cfg2 = cfg.model_copy(update=update)
    if issue and new_binding is not None:
        spec = r.contexts[PROFILE]["runtime_authority"]
        spec.update({"approval_commitment_version": APPROVAL_COMMITMENT_V2, "policy_generation": new_binding.policy_generation,
                     "policy_activation_ref": new_binding.activation_ref})
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    return cfg2


def decide(f, p):
    return f.decide(p, now=NOW)


# ------------------------------------------------------------------------------------------------ default path
def test_default_path_is_byte_identical_and_carries_no_binding_key(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    ctx = r.contexts[PROFILE]
    assert "policy_binding" not in c.model_dump(mode="json")
    assert approval_commitment(c, ctx) == GOLDEN["default"]
    assert approval_commitment(c.model_copy(update={"freshness": FreshnessProfile()}), ctx) == GOLDEN["fresh0"]
    assert approval_commitment(c.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=300)}), ctx) == GOLDEN["fresh300"]
    anchored = FreshnessProfile(max_age_extension_seconds=300, anchor_deadline_to_inputs=True)
    assert approval_commitment(c.model_copy(update={"freshness": anchored}), ctx) == GOLDEN["fresh300_anchored"]


def test_a_binding_changes_the_commitment_and_selects_the_tagged_version(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    ctx = r.contexts[PROFILE]
    assert approval_commitment(c.model_copy(update={"policy_binding": binding()}), ctx) != GOLDEN["default"]


def test_epoch_and_generation_are_independent_members_of_the_commitment(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    ctx = r.contexts[PROFILE]
    commit = lambda b: approval_commitment(c.model_copy(update={"policy_binding": b}), ctx)  # noqa: E731
    base = commit(binding())
    assert commit(binding(policy_generation=2)) != base          # same epoch, different generation
    assert commit(binding(selection_epoch=2)) != base            # different epoch, same generation
    assert commit(binding(activation_ref=A2)) != base
    assert commit(binding(binding_digest=D2)) != base
    assert commit(binding(selection_epoch=2)) != commit(binding(policy_generation=2))
    assert commit(binding()) == base                             # deterministic


def test_the_tagged_preimage_has_the_version_the_identity_and_the_generation_as_separate_members(tmp_path):
    """Rebuilt independently of ``approval_commitment``: the tag leads, and identity and generation are members of their own."""
    from agent_control_plane.bounded import commitment
    p, r, f, c = setup_flow(tmp_path)
    ctx = r.contexts[PROFILE]
    for b in (binding(selection_epoch=3, policy_generation=5), withdrawn(selection_epoch=4, policy_generation=6)):
        cfg2 = c.model_copy(update={"policy_binding": b})
        identity = {"activation_ref": b.activation_ref, "selection_epoch": b.selection_epoch, "disposition": b.disposition}
        if b.binding_digest is not None:
            identity["binding_digest"] = b.binding_digest
        expected = commitment({
            "commitment_version": "approval-commitment/0.2", "profile": cfg2.model_dump(mode="json"), "runtime_authority": ctx.get("runtime_authority"),
            "purpose_ref": (ctx.get("grant") or {}).get("purpose_ref"), "grant_expires_at": (ctx.get("grant") or {}).get("expires_at"),
            "policy_identity": identity, "policy_generation": b.policy_generation})
        assert approval_commitment(cfg2, ctx) == expected


# ------------------------------------------------------------------------------------------------ withdrawal and revival sequences
def test_narrowing_then_withdrawal_never_revives_the_original_approval(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    old_commitment = approval_commitment(c, r.contexts[PROFILE])
    d0 = decide(f, p)
    assert d0.result == "authorized", d0.reasons                 # step 1: legacy approval, no binding
    # step 2: narrow (binding epoch 1, ceiling 120, composed limit 60, anchored)
    c1 = adopt(r, f, c, binding(age_ceilings={p.action_id: 120}), freshness=FreshnessProfile(max_age_extension_seconds=60, anchor_deadline_to_inputs=True),
               issue=False)
    # the approval minted for the legacy profile is still in the store, bound to the OLD commitment
    for a in r.approvals.values():
        a.runtime_authority_commitment = old_commitment
    d1 = decide(f, p)
    assert d1.result == "hold" and {"approval_policy_generation_missing", "runtime_authority_approval_mismatch"} <= set(d1.reasons)
    # step 4: withdrawal (own activation_ref, generation 2, disposition withdrawn, no digest)
    adopt(r, f, c, withdrawn(), issue=False)
    for a in r.approvals.values():
        a.runtime_authority_commitment = old_commitment
    d2 = decide(f, p)
    assert d2.result == "hold" and {"approval_policy_generation_missing", "runtime_authority_approval_mismatch"} <= set(d2.reasons)
    assert old_commitment != approval_commitment(f.runtime_authority_profile, r.contexts[PROFILE])
    # step 6: a fresh approval minted under the withdrawal binding is authorized
    adopt(r, f, c, withdrawn(), issue=True)
    d3 = decide(f, p)
    assert d3.result == "authorized", d3.reasons
    assert c1.policy_binding.policy_generation == 1


def test_an_approval_for_one_generation_is_refused_at_every_other_generation(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())                                    # G0 approval minted
    assert decide(f, p).result == "authorized"
    g0_spec = dict(r.contexts[PROFILE]["runtime_authority"])
    for nxt in (binding(selection_epoch=2, policy_generation=2, activation_ref=A2), withdrawn(selection_epoch=3, policy_generation=3, activation_ref=A3)):
        cfg2 = c.model_copy(update={"policy_binding": nxt})
        r.contexts[PROFILE]["runtime_authority"] = dict(g0_spec)  # the G0 approval-bound spec
        # bind the approver's commitment over the G0 spec as the approval system would have, under the NEW profile
        bind_approval(r, cfg2)
        f.runtime_authority_profile = cfg2.snapshot()
        d = decide(f, p)
        assert d.result == "hold"
        assert {"approval_policy_generation_mismatch", "approval_policy_activation_mismatch"} <= set(d.reasons), d.reasons
        adopt(r, f, c, nxt)                                       # re-issued under the current generation
        assert decide(f, p).result == "authorized"


def test_forging_the_current_generation_into_an_old_approval_is_refused_by_its_commitment(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    old = approval_commitment(c, r.contexts[PROFILE])
    adopt(r, f, c, binding(), issue=True)
    for a in r.approvals.values():
        a.runtime_authority_commitment = old                      # the old approval: forged members, old commitment
    d = decide(f, p)
    assert d.result == "hold" and d.reasons.count("runtime_authority_approval_mismatch") == 1
    assert "approval_policy_generation_mismatch" not in d.reasons  # the members equal the profile's; the commitment alone refuses


def test_tampered_generation_in_the_approved_spec_is_refused(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["policy_generation"] = 7   # commitment untouched
    d = decide(f, p)
    assert d.result == "hold" and {"approval_policy_generation_mismatch", "runtime_authority_approval_mismatch"} <= set(d.reasons)


def test_cross_profile_activation_substitution_is_refused(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding(activation_ref=A1))                    # approval minted under activation A1
    spec = dict(r.contexts[PROFILE]["runtime_authority"])
    other = c.model_copy(update={"policy_binding": binding(activation_ref=A2)})     # same epoch, digest and generation; other activation
    r.contexts[PROFILE]["runtime_authority"] = spec
    f.runtime_authority_profile = other.snapshot()
    d = decide(f, p)
    assert d.result == "hold" and {"approval_policy_activation_mismatch", "runtime_authority_approval_mismatch"} <= set(d.reasons)
    assert "approval_policy_generation_mismatch" not in d.reasons


def test_a_legacy_approval_is_missing_its_generation_under_a_binding_profile(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding(), issue=False)
    d = decide(f, p)
    assert d.result == "hold" and "approval_policy_generation_missing" in d.reasons


@pytest.mark.parametrize("member", ["approval_commitment_version", "policy_generation", "policy_activation_ref"])
def test_each_stripped_member_is_missing(tmp_path, member):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    del r.contexts[PROFILE]["runtime_authority"][member]
    bind_approval(r, f.runtime_authority_profile)
    assert "approval_policy_generation_missing" in decide(f, p).reasons


def test_unknown_commitment_version_is_refused_even_when_the_commitment_matches(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["approval_commitment_version"] = "approval-commitment/0.9"
    bind_approval(r, f.runtime_authority_profile)                 # the approval system signs over it: commitment equal
    d = decide(f, p)
    assert d.result == "hold" and d.reasons == ["approval_commitment_version_unsupported"]


@pytest.mark.parametrize("version", [1, ["approval-commitment/0.2"], {"v": 1}, True, ""])
def test_a_non_string_or_empty_version_is_unsupported_and_never_raises(tmp_path, version):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["approval_commitment_version"] = version
    bind_approval(r, f.runtime_authority_profile)
    d = decide(f, p)
    assert d.result == "hold" and "approval_commitment_version_unsupported" in d.reasons


@pytest.mark.parametrize("generation", [True, 0, -1, 2147483648, "1", 1.0, []])
def test_a_malformed_carried_generation_is_invalid_not_a_mismatch(tmp_path, generation):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["policy_generation"] = generation
    bind_approval(r, f.runtime_authority_profile)
    d = decide(f, p)
    assert d.result == "hold" and "approval_policy_generation_invalid" in d.reasons
    assert "approval_policy_generation_mismatch" not in d.reasons


@pytest.mark.parametrize("ref", ["", "sha256:" + "A" * 64, "sha256:" + "0" * 63, "x" * 71, ZERO_DIGEST, 5, ["a"]])
def test_a_malformed_carried_activation_ref_is_invalid_not_a_mismatch(tmp_path, ref):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["policy_activation_ref"] = ref
    bind_approval(r, f.runtime_authority_profile)
    d = decide(f, p)
    assert d.result == "hold" and "approval_policy_generation_invalid" in d.reasons
    assert "approval_policy_activation_mismatch" not in d.reasons


def test_generation_members_under_a_profile_without_a_binding_are_unsupported(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    r.contexts[PROFILE]["runtime_authority"].update({"approval_commitment_version": APPROVAL_COMMITMENT_V2, "policy_generation": 1,
                                                     "policy_activation_ref": A1})
    bind_approval(r, c)
    d = decide(f, p)
    assert d.result == "hold" and "runtime_authority_field_unsupported" in d.reasons


def test_activation_sequence_is_reserved_and_refused_everywhere(tmp_path):
    with pytest.raises(ValidationError):
        PolicyBinding(binding_digest=D1, selection_epoch=1, activation_ref=A1, policy_generation=1, disposition="selected", activation_sequence=1)
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["activation_sequence"] = 1
    bind_approval(r, f.runtime_authority_profile)
    d = decide(f, p)
    assert d.result == "hold" and "runtime_authority_field_unsupported" in d.reasons


def test_a_decision_does_not_survive_a_generation_change_before_effect(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    adopt(r, f, c, binding(selection_epoch=2, policy_generation=2, activation_ref=A2))     # the trusted profile moved; approval re-issued
    with pytest.raises(PermissionError):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


def test_the_authorized_decision_applies_and_carries_the_generation_in_its_binding(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding(selection_epoch=3, policy_generation=5))   # epoch and generation differ: the generation is never the epoch
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    attempt, outcome = execute(f, p, d)
    assert attempt.status == "acknowledged" and outcome.state == "applied"
    extension = d.binding.model_dump(mode="json")["runtime_authority"]
    assert (extension["approval_commitment_version"], extension["policy_generation"], extension["policy_activation_ref"]) == (
        APPROVAL_COMMITMENT_V2, 5, A1)


# ------------------------------------------------------------------------------------------------ binding strictness
@pytest.mark.parametrize("override", [
    {"selection_epoch": 0}, {"selection_epoch": -1}, {"selection_epoch": True}, {"selection_epoch": 1.0}, {"selection_epoch": "1"},
    {"selection_epoch": 2147483648},
    {"policy_generation": 0}, {"policy_generation": True}, {"policy_generation": 1.0}, {"policy_generation": "1"},
    {"policy_generation": 2147483648},
    {"activation_ref": ""}, {"activation_ref": "sha256:" + "A" * 64}, {"activation_ref": ZERO_DIGEST}, {"activation_ref": "abc"},
    {"activation_ref": "sha256:" + "a" * 64 + "\n"},
    {"binding_digest": None}, {"binding_digest": ""}, {"binding_digest": ZERO_DIGEST}, {"binding_digest": "sha256:xyz"},
    {"age_ceilings": {"x": 0}}, {"age_ceilings": {"": 5}}, {"age_ceilings": {"x": True}}, {"age_ceilings": {"x": 1.5}},
    {"disposition": "other"}, {"version": "policy-binding/0.2"},
])
def test_binding_members_are_strict(override):
    with pytest.raises((ValidationError, ValueError)):
        binding(**override)


@pytest.mark.parametrize("override", [
    {"binding_digest": D1}, {"binding_digest": None}, {"binding_digest": ""}, {"binding_digest": ZERO_DIGEST},
    {"age_ceilings": {"x": 5}},
])
def test_a_withdrawn_binding_carries_no_digest_and_narrows_nothing(override):
    with pytest.raises((ValidationError, ValueError)):
        withdrawn(**override)
    assert withdrawn().binding_digest is None and "binding_digest" not in withdrawn().model_dump(mode="json")


def test_a_selected_binding_requires_its_digest():
    with pytest.raises((ValidationError, ValueError)):
        PolicyBinding(selection_epoch=1, activation_ref=A1, policy_generation=1, disposition="selected")


@pytest.mark.parametrize("update", [
    {"binding_digest": ZERO_DIGEST}, {"binding_digest": "nope"}, {"selection_epoch": True}, {"policy_generation": 0}, {"activation_ref": "x"},
    {"disposition": "other"}, {"age_ceilings": {"unknown-action": 5}},
])
def test_a_validator_bypassed_binding_is_still_refused_at_every_evaluation(tmp_path, update):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    bad = f.runtime_authority_profile.policy_binding.model_copy(update=update)        # model_copy skips validators
    f.runtime_authority_profile = f.runtime_authority_profile.model_copy(update={"policy_binding": bad})
    d = decide(f, p)
    assert d.result == "hold" and "policy_binding_invalid" in d.reasons


def test_a_malformed_trusted_binding_is_reported_alone_and_never_compared_with_the_approval(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    bad = f.runtime_authority_profile.policy_binding.model_copy(update={"policy_generation": 0, "activation_ref": "x"})
    f.runtime_authority_profile = f.runtime_authority_profile.model_copy(update={"policy_binding": bad})
    d = decide(f, p)
    assert "policy_binding_invalid" in d.reasons
    assert not {"approval_policy_generation_mismatch", "approval_policy_activation_mismatch"} & set(d.reasons)


def test_a_bypassed_withdrawn_binding_that_regained_a_digest_is_refused(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, withdrawn())
    bad = f.runtime_authority_profile.policy_binding.model_copy(update={"binding_digest": D1})
    f.runtime_authority_profile = f.runtime_authority_profile.model_copy(update={"policy_binding": bad})
    assert "policy_binding_invalid" in decide(f, p).reasons


# ------------------------------------------------------------------------------------------------ R6 freshness ceilings
def ceilinged(p, *, ceiling=120, limit=60, anchored=True):
    return dict(b=binding(age_ceilings={p.action_id: ceiling}), fr=FreshnessProfile(max_age_extension_seconds=limit, anchor_deadline_to_inputs=anchored))


def test_a_profile_that_violates_its_ceiling_cannot_be_constructed(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    base = c.model_dump(mode="json")
    good = dict(base, policy_binding=binding(age_ceilings={p.action_id: 120}).model_dump(mode="json"),
                freshness=FreshnessProfile(max_age_extension_seconds=60, anchor_deadline_to_inputs=True).model_dump(mode="json"))
    RuntimeAuthorityProfile.model_validate(good)
    exceeding = dict(good, freshness=FreshnessProfile(max_age_extension_seconds=300, anchor_deadline_to_inputs=True).model_dump(mode="json"))
    with pytest.raises(ValidationError, match="exceeded"):
        RuntimeAuthorityProfile.model_validate(exceeding)
    unanchored = dict(good, freshness=FreshnessProfile(max_age_extension_seconds=60).model_dump(mode="json"))
    with pytest.raises(ValidationError, match="unanchored"):
        RuntimeAuthorityProfile.model_validate(unanchored)
    nofresh = {k: v for k, v in good.items() if k != "freshness"}
    with pytest.raises(ValidationError, match="unanchored"):
        RuntimeAuthorityProfile.model_validate(nofresh)
    unknown = dict(good, policy_binding=binding(age_ceilings={"not-an-action": 120}).model_dump(mode="json"))
    with pytest.raises(ValidationError, match="invalid"):
        RuntimeAuthorityProfile.model_validate(unknown)
    below = dict(good, policy_binding=binding(age_ceilings={p.action_id: 59}).model_dump(mode="json"))   # class base 60 alone exceeds 59
    with pytest.raises(ValidationError, match="exceeded"):
        RuntimeAuthorityProfile.model_validate(below)


@pytest.mark.parametrize("fresh,code", [
    (FreshnessProfile(max_age_extension_seconds=300, anchor_deadline_to_inputs=True), "freshness_ceiling_exceeded"),
    (FreshnessProfile(max_age_extension_seconds=60), "freshness_ceiling_unanchored"),
    (None, "freshness_ceiling_unanchored"),
])
def test_ceiling_violations_are_refused_at_evaluation_even_when_validators_are_bypassed(tmp_path, clock, fresh, code):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding(age_ceilings={p.action_id: 120}), freshness=FreshnessProfile(max_age_extension_seconds=60, anchor_deadline_to_inputs=True))
    bypassed = f.runtime_authority_profile.model_copy(update={"freshness": fresh})
    bind_approval(r, bypassed)
    f.runtime_authority_profile = bypassed
    d = decide(f, p)
    assert d.result == "hold" and code in d.reasons


def test_an_outage_extension_cannot_widen_a_registry_ceiling(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    spec = ceilinged(p)
    adopt(r, f, c, spec["b"], freshness=spec["fr"])
    authority(f, r)
    for beyond in (330, 121):
        with pytest.raises(AgeExtensionRefused) as caught:
            request(f, to_max_age_seconds=beyond)
        assert "age_extension_exceeds_limit" in caught.value.reasons
    request(f, to_max_age_seconds=120)                            # base 60 + limit 60 = the ceiling: allowed
    stale_grant(r, 120)
    assert decide(f, p).result == "authorized"
    stale_grant(r, 121)
    d = decide(f, p)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons


def test_a_delayed_dispatch_cannot_use_a_status_beyond_the_ceiling(tmp_path, clock):
    """Anchored (required for a ceilinged profile): the deadline is observed_at + the extended bound. Control: the same extension
    without a binding and without anchoring dispatches a status that is older than the ceiling at dispatch."""
    p, r, f, c = setup_flow(tmp_path)
    spec = ceilinged(p)
    adopt(r, f, c, spec["b"], freshness=spec["fr"])
    authority(f, r)
    request(f, to_max_age_seconds=120)
    stale_grant(r, 100)                                           # inside the extended bound at the check
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    stall_before_dispatch(f, clock, 30, pin_observation=True)     # status age at dispatch would be 130 > ceiling 120
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


def test_control_without_binding_or_anchor_dispatches_beyond_the_ceiling(tmp_path, clock):
    """Pins today's documented unanchored behaviour (not a guarantee): this is the window the ceilinged profile closes."""
    p, r, f, c = setup_flow(tmp_path)
    cfg2 = c.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=60)})
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    authority(f, r)
    request(f, to_max_age_seconds=120)
    stale_grant(r, 100)
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    stall_before_dispatch(f, clock, 30, pin_observation=True)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged"
    age_at_dispatch = (clock.now - (NOW - timedelta(seconds=100))).total_seconds()
    assert age_at_dispatch > 120, "dispatched a status older than the ceiling the ceilinged profile would have held"


# ------------------------------------------------------------------------------------------------ NEGATIVE CONTROLS (what the local check cannot prevent)
def test_control_older_generation_with_an_identical_binding_revives_the_older_approval(tmp_path, clock):
    """The Control Plane compares equality only and has no durable memory of a newer generation. If a supplier presents the older
    binding again, the older approval is valid again. Preventing this is the enforcing consumer's durable ratchet (EXT-S4), not this
    module. This test proves the LOCAL candidate cannot prevent revival after durable-state regression."""
    p, r, f, c = setup_flow(tmp_path)
    old = binding()
    adopt(r, f, c, old)                                           # approval minted at the older generation
    spec_old = dict(r.contexts[PROFILE]["runtime_authority"])
    newer = c.model_copy(update={"policy_binding": binding(selection_epoch=2, policy_generation=2, activation_ref=A2)})
    f.runtime_authority_profile = newer.snapshot()
    r.contexts[PROFILE]["runtime_authority"] = dict(spec_old)
    bind_approval(r, c.model_copy(update={"policy_binding": old}))
    assert decide(f, p).result == "hold"                          # the newer generation refuses the older approval
    f.runtime_authority_profile = c.model_copy(update={"policy_binding": old}).snapshot()    # supplier regresses to the older binding
    d = decide(f, p)
    assert d.result == "authorized", d.reasons                    # REVIVAL: pinned as a limit, not a guarantee


def test_control_binding_dropped_revives_legacy_approval(tmp_path, clock):
    """Dropping the binding restores the legacy preimage: the pre-narrowing approval authorizes again. An absent binding is the
    legacy path ONLY when trusted consumer state establishes Registry V1 participation was never required or activated; the Control
    Plane cannot establish that and never infers withdrawal or non-participation from absence."""
    p, r, f, c = setup_flow(tmp_path)
    assert decide(f, p).result == "authorized"                    # legacy approval
    adopt(r, f, c, binding(), issue=False)
    for a in r.approvals.values():
        a.runtime_authority_commitment = approval_commitment(c, r.contexts[PROFILE])
    assert decide(f, p).result == "hold"                          # narrowed: legacy approval refused
    f.runtime_authority_profile = c.snapshot()                    # supplier stops emitting the binding
    r.contexts[PROFILE]["runtime_authority"] = {k: v for k, v in r.contexts[PROFILE]["runtime_authority"].items()
                                                if k not in ("approval_commitment_version", "policy_generation", "policy_activation_ref")}
    bind_approval(r, c)
    assert decide(f, p).result == "authorized"                    # REVIVAL: consumer ratchet obligation (EXT-S4)


def test_the_eight_codes_are_the_policy_binding_vocabulary():
    assert len(NEW_CODES) == len(set(NEW_CODES)) == 8


@pytest.mark.parametrize("update", [
    {"policy_generation": object()}, {"selection_epoch": float("nan")}, {"binding_digest": {"x"}}, {"activation_ref": b"bytes"},
    {"age_ceilings": {"x": float("inf")}},
])
def test_a_non_serializable_bypassed_binding_is_a_typed_refusal_not_an_exception(tmp_path, update):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    bad = f.runtime_authority_profile.policy_binding.model_copy(update=update)
    f.runtime_authority_profile = f.runtime_authority_profile.model_copy(update={"policy_binding": bad})
    d = decide(f, p)
    assert d.result == "hold" and "policy_binding_invalid" in d.reasons


def test_a_withdrawn_binding_still_authorizes_a_matching_approval_locally(tmp_path, clock):
    """Pinned, not endorsed: the Control Plane does not stop authority on withdrawal; that is a consumer decision (EXT-S4-0/EXT-S4-2)."""
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, withdrawn())
    assert decide(f, p).result == "authorized"


def test_a_binding_naming_an_undeclared_ceiling_action_is_reported_alone_even_with_a_wrong_generation(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding())
    r.contexts[PROFILE]["runtime_authority"]["policy_generation"] = 9          # does not equal the trusted generation
    bind_approval(r, f.runtime_authority_profile)
    bad = f.runtime_authority_profile.policy_binding.model_copy(update={"age_ceilings": {"undeclared-action": 120}})
    f.runtime_authority_profile = f.runtime_authority_profile.model_copy(update={"policy_binding": bad})
    d = decide(f, p)
    assert "policy_binding_invalid" in d.reasons
    assert "approval_policy_generation_mismatch" not in d.reasons


def test_a_negative_bypassed_extension_limit_cannot_hide_a_ceiling_violation(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    adopt(r, f, c, binding(age_ceilings={p.action_id: 120}), freshness=FreshnessProfile(max_age_extension_seconds=60, anchor_deadline_to_inputs=True))
    # class base 60 and ceiling 30 would be refused; a negative limit must not cancel the base (a negative limit lowers no bound)
    below = f.runtime_authority_profile.policy_binding.model_copy(update={"age_ceilings": {p.action_id: 30}})
    fresh = f.runtime_authority_profile.freshness.model_copy(update={"max_age_extension_seconds": -30})
    bypassed = f.runtime_authority_profile.model_copy(update={"policy_binding": below, "freshness": fresh})
    bind_approval(r, bypassed)
    f.runtime_authority_profile = bypassed
    d = decide(f, p)
    assert d.result == "hold" and "freshness_ceiling_exceeded" in d.reasons


# ------------------------------------------------------------------------------------------------ purpose-status dispatch anchoring (R6)
def _stall_once(f, clock, seconds):
    """Tick the controlled clock exactly once, inside the destination observation between the effect check and the dispatch gate."""
    original, calls, pinned = f.destination.observe, [], clock.now

    def stalled(effect_id):
        calls.append(1)
        if len(calls) == 1:
            clock.tick(seconds)
        return original(effect_id).model_copy(update={"observed_at": pinned.isoformat()})
    f.destination.observe = stalled


def _purpose_flow(tmp_path, *, bound_binding):
    p, r, f, c = setup_flow(tmp_path, purpose=True)
    r.purpose.observed_at = (NOW - timedelta(seconds=59)).isoformat()          # satisfies the 60 s bound at evaluation
    fresh = FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)
    if bound_binding:
        adopt(r, f, c, binding(age_ceilings={p.action_id: 60}), freshness=fresh)
    else:                                                                       # legacy: same freshness profile, no policy binding
        cfg2 = c.model_copy(update={"freshness": fresh})
        bind_approval(r, cfg2)
        f.runtime_authority_profile = cfg2.snapshot()
    return p, r, f


def test_purpose_status_that_met_the_ceiling_at_evaluation_is_refused_after_a_two_second_dispatch_delay(tmp_path, clock):
    """Effective ceiling 60 s, purpose-status age 59 s at evaluation, 2 s delay before dispatch: the status would be 61 s old."""
    p, r, f = _purpose_flow(tmp_path, bound_binding=True)
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, 2)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}, "no effect may proceed"


@pytest.mark.parametrize("delay,dispatches", [(0, True), (1, True), (2, False)])
def test_purpose_status_deadline_is_exactly_observed_at_plus_the_bound(tmp_path, clock, delay, dispatches):
    p, r, f = _purpose_flow(tmp_path, bound_binding=True)
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, delay)
    if dispatches:
        attempt, _ = execute(f, p, d)
        assert attempt.status == "acknowledged"
    else:
        with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
            execute(f, p, d)
        assert f.destination.snapshot()["effects"] == {}


def test_legacy_profile_without_a_policy_binding_now_anchors_the_purpose_status_d07_successor(tmp_path, clock):
    """D-07 SUCCESSOR of ``test_legacy_profile_without_a_policy_binding_keeps_its_behaviour_for_the_purpose_status``.

    Predecessor (in git history, pinned until CP #94 head 061a986): "Pinned legacy behaviour (not a guarantee): without a binding the purpose
    age is judged at evaluation and is not anchored" -- the same fixture (freshness anchor flag True, no ``policy_binding``, 60 s bound, purpose
    age 59 s at evaluation, 2 s dispatch stall = 61 s) was DISPATCHED (``attempt.status == "acknowledged"``).
    What changed and why: the Architect authorized D-07 Option A (2026-10-29; ``family-migration/final-three/02-architect-authorization-and-
    contract-freeze-2026-10-29.md`` section 6) -- the purpose-observation anchoring in ``runtime_authority.py`` no longer depends on a
    ``PolicyBinding`` being present, because that dependence left a window of up to 2x the (Registry-narrowed) ceiling. The same fixture is now
    REFUSED by the existing ``check_expired_before_dispatch`` (strictly more restrictive; no new reason code, commitment or schema change).
    The legacy behaviour is withdrawn only for profiles that set ``anchor_deadline_to_inputs=True``; profiles without the flag are unchanged
    (see tests/test_freshness_purpose_anchor_successor.py). Original result retained: docs/evidence/d07/postchange-01-*.txt."""
    p, r, f = _purpose_flow(tmp_path, bound_binding=False)
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, 2)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


def test_an_accepted_cached_purpose_snapshot_joins_the_dispatch_deadline_with_its_recorded_bound(tmp_path, clock):
    from tests.test_reversibility import cls, flow as rev_flow, outage
    p, r, f, c = rev_flow(tmp_path, cls("reversible_until", max_status_age_seconds=60))
    r.cached.observed_at = (NOW - timedelta(seconds=59)).isoformat()
    outage(r)                                                                   # the purpose store is down: the cached snapshot stands in
    adopt(r, f, c, binding(age_ceilings={p.action_id: 60}), freshness=FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True))
    d = decide(f, p)
    assert d.result == "authorized", d.reasons
    assert any(x.input_type == "purpose" and x.read_state == "cached_positive" for x in d.resolution_inputs)
    _stall_once(f, clock, 2)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}
