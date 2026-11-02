"""RW-01-F4-PoC (Register #259, parent #254) Control Plane carriage of the exact Registry F4 selection bytes. BUILDER_TESTED developer evidence. NOT independently qualified.

CLAIM SCOPE (do not read more into these tests): they show that the Control Plane CARRIES the exact verified bytes on authorized decisions, outside the binding, without changing
any authorization result; and that those bytes can be re-verified by Registry's own `verify_selection_v2` with INDEPENDENT trust inputs and real Ed25519. They do NOT show that the
Control Plane decision is authenticated (a Registry signature covers the selection statement, not any Control Plane decision member): CARRIAGE IS NOT AUTHENTICATION. Claim A only.
Synthetic Ed25519 keys (mechanism tests only); no production trust root, no real key custody.

Same harness as `tests/test_f4_age_governance.py`: a Registry checkout at the exact `PIN` in `OCS_REGISTRY_PIN_DIR` and PyNaCl are needed. With `OCS_REQUIRE_REGISTRY_PIN=1` a missing pin or
missing PyNaCl is a FAILURE; without it the module is reported NOT RUN, never passed. Sprint numbering N01..N28 is used verbatim where a test supports a row.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

PIN = "6f600ab1150f00ef3d96834159b1807e866a78b6"
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
    import nacl.bindings  # noqa: F401
    import nacl as _nacl
except ImportError:
    _unavailable("PyNaCl (Registry requirements-ed25519.lock.txt) is not installed")

from registry_adapters import ed25519_verifier as ev  # noqa: E402
from registry_successor import decision as reg_decision  # noqa: E402
from registry_successor import v2_age_bounds as f4  # noqa: E402
from registry_successor import v2_policy_identity as v2i  # noqa: E402
from registry_successor import verify as reg_verify  # noqa: E402
from registry_successor import v2_selection as reg_sel  # noqa: E402

from agent_control_plane import selection_evidence as se  # noqa: E402
from agent_control_plane import registry_governed_lifecycle as life  # noqa: E402
from agent_control_plane.bounded import RuntimeDecision  # noqa: E402
from agent_control_plane.registry_f4_age_governance import RegistrySelectionRefused, SelectionMaterial  # noqa: E402
from tests import rw01_f4_poc_support as sup  # noqa: E402
from tests.test_bounded_authorization import NOW, tenant_proposal  # noqa: E402
from tests.test_f4_age_governance import (  # noqa: E402,F401  (the F4 harness is reused, not copied)
    CTX, OPERATION, SCOPE, Source, _fixed_synthetic_clock, aged, build, c, file_state, mat, refused, trust_for, record, material, r, s, _sign, PK, REVOKED, gov,
)

HERE = Path(__file__).resolve().parent
GOLDEN_WIRE = HERE / "fixtures" / "f4_selection_evidence_wire_0_1.json"
GOLDEN_LEGACY = HERE / "fixtures" / "rw01_f4_poc_legacy_run_b19c47dd.json"
VERIFIED_AT = NOW.astimezone(timezone.utc).isoformat()


def decide_authorized(tmp_path, *, carry, source=None, **kw):
    p = tenant_proposal()
    src = source or Source(mat(60, 60))
    flow = build(tmp_path, src, **({"carry_selection_evidence": carry} if carry is not None else {}), **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, src, flow, d


def stored_decisions(tmp_path):
    return json.loads((tmp_path / "run.json").read_text())["decisions"]


# =============================================================================================================== default off (N25)
@pytest.mark.parametrize("flag", [None, False])
def test_n25_default_off_decisions_carry_nothing_and_the_member_is_absent_from_every_dump(tmp_path, flag):
    p, src, flow, d = decide_authorized(tmp_path, carry=flag)
    assert d.selection_evidence is None and "selection_evidence" not in d.model_dump(mode="json") and "selection_evidence" not in d.model_dump()
    assert all("selection_evidence" not in x for x in stored_decisions(tmp_path)) and b"selection_evidence" not in (tmp_path / "run.json").read_bytes()
    assert flow.registry_f4_policy_identity and "carry" not in json.dumps(flow.registry_f4_policy_identity)  # the flag is not part of the exposed identity


def test_n25_legacy_decision_is_byte_identical_to_the_decision_of_b19c47dd_golden_comparison(tmp_path, monkeypatch):
    """GOLDEN: `fixtures/rw01_f4_poc_legacy_run_b19c47dd.json` was produced by `rw01_f4_poc_support.legacy_run_document` on the UNTOUCHED b19c47dd tree. The edited tree with the
    flag off (default) must reproduce both stores (an authorized+executed flow and a hold) byte for byte."""
    golden = json.loads(GOLDEN_LEGACY.read_text())
    got = sup.legacy_run_document(tmp_path, monkeypatch, build=build, mat=mat, Source=Source, tenant_proposal=tenant_proposal, NOW=NOW, aged=aged)
    assert got == golden


def test_n25_flag_on_changes_nothing_but_the_added_member_golden_comparison(tmp_path, monkeypatch):
    golden = json.loads(GOLDEN_LEGACY.read_text())
    got = sup.legacy_run_document(tmp_path, monkeypatch, build=build, mat=mat, Source=Source, tenant_proposal=tenant_proposal, NOW=NOW, aged=aged,
                                  extra_kwargs={"carry_selection_evidence": True})
    main, ref = json.loads(got["main"]), json.loads(golden["main"])
    carried = [d.pop("selection_evidence") for d in main["decisions"] if d["result"] == "authorized"]
    assert len(carried) == 1 and carried[0]["version"] == "selection-evidence/0.1"
    assert main == ref  # after removing the one added member the store is the legacy store, member for member
    assert got["hold"] == golden["hold"]  # a hold flow with carriage on is byte-identical to legacy (nothing carried)


def test_legacy_decisions_without_the_member_load_with_none_and_redump_without_it():
    legacy = json.loads(GOLDEN_LEGACY.read_text())["main"]
    decisions = json.loads(legacy)["decisions"]
    assert decisions
    for dec in decisions:
        loaded = RuntimeDecision.model_validate(dec)
        assert loaded.selection_evidence is None and "selection_evidence" not in loaded.model_dump(mode="json")


# =============================================================================================================== carried bytes
def test_carried_texts_are_the_exact_verified_bytes_and_nothing_else_is_read(tmp_path):
    material_ = mat(60, 60)
    src = Source(material_)
    p, src, flow, d = decide_authorized(tmp_path, carry=True, source=src)
    ev_ = d.selection_evidence
    assert ev_ is not None and type(ev_) is se.SelectionEvidence
    assert ev_.record_text == material_.record_text and ev_.selection_text == material_.selection_text  # exact str equality with the material that was verified
    assert ev_.record_text.encode("utf-8") == material_.record_text.encode("utf-8") and ev_.selection_text.encode("utf-8") == material_.selection_text.encode("utf-8")
    assert (ev_.version, ev_.contract_version, ev_.family, ev_.operation_id) == ("selection-evidence/0.1", "r08-v2", f4.FAMILY_F4, OPERATION)
    assert ev_.verified_at == VERIFIED_AT
    assert src.calls == 2  # construction + decision only: carriage added NO source read (no TOCTOU window)


def test_carried_bytes_survive_the_store_round_trip_byte_exact_and_equal_the_decision(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    persisted = flow.records.decision(d.decision_id)
    assert persisted == d and persisted.selection_evidence == d.selection_evidence
    raw = stored_decisions(tmp_path)[0]["selection_evidence"]
    assert raw["record_text"] == d.selection_evidence.record_text and raw["selection_text"] == d.selection_evidence.selection_text


@pytest.mark.parametrize("record_text", ["café 中文 \U0001F600 \r\n\t\"\\ end"])
def test_carried_text_with_non_ascii_and_escapes_round_trips_byte_exact(tmp_path, record_text):
    ev_ = se.for_f4(record_text=record_text, selection_text="x y z", operation_id=OPERATION, verified_at=NOW)
    d = RuntimeDecision.model_validate(json.loads(json.dumps(
        {"decision_id": "d", "effect_id": "e", "result": "authorized", "reasons": [], "decided_at": VERIFIED_AT, "selection_evidence": ev_.model_dump(mode="json")})))
    assert d.selection_evidence == ev_ and d.selection_evidence.record_text.encode("utf-8") == record_text.encode("utf-8")
    from agent_control_plane.strict_json import dumps_bytes, strict_loads
    assert strict_loads(dumps_bytes(d.model_dump(mode="json"), indent=2, ensure_ascii=True))["selection_evidence"]["record_text"] == record_text


# =============================================================================================================== only authorized decisions
def test_only_authorized_decisions_carry_evidence_holds_do_not(tmp_path):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(10, 10)), resolver=aged(p, 30, "status"), carry_selection_evidence=True)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "grant_status_stale_or_future" in d.reasons
    assert d.selection_evidence is None and "selection_evidence" not in stored_decisions(tmp_path)[0]


# =============================================================================================================== authorization unchanged
def test_binding_ecb_digest_effect_identity_and_authorization_result_are_identical_with_carriage_on_and_off(tmp_path):
    p = tenant_proposal()
    _, _, off_flow, off = decide_authorized(tmp_path / "off", carry=False) if (tmp_path / "off").mkdir() is None else None
    _, _, on_flow, on = decide_authorized(tmp_path / "on", carry=True) if (tmp_path / "on").mkdir() is None else None
    assert (off.result, off.reasons, off.effect_id) == (on.result, on.reasons, on.effect_id)
    assert off.binding.model_dump(mode="json") == on.binding.model_dump(mode="json")  # the whole binding, incl. runtime_authority.effective_configuration
    ecb_off = off.binding.runtime_authority["effective_configuration"]
    ecb_on = on.binding.runtime_authority["effective_configuration"]
    assert ecb_off == ecb_on and ecb_on["digest"].startswith("sha256:")
    assert "carry" not in json.dumps(ecb_on)  # the flag is NOT a member of effective_configuration
    assert "selection_evidence" not in json.dumps(on.binding.model_dump(mode="json"))  # OUTSIDE the binding
    a_off, o_off = off_flow.execute(p, off, adapter_id=p.adapter_id, now=NOW)
    a_on, o_on = on_flow.execute(p, on, adapter_id=p.adapter_id, now=NOW)
    assert (a_off.status, o_off.state) == (a_on.status, o_on.state) == ("acknowledged", "applied")
    assert off_flow.registry_f4_policy_identity == on_flow.registry_f4_policy_identity


def test_equal_replacement_selection_semantics_are_preserved_and_the_carried_bytes_are_the_replacements_l05(tmp_path):
    p = tenant_proposal()
    first = mat(10, 10)
    src = Source(first)
    flow = build(tmp_path, src, carry_selection_evidence=True)
    replacement = mat(10, 10, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    assert replacement.selection_text != first.selection_text
    src.mat = replacement
    d = flow.decide(p, now=NOW)
    assert d.result in ("authorized", "hold")  # test_l05 semantics unchanged: same effective policy identity proceeds
    assert d.result == "authorized" and d.selection_evidence.selection_text == replacement.selection_text != first.selection_text  # evidence = the material that governed THIS decision
    # and a DIFFERENT policy is still refused exactly as without carriage
    src.mat = mat(5, 5, stmt_over={"selection_id": "sel-test-3", "epoch": 3})
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", boundary="decision")


def test_execute_requires_persisted_equals_decision_and_a_tampered_stored_evidence_refuses(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    persisted = flow.records.decision(d.decision_id)
    assert persisted == d  # execute's immutability gate passes
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and len(flow.destination.snapshot()["effects"]) == 1
    # tamper with the stored evidence in a second store: execute must refuse and the effect must not happen
    t2 = tmp_path / "t2"
    t2.mkdir()
    p2, src2, flow2, d2 = decide_authorized(t2, carry=True)
    doc = json.loads((t2 / "run.json").read_text())
    doc["decisions"][0]["selection_evidence"]["selection_text"] += " "
    (t2 / "run.json").write_text(json.dumps(doc, indent=2))
    with pytest.raises(PermissionError, match="decision is not the immutable persisted decision"):
        flow2.execute(p2, d2, adapter_id=p2.adapter_id, now=NOW)
    assert flow2.destination.snapshot()["effects"] == {}
    assert json.loads((t2 / "run.json").read_text())["attempts"] == []


def test_commit_gate_cannot_substitute_carried_bytes(tmp_path):
    """Source calls: 1 construction, 2 decision, 3 execute entry, 4 commit gate. From call 3 the source serves an equal-value replacement with DIFFERENT bytes."""
    p = tenant_proposal()
    first = mat(60, 60)
    src = Source(first)
    flow = build(tmp_path, src, carry_selection_evidence=True)
    d = flow.decide(p, now=NOW)
    replacement = mat(60, 60, stmt_over={"selection_id": "sel-test-2", "epoch": 2})
    src.after = (3, replacement)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and src.calls == 4
    after = flow.records.decision(d.decision_id)
    assert after.selection_evidence.selection_text == first.selection_text != replacement.selection_text  # the persisted decision still carries the DECISION-time bytes
    assert after == d


def test_a_revoked_selection_at_the_commit_gate_is_refused_and_the_carried_evidence_is_untouched(tmp_path):
    p = tenant_proposal()
    src = Source(mat(60, 60))
    flow = build(tmp_path, src, carry_selection_evidence=True)
    d = flow.decide(p, now=NOW)
    before = json.dumps(stored_decisions(tmp_path), sort_keys=True)
    src.after = (4, REVOKED(60, 60))
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert src.calls == 4 and attempt.status == "failed" and attempt.error == gov.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.f4_last_commit_refusal.registry_code == "selection_revoked"
    assert json.dumps(stored_decisions(tmp_path), sort_keys=True) == before  # the stored decision (and its carried bytes) is untouched
    assert flow.records.decision(d.decision_id).selection_evidence == d.selection_evidence


# =============================================================================================================== independent re-verification (mechanism check, claim A)
def _independent_verify(evidence, *, trust=None, now=NOW):
    """What an ENFORCING CONSUMER does with the carried bytes: its OWN trust snapshot, expected context, time and verifier; nothing is taken from the decision except the two texts."""
    sel = reg_sel.parse_selection_envelope_v2(evidence["selection_text"] if isinstance(evidence, dict) else evidence.selection_text)
    rec = reg_decision.validate_record_text_v2(evidence["record_text"] if isinstance(evidence, dict) else evidence.record_text)
    report = reg_verify.verify_selection_v2(sel, CTX, trust or trust_for(), ev.Ed25519Verifier(), now, rec, None, min_trust_snapshot_version=1)
    return sel, rec, report


def test_independent_registry_reverification_of_the_persisted_carried_bytes_passes_with_real_ed25519(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    carried = stored_decisions(tmp_path)[0]["selection_evidence"]  # from the PERSISTED document, not from memory
    sel, rec, report = _independent_verify(carried)
    assert sel.ok and rec.ok
    assert report.ok is True and report.code is None and report.authenticated is True and report.operationally_authorized is False
    assert set(report.layers) == set(reg_verify.LAYERS_V2) and all(report.layers[k] == "pass" for k in reg_verify.LAYERS_V2) and len(reg_verify.LAYERS_V2) == 11
    assert report.bound_record_digest == rec.record_digest
    # and the full decision path on the carried bytes reproduces exactly the F4 values / digest the Control Plane bound
    decision = reg_decision.verify_and_decide_v2("required", {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}, carried["record_text"], carried["selection_text"],
                                                 CTX, trust_for(), ev.Ed25519Verifier(), NOW)
    members = d.binding.runtime_authority["effective_configuration"]["members"]
    row = [r_ for r_ in members["families"] if r_["slot"] == "f4_ages"][0]
    assert decision.kind == "applied" and dict(decision.effective) == members["f4_scalars"]
    assert v2i.effective_policy_digest(f4.FAMILY_F4, dict(decision.effective)) == row["effective_policy_digest"]


def _replace_selection(good, mutate):
    obj = json.loads(good.selection_text)
    mutate(obj)
    return good.model_copy(update={"selection_text": json.dumps(obj)})


def test_tampered_carried_selection_signature_fails_the_independent_verification_with_signature_invalid(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)

    def flip(obj):
        sig = obj["signatures"][0]["signature"]
        obj["signatures"][0]["signature"] = sig[:10] + ("A" if sig[10] != "A" else "B") + sig[11:]
    sel, rec, report = _independent_verify(_replace_selection(d.selection_evidence, flip))
    assert report.ok is False and report.code == "signature_invalid" and report.authenticated is False
    assert report.layers["authenticity"] == "refuse" and report.layers["disposition"] == "not_evaluated"


def test_tampered_carried_statement_fails_the_independent_verification_with_and_without_a_recomputed_digest(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)

    def bump(obj):
        obj["statement"]["epoch"] += 1
    sel, rec, report = _independent_verify(_replace_selection(d.selection_evidence, bump))
    assert report.ok is False and report.code == "digest_mismatch" and report.authenticated is False and report.layers["structural"] == "refuse"

    def bump_and_redigest(obj):
        obj["statement"]["epoch"] += 1
        obj["statement_digest"] = c.digest(obj["statement"])
    sel, rec, report = _independent_verify(_replace_selection(d.selection_evidence, bump_and_redigest))
    assert report.ok is False and report.code == "signature_invalid" and report.authenticated is False and report.layers["authenticity"] == "refuse"


def test_tampered_carried_record_text_fails_the_independent_verification_at_record_binding(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    rec_obj = json.loads(d.selection_evidence.record_text)
    rec_obj["payload"]["status_max_age_seconds"] += 1
    forged = d.selection_evidence.model_copy(update={"record_text": json.dumps(rec_obj)})
    sel, rec, report = _independent_verify(forged)
    assert report.ok is False and report.code == "composition_record_invalid" and report.layers["record_binding"] == "refuse" and report.layers["disposition"] == "not_evaluated"


def test_independent_verification_with_a_foreign_trust_snapshot_fails_so_carriage_confers_no_trust(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    from registry_successor import verify as v
    other_pk = bytes(range(32))  # not the signer
    foreign = v.TrustSnapshot("snap-foreign", 1, "2026-10-07T00:00:00Z", (v.IssuerEntry("some-other-key", "issuer-x", "ed25519", other_pk, ()),))
    sel, rec, report = _independent_verify(d.selection_evidence, trust=foreign)
    assert report.ok is False and report.authenticated is False and report.code is not None and report.layers["authenticity"] != "pass"


# =============================================================================================================== N27: nothing authenticated is carried
def test_n27_no_trust_verdict_or_authenticated_field_exists_is_carried_or_persisted(tmp_path):
    assert set(se.SelectionEvidence.model_fields) == {"version", "contract_version", "family", "operation_id", "verified_at", "record_text", "selection_text"}
    banned = {"trust", "trust_snapshot", "verdict", "authenticated", "ok", "issuer", "issuer_id", "signature", "key_id", "report", "layers", "admitted", "registry_authenticated"}
    assert not banned & set(se.SelectionEvidence.model_fields) and not banned & set(RuntimeDecision.model_fields)
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    raw_text = (tmp_path / "run.json").read_text()
    assert "snap-test-1" not in raw_text  # the trust snapshot id never reaches the store
    evidence_dict = stored_decisions(tmp_path)[0]["selection_evidence"]
    assert not banned & set(evidence_dict)
    assert se.SelectionEvidence.model_config["extra"] == "forbid" and se.SelectionEvidence.model_config["frozen"] is True


@pytest.mark.parametrize("extra", [{"authenticated": True}, {"trust": {"snapshot_id": "x"}}, {"verdict": {"ok": True}}, {"issuer_id": "issuer-test-1"}, {"ok": True}])
def test_n27_extra_members_are_refused_at_construction_and_at_load(tmp_path, extra):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    good = d.selection_evidence.model_dump(mode="json")
    with pytest.raises(se.SelectionEvidenceRefused) as e:
        se.SelectionEvidence(**good, **extra)
    assert e.value.code == se.CODE_MALFORMED
    with pytest.raises(ValidationError):
        RuntimeDecision.model_validate(dict(d.model_dump(mode="json"), selection_evidence=dict(good, **extra)))
    with pytest.raises(ValidationError):
        se.SelectionEvidence.model_validate(dict(good, **extra))
    with pytest.raises(ValidationError):  # frozen
        d.selection_evidence.record_text = "x"


@pytest.mark.parametrize("field,value", [("version", "selection-evidence/0.2"), ("contract_version", "r08-v1"), ("family", "f5-class-age"), ("operation_id", ""),
                                          ("verified_at", "2026-10-05T19:00:00"), ("verified_at", "not a time"), ("verified_at", "2026-10-05T19:00:00+02:00"),
                                          ("record_text", b"bytes"), ("selection_text", 5), ("selection_text", None)])
def test_n11_malformed_evidence_is_a_typed_refusal(field, value):
    base = dict(contract_version="r08-v2", family=f4.FAMILY_F4, operation_id=OPERATION, verified_at=VERIFIED_AT, record_text="{}", selection_text="{}")
    base[field] = value
    with pytest.raises(se.SelectionEvidenceRefused) as e:
        se.SelectionEvidence(**base)
    assert e.value.code == se.CODE_MALFORMED and str(e.value) == se.CODE_MALFORMED  # no input echoed


# =============================================================================================================== N11 support: size cap + unencodable
def test_n11_size_cap_is_65536_utf8_bytes_per_text():
    kw = dict(operation_id=OPERATION, verified_at=NOW)
    assert se.MAX_TEXT_BYTES == 65536
    ok = se.for_f4(record_text="a" * 65536, selection_text="b" * 65536, **kw)
    assert len(ok.record_text.encode()) == len(ok.selection_text.encode()) == 65536
    for big in ("a" * 65537, "é" * 32769, "\U0001F600" * 16385):  # ASCII, 2-byte and 4-byte code points: the cap counts UTF-8 BYTES
        assert len(big.encode()) > 65536
        with pytest.raises(se.SelectionEvidenceRefused) as e:
            se.for_f4(record_text=big, selection_text="{}", **kw)
        assert e.value.code == se.CODE_TOO_LARGE
        with pytest.raises(se.SelectionEvidenceRefused) as e:
            se.for_f4(record_text="{}", selection_text=big, **kw)
        assert e.value.code == se.CODE_TOO_LARGE
    assert len(se.for_f4(record_text="é" * 32768, selection_text="{}", **kw).record_text.encode()) == 65536  # exactly at the cap in 2-byte code points


@pytest.mark.parametrize("bad", ["lone \ud800 surrogate", "\udfff", "ok then \udc80"])
def test_n11_unencodable_text_is_a_typed_refusal_never_an_uncaught_exception(bad):
    for field in ("record_text", "selection_text"):
        kw = dict(record_text="{}", selection_text="{}", operation_id=OPERATION, verified_at=NOW)
        kw[field] = bad
        with pytest.raises(se.SelectionEvidenceRefused) as e:
            se.for_f4(**kw)
        assert e.value.code == se.CODE_MALFORMED
    with pytest.raises(se.SelectionEvidenceRefused) as e:  # also through the model constructor
        se.SelectionEvidence(contract_version="r08-v2", family=f4.FAMILY_F4, operation_id=OPERATION, verified_at=VERIFIED_AT, record_text=bad, selection_text="{}")
    assert e.value.code == se.CODE_MALFORMED


def test_for_f4_refuses_a_naive_or_non_datetime_verification_time():
    for bad in (datetime(2026, 10, 5, 19, 0), "2026-10-05T19:00:00+00:00", None):
        with pytest.raises(se.SelectionEvidenceRefused) as e:
            se.for_f4(record_text="{}", selection_text="{}", operation_id=OPERATION, verified_at=bad)
        assert e.value.code == se.CODE_MALFORMED


def test_unrepresentable_material_at_the_decision_boundary_refuses_before_any_write(tmp_path, monkeypatch):
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(60, 60)), carry_selection_evidence=True)
    monkeypatch.setattr(se, "MAX_TEXT_BYTES", 10)  # the real cap cannot be exceeded by text Registry accepted; shrink it to exercise the in-workflow refusal
    before = file_state(tmp_path, flow)
    with pytest.raises(RegistrySelectionRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_evidence_unrepresentable", boundary="decision")
    assert file_state(tmp_path, flow) == before  # no state change at all
    assert not (tmp_path / "run.json").exists() or json.loads((tmp_path / "run.json").read_text()).get("decisions", []) == []
    assert str(e.value) == "registry_f4_selection_refused:decision:selection_evidence_unrepresentable"  # the code only: no text echoed


# =============================================================================================================== opt-in flag validation
@pytest.mark.parametrize("bad", [1, 0, "yes", "True", None, 1.0, [], {}, object()])
def test_flag_must_be_an_exact_bool(tmp_path, bad):
    with pytest.raises(RegistrySelectionRefused) as e:
        build(tmp_path, Source(mat(60, 60)), carry_selection_evidence=bad)
    refused(e, "selection_evidence_flag_invalid", boundary="construction")
    assert json.loads((tmp_path / "run.json").read_text())["decisions"] == [] and json.loads((tmp_path / "run.json").read_text())["attempts"] == []  # the (empty) store the caller supplied is untouched


@pytest.mark.parametrize("flag", [True, False])
def test_flag_exact_bool_is_accepted_and_is_not_authority(tmp_path, flag):
    flow = build(tmp_path, Source(mat(60, 60)), carry_selection_evidence=flag)
    assert flow._gl_carry is flag
    ident = flow.registry_f4_policy_identity
    assert "carry_selection_evidence" not in json.dumps(ident)


def test_other_governed_workflows_refuse_the_flag_f4_only_scope():
    from agent_control_plane import registry_f5_class_age_governance as f5age, registry_f5_class_unreadable_governance as f5unr, registry_governed_policy as pol
    from agent_control_plane.registry_f4_age_governance import GovernedAgeWorkflow
    for cls in (f5age.GovernedClassAgeWorkflow, f5unr.GovernedClassUnreadableWorkflow, pol.GovernedPolicyWorkflow):
        assert not issubclass(cls, GovernedAgeWorkflow)
        bare = object.__new__(cls)
        assert bare._gl_carriage_supported() is False and bare._gl_carry is False
        assert bare._gl_selection_evidence(object(), NOW, "decision") is None  # never carries, whatever the flag
    assert object.__new__(GovernedAgeWorkflow)._gl_carriage_supported() is True
    # and the constructor path itself: a non-F4 governed workflow refuses the flag BEFORE the base constructor runs (typed, boundary "construction")
    bare = object.__new__(f5age.GovernedClassAgeWorkflow)
    with pytest.raises(PermissionError) as e:
        life.GovernedLifecycle.__init__(bare, carry_selection_evidence=True)
    refused(e, "selection_evidence_unsupported", boundary="construction")
    with pytest.raises(PermissionError) as e:
        life.GovernedLifecycle.__init__(bare, carry_selection_evidence=1)
    refused(e, "selection_evidence_flag_invalid", boundary="construction")


# =============================================================================================================== wire-shape golden fixture
def _wire_shape(tmp_path):
    p, src, flow, d = decide_authorized(tmp_path, carry=True)
    return json.dumps(d.selection_evidence.model_dump(mode="json"), indent=2, ensure_ascii=True) + "\n"


def test_wire_shape_golden_fixture_is_the_exact_json_of_a_carried_selection_evidence_object(tmp_path):
    """`fixtures/f4_selection_evidence_wire_0_1.json` is the exact JSON object a Replay verifier receives for `decision.selection_evidence` (key order = model order). Synthetic keys.
    Regenerate only deliberately: RW01_WRITE_GOLDEN=1 (and then report the new sha256)."""
    got = _wire_shape(tmp_path)
    if os.environ.get("RW01_WRITE_GOLDEN") == "1":
        GOLDEN_WIRE.write_text(got)
    assert GOLDEN_WIRE.read_text() == got
    obj = json.loads(got)
    assert list(obj) == ["version", "contract_version", "family", "operation_id", "verified_at", "record_text", "selection_text"]
    assert se.SelectionEvidence.model_validate(obj).model_dump(mode="json") == obj
    sel, rec, report = _independent_verify(obj)  # the golden bytes themselves verify independently (real Ed25519, synthetic key, trust supplied by the verifier)
    assert report.ok is True and report.authenticated is True and all(v == "pass" for v in report.layers.values())


def test_wire_shape_fixture_contains_no_trust_verdict_or_authenticated_member():
    obj = json.loads(GOLDEN_WIRE.read_text())
    assert not {"trust", "trust_snapshot", "verdict", "authenticated", "ok", "issuer_id", "key_id"} & set(obj)


# =============================================================================================================== mutation-style guard
def test_mutation_a_lifecycle_that_carried_other_bytes_than_it_verified_would_be_caught(tmp_path, monkeypatch):
    """Documents the guard: if `_gl_selection_evidence` built from a DIFFERENT material than the one `_gl_reverify` verified, the exact-bytes assertion fails."""
    p = tenant_proposal()
    material_ = mat(60, 60)
    other = mat(60, 60, stmt_over={"selection_id": "sel-test-9", "epoch": 9})
    flow = build(tmp_path, Source(material_), carry_selection_evidence=True)
    monkeypatch.setattr(life.GovernedLifecycle, "_gl_reverify", lambda self, boundary, now: other)
    d = flow.decide(p, now=NOW)
    assert d.selection_evidence.selection_text != material_.selection_text  # the mutation is visible to the exact-bytes comparison used above
