"""V02 / EXT-S4-4 test support: deterministic claim fixtures and an INDEPENDENT reference for the canonical policy-binding digest.

Nothing here imports the V02 implementation module, so this file (and the frozen legacy vectors) can be exercised on the unmodified base.
Synthetic fixtures only. Builder-authored; not independent qualification.

Regenerate the frozen legacy vectors ONLY on a base whose legacy claim behavior is the accepted reference:
    python -m tests.v02_support > tests/fixtures/v02_legacy_claim_vectors.json
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import tempfile
import uuid
from pathlib import Path
from unittest import mock

from agent_control_plane.bounded import (
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    LocalRefundDestination,
    ObservationPolicy,
    _canonical_bytes,
    commitment,
)
from agent_control_plane.local_authority_effect import materialize_local_execution_claim
from agent_control_plane.policy_binding import APPROVAL_COMMITMENT_V2, PolicyBinding
from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile
from tests import test_local_authority_effect_profile as legacy_mod
from tests.test_bounded_authorization import INSTITUTION, NOW as TENANT_NOW, PROFILE, TENANT, manifest, tenant_proposal, tenant_resolver_for, workflow
from tests.test_runtime_authority import MEMBERS, PUBLIC, bind_approval, sign_evidence

LEGACY_NOW = legacy_mod.NOW
DOMAIN = "customer-refunds"
CONSUMER = "runtime-emulator"
OPERATION = "op-transfer"
FAMILY = "f1ab-local-execution-allowlist"
DIGEST_PREFIX = b"ocs-reg/r08-v2/policy-binding\n"
VECTORS = Path(__file__).resolve().parent / "fixtures" / "v02_legacy_claim_vectors.json"


def sha(char: str) -> str:
    return "sha256:" + char * 64


def reference_binding_digest(binding: dict) -> str:
    """Independent reference (ASCII canonical bytes via the existing Control Plane serializer, published domain prefix)."""
    return "sha256:" + hashlib.sha256(DIGEST_PREFIX + _canonical_bytes(binding)).hexdigest()


def canonical_binding(**over) -> dict:
    """A complete, valid ocs-policy-binding/1 object consistent with `tenant_flow`'s claim (tenant, institution, authority domain)."""
    base = {
        "binding_profile": "ocs-policy-binding/1",
        "record_id": "rec-example-f1ab", "record_version": 2, "record_digest": sha("a"),
        "selection_id": "sel-example-f1ab", "selection_epoch": 3, "selection_digest": sha("b"),
        "family": FAMILY, "consumer_id": CONSUMER,
        "scope": {"tenant": TENANT, "institution": INSTITUTION, "authority_domain": DOMAIN},
        "operation": OPERATION,
        "effective_policy_digest": sha("d"),
        "activation_ref": sha("c"),
        "trust_snapshot_version": 7, "trust_snapshot_fingerprint": sha("e"),
    }
    base.update(over)
    return base


@contextlib.contextmanager
def deterministic_uuids():
    counter = iter(range(1, 10_000))
    with mock.patch.object(uuid, "uuid4", lambda: uuid.UUID(int=next(counter))):
        yield


def legacy_flow(tmp_path):
    """Non-tenant claim fixture (the existing local-authority-effect fixture): proposal, resolver, workflow, decision."""
    return legacy_mod.setup(tmp_path)


def profile_for(binding: dict | None, *, generation: int = 1):
    """The approval-side R6 `policy-binding/0.1` that corresponds to a canonical binding (shared digest, epoch, activation_ref)."""
    if binding is None:
        return None
    return PolicyBinding(binding_digest=reference_binding_digest(binding), selection_epoch=binding["selection_epoch"],
                         activation_ref=binding["activation_ref"], policy_generation=generation, disposition="selected")


def tenant_flow(tmp_path, binding: dict | None = None, *, profile_binding="derive", generation: int = 1):
    """Tenant-aware, journal-mode (runtime-authority profile) fixture whose approvals commit to the approval-side policy binding.

    `profile_binding`: "derive" builds the profile binding from `binding`; None gives a profile without one; a PolicyBinding is used as given.
    Returns (proposal, resolver, workflow, decision, profile).
    """
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    pb = profile_for(binding, generation=generation) if profile_binding == "derive" else profile_binding
    cl = ActionClass(class_id="synthetic-irreversible", irreversible=True, max_status_age_seconds=60, on_unreadable="refuse")
    cfg = RuntimeAuthorityProfile(catalogue_version="synthetic-catalogue/1", actions={p.action_id: cl}, producer_keys={"synthetic-validator": PUBLIC},
                                  allow_synthetic_resolver=True, **({"policy_binding": pb} if pb is not None else {}))
    base = workflow(Path(tmp_path) / "baseline", p, resolver=r).decide(p, now=TENANT_NOW)
    required = sorted([{"input_type": x.input_type, "input_id": x.input_id} for x in base.resolution_inputs], key=lambda x: (x["input_type"], x["input_id"]))
    context, criteria = r.contexts[PROFILE], {}
    for ob in context["requirement"]["evidence"]:
        if ob["required"] and ob["kind"] == "authorization":
            criteria[ob["obligation_id"]] = {"kind": "exact_members", "producer_id": "synthetic-validator", "subject_digest": commitment(MEMBERS),
                                             "minimum_count": 40, "members": MEMBERS}
            sign_evidence(r.evidence[ob["obligation_id"]], tenant_id=TENANT)
    spec = {"profile": "runtime-authority/0.1", "required_inputs": required, "required_inputs_digest": commitment(required), "evidence_criteria": criteria}
    if pb is not None:
        spec.update({"approval_commitment_version": APPROVAL_COMMITMENT_V2, "policy_generation": pb.policy_generation, "policy_activation_ref": pb.activation_ref})
    context["runtime_authority"] = spec
    bind_approval(r, cfg)
    f = BoundedAuthorizationWorkflow(manifest=manifest(), resolver=r, destination=LocalRefundDestination(Path(tmp_path) / "destination.json"),
                                     records=BoundedRecordStore(Path(tmp_path) / "run.json", "run-1"),
                                     observation_policy=ObservationPolicy(max_age_seconds=300), allow_test_time=True, runtime_authority_profile=cfg)
    d = f.decide(p, now=TENANT_NOW)
    assert d.result == "authorized", d.reasons
    return p, r, f, d, cfg


# ---------------------------------------------------------------------------------------------------------------------------------
# Frozen legacy vectors (generated on the unmodified base fff27ebf)
# ---------------------------------------------------------------------------------------------------------------------------------
def build_legacy_vectors() -> dict:
    """Byte-exact legacy (no-binding) claims: JSON text, claim_commitment and canonical-bytes digest, under deterministic uuids."""
    out = {}
    with tempfile.TemporaryDirectory() as tmp, deterministic_uuids():
        p, _, f, d = legacy_flow(Path(tmp))
        c = materialize_local_execution_claim(f, p, d, now=LEGACY_NOW, claim_id="claim-v02-legacy-plain")
        out["plain"] = _entry(c)
    with tempfile.TemporaryDirectory() as tmp, deterministic_uuids():
        p, _, f, d = legacy_flow(Path(tmp))
        c = materialize_local_execution_claim(f, p, d, now=LEGACY_NOW, claim_id="claim-v02-legacy-dic", decision_input_commitment=sha("a"),
                                              decision_input_profile_version="0.1.0-proposed")
        out["decision_input"] = _entry(c)
    with tempfile.TemporaryDirectory() as tmp, deterministic_uuids():
        p, _, f, d, _cfg = tenant_flow(Path(tmp), None, profile_binding=None)
        c = materialize_local_execution_claim(f, p, d, now=TENANT_NOW, claim_id="claim-v02-legacy-tenant")
        out["tenant"] = _entry(c)
    return out


def _entry(claim) -> dict:
    dumped = claim.model_dump(mode="json", exclude_none=False)
    return {
        "claim_class": type(claim).__name__,
        "claim_json": claim.model_dump_json(),
        "claim_commitment": claim.claim_commitment,
        "canonical_bytes_sha256": hashlib.sha256(_canonical_bytes(dumped)).hexdigest(),
        "keys": sorted(dumped),
    }


if __name__ == "__main__":
    print(json.dumps(build_legacy_vectors(), indent=1, sort_keys=True))
