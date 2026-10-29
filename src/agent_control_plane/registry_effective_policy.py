"""Immutable snapshot of the ONE effective policy a `GovernedPolicyWorkflow` is running under, and a thin pure resolver over the existing `derive_policy` path.

BUILDER_TESTED developer implementation. NOT independently qualified. NON-AUTHORIZING: a snapshot is a description of what was already derived and verified; it grants nothing, is not
an approval and is not read by any evaluator. It adds no workflow class, no policy language and no new Registry call: every value in it comes from the bound identity that the
existing derivation already produced (`registry_governed_policy.derive_policy`) and from the already Registry-verified selection envelope.

What it holds: the host profile digest, the effective profile digest, one entry per APPLIED family (workflow slot, Registry family id, contract version, the Registry effective-policy
digest, the effective value as sorted pairs, the selection id and epoch), the Control Plane scope and the evaluation time. Only tuples and scalars: there is no mutable member, so a
holder cannot edit it. `identity_digest` commits to all of it, so a change of any family's value, digest, selection id or epoch changes the identity.

`resolve_effective_policy(...)` runs the existing derivation and returns the snapshot, or raises the existing refusal type. It never returns a weaker policy: any family failure
refuses the whole resolution (no fallback to a smaller set).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Optional

from agent_control_plane.bounded import commitment
from agent_control_plane.registry_governed_lifecycle import Refusal

# workflow slot -> (Registry family id, Registry contract version). A slot that is not declared is simply absent from a snapshot.
FAMILY_TABLE = {
    "f4_ages": ("f4-control-plane-age-bounds", "r08-v2"),
    "class_age": ("f5-action-class-age-bounds", "r08-v2"),
    "class_unreadable": ("f5-action-class-unreadable-policy", "r08-v5"),
    "class_revocation_assurance": ("f5-action-class-revocation-assurance-policy", "r08-v6"),
    "class_irreversible": ("f5-action-class-irreversibility-policy", "r08-v7"),
    "terminal_revocation": ("f5-terminal-revocation-enablement-policy", "r08-v6"),
}
# Only the r08-v7 family has a family schema revision recorded by this adapter; older families are identified by contract version alone.
SCHEMA_REVISIONS = {"class_irreversible": 1}


def _strict_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_number(_):
    raise ValueError("non-integer number")


def selection_ref(selection_text: Any) -> Optional[tuple]:
    """`(selection_id, epoch)` of an ALREADY Registry-verified selection envelope text (a second strict parse), or None."""
    try:
        doc = json.loads(selection_text, object_pairs_hook=_strict_pairs, parse_float=_reject_number, parse_constant=_reject_number)
        stmt = doc["statement"]
        sid, epoch = stmt["selection_id"], stmt["epoch"]
    except Exception:
        return None
    if type(sid) is not str or not sid or type(epoch) is not int:
        return None
    return sid, epoch


def _frozen(value: Any) -> Any:
    """A deeply immutable, order-independent form of an effective value: mappings become sorted tuples of pairs."""
    if isinstance(value, Mapping):
        return tuple(sorted((str(k), _frozen(v)) for k, v in value.items()))
    return value


@dataclass(frozen=True)
class AppliedFamily:
    slot: str
    family_id: str
    contract_version: str
    family_schema_revision: Optional[int]
    effective_policy_digest: str
    effective: Any
    selection_id: Optional[str]
    selection_epoch: Optional[int]


@dataclass(frozen=True)
class EffectivePolicySnapshot:
    host_profile_digest: Optional[str]
    effective_profile_digest: Optional[str]
    families: tuple
    scope: tuple
    evaluated_at: str

    @property
    def identity_digest(self) -> str:
        return commitment({
            "host_profile_digest": self.host_profile_digest, "effective_profile_digest": self.effective_profile_digest, "scope": [list(p) for p in self.scope],
            "evaluated_at": self.evaluated_at,
            "families": [[f.slot, f.family_id, f.contract_version, f.family_schema_revision, f.effective_policy_digest, _jsonable(f.effective), f.selection_id, f.selection_epoch]
                         for f in self.families]})

    def family(self, slot: str) -> Optional[AppliedFamily]:
        return next((f for f in self.families if f.slot == slot), None)


def _jsonable(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_jsonable(v) for v in value]
    return value


def build_snapshot(*, bound: Mapping[str, Any], host_profile_digest: Optional[str], refs: Mapping[str, Optional[tuple]], scope: Any, operation_ids: Mapping[str, str],
                   evaluated_at: datetime, order: tuple) -> EffectivePolicySnapshot:
    """The snapshot of one already derived `bound` identity. `order` is the deterministic composition order; `refs` maps a slot to `(selection_id, epoch)`."""
    families = []
    for slot in order:
        part = bound.get(slot)
        if part is None:
            continue
        family_id, contract = FAMILY_TABLE[slot]
        ref = refs.get(slot)
        families.append(AppliedFamily(slot, family_id, contract, SCHEMA_REVISIONS.get(slot), part[1], _frozen(part[0]),
                                      ref[0] if ref else None, ref[1] if ref else None))
    scope_pairs = (("consumer_id", scope.consumer_id), ("tenant_id", scope.tenant_id), ("action_id", scope.action_id),
                   ("operation_ids", tuple(sorted(operation_ids.items()))))
    return EffectivePolicySnapshot(host_profile_digest, bound.get("effective_profile_digest"), tuple(families), scope_pairs, evaluated_at.isoformat())


def resolve_effective_policy(*, families: Any, host: Any, host_scalars: Mapping[str, int], materials: Mapping[str, Any], verifier: Any, institution_id: str,
                             authority_domain: str, now: datetime, host_ages: Optional[Mapping[str, int]] = None, host_values: Optional[Mapping[str, str]] = None,
                             host_assurance: Optional[Mapping[str, str]] = None, host_irreversible: Optional[Mapping[str, str]] = None,
                             host_terminal: Optional[str] = None) -> EffectivePolicySnapshot:
    """Run the EXISTING `derive_policy` over every declared family and return the snapshot of the one effective policy, or raise `RegistryGovernedPolicyRefused` (boundary
    `resolution`) with the same refusal `derive_policy` returned. Pure: builds no workflow, writes nothing and never returns a partial or weaker policy."""
    from agent_control_plane import registry_governed_policy as pol  # late import: that module builds snapshots with this one
    declared = pol._declared(families)
    if not declared:
        raise pol.RegistryGovernedPolicyRefused(Refusal("no_family_declared"), "resolution")
    materials = {name: materials.get(name) for name, _ in declared}  # ONE read of each material: the verified object is the one named in the snapshot
    if any(m is None for m in materials.values()):  # a declared family is mandatory: no fallback to a smaller set
        raise pol.RegistryGovernedPolicyRefused(Refusal("selection_missing"), "resolution")
    derived, refusal = pol.derive_policy(families=families, host=host, host_scalars=host_scalars, host_ages=host_ages, host_values=host_values, materials=materials,
                                         verifier=verifier, institution_id=institution_id, authority_domain=authority_domain, now=now, host_assurance=host_assurance,
                                         host_terminal=host_terminal, host_irreversible=host_irreversible)
    if refusal is not None:
        raise pol.RegistryGovernedPolicyRefused(refusal, "resolution")
    _, _, bound = derived
    first = declared[0][1].scope
    refs = {name: selection_ref(getattr(materials[name], "selection_text", None)) for name, _ in declared}
    return build_snapshot(bound=bound, host_profile_digest=pol.agemod.profile_digest(host) if host is not None else None, refs=refs, scope=first,
                          operation_ids={n: f.scope.operation_id for n, f in declared}, evaluated_at=now, order=pol.FAMILY_NAMES)
