"""Composed Registry-governed bounded-authorization workflow: F4 status/approval ages, F5 per-class status age and F5 per-class unreadable policy governing ONE scope together.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism and NOT a policy interpreter: every Registry selection only NARROWS a
host-configured value and grants nothing. `bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py` and every evaluator are unchanged; the per-family derivations
(`verify_scope_selection`, `derive_effective`, `derive_unreadable`, `compose_unreadable`) are the existing ones, called unchanged.

Explicit host-declared applicability. The host passes `GovernedFamilies` naming WHICH families govern this scope and the (scope, selection_source) of each. Every declared family is
mandatory: it is verified at construction, decision entry, execute entry and immediately before `destination.apply`, and ANY failure (unreadable source, revoked, withdrawn,
expired, changed, out of scope) refuses the whole workflow. There is no partial activation, no fallback to a smaller set and no optional overlay. A family that is not declared is not
governed by Registry here (the host value stays in force). The scopes must share consumer, tenant and action (operation ids may differ).

Deterministic composition. Order: (1) F4 scalars, (2) class status age over the host profile, (3) class unreadable policy over the age-effective profile. The result is ONE
effective `RuntimeAuthorityProfile` (profile-bearing fields) plus the two F4 constructor scalars (which are NOT part of the profile). Before use the ORIGINAL host profile is validated
against the existing invariant (an irreversible class that is not `refuse` is invalid: no Registry value may repair it), and the FINAL composed configuration is validated: every
value is at most the host value, only the governed fields differ from the host, and the result still satisfies the host invariants (`composed_*` refusals).

Identity. Profile-bearing fields are bound by the EXISTING mechanism: `approval_commitment(profile, context)` hashes `profile.model_dump()` and the same profile hash is the
persisted decision binding's `catalogue_digest`, so the FINAL effective profile (`workflow.runtime_authority_profile`) is what the issuer commits. The F4 scalars are NOT in
`approval_commitment` nor in the persisted decision binding, and this module does not invent a preimage for them: they are bound explicitly in this workflow's own bound identity
(compared at every boundary; exposed by `registry_governed_policy_identity`), and the workflow refuses if they are edited after construction. UNRESOLVED DESIGN DECISION (reported,
not decided here): whether the F4 scalars (or this identity) should enter the approval preimage / persisted decision binding. That is an authority-semantic change to a commitment and
needs an explicit Architect decision and F3 requalification. Until then a decision persisted under one scalar pair carries no scalar binding; freshness is re-resolved at execute
under the executing workflow's own (Registry-verified) scalars.

Applicability (deployment). `activation_ledger` (optional, host-owned, in-process, `GovernedActivationLedger`) lets a host refuse a second DIFFERENTLY configured governed workflow for
the same (tenant, action, institution, authority domain). It is a LOCAL check: it cannot see another process, a plain `BoundedAuthorizationWorkflow`, or a workflow built without the
ledger, so it is NOT deployment-wide exclusivity. The supported activation boundary that could enforce exclusivity does not exist in the Control Plane (see
docs/governed-workflow-consolidation.md for the missing contract and a minimal proposal).

Residual limitations are those of the family workflows: the commit gate runs immediately before `destination.apply`, not inside the destination's transaction (accepted for bounded
engineering only); freshness, revocation visibility, epoch floors and rollback protection of the selection sources are host custody duties; the Control Plane has no durable ratchet; the
cached-purpose-snapshot path does not read `on_unreadable`; a profile carrying `policy_binding` is refused for the profile-bearing families.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane import registry_f4_age_governance as f4mod
from agent_control_plane import registry_f5_class_age_governance as agemod
from agent_control_plane import registry_f5_class_unreadable_governance as unrmod
from agent_control_plane.bounded import _now, commitment
from agent_control_plane.registry_governed_lifecycle import (
    GovernedLifecycle, GovernedScope, Refusal, RegistrySelectionRefused, _GatedDestination, _scalar, check_scope, check_source, construction_now, read_source, require_authority,
    take_destination,
)
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

REJECTION_CODE = "registry_governed_policy_selection_invalid"
FAMILY_NAMES = ("f4_ages", "class_age", "class_unreadable")  # deterministic composition order


class RegistryGovernedPolicyRefused(RegistrySelectionRefused):
    """Raised before any existing decision/effect code or state write. `.refusal` carries the closed adapter vocabulary and Registry's typed code."""

    def __init__(self, refusal: Refusal, boundary: str):
        PermissionError.__init__(self, f"registry_governed_policy_refused:{boundary}:{refusal.code}" + (f":{refusal.registry_code}" if refusal.registry_code else ""))
        self.refusal, self.boundary = refusal, boundary


def _refuse(code: str, boundary: str) -> RegistryGovernedPolicyRefused:
    return RegistryGovernedPolicyRefused(Refusal(code), boundary)


@dataclass(frozen=True)
class GovernedFamily:
    """One declared family: its host-fixed Registry scope and the host source of its selection material."""
    scope: GovernedScope
    selection_source: Callable[[], Any]


@dataclass(frozen=True)
class GovernedFamilies:
    """Host-declared applicability. A member that is None is NOT governed by Registry in this workflow; a member that is set is mandatory."""
    f4_ages: Optional[GovernedFamily] = None
    class_age: Optional[GovernedFamily] = None
    class_unreadable: Optional[GovernedFamily] = None


class GovernedActivationLedger:
    """Optional host-owned, in-process claim table: ONE configuration identity per (tenant, action, institution, authority domain).

    Local and advisory by construction: it only ever REFUSES, grants nothing and is not a distributed lock. It cannot observe another process, a plain `BoundedAuthorizationWorkflow`
    or a governed workflow built without the ledger, so it never establishes deployment-wide exclusivity. The host replaces a configuration only by an explicit `supersede`."""

    def __init__(self) -> None:
        self._claims: dict = {}
        self._lock = threading.Lock()

    def claim(self, key: tuple, configuration_id: str) -> bool:
        with self._lock:
            held = self._claims.setdefault(key, configuration_id)
            return held == configuration_id

    def holder(self, key: tuple) -> Optional[str]:
        with self._lock:
            return self._claims.get(key)

    def supersede(self, key: tuple, expected: str, new: str) -> bool:
        with self._lock:
            if self._claims.get(key) != expected:
                return False
            self._claims[key] = new
            return True


def _declared(families: GovernedFamilies) -> list:
    return [(name, getattr(families, name)) for name in FAMILY_NAMES if getattr(families, name) is not None]


def _prefixed(name: str, refusal: Refusal) -> Refusal:
    return Refusal(name + ":" + refusal.code, refusal.registry_code, refusal.registry_kind)


def final_composition_defect(host: Optional[RuntimeAuthorityProfile], final: Optional[RuntimeAuthorityProfile], host_scalars: Mapping[str, int],
                             final_scalars: Optional[Mapping[str, int]]) -> Optional[str]:
    """Validate the FINAL composed configuration against the ORIGINAL host: no value above the host value, only the governed fields differ, the host invariants still hold."""
    if final_scalars is not None and any(final_scalars[k] > host_scalars[k] for k in f4mod.AGES):
        return "composed_widens_host"
    if host is None or final is None:
        return None if (host is None) == (final is None) else "composed_profile_invalid"
    if unrmod.host_class_defect(host) is not None:  # defence in depth: the original host must already have been admissible; a composition never repairs it
        return "host_class_invalid"
    if unrmod.host_class_defect(final) is not None:
        return "composed_profile_invalid"
    dh, df = host.model_dump(mode="json"), final.model_dump(mode="json")
    if set(dh["actions"]) != set(df["actions"]):
        return "composed_profile_invalid"
    for aid, ch in dh["actions"].items():
        cf = df["actions"][aid]
        if cf["max_status_age_seconds"] > ch["max_status_age_seconds"] or unrmod._RANK[cf["on_unreadable"]] > unrmod._RANK[ch["on_unreadable"]]:
            return "composed_widens_host"
        ch.pop("max_status_age_seconds"), cf.pop("max_status_age_seconds"), ch.pop("on_unreadable"), cf.pop("on_unreadable")
    fh, ff = dh.get("freshness"), df.get("freshness")
    if fh and ff:
        if ff.get("max_age_extension_seconds", 0) > fh.get("max_age_extension_seconds", 0):
            return "composed_widens_host"
        fh.pop("max_age_extension_seconds", None), ff.pop("max_age_extension_seconds", None)
    return None if dh == df else "composed_profile_invalid"


def derive_policy(*, families: GovernedFamilies, host: Optional[RuntimeAuthorityProfile], host_scalars: Mapping[str, int], host_ages: Optional[Mapping[str, int]],
                  host_values: Optional[Mapping[str, str]], materials: Mapping[str, Any], verifier: Any, institution_id: str, authority_domain: str, now: datetime):
    """Pure verification of EVERY declared family and composition of the one effective configuration. Returns `((profile or None, scalars or None, bound), None)` or `(None, Refusal)`.
    Builds no workflow and writes nothing."""
    scalars = age_part = unreadable = None
    base = host
    if families.f4_ages is not None:
        values, digest, refusal = f4mod.verify_scope_selection(scope=families.f4_ages.scope, institution_id=institution_id, authority_domain=authority_domain,
                                                               caller_ages=host_scalars, material=materials["f4_ages"], verifier=verifier, now=now)
        if refusal is not None:
            return None, _prefixed("f4_ages", refusal)
        scalars = (dict(values), digest)
    if families.class_age is not None:
        derived, refusal = agemod.derive_effective(scope=families.class_age.scope, institution_id=institution_id, authority_domain=authority_domain, host=host,
                                                   host_ages=host_ages, material=materials["class_age"], verifier=verifier, now=now)
        if refusal is not None:
            return None, _prefixed("class_age", refusal)
        base, age_effective, age_digest, age_pdigest = derived
        age_part = (dict(age_effective), age_digest, age_pdigest)
    if families.class_unreadable is not None:
        derived_u, refusal = unrmod.derive_unreadable(scope=families.class_unreadable.scope, institution_id=institution_id, authority_domain=authority_domain, host=host,
                                                      host_values=host_values, material=materials["class_unreadable"], verifier=verifier, now=now)
        if refusal is not None:
            return None, _prefixed("class_unreadable", refusal)
        effective, digest = derived_u
        try:
            base = unrmod.compose_unreadable(base, effective)
        except Exception:
            return None, Refusal("effective_profile_invalid")
        unreadable = (dict(effective), digest)
    defect = final_composition_defect(host, base, host_scalars, scalars[0] if scalars else None)
    if defect is not None:
        return None, Refusal(defect)
    pdigest = agemod.profile_digest(base) if (base is not None and (age_part or unreadable)) else None
    bound = {"f4_ages": scalars, "class_age": age_part, "class_unreadable": unreadable, "effective_profile_digest": pdigest}
    return (base, scalars, bound), None


class GovernedPolicyWorkflow(GovernedLifecycle):
    """`BoundedAuthorizationWorkflow` governed by every declared Registry family together, re-validated at every decision and effect.

    `runtime_authority_profile` is the HOST profile (required when `class_age` or `class_unreadable` is declared). `self.runtime_authority_profile` is the FINAL effective profile:
    issue approvals against it. The F4 scalars are the Registry-narrowed `status_max_age_seconds` and `approval_max_age_seconds` of this instance."""

    _gl_rejection_code = REJECTION_CODE

    def __init__(self, *, families: GovernedFamilies, verifier: Any, runtime_authority_profile: Any = None, status_max_age_seconds: int = 60, approval_max_age_seconds: int = 60,
                 construction_time: Optional[datetime] = None, activation_ledger: Optional[GovernedActivationLedger] = None, **workflow_kwargs: Any):
        if type(families) is not GovernedFamilies:
            raise _refuse("families_invalid", "construction")
        declared = _declared(families)
        if not declared:
            raise _refuse("no_family_declared", "construction")
        for _, fam in declared:
            if type(fam) is not GovernedFamily:
                raise _refuse("families_invalid", "construction")
            check_scope(fam.scope, _refuse)
            check_source(fam.selection_source, _refuse)
        first = declared[0][1].scope
        if any((f.scope.consumer_id, f.scope.tenant_id, f.scope.action_id) != (first.consumer_id, first.tenant_id, first.action_id) for _, f in declared):
            raise _refuse("family_scope_mismatch", "construction")
        scope = first
        profile_families = families.class_age is not None or families.class_unreadable is not None
        host = None
        if profile_families and runtime_authority_profile is None:
            raise _refuse("runtime_authority_profile_required", "construction")
        if runtime_authority_profile is not None:
            try:
                host = RuntimeAuthorityProfile.model_validate(runtime_authority_profile).snapshot()
            except Exception:
                raise _refuse("host_profile_invalid", "construction") from None
            if profile_families and host.policy_binding is not None:
                raise _refuse("policy_binding_unsupported", "construction")
        host_values = host_ages = None
        if families.class_unreadable is not None:
            host_values, code = unrmod.host_class_unreadable(host)
            if host_values is None:
                raise _refuse(code, "construction")
            defect = unrmod.host_class_defect(host)  # ORIGINAL host validity FIRST: before any Registry call or source read
            if defect is not None:
                raise _refuse(defect, "construction")
        if families.class_age is not None:
            host_ages, code = agemod.host_class_ages(host)
            if host_ages is None:
                raise _refuse(code, "construction")
        if profile_families and scope.action_id not in host.actions:
            raise _refuse("action_class_unknown", "construction")
        if families.f4_ages is not None and not (_scalar(status_max_age_seconds) and _scalar(approval_max_age_seconds)):
            raise _refuse("host_scalar_invalid", "construction")
        authority = require_authority(workflow_kwargs, scope.action_id, _refuse)
        now = construction_now(construction_time, workflow_kwargs, _now, _refuse)
        host_scalars = {f4mod.AGES[0]: status_max_age_seconds, f4mod.AGES[1]: approval_max_age_seconds}
        materials = {name: read_source(fam.selection_source, _refuse, "construction") for name, fam in declared}
        derived, refusal = derive_policy(families=families, host=host, host_scalars=host_scalars, host_ages=host_ages, host_values=host_values, materials=materials,
                                         verifier=verifier, institution_id=authority[0], authority_domain=authority[1], now=now)
        if refusal is not None:
            raise RegistryGovernedPolicyRefused(refusal, "construction")
        profile, scalars, bound = derived
        configuration = commitment({"families": [n for n, _ in declared], "scopes": {n: f.scope.operation_id for n, f in declared}, "consumer_id": scope.consumer_id,
                                    "tenant_id": scope.tenant_id, "action_id": scope.action_id, "institution_id": authority[0], "authority_domain": authority[1]})
        key = (scope.tenant_id, scope.action_id, authority[0], authority[1])
        destination = take_destination(workflow_kwargs, _refuse)
        if activation_ledger is not None and not activation_ledger.claim(key, configuration):
            raise _refuse("conflicting_governed_configuration", "construction")
        extra = {}
        if profile is not None:
            extra["runtime_authority_profile"] = profile
        if scalars is not None:
            extra.update(status_max_age_seconds=scalars[0][f4mod.AGES[0]], approval_max_age_seconds=scalars[0][f4mod.AGES[1]])
        else:
            extra.update(status_max_age_seconds=status_max_age_seconds, approval_max_age_seconds=approval_max_age_seconds)
        super().__init__(destination=_GatedDestination(destination, self._gl_commit_gate), **extra, **workflow_kwargs)
        self._gp_families, self._gp_verifier, self._gp_host, self._gp_host_scalars = families, verifier, host, host_scalars
        self._gp_host_values, self._gp_host_ages = host_values, host_ages
        self._gp_ledger, self._gp_key, self._gp_configuration = activation_ledger, key, configuration
        self._gl_attach(scope=scope, authority=authority, bound=bound)

    @property
    def governed_last_commit_refusal(self) -> Optional[Refusal]:
        return self._gl_last_commit_refusal

    @governed_last_commit_refusal.setter
    def governed_last_commit_refusal(self, value: Optional[Refusal]) -> None:
        self._gl_last_commit_refusal = value

    @property
    def registry_governed_policy_identity(self) -> dict:
        """The one bound identity of this workflow: which families govern it, each family's Registry digest and effective values, the F4 scalars (explicit, NOT in
        `approval_commitment`) and the FINAL effective-profile digest (the persisted `catalogue_digest`)."""
        b = self._gl_bound
        scope = self._gl_scope
        return {"families": [n for n, _ in _declared(self._gp_families)], "configuration_digest": self._gp_configuration,
                "scope": {"consumer_id": scope.consumer_id, "tenant_id": scope.tenant_id, "action_id": scope.action_id,
                          "operation_ids": {n: f.scope.operation_id for n, f in _declared(self._gp_families)}},
                "host": {"f4_ages": dict(self._gp_host_scalars) if b["f4_ages"] else None, "class_age": dict(self._gp_host_ages) if self._gp_host_ages else None,
                         "class_unreadable": dict(self._gp_host_values) if self._gp_host_values else None},
                "f4_ages": None if b["f4_ages"] is None else {"effective": dict(b["f4_ages"][0]), "effective_policy_digest": b["f4_ages"][1]},
                "class_age": None if b["class_age"] is None else {"effective": dict(b["class_age"][0]), "effective_policy_digest": b["class_age"][1],
                                                                   "effective_profile_digest": b["class_age"][2]},
                "class_unreadable": None if b["class_unreadable"] is None else {"effective": dict(b["class_unreadable"][0]),
                                                                                  "effective_policy_digest": b["class_unreadable"][1]},
                "effective_profile_digest": b["effective_profile_digest"], "f4_scalars_in_approval_commitment": False}

    def _gl_error(self, refusal: Refusal, boundary: str) -> Exception:
        return RegistryGovernedPolicyRefused(refusal, boundary)

    def _gl_held_defect(self) -> Optional[str]:
        b = self._gl_bound
        if b["f4_ages"] is not None:
            values = b["f4_ages"][0]
            if (self.status_max_age_seconds, self.approval_max_age_seconds) != (values[f4mod.AGES[0]], values[f4mod.AGES[1]]):
                return "scalars_modified"
        if b["effective_profile_digest"] is not None:
            held = self.runtime_authority_profile
            if type(held) is not RuntimeAuthorityProfile or agemod.profile_digest(held) != b["effective_profile_digest"]:
                return "profile_modified"
        if self._gp_ledger is not None and self._gp_ledger.holder(self._gp_key) != self._gp_configuration:
            return "activation_superseded"
        return None

    def _gl_read_sources(self, boundary: str) -> Any:
        return {name: read_source(fam.selection_source, _refuse, boundary) for name, fam in _declared(self._gp_families)}

    def _gl_derive(self, materials: Any, authority: Any, now: datetime, boundary: str) -> Any:
        derived, refusal = derive_policy(families=self._gp_families, host=self._gp_host, host_scalars=self._gp_host_scalars, host_ages=self._gp_host_ages,
                                         host_values=self._gp_host_values, materials=materials, verifier=self._gp_verifier, institution_id=authority[0],
                                         authority_domain=authority[1], now=now)
        if refusal is not None:
            raise RegistryGovernedPolicyRefused(refusal, boundary)
        return derived[2]
