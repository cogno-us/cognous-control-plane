# Registry-governed `requires_revocation_assurance` and terminal-revocation enablement (Registry `r08-v6`)

Status: BUILDER_TESTED developer documentation. Non-authorizing. Not independently qualified (independent qualification is deferred, not waived). Governing documents: Engineering Constitution `1c2e920f4e58e07a52e8e2408a506cf7dbc1292b` (`ADOPTION.md` at the same revision), Static Migration Plan v1.1, Engineering Plan v1.5, adopted audit (Registry PR #60), consolidation decision (Registry PR #67). Base: Control Plane `main` `4780abe0af54147c0770e98cb7b964b74b2008c4`. Source reconciliation and decisions: Registry `docs/family-migration/revocation-families/`.

## What this adds

Two more families in the composed `GovernedPolicyWorkflow` (`registry_governed_policy.py`), derived by the pure functions of `registry_revocation_governance.py`. **No workflow class was added**; the shared lifecycle (construction, decision entry, execute entry, pre-dispatch commit gate, original-host validity, final-composition validation, one effective profile) is the consolidated one, unchanged.

| Family (Registry `r08-v6`) | Control Plane value | Stricter | What the stricter value does (existing evaluator, unchanged) |
|---|---|---|---|
| `f5-action-class-revocation-assurance-policy`, member `class_requires_revocation_assurance` (`class -> required\|not_required`) | `ActionClass.requires_revocation_assurance` | `required` | The class holds `holder_inventory_missing` unless the HOST profile carries a holder inventory enumerating at least one holder (`runtime_authority.validate_extensions`). |
| `f5-terminal-revocation-enablement-policy`, member `terminal_revocation` (`off\|on`) | presence of `RuntimeAuthorityProfile.terminal_revocation` | `on` | A grant revision whose revocation a retained resolution check already observed stays refused (`grant_revocation_recorded`) even if its status later reads `active` (`bounded.py`, `_recorded_grant_denial`). `suspended` stays reversible. |

The effective value is the stricter of the host value and the Registry value, per class for the first family. A Registry `not_required`/`off` over a stricter host value changes nothing; no Registry value can remove a host requirement or section (`composed_widens_host`).

## Requirement is not evidence

`required` is a POLICY REQUIREMENT. It does not establish that revocation reaches any holder: the only thing that lifts the hold is a host-declared inventory, which `holder_inventory.py` itself calls "a claim by whoever wrote it". A Registry `required` never creates, supplies or verifies an inventory and no assurance receipt exists or is invented. Where the host has no inventory a Registry `required` makes every action of the class hold (a self-inflicted denial; fail-closed, documented, tested, not repaired).

Terminal revocation `on` is the host's own "obligation to enforce", not permission to revoke. It does not decide who may revoke, does not write or edit a revocation record, does not create a state transition and does not reverse or supersede one. The memory it reads is the host's own retained checks (a revocation this control plane never observed cannot be remembered; the store has no keyed integrity check).

## Binding (no F4-style gap)

Both values are INSIDE the `RuntimeAuthorityProfile`. `approval_commitment` hashes `profile.model_dump()` and the same hash is the persisted decision binding's `catalogue_digest`, so the FINAL effective profile (`workflow.runtime_authority_profile`) is what the issuer commits. The flag is omitted from dumps while false and the section while absent, so forcing a value changes the commitment: an approval issued for the host profile does not authorize the forced one (`runtime_authority_approval_mismatch`), and a decision persisted under one effective profile is refused by a workflow with another (`authorization-critical inputs changed`). Neither parameter has a constructor-only copy, so the unresolved F4 scalar-binding decision (U-1) is NOT repeated here and no approval format, preimage or persisted field changed.

## Composition and lifecycle

Order: F4 scalars, class status age, class unreadable value, revocation assurance, terminal revocation (the fields are disjoint, so the order does not change the result; it is fixed for determinism). The original host profile is validated first (an irreversible class that is not `refuse` is `host_class_invalid`, before any source read); the final configuration is validated (`final_composition_defect`: no scalar, class age or unreadable value above the host, no dropped host requirement or section, only governed fields differ). Every declared family is mandatory at construction, decision entry, execute entry and immediately before `destination.apply`; any failure refuses the whole workflow. The activation ledger's configuration identity includes the new host values and Registry digests.

## Limits (not hidden)

The commit gate runs immediately before `destination.apply`, not inside the destination's transaction (accepted for bounded engineering only). Selection-source custody, freshness, revocation visibility, epoch floors and rollback protection are host duties (`registry-f4-selection-source-custody.md`); there is no Control Plane ratchet, and rebuilding the workflow without Registry is a host configuration decision this adapter cannot prevent. The cached-purpose path does not read `on_unreadable`. A profile carrying `policy_binding` is refused for the profile-bearing families. The activation ledger is local and advisory (see `governed-workflow-consolidation.md`). Only `r08-v6` records are accepted by these families; v1-v5 are frozen and unchanged.

## Tests and CI

`tests/test_revocation_families_governance.py` (real synthetic Ed25519 through the real workflow): each family alone, both together, all combinations with F4/F5, scope and authority mismatch, host-invalid, attempted widening (forged Registry results), missing mandatory selection, replacement, key revocation/withdrawal/expiry, revocation between decision and effect, after execute entry before dispatch, missing assurance evidence, recorded revocation and its persistence across restart, stale and cross-profile decisions, approval binding, ledger identity, frozen compatibility and protected-file pins. CI runs it (with the composed and `on_unreadable` suites) against a third Registry checkout at the exact `r08-v6` pin with `OCS_REQUIRE_REGISTRY_PIN=1` and a junit gate (0 skipped, 0 failed).
