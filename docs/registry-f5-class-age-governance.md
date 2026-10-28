# Registry F5 per-class status age (`GovernedClassAgeWorkflow`)

Status: BUILDER_TESTED developer documentation. Non-authorizing. Not independently qualified. Module: `agent_control_plane.registry_f5_class_age_governance`. Governing documents: Static Migration Plan v1.1 (adoption merge `6f600ab1150f00ef3d96834159b1807e866a78b6`), Engineering Plan v1.5, adopted inventory audit (Registry PR #60, merge `6516446a4e551e50f2bb47c1d57fbf8ace27d7c5`), Engineering Constitution `1c2e920f4e58e07a52e8e2408a506cf7dbc1292b` (`ADOPTION.md` read at the same revision).

## What it does
A Registry r08-v2 F5 selection (`class_status_max_age_seconds`: class id to seconds) can only LOWER the host's `ActionClass.max_status_age_seconds`. The workflow verifies the selection with Registry (`verify_and_decide_v2`, required participation, exact `Ed25519Verifier`), builds ONE effective `RuntimeAuthorityProfile` and passes it to the unchanged `BoundedAuthorizationWorkflow` constructor. Every existing check that reads a class bound (`bounded.py` grant status, `_class_age_bound`, purpose status, extensions) reads that profile.

## How the narrowed value reaches the approval commitment
`approval_commitment(profile, context)` already hashes `profile.model_dump()`, which contains every `ActionClass`. So the narrowed age is bound by being in the profile that is committed, BEFORE approval issuance. No commitment code, reason code or evaluator is changed.

| Registry result | Effective profile | Existing approvals / decisions |
|---|---|---|
| value equal to or above the host value, no outage extension configured | byte-identical to the host profile | remain valid (same commitment) |
| value below the host value | class age lowered | an approval issued for the host profile holds with the existing `runtime_authority_approval_mismatch`; a new approval over the effective profile is required; nothing is rewritten |
| any change of selection that changes the effective profile | different profile digest | the running workflow refuses (`selection_changed`); a rebuilt workflow cannot execute a decision persisted under the old profile (`authorization-critical inputs changed before effect`) |

**Issuer procedure.** Build the governed workflow first, then compute the approval commitment over `workflow.runtime_authority_profile` (the EFFECTIVE profile), not the host profile. `workflow.registry_f5_policy_identity` reports the host map, the effective map, the Registry effective-policy digest and the effective-profile digest (equal to the `catalogue_digest` recorded in every decision binding).

## Outage extensions (freshness/0.1)
Extensions are measured from the class base. A narrowed base of 30 with a host limit of 300 could still be extended to 330, above the Registry value. DR-CP-AGE-1 decision 5 is therefore applied when, and only when, the host profile carries `freshness.max_age_extension_seconds > 0`: `limit := min(host limit, min over Registry-governed classes of max(0, registry value - narrowed base))`. Consequence: a Registry value EQUAL to the host value removes outage extensions for that deployment, because base + extension may not exceed the Registry value. Extension rows recorded against the old base are invalid (`age_extension_invalid`, existing fail-closed behaviour).

## Lifecycle
The selection is verified at construction, at the start of `decide`, at the start of `execute`, and at the commit gate immediately before `destination.apply` (4 source calls per effect). Each must reproduce the bound effective class map, Registry digest and effective-profile digest, and the profile held by the workflow must still hash to the bound digest (a later attribute edit or `model_copy` cannot widen a bound). Refusals before the commit gate raise `RegistryClassAgeRefused` (a `PermissionError`) before any state write; at the gate the existing `DefinitiveDestinationRejection("registry_f5_selection_invalid")` is raised, the destination is not called and the attempt is recorded `failed`, which blocks automatic retry.

## Scope and refusals
One (consumer, tenant, action) scope per workflow; institution and authority domain come from the manifest; the Registry `operation` is a host-fixed identifier. Refused: no profile, a profile with `policy_binding`, an invalid host profile, a scoped action absent from the profile or manifest, two actions sharing a class id with different host ages, a Registry class the host does not define, a record that does not name the scoped class, optional participation, a non-admitted verifier, a wrapped or missing destination.

## Limitations
1. Residual delegated `apply` window: accepted for bounded engineering only; stronger production atomicity is unqualified.
2. `selection_source` custody (freshness, revocation visibility, epoch, rollback) is the host's duty: see `registry-f4-selection-source-custody.md`, which applies unchanged. No separate ratchet exists.
3. `policy_binding` (approval generation, `age_ceilings`) is refused: how a Registry class age would feed the generation and the ceilings is not decided.
4. Not governed here: F4 scalars, clock tolerance, identity and mandate ages, `on_unreadable`, `requires_revocation_assurance`, reversibility, `anchor_deadline_to_inputs`, terminal revocation, observation policy. This workflow does not compose with `GovernedAgeWorkflow`.
