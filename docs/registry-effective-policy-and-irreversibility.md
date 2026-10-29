# Registry-governed `ActionClass.irreversible` (Registry `r08-v7`) and the effective-policy snapshot

Status: BUILDER_TESTED developer documentation. Non-authorizing. Not independently qualified (independent qualification is deferred, not waived). Governing documents: Engineering Constitution `1c2e920f4e58e07a52e8e2408a506cf7dbc1292b`, Static Migration Plan v1.1, Engineering Plan v1.5, adopted audit (Registry PR #60). Base: Control Plane PR #92 head `a62ca8d8e4088c95407c2000dcca081383d8dd4d` (stacked; #92 is neither rewritten nor rebased). Registry side: the `r08-v7` unified engine (`docs/r08-v7-contract.md` in the Registry repository); the Registry pin used by CI is set by the lead (`PIN_V7` in `tests/test_f5_class_unreadable_governance.py` and the workflow step are placeholders until then).

## What this adds

One more family in the composed `GovernedPolicyWorkflow` (`registry_governed_policy.py`), derived by the pure functions of `registry_irreversibility_governance.py`, and an immutable description of the resulting policy (`registry_effective_policy.py`). **No workflow class was added**; the shared lifecycle (construction, decision entry, execute entry, pre-dispatch commit gate, original-host validity, final-composition validation, one effective profile) is the consolidated one, unchanged. Protected evaluators (`bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`, `rule_revision.py`, `reversibility.py`, `holder_inventory.py`) are byte-identical (pinned by tests).

| Family (Registry `r08-v7`, schema revision 1) | Control Plane value | Stricter | What the stricter value does (existing evaluator, unchanged) |
|---|---|---|---|
| `f5-action-class-irreversibility-policy`, member `class_irreversible` (`class -> irreversible\|no_change`) | `ActionClass.irreversible` for EVERY action of the class | `irreversible` | The evaluator refuses every action of an irreversible class whose `on_unreadable` is not `refuse` (`bounded.py`, `action_class_invalid`) and treats the class as irreversible wherever it reads the legacy flag (`reversibility.effectively_irreversible`). Nothing else reads the flag. |

The effective value is the stricter of the host value and the Registry value, per class. A Registry `no_change` never lowers a host `irreversible` (the family can never assert reversibility); a Registry class the host does not define is refused; the record must name the scoped action's class.

## A flip is never a repair

`ActionClass.irreversible` is the derived legacy field of the opt-in reversibility members. A flip false to true is accepted only when the HOST class is a plain legacy-reversible class. Before anything is composed (and after the Registry result is verified) every host class that would flip is checked, and each failing condition is its own named refusal `class_irreversible:irreversible_flip_conflict:<cause>`:

| Cause | Host condition that refuses the flip |
|---|---|
| `reversibility_declared` | `reversibility` is not None |
| `reversible_until_declared` / `reversal_cost_declared` | `reversible_until` / `reversal_cost` is not None |
| `on_unreadable_not_refuse` | the HOST `on_unreadable` is not `refuse`. It is the host value, never a value another family composed: a flip must not hide a host defect by relying on a narrowing (a Registry `irreversible` over a host `bounded_tolerance` class is refused even when the unreadable family would make it `refuse`) |
| `reads_protected_data` | `reads_protected_data` is true |
| `counterparty_observable_not_default` | `counterparty_observable` is not true |

A host class that is already `irreversible` is a no-op (the profile stays byte-identical). Two host actions that share a class id but carry different flags are `class_irreversible_ambiguous` (refused before any source read), so a flip is never applied to half a class. The existing host check (`host_class_invalid`: irreversible with `on_unreadable` other than `refuse`) runs first, before any Registry call. The final-composition validator repeats the key conditions as defence in depth (`composed_widens_host` for a host true that became false, `irreversible_flip_conflict:on_unreadable_not_refuse` for a flip over a host `on_unreadable` that was not `refuse`, `composed_profile_invalid` for any undeclared difference).

## Binding (nothing new in the preimage)

`irreversible` has no `exclude_if`, so it is in the profile dump that `approval_commitment` hashes, and that dump hash is the persisted decision binding's `catalogue_digest`. A flipped profile therefore has another commitment: an approval issued for the host profile holds (`runtime_authority_approval_mismatch`) and a decision persisted under one effective profile is refused by a workflow with another (`authorization-critical inputs changed`). No approval format, preimage, persisted field or reason code changed. The family schema revision is part of the Registry effective-policy preimage (Registry side), so the digest recorded here changes if the schema revision ever changes.

## Composition order

F4 scalars, class status age, class unreadable value, revocation assurance, irreversibility, terminal revocation (the fields are disjoint, so the order does not change the result; it is fixed for determinism). Every declared family is mandatory at construction, decision entry, execute entry and immediately before `destination.apply`; any failure refuses the whole workflow. The new bound-identity member and the configuration-identity member exist only while the family is declared, so every pre-existing bound identity and configuration digest is byte-identical (a golden literal computed on the base pins it).

## `EffectivePolicySnapshot`

`workflow.effective_policy_snapshot` is a frozen dataclass built once from the bound identity at construction: host profile digest, effective profile digest, one entry per applied family (workflow slot, Registry family id, contract version, family schema revision where recorded, Registry effective-policy digest, effective value as sorted pairs, selection id and epoch), the Control Plane scope and the evaluation time. Only tuples and scalars (no mutable member), deterministic, and `identity_digest` commits to all of it, so a change of any family's value, digest, selection id or epoch changes the identity. `resolve_effective_policy(...)` runs the EXISTING `derive_policy` and returns the snapshot, or raises `RegistryGovernedPolicyRefused` (boundary `resolution`); a missing mandatory selection (`selection_missing`), an empty declaration or any family failure refuses the whole resolution, never a smaller or weaker policy. A snapshot grants nothing and is read by no evaluator.

## Limits (not hidden)

The commit gate runs immediately before `destination.apply`, not inside the destination's transaction (accepted for bounded engineering only). Selection-source custody, freshness, revocation visibility, epoch floors and rollback protection are host duties (`registry-f4-selection-source-custody.md`); there is no Control Plane ratchet, and rebuilding the workflow without the family (or without Registry) is a host configuration decision this adapter cannot prevent. The boundary comparison is on the effective values and Registry digests: a replacement selection with the same effective value but another selection id or epoch is accepted and the snapshot, which describes construction time, then names the earlier selection. A profile carrying `policy_binding` is refused for the profile-bearing families. The flip is a per-class declaration of the legacy flag only; it does not create, supply or verify any reversibility member, and `anchor_deadline_to_inputs`, `ObservationPolicy.max_age_seconds` and `ObservationPolicy.clock_tolerance_seconds` are BLOCKED and have no family here. Only `r08-v7` records are accepted by this family; v1-v6 are frozen and unchanged (a record of another contract or family in the new slot, or of this family in another slot, is refused with no fallback).

## Tests and CI

`tests/test_irreversibility_governance.py` (real synthetic Ed25519 through the real workflow): alone, the value matrix, every flip-conflict cause, ambiguity, every combination with the five other families, scope and authority mismatch, host-invalid, attempted widening (forged Registry results), missing mandatory selection, replacement, key revocation, withdrawal and expiry, revocation between decision and effect and after execute entry, stale and cross-profile decisions, approval binding, restart, no effect after refusal, ledger identity, snapshot immutability/determinism/identity/no-fallback, frozen-compatibility and protected-file pins. `tests/test_irreversibility_unit.py` needs no Registry checkout (named fakes of the Registry result). CI runs both with the existing composed, revocation-families and on_unreadable suites against a fourth Registry checkout at the exact `r08-v7` pin with `OCS_REQUIRE_REGISTRY_PIN=1` and a junit gate (0 skipped, 0 failed).
