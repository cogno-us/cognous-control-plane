# Persisted effective-configuration binding `effective-configuration-binding/0.1` (D-06 Option B, carriage C2)

Status: BUILDER_TESTED developer implementation. Non-authorizing. **Not independently qualified**: F3-A independent qualification is PENDING; independent Tier 1 qualification is DEFERRED, NOT WAIVED. Nothing here is a security clearance, certification or production-readiness claim, and production stays on HOLD. The binding is an equality check that can only ADD a refusal: it is never an approval input, never widens a bound and grants no authority.

Authorization and contract: Architect directive "ARCHITECT AUTHORIZATION AND BUILDER DIRECTIVE" (2026-10-29), D-06 Option B. The frozen contract is section 4 of `docs/family-migration/final-three/02-architect-authorization-and-contract-freeze-2026-10-29.md` in the docs repository; the qualification expectations are in `03-f3-qualification-expectations-F3A-F3B-2026-10-29.md`. This file describes what the code does; where it differs from the frozen text that is a defect to report, not a decision.

## 1. What problem it closes

Before D-06 a governed decision persisted only the profile-bearing identity (`catalogue_digest`, `approval_commitment`). The F4 scalars, the other constructor scalars, the `ObservationPolicy`, the host profile, the declared family set and the Registry contract versions were bound to nothing durable. A decision minted under configuration A was executable after a restart or rebuild under configuration B whenever the final profile was byte-identical (the gap characterized by `test_i04`). The binding persists the configuration a decision ran under and refuses to execute it under a different one.

## 2. The record (carriage C2)

The member lives inside the already-persisted opaque dict `binding.runtime_authority`; there is no typed field, no JSON-schema change and no change to `approval_commitment`, `catalogue_digest`, `RuntimeAuthorityProfile`, `EffectivePolicySnapshot.identity_digest` or the reason vocabulary.

```json
"runtime_authority": {
  "...existing members unchanged...",
  "effective_configuration": {
    "version": "effective-configuration-binding/0.1",
    "digest":  "sha256:<64 lowercase hex>",
    "members": { "scope": {...}, "host_profile_digest": ..., "effective_profile_digest": ..., "f4_scalars": {...}, "other_scalars": {...}, "observation_policy": ..., "families": [...] }
  }
}
```

`digest` is the EXISTING canonical `commitment()` (`bounded.commitment`, sorted-key canonical JSON, SHA-256) over:

| member | content |
|---|---|
| `domain` (constant) | `cognous.control-plane.effective-configuration-binding` |
| `version` | `effective-configuration-binding/0.1` |
| `scope` | `consumer_id`, `tenant_id`, `action_id`, `institution_id`, `authority_domain` (the governed scope; the same five-key helper `scope_identity` is shared with the activation ledger's configuration digest) |
| `host_profile_digest` | `profile_digest` of the HOST profile, or null when there is none |
| `effective_profile_digest` | digest of the FINAL held profile (equals `catalogue_digest`), or null for a workflow with no profile |
| `f4_scalars` | live `status_max_age_seconds`, `approval_max_age_seconds` (host values when the F4 family is not declared; Registry-narrowed when it is) |
| `other_scalars` | live `clock_tolerance_seconds` (the CONSTRUCTOR tolerance), `identity_max_age_seconds`, `mandate_max_age_seconds` - bound **for equality only** |
| `observation_policy` | `{max_age_seconds, clock_tolerance_seconds}` effective values, or an explicit JSON null when the workflow has no policy |
| `families` | the declared mandatory families in composition order, each `{slot, family_id, contract_version, family_schema_revision, effective_policy_digest}`; an undeclared family is ABSENT, so the declared set is part of the identity |

Excluded on purpose: `evaluated_at` (non-deterministic), `selection_id` and `selection_epoch` (an equal replacement selection is accepted today; its effect is carried by the effective-policy digest).

Every value is validated BEFORE hashing and again by the reader: exact `int` (never `bool`, never float or string), `0 <= v <= 2147483647`; exact non-empty `str`; digests `sha256:` + 64 lowercase hex and not all-zero. The record has exactly the keys `version`, `digest`, `members`; `members` has exactly the frozen keys; no extra key at any level is tolerated.

The constructor `clock_tolerance_seconds` is bound only so that drift refuses. There is NO Registry family for it and it is NOT narrowable; the standing hold "constructor clock tolerance: NOT AUTHORIZED" is untouched. The family list is built from the existing `FAMILY_TABLE`, `SCHEMA_REVISIONS`, `FAMILY_NAMES` and the `bound` slots, so a family added there later appears in the binding without a change to the binding code; a `bound` slot that the table does not know is REFUSED (`configuration_binding_invalid`), never silently left out.

## 3. Where it is minted and checked

* Module: `src/agent_control_plane/effective_configuration_binding.py` (pure; imports only `commitment`). Lifecycle: `GovernedLifecycle._resolve` (non-protected `registry_governed_lifecycle.py`). The ONE implementation of the live members, the held-state guard for the scalars and the ObservationPolicy, the `legacy_cutoff` check and the construction-time bind step is in `GovernedLifecycle` (`_gl_build_members`, `_gl_config_defect`, `check_cutoff`, `_gl_bind_configuration`); each governed workflow supplies only a small hook `_gl_configuration_members` that names its host/effective profile digests and its bound family slots (section 3a).
* **Mint** on every AUTHORIZED decision of every governed workflow (the composed `GovernedPolicyWorkflow` and the three dedicated single-family workflows, section 3a). Always on: there is no constructor switch, no default-off mode. A hold persists no binding (as before); a hold stays a hold.
* **Check** on `execute` and on the pin-export / claim path. Both re-resolve through `workflow._resolve`, so the one override covers both; a test pins each. The base class's existing equality `current != persisted.binding` then does the refusing: the live member is placed in the rebuilt binding (or, for a legacy decision, deliberately left out), so a mismatch yields the registered reason `authorization_binding_changed`. On `execute` this is a durable `EffectTimeRefusal` and `execute` raises the existing `PermissionError("authorization-critical inputs changed before effect")`. On the read-only pin-export path it yields a non-`active` result with no payload and writes no `EffectTimeRefusal`; at claim issuance no claim is issued and no `EffectTimeRefusal` is written. The destination is not touched and no attempt is created. (Correction 2026-10-29: this sentence previously attributed the durable refusal to the pin-export / claim path as well; the code has always behaved as stated here. See OCS-F3A-DEV-PE-1-INTERPRETATION/1.0 in the Registry.)
* Not covered, by scope: the plain `BoundedAuthorizationWorkflow` mints nothing (it has no governed configuration to bind). It is not a governed workflow.

## 3a. The dedicated single-family workflows (follow-up that closes "no unbound configuration in newly governed decisions")

`GovernedAgeWorkflow` (F4, no profile), `GovernedClassAgeWorkflow` and `GovernedClassUnreadableWorkflow` (alone, or joined with class age) now mint and check the same binding. Each module adds exactly: a `legacy_cutoff=0` keyword validated by the shared `check_cutoff`; one call to the shared `_gl_bind_configuration` as the last construction step; `_gl_config_defect()` at the end of its `_gl_held_defect`; and one `_gl_configuration_members` hook that calls the shared builder. There is no second implementation, no new reason code, the same `legacy_cutoff` semantics (default 0, exact int 0..2147483647, `legacy_cutoff_invalid`) and the same refusal path (`authorization_binding_changed`). The composed workflow was moved onto the same shared code, so the four workflows differ only in their hook:

| workflow | `host_profile_digest` | `effective_profile_digest` | family slots bound |
|---|---|---|---|
| F4 (`GovernedAgeWorkflow`) | null | null | `f4_ages` |
| class age | host profile | held (derived) profile | `class_age` |
| class unreadable alone | host profile | held (derived) profile | `class_unreadable` |
| class unreadable + class age (joint) | host profile | held (derived) profile | `class_age`, `class_unreadable` |

The F4 record has `runtime_authority == {"effective_configuration": {...}}` (it carried `None` before). The revocation and irreversibility modules (`registry_revocation_governance.py`, `registry_irreversibility_governance.py`) do not construct decision-minting workflows (they are family evaluators consumed by the composed workflow), so they needed and received no change. A dedicated and a composed decision are different records (different `scope`/`families`/profile digests), so a decision minted by one is refused by the other, by design. Row order is `FAMILY_TABLE` order in the dedicated workflows and `FAMILY_NAMES` order in the composed one; the two agree on every slot a dedicated workflow can bind (`test_d18`).

## 4. Reader rules and the read-only classifier

`GovernedLifecycle.configuration_binding_status(decision)` (and the pure `effective_configuration_binding.classify`) returns one of:

| status | meaning | accepted? |
|---|---|---|
| `bound` | valid member equal to the live member | yes |
| `legacy` | member absent AND decision index below the explicit `legacy_cutoff` (valid, not above the store's decision count) | yes, under exactly the previous semantics |
| `mismatch` | valid member, unequal to the live member (any member, including the explicit null of an absent ObservationPolicy) | no |
| `invalid` | present but malformed, wrong type or range, extra or missing key, or `digest` not equal to the recomputation over its own `members` | no |
| `version-unsupported` | present with a `version` other than `effective-configuration-binding/0.1` (a closed set) | no |
| `unbound-after-cutoff` | member absent and not legacy: no cutoff (default 0), at or after the cutoff, a stripped member, an invalid cutoff, an unknown position | no |

Every non-accepted status refuses with `authorization_binding_changed`. There is no fallback to a smaller set, a host value, the legacy path or a warning. The binding can only add a refusal through the existing equality; a refusal produced by another check is returned unchanged (`test_f01`, `test_f02`).

`legacy` omits ONLY the new key from the live side before the existing equality; it never ignores any other key (`test_d05`).

## 5. `legacy_cutoff` and migration

`GovernedPolicyWorkflow(..., legacy_cutoff=0)` and, identically, `GovernedAgeWorkflow`, `GovernedClassAgeWorkflow`, `GovernedClassUnreadableWorkflow` (`legacy_cutoff=0`; frozen fixtures from the unchanged b7eb11a code for each: `tests/fixtures/d06_legacy_store_dedicated_*.json`). The cutoff is the number of rows in the append-only `decisions` list at activation, supplied by the host as an explicit finite integer. A decision without the member and with index below the cutoff executes under the previous semantics and is reported `legacy`. Rules:

* Default 0: no legacy decision is accepted. There is no wildcard value.
* A cutoff that is not an exact `int` (bool, float, str, None), is negative, or exceeds 2147483647 is refused at construction (`legacy_cutoff_invalid`).
* A cutoff larger than the number of decisions in the store cannot describe "the decisions at activation" (the list only grows). Construction of every governed workflow therefore REFUSES a cutoff larger than the number of decisions currently in the store (`legacy_cutoff_invalid`; also when the store cannot be read to count them). The count only grows, so afterwards every post-construction append has an index at or above the cutoff and can never be legacy; an oversize cutoff can no longer act as a quiet wildcard for future appends (independent review scenario: 3 decisions, index 1 stripped, cutoff 5, later count 5; `test_d07`, `test_d07b`, `test_a07`, dedicated `test_d17`). The classifier rule `legacy iff 0 <= index < cutoff <= count` is kept as defence in depth (unit tests). A cutoff of 0 never reads the store.
* Pre-existing decisions are never rewritten, re-signed or back-filled (a back-fill would manufacture a binding the issuer never saw). Existing approvals are untouched: `approval_commitment` is byte-identical, so every already-issued approval still validates (`test_a03`, `test_h01`).
* Procedure: stop old writers; count the decisions (`len(workflow.records.load().decisions)`); construct the new workflow with that number as `legacy_cutoff`; let legacy decisions drain (they execute or expire); then drop the cutoff (omit it). Nothing in the store changes. Do not leave a cutoff configured longer than needed: a legacy decision has no member to compare, so it keeps exactly the previous semantics including the previous gap (`test_a08`).

## 6. Reader compatibility matrix (carriage C2)

| Writer -> reader | Result |
|---|---|
| legacy record -> new reader, no cutoff | REFUSE `authorization_binding_changed` |
| legacy record -> new reader, cutoff above its index | OK under the previous semantics, reported `legacy` |
| legacy record at/after the cutoff (legacy writer appends after the upgrade, or a stripped member) | REFUSE |
| new record, same configuration -> new reader | OK (`bound`), also across a restart and in a separate process |
| new record, different configuration (any member) -> new reader | REFUSE. `execute`: durable `EffectTimeRefusal` `authorization_binding_changed` and `PermissionError`. Pin export (read-only assessment): fails closed, state not `active`, payload `None`, no `EffectTimeRefusal` written. Claim issuance: no claim issued (`PermissionError`), no `EffectTimeRefusal` written. |
| new record -> LEGACY binary | REFUSE (fail closed): its `current != persisted.binding` sees a one-key-larger dict (`test_b01`, `test_b03` run the unchanged comparison code on a new record) |
| legacy writer appends after upgrade (mixed fleet) | new readers refuse it past the cutoff; legacy readers accept it (unchanged legacy semantics; cannot be prevented in code; "stop old writers before upgrading" stays an operational requirement) |
| new writer, legacy peer executing it | peer REFUSES, so a mixed fleet cannot bypass the binding on records the new writer mints |
| unknown future `version` -> this reader | REFUSE (closed version set) |

## 7. Restart and recovery

Nothing is held in memory. The persisted member says what the decision ran under; the live process says what runs now. Same families, values, scalars and policies give an equal digest and the decision resumes. A different F4 scalar, other scalar, ObservationPolicy (either value, or present versus absent), host or final profile, scope, family set, family contract version, schema revision or effective value refuses. There is no "re-bind": a changed configuration needs a new decision, and an operator who changes configuration must expect to re-issue in-flight decisions. A configuration refusal is a pre-dispatch refusal row, not an attempt, so an attempt already `failed` at the commit gate still blocks automatic retry (`test_f03`). `test_c01`/`c02`/`c04`/`c05` run recovery in a separate Python process against the persisted store.

## 8. Exact refusal semantics

Durable (reuses the registered code; no new durable reason code, no new vocabulary version): `authorization_binding_changed` as an `EffectTimeRefusal` with `reason_vocabulary_version` set by the existing `vocabulary_for`. On the pin-export path the result is not `active`, carries no payload and writes no `EffectTimeRefusal` (`test_g02`, `test_c04` assert the first two; the absence of a refusal row follows from the source, `authorization_pin_export.py` never calls `append_refusal`); at claim issuance no claim is issued and no `EffectTimeRefusal` is written. The pin export (and claim issuance) still journals through the existing resolution step: a data-dependent number of stage-`claim` `check_events` records plus one `ResolutionCheck` row, and the per-input `input_time_floors` may advance. This is unchanged, non-authorizing and conservative (floors can only add a refusal reason); it grants no authority and creates no `EffectTimeRefusal` obligation on read-only paths. Details and source references: `docs/authorization-pin-export.md`, "Journaling and non-authorization". Effecting `execute` still requires the durable refusal row.

Pre-write adapter refusals (the existing closed adapter vocabulary of the governed workflows; not durable reason codes; raised before any state write):

| code | when |
|---|---|
| `legacy_cutoff_invalid` | constructor `legacy_cutoff` is not an exact int in 0..2147483647, or exceeds the number of decisions in the store at construction |
| `host_scalar_invalid` | at construction, a scalar or ObservationPolicy value cannot be bound (previously only checked when the F4 family was declared) |
| `scalars_modified` | the held-state guard: any of the five scalars (also when F4 is not declared) or the ObservationPolicy values/object differ from construction (NEW coverage), judged first, before any selection source runs, and again at the commit gate |
| `configuration_binding_invalid` | the live configuration cannot be bound at a boundary (unreadable or foreign held value, a governed slot unknown to the family table, or a governed subclass that did not implement `_gl_configuration_members`) |

Which refusal applies to which defect (do not conflate them):

* A defect in the PERSISTED record (member absent past the cutoff, malformed, unknown version, inconsistent digest, or unequal to the live configuration) is a durable `EffectTimeRefusal` with `authorization_binding_changed`; `execute` raises the existing `PermissionError`. On the pin-export path the same defect gives a non-`active` result with no payload (state `unknown`) and no `EffectTimeRefusal`; at claim issuance, no claim.
* A malformed LIVE configuration (a scalar edited to an unbindable value, an unreadable held profile) never reaches a classification: construction-style adapter code `configuration_binding_invalid` is raised before any state write (not a durable reason code, no refusal row), and the pin export reports `unknown`. `configuration_binding_status`, being read-only, RAISES `BindingInvalid` in that case instead of returning a status (`test_d09`); callers must treat the exception as "cannot classify".
* The base hook `_gl_configuration_members` has no "do not bind" answer. It raises `BindingInvalid("hook_not_implemented")`: a governed subclass that forgets to override it cannot be constructed, and would refuse any decision (`test_d08`).

## 9. Behaviour changes that tighten

* Newly authorized governed decisions persist the extra member (`runtime_authority` becomes a one-key dict for a workflow with no profile).
* All five scalars and the ObservationPolicy values must be exact ints in 0..2147483647 at construction, even when the F4 family is not declared. A host that supplied a float or a larger value now gets `host_scalar_invalid`. (The pre-existing extreme-tolerance `OverflowError` defect of the protected `bounded.py` is unrelated and untouched.)
* `tests/test_governed_policy_composition.py::test_i04...` characterized the gap that this closes. It is converted IN PLACE into its successor form (same fixtures, final assertion inverted to the refusal, a SUPERSESSION RECORD in the docstring quoting the original assertions verbatim; no xfail, because the CI junit gates require zero skipped tests); a further successor with the classification and the durable refusal row is `tests/test_effective_configuration_binding.py::test_c03_the_documented_i04_scenario_now_refuses`. Its original passing result is in `docs/evidence/d06/baseline-b7eb11a-v7pin.log`.

### 9a. Behaviour tightening for governed workflows: scalar and ObservationPolicy validation (before / after)

Applies to the composed workflow (since the first D-06 change) AND, with the follow-up, to the three dedicated workflows. The five scalars are `status_max_age_seconds`, `approval_max_age_seconds`, `clock_tolerance_seconds`, `identity_max_age_seconds`, `mandate_max_age_seconds`; the ObservationPolicy values are `max_age_seconds` and `clock_tolerance_seconds`.

| | before (b7eb11a) | after |
|---|---|---|
| The two F4 scalars, F4 declared / dedicated F4 | validated by the F4 module (unchanged) | validated by the F4 module (unchanged) and by the binding |
| The two F4 scalars, F4 NOT declared (composed without F4; dedicated class age and class unreadable) | not validated by the governed layer; any value the base class accepted | must be exact ints 0..2147483647, else construction refuses `host_scalar_invalid` |
| `clock_tolerance_seconds`, `identity_max_age_seconds`, `mandate_max_age_seconds` | not validated by the governed layer | must be exact ints 0..2147483647, else `host_scalar_invalid` |
| ObservationPolicy `max_age_seconds` / `clock_tolerance_seconds` | not validated by the governed layer | exact ints 0..2147483647, else `host_scalar_invalid` (an absent ObservationPolicy stays allowed and is bound as an explicit null) |
| Post-construction edit of any of these | only the two F4 scalars (when F4 declared) were guarded | any edit, including a type change such as `True` for `1` or an in-place edit of the ObservationPolicy object, is refused as `scalars_modified` before any selection source runs and again at the commit gate |

Inputs that therefore now FAIL construction in every governed workflow, whether or not F4 is declared: a `bool` (`True`), a `float` (`60.0`, `1.5`), a `str` (`"60"`), `None`, a negative int, and an int above 2147483647, for any of the five scalars and the two ObservationPolicy values. Hosts that passed such values to a governed workflow must correct them; the plain `BoundedAuthorizationWorkflow` is unchanged. The pre-existing extreme-tolerance `OverflowError` defect of the protected `bounded.py` is unrelated and untouched. Tests: composed `test_e01`/`e02`/`e03`, dedicated `test_d09`/`d10`/`d12`.

## 10. Honest limits (do not state otherwise)

* The record store is unsigned local JSON (existing tests rewrite persisted digests in place). The binding guards configuration DRIFT, restart and rebuild mix-ups, partial upgrades and buggy writers. It does NOT defend against a party who can rewrite the store: such a party can forge a whole decision, a member, or the data the cutoff is judged against.
* **No anti-rollback guarantee.** There is no durable ratchet in the Control Plane. Rolling back to an older configuration whose digest equals an older persisted binding revives that old decision, now visibly (`bound`). Anti-rollback and a signed decision store remain a separate held item (EXT-S4).
* The `legacy_cutoff` is host configuration with no durable provenance. A host that sets it too high (bounded only by the decision count) or an editor of the store defeats the check. Below the cutoff a stripped member is indistinguishable from a legacy record (`test_d04`).
* **Mint versus check without a profile.** For a workflow with no runtime-authority profile (the dedicated F4 workflow), the lifecycle tells "mint a new decision" from "check an existing one" only through the `_EXEC_DECISION` context variable that `GovernedLifecycle.execute` sets. A caller that reaches `_resolve` outside it (a direct base-class call, a nested decide) collapses to the base equality, in which Python conflates numerically equal values (`30.0 == 30`, `True == 1`), so a numerically equal malformed persisted member would not be classified `invalid` on that route. What was verified: the public governed `execute()` path (all four workflows) classifies such a record `invalid` and refuses it durably (`test_d17b`, composed `test_d01[float_scalar]`), and the guard in `_resolve` that adds the reason when equality conflates values is mutation-tested. A direct non-`execute` route into `_resolve` without a profile (only `local_authority_effect` issuance without a profile could be a candidate) was not found by the reviewer and was not driven here; it is an open, unverified edge, not a claim of safety.
* Mixed fleets: a legacy writer can still append records without the member; new readers refuse them past the cutoff, legacy readers accept them.
* The binding checks the executing workflow's configuration as bound (effective values for the F4 scalars and the ObservationPolicy; see the masked-host-change limit below). Registry freshness, revocation visibility and epoch floors remain host custody duties. Workers given different `observation_policy` or scalar values refuse each other's decisions (correct, but operationally visible).
* **Host change masked by a stricter Registry value.** A change in the host configuration that is completely masked by a stricter effective Registry value may not change the effective-configuration binding and therefore may not cause refusal. The binding carries the EFFECTIVE values (frozen contract, section 4 of `docs/family-migration/final-three/02-architect-authorization-and-contract-freeze-2026-10-29.md` in the Registry), so this applies only where the workflow's F4 scalars (`status_max_age_seconds`, `approval_max_age_seconds`) or ObservationPolicy values (`max_age_seconds`, `clock_tolerance_seconds`) are narrowed by a Registry family and a host change leaves every effective value and every declared family's effective-policy digest unchanged. Example covered by a test: host ObservationPolicy `max_age_seconds` 300 -> 299 under a Registry value of 60 is accepted as bound (`tests/test_final3_composed_binding.py::test_b03b_...`); the F4-scalar case follows from the same code path but has no dedicated test. This is not protection against every host change and is not a guarantee: a host change that moves an effective value, any change to the host PROFILE (`host_profile_digest` is a member, so a host profile edit is refused even if the final profile is identical), the constructor scalars `clock_tolerance_seconds`, `identity_max_age_seconds` and `mandate_max_age_seconds` (bound for equality), the scope and the declared family set are all still refused. The activation-ledger configuration digest covers the host values but is a separate check.
* Scope: the four governed workflows bind (section 3a); the plain `BoundedAuthorizationWorkflow` does not (it is not governed). A decision minted by one governed workflow is refused by another (different scope/profile/family members).
* A legacy decision below the cutoff keeps the previous gap: its F4 scalars and ObservationPolicy are still unbound.

## 11. Evidence

Tests: `tests/test_effective_configuration_binding_unit.py` (pure), `tests/test_effective_configuration_binding.py` (real workflow), `tests/test_effective_configuration_binding_legacy.py` (frozen fixtures, legacy reader, separate process; helpers `tests/d06_support.py`, `tests/d06_worker.py`), `tests/test_effective_configuration_binding_dedicated.py` (the three dedicated workflows: mint, same-config accept, changed scalar / ObservationPolicy / family value / host profile refuse, missing member refuse, legacy below the cutoff, held-state, construction refusals). `test_h05` and `test_i04` are converted IN PLACE into their successor form (same fixtures, assertions inverted to the new outcome, a SUPERSESSION RECORD in the docstring quoting the original assertions verbatim); no xfail/skip is used in any gated suite, because the CI junit gates require `skipped == 0` (a strict xfail is reported as skipped). Frozen legacy fixtures `tests/fixtures/d06_legacy_store_*.json` (exact provenance): only the composed and f4_noprofile fixtures were committed BEFORE the source change (3dc2483); the four dedicated fixtures and `d06_legacy_store_meta_dedicated.json` were committed together with the dedicated source change (74ad2fa). All five were GENERATED by the unchanged prior code (b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa) via the committed generator `docs/evidence/d06/gen_legacy_fixture.py` (`dedicated` mode runs it over a `git archive b7eb11a` tree), and the b7eb11a classes load all six stores (independent review probe `probe5_fixtures_oldload.py`). Raw baseline and final outputs, the protected-evaluator hashes, the mutation harness and its logs, and the draft CI Scope Declaration: `docs/evidence/d06/`. These are developer evidence, not independent qualification. Registry pin note (added 2026-10-29): the D-06 test files run under any pin in `ACCEPTED_PINS` (`tests/test_f5_class_unreadable_governance.py:28`: r08-v5 `6c3e5e4`, r08-v6 `42a6663`, r08-v7 `b73c59e`, r08-v8 `a40fe755`; enforced at lines 43-44); their file docstrings that say 'r08-v7 pin' are narrower than that gate, and their irreversibility-family cases need a Registry containing r08-v7 (the v7 or v8 pin). Behaviour under the v5/v6 pins was not run (UNVERIFIED). Mutation-count errata: `docs/evidence/d06/ERRATA-mutation-counts-2026-10-29.md`.

## 12. Status note (2026-10-30; append-only; earlier text above is as authored)

* "F3-A independent qualification PENDING" wording elsewhere in this file and in `CHANGELOG.md` is as of authoring. Current lifecycle: **original F3-A: FAIL** under the frozen oracle (DEV-PE-1, 23 failed assertions), a permanent historical result. **Successor F3-A:** conditional technical PASS under OCS-F3A-DEV-PE-1-INTERPRETATION/1.0, as reported by the successor session; its evidence has not been published in custody and is not independently accepted. **F3-B:** scoped technical PASS. **Formal independent acceptance: NOT ESTABLISHED.** Final Tier 1: DEFERRED, NOT WAIVED. Production: HOLD. The two qualification results are separate and neither replaces the other.
* The masked host-change limit in section 10 stays as stated. A25(a) (authority-domain isolation) and A25(e) (host and effective digest isolation) remain open qualification obligations, tracked in the Registry record `docs/family-migration/final-three/12-f3-closeout-coverage-and-adoption-status-2026-10-30.md`.
