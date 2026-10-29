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

* Module: `src/agent_control_plane/effective_configuration_binding.py` (pure; imports only `commitment`). Lifecycle: `GovernedLifecycle._resolve` (non-protected `registry_governed_lifecycle.py`). Live members: `GovernedPolicyWorkflow._gl_configuration_members` (`registry_governed_policy.py`).
* **Mint** on every AUTHORIZED decision of the composed governed workflow. Always on: there is no constructor switch, no default-off mode. A hold persists no binding (as before); a hold stays a hold.
* **Check** on `execute` and on the pin-export / claim path. Both re-resolve through `workflow._resolve`, so the one override covers both; a test pins each. The base class's existing equality `current != persisted.binding` then does the refusing: the live member is placed in the rebuilt binding (or, for a legacy decision, deliberately left out), so a mismatch yields the registered reason `authorization_binding_changed` as a durable `EffectTimeRefusal`, and `execute` raises the existing `PermissionError("authorization-critical inputs changed before effect")`. The destination is not touched and no attempt is created.
* Not covered, by scope: the plain `BoundedAuthorizationWorkflow` mints nothing (it has no governed configuration to bind), and the three dedicated single-family workflows (`registry_f4_age_governance`, `registry_f5_class_age_governance`, `registry_f5_class_unreadable_governance`) keep no configuration hook because their modules were outside the authorized file set. They mint no member and their records are byte-identical to before (`test_h05`). Governing them needs a one-hook addition in each module and is reported as a follow-up.

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

`GovernedPolicyWorkflow(..., legacy_cutoff=0)`. The cutoff is the number of rows in the append-only `decisions` list at activation, supplied by the host as an explicit finite integer. A decision without the member and with index below the cutoff executes under the previous semantics and is reported `legacy`. Rules:

* Default 0: no legacy decision is accepted. There is no wildcard value.
* A cutoff that is not an exact `int` (bool, float, str, None), is negative, or exceeds 2147483647 is refused at construction (`legacy_cutoff_invalid`).
* A cutoff larger than the number of decisions in the store cannot describe "the decisions at activation" (the list only grows). It disables the legacy rule instead of accepting later appended records.
* Pre-existing decisions are never rewritten, re-signed or back-filled (a back-fill would manufacture a binding the issuer never saw). Existing approvals are untouched: `approval_commitment` is byte-identical, so every already-issued approval still validates (`test_a03`, `test_h01`).
* Procedure: stop old writers; count the decisions (`len(workflow.records.load().decisions)`); construct the new workflow with that number as `legacy_cutoff`; let legacy decisions drain (they execute or expire); then drop the cutoff (omit it). Nothing in the store changes. Do not leave a cutoff configured longer than needed: a legacy decision has no member to compare, so it keeps exactly the previous semantics including the previous gap (`test_a08`).

## 6. Reader compatibility matrix (carriage C2)

| Writer -> reader | Result |
|---|---|
| legacy record -> new reader, no cutoff | REFUSE `authorization_binding_changed` |
| legacy record -> new reader, cutoff above its index | OK under the previous semantics, reported `legacy` |
| legacy record at/after the cutoff (legacy writer appends after the upgrade, or a stripped member) | REFUSE |
| new record, same configuration -> new reader | OK (`bound`), also across a restart and in a separate process |
| new record, different configuration (any member) -> new reader | REFUSE, durable `EffectTimeRefusal`; execute and pin-export both |
| new record -> LEGACY binary | REFUSE (fail closed): its `current != persisted.binding` sees a one-key-larger dict (`test_b01`, `test_b03` run the unchanged comparison code on a new record) |
| legacy writer appends after upgrade (mixed fleet) | new readers refuse it past the cutoff; legacy readers accept it (unchanged legacy semantics; cannot be prevented in code; "stop old writers before upgrading" stays an operational requirement) |
| new writer, legacy peer executing it | peer REFUSES, so a mixed fleet cannot bypass the binding on records the new writer mints |
| unknown future `version` -> this reader | REFUSE (closed version set) |

## 7. Restart and recovery

Nothing is held in memory. The persisted member says what the decision ran under; the live process says what runs now. Same families, values, scalars and policies give an equal digest and the decision resumes. A different F4 scalar, other scalar, ObservationPolicy (either value, or present versus absent), host or final profile, scope, family set, family contract version, schema revision or effective value refuses. There is no "re-bind": a changed configuration needs a new decision, and an operator who changes configuration must expect to re-issue in-flight decisions. A configuration refusal is a pre-dispatch refusal row, not an attempt, so an attempt already `failed` at the commit gate still blocks automatic retry (`test_f03`). `test_c01`/`c02`/`c04`/`c05` run recovery in a separate Python process against the persisted store.

## 8. Exact refusal semantics

Durable (reuses the registered code; no new durable reason code, no new vocabulary version): `authorization_binding_changed` as an `EffectTimeRefusal` with `reason_vocabulary_version` set by the existing `vocabulary_for`. On the pin-export path the result is not `active` and carries no payload (`test_g02`, `test_c04`).

Pre-write adapter refusals (the existing closed adapter vocabulary of the governed workflows; not durable reason codes; raised before any state write):

| code | when |
|---|---|
| `legacy_cutoff_invalid` | constructor `legacy_cutoff` is not an exact int in 0..2147483647 |
| `host_scalar_invalid` | at construction, a scalar or ObservationPolicy value cannot be bound (previously only checked when the F4 family was declared) |
| `scalars_modified` | the held-state guard: any of the five scalars (also when F4 is not declared) or the ObservationPolicy values/object differ from construction (NEW coverage), judged first, before any selection source runs, and again at the commit gate |
| `configuration_binding_invalid` | the live configuration cannot be bound at a boundary (unreadable or foreign held value, a governed slot unknown to the family table) |

## 9. Behaviour changes that tighten

* Newly authorized governed decisions persist the extra member (`runtime_authority` becomes a one-key dict for a workflow with no profile).
* All five scalars and the ObservationPolicy values must be exact ints in 0..2147483647 at construction, even when the F4 family is not declared. A host that supplied a float or a larger value now gets `host_scalar_invalid`. (The pre-existing extreme-tolerance `OverflowError` defect of the protected `bounded.py` is unrelated and untouched.)
* `tests/test_governed_policy_composition.py::test_i04...` characterized the gap that this closes. It is kept verbatim as a strict `xfail` with a comment citing the authorization; its documented successor is `tests/test_effective_configuration_binding.py::test_c03_the_documented_i04_scenario_now_refuses`. Its original passing result is in `docs/evidence/d06/baseline-b7eb11a-v7pin.log`.

## 10. Honest limits (do not state otherwise)

* The record store is unsigned local JSON (existing tests rewrite persisted digests in place). The binding guards configuration DRIFT, restart and rebuild mix-ups, partial upgrades and buggy writers. It does NOT defend against a party who can rewrite the store: such a party can forge a whole decision, a member, or the data the cutoff is judged against.
* **No anti-rollback guarantee.** There is no durable ratchet in the Control Plane. Rolling back to an older configuration whose digest equals an older persisted binding revives that old decision, now visibly (`bound`). Anti-rollback and a signed decision store remain a separate held item (EXT-S4).
* The `legacy_cutoff` is host configuration with no durable provenance. A host that sets it too high (bounded only by the decision count) or an editor of the store defeats the check. Below the cutoff a stripped member is indistinguishable from a legacy record (`test_d04`).
* Mixed fleets: a legacy writer can still append records without the member; new readers refuse them past the cutoff, legacy readers accept them.
* The binding checks the executing workflow's HOST-supplied values. Registry freshness, revocation visibility and epoch floors remain host custody duties. Workers given different `observation_policy` or scalar values refuse each other's decisions (correct, but operationally visible).
* Scope: only the composed `GovernedPolicyWorkflow` binds (see section 3).
* A legacy decision below the cutoff keeps the previous gap: its F4 scalars and ObservationPolicy are still unbound.

## 11. Evidence

Tests: `tests/test_effective_configuration_binding_unit.py` (pure), `tests/test_effective_configuration_binding.py` (real workflow), `tests/test_effective_configuration_binding_legacy.py` (frozen fixtures, legacy reader, separate process; helpers `tests/d06_support.py`, `tests/d06_worker.py`). Frozen legacy fixtures: `tests/fixtures/d06_legacy_store_*.json`, generated by the UNCHANGED prior code (b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa) before any source change. Raw baseline and final outputs, the protected-evaluator hashes, the mutation harness and its logs, and the draft CI Scope Declaration: `docs/evidence/d06/`. These are developer evidence, not independent qualification.
