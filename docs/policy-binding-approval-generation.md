# policy-binding/0.1: approval generation, approval-commitment/0.2 and registry freshness ceilings (R6)

Status: opt-in, builder-tested, NOT independently reviewed or qualified. Release, publication and production: HOLD. This is a LOCAL check
against trusted host configuration. It does not complete the Registry V1 authority-to-effect guarantee.

## What it does

A host may set `RuntimeAuthorityProfile.policy_binding` (module `agent_control_plane/policy_binding.py`). Absent, every dump, every
commitment and every row is byte-identical to before (golden literals in `tests/test_policy_binding_approval_generation.py`).

| Member | Meaning |
|---|---|
| `binding_digest` | Opaque effective-policy-identity digest (EXT-S1-5). Required for `selected`; MUST be absent for `withdrawn`. |
| `selection_epoch` | Evidence of the issuing selection. Carried and committed, never interpreted, never used as the generation. |
| `activation_ref` | `sha256:` digest naming the governing activation transition. |
| `policy_generation` | Opaque strict integer (1 to 2147483647) supplied by the enforcing consumer. Never derived from `selection_epoch`. |
| `disposition` | `selected` or `withdrawn` (withdrawn is PROVISIONAL, see below). |
| `age_ceilings` | `{action_id: seconds >= 1}` registry-narrowed freshness ceilings. Empty while unset. |

* `activation_sequence` (the durable activation-log position) is RESERVED. It is not a member; it is refused as an unknown member of the
  binding and of the approved spec until EXT-S4-0 defines it. Epoch, activation-log position and generation are three different things.
* With a binding the approval commitment is `approval-commitment/0.2`: a tagged preimage in which the effective policy identity
  (`binding_digest` when selected, `activation_ref`, `selection_epoch`, `disposition`) and the generation are separate members. The trusted
  profile selects the verifier; an approval cannot select it. An unknown commitment version is refused even when the commitment matches.
* The approved `runtime_authority` spec must carry `approval_commitment_version`, `policy_generation` and `policy_activation_ref`. Each is
  compared by equality with the TRUSTED profile (strict type, range, canonical form). Missing, invalid, mismatched generation and
  mismatched activation have distinct typed codes (`runtime-authority-reasons/0.3`).
* Freshness ceilings. A ceilinged profile must carry a freshness/0.1 profile with `anchor_deadline_to_inputs`, every ceilinged action id
  must exist, and `class base + max_age_extension_seconds` may not exceed any ceiling. This is checked at construction AND at every
  evaluation, because `model_copy` and `snapshot` skip validators. `bounded.py`, `freshness.py` and `local_authority_effect.py` are not
  changed: with the invariant, an extension can never push an effective bound above a ceiling, and the anchored deadline
  (`min(opened + bound, observed_at + bound)`) closes the 2x window for the status inputs judged through the freshness check (`_fresh`:
  grant status, identity, mandate, conflict, policy, approval) AND, under a binding, for the purpose-status observation: `validate_extensions`
  adds `observed_at + bound` of the purpose observation to the same deadline collector (the class bound for a direct read, the recorded
  bound of an accepted cached snapshot). A purpose status that met its bound at evaluation (for example 59 s of a 60 s ceiling) is
  refused before dispatch once the deadline passes (`check_expired_before_dispatch`, no effect). Without a binding the purpose age is judged at
  evaluation and is not anchored (unchanged legacy behaviour). The dispatch guarantee does NOT cover evidence obligations or destination
  observation, which have their own age paths and are not ceilinged. No maximum age is adopted (the Architect has
  not adopted one); the pre-existing `OverflowError` at about 2.5e11 seconds is not addressed here.

## What it cannot do (negative controls, pinned by tests)

The Control Plane has no durable memory and compares equality only. Therefore:

1. An older generation presented with a profile that still carries the older binding revives the older approval.
2. A supplier that stops emitting the binding restores the legacy preimage and revives the legacy approval. An absent binding is the legacy
   path only when trusted consumer state establishes that Registry V1 participation was never required or activated; this module never
   infers withdrawal or non-participation from absence.
3. It cannot check that the binding members are the ones a durable activation log holds.

Preventing these belongs to the enforcing consumer: a durable `scope_required` ratchet, withdrawal persistence, monotonic generation and
atomic effect-time claim verification. Those are EXT-S4 and are NOT implemented here. The tests
`test_control_older_generation_with_an_identical_binding_revives_the_older_approval` and
`test_control_binding_dropped_revives_legacy_approval` prove the local candidate cannot prevent revival after durable-state regression.
Approval authenticity remains the existing unsigned trust model.

## Contract-blocked and provisional

* `activation_sequence`: RESERVED (EXT-S4-0).
* **A withdrawn binding still authorizes locally.** The Control Plane does not treat `withdrawn` as a refusal: an approval minted under a
  withdrawn binding (its own `activation_ref` and generation) is authorized, and the earlier approvals are refused only because their
  generation and activation no longer match. Whether a withdrawn scope may authorize at all is a consumer decision (EXT-S4-0/EXT-S4-2); nothing
  here stops authority on withdrawal.
* `disposition = "withdrawn"`: PROVISIONAL representation (consumer-supplied `activation_ref` and `policy_generation`, no digest, no
  ceilings). Zero, empty, null and copied digests are refused, also when validators are bypassed. EXT-S4-0 must define the canonical
  withdrawal binding; if it references a withdraw entry differently this shape must be replaced.
* The eight reason codes are PROPOSED and NOT RATIFIED: [runtime-authority-reasons-0-3-code-ownership.md](runtime-authority-reasons-0-3-code-ownership.md).
* The generation range is an interim conservative subset of the 1 to 2^53-1 range EXT-S1-5 reserves for EXT-S3-4.

## Rollback

Additive and opt-in; without a binding behaviour is byte-identical, so reverting changes nothing for a caller that never set it. For a
live registry-managed scope: stop emitting `policy_binding` and re-issue approvals under the legacy profile FIRST (the older profile model
has `extra="forbid"`, so a profile carrying `policy_binding` fails to construct: fail closed), then revert. The interval after stopping
emission is the revival window above and needs explicit acceptance. Do not revert `runtime_authority_reasons_0_3.json` while any recorded
row carries label 0.3; prefer a forward fix. 0.1 and 0.2 are never edited.

## Not in this change

Durable consumer activation ratchet, EXT-S4, atomic Route B effect-time integration, production trust-root activation, any Runtime change
(Runtime does not exercise a binding profile, so that integration is UNTESTED), `engine/safe_executor.py`.
