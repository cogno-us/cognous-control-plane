# rule-revision/0.1 (opt-in)

One record shape, `RuleRevision`, modelled on `VocabularyChange`, covers four rule kinds: `reason_registry`, `policy`,
`gate_implementation`, `merge_equivalence_rule`. Nothing is active unless a `RuleRevisionProfile` is passed to
`BoundedAuthorizationWorkflow(rule_revision_profile=...)`. The pinned default path is unchanged (for well-formed input; see opt-in-profiles.md). The reason registry is two labels:
`runtime-authority-reasons/0.1` is the original 121 codes (120 `typed_only`, 1 `recomputable`) in `schemas/runtime_authority_reasons_0_1.json`,
byte-identical to its pinned form; `runtime-authority-reasons/0.2` is the full set (164 codes: 163 `typed_only`, 1 `recomputable`) in
`schemas/runtime_authority_reasons_0_2.json`, the 0.1 entries unchanged plus the codes the opt-in profiles emit. A row carries 0.1 unless one
of its reasons is a 0.2 code, so default-path rows are unchanged. `runtime-authority-reasons/0.3` (172 codes) is a later immutable successor of 0.2 for the opt-in `policy-binding/0.1` profile; 0.2 is not edited.

## Row
`rule_ref`, `from_digest` (None on an adoption row), `to_digest`, `reviser`, `signer`, `authority_ref`, `reason`, `supersedes`,
`recorded_at`, plus `revision_id` and `rule_kind` (needed to reference a row and to cover four kinds) and an optional
`declared_arity` (reason registry rows only). Rows are appended, never edited.

## Rules
- A digest is adopted only by a row whose `signer` is in `RuleRevisionProfile.signers` and differs from the `reviser`. Otherwise the
  rule resolves to `unknown` and the policy input holds with the existing code `policy_status_unknown`. The signer set is
  configured. The owner default (the owner signs until a second signer exists) is a configuration choice, not code.
- Self-signed and unconfigured-signer attempts are refused and kept as `rule_revision_refusals` rows. Unsigned rows are kept but never count.
- `from_digest` must equal the currently adopted digest (or the superseded row's `from_digest` when `supersedes` is set).
- `PolicyStatus.digest` (optional) carries the policy content digest. Decision and refusal rows carry `rule_identity`: per rule the digest,
  state, findings and `verified_through` (`none`, `revision_row_present`, `signer_independent_and_configured`,
  `digest_matches_signed_revision`), the level at which verification stopped. Findings are `no_signed_revision`,
  `unsigned_revision_row`, `self_signed_revision_row`, `signer_not_configured`, `digest_mismatch_with_adopted`, `observed_digest_absent`.
- `refusal_trends(..., vocabulary_changes=, rule_revisions=)` flags rows whose version predates that version's adoption row and sets
  `tainted_for_trend` on pre-split counts and on counts of rows predating adoption. Without those arguments the output is unchanged.
  A version with no adoption row (the pinned default) is not flagged.
- Arity: declared at signing (`declared_arity`) and measured (`measured_arity`: distinct operand shapes per code over a period, "as of T").
  Both are kept; `arity_flags` flags `measured_exceeds_declared` and `arity_undeclared`.
- Recomputability is derived per row (`derive_recomputability`): `underivable` when the operands are not retained (a real decision row keeps only
  allow-listed scalars plus a commitment, so this is the usual case), `typed_only` when operands are present but do not reproduce a refusal,
  `recomputable` otherwise. `reason_kind` stays the declared expectation. `recomputability_flags` reports `derivation_unavailable` where a code
  declared `recomputable` is `underivable` (not a verdict on the declaration), `declared_overclaim` only where operands are present and the
  derivation shows the declared kind cannot hold (the integrity-relevant direction), and `declared_underclaim` (informational).

## Limits
This moves trust to the revision signer; it does not remove it. All of it is a join over rows in the record store. The store (`BoundedRecordStore`) is a plain JSON file under a same-host lock
with **no keyed integrity check: there is no HMAC key protecting it** (the only HMAC in this package signs replay bundles, `signing`).
Anyone who can write the file can rewrite rows, so it gives visibility to an honest reader, not tamper evidence. `signer` and
`reviser` are asserted names: they are checked against the configured signer set and against each other, but nothing authenticates who
supplied them, and the signer remains an asserted name unless a keyed proof is configured (none is built). An outside-held digest is a
separate control.
Host rules (registry, gate implementation, merge rule) are checked from `RuleRevisionProfile.host_digests`, which the host computes; the
workflow does not compute them.

## ODES contract delta
Optional members on decision and refusal rows: `rule_identity` (object: `rules` map of ref to `{digest, state, verified_through, findings}`,
and `unknown` list). A `rule_revision` record and `rule_revision_refusal` record shape as above. Drafted since in ODES as `contracts/rule-revision` (`0.1.0-draft`, not frozen); the journal contract declares `rule_identity` as an optional member. The Control Plane code is unchanged by that draft.
