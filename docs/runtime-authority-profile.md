# Runtime authority profile 0.1

Opt in with `BoundedAuthorizationWorkflow(runtime_authority_profile=RuntimeAuthorityProfile(...))`.
This is a nonselected implementation of Moltbook 101526_A K1–K5, tracked in
[cognous-control-plane issue 32](https://github.com/cogno-us/cognous-control-plane/issues/32).
It does not change historical hub selection, authorize publication, or establish
production trust. The baseline is c7f122ba3a6e39f9268a7163c99be3ee514cd97e.

## Authority and trust

The trusted host supplies a detached catalogue snapshot and admitted Ed25519
producer public keys. Grant holders cannot select action classes or trusted
validator keys through a proposal. The resolver is a host-injected trust boundary;
its `authenticated` flag is an adapter assertion, not remote authentication proof.
Synthetic resolvers require both explicit profile permission and the test clock.
Use an authenticated deployment adapter for operational use. This component does
not implement key custody, key-status distribution or institutional adoption.

The authority context's `runtime_authority` object carries profile version,
`required_inputs`, canonical `required_inputs_digest`, and `evidence_criteria`.
Descriptors are objects containing `input_type` and `input_id`, sorted by those
fields for commitment. They identify actual resolution reads; the existing grant,
policy, evidence and approval bindings establish value/scope semantics.

Every required approval carries `runtime_authority_commitment`, computed by
`approval_commitment(profile, context)`. It binds this object, the governed
catalogue and producer keys, grant purpose reference and expiry. The proposal
commitment, grant revision and policies remain independently checked. A planner
cannot remove an input or weaken a criterion without invalidating the approval.
Changing the catalogue or admitted key set requires approval renewal. The fixture
builds its descriptor set during fixture preparation; production issuance must use
an authority-approved input list, not learn acceptance requirements from the run.

## Durable resolution journal

`check_events` is an append-only opening/input/completion/interruption journal in
the existing locked, fsynced JSON store. Open before reading the resolver; persist
each minimized read before returning it to resolution. Each event binds a unique
check ID, proposal commitment, stage, owner token and action class. Effect checks
also carry the persisted decision/effect identities. A completion means resolution
finished, not that authorization, durable decision recording or effect commit
succeeded. Time-floor checks, decisions and refusals remain separate durable rows.

Stable per-check flock files prevent recovery from closing live checks. Process
exit releases the lease; `recover_interrupted_checks()` closes abandoned openings
once. Never unlink lock files while clients can use them. Recovery infers no
external destination state and never dispatches. The store is Linux local-filesystem
only and assumes cooperating writers and trusted storage access. It rewrites the
whole JSON document per append; production volume and retention require a separately
qualified storage implementation. Power-loss recovery is not established by a
process-exit test.

Resolver exceptions yield `status_unreadable`, retain prior reads, and lead to an
effect-time refusal before dispatch. A missing snapshot never yields
`grant_revoked`. Irreversible classes refuse on unreadability; reversible bounded
tolerance requires the trusted resolver's `cached_grant_status` positive snapshot,
within class age, scope and grant validity. Known denial overrides cache. No cache
means HOLD. Reopen predicates invite full reevaluation, never direct retry.

## Authenticated evidence criteria

Install the `runtime-authority` extra for Ed25519 verification. `minimum_count`
requires a strict integer; `exact_members` compares distinct members to the
approved manifest and rejects duplicates or unrelated members. An approved member
set that is empty does not pass (`evidence_criterion_unmet`). EvidenceStatus's
`validation_record` wraps exactly `statement` and hexadecimal `signature`.
The canonical signed statement contains version `validation-record/0.1`, producer,
obligation, subject digest, observation time, institution/domain/tenant and values.
The gate verifies identity admission, signature, scope, subject and freshness.
It evaluates only typed predicates, never executable source expressions.
Signature validity is attribution, not validator correctness or independence.

## Purpose and destination capability

A grant may contain `purpose_ref` with owning `system`, `record_id` and `epoch`.
The trusted adapter implements `purpose_status(ref)` and returns PurposeStatus.
Resolve at decision and effect time. Closure, epoch change or unreadability holds;
status-only sources cannot establish epoch protection. No push notification alone
suffices. Without the reversibility profile, purpose outages refuse for every class and only fresh positive purpose snapshots are accepted; with the opt-in `reversibility/0.1` profile, a cached open snapshot is accepted for reversible classes within the age bound (see reversibility.py). Grants without a purpose still
require expiry; no expiry is synthesized for legacy grants.

An optional approval-bound `expected_effective_grant_digest` with derivation
`effective-grant/0.1` requires the runtime's `sqlite-effective-grant/0.1` destination
capability. It travels from the revalidated decision to the actual commit call.
The runtime compares authoritative local permission state under the same SQLite
transaction as the effect. Remote permission, purpose and policy changes outside
that transaction retain a race. Omitting this precondition does not claim atomic
authority. Existing C0/C1 limits and release holds remain.

## Refusal vocabulary and consumers

Profile decisions and refusals carry `runtime-authority-reasons/0.1`, or `runtime-authority-reasons/0.2` when one of their reasons is a
code that only 0.2 registers (a code emitted by an opt-in profile: operation identity, freshness, holder inventory, merge, reversibility,
dedupe, terminal revocation). 0.2 is a superset of 0.1, because a row mixes codes and carries one label. The registry
identifies reason kinds; `grant_revoked` is reproducible from its captured status.
Other reasons are typed classifications unless their registry declares operands.
`VocabularyChange` records adopted changes without rewriting prior rows.
`refusal_trends` preserves unknown versions and reports per-code shares with
explicit exposure; disappearance is only an investigation signal.

### Reading a blocked count

The registry (`runtime-authority-reasons/0.1` and `/0.2`) classifies a code only as `typed_only` or `recomputable`. It does not separate
"an input the decision needs was unavailable" from "the inputs were read and the rule withheld". The workflow emits `authorized` or `hold`; the
`deny` result is declared but emitted only by the Microsoft AGT adapter. A count of blocked decisions must therefore not be read as a
count of denials. The lists below are a reading of the emission sites in this repository; they are not declared in the registry.

- Unavailable-class codes (a needed input was missing, unreadable or not read): `status_unreadable`, `authority_context_missing`,
  `role_mapping_missing`, `issued_grant_missing`, `required_input_not_read`, `purpose_unreadable`, `evidence_verifier_unavailable`,
  `check_lease_unavailable`, `holder_inventory_missing`, `operation_id_missing`.
- Policy-class codes (inputs were read and a rule was not met), for example: `target_out_of_scope`, `amount_exceeded`,
  `effect_count_exceeded`, `forbidden_payload_field`, `undeclared_payload_field`, `missing_required_payload_field`,
  `missing_requested_permission`, `grant_revoked`, `grant_suspended`, `purpose_closed`, `approval_not_active`,
  `required_approval_missing`, `delegation_profile_unsupported`, `action_blocked`, `missing_effect_limits`, `missing_amount_limit`, `effect_limit_malformed`, `authority_limit_malformed`, `invalid_manifest`.
- Codes that cover both: `required_evidence_not_current` (no evidence record, or a record whose state is not current),
  `context_unknown_requires_hold` (missing, non-current or stale evidence under `hold_effect`), `policy_status_unknown` (policy status
  not readable or not active, and an unadopted rule digest), `grant_not_active` (with the runtime-authority profile off: an unreadable or a
  non-active grant status; with it on the two split into `status_unreadable` and the `grant_*` codes) and `purpose_unreadable` (also
  emitted for a readable snapshot older than the class bound). For these, read `resolution_inputs` (`missing`, `read_state`) on the decision.

A typed unavailable/withheld class member in the registry is a freeze item (a registry change).

New optional fields serialize only when present, preserving historical empty
shapes. This requires Pydantic 2.12 or newer. Old readers can silently discard new
fields; they cannot claim conformance to this profile. Use the explicit new
Replay/consumer mapping and retain original journal rows, vocabulary version,
purpose read and binding. No automatic historical migration or selected-pin
update is performed.

## Verification and provenance

The tests are original synthetic fixtures derived from K1–K5 in the supplied
Cognous Engineering Addendum Moltbook 101526_A dated 15 October 2026. Discussion
posts are idea provenance, not imported third-party implementation. Existing
Apache-2.0 licensing applies. Tests assert destination absence on blocked paths,
actual process exit/recovery, producer tampering, set coverage, input omission,
purpose reopening, expiry and vocabulary history. Cross-component execution and
consumer preservation belong in cognous-stack-qualification. K6 is a separate PRP
benchmark and cannot qualify runtime enforcement.
