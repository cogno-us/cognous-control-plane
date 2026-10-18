# Bounded authorization-to-effect contract

Status: public synthetic pilot; not a production authority, identity, or payment system.

## Supported upstream interfaces

This implementation is pinned and tested against the following interface conventions:

- Agent Action Manifest v1.1 at commit 46c950bed37fe3812000895430bc0312d29e37ce.
  Manifest, payload, and proposal commitments use SHA-256 over sorted compact UTF-8
  JSON with ensure_ascii=false and allow_nan=false, prefixed with sha256:.
- Alvorada Authority Context 0.1.0 at commit
  fb3d97938969a89e149e8ff8db2756091d1233fc. The serialized
  interface_status value remains proposed_pending_governor_review.
- BitRep v1 at commit 5b5077dafde232a7801cb425c4efddcffb468723.
  A verification result establishes only the verification assertions defined by
  that contract; it does not issue institutional authority.
- The Index local blockchain reference at commit
  d5e45d275cb301d9684b543e93b05997991d1cf2. Chain inclusion and wallet
  attribution are evidence/provenance properties, not grants.

The control plane does not duplicate BitRep verification or The Index consensus
and does not introduce a central authority over The Index.

## Runtime ownership

The Manifest declares the proposed action envelope. The Control Plane resolves
current inputs and makes a runtime decision. Institutions own mandates, grants,
approval records and status sources. An execution adapter enforces the exact
checked operation and exposes delivery/reconciliation behavior.

A conforming manifest, valid signature, accepted verification-result JSON or
blockchain inclusion is therefore insufficient by itself to execute an effect.

## Resolver interface

The bounded workflow requires independently supplied resolvers for:

1. Authority Context and requirement/profile binding.
2. Current grant ID, revision, status and authority basis.
3. Acting identity, principal and delegation-chain validity.
4. Issuer/role mandate.
5. Approval records bound to grant revision, proposal commitment and policy versions.
6. Current policy versions/status and explicit authority-conflict status.
7. Required evidence status and freshness.
8. Explicit reviewer-role mapping where declaration labels differ from authority role IDs. Mapping records are institution-scoped, versioned, canonicalized and bound into the runtime decision.

SyntheticResolver is deterministic fixture infrastructure. Its authenticated
attribute is false by design. Caller-supplied dictionaries are not promoted to
trusted institutional facts. A production profile still needs authenticated
identity, mandate, approval, status, policy and evidence services, including
key custody, source authentication, clock uncertainty and revocation propagation.

## Decision binding

AuthorizationBinding records proposal commitment and separates it from the
legacy deterministic policy fingerprint. It binds:

- manifest ID/version/digest;
- actor/principal through Authority Context resolution;
- declared action and requested permissions through proposal commitment;
- adapter ID;
- target;
- canonical payload commitment;
- Authority Context and requirement ID;
- grant ID/revision;
- applicable policy versions.

The full RuntimeProposal commitment also covers amount, unit, effect count,
temporal fields, evidence references, correlation/run identifiers, risk metadata
and expected side effects.

Immediately before effect, the workflow resolves these inputs again and compares
the complete binding, including the requirement commitment and role-mapping version/digest. The supplied decision must exactly equal the persisted decision record, and its effect ID must equal the deterministic effect ID derived from the persisted binding. Changed payload, target, actor, adapter, manifest, grant
revision/status, approval, policy or required evidence prevents effect.

## Scope, validity and consequence handling

The pilot uses exact finite target and permission matching. No wildcard,
hierarchical permission inference, fuzzy matching or unit conversion is
implemented. Grant validity is exclusive at expires_at. Suspended, revoked,
unknown, stale or revision-mismatched status holds the effect.

The manifest consequence tier must equal the Authority Context requirement tier.
Canonical authority role identifiers are institution-scoped URNs. Legacy Manifest short labels may resolve only through an explicit versioned alias table for the same institution. Unknown mappings, ambiguous aliases, mapping digest/version changes, and implicit string-prefix equivalence all hold the effect. Manifest review roles must resolve explicitly to Authority Context approval role IDs.
Unmapped roles and unresolved, unknown, or stale authority conflicts hold the effect. Approval records must bind the exact proposal commitment and policy
versions and satisfy actor-independence when requested.

Required authorization evidence must be current and within the declared
max_age_seconds. Optional unknown context with
preserve_if_other_basis_suffices does not independently hold an otherwise valid
pilot action.

Delegated authority is accepted only when the identity/delegation resolver
returns an authenticated valid chain and the child grant itself remains within
the exact finite operation envelope. Production delegation must authenticate and
evaluate every ancestor; the synthetic resolver does not perform cryptography.

## Effect and recovery records

The bounded record store keeps linked:

- RuntimeDecision: authorized, hold or deny;
- stable effect_id;
- EffectAttempt with a new attempt_id for every execution/recovery attempt;
- execution acknowledgement or unknown/failure/partial state;
- independent destination EffectObservation;
- ReconciliationResult.

Authorized, attempted, acknowledged, observed and verified are not synonyms.
This pilot never emits a verified effect state because no independent verifier
is implemented.

A lost acknowledgement is reconciled against destination state before another
submission. An already applied effect is not re-applied. A partial effect is
held. If a future adapter cannot expose durable effect identity or authoritative
reconciliation, the safe behavior is to hold rather than claim exactly-once
delivery.

The durable JSON record and local destination are reopened in restart tests.
The bounded record store separately protects same-host append/read transactions;
see [record-store persistence](record-store-persistence.md). Destination and
workflow concurrency boundaries below remain unchanged.

## Limit semantics

Manifest v1.1 max_amount and max_effects are first checked per proposal. That
alone is not a cumulative budget guarantee.

For this isolated local pilot only, LocalRefundDestination additionally enforces
max_effects cumulatively per grant while holding a process-local lock. Concurrent
threads sharing that destination cannot both consume a one-effect grant. This is
not a distributed budget service and does not protect multiple processes or
remote destinations. Production shared budgets require destination-side atomic
reservation/commit or another reviewed consistency boundary.

## TOCTOU and destination guarantees

The workflow revalidates immediately before calling the destination, but there is
still a check-to-commit race unless authority/policy state and destination commit
share an atomic or reservation protocol. The local synthetic destination closes
only its own deduplication and cumulative-count race with a process lock and
atomic file replacement.

The validated execution envelope supplies the destination with the persisted effect ID, grant ID, effective max_effects and frozen proposal fields. The workflow does not re-read Authority Context or grant data after revalidation.

A production executor must declare:

- idempotency/effect-key behavior;
- authoritative observation semantics;
- partial-delivery representation;
- commit or reservation guarantees;
- credential scope and isolation;
- revocation/status maximum age and clock uncertainty;
- retry and reconciliation behavior.

## Migration and compatibility

Existing PolicyGate and execute_with_control APIs remain available. Their allow
result is not retroactively converted into an institutional grant. The legacy
fingerprint now includes payload content, and execute_with_control rejects a
provided adapter whose name/action_type do not match the approved proposal.

New integrations should use BoundedAuthorizationWorkflow for the pinned pilot
contract. Existing recorded allows remain historical policy-gate results only.

Scheduling and fleet orchestration remain outside this package. A future fleet
coordinator may supply bounded tasks/delegation and consume these decisions, but
it must not bypass the manifest, authority resolver, decision binding or executor
reconciliation interfaces.


## Resolver response binding and freshness

Resolver lookup arguments are not treated as proof that the returned record belongs to
the requested object. The pilot checks returned identifiers and institutional context
explicitly:

- grant-status responses bind grant ID, revision, status_ref, authority basis, institution and domain;
- identity responses bind acting identity, principal, institution and domain;
- mandate responses bind issuer, issuer role, issuance_record_ref, institution and domain;
- approval responses bind approval reference, role, grant/revision, operation commitment,
  policy versions, institution and domain;
- policy responses bind policy reference/version, institution and domain;
- conflict responses bind requirement ID, declared precedence references, institution and domain;
- evidence responses bind obligation ID, declared source_ref, institution and domain.

Tenant binding (bounded-authorization-effect/0.2). For a `TenantRuntimeProposal`,
the Authority Context, issued grant, grant status, approval and policy responses
must carry the proposal's exact `tenant_id`. A historical 0.1 `RuntimeProposal`
cannot establish tenant equality, so it holds with `tenant_proposal_required`
when any of those inputs carries a `tenant_id`; 0.1 behaviour is unchanged when
no tenant is involved.

Evidence status is tenant-bound only when the resolver supplies the optional
`EvidenceStatus.tenant_id`. When present on a tenant-aware proposal it must equal
the proposal's tenant (otherwise `evidence_binding_mismatch`), and a tenantless
0.1 proposal refuses tenant-bearing evidence (`tenant_proposal_required`). The
field is omitted from dumps while unset, so tenantless evidence is unchanged.
Compatibility limit: evidence that carries no `tenant_id` is still accepted for
a tenant-aware proposal, so if tenants share an institution/domain and reuse
obligation or source identifiers, tenantless evidence from one tenant can satisfy
another tenant's obligation unless the trusted resolver returns only the
evaluating tenant's evidence. Deployment rule: where the engine keys evidence by
obligation id alone, use one engine database per tenant, or tenant-unique obligation
ids. The opt-in runtime-authority profile's evidence
statements (named by a configured signer: asserted, unauthenticated) include
`tenant_id` and are compared with the Authority Context tenant.

Grant, policy, conflict, identity, mandate and approval observations use explicit maximum
ages. Required evidence uses its Authority Context max_age_seconds. All observed_at values
are rejected when they exceed the configured future clock tolerance. Synthetic tests inject
their evaluation time explicitly; production clock authority and uncertainty remain external
dependencies.

## Requirement versus grant scope

Authorization requires the proposal to fit the Manifest declaration, the Authority Context
requirement permission envelope, and the issued grant. A grant broader than the requirement
does not widen the requirement. The execution envelope uses the narrowest represented
max_effects value across Manifest, requirement and grant for the local pilot.


## Observation validation and reconciliation

Destination observations are evidence, not authorization. Reconciliation never
executes an effect, renews a RuntimeDecision, or creates a new grant or approval.

A BoundedAuthorizationWorkflow that relies on destination observations must be
constructed with an explicit ObservationPolicy. Reconciliation also requires an
explicit timezone-aware evaluation time supplied by the caller. Missing policy or
missing/untrusted evaluation time fails closed.

Before an observation can establish applied, partial, or absent state, the Control
Plane validates:

- the returned effect_id exactly matches the requested effect;
- observed_at is present, parseable, timezone-aware and within the configured age;
- observed_at is not beyond the configured future clock tolerance;
- positive destination evidence names the same effect and has a state consistent
  with the top-level observation;
- absence carries no contradictory destination state.

Rejected observations remain attached to ReconciliationResult with explicit reasons
and observation_accepted=false. They are not appended to the accepted observations
collection. Observation transport failures are retained as reconciliation reasons
without manufacturing a destination fact.

A fresh matching absence produces result=observed_absent with retry_eligible=false.
It proves only that the destination did not report that effect at the observation
boundary. It does not prove that an earlier dispatch cannot commit later, that an
in-flight request was cancelled, that all replicas were covered, or that the
destination is final.

The legacy safe_to_retry enum value remains accepted when reading historical
ReconciliationResult records, but current reconcile() does not emit it and its
default retry_eligible value is false. No historical record is upgraded into new
retry permission.

### Execution compatibility

Execution still requires the persisted authorized decision and full effect binding.
Before first dispatch, the destination observation must itself validate under the
ObservationPolicy. A fresh validated absence permits only the initial dispatch.

If any prior EffectAttempt for the effect exists, observed_absent does not permit
resubmission. The caller must obtain a separately specified retry-eligibility
mechanism with destination idempotency/finality or confirmed in-flight termination
semantics before a future implementation may emit retry_eligible=true. This pilot
implements no such mechanism.

Fresh matching applied observations continue to support lost-acknowledgement and
duplicate-effect recovery without a new dispatch. Fresh matching partial observations
remain held. Unknown, unavailable, stale, malformed, contradictory or mismatched
observations fail closed.

### Trusted adapter assumptions

The local pilot trusts only the configured destination adapter to return its own
observation object for the requested effect. That is an integration assumption,
not source authentication. This package does not authenticate the observation
producer, prove observation coverage across replicas, establish destination finality,
or prove cancellation/termination of earlier in-flight requests.

Production adapters must separately specify and qualify those properties before
retry eligibility can be derived from destination evidence.

### Downstream migration

Consumers that previously treated ReconciliationResult.result == "safe_to_retry"
as an instruction to dispatch must change. For new records:

- applied means a fresh matching positive observation was accepted;
- observed_absent means only point-in-time absence;
- hold means the evidence is insufficient, invalid, unknown, unavailable, partial,
  or otherwise non-actionable;
- retry_eligible is the explicit dispatch-recovery signal and remains false in this
  pilot.

Downstream consumers must not map observed_absent to dispatch. They should preserve
the reconciliation result as evidence and keep authorization/retry decisions in
their own explicit contract until a destination-specific retry-safety mechanism is
implemented and qualified.


### Post-dispatch observation validity

Execution acknowledgement and destination observation are separate facts. After
an adapter apply attempt, execute() routes the post-dispatch observation through
the same identity, timestamp, policy and contradiction checks used by reconcile().

A successful adapter acknowledgement remains recorded in EffectAttempt even when
the subsequent observation is invalid or unavailable. The rejected observation
or observation-channel exception is retained in ReconciliationResult with explicit
reasons and observation_accepted=false. It is not appended to the accepted
observations collection.

For API callers, execute() now returns `EffectObservation | None` as its second
tuple value. `None` means no validated destination observation was established
for that post-dispatch read; it does not mean the effect was rolled back, absent,
or safe to repeat. Callers must inspect the attempt record and reconciliation
evidence separately.

A later recovery may accept a fresh matching applied observation and suppress
duplicate execution. Invalid or unavailable post-dispatch evidence never grants
permission to replay the effect.

## Dispatch outcome and clock corrections

See [the 2026-10-13 addendum disposition](moltbook-addendum-2026-10-13.md) for
unknown outcome handling, explicit test-time configuration, input timestamp
floors, attempt closeouts and original/resumed proposal horizons.
