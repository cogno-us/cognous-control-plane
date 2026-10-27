# Local authority/effect execution-claim profile

Status: **implemented proposal on Control Plane `main` (originally developed on the Worker 21 branch); opt-in; not hub-selected**.

Profile: `urn:cognous:profiles:local-authority-effect:0.1.0-proposed`.

## Purpose

This contract is the Control Plane side of a bounded same-host profile that can
order authorization-critical invalidation against one protected SQLite effect.
The legacy `BoundedAuthorizationWorkflow.execute()` path is unchanged (for well-formed input; see opt-in-profiles.md).

A claim is materialized only from:

- a persisted (append-only, unkeyed) `authorized` decision;
- the exact `AuthorizationBinding`;
- a fresh resolution of the same trusted workflow;
- the institution/domain and grant from the trusted Authority Context;
- current approval, policy and decision-relevant evidence state.

Possession of the claim does not authorize execution. A participating local
authority/effect store must provision the claim and become authoritative for all
subsequent invalidating writes in the profile.

## Claim bindings

The claim binds:

- institution and authority domain;
- actor, principal, grant ID and revision;
- decision and effect IDs;
- Manifest, action, adapter, target and exact operation commitment;
- approval state and commitment;
- policy state and commitment;
- evidence obligations/state/freshness inputs and commitment;
- requirement commitment;
- budget ID and maximum effects;
- not-before and expiry;
- profile version and complete claim commitment.

### Authorization inputs the claim does not bind

Bounded resolution treats more inputs as authorization-critical than the claim
carries. The claim's `authority_state_commitment` covers only grant ID,
revision and status, requirement commitment, approvals, policies and evidence.
The claim does **not** bind, and the claim schema gives the executor no way to
invalidate it on a change to:

- acting identity authentication and delegation validity (identity status);
- issuer mandate validity;
- role mapping version and digest (present in `AuthorizationBinding`, absent
  from the claim);
- authority conflict status;
- runtime-authority purpose/epoch state, when a grant carries `purpose_ref`;
- other runtime-authority extension inputs (required-input set, evidence
  criteria, effective-grant digest);
- evidence tenant: evidence projections carry no `tenant_id`.

These inputs are checked once at the final resolve inside the handoff. After
`provision()` returns, a revocation or change of any of them is not visible to a
participating executor that validates only the claim. An integration that needs
those inputs to invalidate a provisioned claim must route their writers through
the same authoritative store or re-resolve before consumption; this profile
does not do so.

The optional `decision_input_commitment` and
`decision_input_profile_version` fields are opaque compatibility hooks for the
Decision Input Commitment profile now merged on Control Plane `main` at
`29337fe900d3b2da5656c77d56d70f18feb190b8`. Worker 21 does **not**
silently adopt that profile into the authority/effect runtime and does not
reinterpret the Decision Input Commitment Record as executable authority.

## Trust boundary

Claim issuance has two distinct APIs.

`materialize_local_execution_claim()` returns a validated, non-executable
snapshot artifact. It is not sufficient for the Worker 21 execution profile.

`provision_local_execution_claim()` defines the trusted authority handoff.
The resolver must expose an `authority_effect_handoff` boundary that excludes
all trusted authority-invalidating writers while the Control Plane performs the
final resolve, captures one coherent authority snapshot, validates active/current
grant, approval, policy and evidence projections, constructs the claim, and
provisions that exact claim into the participating executor store.

Only after the provisioning callback returns does the local SQLite store become
authoritative for subsequent profile mutations. A second ordinary resolver check
without this exclusion-and-provisioning handoff does not establish the profile.

The claim is still not cryptographic authority. The corresponding executor must
validate and consume the provisioned claim in the same authoritative SQLite
transaction as the protected effect.

## Compatibility

- No existing Control Plane schema changes.
- No changes to `RuntimeDecision`, `AuthorizationBinding` or
  `BoundedRunRecord`.
- Existing consumers remain compatible.
- The existing execution path remains selected unless an integrator explicitly
  opts into the new local profile.
- The merged Worker 20 Decision Input Commitment profile remains independent
  and non-authorizing; Worker 21 uses only optional opaque linkage fields unless
  a later explicit integration is reviewed.

## Not claimed

This profile does not establish production identity, source authenticity,
distributed transactions, remote revocation, universal mediation, external
destination atomicity, EBL-Core conformance, or production readiness.

## Successor profile: claim-carried canonical policy binding (EXT-S4-4, V02)

Status: **BUILDER_TESTED developer increment; non-authorizing; not independently qualified. Tier 1, independent Ed25519 review, release, publication and production remain on HOLD.**

Successor profile: `urn:cognous:profiles:local-authority-effect:0.2.0-proposed` (the identifier is a builder proposal pending ratification by the Control Plane owner). The legacy profile above is unchanged.

- A claim MAY carry the completed Registry `ocs-policy-binding/1` object (Registry `docs/r08-v2-contract.md` section 4) as the declared optional member `policy_binding`. The member is omitted from every dump while absent, so a claim without a binding keeps its exact legacy bytes, commitment, issuance and verification behavior (frozen byte vectors in `tests/fixtures/v02_legacy_claim_vectors.json`, generated on the unmodified base).
- Under the successor profile the binding is REQUIRED and valid; under the legacy profile it is REFUSED (an undeclared member). Any other undeclared member of a dictionary claim is also refused, because a bare extra key is dropped by the model path.
- The existing `claim_commitment` (`bounded.commitment`) covers the complete binding. There is no sibling digest field. `bounded.py` is unchanged.
- Validation (`canonical_policy_binding.py`) implements the published profile with strict types and closed membership, no normalization and no coercion; it imports no Registry code. It is distinct from the approval-side `policy-binding/0.1` object, which is unchanged.
- Issuance (`materialize_local_execution_claim` / `provision_local_execution_claim`) accepts keyword-only `policy_binding`, `expected_consumer_id` and `expected_operation`. The consumer and operation are host-expected inputs (the claim has no such members). The binding must be a tenant claim whose scope equals the claim's tenant, institution and authority domain, and must agree with the approval-side `policy-binding/0.1` the approvals already commit to (shared `binding_digest`, `selection_epoch`, `activation_ref`; `policy_generation` is never inferred from or compared with the epoch). Refusal is `PermissionError`; evidence is the existing claim-stage resolution check using the existing codes `policy_binding_invalid` and `approval_policy_activation_mismatch`. No reason code is added.
- The binding is not part of `policy_state` or `authority_state`, and it is not a grant, an approval or an activation.

Limits (unchanged by this increment): the claim commitment is self-consistency, not a signature; possession of a claim, with or without a binding, authorizes nothing. The Runtime must compare the claim-carried binding with durable active authority under the destination transaction lock, with rollback protection, the ratchet and the atomic effect guard. That work is V04/V05 and is not implemented here. `activation_ref` is filled by the enforcing gate and is not derived or invented by the Control Plane.

