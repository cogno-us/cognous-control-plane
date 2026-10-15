# Changelog

## Unreleased

### Fixed — reconciliation observation validation
- Reconciliation validates observation effect identity and temporal validity before accepting applied or absent state.
- Explicit ObservationPolicy and timezone-aware evaluation time are required; missing, stale, malformed, timezone-free, excessive-future, unknown and unavailable observations fail closed.
- Fresh absence is now represented as observed_absent with retry_eligible=false rather than being promoted to safe_to_retry.
- Rejected observations remain attached to reconciliation evidence with reasons but are not added to accepted destination observations.
- Execution validates both pre-dispatch and post-dispatch observations; rejected post-dispatch evidence is retained in reconciliation records but is not added to accepted destination observations.
- Execution preserves acknowledgement/attempt history independently from observation validity and will not resubmit after any prior attempt merely because a fresh absence is observed.
- Historical safe_to_retry records remain parseable for reconstruction but do not become current retry permission.


### Fixed — Governor validation gaps
- Resolver records are now rebound to requested identifiers, source references, institution and authority domain instead of trusting lookup keys.
- Identity, mandate and approval observations now have explicit freshness limits; future observations beyond clock tolerance fail closed.
- Runtime authorization now enforces the Authority Context requirement envelope independently from both Manifest and grant scope.
- Executed decisions must exactly match the persisted issued decision and deterministic effect identity.
- Effect execution consumes a frozen validated envelope; the unchecked post-revalidation Authority Context reread was removed.
- Legacy reviewer labels resolve only through an explicit versioned institution-scoped alias mapping whose digest/version are decision-bound.


### Added
- Bounded Manifest v1.1 and Alvorada Authority Context 0.1.0 integration surface.
- Explicit resolver contracts for grant/status, identity/delegation, issuer mandate,
  approvals, policy state, and evidence freshness.
- Stable effect and distinct attempt records with destination observation and
  reconciliation.
- Durable synthetic refund destination with restart recovery, effect deduplication,
  partial-delivery handling, and a local cumulative max_effects guard.
- Adversarial acceptance tests for substitution, revocation, staleness, delegation,
  evidence, lost acknowledgements, restart, duplicates, partial delivery, and
  concurrent attempts.

### Changed
- Legacy policy fingerprints now include payload content.
- Legacy tool execution rejects adapter name/action-type substitution before effect.

### Boundaries
- Synthetic resolver inputs are not institutionally authenticated.
- BitRep verification and Index chain inclusion are not execution grants.
- No production credentials, remote refunds, public-chain writes, scheduler, fleet
  coordinator, distributed budget service, or exactly-once guarantee is added.

## Runtime authority candidate

Add the opt-in runtime-authority/0.1 profile for issue #32: durable resolution
journaling, governed freshness, authenticated criteria, required-input and purpose
binding, and versioned refusal reporting. Historical selection remains unchanged.
