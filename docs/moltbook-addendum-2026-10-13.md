# Moltbook addendum disposition, 2026-10-13

This is a bounded engineering correction, not publication or production approval.
The supplied addendum describes selected historical pins. This patch starts at
Control Plane `8cb2a0a493dca59ed578447db9e458a6b0334fb0`, after issue #27's negative
input evidence fix. The hub selection is unchanged. Issue #29 tracks this work.

## I1: ambiguous dispatch outcomes

`destination.apply` errors are `unknown` unless a trusted adapter raises
`DefinitiveDestinationRejection` with a bounded reason code. That exception is a
contractual assertion of no dispatch or definitive provider non-acceptance; it is
not evidence supplied by a generic exception class. Network, proxy, connection,
and timeout errors cannot establish non-effect. The local synthetic destination
uses the declaration only for its pre-commit cumulative-cap refusal. No external
provider adapter is newly certified. Runtime adapters that raise generic errors
are conservatively unknown under this Control Plane.

An accepted later applied/partial observation appends an `AttemptCloseout` linked
to the original attempt. Original attempted/unknown/failed rows remain unchanged.
This also handles contrary observations of historical `failed` attempts. An
absent read, even after a declared rejection, never independently authorizes retry.
Raw transport exception messages are omitted from the new dispatch error field.

## I2: input suppliers and clock boundary

| Input | Supplier | What this patch establishes |
| --- | --- | --- |
| Evaluation time | Control Plane process clock by default | Caller `now` cannot replace it; recorded in decisions, attempts, refusal/check rows |
| Synthetic evaluation time | Explicit `allow_test_time=True` workflow configuration | Test-only override is labeled `test_override`; never an independent time source |
| Grant status and observation time | Configured resolver | Freshness and durable per-record non-regression checks; no proof of resolver truth |
| Policy, approval, evidence and their times | Configured resolver | Same checks and read commitments; not independent witnesses |
| Identity, mandate, conflict status | Configured resolver | Same timestamp-floor check where `observed_at` exists |
| Destination observation and timestamp | Destination adapter (runtime may inject its observation clock) | Compared with service evaluation time; accepted observation is not authority |
| Optional C1 claim-issuance time | Control Plane clock unless test override enabled | Caller `now` no longer selects production-default claim time |
| Optional C1 commit time | Runtime destination's configured host clock | Separate trusted-host boundary, not changed or independently authenticated here |

`BoundedRecordStore.record_resolution_check` compares and advances timestamp
floors under the same existing local file transaction as its durable checkpoint.
Floors survive process restart using that store; regressions hold and preserve
both the previous floor and new timestamp. Invalid future stamps do not advance
a floor. Floors are scoped to that store and keyed by input type and stable ID;
operators must use stable, appropriately scoped IDs. They do not span separate
stores, survive rollback of the entire store, or resist its owner's deletion.
Fresh source observations do not make compromised contents trustworthy.

The process clock/configuration and resolver must be controlled by the trusted
service operator. An agent that can modify the Python process, enable test mode,
change the host clock or delete the store remains inside the trust boundary.
This is not a new isolated production profile or a signed time service. Existing
synthetic harnesses must explicitly opt in to test time; do not silently update
hub pins without rerunning integration qualification.

## I3 and I4: ordering and custody

Current runtime source has an optional same-host SQLite authority/effect
transaction, and requires invalidating writes through that same database.
Runtime issue #84 tracks commit-state receipts and both ordering tests. C0 still
has a recheck/commit gap. Mirroring remote revocations does not create a common
ordering point with the remote authority.

Control Plane refusal/check rows are durable local records, not independently
numbered external custody. An external verifier whose mandatory claims protect
all effect paths is not established by this patch. Existing HMACs and a local
counter cannot prove it. I4's log-deletion independence remains an architectural
acceptance item; no external service or credential has been provisioned.

## I5: operation horizon

`OperationHorizon` retains the original proposal's `not_before`, `expires_at`,
source (`runtime_proposal`) and proposal commitment on decisions. Refusals also
retain the resumed proposal's values beside the original values. Historical
records have no invented original horizon. Existing expiry enforcement remains;
this patch does not add an unversioned manifest field to require expiry for
particular actions. A required-horizon action profile needs an agreed Manifest
contract and compatibility qualification. These source labels describe proposal
origin, not proof that an underlying external fact is true.

## I6 and posting operations

The runtime's current `OperationAdmissionRegistry` is explicitly an in-memory
optional conformance registry, not a restore-safe epoch issuer. No durable epoch
service exists in this path to repair. Issuer identity, downstream restore floor,
and mandatory admission need a separately scoped contract; no restore guarantee
is claimed. The Moltbook scheduler, posting code and live operational logs are not
part of these repositories. No posting, correction, verification challenge,
message, scheduling change, release tag or production activation was performed.

## Qualification

`tests/test_moltbook_addendum.py` tests commit-then-connection-error with both
immediate and delayed observation; declared non-acceptance; later closeout of a
historical failed attempt; coordinated backdated inputs after expiry; explicit
test-clock labeling; persistent timestamp regression; rejected future timestamps;
checkpoint failure before dispatch; original/resumed horizons; and service-time
reconciliation. Existing authority/effect, refusal, concurrency and compatibility
tests remain required. Full test totals and exact candidate CI are recorded in
the associated PR rather than treating this document as independent signoff.

Operational trust remains HOLD / NOT ESTABLISHED. No C2/C3 or real settlement.
