# O6-P0B check-to-commit contract inventory

Status: qualification artifact for issue #19. No release selection, grant issuance, or runtime profile activation is changed here.

## Source inventory

- Task source main: `99bb62fff879a8d4e87d7badb0d7d8a17501e4c1`.
- Hub-selected Control Plane supplied by the task: `d3dadee70bd319812b207389ab1e0f6efe511916`.
- Current source is eight commits ahead of that selected pin. The delta includes W0 tenant/current-authority contract work, the opt-in local authority/effect profile, and optional Microsoft AGT compatibility.
- The selected/default bounded workflow remains `BoundedAuthorizationWorkflow.execute()`; this qualification does not modify that path.
- The opt-in same-host profile remains `urn:cognous:profiles:local-authority-effect:0.1.0-proposed`; this qualification does not select or activate it.

## C0: revalidate then dispatch

C0 is the behavior of the selected/default bounded execution path.

1. Load and verify the persisted (append-only, unkeyed) authorization decision.
2. Resolve current decision-critical authority, policy, approval, and evidence.
3. Require the resolved binding to equal the persisted authorization binding.
4. Validate adapter identity.
5. Reconcile current destination state.
6. Record an attempt and call the destination adapter.

There is no authority reread after step 2 and no transaction shared with the destination commit. Therefore C0 means **pre-effect revalidation followed by dispatch**. It does **not** mean destination-commit atomicity.

The deterministic tests qualify both sides of this boundary:

- revocation, policy supersession, approval withdrawal, unknown evidence, or stale evidence **before revalidation** fails closed and produces no destination effect;
- the same changes injected **after revalidation but before destination commit** can still be followed by an applied synthetic effect, proving the residual check-to-commit race;
- a mutation after an already committed effect does not rewrite that historical effect.

The second case is a limitation intentionally asserted by the test. Treating it as a failure would incorrectly upgrade C0 into a stronger contract.

## C1: optional same-host authoritative ordering

C1 is a separately qualified optional profile. It is not enabled by this PR.

A C1 claim requires the trusted handoff already specified by `provision_local_execution_claim()`: final resolve, coherent snapshot validation, claim construction, and sink provisioning occur while authority-invalidating writers are excluded. After provisioning, the participating local SQLite store must become authoritative for every later grant, policy, approval, and decision-critical evidence mutation covered by the profile.

For C1, the protected effect and those invalidating mutations are serialized by the **same SQLite transaction boundary**. Qualification uses a test-only SQLite inventory:

- if an invalidating mutation obtains the authoritative database order first, effect commit rereads the authoritative rows in its transaction and holds with no destination effect;
- if the effect transaction obtains the authoritative order first, the effect commits and a later revocation is historical ordering after the effect;
- concurrent tests deliberately hold the winning SQLite write transaction so the other writer blocks. Assertions use persisted SQLite ordering plus the effects table, not thread start order or application log sequence.

The database order is the authoritative order for this synthetic same-host profile. Log emission time is not used to infer which operation won.

## Scenario matrix

| Mutation / race | C0 selected path | Optional C1 same-host profile |
|---|---|---|
| Revocation before check | HOLD / no effect | HOLD / no effect |
| Policy change before check | HOLD / no effect | HOLD / no effect |
| Approval withdrawal before check | HOLD / no effect | HOLD / no effect |
| Required evidence stale/unknown before check | HOLD / no effect | HOLD / no effect |
| Change after check, before destination commit | Residual race; effect may commit | Serialized: mutation-first holds, effect-first commits |
| Concurrent invalidation/effect commit | No shared authoritative commit order | SQLite transaction order is authoritative |
| Invalidation after committed effect | Historical effect remains | Historical effect remains |

## Qualified boundary

This PR qualifies only:

- C0 current-state revalidation and its explicit check-to-commit limitation;
- C1 test-only same-host ordering semantics when all covered writers and the protected effect use one authoritative SQLite transaction domain;
- direct destination/effects-table assertions for the synthetic cases.

## Not qualified or claimed

- C1 is not selected, activated, or made the default.
- No production identity, credential, grant-issuance, or deployment profile is added.
- No cross-host or distributed transaction is claimed.
- No external processor or remote destination commit is made atomic.
- No C2/C3 production guarantee is introduced.
- No exactly-once business effect, remote finality, or universal mediation guarantee is established.
- The hub release lock is not modified.
- The C1 harness is qualification infrastructure only; it is not a production executor or payment adapter.
