# O6-P1B durable effect-time refusal evidence

Status: scoped Control Plane qualification for issue #21. This does not select or activate C1 and does not change grant issuance, release locks, or Execution Runtime behavior.

## Source boundary

- Task branch base: `4b399f446cea4936050b7b532dcd052068df2d8d`.
- The selected/default path remains C0 pre-effect revalidation followed by dispatch.
- The optional same-host C1 profile remains separately qualified and opt-in.
- No C2/C3 or destination-commit atomicity claim is introduced.

## Refusal record

When an immutable authorized decision reaches effect-time revalidation and current decision-critical inputs no longer resolve to the persisted authorization binding, the Control Plane now retains one minimal `EffectTimeRefusal` row before raising the existing refusal exception.

The row binds:

- `decision_id`;
- `effect_id`;
- exact current `_resolve` reason codes;
- minimized changed-input entries containing only input type, stable input identifier, expected version/state descriptor, and observed version/state descriptor;
- effect-time refusal stage and record time.

Raw proposal payload is not copied into the refusal row or ordinary refusal diagnostics.

## Qualified cases

Scoped tests establish:

- a revoked grant retains `grant_not_active` rather than only the previous generic exception text;
- the observed grant revision/status version is retained;
- disabling the refusal writer causes the evidence assertion itself to fail;
- two concurrent refusals for distinct revoked grant IDs remain attributed to their own decision/effect and grant item;
- destination state remains untouched for pre-dispatch refusal.

## Limitations

This record is evidence of Control Plane refusal, not proof of remote non-effect. C0 still has a residual change-after-check/before-destination-commit race. C1 remains optional, same-host only, and is not activated by this work. The refusal record does not issue authority, close Execution Runtime attempts, reconcile remote settlement, or establish distributed atomicity.

## Negative resolution evidence (issue #27)

The follow-up adds `resolution_inputs` to bounded decisions (including holds)
and effect-time refusal rows. A held decision still has `binding: null` and
cannot authorize execution. Historical records without this field load with an
empty list; their missing evidence is not reconstructed or invented.

Each entry describes one actual read, in read order: input type and requested
identifier, expected version/state where applicable, observed version/state and
observation timestamp where available, a canonical SHA-256 commitment to the
returned record, and an explicit `missing` flag. The manifest and authority
context are committed too. Evidence statuses have no dedicated version field in
this interface: their record commitment, state and observation time identify the
read; this does not invent an upstream evidence version. Unread inputs have no
entry. Repeated reads remain separate entries.

These entries are captured during `_resolve`, including on early hold returns.
Effect-time `changed_inputs` is projected from those captured entries against the
original authorization binding without rereading the resolver. An input that
changes again after checking therefore cannot replace the evidence of the read
that caused refusal. The full `resolution_inputs` list includes timestamps and
record commitments even when a freshness or binding failure does not appear in
the narrower changed-version projection.

Policy failures retain the compatibility code `policy_stale_or_changed` and add
one or more specific codes: `policy_missing`, `policy_superseded`,
`policy_status_unknown`, or `policy_version_changed`. Freshness continues to use
`policy_status_stale_or_future`.

`tests/test_negative_resolution_evidence.py` exercises denied targets, missing
required payload fields, stale/revoked grants, approval withdrawal, separate
policy failure causes, missing context, old-record loading, diagnostic payload
minimization, permitted dispatch, and restart inspection of refusal evidence.
The approve/revoke test supplies a resolver that returns revoked revision
`revoked-r2` on the check and active on a hypothetical subsequent read: refusal
must retain `revoked-r2`, make only one grant read, and leave zero destination
effects. Persistence failures propagate before dispatch; no durable record is
claimed when storage fails. Mutation controls ensure missing evidence is detected.

This is replay by reloading the bounded run record for inspection, not a new
export to the separate generic `RunRecord`/`ReplayBundle` format or a re-execution
of historical policy. Digests are neither signatures nor proof of resolver
truth, and reproducing a full check requires separately retained source records.
The collector does not establish an atomic snapshot across different reads.
Identifiers/version labels remain visible and require appropriate access control;
raw payloads, approver identities and record bodies are not copied into these
new diagnostic fields.

Approval withdrawal is the supported human intervention tested here; no new
human override or authorization bypass is introduced. Exceptions before a
bounded decision can be formed, invalid decision submissions, adapter
substitution, and optional C1 claim-issuance failures are not newly covered by
this record. This change does not select new hub component pins or change the
C0 race, optional same-host C1, C2/C3 exclusion, real-settlement exclusion, or
operational-trust HOLD.
