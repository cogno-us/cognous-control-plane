# Registry authority profile `ocs-authority-profile/0.1` (CAP v0.1, gate G1)

Status: BUILDER_TESTED developer implementation. Not independently qualified. **No durable anti-rollback (G2).** Claim A only (the Registry selection signature is admitted at decision time by the injected real Ed25519 verifier). Operational trust, issuer identity, key custody, adoption and a decision-authenticated claim are NOT established.

## What it is
One closed, strict-JSON configuration plus a wrapper around the host `selection_source`. The verification mechanism (Registry `verify_f4_selection_v2`, all eleven layers, exact `Ed25519Verifier`) is identical in `synthetic` and `operational` modes; only the declared inputs differ. No pinned Control Plane file is edited.

## Configuration (all members required, no others)
`version`, `id`, `mode`, `verifier{contract:"r08-v2",family:"f4"}`, `trust_anchor{algorithm:"ed25519",keys[{key_id,public_key_sha256:"sha256:<hex>"}]}`, `issuers[{issuer_id,key_id,grants[{consumer_id,tenant,institution,authority_domain,operation}]}]` (exact tokens, no wildcard, one key per issuer), `expected_context`, `snapshot{source{kind:"file",reference},expected{snapshot_id,version,fingerprint}}`, `clock{kind:"system_utc"}` or `{kind:"fixed_instant",as_of}` (synthetic only), `state{backend,namespace,reference,anchor_reference}`, `identities{snapshot_publisher_ref,enforcing_operator_ref,state_admin_ref}` (synthetic: `UNSELECTED-SYNTHETIC`).
Public key bytes live in the separate snapshot document, never in the configuration. Member names or values that look like private key material (names containing private/secret/seed/passw/credential/signing, bare 64/128 hex, base64 of 32/64 bytes, PEM) are refused in both modes.
The process owner supplies `expected_mode` and (operational) `expected_config_digest` as process arguments, never request data. A mode mismatch refuses in either direction; there is no fallback.

## Per-call flow
Re-read the pinned snapshot file (no cache) → its Registry fingerprint, id and version equal the pin and its issuers, keys (sha256 of the public bytes) and grants equal the declarations → any host-supplied snapshot must equal the pin → `verify_f4_selection_v2` → verdict fingerprint equals the pin and a per-selection epoch floor was applied (`epoch_floor_missing` otherwise) → return fresh material carrying the pinned snapshot. The typed refusal stays on the wrapper (`last_refusal`) because the Control Plane collapses source exceptions to `selection_source_failed`.

## Refusal codes (Control Plane local)
`authority_config_missing|malformed|version_unsupported|secret_material|mode_mismatch|unprovisioned|digest_mismatch|scope_mismatch`, `snapshot_pin_mismatch`, `epoch_floor_missing`, `verifier_unavailable`, `authority_factory_argument_refused`; Registry non-admission surfaces as the existing `registry_not_applied` with the Registry code.

## Operational mode in G1
Fails closed: placeholders, `UNSELECTED` identities, fixed instants, a missing owner digest and any blank reference refuse; and an otherwise complete operational profile still refuses `authority_config_unprovisioned` because durable state does not exist until G2.

## Limits
No state: a replayed older snapshot or selection that still satisfies the pin is not detected across processes (G2). Hosts that do not build workflows through `governed_age_workflow` bypass the profile (operational responsibility). Replay stays stateless and unedited; its fixed claim note ("synthetic keys") is not changed here (G3 gate). `replay_trust_kwargs` and `check_replay_markers` are pure helpers; Control Plane never imports Replay.
