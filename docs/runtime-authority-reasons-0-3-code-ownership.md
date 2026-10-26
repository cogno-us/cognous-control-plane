# Reasons 0.3: ownership record for the eight additive codes

Every name and classification below is **PROPOSED, NOT RATIFIED by the Control Plane component owner.** Passing tests is not ratification.
Registry: `runtime-authority-reasons/0.3` (`schemas/runtime_authority_reasons_0_3.json`, 172 codes: the 164 entries of 0.2 unchanged and in
order plus these eight). 0.2 stays frozen at git blob `a46ef35e7ece5c3a16e50d174000c49e3632eb12`; 0.1 is untouched. All eight are
`typed_only`, introduced in 0.3, produced by `validate_extensions` in `runtime_authority.py` for a profile carrying `policy_binding`.
The expected consumer is the caller that reads the decision result and reasons (the Runtime through the decision surface); no consumer is
verified.

## Classification rule (Architect)
Definitive invalidity or policy violation: REFUSE. Definitive stale or rolled-back authority: REFUSE_STALE where the owning outcome contract
supports it. Unavailable or indeterminate authority: HOLD. The current result must not be used to classify a code: the decision gate
computes `"authorized" if not reasons else "hold"` and never emits `deny` for any code, including older definitive ones. There is no
REFUSE_STALE outcome. The registry file carries no per-code outcome class, so a classification cannot be stored in the immutable 0.3.
No behaviour was changed here; emitting `deny` or adding REFUSE_STALE is an owner decision about the outcome contract.

## Per-code record (all PROPOSED)

| Exact string | Trigger | Proposed class | Current result |
|---|---|---|---|
| `approval_commitment_version_unsupported` | The approved spec names a commitment version outside the closed set (even if the commitment matches). | REFUSE | `hold` |
| `approval_policy_generation_missing` | A binding profile, but the spec lacks the version, generation or activation reference (a legacy approval or stripped member). | REFUSE | `hold` |
| `approval_policy_generation_invalid` | The carried generation or activation reference has the wrong type, range or non-canonical form. | REFUSE | `hold` |
| `approval_policy_generation_mismatch` | The carried generation differs from the trusted profile's (inequality only, no direction recorded). | Split by direction (owner decision): below the trusted generation is stale (REFUSE_STALE where it exists, else REFUSE); above is indeterminate (HOLD). Ordering is CONTRACT-BLOCKED until EXT-S3-4. | `hold` |
| `approval_policy_activation_mismatch` | The carried activation reference differs from the trusted profile's; a digest has no order. | REFUSE | `hold` |
| `freshness_ceiling_exceeded` | Class bound plus the extension limit exceeds a registry ceiling (construction and every evaluation). | REFUSE | `hold` |
| `freshness_ceiling_unanchored` | A ceilinged profile lacks a freshness/0.1 profile with `anchor_deadline_to_inputs`. | REFUSE | `hold` |
| `policy_binding_invalid` | The binding is malformed, outside its strict ranges or forms, carries a digest or ceilings in a withdrawn disposition, or names an undeclared action id. | REFUSE | `hold` |

Negative-evidence semantics: the absence of any of these codes proves only local equality, well-formedness or ceiling arithmetic against the
trusted profile. It does not prove that a generation is the highest observed, that an activation is current, or that the binding comes from an
authenticated activation. The durable ratchet is a consumer / EXT-S4 obligation.

## Registry identity
`registry_identity(label)` returns this build's pinned sha256 of the file a label names and fails closed on any unsupported label;
`registry_admits(label, reasons, registry_codes)` (the consumer's loaded registry is required, never defaulted) refuses a 0.3 code under 0.1 or 0.2, an unsupported label and any code the loaded registry does not list. This is an
integrity check against the build's own pin. It is NOT an authenticated production evidence chain: no signed mapping or trust-root contract
exists in the Control Plane and none was invented. The mapping must be retained with the evidence package and its trust must come from an
authenticated publication or custody mechanism (Architect ruling); that mechanism is CONTRACT-BLOCKED.

## Questions for the contract owner
1. Ratify, rename or reject each exact string.
2. Confirm or change each class. May `approval_policy_generation_mismatch` stay one code, or must direction be recorded (a later registry revision)?
3. Will the outcome contract emit `deny` for definitive reasons, and add REFUSE_STALE?
4. Who is the named consumer of each code, and what does it do on an unknown 0.3 code?
5. Must result rows carry a digest, or is the label plus an authenticated retained mapping enough?
6. Is a signed label-to-digest mapping contract planned?
7. Should `policy_generation` stay opaque and consumer-supplied until EXT-S3-4 fixes its domain and ordering?
