# Authorization pin export (Registry r08-v2 Amendment 4, section 3.2)

Status: candidate, NON-AUTHORIZING. RELEASE, PUBLICATION and PRODUCTION: HOLD. Nothing here is qualified, certified or production ready.

`agent_control_plane.authorization_pin_export.assess_authorization_pin(workflow, proposal, decision, *, now, host_policy_binding)` is the Control Plane side of the trusted handoff to the host authorization-pin installer. Profile string: `ocs-s4/authorization-pin-export/0.1`. It is read-only with respect to authorization state: it builds no claim, calls no `provision`, creates no decision, grant, approval or policy record, and has no claim or `expected_*` parameter. (The existing resolution step journals checks in the Control Plane record store, as claim issuance does; see "Journaling and non-authorization" below.)

## Result

`state` is one of:

- `active`: `payload` holds exactly the 17 Control Plane sourced pin members, copied from the persisted decision, the handoff snapshot, the trusted host-config profile and the installer-owned host binding body. Never from a claim or caller value.
- `terminal`: persisted authority positively shows the decision is no longer supported. `terminal_status` is `revoked` (grant revoked, terminal revocation recorded, or an approval whose handoff status is `revoked`), `superseded` (stale grant revision, superseded policy) or `withdrawn` (approval-side binding disposition `withdrawn`, or activation mismatch). Mixed or unlisted reasons are never mapped.
- `unknown`: unreadable, unresolved, ambiguous, expired or unmapped. No pin change. Expiry is not a terminal transition; the Runtime derives it.

Mismatches in what the export is given (decision not the persisted authorized one, host binding digest, epoch or activation differing from the profile, profile differing from the persisted `catalogue_digest`, recomputed `approval_commitment` differing from the persisted value) raise `PermissionError`.

## What this proves

- The decision is the persisted, authorized one.
- The host-config profile equals the profile the persisted decision committed to (`catalogue_digest`), and `approval_commitment` recomputed from the handoff context equals the persisted value.
- The installer-owned binding body has the digest the host-config profile names, with matching `selection_epoch` and `activation_ref`.
- Under the resolver handoff lock, the existing issuance validation (grant, approvals, policies, evidence) still supports the decision at `now`.

## What this does not prove

- Authenticity of the Control Plane approval: the persisted state is unsigned (see `policy-binding-approval-generation.md`).
- That the activation is still current at the Registry: the Control Plane keeps no durable Registry state.
- That the host-config binding was built correctly from consumer state.
- For the provisional `withdrawn` disposition: the profile has no `binding_digest` and a different catalogue, so the catalogue and approval commitment cannot be compared; the link to the decision is only that the host binding body names the activation the persisted decision committed to.
- Instantaneous revocation: the interval between an upstream change and the installer running is a propagation delay.

## Custody

Authenticity of the persisted Control Plane state rests on OS custody of the Control Plane stores, the resolver and the host configuration (Amendment 4 P-1 to P-4). A Python function boundary provides no OS isolation: the separation of the claim supplier, this export, the installer and the Runtime comes only from the deployment's OS identities and file permissions. No cryptographic scheme is introduced.

## Journaling and non-authorization (documentation clarification, 2026-10-30)

Verified from source at Control Plane `8616d5f64a901b8f858359809193961a1124b5f6` (code-equivalent to `739efe7`; not re-executed for this note). Nothing below describes a behavior change.

* **Pin export is non-authorizing.** It grants, widens or installs nothing; `active` is an assessment for the host installer.
* **Binding mismatch.** A persisted effective-configuration binding that differs from the live one (or is absent past the legacy cutoff, malformed or inconsistent) returns a non-`active` assessment (state `unknown`, no authorization payload). No durable `EffectTimeRefusal` is written on this read-only path and none is required; `append_refusal` is not called from this module. Effecting `execute` still requires the durable `authorization_binding_changed` `EffectTimeRefusal` (`bounded.py:1694`), and claim issuance still raises `PermissionError("authorization-critical inputs changed before claim issuance")` without a refusal row.
* **Existing resolution-check journaling is retained, unchanged and shared with claim issuance.** The export calls `workflow._resolve(..., stage="claim")` (`authorization_pin_export.py:170-173`) and then `workflow._record_check(...)` (line 175); claim issuance makes the same two calls (`local_authority_effect.py:443-454`). Where the resolve step journals, it appends stage-`claim` `check_events` entries (one `opened`, one `input` per resolver input read, one `completed`; the number of `input` entries is data dependent, `bounded.py:2094`, `2142`), and `_record_check` appends one stage-`claim` `ResolutionCheck` row. Therefore a pin export or claim issuance may append a data-dependent number of `check_events` records plus one `ResolutionCheck`; "one `ResolutionCheck` row" alone understates this.
* **Per-input `input_time_floors` may advance.** `record_resolution_check` (`bounded.py:627-661`) compares each input's `observed_at` with the stored floor and moves the floor forward only when the observation is not older than it and not beyond now plus tolerance; an older observation adds `input_observation_time_regressed` and does not move the floor. A floor can therefore only add a refusal reason on a later check; it never removes a reason, grants authority or creates an obligation. This is conservative refusal behavior.
* **No new authority and no new obligation.** These rows are audit and freshness bookkeeping. Neither the journaling nor the floors grant new authority or create an `EffectTimeRefusal` obligation for read-only paths. Nothing else is written: no decision, attempt, observation or claim state.
* **Not verified here:** the exact `input` count for any fixture, and row counts on exceptional branches (for example a failing record write), which were read from source only.
