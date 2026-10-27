# Authorization pin export (Registry r08-v2 Amendment 4, section 3.2)

Status: candidate, NON-AUTHORIZING. RELEASE, PUBLICATION and PRODUCTION: HOLD. Nothing here is qualified, certified or production ready.

`agent_control_plane.authorization_pin_export.assess_authorization_pin(workflow, proposal, decision, *, now, host_policy_binding)` is the Control Plane side of the trusted handoff to the host authorization-pin installer. Profile string: `ocs-s4/authorization-pin-export/0.1`. It is read-only with respect to authorization state: it builds no claim, calls no `provision`, creates no decision, grant, approval or policy record, and has no claim or `expected_*` parameter. (The existing resolution step journals a resolution check in the Control Plane record store, as claim issuance does.)

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
