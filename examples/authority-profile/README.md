# Authority profile examples — NON-PRODUCTION

These files document the shape of `ocs-authority-profile/0.1`. They are **not** trust anchors.

- `synthetic.profile.json` + `synthetic.snapshot.json`: SYNTHETIC-VERIFIED shape. The public key in the snapshot is derived from the **public** test seed `bytes(range(32))`, which appears in several Cognous test suites. **Anyone can sign with it.** A copy of these files run under `expected_mode="synthetic"` would accept forged selections if the snapshot were not expired. The snapshot is therefore expired (`valid_until` in the past), so it never admits a live selection. Do not "refresh" it and do not use it outside tests.
- `operational.profile.template.json`: CUSTOMER-OPERATIONAL template with `UNSELECTED-*` placeholders. Operational mode refuses (`authority_config_unprovisioned`) in the current code even when every field is filled in: a trusted clock, independently anchored state and a customer verifier are not provisioned (H3). The test over this file is only a tripwire that no operational file loads; it does not prove input-dependent behaviour.
- Private keys never belong in any profile, snapshot or repository. Customer anchors, grants, snapshot publication, the fingerprint pin, `expected_mode` and `expected_config_digest` are supplied through protected deployment inputs outside GitHub.
- Supply `expected_config_digest` whenever the configuration or state store matters: without it a synthetic profile can be edited (for example to `state.backend = "none-g1"`) undetected.
- `schemas/ocs_authority_profile_0_1.schema.json` is documentation of shape. The loader is the sole authority; schema-valid does not mean accepted.
