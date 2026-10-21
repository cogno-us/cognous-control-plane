# Changelog

## Unreleased

### Fixed — decision gate parity with the action-manifest contract, strict numeric limits, strict decision-input tool (2026-10-22, scan 3)
- Default path (CP-1): the decision's manifest gate now applies the action-manifest runtime consumption contract it previously skipped. It refuses with `action_blocked` when the action's effective `default_action` (its own, else the manifest's) is `block` or its tool is not `allowed` (anything other than boolean `true`; absent means allowed, as in the manifest); with `missing_effect_limits` when the action declares no `effect_limits` and the proposal carries an amount above 0 or more than one effect; and with `missing_amount_limit` when `effect_limits` has no `max_amount` and the amount is above 0. The shipped example (amount 50.0, `max_amount` 100.0, `escalate` defaults, tool allowed) is still authorized. Hold-only, non-authorizing; no production claim.
- Default path (CP-2): a manifest `effect_limits.max_amount` must be a finite JSON number and `max_effects` an exact JSON integer, and a requirement or grant permission `max_amount` / `max_effects` likewise (no bool, no string, no NaN, no `1.9` truncation); otherwise the decision refuses with `effect_limit_malformed` (manifest) or `authority_limit_malformed` (context), and a malformed permission grants nothing. Previously the string `"nan"` made `amount > float(limit)` false, so the limit never applied.
- Registry: five codes added to `runtime_authority_reasons_0_2.json` (`action_blocked`, `missing_effect_limits`, `missing_amount_limit`, `effect_limit_malformed`, `authority_limit_malformed`; 163 codes). `..._0_1.json` is untouched (byte-identical). These are default-path codes, so a refusal row carrying one now has label 0.2; rows without them keep 0.1.
- Tool (DIP-1): `tools/verify_decision_input_commitment.py` reads its record with `strict_json.strict_loads` (UTF-8 only; duplicate object members, NaN/Infinity and unpaired surrogates refused with `INPUT_INVALID`, exit 2) instead of `json.loads`, which kept the last duplicate member.
- Not changed: manifest `authority_context.evidence_obligation_ids` is still not compared with the context's requirement evidence (the contract only says "resolve required evidence", not that the lists must match).

### Fixed — decision-step action identity binding
- Default path: when the manifest declares one `action_id` more than once, the decision binds no action and refuses with the registered reason `unknown_action` (fail closed), whichever declaration comes first. A single declaration decides as before. No reason code added; registry labels unchanged.

### Fixed — decision-step tool binding
- Default path: when the manifest declares a tool name more than once, the decision refuses with the registered reason `adapter_mismatch` (fail closed), whichever declaration a request names. The decision still does not run the manifest validator; it no longer binds the first declaration of a repeated name. A manifest that declares each tool name once decides exactly as before. No reason code added; registry labels unchanged.

### Fixed — writers now match the strict readers (scan remediation, stream C)
- Default path: the record store, destination state, `FileSystemPersistenceAdapter`, `RunRecorder.export_json` and the CLI writers serialise with `allow_nan=False`, encode to UTF-8 before any file is opened, and replace atomically (temp file + `os.replace`), so a refused write leaves the existing record intact and readable. Files are created `0600`, directories `0700`. Store and destination bytes are unchanged for valid data (`ensure_ascii` kept). `export_json` uses `mode="json"`, so `acp validate-run` accepts it.
- Default path: `FileSystemPersistenceAdapter` creates exclusively; pass `overwrite=True` (constructor or per call) to replace.
- Default path: redacted decisions/traces blank `deterministic_fingerprint`; `RedactionConfig.keep_fingerprints=True` is the explicit opt-out.
- Default path: `effect_limits: {}` (or a malformed limits object) now checks `max_effects` instead of skipping the check.
- Default path: legacy `RunRecorder` evaluates the stored proposal by action id and refuses a different submitted proposal, deep-copies on store and return, makes `complete_run` terminal, and `generate_replay_bundle` requires a completed run (`allow_incomplete=True` to override). `ReplayBundle` and `replay.py` are unchanged.
- Default path: the Microsoft AGT adapter holds with `tenant_mismatch` when a `TenantRuntimeProposal.tenant_id` differs from the `tenant_id` argument. Opt-in: `tool_bindings={adapter_id: tool_name}` holds with `tool_binding_mismatch`.
- Default path (tenant-bearing evidence only): optional `EvidenceStatus.tenant_id`; a mismatch holds with `evidence_binding_mismatch`, a tenantless proposal refuses tenant-bearing evidence. Tenantless evidence is still accepted for a tenant-aware proposal (documented limit).
- Opt-in: `FreshnessProfile.anchor_deadline_to_inputs` sets the dispatch deadline to the earliest `observed_at + own bound`; omitted from the profile dump while off, so the documented profile is byte-identical.
- Docs: "signed" / "record-store key" wording replaced with "named by a configured signer (asserted, unauthenticated)"; `opt-in-profiles.md` states which strict behaviours apply by default.

### Changed — time parsing conformance (ODES time semantics, decision 35)
- New leaf module `time_instant.py` (`parse_instant`, `aware_utc`) implements section 1 of the ODES time semantics: an RFC 3339 date-time with an explicit offset, ASCII digits, seconds mandatory, one to six fraction digits, whole-string match. It replaces the copies of the `fromisoformat` parser in `bounded._parse` (grants, proposals, deadlines, cached inputs, extensions, purpose status age; also used by `local_authority_effect` and `runtime_authority`), `freshness.parse_time`, `policy_gate._parse_time`, `dedupe._t`, `reversibility._utc`, `rule_revision._t`, and the time checks of `decision_input_profile._parse_time`, the destination observation time, the `reversible_until` declaration and `acp run --now`.
- Refused now (stable message codes `time_instant_naive`, `time_instant_invalid`; `InstantError` is a `ValueError`, so each site keeps the refusal path it already had for a malformed time): a time without an offset (was read as UTC; `rule_revision` kept it naive, so a later comparison with an aware time raised `TypeError`), a seventh fraction digit (was truncated, so two different instants compared equal), a leap second, offset minutes above 59 (`+00:60` was read as one hour) or hours above 23, and the non-RFC 3339 forms `fromisoformat` accepts (date only, no seconds, space separator, basic format, comma fraction, hour-only offset). A naive `datetime` passed to `PolicyGate.evaluate(now=...)` is refused too (the docstring said it was read as UTC). Sites with their own codes keep them: `observation_time_timezone_missing`/`observation_time_malformed`, `timestamp_invalid: reversible_until`, `EVIDENCE_TIME_INVALID`/`EVALUATION_TIME_INVALID`, `acp run` exit 2 for `--now`. A bad grant time with a runtime-authority profile holds as `resolution_record_invalid`; on the legacy path (and `acp run`) it ends the run before any decision or effect with exit 4, exactly as a malformed grant time already did. No reason code added; registry labels unchanged.
- `dedupe.classify`: the escalation deadline is inclusive (ODES time semantics section 3). At exactly `first + escalation_deadline_seconds` an unresolved attempt is still `horizon_passed_awaiting_escalation`; it is `escalation_due` only strictly after it (was `>=`). Opt-in `dedupe-ttl/0.1` only.
- Valid instants (aware, at most six fraction digits) parse to exactly the datetime the old parsers returned (2015-instant differential test), so the default path is unchanged: default `acp run` authorized and held examples, `validate-run` and `witness digest` byte-identical before/after. Not changed: the trend-report reporting period in `reason_vocabulary.measured_arity` (`(start, end]`, a reporting period rather than a validity window) and the adoption-time comparisons in `reason_vocabulary`.

### Changed — RuntimeProposal numeric members read strictly
- `RuntimeProposal.amount` accepts a JSON number only (an integer becomes its float value, as before) and `effects` a JSON integer only; a string, boolean, `null` or (for `effects`) a float such as `1.0` is refused instead of coerced (`acp run`: exit 2). Valid proposals validate to the same values and the same commitment; the full test suite passed unchanged and the default `acp run` examples are byte-identical before/after.

### Added — terminal-revocation/0.1 (opt-in)
- `RuntimeAuthorityProfile.terminal_revocation` (`TerminalRevocationProfile`): when a retained resolution check already observed `revoked` for the same `(grant_id, revision)`, decision and execution are refused with `grant_revocation_recorded` even if the status read now says `active`; the row carries a `successor_grant_revision` reopen condition. It reuses the retained-check lookup of the cached-positive denial rule (now one helper, `_recorded_grant_denial`, same behaviour). `suspended` stays reversible. One reason code added to label 0.2 only (registry 0.2: 158 codes; 0.1 byte-identical). Omitted from profile dumps while unset, so the default path and every commitment over the profile are unchanged (default `acp run` examples byte-identical before/after).

### Fixed — strict JSON: out-of-range numbers and unpaired surrogates
- `strict_json.strict_loads` now also refuses a number that overflows to a non-finite float (`input_json_non_finite_number`, the same code as `NaN`/`Infinity`) and a string or member name holding an unpaired UTF-16 surrogate (new code `input_json_lone_surrogate`). `acp run` reports both as invalid input (exit 2) instead of an internal error (exit 4); nothing was applied before either. Applies at every strict read site. Valid input parses exactly as before (the float hook is `float`; the surrogate walk runs only when the text holds a surrogate escape or code point). Default `acp run` examples byte-identical before/after.

### Fixed — declared string lists are type-checked
- The members read by the target, payload-field and data-scope checks (manifest `allowed_targets`, `required_fields`, `optional_fields`, `forbidden_fields`; authority-context `permissions` and each permission's `targets` and `data_scopes`) must be lists of exact strings. Any other shape declares nothing, so its check refuses with the existing registered reason (`target_out_of_scope`, `missing_payload_policy`, `requirement_scope_mismatch`, `grant_scope_mismatch`). No reason code added; label 0.1 unchanged. Well-formed inputs are unchanged (default `acp run` examples byte-identical before/after).

### Changed — strict JSON at the remaining stored-file and operator-file reads (follow-up to F1)
- New leaf module `strict_json.py` holds the loader F1 added to `acp run` (UTF-8 only, no duplicate object members, no `NaN`/`Infinity`/`-Infinity`; codes `input_not_utf8`, `input_json_duplicate_member`, `input_json_non_finite_number`; messages unchanged). `cli_run` re-exports it. Now strict: `cli._load_json_model` (exit 2, was an uncaught traceback for non-UTF-8), `persistence._load_model`, `policy_config.load_policy_config`, `witness._as_document` and `LocalFileWitness.history`, `BoundedRecordStore._read_document`, `LocalRefundDestination._load`. Every one of those files is written with `model_dump(mode="json")` (NaN becomes null) or `allow_nan=False`, and a dict cannot hold a duplicate member, so a file this project wrote is never refused. Reads are read-only: a refusal changes no file and creates no state (a corrupt store still refuses to re-initialize).
- Kept as is, on purpose: `replay.from_json` (`to_json` writes the python-mode dump, which can hold NaN/Infinity in free-form `payload`/`result` members, so strict reading would refuse a file this project wrote; a test pins it) and `cli_run` line reading `records.path` back right after this process wrote it (not an input boundary). Default path byte-identical: `acp run` authorized and held examples, witness digest/publish/verify, `validate-run`, store loads, diffed before/after.

### Changed — reason registry split into labels 0.1 and 0.2 (review R1 finding 4)
- The registry grew from 121 to 157 codes (N1, N3, N5, N4) under the single label `runtime-authority-reasons/0.1`, while a test and `docs/rule-revision-profile.md` said it was unchanged. Now `schemas/runtime_authority_reasons_0_1.json` is the original 121 codes again, byte-identical to its form at 2936e3f (sha256 `fbc4df2e...c0`, pinned by a test), and the new `schemas/runtime_authority_reasons_0_2.json` is the full 157-code set (0.1 entries unchanged and in place, plus 36 profile codes; a superset because one row can mix codes and carries one label).
- `runtime_authority.vocabulary_for(reasons)` returns 0.2 only when a reason is one of `CODES_ADDED_IN_0_2`; decisions, refusals and journal events are stamped with it. Default-path rows (no profile code) keep label 0.1 and are byte-identical (default `acp run` examples and a profile run diffed before/after). Consumers that pin one registry (the independent verifier first vendored the full set as 0.1; it now vendors both labels and resolves each row by its own label) must accept both labels; see the PR for the list. No row already written is edited.
- Docs corrected where they said the registry was unchanged.

### Added — merge-record/0.1, reversibility/0.1, dedupe-ttl/0.1 (opt-in, N4)
- `RuntimeAuthorityProfile.merge` (`merge.py`): a merge record over operation ids only (never attempt ids). A merge names a survivor and folded operations; the equivalence rule behind it is a content digest that must be adopted by a signed, independent `merge_equivalence_rule` revision (rule-revision/0.1); a merge by an authority outside `funded_authorities` is `held`; every outcome (`merged`, `held`, `unknown`, `refused`) is an appended row and only `merged` has effect. A merged set shares one effect budget: a second effect is refused before dispatch (`operation_merged_effect_exists`, or `_unresolved` while an attempt has no outcome); a folded operation dispatches under the survivor's id; attempt joins carry `merged_into`; a merge after two effects landed appends a record-only `CompensationObligation` (nothing is compensated). Needs operation-identity/0.1.
- `RuntimeAuthorityProfile.reversibility` and the action-class member `x-reversibility` (the ODES `effect-reversibility` shape: `reversibility` `irreversible | reversible_until | reversible_at_cost`, `reversible_until`, `reversal_cost` `{description}`, `reads_protected_data`, `counterparty_observable`; all five present, null where not applicable). The legacy `irreversible` flag is true if and only if the value is `irreversible`; protected reads and unobservable counterparties are `irreversible`; a `reversible_until` class is irreversible once its window passed. During a purpose outage a cached `open` purpose snapshot is accepted only for a reversible class, inside its age bound (inclusive), and never against a closure this control plane already recorded; every use (accepted or refused) is a `snapshot_uses` row with epoch and age. An outage extension never raises the bound of an irreversible class. `x-effect-class` (stageable/stallable/blocking) is NOT implemented: the code has no staging or stalled-start phase.
- `RuntimeAuthorityProfile.dedupe` (`dedupe.py`): `provider_horizon_seconds <= escalation_deadline_seconds < dedupe_ttl_seconds`. The destination declares `dedupe-ttl/0.1` and its TTL (never inferred). An unresolved attempt stays `unknown` through the horizon and escalates once at the deadline, inside the key TTL (`escalation_pass`; a late row carries `escalation_after_key_ttl`). An `in_progress` answer is `unknown` and no new key is minted (`dedupe_unresolved_attempt_blocks_new_key`). Expiry of the destination's operation key never makes a second effect fresh: the control plane refuses a new effect id for an operation that already has an applied effect from its own ledger (`dedupe_operation_effect_applied`). Effect-id dedupe never expires. Needs operation-identity/0.1. `dedupe_report`/`escalation_pass` take an optional `destination` for the runtime executor route.
- 18 reason codes added (registry 157; see the label split below). Default path unchanged: `acp run` examples (authorized, held) byte-identical before/after under fixed `--now` and a deterministic uuid source; a runtime-authority profile run without the new members diffs identical (record, profile dump).

### Fixed — reaper failure, atomic gate refusal, monotonic guard (F1, review R1 findings 4, 6)
- freshness/0.1 only. A reaper thread that stops on an error (or dies) is now surfaced: `Reaper.failure`, `Reaper.failed`, `Reaper.check()` raising `ReaperFailed`, an error log line, and `decide`/`execute` of the workflow that started it raise `ReaperFailed` (fail closed, nothing written). No new reason code (the registry is untouched).
- The dispatch-gate refusal (failed attempt, effect-time refusal, `expired` journal event) is one document replacement (`BoundedRecordStore.record_gate_refusal`), so a crash leaves all three rows or none.
- Monotonic guard at the dispatch gate: the process monotonic clock since opening and a wall clock earlier than the recorded opening both withdraw the licence; the reaper runs when the wall clock was stepped back below its last run.
- Default path unchanged (default records diffed before/after).

### Fixed — age-extension base, store-integrity wording, 2x age (F1, review R1 findings 2, 3, 5)
- Age-extension limits are measured from the host profile's class bound, not the base the stored row records about itself; a row whose recorded base differs from the class bound is `age_extension_invalid` (fail closed). Only affects freshness/0.1 (opt-in); rows written by `record_age_extension` are unchanged.
- Docs and docstrings no longer mention an HMAC key protecting the record store: there is none. The store is a plain JSON file under a same-host lock; `signer`/`reviser` are asserted names unless a keyed proof is configured (none is built). No code path changed for this item.
- Status age at dispatch can reach twice the class bound under freshness/0.1 (deadline anchored at opening). Documented in `freshness.py` and pinned by a test; not tightened.

### Fixed — `acp run` strict input parsing (F1)
- Input files are parsed fail-closed: duplicate object members (`input_json_duplicate_member`), `NaN`/`Infinity`/`-Infinity` (`input_json_non_finite_number`) and non-UTF-8 bytes (`input_not_utf8`) are refused with exit 2 and the stable code in the message. Before, duplicates silently resolved to the last value. Records for valid inputs are unchanged (examples diffed before/after, 11 files equal after normalising uuids, timestamps and paths). Other CLI entry points are not changed.

### Fixed — `acp run` hardening (F1, review R1 finding 9)
- Untrusted member and key names are escaped (control, format and non-printable characters become `\xNN`/`\uNNNN`), bounded to five names of 60 characters and a 200-character message before they reach stderr or the text output, so a name can no longer forge a line or an ANSI sequence. Output directories that did not exist are created without `exist_ok` and existing ones are re-verified (same inode, not a symlink, still empty) at use; inputs are read through one `O_NOFOLLOW` descriptor with `fstat` re-checks. The window between check and use is narrowed, not closed against a hostile local writer. Tests added for the surviving mutants R1 found (CR/LF/NUL on an existing path, a real hard link, both nesting directions with an existing parent, both input-containment halves).

### Added — witness-digest/0.1 and holder-inventory/0.1 (opt-in, N5)
- `agent_control_plane.witness` (and `acp witness digest|publish|verify`): a hash chain over the rows of every list-valued ledger of a record set, a `Witness` protocol (`publish`, `latest`, optional `history`) with a local append-only file implementation, `verify_against_witness` (rejects a record set whose covered rows were dropped or rewritten after a digest the witness holds, whatever seal the key holder re-applied) and `publish_head` (verifies before publishing). Gives visibility to a reader who holds the witness digest; it is not tamper evidence against the witness holder, and rows appended after the latest digest are not covered. Makes no network call and publishes nothing: where a real witness is held (owner default: a signed tag in the hub repository) is a deployment step the owner triggers. Off unless called.
- `RuntimeAuthorityProfile.holder_inventory` and `ActionClass.requires_revocation_assurance`: a flagged class holds (`holder_inventory_missing`) until an inventory that enumerates a holder exists; `holder_inventory.classify_holders` reports witnessed refusals vs `coverage_unknown` holders (never "expired"). Both fields are omitted from profile dumps while unset, so every commitment is unchanged. One reason code added (registry 139). Qualification: `suites/outside-holder`.

### Added — `acp run`
- New CLI subcommand that executes one declared bounded operation (synthetic resolver from JSON, real `BoundedAuthorizationWorkflow`, local throwaway store and `LocalRefundDestination`), writes a native bounded record, a `RunRecord` projection accepted by `acp validate-run`, and a result envelope. Exit codes 0/1/2/4. No network; confined writes. Library behaviour unchanged. See `docs/concepts.md`.

### Added — freshness/0.1 (opt-in, N3)
- `RuntimeAuthorityProfile.freshness`: three named clocks in the records (`evaluated_at`, `recorded_at` stamped at each write, `observed_at` from the source), a deadline fixed at opening (`opened_at` plus the class age bound), a re-read of the service clock immediately before `destination.apply` (`check_expired_before_dispatch`, check closed `expired`), a recovery pass that reports live checks past their deadline as `check_overdue` without closing them, a `Reaper` (start-up and declared interval) with counts for the report, a non-blocking check lease with an acquisition deadline, nonce-bound or source-asserted `age_basis` per read, and outage extensions of an age bound recorded with a signer from the rule-revision signer set. Observation "future" is judged against the re-read service clock under the profile. Off unless configured; 10 reason codes added (registry 138). See `src/agent_control_plane/freshness.py`.

### Added — rule-revision/0.1 (opt-in, N2)
- `RuleRevision` records, digest-pinned rules and independently signed revision rows for registry, policy, gate and merge rules; `rule_identity` on decision and refusal rows; trend adoption flags, measured arity and derived recomputability helpers. Off unless configured; reason registry version unchanged. See `docs/rule-revision-profile.md`.

### Fixed — rule-revision recomputability (N2b, opt-in helpers only)
- `derive_recomputability` returns `underivable` (not `typed_only`) when operands are not retained, and `recomputability_flags` reports `derivation_unavailable` instead of a false `declared_overclaim` for a real `grant_revoked` hold. `declared_overclaim` is reserved for rows with operands present. Registry and its version unchanged.

### Fixed — F5b security repairs
- A historical 0.1 `RuntimeProposal` now holds with `tenant_proposal_required` when the Authority Context, grant, grant status, approval or policy carries a `tenant_id`; tenantless 0.1 behaviour is unchanged.
- `FileSystemPersistenceAdapter` rejects run and replay-bundle identifiers whose resolved path leaves the store directory.
- `LocalExecutionClaim.amount` rejects NaN and infinity, so `verify_local_execution_claim` returns `False` instead of raising.
- `runtime-authority-reasons/0.1` now registers every reason code the workflow emits (24 previously unregistered codes plus the new `tenant_proposal_required`); a test enforces registry completeness against source.
- Documentation states the limits of legacy record validation, replay-bundle HMAC coverage, `--secret` argv exposure, AGT tool-name binding, evidence tenant binding, local-claim invalidation inputs and legacy tool-execution failure retention.

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
