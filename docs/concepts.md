# Core Concepts

This page defines the core objects in Agent Control Plane.

---

## Frame

A **Frame** is the execution context for a single agent run.  It specifies:

- **actor** – who or what is executing the task (agent identifier, user ID, service name).
- **environment** – the deployment environment, e.g. `"production"`, `"staging"`, `"sandbox"`.
- **allowed_tools** – tools the agent is explicitly permitted to call.
- **blocked_tools** – tools the agent is explicitly forbidden from calling.
- **policy_version** – the version of the policy set in effect.

A Frame is created once at the start of a run and is not modified thereafter.
The policy gate uses the Frame to evaluate every action proposal.

---

## ActionProposal

An **ActionProposal** is a record of an action the agent *wants* to execute,
captured *before* any tool is called.

Key fields:

- **tool_name** – the tool the agent wants to invoke.
- **action_type** – the semantic type of the action: `"read"`, `"write"`,
  `"external_send"`, or any other type defined by your policy.
- **target** – the resource, endpoint, or object the action targets.
- **payload** – arguments or parameters for the tool.
- **reason** – optional agent-supplied justification.

Every proposal is stored regardless of whether it is ultimately allowed or
blocked.

---

## PolicyDecision

A **PolicyDecision** is the output of the policy gate for one `ActionProposal`.

Key fields:

- **result** – one of `"allow"`, `"block"`, or `"escalate"`.
- **policy_name** – the name of the rule that determined the outcome.
- **reason** – a human-readable explanation.
- **trace_id** – optional reference to a `PolicyEvaluationTrace`.
- **deterministic_fingerprint** – a SHA-256 hex digest of the canonical
  inputs (tool name, action type, target, allowed/blocked tools, policy
  version, active authority scopes).  Identical inputs always produce the
  same result and fingerprint, enabling verification that a decision was
  reached correctly.  The `decision_id` and `decided_at` fields are
  generated per evaluation.

---

## PolicyEvaluationTrace

A **PolicyEvaluationTrace** records the ordered rule path used by the policy
gate for one `ActionProposal`.

It includes:

- `trace_id`
- `action_id`
- `rules_evaluated`
- `final_result`
- `deterministic_fingerprint`

Each entry in `rules_evaluated` is a `PolicyRuleEvaluation` with the rule name,
whether it matched, the rule result, and a short reason.

---

## BlockedAction

A **BlockedAction** record is created automatically whenever a
`PolicyDecision` has `result == "block"`.

It captures:

- **action_id** – the proposal that was blocked.
- **reason** – why it was blocked.
- **policy_name** – which policy rule triggered the block.
- **blocked_at** – timestamp.

No real tool is called when an action is blocked.

---

## AuthorityRecord

An **AuthorityRecord** grants an actor a set of permission **scopes** for
the duration of a run.

Scopes that the policy gate checks:

- `"read"` – allows read-type actions on allowed tools.
- `"write"` – allows write-type actions on allowed tools.
- `"external_send"` – allows `external_send` actions on allowed tools.

Multiple authority records can be active simultaneously.  The policy gate
collects scopes only from active records that match the current run, match
the Frame actor, and have not expired when the proposal is evaluated.

---

## RelianceRecord

A **RelianceRecord** documents that the agent relied on an external source
during the run.

Key fields:

- **source_name** – name of the source (e.g. `"crm_read"`, `"user_prompt"`).
- **source_type** – category: `"tool"`, `"database"`, `"file"`, `"api"`,
  `"user_input"`, `"model_output"`, or `"other"`.
- **scope** – what was accessed, e.g. `"customer record fields: name, email"`.
- **referenced_action_id** – optional link to the `ActionProposal` that
  triggered the reliance.

Reliance records help auditors trace the origin of information used to
produce the final output.

---

## ReplayBundle

A **ReplayBundle** is a self-contained, portable snapshot of a completed run.

It contains:

- The `Frame`
- All `ActionProposal` records
- All `PolicyDecision` records
- All `PolicyEvaluationTrace` records
- All `AuthorityRecord` records
- All `RelianceRecord` records
- All `BlockedAction` records
- The final output

Bundles can be serialised to JSON via `replay.to_json()` and deserialised
via `replay.from_json()`.  They are intended for offline audit, compliance
review, or replay simulation.

---

## ValidationReport

A **ValidationReport** is the semantic validation result for a `RunRecord` or
`ReplayBundle`.

It includes:

- `valid` – `True` when no error-severity issues are present
- `checked_object_type` – `RunRecord` or `ReplayBundle`
- `checked_id` – identifier of the checked object
- `issues` – list of `ValidationIssue` objects

Each `ValidationIssue` has a severity (`"error"` or `"warning"`), a stable
code, a human-readable message, and an optional path.

---

## RedactionConfig

A **RedactionConfig** controls privacy-safe export redaction.

It can redact:

- action payloads
- action targets
- final output
- recorded reasons

Redaction preserves IDs, timestamps, policy names, fingerprints, and trace
relationships so exports remain usable for replay and audit workflows.

---

## ToolAdapter and ToolExecutionResult

A **ToolAdapter** is a minimal execution interface with `name`,
`action_type`, and `execute(target, payload) -> dict`.

`execute_with_control()` uses a `ToolAdapter` only after the policy gate
returns `"allow"`. The returned **ToolExecutionResult** records the `action_id`,
`run_id`, whether execution was attempted, the adapter result payload, and any
error message.

The `ToolExecutionResult` is returned to the caller only. `execute_with_control()`
keeps no durable record of the attempt or its outcome: `RunRecord` and
`ReplayBundle` have no field for tool attempts or results. A successful call adds
only a reliance entry, not the result. A failed attempt (including an adapter
that commits an effect and then raises, or a lost acknowledgement) leaves no
trace in the exported record, so the record cannot show whether an effect may
have happened or support a safe retry decision. Callers that need that history
must persist the returned result themselves; `BoundedAuthorizationWorkflow`
records effect attempts and reconciliation durably.

---

## SignedReplayBundle

A **SignedReplayBundle** wraps a `ReplayBundle` plus an HMAC-SHA256 signature
and signing metadata.

It supports optional integrity verification for exported bundles. It does not
provide production key management or claim to be a complete security boundary.

The HMAC covers only the canonical JSON of `replay_bundle`. The wrapper fields
`signed_bundle_id`, `signed_at` and `signature_algorithm` are not signed: they
can be changed without invalidating the signature, so a relabelled or
backdated export still verifies. Treat them as unauthenticated metadata.

The `acp sign-replay` and `acp verify-signed-replay` commands take the shared
secret as a `--secret` command-line argument. Command-line arguments are
visible to other local users and processes through the process listing (for
example `ps` or `/proc/<pid>/cmdline`) and may be retained in shell history or
command telemetry. Anyone who learns the secret can forge signatures. Use these
commands only with throwaway secrets on hosts you control, or call
`sign_replay_bundle()` / `verify_signed_replay_bundle()` from Python with a
secret obtained from a protected source.

---

## PolicyConfig

A **PolicyConfig** is a lightweight JSON configuration model that can be used
to create a `Frame` for examples or small integrations.

It includes:

- `policy_version`
- `allowed_tools`
- `blocked_tools`
- `authority_required`
- `default_action`

This is intentionally a simple configuration format, not a full policy DSL.
