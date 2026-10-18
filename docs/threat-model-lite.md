# Threat Model (Lite)

This document outlines what Agent Control Plane helps with and what it
does not solve.  It is intentionally concise.

---

## What this MVP helps with

### Unrecorded agent actions

**Risk**: an agent calls tools without any record, making it impossible to
audit what happened.

**Mitigation**: every `ActionProposal` is recorded before any tool is
called, regardless of whether the action is allowed or blocked.

---

### Unauthorised tool use

**Risk**: an agent calls a tool that should not be accessible in the current
context (e.g. sending external emails without approval).

**Mitigation**: the `PolicyGate` checks every proposal against the Frame's
allow/block lists and the active authority records.  Blocked tools and
unauthorised action types receive a `block` decision; execution is withheld only when the caller
executes through `execute_with_control` or `BoundedAuthorizationWorkflow`.

---

### Missing blocked-action records

**Risk**: a blocked action leaves no trace, so auditors cannot tell whether
blocking occurred.

**Mitigation**: a `BlockedAction` record is automatically created for every
`block` decision and stored in the `RunRecord`.

---

### Inability to replay a run

**Risk**: there is no way to reconstruct exactly what an agent proposed,
decided, and output during a past run.

**Mitigation**: `generate_replay_bundle()` produces a `ReplayBundle` that contains the frame, all proposals,
decisions, traces, authority records, reliance records, blocked actions, and final output. It omits tool
attempts and results and carries no completion marker.

---

### External-source reliance ambiguity

**Risk**: the origin of information used by the agent is unknown, making
it hard to assess trustworthiness or identify data-quality issues.

**Mitigation**: `record_reliance()` captures each external source the agent
accessed, including source name, type, scope, and a link to the triggering
action.

---

### Inconsistent policy decisions

**Risk**: the same action evaluated twice produces different results,
making audits unreliable.

**Mitigation**: the `PolicyGate` is stateless and deterministic.  The
`deterministic_fingerprint` field is a hash of the evaluated inputs, so
re-evaluating the same inputs with the same gate produces the same
fingerprint.

**Limit**: the legacy record validator (`validate-run` / `validate-replay`)
does not recompute fingerprints.  It only checks that a decision's
`trace_id` resolves to a trace in the same record and that the two stored
`deterministic_fingerprint` values are equal.  It does not check that the
trace's action or final result matches the decision, and it does not
require a `BlockedAction` for every `block` decision.  Anyone able to edit
unsigned run or replay JSON can therefore produce internally consistent but
contradictory authorization history that still validates.  A fingerprint is
only checkable by re-running the gate against the original inputs; a valid
validation report is not evidence of authentic provenance.

---

## What this MVP does NOT solve

### Model hallucination

Agent Control Plane records what the agent proposed and what the policy
decided.  It cannot detect or prevent hallucinated reasoning inside the
model that led to the proposal.

### Bad policy definitions

The gate enforces the policies you define.  If the allow/block lists or
authority scopes are misconfigured, the gate will enforce the misconfigured
policy faithfully.

### Compromised infrastructure

If the host environment, dependencies, or the process running the recorder
are compromised, the integrity of the records cannot be guaranteed by this
library alone.

### Complete compliance automation

This MVP provides structured records suitable for compliance workflows but
does not automate regulatory compliance, generate compliance reports, or
integrate with compliance management platforms.

### Full semantic understanding

The gate classifies actions by `tool_name` and `action_type` as declared
by the agent.  It does not inspect the semantic content of the `payload`
or infer intent from natural-language reasoning.
