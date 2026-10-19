# Documentation index

Pages in this repository, grouped by what a reader wants to do. Status labels: **merged** (reviewed and merged here), **selected** (pinned in the hub lock), **known limit** and **proposed** (see the [README](../README.md#where-it-fits)). Pages marked *historical* record a checkpoint and keep the status and scope of the work they recorded; read them as evidence of that moment, not as current behaviour.

Back to the [README](../README.md) (what it is, quick start, what ships, known limits). Hub pages: [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md), [naming](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/naming.md), [profiles and tools](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/profiles-and-tools.md).

## Reading paths

| If you are | Read, in order |
| --- | --- |
| New to the project | [concepts](concepts.md), [architecture](architecture.md), [README quick start](../README.md#quick-start) |
| An integrator | [concepts (`acp run`, PolicyConfig)](concepts.md), [bounded authorization-to-effect contract](bounded_authorization_effect.md), [opt-in profiles](opt-in-profiles.md), [record-store persistence](record-store-persistence.md) |
| A reviewer of claims and limits | [bounded authorization-to-effect contract](bounded_authorization_effect.md) (including stated limits), [threat model (lite)](threat-model-lite.md), [local authority/effect profile](local-authority-effect-profile.md), the [known limits table](../README.md#what-it-does-not-do-known-limits) |
| A maintainer | [CONTRIBUTING](../CONTRIBUTING.md), [CHANGELOG](../CHANGELOG.md), [contract conformance](contract-conformance-execution-attempt-lifecycle.md), [check-to-commit inventory](check-commit-inventory.md) |

## Core pages

| Page | What it covers | Label |
| --- | --- | --- |
| [concepts.md](concepts.md) | Core objects (Frame, proposals, decisions, run records, replay bundles), the `acp run` command with exit codes, PolicyConfig. | merged |
| [architecture.md](architecture.md) | How the control plane sits beside an agent; what it records. | merged |
| [bounded_authorization_effect.md](bounded_authorization_effect.md) | The bounded authorization-to-effect contract, supported interfaces, delegation entry conditions, stated limits, effect and recovery records. | selected (bounded authorization/effect 0.1) |
| [record-store-persistence.md](record-store-persistence.md) | Bounded record-store persistence under a Linux `flock` sidecar. | merged |
| [threat-model-lite.md](threat-model-lite.md) | What the project helps with and what it does not solve. | merged |
| [roadmap.md](roadmap.md) | Planned phases. | proposed |

## Profiles (opt-in, `0.1.0-draft`, proposed)

| Page | Profile |
| --- | --- |
| [opt-in-profiles.md](opt-in-profiles.md) | Overview table of operation identity, rule revision, freshness, witness digest, holder inventory, merge record, reversibility, terminal revocation and dedupe-ttl; the two reason-registry labels; strict JSON. |
| [runtime-authority-profile.md](runtime-authority-profile.md) | Runtime authority profile 0.1. |
| [rule-revision-profile.md](rule-revision-profile.md) | Rule revision 0.1. |
| [local-authority-effect-profile.md](local-authority-effect-profile.md) | Local authority/effect execution claim (implemented as an opt-in proposal; not hub-selected). |
| [decision-input-commitment-profile.md](decision-input-commitment-profile.md) | Decision input commitment (proposal, non-authorizing). |
| [durable-refusal-profile.md](durable-refusal-profile.md) | Durable effect-time refusal evidence (scoped qualification; does not activate any profile). |
| [microsoft-agt-compatibility.md](microsoft-agt-compatibility.md) | Optional Microsoft Agent Governance Toolkit compatibility profile (not in the lock). |

## Contracts and qualification records (historical or draft)

| Page | Note |
| --- | --- |
| [contract-conformance-execution-attempt-lifecycle.md](contract-conformance-execution-attempt-lifecycle.md) | Producer conformance against the vendored lifecycle contract draft. |
| [w0-c1-c2-c4-c6-contracts.md](w0-c1-c2-c4-c6-contracts.md) | W0 candidate contract addendum; no runtime behaviour changed. *Historical.* |
| [check-commit-inventory.md](check-commit-inventory.md) | Check-to-commit contract inventory (qualification artifact). *Historical.* |
| [moltbook-addendum-2026-10-13.md](moltbook-addendum-2026-10-13.md) | Disposition of an engineering addendum, 2026-10-13. *Historical.* |
| [workstreams/store-concurrency-checkpoint.md](workstreams/store-concurrency-checkpoint.md) | Record-store concurrency checkpoint. *Historical.* |
| [workstreams/local-authority-effect-checkpoint.md](workstreams/local-authority-effect-checkpoint.md) | Local authority/effect claim checkpoint. *Historical.* |
| [workstreams/decision-input-commitment-checkpoint.md](workstreams/decision-input-commitment-checkpoint.md) | Decision input commitment checkpoint. *Historical.* |

## Repository pages outside docs/

[README](../README.md) · [CHANGELOG](../CHANGELOG.md) · [CONTRIBUTING](../CONTRIBUTING.md) · [SECURITY](../SECURITY.md) · [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md) · [LICENSE](../LICENSE) · [NOTICE](../NOTICE) · [business overview](../collateral/business-collateral.md) · [one-page overview](../collateral/one-page-overview.md)

## Source modules

Every module under `src/agent_control_plane/` (32 modules plus the package `__init__.py`). Opt-in modules are **proposed**; read each module docstring for its limits.

| Module | Purpose |
| --- | --- |
| `atomic_write.py` | Atomic, private file writes for stored records. |
| `bounded.py` | Bounded authorization-to-effect workflow for the synthetic pilot (default path). |
| `cli.py` | Command-line utilities for exported run records and replay bundles. |
| `cli_run.py` | `acp run`: one declared bounded operation against a local throwaway store. |
| `decision_input_profile.py` | Proposed decision-input commitment profile. |
| `dedupe.py` | Opt-in dedupe-ttl/0.1. |
| `demo_policies.py` | Demo policy configurations for getting started. |
| `exceptions.py` | Custom exceptions. |
| `frame.py` | Frame factory helpers. |
| `freshness.py` | Opt-in freshness/0.1. |
| `holder_inventory.py` | Opt-in holder-inventory/0.1. |
| `local_authority_effect.py` | Opt-in local authority/effect execution-claim contract. |
| `merge.py` | Opt-in merge-record/0.1. |
| `microsoft_agt.py` | Optional Microsoft Agent Governance Toolkit pre-tool-call compatibility profile. |
| `models.py` | Core data models. |
| `operation_identity.py` | Opt-in operation-identity/0.1. |
| `persistence.py` | Minimal persistence interfaces and filesystem adapter. |
| `policy_config.py` | Loading lightweight JSON policy configuration. |
| `policy_gate.py` | Deterministic policy gate. |
| `reason_vocabulary.py` | Attributable vocabulary changes and exposure-aware refusal reporting. |
| `records.py` | Run recorder: accumulates run state and produces a run record or replay bundle. |
| `redaction.py` | Privacy-safe redaction helpers. |
| `replay.py` | Replay bundle generation and serialisation. |
| `reversibility.py` | Opt-in reversibility/0.1. |
| `rule_revision.py` | Opt-in rule-revision/0.1. |
| `runtime_authority.py` | Opt-in runtime-authority/0.1 contracts. |
| `signing.py` | Replay bundle signing helpers. |
| `strict_json.py` | Strict JSON reading for operator-supplied and stored documents. |
| `time_instant.py` | Strict instant parsing. |
| `tools.py` | Tool adapter execution helpers. |
| `validation.py` | Semantic validation for run records and replay bundles. |
| `witness.py` | Opt-in witness-digest/0.1. |
