<!-- cognous-banner:start -->
```text
──────────────────────────────────────────────────
   __________  _______   ______  __  _______
  / ____/ __ \/ ____/ | / / __ \/ / / / ___/
 / /   / / / / / __/  |/ / / / / / / /\__ \
/ /___/ /_/ / /_/ / /|  / /_/ / /_/ /___/ /
\____/\____/\____/_/ |_/\____/\____//____/
              COGNOUS CONTROL PLANE
       g o v e r n e d   b y   d e s i g n
  github.com/cogno-us/cognous-open-control-stack
──────────────────────────────────────────────────
```
<!-- cognous-banner:end -->

# Cognous Control Plane

**Evaluate proposals against authority and preserve the decision record.**

**Stack group: 03 · Declaration & Policy Control.** See the [six-group component map](#cognous-stack-components).

## Overview

A Python reference implementation for bounded agent authorization, effect-time revalidation and persistent runtime records. It connects declared actions, independently resolved authority, execution attempts and reconciliation without treating an earlier decision as a permanent credential.

**Implementation status:** public reference work. The [current component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) defines the selected integration; a component merge does not automatically change that selection or approve deployment.

## Selection and example

Use the [current component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) for integration selection and the [central test hub](https://github.com/cogno-us/cognous-stack-qualification/blob/main/results/readme-commentary/index.md) for revision-specific qualification commentary. Source acceptance, selection and deployment approval remain separate decisions.

**Example:** A valid synthetic refund decision can be followed by approval withdrawal before effect dispatch. Effect-time revalidation must then refuse the changed request; an earlier permit is not a reusable capability. If the destination might have committed an earlier attempt but the acknowledgment was lost, keep the original effect/attempt identity as `unknown` and reconcile it. Missing observation is not safe retry authorization. Neither case establishes authenticated institutional adoption or external payment settlement.

For audience navigation and evidence interpretation, use the hub [start guide](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/start-here.md). Operational trust remains [HOLD under #30](https://github.com/cogno-us/cognous-stack-orchestrator/issues/30).

## Purpose and intended users

Organizations need to distinguish what an agent proposed from what policy allowed and what a destination actually did. A cached approval or fluent explanation cannot answer whether authority, evidence and approvals were still valid when an effect was attempted.

Engineers can inspect the reference contracts and examples; enterprise architecture, security and governance reviewers can examine the boundary and evidence. Evaluate this component for its named responsibility rather than as a complete governance platform.

## Key features

| Capability | Implemented or specified responsibility |
|---|---|
| **Bounded authorization** | Evaluate Manifest-bound proposals using the trusted Authority Context resolver and explicit policy. |
| **Effect-time checks** | Revalidate authorization-critical inputs before the supported execution path reaches a destination. |
| **Lifecycle records** | Keep decisions, attempts, observations and reconciliation distinguishable, including unknown acknowledgements. |
| **Persistent record transactions** | Reload and append under a stable Linux sidecar flock with atomic replacement and explicit persistence failures. |
| **Developer tools** | Use run validation, policy examples, replay export, redaction and integrity helpers with their documented assurance limits. |

## How it works

A synthetic refund is proposed under a bounded grant. The controller records its decision, rechecks current authority at effect time and invokes the constrained adapter. After a timeout, reconciliation concerns the original effect. Fresh observed absence does not authorize a replacement; accepted applied evidence can resolve delivery while preserving the interrupted acknowledgement history.

A valid signature, chain inclusion, message receipt, reasoning instruction or evidence-package digest does not authorize execution. Institutional authority must be supplied and evaluated through the appropriate trusted boundary.

## Getting started

From a fresh repository checkout, use Python 3.11+ and an activated virtual environment. Install only into that environment. Package installation needs network access; the commands below exercise local reference tooling. For the full selected integration, use the [hub quickstart](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/quickstart.md), whose runner supplies exact producer checkouts and test wiring.

```bash
python -m pip install -e ".[dev]"
acp --help
acp validate-run examples/sample_run_record.json
acp run --help   # run one declared bounded operation locally; see docs/concepts.md
python examples/policy_config_demo.py
```

## Scope and compatibility

The persistence contract covers cooperating local Linux writers. Historical persistence qualification commentary is retained in the central test hub.

Test results, run commentary and historical qualification records are maintained in the [central test hub](https://github.com/cogno-us/cognous-stack-qualification/blob/main/results/readme-commentary/index.md). Read them against their recorded source revisions; source selection and deployment approval are separate decisions.

## Limitations and deployment decisions

The repaired store supports cooperating writers on documented local Linux filesystems with shared canonical-path assumptions. Individual record transactions are protected; the entire decide/execute/reconcile workflow is not atomic. Production resolver authentication, distributed budgets, remote finality and exactly-once delivery are not established.

Review original artifacts and their exact source revisions before extending a claim to a new environment. New dependencies, authority sources, destinations or enforcement mechanisms need their own compatibility and qualification. A passing reference case is not a certification of an enterprise deployment.

## Opt-in local authority/effect claim profile

Worker 21 adds a proposed, opt-in claim contract for a same-host SQLite authority/effect boundary. The legacy bounded execution path is unchanged.

The enforceable profile uses an explicit trusted authority handoff, not merely another pre-effect check. While the authority source excludes its own invalidating writers, the Control Plane performs a final resolve, captures and validates one coherent active/current authority projection, and provisions the exact claim into the participating local store. Only then does that store become authoritative for later profile mutations. The claim binds institution/domain, actor/principal, grant identity/revision/status, the fully materialized operation, approvals, policy state, evidence state, effect limits and a bounded validity interval. Possession remains non-authorizing.

See [docs/local-authority-effect-profile.md](docs/local-authority-effect-profile.md). This profile is implemented on this repository's `main` as an opt-in proposal; it is not selected by the stack hub.

## Other opt-in profiles

The runtime-authority and rule-revision profiles, operation identity, freshness, witness and holder inventory, merge record, reversibility, dedupe-ttl and terminal revocation are all optional, `0.1.0-draft` and off unless a host configures them; the pinned default path is unchanged. The reason registry has two labels (`runtime-authority-reasons/0.1`, the original 121 codes, and `/0.2`, the full 158), and operator-supplied and stored JSON is read strictly. See [docs/opt-in-profiles.md](docs/opt-in-profiles.md).

## Repository guide

Use these sources for details; their historical checkpoints retain the status and scope of the work they recorded:

- [docs/bounded_authorization_effect.md](docs/bounded_authorization_effect.md)
- [docs/record-store-persistence.md](docs/record-store-persistence.md)
- [docs/workstreams/store-concurrency-checkpoint.md](docs/workstreams/store-concurrency-checkpoint.md)
- [docs/threat-model-lite.md](docs/threat-model-lite.md)
- [docs/opt-in-profiles.md](docs/opt-in-profiles.md)

For a nontechnical introduction, read the [business overview](collateral/business-collateral.md) and [one-page overview](collateral/one-page-overview.md). Both describe this component's role and evidence limits, not additional runtime features.

## Contributing and attribution

[Contribution guidance](CONTRIBUTING.md) describes review and validation expectations. Keep evidence-linked claims, preserve historical records and separate proposed features from accepted implementation.

See [LICENSE](LICENSE) and [attribution](NOTICE) for the existing terms and third-party scope. Developed by [Cognous](https://cogno.us); no licensing change is part of this documentation update.

---

## Bibliography

Selected external sources from the October 2026 research review. These inform evaluation questions; they do not establish Cognous implementation, adoption, conformance or production qualification.

- [John M. Willis. *Runtime Governance Body of Knowledge for Artificial Intelligence and Other Autonomous Systems — Glossary* (19 July 2026)](https://sustainablefuturetech.com/asg-wg-runtime-governance-glossary/). Discussion draft on authority, execution and evidence terminology; not an adopted standard or Cognous conformance requirement.
- Jonathan Chadbourne / JCEE Labs. *When a Timeout Is Not a Failure: Authority, Evidence, and Recovery in Consequential AI Execution*. Technical Note 001, public release v0.1.1 (6 October 2026). Technical note on uncertain outcomes and recovery. An original public URL has not been verified; no substitute or private copy is linked.
- [OWASP GenAI Security Project. *State of Agentic AI Security and Governance*, version 2.01 (June 2026)](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/). Security synthesis covering agent identity, delegated permissions, tool access and containment.

See the [research bibliography](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/research-bibliography.md) for review scope and source-verification limits.

## Cognous stack components

The six groups organize component responsibilities. They are not an execution
sequence or a requirement to install every component. The [hub lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json)
defines the selected integration; [release status](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/release-status.md)
defines its evidence and limits.

| Group | Components |
| --- | --- |
| **01 · Knowledge & Provenance** | [The Index (Evidence Registry)](https://github.com/cogno-us/cognous-evidence-registry) · [BitRep (Evidence Attestation)](https://github.com/cogno-us/cognous-evidence-attestation) |
| **02 · Institutional Governance** | [Alvorada (Institutional Governance)](https://github.com/cogno-us/cognous-institutional-governance) · authority contracts |
| **03 · Declaration & Policy Control** | [Action Manifest](https://github.com/cogno-us/cognous-action-manifest) · [Control Plane](https://github.com/cogno-us/cognous-control-plane) |
| **04 · Constrained Execution** | [Execution Runtime (Moltbot Safe)](https://github.com/cogno-us/cognous-execution-runtime) |
| **05 · Replay & Evidence** | [Replay Bundle](https://github.com/cogno-us/cognous-replay-bundle) · [Governance Evidence Pack](https://github.com/cogno-us/cognous-governance-evidence-pack) · [ODES](https://github.com/cogno-us/open-decision-evidence-standard) |
| **06 · Reasoning & Human Oversight** | [PRP](https://github.com/cogno-us/portable-reasoning-protocol) · [Research Intelligence](https://github.com/cogno-us/research-intelligence-protocol) · [TFA](https://github.com/cogno-us/truth-freedom-agency-protocol) |

**Cross-cutting exchange:** [Governed Exchange (GAX/IMX)](https://github.com/cogno-us/cognous-governed-exchange) connects
governed messages, recipient assessment and continuity across the groups. It is
separate from Alvorada's institutional authority framework.

Execution Runtime and Moltbot Safe name the same repository here. The supported
Cognous Python execution boundary remains distinct from the retained upstream
application. PRP, Research Intelligence and TFA are optional behavioral
instructions; they do not enforce authorization or substitute for human oversight.
A signature, registry entry, message receipt or evidence summary does not grant
execution authority.


## Repository locations

See the [repository rename map and compatibility notes](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/repository-renames.md) for current component URLs. Existing package names, schema identifiers and retained producer identities are unchanged.

<!-- Retained anchors for existing documentation links. -->
<a id="current-selection-versus-historical-qualification"></a>
<a id="evidence-and-supported-scope"></a>
