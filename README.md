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

**Status:** group 03 · Declaration & Policy Control; lock status **selected** (interface: bounded authorization/effect 0.1); opt-in profiles are **proposed** and not selected; contract drafts stay `0.1.0-draft`. Nothing here is a release; operational trust remains [HOLD under #30](https://github.com/cogno-us/cognous-stack-orchestrator/issues/30).

## What it is

A Python reference implementation (package `agent-control-plane`, import `agent_control_plane`, command `acp`) for bounded agent authorization, effect-time revalidation and persistent runtime records. It connects declared actions, independently resolved authority, execution attempts and reconciliation without treating an earlier decision as a permanent credential.

**Who it is for.** Engineers who want to inspect the reference contracts and run the examples; architecture, security and governance reviewers who want to examine the boundary and the evidence it leaves. Evaluate it for its named responsibility, not as a complete governance platform.

**What it does not do.** It does not authenticate institutional authority (the resolver in the examples is synthetic), does not make the decide, execute and reconcile workflow atomic, and does not establish exactly-once delivery or external payment settlement. A valid signature, chain inclusion, message receipt, reasoning instruction or evidence-package digest does not authorize execution. The limits are listed under [what it does not do](#what-it-does-not-do-known-limits).

**Example.** A valid synthetic refund decision can be followed by approval withdrawal before effect dispatch. Effect-time revalidation must then refuse the changed request; an earlier permit is not a reusable capability. If the destination might have committed an earlier attempt but the acknowledgment was lost, the original effect and attempt identity stays `unknown` and is reconciled. A missing observation is not safe retry authorization.

## Where it fits

<a id="cognous-stack-components"></a>

<!-- stack-map:start -->
<!-- Canonical block: identical text in every component README. Source: docs/stack-map.md in the hub. Refresh at the pin round. -->
The Open Control Stack groups its repositories by responsibility. The groups are a navigation map, not an execution sequence and not a requirement to install every component. The hub [component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) is the only source of selected revisions; [release status](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/release-status.md) states their evidence and limits. The component revisions selected for the stack are listed in the hub's `component-lock.json`; this repository does not record which hub commit it was last checked against.

| Group | Members |
| --- | --- |
| **01 Knowledge & Provenance** | [Evidence Registry (The Index)](https://github.com/cogno-us/cognous-evidence-registry) · [Evidence Attestation (BitRep)](https://github.com/cogno-us/cognous-evidence-attestation) |
| **02 Institutional Governance** | [Institutional Governance (Alvorada)](https://github.com/cogno-us/cognous-institutional-governance) |
| **03 Declaration & Policy Control** | [Action Manifest](https://github.com/cogno-us/cognous-action-manifest) · [Control Plane](https://github.com/cogno-us/cognous-control-plane) |
| **04 Constrained Execution** | [Execution Runtime](https://github.com/cogno-us/cognous-execution-runtime) |
| **05 Replay & Evidence** | [Replay Bundle](https://github.com/cogno-us/cognous-replay-bundle) · [Governance Evidence Pack](https://github.com/cogno-us/cognous-governance-evidence-pack) · [ODES](https://github.com/cogno-us/open-decision-evidence-standard) |
| **Cross-cutting exchange** | [Governed Exchange (GAX/IMX)](https://github.com/cogno-us/cognous-governed-exchange) |
| **Tooling and qualification** (side group) | [Ergonomics (`cognous-ocs`)](https://github.com/cogno-us/cognous-open-control-stack-ergonomics) · [Verifier](https://github.com/cogno-us/cognous-open-control-stack-verifier) · [Orchestrator](https://github.com/cogno-us/cognous-stack-orchestrator) · [Qualification](https://github.com/cogno-us/cognous-stack-qualification) |

Status labels used in this README: **merged** (reviewed and merged in the owning repository; not by itself selected), **selected** (pinned in the hub lock), **known limit** (a limitation that is stated and kept visible) and **proposed** (draft or planned work, not a supported interface). Full map, names and commands: [stack map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/stack-map.md), [naming](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/naming.md), [profiles and tools](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/profiles-and-tools.md). A signature, registry entry, message receipt or evidence summary does not grant execution authority.
<!-- stack-map:end -->

This component sits in group 03, beside [Action Manifest](https://github.com/cogno-us/cognous-action-manifest) (which declares the actions it evaluates) and upstream of [Execution Runtime](https://github.com/cogno-us/cognous-execution-runtime), [Replay Bundle](https://github.com/cogno-us/cognous-replay-bundle) and [ODES](https://github.com/cogno-us/open-decision-evidence-standard), which consume its records. Revision-specific qualification commentary is in the [central test hub](https://github.com/cogno-us/cognous-stack-qualification/blob/main/results/readme-commentary/index.md); for audience navigation use the hub [start guide](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/start-here.md).

## Quick start

Prerequisites: Linux, Python 3.11 or newer, an activated virtual environment and network access for the install. Everything below runs locally; nothing contacts a network after the install. From a fresh checkout (about 20 seconds in total):

```bash
python -m pip install -e ".[dev]"
acp validate-run examples/sample_run_record.json
acp run \
  --manifest examples/acp_run/manifest.json \
  --proposal examples/acp_run/authorized/proposal.json \
  --authority-context examples/acp_run/authorized/authority-context.json \
  --resolver-state examples/acp_run/authorized/resolver-state.json \
  --store-dir /tmp/acp-store --out-dir /tmp/acp-out \
  --now 2026-10-05T19:00:00Z
acp validate-run /tmp/acp-out/run-record.json
```

Expected output (exit code 0 each time; the `effect_id` value is a content digest and is the same on every run of these inputs):

```text
RunRecord 069e07a8-5a60-4417-9903-2ddd194f0a37: valid (0 errors, 0 warnings)
acp run: pass (exit 0)
  authorized and applied to the local synthetic destination
  time_source: test_override
  effect_id: sha256:d19d83b15e0ec164f3da356fe7a1ecef64734724d7fd65265e91e95f2ffe2829
  attempt_status: acknowledged
  out_dir: /tmp/acp-out
  does not prove:
    - institutional authority: the resolver is synthetic and not authenticated
    - real-world effect: the destination is a local file, not a provider
    - exactly-once delivery or a safe retry
    - producer authenticity of the input files
    - that run-record.json is anything more than a projection of bounded-run-record.json
RunRecord run-1: valid (0 errors, 0 warnings)
```

Notes on this quick start:

- `--now` is needed. The shipped example fixtures carry fixed October 2026 times; without `--now` the real clock is used, the inputs read as stale, and the run is **held** (exit 1, reason codes ending `_stale_or_future`). `--now` takes a timezone-aware time and is recorded as `time_source: test_override`.
- `--store-dir` and `--out-dir` must be new or empty directories whose parent exists; remove them (`rm -rf /tmp/acp-store /tmp/acp-out`) before a second run.
- `acp run` exit codes: 0 authorized and applied to the local synthetic destination; 1 held at decision time, refused at effect time or rejected by the destination; 2 invalid input or refused path; 4 internal error. To see a hold, run the same command with the `examples/acp_run/held/` inputs (exit 1, reason codes `grant_scope_mismatch` and `requirement_scope_mismatch`; nothing applied).
- What this does not prove: a passing run is internal consistency of a local synthetic run. It does not show institutional authority, a real-world effect or exactly-once delivery. Details: [docs/concepts.md](docs/concepts.md#acp-run).
- For the full selected integration (exact producer checkouts and test wiring) use the [hub quickstart](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/quickstart.md).

## What ships

Status labels as defined above. Everything below is in this repository on `main`; the hub lock records the selected revision (see [compatibility](#compatibility-and-selection)).

### Command line: `acp`

| Command | Purpose | Label |
| --- | --- | --- |
| `acp validate-run <path>` | Validate a run record. | selected |
| `acp validate-replay <path>` | Validate a replay bundle. | selected |
| `acp redact-run <path> --out <file>` | Write a redacted copy of a run record (`--targets`, `--final-output`, `--reasons`, `--replacement`). | selected |
| `acp redact-replay <path> --out <file>` | Write a redacted copy of a replay bundle. | selected |
| `acp sign-replay <path> --secret <key> --out <file>` | Sign a replay bundle. | selected |
| `acp verify-signed-replay <path> --secret <key>` | Verify a signed replay bundle. | selected |
| `acp run --manifest F --proposal F --authority-context F --resolver-state F --store-dir DIR --out-dir DIR [--now T] [--format text\|json]` | Run one declared bounded operation against a local throwaway store ([docs](docs/concepts.md#acp-run)). | merged |
| `acp witness digest\|publish\|verify <path>` | Head digest chain of a record store document, local file witness, drop and rewrite detection ([docs](docs/opt-in-profiles.md)). | merged |

That is eight top-level commands. `acp --help` lists them.

### Profiles

The default path is the bounded authorization workflow described in [docs/bounded_authorization_effect.md](docs/bounded_authorization_effect.md). Every profile below is **proposed**: optional, `0.1.0-draft`, off unless a host configures it, and not selected by the hub. The pinned default path is unchanged for well-formed input; malformed JSON and instants are refused, and record files are written atomically with mode `0600`.

| Profile | Selected by | Documentation |
| --- | --- | --- |
| Local authority/effect claim | an integrator calling the provisioning API | [local-authority-effect-profile.md](docs/local-authority-effect-profile.md) |
| Runtime authority | `RuntimeAuthorityProfile(...)` | [runtime-authority-profile.md](docs/runtime-authority-profile.md) |
| Rule revision | `rule_revision_profile=` on the workflow | [rule-revision-profile.md](docs/rule-revision-profile.md) |
| Decision input commitment | optional opaque hooks only | [decision-input-commitment-profile.md](docs/decision-input-commitment-profile.md) |
| Durable effect-time refusal evidence | scoped qualification, not activated | [durable-refusal-profile.md](docs/durable-refusal-profile.md) |
| Operation identity, freshness, witness digest, holder inventory, merge record, reversibility, dedupe-ttl, terminal revocation | `RuntimeAuthorityProfile` fields (witness: host call) | [opt-in-profiles.md](docs/opt-in-profiles.md) (one row each) |
| Microsoft Agent Governance Toolkit pre-tool-call compatibility | optional extra, not in the lock | [microsoft-agt-compatibility.md](docs/microsoft-agt-compatibility.md) |

The reason registry has three labels: `runtime-authority-reasons/0.1` (the original 121 codes), `/0.2` (the frozen 164) and `/0.3` (172: the 164 plus eight policy-binding codes, proposed and not ratified). Operator-supplied and stored JSON is read strictly.

### Schemas, modules, examples and tools

- **Schemas (18)** in [schemas/](schemas): run record, replay bundle, signed replay bundle, action proposal, authority record, frame, policy decision, policy evaluation trace and rule evaluation, redaction configuration, reliance record, tool execution result, validation issue and report, runtime-authority configuration and run (0.1), and the two reason registries (`runtime_authority_reasons_0_1.json`, `runtime_authority_reasons_0_2.json`).
- **Modules (32 plus the package `__init__.py`)** under [src/agent_control_plane/](src/agent_control_plane). Each module docstring states its limits; the module-by-module list is in [docs/README.md](docs/README.md#source-modules).
- **Examples** in [examples/](examples): `acp_run/` (authorized and held input sets, used above), `sample_run_record.json`, `policy_config.json` and five scripts run with `python examples/<name>.py`: `policy_config_demo.py`, `simple_agent_run.py` (rewrites `examples/sample_run_record.json`), `tool_adapter_demo.py`, `tool_policy_demo.py` and `framework_integration_demo.py`. `tool_adapter_demo.py` and `framework_integration_demo.py` write under `examples/output/`.
- **Tools** in [tools/](tools): `verify_decision_input_commitment.py` and `adversarial_mutations.py`; conformance vectors in [conformance/](conformance).

## What it does not do (known limits)

Each item is a stated limit that is kept visible. Items marked as pinned have a test whose name ends in `_known_limit`; a later change to that behaviour must be deliberate.

| Limit | Detail |
| --- | --- |
| Workflow is not atomic | Individual record transactions are protected (cooperating local Linux writers, documented filesystems). The whole decide, execute and reconcile workflow is not atomic. Production resolver authentication, distributed budgets, remote finality and exactly-once delivery are not established. |
| Provisioned claim covers a subset of inputs | A claim-only store that validates the provisioned claim does not see a later change of identity authentication or mandate validity: the claim carries neither. Issuing a new claim and the default execute path both re-read them and refuse. Holds for the claim-only store modelled in the test, not for a shipped runtime. See [docs/local-authority-effect-profile.md](docs/local-authority-effect-profile.md) and `tests/test_known_limits.py`. |
| Payload policy is value-blind | The payload policy checks field names, not values. A field that selects a recipient, resource or amount belongs in `target` or `amount`, which are checked against the grant. A per-field value constraint is a freeze item. |
| Approvals prove identity, not what was shown | An approval record proves the approver's identity and commitment to the operation commitment, not what the approver was shown. A human step-up profile is a freeze item. |
| Delegation is refused | A grant naming a parent is held with `delegation_profile_unsupported`. Entry conditions for enabling it are in [docs/bounded_authorization_effect.md](docs/bounded_authorization_effect.md#delegation-entry-conditions). |
| Budgets are per grant | The destination counts effects per grant identity. Three independently issued grants of 40 can reach 120; no parent total is consulted (pinned). |
| Decision age is not consulted | A week-old authorized decision still executes when the inputs read now match (pinned). |
| Operation identity | The same operation id with a different payload gets the same refusal as a replay, `operation_already_committed` (pinned). The operation ledger has no retention rule: removing its rows lets a revision-2 decision authorize, while the destination still refuses the second effect (pinned). |
| Holds keep no lifecycle | A hold keeps its resolution inputs and reasons on the default path, but no binding, lifecycle or link to a later decision (pinned). |
| A manifest action without `authority_context` | Does not pin the proposal's authority-context reference; the decision still holds through the institution, domain and tier comparisons (pinned). |
| `minimum_count` of 0 | An explicit operator declaration; it passes with a count of 0 (pinned). |
| Record store is not tamper evidence | The store is a plain JSON file under a same-host lock with no keyed integrity check. `signer` and `issuer` members are asserted names. |
| Credentials | The destination check says nothing about credentials inherited by subprocesses. The hub [guarantees and limits](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/guarantees-and-limits.md) page carries the complete wording. |
| Reason registry classes | The 164-code runtime-authority registry classifies codes only as `typed_only` or `recomputable`; it does not separate unavailable input from withheld policy. A blocked count is not a denial count. |

Review original artifacts and their exact source revisions before extending a claim to a new environment. New dependencies, authority sources, destinations or enforcement mechanisms need their own compatibility and qualification. A passing reference case is not a certification of an enterprise deployment.

## Documentation

The [documentation index](docs/README.md) lists every page in this repository by role (new reader, integrator, reviewer, maintainer) and marks historical checkpoints. Start with [docs/concepts.md](docs/concepts.md) and [docs/architecture.md](docs/architecture.md); for the contract and its limits read [docs/bounded_authorization_effect.md](docs/bounded_authorization_effect.md). For a non-technical introduction, read the [business overview](collateral/business-collateral.md) and [one-page overview](collateral/one-page-overview.md); both describe this component's role and evidence limits, not additional runtime features.

## Compatibility and selection

The [component lock](https://github.com/cogno-us/cognous-open-control-stack/blob/main/component-lock.json) selects the integration; a merge here does not change that selection or approve deployment. The hub lock records the selected revision of this repository (bounded authorization/effect 0.1); see the lock for that revision. The `run` and `witness` commands and the opt-in profiles above are labelled by their own status, not by the lock.
Source acceptance, selection and deployment approval remain separate decisions. Contract drafts consumed from [ODES](https://github.com/cogno-us/open-decision-evidence-standard) are vendored under `tests/contracts/`; they are `0.1.0-draft` and are not edited here. The persistence contract covers cooperating local Linux writers; historical persistence qualification commentary is in the central test hub.

## Run the tests

```bash
python -m pip install -e ".[dev]"
python -m pytest -q   # about five minutes
```

The `dev` extra includes `pytest-asyncio`, which the Microsoft AGT compatibility tests need; one test there is skipped unless the pinned third-party SDK is installed.

## Contributing and attribution

[Contribution guidance](CONTRIBUTING.md) describes review and validation expectations; see also [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and the [CHANGELOG](CHANGELOG.md). Keep evidence-linked claims, preserve historical records and separate proposed features from accepted implementation.

See [LICENSE](LICENSE) and [attribution](NOTICE) for the existing terms and third-party scope. Developed by [Cognous](https://cogno.us); no licensing change is part of this documentation update. Repository renames: see the [rename map](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/repository-renames.md); package names, schema identifiers and retained producer identities are unchanged.

---

## Bibliography

Selected external sources from the October 2026 research review. These inform evaluation questions; they do not establish Cognous implementation, adoption, conformance or production qualification.

- [John M. Willis. *Runtime Governance Body of Knowledge for Artificial Intelligence and Other Autonomous Systems — Glossary* (19 July 2026)](https://sustainablefuturetech.com/asg-wg-runtime-governance-glossary/). Discussion draft on authority, execution and evidence terminology; not an adopted standard or Cognous conformance requirement.
- Jonathan Chadbourne / JCEE Labs. *When a Timeout Is Not a Failure: Authority, Evidence, and Recovery in Consequential AI Execution*. Technical Note 001, public release v0.1.1 (6 October 2026). Technical note on uncertain outcomes and recovery. An original public URL has not been verified; no substitute or private copy is linked.
- [OWASP GenAI Security Project. *State of Agentic AI Security and Governance*, version 2.01 (June 2026)](https://genai.owasp.org/resource/state-of-agentic-ai-security-and-governance/). Security synthesis covering agent identity, delegated permissions, tool access and containment.

See the [research bibliography](https://github.com/cogno-us/cognous-open-control-stack/blob/main/docs/research-bibliography.md) for review scope and source-verification limits.

<!-- Retained anchors for existing documentation links. -->
<a id="current-selection-versus-historical-qualification"></a>
<a id="evidence-and-supported-scope"></a>
