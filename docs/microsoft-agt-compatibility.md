# Optional Microsoft Agent Governance Toolkit compatibility profile

Status: optional W5 compatibility surface. It is not part of the core component lock.

## Pin

- Upstream: `microsoft/agent-governance-toolkit`
- Revision: `84ae67348705996a3d65e31936afb7d02853f2a0`
- Selected SDK: Python `agent-control-specification` `0.4.0b0`
- License: MIT
- Python prerequisite: 3.11+
- Selected intervention point: `pre_tool_call`

The pinned SDK exposes `InterventionPoint.PRE_TOOL_CALL`,
`InterventionPointRequest`, `InterventionPointResult`, and an async
`RuntimeClient.evaluate_intervention_point(...)` boundary. The current engine
produces allow/deny/transform; warning is carried in `warnings[]`, and
approval/escalation semantics are represented as deny-side host behavior.
Legacy enum members are treated conservatively by this profile.

## Mapping

The compatibility adapter receives a Cognous `RuntimeProposal` plus an
explicit `tenant_id`. It sends only the bounded tool name, tool call identity,
proposal payload and supplied snapshot to AGT `pre_tool_call`.

Limit: the `tool_name` sent to AGT is supplied by the caller of
`MicrosoftAgtPreToolCallAdapter.evaluate`. By default the adapter does not check
it against the proposal's `action_id`, `adapter_id` or the manifest tool mapping,
so a caller can pair a benign tool name (evaluated by AGT) with a different
proposal (evaluated by Cognous), and AGT's tool-specific rules then apply to the
wrong tool identity. Opt-in binding: pass `tool_bindings={adapter_id: tool_name}`
(built from the same trusted manifest entries as the proposals) to the adapter;
an evaluation whose proposal adapter has no entry, or whose `tool_name` differs,
is held with reason `tool_binding_mismatch` before AGT is asked. Without
`tool_bindings` the integration must still derive `tool_name` from the same
trusted manifest entry as the proposal.

Cognous remains authoritative for:
- exact tenant;
- action ID and adapter ID;
- target and payload commitment;
- requested permissions and effect limits;
- grant/approval/policy/evidence freshness;
- the final protected-dispatch decision.

AGT is conjunctive only. An AGT allow is not a grant and cannot override a
Cognous hold/deny. AGT denial blocks the compatibility path. Warning,
escalation, unavailable service, malformed/unsupported response and evaluation
error do not authorize.

## Transform rule

A transform may replace only the AGT policy target. For this profile the policy
target must materialize as a mapping usable as the Cognous proposal payload.
The adapter recalculates `payload_commitment` and invokes Cognous authority
again on the transformed proposal. Authorization for the original proposal is
never reused.

This is intentionally conservative. A transform that changes target, action,
tool/adapter identity, tenant, amount, permissions, or other commitment-bearing
fields is unsupported by this profile and must be represented as a new Cognous
proposal by the caller, followed by fresh authorization.

Exactness (scan 6): the AGT decision string is matched exactly (`allow`, `deny`, `escalate`, `warn`, `transform`); any other spelling, including a
different case or surrounding whitespace, is held as `unsupported_agt_decision`. The tenant is passed on exactly as supplied; only a blank
tenant is `tenant_missing`. A transformed proposal whose Cognous authorization carries no decision binding is held with
`transform_authorization_unbound`.

## Evidence boundary

The adapter records:
- exact AGT upstream revision and compatibility profile;
- tool and call identity;
- AGT decision, reason/message, warnings and input/enforced identities;
- opaque AGT evidence artefact and verification pointers;
- original and effective Cognous proposal commitments;
- Cognous decision ID/result when evaluated;
- whether a transform occurred.

AGT telemetry/evidence is source-attributed evidence about the AGT decision.
It is not proof of Cognous authority, destination execution, observation or
independent verification.

## Tenant input

At W0 baseline `74a3f1e7d7c872ad1b61fd9f857ac5fa517615f5`, `RuntimeProposal`
had no tenant field, so W5 accepted tenant as an explicit required
compatibility input. The tenant-aware 0.2 producer type now exists as
`TenantRuntimeProposal` (with `tenant_id`) in
`agent_control_plane.bounded`; the historical 0.1 `RuntimeProposal` remains
tenantless.

The adapter still requires the explicit `tenant_id` argument and passes it
unchanged to AGT and to the independent Cognous authority evaluator. When the
proposal carries a `tenant_id` (`TenantRuntimeProposal`) that differs from the
argument, the evaluation is held with reason `tenant_mismatch` before AGT is
asked; a tenantless 0.1 `RuntimeProposal` is unchanged. It must not infer or
default tenant.

## Qualification

Unit tests use deterministic local fakes for AGT outcomes and the Cognous
authority evaluator. `test_real_sdk_types_are_supported_when_installed`
uses the actual pinned Python SDK types and request shape with an in-process
runtime client. The W5 qualification workflow installs the SDK from the exact
upstream revision and runs this test plus the adapter suite.

That is a real SDK compatibility test, but not a live remote policy service.
No cloud service, tenant, identity provider, or external approval backend is
required or claimed. A deployment using OPA/Cedar/remote annotators requires
its own backend-specific qualification and must fail closed when unavailable.
