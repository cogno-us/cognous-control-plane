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

Tool identity invariant (R1-A2): AGT must never evaluate a tool identity that
differs from the proposal identity Cognous authorizes. At adapter entry, on the
private proposal snapshot and before AGT is asked, `tool_name` and
`proposal.adapter_id` are bound as one identity:

- without `tool_bindings`, `tool_name` must equal `proposal.adapter_id` exactly
  (no trimming, case folding or inference); otherwise the evaluation is held with
  reason `tool_identity_unbound`;
- with `tool_bindings={adapter_id: tool_name}` (built from the same trusted
  manifest entries as the proposals), the exact entry for `proposal.adapter_id`
  must equal `tool_name`; a missing entry or any difference is held with reason
  `tool_binding_mismatch`, and the adapter_id is not accepted as an alias;
- a missing, empty or non-exact-`str` `tool_name` or `adapter_id` (a `str` subclass is refused, since it can override equality) is held with
  `tool_identity_unbound`; `tool_bindings` keys and values must be non-empty exact `str` (else the constructor raises `ValueError`) and are copied at construction;
- a transform replaces only the payload; if the effective proposal's `adapter_id`
  differs from the bound one the evaluation is held with
  `transform_identity_changed` and Cognous is not asked;
- the bound `adapter_id` is recorded as `evidence.bound_adapter_id`, so the AGT
  decision (`evidence.tool_name`) and the Cognous authorization (the effective
  proposal) are tied to the same identity.

All holds occur before AGT and Cognous are called. Callers must supply a
`tool_bindings` map built from trusted configuration when the external AGT tool
name differs from the adapter ID.

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

This is intentionally conservative. A transform cannot change the adapter
identity bound at entry (held as `transform_identity_changed`). A transform that changes target, action,
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
