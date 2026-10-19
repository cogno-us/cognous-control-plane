# W0 contract addendum: C1, C2, C4 and C6

Status: W0 candidate contract. No runtime behavior is changed by this document.

## Baseline
Inspected Control Plane main at the time of writing: `d3dadee70bd319812b207389ab1e0f6efe511916`.
Existing bounded authorization/effect 0.1 remains historical and supported.

## C1 exact action binding
For tenant-aware V1, `RuntimeProposal` and `AuthorizationBinding` gain a new contract generation, `bounded-authorization-effect/0.2`, that requires the Manifest proposal `tenant_id` unchanged. The field is included in the full proposal commitment and copied into the authorization binding. Tenant is not inferred from institution, authority domain, target, payload, adapter metadata or caller assertions.

## C2 current authority
At decision and effect-time revalidation, the exact tenant must join the existing grant/approval/current-policy inputs. A conforming 0.2 binding includes:
- `tenant_id`
- existing proposal commitment and exact action fields
- grant ID/revision
- approval references/revisions where applicable
- policy versions, evidence freshness inputs and role mapping version/digest.

Wrong tenant, wrong grant/approval, expiry, revocation or changed protected inputs yields no protected dispatch. Earlier committed effects remain historical.

Credentials, reviews, remedies, adapter allowances and replay do not issue Cognous grants. Atomic authority/effect and refund-intent profiles remain separate and MUST NOT share or reinterpret identity/store semantics.

## C4 failure record
W0 freezes typed failure classes for the bounded path:
`policy_denial`, `authority_hold`, `malformed_input`, `capability_unavailable`, `evaluation_error`, `dispatch_error`.

A retained failure record identifies the decision/run correlation, proposal commitment when available, relevant input revisions, failure class, reason codes, stage (`pre_dispatch` or `post_dispatch`) and minimized protected references. Missing evidence is not success and is not proof of no effect.

Existing decision/attempt namespaces are retained. W2 must verify whether current outer callers already persist each path before adding a new record type.

## C6 flow and result admission join
For an optional flow profile, dispatch is permitted only when the external flow decision and current Cognous authorization refer to the identical C1 canonical operation. Result admission is a separate decision bound to exact attempt/effect and result identity. Withholding a result does not erase an applied effect.

No external remedy, escalation or flow decision has Cognous authority effect by itself.

## Migration
- 0.1 historical records remain decodable.
- 0.2 tenant-aware records require tenant; no backfill/default.
- Changed action/tenant/profile bytes require fresh authorization.
- W1 implements tenant producer/enforcement changes; W2 validates/repairs failure retention; W4 implements optional flow semantics.
