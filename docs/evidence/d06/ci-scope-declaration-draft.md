# CI Scope Declaration (DRAFT) - Control Plane D-06 persisted effective-configuration binding

Status: BUILDER_TESTED developer record, written by the implementation worker (Worker A, OCS-REG-FINAL3). Non-authorizing. **Not independently qualified; F3-A independent qualification is PENDING.** Independent Tier 1 qualification: DEFERRED, NOT WAIVED. Nothing here is a certification, a security clearance or a production-readiness claim; production, publication and release remain on HOLD. This declaration is model output and approves nothing.

* Risk tier: T3 (change); T4 is prescribed for the independent qualification and final engineering freeze (`03-f3-qualification-expectations-F3A-F3B-2026-10-29.md`).
* Governance baseline named by the Architect: `cogno-us/cognous-engineering-constitution` `230c0aff1c2d1e054652cfc1be175147260b8aae`.
* Base: Control Plane `main` `b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa`. Branch `d06-effective-configuration-binding`.
* Exact head of the SOURCE and TESTS declared here: `7bfe8424e99603acaa00abd35ebaaad608c2a86f` (later commits on the branch, if any, add only evidence/docs files and are listed in the final report; they do not change `src/` or `tests/`). A pass at this head does not transfer to any other revision (CA07).
* Dependencies: none. This change is independent of the D-07 PR (`runtime_authority.py`, different worktree) and of the Registry `r08-v8` work; it does not edit Registry, CP #94, `runtime_authority.py` or any other protected evaluator.

## Scope of the change
Files changed in `src/`: new `effective_configuration_binding.py`; `registry_governed_lifecycle.py`; `registry_governed_policy.py`. No protected evaluator (`bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`, `rule_revision.py`, `reversibility.py`, `holder_inventory.py`), no schema, no approval preimage / `approval_commitment` / `catalogue_digest` / `RuntimeAuthorityProfile`, no reason vocabulary and no Registry file changed. SHA-256 of the seven protected files are byte-identical to the pre-change baseline (`protected-hashes-b7eb11a.txt` versus `protected-hashes-final.txt`; `test_z03` also passes).

## Tests executed (this head; Python 3.13.17 in the scratch venv; Registry pin `b73c59e6769acd5af7263397e81dfc6fa4561f38` for the r08-v7 suites, `6f600ab1150f00ef3d96834159b1807e866a78b6` for the two older-pin suites)
| run | result | raw output |
|---|---|---|
| Affected suites, baseline at b7eb11a, v7 pin (governed composition, F5 unreadable, irreversibility x2, revocation families, pin export, bounded authorization, runtime authority, local authority effect, policy-binding approval generation) | 825 passed | `baseline-b7eb11a-v7pin.log` |
| Same suites + the three new D-06 files, this head | 1017 passed, 1 xfailed (the superseded `test_i04`, strict) | `final-v7pin.log` |
| F4 and F5 class-age suites (older pin), baseline | 184 passed | `baseline-b7eb11a-oldpin.log` |
| F4 and F5 class-age suites (older pin), this head | 184 passed | `final-oldpin.log` |
| FULL suite, baseline b7eb11a (v7 pin, `--continue-on-collection-errors`) | 41 failed, 1901 passed, 90 skipped, 2 collection errors | `baseline-b7eb11a-FULL.log` |
| FULL suite, this head (same command) | 41 failed, 2093 passed, 90 skipped, 1 xfailed, 2 collection errors | `final-FULL.log` |
| New pure unit file on Python 3.11 and 3.12 | 54 passed each | `final-py3.11-unit-only.log`, `final-py3.12-unit-only.log` |
| Mutation harness (49 mutants, scratch copies of this head's source) | 47 killed, 2 survived (both explained below) | `mutation/summary.json`, `mutation-extra/summary.json`, per-mutant logs |

New tests: 54 unit + 112 workflow + 27 legacy/cross-process = 193 collected, all passed (825 baseline - 1 superseded `test_i04` + 193 = 1017). The Registry-pinned suites need `OCS_REGISTRY_PIN_DIR` and PyNaCl; the 3.11 and 3.12 scratch venvs have no PyNaCl, so only the pure unit file ran there.

## Original and new failures
* Baseline failures (identical set before and after, compared by name): 41 FAILED (`test_microsoft_agt.py` 14, `test_scan6_agt_exact.py` 16, `test_v02_claim_policy_binding.py` 6, `test_wave7_agt_binding_equality.py` 5) and 2 collection ERRORS (`test_f4_age_governance.py`, `test_f5_class_age_governance.py` expect the older Registry pin when run with the v7 pin directory; they pass, 184 tests, with that pin). They are environmental (missing `cognous_verify` / `agent_action_manifest` / other pins) and are NOT introduced or fixed here.
* New failures: none.
* Tests whose outcome the authorized behaviour change inverts: `tests/test_governed_policy_composition.py::test_i04_...` (the documented gap). Original body kept verbatim, now `xfail(strict=True)` with a comment citing the authorization; documented successor `test_effective_configuration_binding.py::test_c03_the_documented_i04_scenario_now_refuses`; the original passing result is `baseline-b7eb11a-v7pin.log`. `test_z04` passed unchanged.

## Evidence reused
None. Nothing from an earlier revision is claimed for this head. The legacy fixtures were generated by the UNCHANGED prior code at b7eb11a on purpose and are committed unchanged (`tests/fixtures/d06_legacy_store_*.json`, generator and provenance in `gen_legacy_fixture.py` and `d06_legacy_store_meta.json`); their applicability to this head is shown by the tests that load them.

## Not run, and why
* Independent qualification F3-A (and F3-B): not run; it is specified to be performed by an independent party, and the builder must not qualify its own work.
* GitHub Actions / the repository CI workflows: not run (no push, no PR by instruction); the local equivalent is the pytest commands above. The CI matrix (Python 3.11 and 3.12) was only partially reproduced locally (unit file only).
* The cross-component suites in `CROSS_COMPONENT_TESTS.md` / the pinned qualification workflows in `cogno-us/cognous-stack-qualification`: not run.
* A durable-store crash-injection harness around `_append`: only the failed-append case is tested (`test_a07`).

## Mutation results (developer evidence; honest list)
Killed (47): drop each of the seven members from the preimage, drop the domain, drop the version, skip digest recomputation, skip members validation, accept an unknown version, digest-only comparison combined with no recomputation, treat missing as legacy without a cutoff, cutoff off-by-one, cutoff not validated, cutoff above the store accepted, unknown position treated as legacy, all-zero digest allowed, bool accepted as scalar, no scalar upper range, no validation in `build_members`, unknown family slot skipped, extra record keys tolerated, skip the claim path, skip the execute check, legacy ignores other keys, never stamp the live member, a hold turned into an authorization, no mint on decide, an unbindable live configuration falling back to unbound, execute not carrying the decision (no-profile path), held-state guard blind to the ObservationPolicy / to the other scalars / disabled, construction skipping validation, cutoff not validated / not applied at the constructor, F4 scalars not live, constructor tolerance not live, host digest used as effective digest, fixed tenant in the scope, empty family set, no schema revisions, null ObservationPolicy, the defensive guard removed, and the persisted member stamped with the guard removed.
Survived (2), reported as such:
1. `compare-only-digest` - EQUIVALENT: `record_defect` already proves `digest == recomputation(members)` before the comparison, so digest equality implies member equality. (With recomputation also removed the mutant is killed.)
2. `stamp-persisted-member` - survives ALONE because the defensive guard (stamped equals persisted although the status is not accepted) still refuses; combined with removing the guard it is killed. The run also showed the guard is LOAD-BEARING and not merely redundant: Python equality conflates `60.0 == 60` and `True == 1`, so a malformed persisted member can compare equal to the live one and only the classification refuses it (`test_d01[float_scalar]`).
Weakness to know: nine "drop member from the preimage" mutants are killed only by the golden-digest test (the live comparison also compares the members themselves, so the redundancy hides a dropped member from the end-to-end tests). That is a property of the redundant design, not evidence that every member is independently protected by the digest alone.
Harness note: the first full run marked the last two added mutants INVALID (the harness text carried a stale source comment); they were re-run against the same source and are in `mutation-extra/`.

## Remaining qualification obligations
* F3-A independent qualification of this head: PENDING (nothing is accepted by this document).
* Independent Tier 1 qualification: DEFERRED, NOT WAIVED. Accounting is unchanged until the enforcement implementations merge and independent evidence is recorded: 16/19 integrated, 3 remaining, 0 independently accepted.
* Merging, deployment, publication: not performed, not authorized here.

## Known limits (must be repeated by any reader of this declaration)
Unsigned local JSON store (guards DRIFT, not a malicious store writer); NO anti-rollback guarantee; the `legacy_cutoff` is host configuration without durable provenance, and a stripped member below the cutoff is indistinguishable from a legacy record; mixed-fleet legacy writers still append records without the member (new readers refuse them past the cutoff, legacy readers accept them); a legacy decision below the cutoff keeps the previous gap; only the composed `GovernedPolicyWorkflow` binds (the three dedicated single-family workflows do not; a one-hook addition to each module is the follow-up); the five scalars and the ObservationPolicy must now be exact ints in 0..2147483647 at construction; JSON duplicate keys in the store are resolved by the store loader (last wins) before this code sees them.
