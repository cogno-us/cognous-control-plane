# CI Scope Declaration (DRAFT) - Control Plane D-06 persisted effective-configuration binding

Status: BUILDER_TESTED developer record, written by the implementation worker (Worker A, OCS-REG-FINAL3). Non-authorizing. **Not independently qualified; F3-A independent qualification is PENDING.** Independent Tier 1 qualification: DEFERRED, NOT WAIVED. Nothing here is a certification, a security clearance or a production-readiness claim; production, publication and release remain on HOLD. This declaration is model output and approves nothing.

* Risk tier: T3 (change); T4 is prescribed for the independent qualification and final engineering freeze (`03-f3-qualification-expectations-F3A-F3B-2026-10-29.md`).
* Governance baseline named by the Architect: `cogno-us/cognous-engineering-constitution` `230c0aff1c2d1e054652cfc1be175147260b8aae`.
* Base: Control Plane `main` `b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa`. Branch `d06-effective-configuration-binding`.
* Exact head of the SOURCE and TESTS declared here: `5ffd0ae20f406d614da047f3f9cb8e8dc227a7a5` (CI-gate repair and review hardening on top of `74ad2fa`, the commit that made the three dedicated single-family workflows bind and `c86f733`, its docs; it supersedes the first-round source/test head `7bfe8424e99603acaa00abd35ebaaad608c2a86f`, whose evidence is kept under the `final-*` logs and does NOT transfer to this head). Later commits on the branch add only evidence/docs files and are listed in the final report; they do not change `src/` or `tests/`. A pass at this head does not transfer to any other revision (CA07).
* Dependencies: none. This change is independent of the D-07 PR (`runtime_authority.py`, different worktree) and of the Registry `r08-v8` work; it does not edit Registry, CP #94, `runtime_authority.py` or any other protected evaluator.

## Scope of the change
Files changed in `src/`: new `effective_configuration_binding.py`; `registry_governed_lifecycle.py` (now holds the shared members builder, held-state guard, cutoff check and bind step); `registry_governed_policy.py` (moved onto the shared code); and, in the follow-up, the three dedicated workflows `registry_f4_age_governance.py`, `registry_f5_class_age_governance.py`, `registry_f5_class_unreadable_governance.py` (each: a `legacy_cutoff=0` keyword, one shared bind call, one held-guard line and one `_gl_configuration_members` hook). `registry_revocation_governance.py` and `registry_irreversibility_governance.py` were checked and do not construct decision-minting workflows: unchanged. `registry_effective_policy.py`, `authorization_pin_export.py` and `schemas/` are byte-identical to b7eb11a. No protected evaluator (`bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`, `rule_revision.py`, `reversibility.py`, `holder_inventory.py`), no schema, no approval preimage / `approval_commitment` / `catalogue_digest` / `RuntimeAuthorityProfile`, no reason vocabulary and no Registry file changed. SHA-256 of the seven protected files are byte-identical to the pre-change baseline (`protected-hashes-b7eb11a.txt` versus `protected-hashes-final2.txt`; `test_z03` also passes). Byte pins of the F4 and class-age consumers in `tests/test_f5_class_age_governance.py` and `tests/test_f5_class_unreadable_governance.py` were updated with comments (the modules changed by authorization); the protected-evaluator pins are unchanged.

## Tests executed (this head; Python 3.13.17 in the scratch venv; Registry pin `b73c59e6769acd5af7263397e81dfc6fa4561f38` for the r08-v7 suites, `6f600ab1150f00ef3d96834159b1807e866a78b6` for the two older-pin suites)
| run | result | raw output |
|---|---|---|
| Affected suites, baseline at b7eb11a, v7 pin | 825 passed | `baseline-b7eb11a-v7pin.log` |
| Same suites + the four D-06 files, this head | 1216 passed, 0 xfailed, 0 skipped | `final3-v7pin.log` |
| F4 and F5 class-age suites (older pin), baseline / this head | 184 passed / 184 passed | `baseline-b7eb11a-oldpin.log`, `final3-oldpin.log` |
| FULL suite, baseline b7eb11a (v7 pin, `--continue-on-collection-errors`, Python 3.13) | 41 failed, 1901 passed, 90 skipped, 2 collection errors | `baseline-b7eb11a-FULL.log` |
| FULL suite, this head (same command) | 41 failed, 2292 passed, 90 skipped, 2 collection errors; failure set identical to the baseline by name | `final3-FULL.log` |
| CI junit gates, replayed locally exactly as `tests.yml` (section "CI gate reproduction") | all six PASS on Python 3.13, 3.12 and 3.11 | `ci-gates/` |
| Mutation harness (67 mutants, scratch copies of this head's source) | 65 killed, 2 survived (both explained below) | `mutation-final3/summary.json`, `mutation-final3-run.log`, `mutation-final3-extra/` |

First-round numbers (head 7bfe842, no dedicated hooks): 1017 passed / 1 xfailed in the affected suites; full suite 2093 passed; 49 mutants, 47 killed, 2 survived. Those logs (`final-*`) stay as history and are not claimed for this head.

New tests: 54 unit + 115 workflow + 27 legacy/cross-process + 195 dedicated-workflow = 391 collected, all passed (no xfail, no skip). Check: 825 baseline + 391 = 1216 passed. The Registry-pinned suites need `OCS_REGISTRY_PIN_DIR` and PyNaCl; the 3.11 and 3.12 scratch venvs have no PyNaCl, so only the pure unit file ran there.

## Original and new failures
* Baseline failures (identical set before and after, compared by name): 41 FAILED (`test_microsoft_agt.py` 14, `test_scan6_agt_exact.py` 16, `test_v02_claim_policy_binding.py` 6, `test_wave7_agt_binding_equality.py` 5) and 2 collection ERRORS (`test_f4_age_governance.py`, `test_f5_class_age_governance.py` expect the older Registry pin when run with the v7 pin directory; they pass, 184 tests, with that pin). They are environmental (missing `cognous_verify` / `agent_action_manifest` / other pins) and are NOT introduced or fixed here.
* New failures: none.
* Tests whose outcome the authorized behaviour change inverts: `tests/test_governed_policy_composition.py::test_i04_...` (the documented gap) and `tests/test_effective_configuration_binding.py::test_h05_...` (dedicated workflows do not bind). Both are converted IN PLACE into their successor form: same fixtures, the inverted assertions, and a SUPERSESSION RECORD in the docstring quoting the original assertions verbatim, citing the authorization, the baseline evidence file (`baseline-b7eb11a-v7pin.log`, `final-v7pin.log`) and b7eb11a. NO xfail or skip is used in any gated suite: the first CI run failed the junit gate (`governed policy tests: 99 run, 1 skipped, 0 failed`) because a strict xfail is reported as skipped. Further successor `test_c03` (adds classification and the durable refusal row). `test_z04`, `test_x01` and `test_e08` forbid certain strings in the lifecycle module; a first draft of the shared code tripped them (a detail string containing `on_unreadable` as a substring) and was renamed; they pass unchanged.

## Evidence reused
None. Nothing from an earlier revision is claimed for this head. The legacy fixtures were generated by the UNCHANGED prior code at b7eb11a on purpose and are committed unchanged (`tests/fixtures/d06_legacy_store_*.json`, generator and provenance in `gen_legacy_fixture.py` and `d06_legacy_store_meta.json`); their applicability to this head is shown by the tests that load them.

## Not run, and why
* Independent qualification F3-A (and F3-B): not run; it is specified to be performed by an independent party, and the builder must not qualify its own work.
* GitHub Actions / the repository CI workflows: not run (no push, no PR by instruction); the local equivalent is the pytest commands above. The CI matrix (Python 3.11 and 3.12) was only partially reproduced locally (unit file only).
* The cross-component suites in `CROSS_COMPONENT_TESTS.md` / the pinned qualification workflows in `cogno-us/cognous-stack-qualification`: not run.
* A durable-store crash-injection harness around `_append`: only the failed-append case is tested (`test_a07`).

## CI gate reproduction (local replay of `.github/workflows/tests.yml`)
Method: `docs/evidence/d06/ci_gates.sh` runs each gated step with the workflow's pytest arguments, `OCS_REGISTRY_PIN_DIR` / `OCS_REQUIRE_REGISTRY_PIN=1` and the junit gate script (skipped == 0, failed == 0, n >= minimum) against read-only detached Registry worktrees of the four pins (6f600ab, 6c3e5e4, 42a6663, b73c59e), then the plain `pytest` step (no pin env) and `tools/adversarial_mutations.py`. Not run: GitHub-hosted runners themselves, the `manifest-validator-parity` job (needs the `agent_action_manifest` package).

| gate (pin) | minimum | b7eb11a baseline | c86f733 BEFORE the repair | this head |
|---|---|---|---|---|
| F4 age (6f600ab) | 70 | 73 run, 0 skipped | 73, 0 | 73, 0 skipped, 0 failed |
| F5 class age (6f600ab) | 105 | 111, 0 | 111, 0 | 111, 0, 0 |
| F5 on_unreadable (6c3e5e4) | 148 | 148, 0 | 148, 0 | 148, 0, 0 |
| composed governed policy (6c3e5e4) | 99 | 99, 0 | 99, **1 skipped -> FAIL** | 99, 0, 0 |
| revocation families + composed + unreadable (42a6663) | 388 | 388, 0 | 388, **1 skipped -> FAIL** | 388, 0, 0 |
| irreversibility + unit + revocation + composed + unreadable (b73c59e) | 576 | 576, 0 | 576, **1 skipped -> FAIL** | 576, 0, 0 |
| plain `pytest`, Python 3.13 scratch env (no pin env) | - | 35 failed, 1372 passed, 102 skipped | 35 failed, 1426 passed, 105 skipped | 35 failed (same names as the baseline), 1426 passed, 105 skipped (`ci-gates/after/plain.txt`) |
| plain `pytest`, Python 3.11 and 3.12 with the hash-locked PyNaCl 1.6.2 | - | not run | not run | 1460 passed, 106 skipped, 0 failed (both) |
| `tools/adversarial_mutations.py` | - | exit 0 (`DETECTED: unknown-context`) | exit 0 | exit 0 |

Cause of the original failure (reproduced, evidence `ci-gate-governed-policy-before.txt`, `ci-gate-revocation-families-before.txt`, `ci-gate-irreversibility-before.txt`): the strict xfail of `test_i04` is counted as skipped by the junit gate. The gated minimums are unchanged and unreduced; the gated suites contain exactly the same number of tests as before. The 35 plain-`pytest` failures in the Python 3.13 scratch env are environmental (missing optional modules) and identical to the baseline set; under Python 3.11 and 3.12 the plain run has 0 failures. The new D-06 test modules skip at module level when no Registry pin is configured (like the existing pin-requiring modules), so the plain step shows 3 more skipped than the baseline; they are not in any gated step and under a pin they run with 0 skipped.

## Mutation results (developer evidence; honest list)
67 mutants against this head (the harness is pointed at the shared lifecycle code and includes 17 dedicated-workflow mutants and 3 for the review hardening: oversize cutoff accepted, unreadable store ignored while counting, base hook meaning "bind nothing"). 64 were killed in the main run; `cutoff-count-load-failure-ignored` survived at first (no test of an unreadable store) and is killed after the added `test_d20` (`mutation-final3-extra/`). The control (unmutated copy) passes; none INVALID.
Survived (2), reported as such:
1. `compare-only-digest` - EQUIVALENT: `record_defect` already proves `digest == recomputation(members)` before the comparison, so digest equality implies member equality. (With recomputation also removed the mutant is killed.)
2. `stamp-persisted-member` - survives ALONE because the defensive guard (stamped equals persisted although the status is not accepted) still refuses; combined with removing the guard it is killed, and removing the guard alone is killed too: the guard is LOAD-BEARING (Python equality conflates `60.0 == 60` and `True == 1`).
Weakness to know: the "drop member from the preimage" mutants are killed only by the golden-digest test (the live comparison also compares the members themselves, so the redundancy hides a dropped member from the end-to-end tests). That is a property of the redundant design, not evidence that every member is independently protected by the digest alone.

## Remaining qualification obligations
* F3-A independent qualification of this head: PENDING (nothing is accepted by this document).
* Independent Tier 1 qualification: DEFERRED, NOT WAIVED. Accounting is unchanged until the enforcement implementations merge and independent evidence is recorded: 16/19 integrated, 3 remaining, 0 independently accepted.
* Merging, deployment, publication: not performed, not authorized here.

## Known limits (must be repeated by any reader of this declaration)
Unsigned local JSON store (guards DRIFT, not a malicious store writer); NO anti-rollback guarantee; the `legacy_cutoff` is host configuration without durable provenance, and a stripped member below the cutoff is indistinguishable from a legacy record; mixed-fleet legacy writers still append records without the member (new readers refuse them past the cutoff, legacy readers accept them); a legacy decision below the cutoff keeps the previous gap; a `legacy_cutoff` above the decisions in the store is refused at construction; without a profile, mint-versus-check relies on the `_EXEC_DECISION` context variable set by `execute` (a direct `_resolve` route is an unverified edge, see the document); the four governed workflows bind (composed and the three dedicated), the plain `BoundedAuthorizationWorkflow` does not; the five scalars and the ObservationPolicy must now be exact ints in 0..2147483647 at construction in EVERY governed workflow, also when F4 is not declared (a behaviour tightening, before/after in `docs/effective-configuration-binding.md` section 9a); JSON duplicate keys in the store are resolved by the store loader (last wins) before this code sees them.
