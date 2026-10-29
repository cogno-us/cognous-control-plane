# D-07 purpose-observation anchor correction (Option A)

Status: BUILDER_TESTED developer record. Non-authorizing. **Not independently qualified.** F3-B independent qualification: PENDING. Independent Tier 1: DEFERRED, NOT WAIVED. This record claims no security clearance, certification or production readiness; publication, release and production stay on HOLD.

Work package OCS-REG-FINAL3. Authorization: Architect directive 2026-10-29, D-07 Option A (`family-migration/final-three/02-architect-authorization-and-contract-freeze-2026-10-29.md` section 6; design and prototype in `annex/B-d07-temporal-enforcement-design-and-options.md`; qualification expectations in `03-f3-qualification-expectations-F3A-F3B-2026-10-29.md`, docs repository).

## 1. What changed

One protected file, one condition: `src/agent_control_plane/runtime_authority.py`. The block that registers the purpose observation (or the accepted cached-purpose snapshot) with the dispatch-deadline collector was guarded by `if binding is not None:` (a `PolicyBinding` on the host profile). The guard is removed; the block's own inner test `collector is not None and cl is not None` stays.

Why the inner test is sufficient (verified by reading before editing): `bounded.py:2105` creates `anchors = [] if (fr is not None and fr.anchor_deadline_to_inputs) else None`; `bounded.py:2116` sets `_FRESH_DEADLINES` only when `anchors is not None`; `_FRESH_DEADLINES.get()` is `None` otherwise (default, `bounded.py:485`). So the block runs only for workflows with `anchor_deadline_to_inputs=True`; flag False (or no freshness profile) never reaches the `append`. `cl is not None` limits it to a known action class. Both the live observation and the cached snapshot pass through this one block (the snapshot supplies `extra["age_bound_seconds"]`, produced by `bounded._cached_purpose`).

Exact location and lines (`runtime_authority.py`, function evaluating the purpose binding, inside `else:` of the `purpose_ref` shape check):

Before (CP main b7eb11a and #94 061a986, lines 404-413, file sha256 `a4b4ac36...ea66`):

```python
                if binding is not None:
                    # R6: under a policy binding the purpose observation joins the dispatch deadline (``observed_at + its bound``) like every
                    # input judged through ``_fresh``, so a status that satisfied its bound at evaluation cannot be dispatched past it. The
                    # bound is the class bound, or the recorded bound of an accepted cached snapshot (<= the ceiling by construction).
                    # Profiles without a binding keep today's behaviour (the purpose age is judged here and not anchored).
                    from .bounded import _FRESH_DEADLINES
                    collector = _FRESH_DEADLINES.get()
                    if collector is not None and cl is not None:
                        anchor_bound = int(extra["age_bound_seconds"]) if extra is not None else cl.max_status_age_seconds
                        collector.append(_parse(observed.observed_at) + timedelta(seconds=anchor_bound))
```

After (lines 404-414, file sha256 `ad7b95e5...5ace01`, git blob `f9bca403...`):

```python
                # R6 / D-07: whenever the deadline collector exists (``anchor_deadline_to_inputs``: ``_FRESH_DEADLINES`` is set only then) the
                # purpose observation joins the dispatch deadline (``observed_at + its bound``) like every input judged through ``_fresh``, so a
                # status that satisfied its bound at evaluation cannot be dispatched past it. The bound is the class bound, or the recorded bound
                # of an accepted cached snapshot (<= the ceiling by construction). This no longer depends on a policy binding being present
                # (D-07 Option A, Architect-authorized 2026-10-29: the former binding-only guard left a 2x residual window); it only ever adds
                # a ``min`` to the deadline, so it cannot widen any bound.
                from .bounded import _FRESH_DEADLINES
                collector = _FRESH_DEADLINES.get()
                if collector is not None and cl is not None:
                    anchor_bound = int(extra["age_bound_seconds"]) if extra is not None else cl.max_status_age_seconds
                    collector.append(_parse(observed.observed_at) + timedelta(seconds=anchor_bound))
```

The code lines are dedented one level and the comment is rewritten; nothing else in the file changed (`docs/evidence/d07/source-diff.patch`; the set of string literals in the module is unchanged, pinned by a test). `bounded.py`, `freshness.py`, `policy_binding.py`, `rule_revision.py`, `reversibility.py`, `holder_inventory.py` and every schema are byte-identical to the predecessor.

## 2. Why

With `anchor_deadline_to_inputs=True` and no `PolicyBinding`, a purpose observation (or accepted cached snapshot) at the Registry-narrowed class bound (30 s) was accepted at evaluation and could still be dispatched after a further stall up to the class deadline (`NOW + 30`): purpose age 59 s (stall 29) or 60 s (stall 30), about 2x the ceiling. The other anchored inputs (grant status, identity, mandate) were already refused for the same stall. The characterization is `tests/test_freshness_purpose_residual.py` at CP #94 head `061a986` and its original results are retained verbatim in `docs/evidence/d07/baseline-01-purpose-residual-characterization-061a986.txt` (10 passed on the unchanged tree).

Effect of the correction: the deadline becomes `min(opened_deadline, observed_at + bound)` also without a binding. The refusal is the existing `check_expired_before_dispatch` (`EffectTimeRefusal`, attempt `failed`); the destination `apply` is never called.

## 3. Properties

* Strictly more restrictive: a pure `min` is added to the deadline. A grid of 124 cases (below) shows `new_deadline <= old_deadline` everywhere and no case dispatched by the new code that the predecessor refused.
* Flag False and no freshness profile: no collector, no new anchoring; outcomes and the normalized persisted run document are byte-identical to the recorded predecessor.
* PolicyBinding path: byte-identical outcomes to the predecessor (the same `append` ran before).
* Unchanged: `approval_commitment`, `catalogue_digest`, the profile dump (five profile variants), the persisted decision/attempt/refusal schema key paths, the reason vocabulary (no new string literal in the module; the only refusal code observed is `check_expired_before_dispatch`).
* Boundary semantics preserved: the clock check is strict (`now > deadline`). **Observation, not previously stated:** the process-monotonic guard also applies, with an allowance equal to the remaining anchored window (`bounded.py:2137-2140`) and real elapsed time. A purpose observation whose age equals the ceiling therefore has a remaining window of 0 s and is now refused at every stall, including 0 (it was dispatched before the change; the same already held for grant status/identity/mandate at the bound and for the PolicyBinding path). Windows of 1-9 s depend on machine speed through that guard, so the tests use remaining windows of 0 or >= 10 s.

## 4. Tests

Predecessor tests superseded (originals stay in git history at 061a986):

| Predecessor | Result on the corrected source | Successor |
|---|---|---|
| `test_freshness_purpose_residual.py::test_residual_purpose_observation_age_at_dispatch_is_twice_...` | FAILED (expected) | `test_successor_purpose_observation_at_the_ceiling_is_refused_after_a_29_second_stall_when_anchored_without_a_binding` |
| `...::test_residual_purpose_observation_is_dispatched_up_to_the_end_of_the_unanchored_window` | FAILED (expected) | `test_successor_purpose_observation_is_refused_at_the_former_end_of_the_unanchored_window` |
| `...::test_residual_cached_purpose_snapshot_age_at_dispatch_is_twice_...` | FAILED (expected) | `test_successor_cached_purpose_snapshot_at_the_ceiling_is_refused_after_a_29_second_stall_when_anchored_without_a_binding` |
| `...::test_residual_window_is_closed_only_by_the_class_deadline_not_by_the_purpose_age` | still PASSED, but its claim became false | `test_successor_a_stall_past_the_ceiling_is_refused_and_the_purpose_anchor_is_what_tightens_the_deadline` |
| `test_policy_binding_approval_generation.py::test_legacy_profile_without_a_policy_binding_keeps_its_behaviour_for_the_purpose_status` | FAILED (expected) | `test_legacy_profile_without_a_policy_binding_now_anchors_the_purpose_status_d07_successor` (docstring explains what changed and cites the authorization) |

The file `test_freshness_purpose_residual.py` carries a module SUPERSESSION RECORD (PR #94 head 061a986, original results file, authorization). Contrast (PolicyBinding) and control tests are unchanged. The raw failing output of the unmodified tests on the corrected source: `docs/evidence/d07/postchange-01-predecessor-tests-on-corrected-source-UNMODIFIED-TESTS.txt`.

Byte pins updated (only the `runtime_authority.py` entry, each with a comment citing the authorization): `test_governed_policy_composition.py::test_z03` (`ad7b95e5...`), and, found by the first full run, three more sites that pin the same file: `test_f5_class_age_governance.py::test_s01`, `test_f5_class_unreadable_governance.py::test_s01`, and `test_v02_legacy_claim_vector.py::test_l05` (git blob `0b2c5e49...` -> `f9bca403...`). `tests/test_freshness_purpose_anchor_successor.py::test_d07_only_runtime_authority_changed_among_the_protected_evaluators` proves the other six protected files (`bounded`, `freshness`, `policy_binding`, `rule_revision`, `reversibility`, `holder_inventory`) are unchanged by hash; `...::test_d07_the_deadline_registration_is_no_longer_guarded_by_the_policy_binding` is a static AST pin.

New file `tests/test_freshness_purpose_anchor_successor.py` (184 tests; helper `tests/freshness_d07_grid.py`; predecessor outcomes in `tests/fixtures/d07_predecessor_outcomes_061a986.json`, recorded by `docs/evidence/d07/record_predecessor_outcomes.py` against the UNCHANGED predecessor source, which the recorder verifies by hash):

* 124-case grid (live irreversible, live reversible, cached reversible; ceilings 30 and 60; ages 0/10/20/ceiling; stalls at remaining-1, remaining, remaining+1, ceiling-1, ceiling; modes anchor without binding, anchor with binding, flag False): new vs recorded old: same decision, `new_deadline <= old_deadline`, `new dispatched => old dispatched`, `new_deadline == min(old_deadline, ceiling - age)`, outcome equals an independently derived strict-boundary oracle (validated first against the OLD recordings), binding and flag-False paths equal the old outcome exactly, `apply` called 0 times after a refusal and once after a dispatch, refusal reason set `== [check_expired_before_dispatch]`.
* Named scenarios: age exactly at the ceiling (live and cached); 29 s and 30 s stalls in the former window refused; one second inside / exactly on / one second outside the anchored deadline (9/10/11 s of a 10 s window); deadline exceeded leaves a durable `EffectTimeRefusal`, a `failed` attempt, no destination effect and a refused retry.
* Controls: grant status, identity, mandate with flag and without (byte-equal to recorded predecessor outcomes); irreversible-class and post-reversal-window cached snapshots still held.
* Outage extension (`max_age_extension_seconds`): a recorded extension to 90 s lets a cached snapshot of age 80 s be accepted, and the anchor follows the recorded bound (deadline `NOW + 10`: stall 10 dispatches, 11 refuses; before the change the same snapshot could be dispatched up to about `NOW + 90`); the extension does not raise the live-purpose acceptance bound or its anchor; an extension beyond the host limit is refused.
* Commitments and persisted shape: `approval_commitment`, `catalogue_digest`, profile dump equal the recorded predecessor for five profile variants; normalized persisted documents of a flag-False dispatch and of a class-deadline refusal are byte-identical (process id and random ids masked); a refusal caused by the change has exactly the key paths of an existing refusal; string literals of `runtime_authority.py` equal the recorded predecessor set.

Wall-clock and monotonic guards are covered by the existing suites (`tests/test_freshness.py`); the interaction with profile-bearing families and `policy_binding_unsupported` is covered by the unchanged `tests/test_governed_policy_composition.py` (`test_c06` etc.).

## 5. Results (original vs new)

Baseline = unchanged tree at 061a986. Runner: `docs/evidence/d07/run_suite.sh` (each suite file hard-codes its exact Registry pin, so the suite runs in two groups: `pin_v7` b73c59e... for everything except `test_f4_age_governance.py` and `test_f5_class_age_governance.py`, which need `regpin` 6f600ab...).

| Run | Baseline (061a986) | After (this change) |
|---|---|---|
| `test_freshness_purpose_residual.py` | 10 passed (`baseline-01-...txt`) | successor form: 10 passed (3 inverted, 1 renamed) |
| `test_policy_binding_approval_generation.py` | 102 passed (`baseline-02-...txt`) | passes with the one successor test |
| Group A (full suite minus two files) | 41 failed, 1911 passed, 90 skipped (`baseline-03b-...txt`) | 41 failed, 2095 passed, 90 skipped (`final-02-...txt`) |
| Group B (f4/f5 age governance) | 184 passed | 184 passed |

Unmodified predecessor tests on the corrected source: 5 failed (3 residual + the legacy pinned test + `test_z03[runtime_authority.py]`), 206 passed (`postchange-01-...txt`). A first full run on the corrected source additionally failed 3 more byte-pin tests of the same file (`final-01-first-final-run-found-3-additional-byte-pin-tests.txt`); they were updated as listed in section 4.

Baseline failures (41, identical set before and after; `baseline-04-preexisting-failures-list.txt`): environmental. `tests/test_microsoft_agt.py`, `test_scan6_agt_exact.py`, `test_wave7_agt_binding_equality.py` fail because `pytest-asyncio` is not installed in the verification venv (async tests); the 6 `test_v02_claim_policy_binding.py::test_a0x` fail because the checkout at hand is not the pinned Registry commit `943ab18...` for that suite (not available here). New failures versus baseline: none. A first run with a single pin directory gave 2 collection errors (f4/f5 expect a different pin): `baseline-03a-...txt`, kept as a run-configuration record, not as a baseline.

Mutation evidence (developer evidence, not qualification): `docs/evidence/d07/mutation_harness.py` applies one mutant at a time to a scratch COPY of `src/`, `schemas/`, `tests/` and runs the D-07 tests (successor, residual, policy-binding generation, freshness) with the static pins deselected. 16 mutants, 16 killed, 0 survived (`mutation-results.json`, `mutation-run.log`): restore the binding guard; anchor only live; anchor only cached; drop the cached recorded bound; +1 s; no bound; doubled bound; extension-sized live bound; `max` instead of `min` over anchors; inverted flag test; flag ignored; inclusive boundary; later deadline wins; anchored deadline never replaces the opening deadline; monotonic allowance not tightened; extension-sized cached bound. Limits: first-failure (`-x`) run, so the reported test is the first of possibly many; several kills are by grid cases in binding mode that compare to the recorded predecessor; mutants are hand-chosen, not exhaustive; killing a mutant shows the tests are sensitive, not that the code is correct.

## 6. Residual limits (unchanged by this change)

* Outage-extension authority for the cached-purpose path is asserted and unauthenticated (comment at `runtime_authority.py:~416`: a configured signer's extension, not authenticated). The correction anchors the snapshot at its recorded (possibly extended) bound, which is <= the Registry-narrowed ceiling by composition; it does not authenticate who asked for the extension.
* No anti-rollback: the decision store is an unsigned local JSON store; nothing here adds a durable ratchet (EXT-S4 not implemented).
* Not covered by this change: the pre-existing extreme-tolerance `OverflowError` (separate defect record 04), the constructor clock tolerance (NOT AUTHORIZED), Registry-side consumers of the anchor family (separate PR 6), `policy_generation`/`activation_ref` semantics (Option B was not taken).
* Behaviour change for existing hosts: hosts that set `anchor_deadline_to_inputs=True` without a `PolicyBinding` and whose grants carry a `purpose_ref` can now see earlier refusals (`check_expired_before_dispatch`), including for a purpose observation exactly at its ceiling. This is the intended, more restrictive behaviour; hosts without the flag are unaffected.
* The change withdraws the documented "legacy keeps its behaviour" comment for flagged profiles only.

## 7. Draft CI Scope Declaration (risk tier T3)

* Subject / exact head: Control Plane branch `d07-purpose-anchor-correction`, stacked on CP #94 `061a986563768f2f8f9f6c0861647a3c5b1935be` (CP main `b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa` plus one test-only commit). Code and test head: commit `2a96cfb` (source + tests); the commit above it adds evidence and this document only (no source or test change). Protected-file change set: `runtime_authority.py` only, sha256 `ad7b95e5d3bc3ddcba110a6758cf63e7f22b537766d3d072cbc7af17385bce01`.
* Dependencies: CP #94 (unchanged); Registry pin directories as listed in section 5. No dependency on the D-06 PR.
* Tests executed: full Control Plane suite in two pin groups (section 5), the D-07 successor and residual suites, 16-mutant harness, byte-pin proofs for six unchanged protected files. Registry checkouts: `b73c59e6769acd5af7263397e81dfc6fa4561f38` and `6f600ab1150f00ef3d96834159b1807e866a78b6`.
* Evidence reused: none, except the recorded predecessor outcomes, which were generated for this change by running the unchanged predecessor source (hash-verified by the recorder) and are exact-source evidence for 061a986 only.
* Not run, and why: `tests/test_v02_claim_policy_binding.py` against its own Registry pin `943ab18...` (checkout not available here: 6 baseline environmental failures, unchanged); async-marked AGT suites (`pytest-asyncio` not installed: baseline failures, unchanged); CI workflows and the qualification-repository reusable workflows (not available locally, pinned SHAs untouched); cross-component suites per `CROSS_COMPONENT_TESTS.md`; no real payments, networks, subprocesses or credentials were used anywhere.
* Original failures vs new: original (predecessor) results retained verbatim; 41 baseline failures are environmental and identical before and after; 5 predecessor tests inverted by the authorized change plus 3 byte-pin tests, all superseded or updated as documented; no other new failure.
* Remaining qualification obligations: F3-B independent qualification PENDING (specified in `03-f3-qualification-expectations-F3A-F3B-2026-10-29.md` before this change was made); independent Tier 1 DEFERRED, NOT WAIVED; F3 requalification, refreeze and re-review required by `CLAUDE.md` before acceptance; Architect and human review of the consolidated change. Accounting unchanged until the enforcement implementations merge: 0 independently accepted. Nothing was pushed, opened as a PR, or merged.
