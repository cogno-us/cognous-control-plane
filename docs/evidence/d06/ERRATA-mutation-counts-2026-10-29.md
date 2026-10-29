# Errata: D-06 mutation-count figures (new text, 2026-10-29)

`ci-scope-declaration-draft.md` (historical builder draft, not edited) reports at line 23 "65 killed, 2 survived" and cites `mutation-final3/summary.json`. The summary file itself records 67 mutants, 64 killed, 3 survived (`compare-only-digest`, `stamp-persisted-member`, `cutoff-count-load-failure-ignored`), 0 invalid, control PASS. The third survivor was re-run after `test_d20` was added and was killed (`mutation-final3-extra/summary.json`, 1 of 1), so 65 killed / 2 survived is the **combined** figure; it was attributed to the wrong single file.

Line 25 ("49 mutants, 47 killed, 2 survived", head `7bfe842`) is combined in the same way: `mutation/summary.json` records 49 total, 45 killed, 2 survived, 2 invalid; the 2 invalid were re-run and killed in `mutation-extra/summary.json`.

The `summary.json` files are the primary record. `docs/final3-consumers.md` line 39 (64 mutants) refers to a different harness and is not affected. These are developer figures, not independent qualification; the independent mutation-adequacy results are in the qualification evidence (`ed31764`).
