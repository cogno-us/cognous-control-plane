# Contract conformance: execution-attempt lifecycle (producer)

- Contract: `execution-attempt-lifecycle`, version `0.1.0-draft` (not frozen; any ODES change may break).
- Source: `cogno-us/open-decision-evidence-standard` at commit `e5fe3822a2d3c3f6885fd61acccb4bb6281041be`.
- Refreshed 2026-10-19: the vendored copy moved from ODES a9db024c to e5fe3822 with ODES `contracts/tools/vendor_contract.py` (still `0.1.0-draft`; README, schema and `validate.py` digests changed; 24 fixtures added). The suite is unchanged apart from the commit literal; all 21 tests pass.
- Refreshed 2026-10-17 (P4): the vendored copy moved from ODES d1e17fa1 to a9db024c (still `0.1.0-draft`, schema digest changed). The suite is unchanged apart from the commit literal; all 21 tests pass against the new fixtures and rules.
- Role: producer. This repo is the Control Plane bounded workflow (`src/agent_control_plane/bounded.py`).
- Vendored copy: `tests/contracts/execution-attempt-lifecycle/` (README, schema, `validate.py`, fixtures, `CONTRACT.json` digests).
- Suite: `tests/test_contract_lifecycle_conformance.py`. Test-only; no product code changed.

## Level claimed

Level P (structure, rules and a real producer run), for the Control Plane side only, for the cases in the table marked conformant. Each of those cases is a real run of `bounded.py` on synthetic proposals, mapped into a contract document (`attempts` to `control_plane_attempts`, `check_events` to `resolution_journal`, `resolution_checks` to `resolution_checks`) and accepted by the vendored `validate.py` with no violations. Nothing here claims conformance for the runtime executor side, for the importer, or for cases not listed. The draft contract is not frozen, so the claim holds only for this version and commit.

## Cases

| Case | Status |
|---|---|
| Normal lifecycle, attempted then acknowledged | conformant |
| Attempted then failed (definitive destination rejection) | conformant |
| Attempted then partial | conformant |
| Uncertain attempt (lost acknowledgement): attempted then unknown | conformant |
| `reconciled_existing` single acknowledged row (after the uncertain attempt) | conformant |
| `reconciled_existing` single partial row (after a partial attempt) | conformant |
| Sequential resolution checks (decision then effect) with journal | conformant |
| Overlapping checks, A completes first, listed A,B / B,A | conformant (2 runs) |
| Overlapping checks, B completes first, listed B,A / A,B | conformant (2 runs) |
| Effect-time refusal | conformant; produces no lifecycle rows, only journal and checks |
| Closeout of an uncertain attempt (`closeouts`) | not exercised as contract content: the contract has no member for it (README, known gaps). The test only asserts the closeout leaves the attempt rows unchanged and still conformant. |
| Known non-conformance | none found (no F-P2-CP-n findings) |

Overlap runs use two real `decide` calls on threads sharing one record, gated so both journal checks open before either completes, and so the completion and listing orders are exactly those named. The tests assert the overlap actually occurred.

Negative controls (the vendored validator must refuse a planted defect in a real document): dropped start record (`missing_start_record`), `reconciled_existing: false` on a start row (`invalid_reconciled_marker`), sequential reorder (`resolution_checks_out_of_order`). The drift check also has its own negative tests (modified, missing, unlisted file).

## Drift check

`test_vendored_copy_has_no_drift` recomputes SHA-256 for every file listed in `CONTRACT.json` and fails on a modified, missing or unlisted file. It does not need the ODES repository.

## Refreshing the vendored copy

From a checkout of the ODES repository at the commit you are adopting:

```
python contracts/tools/vendor_contract.py copy --contract execution-attempt-lifecycle \
  --dest <control_plane>/tests/contracts/execution-attempt-lifecycle \
  --role producer --level P --odes-commit <commit>
```

Then update the commit asserted in `test_vendored_contract_identity`, run `pytest`, and update this page (version, commit, case table).
