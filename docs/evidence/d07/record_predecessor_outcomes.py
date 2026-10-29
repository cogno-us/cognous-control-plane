"""Record the PREDECESSOR outcomes (Control Plane #94 head 061a986, runtime_authority.py sha256 a4b4ac36...) for the D-07 grid.

Usage (the predecessor source must come first on the path; the tests package comes from this worktree):
  git archive 061a986 src schemas | tar -x -C <dir>
  PYTHONPATH=<dir>/src:<worktree> python docs/evidence/d07/record_predecessor_outcomes.py <out.json> <tmp-dir>
It refuses to run unless the imported runtime_authority.py is byte-identical to the predecessor. Developer evidence only.
"""
import hashlib
import json
import pathlib
import sys

import agent_control_plane.runtime_authority as ra
from tests.freshness_d07_grid import (CHANGED_REFUSAL_CASE, DOC_CASES, NEGATIVES, case_key, commitments, control_grid, grid, key_paths,
                                      persisted_document, run_case, run_control, run_negative, string_constants)

PREDECESSOR_SHA = "a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66"
out, tmp = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
sha = hashlib.sha256(pathlib.Path(ra.__file__).read_bytes()).hexdigest()
assert sha == PREDECESSOR_SHA, f"not the predecessor source: {ra.__file__} {sha}"
cases = {}
for i, c in enumerate(grid()):
    kind, ceiling, age, stall, mode = c
    cases[case_key(c)] = run_case(tmp / f"g{i}", kind=kind, ceiling=ceiling, age=age, stall=stall, mode=mode)
controls = {case_key(c): run_control(tmp / f"k{i}", which=c[0], ceiling=c[1], age=c[2], stall=c[3], mode=c[4]) for i, c in enumerate(control_grid())}
negatives = {f"{w}|{m}": run_negative(tmp / f"n{i}{m[:2]}", which=w, mode=m) for i, w in enumerate(NEGATIVES) for m in ("anchor_nobinding", "flag_false_nobinding")}
docs = {name: hashlib.sha256(persisted_document(tmp / f"d_{name}", **kw).encode()).hexdigest() for name, kw in DOC_CASES.items()}
refusal_doc = persisted_document(tmp / "d_ref", **{**DOC_CASES["class_deadline_refusal_nobinding"]})
consts = string_constants(ra.__file__)
doc = {
    "provenance": {"predecessor_head": "061a986563768f2f8f9f6c0861647a3c5b1935be",
                   "runtime_authority_sha256": sha,
                   "generator": "docs/evidence/d07/record_predecessor_outcomes.py",
                   "note": "outcomes of the UNCHANGED predecessor source for the D-07 grid; developer evidence, not independent qualification"},
    "cases": cases,
    "commitments": commitments(tmp / "commit"),
    "controls": controls,
    "negatives": negatives,
    "normalized_document_sha256": docs,
    "old_refusal_document_key_paths": key_paths(refusal_doc),
    "runtime_authority_string_constants": consts,
}
out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8")
print("recorded", len(cases), "cases;", len(consts), "string constants; source", ra.__file__)
