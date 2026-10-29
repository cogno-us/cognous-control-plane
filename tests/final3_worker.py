"""Separate-process worker for the FINAL3 cross-process tests: it rebuilds the composed governed workflow (anchor / observation families) from scratch over a PERSISTED store and
executes one decision. BUILDER_TESTED developer evidence. Nothing is shared with the parent except the store directory, the command line and the read-only Registry pin.
    python -m tests.final3_worker <store_dir> <decision_id> '<json config>'    (config: see tests.final3_support.make, plus "flag": host anchor flag)
Prints one JSON line {"outcome": "executed"|"refused"|"construction_refused", "status": <binding classification>, "reasons": [...]}.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from tests import final3_support as F
from tests.d06_support import patch_clock


def main(store_dir: str, decision_id: str, cfgjson: str) -> dict:
    conf = json.loads(cfgjson)
    mp = pytest.MonkeyPatch()
    patch_clock(mp)
    out = {"outcome": None, "status": None, "reasons": []}
    with tempfile.TemporaryDirectory() as work:
        p, res, host = F.base.prepared(Path(work), t1=F.R_, freshness=F.FreshnessProfile(anchor_deadline_to_inputs=bool(conf.get("flag", False))))
        flow = F.make(store_dir, res, host, conf)
        F.bind_approval(res, flow.runtime_authority_profile)
        persisted = flow.records.decision(decision_id)
        out["status"] = flow.configuration_binding_status(persisted)
        try:
            attempt, observed = flow.execute(p, persisted, adapter_id=p.adapter_id, now=F.NOW)
            out["outcome"] = "executed" if attempt.status == "acknowledged" else "refused"
        except PermissionError as exc:
            out["outcome"] = "refused"
            out["error"] = str(exc)[:120]
        out["reasons"] = sorted({r for ref in flow.records.load().refusals if ref.decision_id == decision_id for r in ref.reasons})
    return out


if __name__ == "__main__":
    try:
        print(json.dumps(main(*sys.argv[1:4])))
    except Exception as exc:  # a construction refusal etc.: reported, never swallowed
        print(json.dumps({"outcome": "construction_refused", "error": type(exc).__name__ + ":" + str(exc)[:160]}))
