"""Separate-process worker for the D-06 cross-process tests: it rebuilds a governed workflow from scratch over a PERSISTED store and executes / pin-exports one decision.

BUILDER_TESTED developer evidence. Nothing is shared with the parent process except the store directory, the command line and the (read-only) Registry pin.
    python -m tests.d06_worker execute|pin <store_dir> <decision_id> '<json config>'
config keys (all optional): f4 (bool), obs ("none" | [max_age, tolerance]), status, approval, tolerance, identity, mandate, cutoff.
Prints one JSON line: {"outcome": "executed"|"refused", "status": <binding classification>, "reasons": [...], "state": <pin state>}.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

from agent_control_plane.authorization_pin_export import assess_authorization_pin
from agent_control_plane.bounded import ObservationPolicy
from tests import d06_support as S


def main(mode: str, store_dir: str, decision_id: str, cfgjson: str) -> dict:
    cfg = json.loads(cfgjson)
    mp = pytest.MonkeyPatch()
    S.patch_clock(mp)
    top = {}
    for key, name in (("status", "status_max_age_seconds"), ("approval", "approval_max_age_seconds"), ("tolerance", "clock_tolerance_seconds"),
                      ("identity", "identity_max_age_seconds"), ("mandate", "mandate_max_age_seconds"), ("cutoff", "legacy_cutoff")):
        if key in cfg:
            top[name] = cfg[key]
    if "obs" in cfg:
        top["obs"] = None if cfg["obs"] == "none" else ObservationPolicy(max_age_seconds=cfg["obs"][0], clock_tolerance_seconds=cfg["obs"][1])
    out = {"outcome": None, "status": None, "reasons": [], "state": None}
    with tempfile.TemporaryDirectory() as work:
        if mode == "pin":
            p, res, profile, binding = S.pin_prepared(work)
            flow = S.pin_governed(store_dir, res, profile, **top)
        else:
            p, res, host = S.T.prepared(Path(work))
            srcs = S.sources(f=bool(cfg.get("f4", False)))
            flow = S.mk(Path(store_dir), res, host, S.T.families(srcs["f"], srcs["a"], srcs["u"]), **top)
            S.bind_approval(res, flow.runtime_authority_profile)
        persisted = flow.records.decision(decision_id)
        out["status"] = flow.configuration_binding_status(persisted)
        try:
            if mode == "pin":
                result = assess_authorization_pin(flow, p, persisted, now=S.NOW, host_policy_binding=binding)
                out["state"], out["outcome"] = result["state"], ("executed" if result["state"] == "active" else "refused")
            else:
                attempt, observed = flow.execute(p, persisted, adapter_id=p.adapter_id, now=S.NOW)
                out["outcome"] = "executed" if attempt.status == "acknowledged" else "refused"
        except PermissionError as exc:
            out["outcome"] = "refused"
            out["error"] = str(exc)[:120]
        out["reasons"] = sorted({r for ref in flow.records.load().refusals if ref.decision_id == decision_id for r in ref.reasons})
    return out


if __name__ == "__main__":
    try:
        print(json.dumps(main(*sys.argv[1:5])))
    except Exception as exc:  # a construction refusal etc.: reported, never swallowed
        print(json.dumps({"outcome": "construction_refused", "error": type(exc).__name__ + ":" + str(exc)[:160]}))
