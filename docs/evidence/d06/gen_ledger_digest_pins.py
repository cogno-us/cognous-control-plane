"""Print the activation-ledger `configuration_digest` of fixed configurations. Run against the unchanged prior code (b7eb11a) to obtain the pinned values; run against the new code to compare."""
import sys, tempfile
from pathlib import Path
root = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(root / "src"), str(root)]
import pytest
import tests.test_governed_policy_composition as T
import tests.test_irreversibility_governance as I
import agent_control_plane.bounded as bm
from agent_control_plane import registry_governed_policy as pol
mp = pytest.MonkeyPatch()
mp.setattr(bm, "_now", lambda: T.NOW)
for m in (pol, I.base.gov, I.base.agegov, I.base.f4gov):
    mp.setattr(m, "_now", lambda: T.NOW)
out = {}
with tempfile.TemporaryDirectory() as td:
    td = Path(td)
    out["composed_f_a_u"] = T.ready(td / "a")[4].registry_governed_policy_identity["configuration_digest"]
    out["f4_only_noprofile"] = pol.GovernedPolicyWorkflow(families=T.families(f=T.fsrc()), verifier=T.ev.Ed25519Verifier(), construction_time=T.REG_NOW,
                                                         **T.kwargs(td / "b", T.base.tenant_resolver_for(T.base.tenant_proposal()))).registry_governed_policy_identity["configuration_digest"]
    out["irreversible_f_a_u"] = I.ready(td / "c", ir_={I.CLASS_T1: I.IRR}, f=True, a=True, u=True, host=I.rv.with_inventory)[4].registry_governed_policy_identity["configuration_digest"]
    out["irreversible_only"] = I.ready(td / "d", ir_={I.CLASS_T1: I.IRR}, host=I.rv.with_inventory)[4].registry_governed_policy_identity["configuration_digest"]
import json; print(json.dumps(out, indent=1, sort_keys=True))
