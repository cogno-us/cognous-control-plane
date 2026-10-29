"""Shared builders for the FINAL3 consumer tests (anchor deadline, observation max age, observation clock tolerance; Registry `r08-v8`).

BUILDER_TESTED developer evidence. NOT independently qualified. Not collected by pytest (no `test_` prefix). Needs the Registry checkout at the exact r08-v8 pin (PIN_V8 of
`tests/test_f5_class_unreadable_governance.py`); a different pin is a FAILURE under OCS_REQUIRE_REGISTRY_PIN=1 and is NOT RUN otherwise (module-level skip, never a pass).
Real synthetic Ed25519 for every Registry verdict.
"""
from __future__ import annotations

import dataclasses
import importlib
from pathlib import Path

import tests.test_f5_class_unreadable_governance as base  # noqa: E402  (enforces the Registry pin list and PyNaCl)

if base._head != base.PIN_V8:
    base._unavailable(f"Registry checkout is {base._head!r}; the FINAL3 consumer tests need the r08-v8 pin {base.PIN_V8}")

import r08v8_support as t8  # noqa: E402  (Registry test builders at the pin)
import tests.test_governed_policy_composition as comp  # noqa: E402
import tests.test_irreversibility_governance as irt  # noqa: E402
import tests.test_revocation_families_governance as rv  # noqa: E402
from agent_control_plane import registry_final3_governance as f3  # noqa: E402
from agent_control_plane import registry_governed_policy as pol  # noqa: E402
from agent_control_plane.bounded import LocalRefundDestination, ObservationPolicy  # noqa: E402
from agent_control_plane.freshness import FreshnessProfile  # noqa: E402
from agent_control_plane.registry_governed_policy import GovernedFamilies, GovernedFamily, GovernedPolicyWorkflow  # noqa: E402

v8id = importlib.import_module("registry_successor.v8_policy_identity")
v8dec = importlib.import_module("registry_successor.v8_decision")
ev, trust_for, bind_approval, file_state, Source, kwargs = base.ev, base.trust_for, base.bind_approval, base.file_state, base.Source, base.kwargs
CLASS_T1, CLASS_T2, TENANT, ACTION_ID, NOW, REG_NOW, PROFILE = base.CLASS_T1, base.CLASS_T2, base.TENANT, base.ACTION_ID, base.NOW, base.REG_NOW, base.PROFILE
R_, B_ = base.R_, base.B_
GovernedScope = base.GovernedScope
SRC = Path(pol.__file__).resolve().parent
MAXV = 2147483647
ANC, AGE, TOL = t8.ANCHOR, t8.MAXAGE, t8.TOL
OPS = {ANC: "refund-issue-anchor", AGE: "refund-issue-obsage", TOL: "refund-issue-obstol"}
SCOPES = {f: GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, op) for f, op in OPS.items()}
SLOTS = {ANC: "anchor_deadline", AGE: "observation_max_age", TOL: "observation_clock_tolerance"}
FIELDS = t8.FIELDS
CHANGED = {"selection_id": "sel-test-2", "epoch": 2}
RV = frozenset({("sel-test-1", 1)})


def rec(family, value=None, **over):
    return t8.record(t8.payload(family, value), family=family, **over)


def mat(family, value=None, *, record=None, **kw):
    """Signed r08-v8 selection material for `family` (default values: anchor `anchor`, max age 60, tolerance 0)."""
    record = record or rec(family, value)
    stmt_over = dict(kw.pop("stmt_over", {}))
    op = stmt_over.pop("operation", OPS[family])
    fam = stmt_over.pop("family", record["family"])
    return base._material(record, op=op, contract=kw.pop("contract", "r08-v8"), domain=kw.pop("domain", t8.V8_DOMAIN), family=fam, stmt_over=stmt_over, **kw)


def revoked(family, value=None, **kw):
    return mat(family, value, trust=trust_for(OPS[family], revoked_selections=RV), **kw)


def withdrawn(family, value=None):
    return base.withdrawn(lambda: rec(family, value), None, OPS[family], t8.V8_DOMAIN, "r08-v8", family)


def fams(*, anc=None, age=None, tol=None, base_fams=None):
    g = base_fams if base_fams is not None else GovernedFamilies()
    return dataclasses.replace(g, anchor_deadline=GovernedFamily(SCOPES[ANC], anc) if anc is not None else None,
                               observation_max_age=GovernedFamily(SCOPES[AGE], age) if age is not None else None,
                               observation_clock_tolerance=GovernedFamily(SCOPES[TOL], tol) if tol is not None else None)


def anchored(freshness=True, flag=False):
    return FreshnessProfile(anchor_deadline_to_inputs=flag) if freshness else None


def host_with_freshness(p, flag=False, **kw):
    return base.host_profile(p, t1=R_, freshness=FreshnessProfile(anchor_deadline_to_inputs=flag), **kw)


def build(tmp_path, res, cfg, families, *, obs=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw):
    k = kwargs(tmp_path, res, **kw)
    k["observation_policy"] = obs
    return GovernedPolicyWorkflow(families=families, verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW, **k)


def refused(exc, code=None, boundary=None, registry_code=None):
    return comp.refused(exc, code, boundary, registry_code)


def effects(flow):
    return flow.destination.snapshot()["effects"]


def op(max_age=300, tol=5):
    return ObservationPolicy(max_age_seconds=max_age, clock_tolerance_seconds=tol)


def make(store, res, cfg, conf):
    """The composed workflow over the persisted store `store` for a plain-data configuration `conf` (shared by the parent tests and the separate-process worker).
    conf keys (all optional): anc / age / tol (Registry values; absent or None = family not declared), host ([max_age, tolerance] or "none"), ctor_tol, identity, status."""
    families = fams(anc=Source(mat(ANC, conf["anc"])) if conf.get("anc") else None, age=Source(mat(AGE, conf["age"])) if conf.get("age") else None,
                    tol=Source(mat(TOL, conf["tol"])) if conf.get("tol") is not None else None)
    host = None if conf.get("host") == "none" else op(*conf.get("host", [300, 5]))
    extra = {}
    for key, name in (("ctor_tol", "clock_tolerance_seconds"), ("identity", "identity_max_age_seconds")):
        if key in conf:
            extra[name] = conf[key]
    return build(Path(store), res, cfg, families, obs=host, **extra)
