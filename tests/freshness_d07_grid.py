"""D-07 scenario runner shared by tests/test_freshness_purpose_anchor_successor.py and docs/evidence/d07/record_predecessor_outcomes.py.

Not a test module. It builds ONE deterministic dispatch scenario (fake service clock, no sleeping) and returns plain data, so the same
function can be run against the PREDECESSOR source (CP #94 head 061a986) to record outcomes, and against the corrected source in the tests.
Synthetic fixtures only. Developer evidence: non-authorizing, not independently qualified.
"""
import json
import re
from datetime import timedelta

import agent_control_plane.bounded as bounded
from agent_control_plane.freshness import FreshnessProfile
from agent_control_plane.runtime_authority import approval_commitment
from tests.test_bounded_authorization import NOW, PROFILE
from tests.test_freshness import Clock
from tests.test_policy_binding_approval_generation import adopt, binding
from tests.test_runtime_authority import bind_approval, setup_flow

MODES = ("anchor_nobinding", "anchor_binding", "flag_false_nobinding")
KINDS = ("live_irreversible", "live_reversible", "cached_reversible")


def stall_once(f, clock, seconds):
    """Tick the fake clock once, inside the destination observation between the effect check and the dispatch gate."""
    original, calls, pinned = f.destination.observe, [], clock.now

    def stalled(effect_id):
        calls.append(1)
        if len(calls) == 1:
            clock.tick(seconds)
        return original(effect_id).model_copy(update={"observed_at": pinned.isoformat()})
    f.destination.observe = stalled


def _fresh(mode, extension=0):
    return FreshnessProfile(max_age_extension_seconds=extension, anchor_deadline_to_inputs=(mode != "flag_false_nobinding"))


def build(tmp_path, *, kind, ceiling, age, mode, extension=0):
    """A flow whose class bound is ``ceiling`` and whose purpose observation (live or cached) is ``age`` seconds old at NOW."""
    if kind == "cached_reversible":
        from tests.test_reversibility import cls, flow as rev_flow, outage
        p, r, f, c = rev_flow(tmp_path, cls("reversible_until", max_status_age_seconds=ceiling))
        r.cached.observed_at = (NOW - timedelta(seconds=age)).isoformat()
        outage(r)                                                    # the live purpose store is down: the cached snapshot stands in
    else:
        p, r, f, c = setup_flow(tmp_path, purpose=True, reversible=(kind == "live_reversible"))
        cl = c.actions[p.action_id].model_copy(update={"max_status_age_seconds": ceiling})
        c = c.model_copy(update={"actions": {p.action_id: cl}})
        r.purpose.observed_at = (NOW - timedelta(seconds=age)).isoformat()
    fresh = _fresh(mode, extension)
    if mode == "anchor_binding":
        adopt(r, f, c, binding(age_ceilings={p.action_id: ceiling}), freshness=fresh)
        assert f.runtime_authority_profile.policy_binding is not None
    else:
        cfg = c.model_copy(update={"freshness": fresh})
        bind_approval(r, cfg)
        f.runtime_authority_profile = cfg.snapshot()
        assert f.runtime_authority_profile.policy_binding is None
    return p, r, f


def opened_deadline_offset(f):
    ev = [e for e in f.records.load().check_events if e.phase == "completed"][-1]
    if ev.deadline is None:
        return None
    from datetime import datetime
    return int((datetime.fromisoformat(ev.deadline) - NOW).total_seconds())


def run_case(tmp_path, *, kind, ceiling, age, stall, mode):
    """Decide at NOW, stall ``stall`` seconds before dispatch, execute. Plain-data outcome."""
    clock = Clock()
    previous = bounded._now
    bounded._now = clock
    try:
        p, r, f = build(tmp_path, kind=kind, ceiling=ceiling, age=age, mode=mode)
        d = f.decide(p, now=NOW)
        out = {"decision": d.result, "decision_reasons": sorted(d.reasons)}
        if d.result != "authorized":
            return out
        calls = []
        real_apply = f.destination.apply

        def counted(*a, **k):
            calls.append(1)
            return real_apply(*a, **k)
        f.destination.apply = counted
        stall_once(f, clock, stall)
        try:
            attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
            out.update(outcome="dispatched" if attempt.status == "acknowledged" else attempt.status, error=None)
        except PermissionError as exc:
            out.update(outcome="refused", error=str(exc))
        out["apply_calls"] = len(calls)
        out["deadline_offset_s"] = opened_deadline_offset(f)
        out["destination_effects"] = len(f.destination.snapshot()["effects"])
        out["refusal_reasons"] = sorted({x for ref in f.records.load().refusals for x in getattr(ref, "reasons", [])})
        return out
    finally:
        bounded._now = previous


def grid():
    """The input grid: (kind, ceiling, age, stall, mode). Stalls include the strict-boundary neighbours (remaining-1, remaining, remaining+1)
    of every case, where ``remaining = ceiling - age`` is the distance from NOW to the purpose-anchored deadline.

    Ages leave ``remaining`` either 0 or >= 10 s on purpose: the gate also applies the process-monotonic guard, whose allowance is the
    remaining anchored window (bounded.py:2137-2140) and which counts REAL elapsed time, so a window of 1-9 s would make the outcome
    depend on machine speed. ``remaining == 0`` (age exactly at the ceiling) is refused for every stall by that guard, deterministically."""
    cases = set()

    def add(kinds, ceilings, ages, modes, extra_stalls):
        for kind in kinds:
            for ceiling in ceilings:
                for age in ages(ceiling):
                    rem = ceiling - age
                    for stall in {0, rem - 1, rem, rem + 1} | {x(ceiling) for x in extra_stalls}:
                        if stall >= 0:
                            for mode in modes:
                                cases.add((kind, ceiling, age, stall, mode))
    add(KINDS, (30,), lambda c: (0, 10, 20, c), ("anchor_nobinding",), (lambda c: c - 1, lambda c: c))
    add(KINDS, (30,), lambda c: (10, c), ("anchor_binding", "flag_false_nobinding"), (lambda c: c - 1,))
    add(("live_irreversible",), (60,), lambda c: (c - 15, c), ("anchor_nobinding", "flag_false_nobinding"), (lambda c: c - 1,))
    return sorted(cases)


def case_key(c):
    return "|".join(str(x) for x in c)


def commitments(tmp_path):
    """approval_commitment, catalogue_digest and the profile dump digest for a set of profiles (the preimage surfaces D-07 must not move)."""
    from agent_control_plane.bounded import commitment
    out = {}
    p, r, f, c = setup_flow(tmp_path / "c", purpose=True)
    ctx = r.contexts[PROFILE]
    variants = {
        "default": c,
        "fresh0": c.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=0)}),
        "fresh_anchored": c.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)}),
        "fresh_anchored_ext300": c.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=300, anchor_deadline_to_inputs=True)}),
    }
    for name, cfg in variants.items():
        out[name] = {"approval_commitment": approval_commitment(cfg, ctx),
                     "catalogue_digest": commitment(cfg.model_dump(mode="json")),
                     "profile_dump": json.dumps(cfg.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))}
    bound = c.model_copy(update={"policy_binding": binding(age_ceilings={p.action_id: 60}),
                                 "freshness": FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)})
    out["with_binding"] = {"approval_commitment": approval_commitment(bound, ctx),
                           "catalogue_digest": commitment(bound.model_dump(mode="json")),
                           "profile_dump": json.dumps(bound.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))}
    return out


def normalized_document(f):
    """The persisted run document with random ids and the process id masked; everything else, including keys and instants, is kept."""
    text = f.records.path.read_text(encoding="utf-8")
    text = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>", text)
    text = re.sub(r"\b[0-9a-f]{32}\b", "<hex32>", text)
    text = re.sub(r'"pid": "[0-9]+"', '"pid": "<pid>"', text)
    return json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))


def key_paths(doc_text):
    """All JSON key paths of a document, list indices collapsed: the persisted SCHEMA shape, independent of values."""
    out = set()

    def walk(node, prefix):
        if isinstance(node, dict):
            for k, v in node.items():
                out.add(prefix + "/" + k)
                walk(v, prefix + "/" + k)
        elif isinstance(node, list):
            for v in node:
                walk(v, prefix + "[]")
    walk(json.loads(doc_text), "")
    return sorted(out)


def persisted_document(tmp_path, *, kind, ceiling, age, stall, mode):
    """Normalized persisted run document after decide, one stall and execute (refusal or dispatch)."""
    clock = Clock()
    previous = bounded._now
    bounded._now = clock
    try:
        p, r, f = build(tmp_path, kind=kind, ceiling=ceiling, age=age, mode=mode)
        d = f.decide(p, now=NOW)
        stall_once(f, clock, stall)
        try:
            f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        except PermissionError:
            pass
        return normalized_document(f)
    finally:
        bounded._now = previous


#: documents whose normalized bytes must not move (old and new agree): flag False dispatch; and a refusal by the class deadline alone.
DOC_CASES = {
    "flag_false_dispatch": dict(kind="live_irreversible", ceiling=60, age=10, stall=3, mode="flag_false_nobinding"),
    "class_deadline_refusal_nobinding": dict(kind="live_irreversible", ceiling=30, age=0, stall=31, mode="anchor_nobinding"),
}
#: the document of a refusal CAUSED BY THE CHANGE must have the same key paths as the document of an already-refusing case.
CHANGED_REFUSAL_CASE = dict(kind="live_irreversible", ceiling=30, age=30, stall=29, mode="anchor_nobinding")

CONTROLS = ("grant_status", "identity", "mandate")


def control_grid():
    """Other anchored inputs (flag True, no binding; and flag False) at the bound: (input, ceiling, age, stall, mode)."""
    out = []
    for which in CONTROLS:
        for age in (20, 30):
            rem = 30 - age
            for stall in sorted({rem, rem + 1}):
                for mode in ("anchor_nobinding", "flag_false_nobinding"):
                    out.append((which, 30, age, stall, mode))
    return out


def run_control(tmp_path, *, which, ceiling, age, stall, mode):
    """grant status / identity / mandate observation ``age`` s old with bound ``ceiling``; same plain-data outcome as ``run_case``."""
    from tests.test_freshness import stale_grant
    clock = Clock()
    previous = bounded._now
    bounded._now = clock
    try:
        p, r, f, c = setup_flow(tmp_path)
        cl = c.actions[p.action_id].model_copy(update={"max_status_age_seconds": ceiling})
        cfg = c.model_copy(update={"actions": {p.action_id: cl}, "freshness": _fresh(mode)})
        bind_approval(r, cfg)
        f.runtime_authority_profile = cfg.snapshot()
        if which == "grant_status":
            stale_grant(r, age)
        else:
            setattr(f, which + "_max_age_seconds", ceiling)
            for item in getattr(r, "identities" if which == "identity" else "mandates").values():
                item.observed_at = (NOW - timedelta(seconds=age)).isoformat()
        d = f.decide(p, now=NOW)
        out = {"decision": d.result, "decision_reasons": sorted(d.reasons)}
        if d.result != "authorized":
            return out
        calls = []
        real_apply = f.destination.apply
        f.destination.apply = lambda *a, **k: (calls.append(1), real_apply(*a, **k))[1]
        stall_once(f, clock, stall)
        try:
            attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
            out.update(outcome="dispatched" if attempt.status == "acknowledged" else attempt.status, error=None)
        except PermissionError as exc:
            out.update(outcome="refused", error=str(exc))
        out["apply_calls"] = len(calls)
        out["deadline_offset_s"] = opened_deadline_offset(f)
        return out
    finally:
        bounded._now = previous


NEGATIVES = ("irreversible_cached_outage", "post_reversal_window_cached_outage")


def run_negative(tmp_path, *, which, mode):
    """A cached purpose snapshot that must NOT be accepted (irreversible class; reversal window already passed): decision-stage outcome."""
    from tests.test_reversibility import cls, flow as rev_flow, outage
    clock = Clock()
    previous = bounded._now
    bounded._now = clock
    try:
        if which == "irreversible_cached_outage":
            p, r, f, c = rev_flow(tmp_path, cls("irreversible"))
        else:
            p, r, f, c = rev_flow(tmp_path, cls("reversible_until", reversible_until=(NOW - timedelta(minutes=1)).isoformat()))
        r.cached.observed_at = (NOW - timedelta(seconds=5)).isoformat()
        outage(r)
        cfg = c.model_copy(update={"freshness": _fresh(mode)})
        bind_approval(r, cfg)
        f.runtime_authority_profile = cfg.snapshot()
        d = f.decide(p, now=NOW)
        return {"decision": d.result, "decision_reasons": sorted(d.reasons), "attempts": len(f.records.load().attempts),
                "destination_effects": len(f.destination.snapshot()["effects"])}
    finally:
        bounded._now = previous


def string_constants(path):
    """Every string literal in a module (docstrings excluded by AST position is not needed: comments are not constants)."""
    import ast
    tree = ast.parse(open(path, encoding="utf-8").read())
    return sorted({n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)})
