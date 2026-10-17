"""Attributable vocabulary changes and exposure-aware refusal reporting."""
from __future__ import annotations
from collections import Counter
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

class VocabularyChange(BaseModel):
    """An adopted registry transition, not a rewrite of historical rows."""
    model_config = ConfigDict(extra="forbid")
    change_id: str
    previous_version: str
    version: str
    registry_digest: str
    kind: Literal["addition", "retirement", "rename", "split"]
    previous_codes: list[str]
    codes: list[str]
    acknowledged_by: str = Field(min_length=1)
    acknowledged_at: str


def refusal_trends(previous: list[dict], current: list[dict], *, previous_exposure: int,
                   current_exposure: int, minimum_prior_count: int = 5,
                   minimum_current_exposure: int = 1, vocabulary_changes: list | None = None,
                   rule_revisions: list | None = None) -> dict:
    """Count versioned reasons with declared exposure; never infer tampering."""
    if min(previous_exposure, current_exposure, minimum_prior_count, minimum_current_exposure) < 0:
        raise ValueError("counts and exposure must be nonnegative")
    def counts(rows):
        return Counter((r.get("reason_vocabulary_version") or "unknown", code)
                       for r in rows for code in set(r.get("reasons", [])))
    before, after = counts(previous), counts(current)
    eligible = previous_exposure > 0 and current_exposure >= minimum_current_exposure
    report = _trend_report(previous, current, before, after, eligible, previous_exposure, current_exposure, minimum_prior_count)
    if vocabulary_changes is not None or rule_revisions is not None:
        _annotate_adoption(report, previous, current, vocabulary_changes or [], rule_revisions or [])
    return report


def _trend_report(previous, current, before, after, eligible, previous_exposure, current_exposure, minimum_prior_count) -> dict:
    return {"total_refusals": len(current), "previous_total_refusals":len(previous),
        "current_exposure":current_exposure,"previous_exposure":previous_exposure,
        "unversioned_rows":sum(not r.get("reason_vocabulary_version") for r in current),
        "series":[{"version":v,"code":c,"count":after[(v,c)],
            "share":after[(v,c)]/len(current) if current else None,
            "previous_count":before[(v,c)],
            "disappeared":bool(eligible and before[(v,c)]>=minimum_prior_count and after[(v,c)]==0)}
            for v,c in sorted(before.keys()|after.keys())],
        "interpretation":"investigation signal only; traffic, loss and vocabulary changes require review"}


# ---- opt-in rule-revision/0.1 trend, arity and recomputability helpers --------------------------------------------------------
def _d(x) -> dict:
    return x.model_dump(mode="json") if isinstance(x, BaseModel) else dict(x)


def _row_time(row: dict) -> str | None:
    return row.get("decided_at") or row.get("recorded_at") or row.get("observed_at")


def adoption_times(vocabulary_changes: list, rule_revisions: list) -> dict[str, str]:
    """Earliest adoption timestamp per version label: a VocabularyChange's `version`, or a counting-or-not revision row's `rule_ref`
    of kind reason_registry (the label of the registry it adopts)."""
    from datetime import datetime
    out: dict[str, str] = {}
    def put(label, ts):
        if label and ts and (label not in out or datetime.fromisoformat(ts) < datetime.fromisoformat(out[label])):
            out[label] = ts
    for c in map(_d, vocabulary_changes):
        put(c["version"], c["acknowledged_at"])
    for r in map(_d, rule_revisions):
        if r["rule_kind"] == "reason_registry":
            put(r["rule_ref"], r["recorded_at"])
    return out


def _annotate_adoption(report: dict, previous: list, current: list, changes: list, revisions: list) -> None:
    """Flag rows whose version predates that version's adoption row; mark pre-split counts `tainted_for_trend`.

    A version with no adoption row (for example the pinned default registry) is not flagged: there is no row to predate."""
    from datetime import datetime
    adopted = adoption_times(changes, revisions)
    flagged, flagged_codes = [], set()
    for which, rows in (("previous", previous), ("current", current)):
        for i, row in enumerate(map(_d, rows)):
            v, ts = row.get("reason_vocabulary_version"), _row_time(row)
            if v in adopted and ts and datetime.fromisoformat(ts) < datetime.fromisoformat(adopted[v]):
                flagged.append({"set": which, "index": i, "version": v, "row_time": ts, "adoption_time": adopted[v]})
                flagged_codes.update((v, code) for code in row.get("reasons", []))
    split_old = {(c["previous_version"], code) for c in map(_d, changes) if c["kind"] == "split" for code in c["previous_codes"]}
    flagged_keys = {(f["set"], f["index"]) for f in flagged}
    for item in report["series"]:
        key = (item["version"], item["code"])
        reasons = []
        if key in split_old:
            reasons.append("pre_split_count")
        if key in flagged_codes:
            reasons.append("row_predates_adoption")
        item["tainted_for_trend"] = bool(reasons)
        item["taint_reasons"] = reasons
    report["rows_predating_adoption"] = flagged
    report["flagged_row_count"] = len(flagged_keys)


def operand_shape(row) -> tuple[str, ...]:
    """The operand shape of a row: an explicit `operand_shape`, else the input types whose recorded expectation was not met
    (or that were missing), else all input types read. Deterministic and derived only from retained row content."""
    r = _d(row)
    if r.get("operand_shape"):
        return tuple(sorted(r["operand_shape"]))
    inputs = [_d(x) for x in r.get("resolution_inputs", [])]
    off = {x["input_type"] for x in inputs
           if x.get("missing") or any(x.get("observed", {}).get(k) != v for k, v in (x.get("expected") or {}).items())}
    return tuple(sorted(off or {x["input_type"] for x in inputs}))


def measured_arity(rows: list, *, as_of: str, period_seconds: int) -> dict:
    """Diversity of operand shapes per code over the period ending at `as_of` (inclusive, exclusive at the start).
    The result is an observation "as of T", not a property of the code."""
    from datetime import datetime, timedelta
    end = datetime.fromisoformat(as_of)
    start = end - timedelta(seconds=period_seconds)
    shapes: dict[str, set] = {}
    for row in map(_d, rows):
        ts = _row_time(row)
        if not ts or not (start < datetime.fromisoformat(ts) <= end):
            continue
        for code in set(row.get("reasons", [])):
            shapes.setdefault(code, set()).add(operand_shape(row))
    return {"as_of": as_of, "period_seconds": period_seconds,
            "codes": {c: {"measured": len(v), "shapes": sorted(list(x) for x in v)} for c, v in sorted(shapes.items())}}


def arity_flags(declared: dict[str, int], measured: dict) -> list[dict]:
    """Declared (at signing) AND measured (at mint time) are both kept; a code measured above its declaration is flagged.
    A code with no declaration is flagged `arity_undeclared`."""
    out = []
    for code, m in measured["codes"].items():
        if code not in declared:
            out.append({"code": code, "flag": "arity_undeclared", "measured": m["measured"], "as_of": measured["as_of"]})
        elif m["measured"] > declared[code]:
            out.append({"code": code, "flag": "measured_exceeds_declared", "declared": declared[code],
                        "measured": m["measured"], "as_of": measured["as_of"]})
    return out


def derive_recomputability(row) -> str:
    """`recomputable` only if the row retains its operands: at least one resolution input, each either explicitly missing or
    carrying a record commitment and observed values. Otherwise `typed_only`."""
    inputs = [_d(x) for x in _d(row).get("resolution_inputs", [])]
    if inputs and all(x.get("missing") or (x.get("record_commitment") and x.get("observed")) for x in inputs):
        return "recomputable"
    return "typed_only"


def recomputability_flags(rows: list, registry_codes: dict) -> list[dict]:
    """Per row and code: `reason_kind` stays the declared expectation; flag where it disagrees with the derived value.
    `declared_overclaim` (declared recomputable, operands absent) is the integrity-relevant direction; `declared_underclaim`
    is informational."""
    out = []
    for i, row in enumerate(map(_d, rows)):
        derived = derive_recomputability(row)
        for code in sorted(set(row.get("reasons", []))):
            declared = (registry_codes.get(code) or {}).get("reason_kind")
            if declared and declared != derived:
                out.append({"row": i, "code": code, "declared": declared, "derived": derived,
                            "flag": "declared_overclaim" if declared == "recomputable" else "declared_underclaim"})
    return out
