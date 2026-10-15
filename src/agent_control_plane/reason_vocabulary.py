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
                   minimum_current_exposure: int = 1) -> dict:
    """Count versioned reasons with declared exposure; never infer tampering."""
    if min(previous_exposure, current_exposure, minimum_prior_count, minimum_current_exposure) < 0:
        raise ValueError("counts and exposure must be nonnegative")
    def counts(rows):
        return Counter((r.get("reason_vocabulary_version") or "unknown", code)
                       for r in rows for code in set(r.get("reasons", [])))
    before, after = counts(previous), counts(current)
    eligible = previous_exposure > 0 and current_exposure >= minimum_current_exposure
    return {"total_refusals": len(current), "previous_total_refusals":len(previous),
        "current_exposure":current_exposure,"previous_exposure":previous_exposure,
        "unversioned_rows":sum(not r.get("reason_vocabulary_version") for r in current),
        "series":[{"version":v,"code":c,"count":after[(v,c)],
            "share":after[(v,c)]/len(current) if current else None,
            "previous_count":before[(v,c)],
            "disappeared":bool(eligible and before[(v,c)]>=minimum_prior_count and after[(v,c)]==0)}
            for v,c in sorted(before.keys()|after.keys())],
        "interpretation":"investigation signal only; traffic, loss and vocabulary changes require review"}
