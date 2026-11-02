"""Deterministic F4 flow used by the RW-01-F4-PoC carriage tests (and, unchanged, to generate the legacy golden at CP b19c47dd where `carry_selection_evidence` does not exist).

Only imports names that exist at the base commit; the golden file `tests/fixtures/rw01_f4_poc_legacy_run_b19c47dd.json` was produced by running `legacy_run_document` against the
untouched b19c47dd tree. Synthetic Ed25519 keys; mechanism-test only.
"""
from __future__ import annotations

import itertools
import json
import uuid
from pathlib import Path


def deterministic_uuid4(monkeypatch):
    counter = itertools.count(1)
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID(int=next(counter)))


def legacy_run_document(tmp_path: Path, monkeypatch, *, build, mat, Source, tenant_proposal, NOW, aged, extra_kwargs=None) -> dict:
    """construct -> decide(authorized) -> execute -> decide(hold, aged status) on one store; returns the RAW run.json text of both stores (byte comparison)."""
    deterministic_uuid4(monkeypatch)
    p = tenant_proposal()
    flow = build(tmp_path, Source(mat(60, 60)), **(extra_kwargs or {}))
    d = flow.decide(p, now=NOW)
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    (tmp_path / "hold").mkdir(exist_ok=True)
    hold_flow = build(tmp_path / "hold", Source(mat(10, 10)), resolver=aged(p, 30, "status"), **(extra_kwargs or {}))
    hold_flow.decide(p, now=NOW)
    return {"main": (tmp_path / "run.json").read_bytes().decode("utf-8"), "hold": (tmp_path / "hold" / "run.json").read_bytes().decode("utf-8")}
