"""Every writer refuses unserialisable output before touching a file, leaves the existing record intact, and writes only
what the strict readers accept. Covers a lone surrogate, NaN and Infinity (the P2 regression: strict readers vs lax writers)."""
from __future__ import annotations

import math
import os
import stat
from pathlib import Path

import pytest

from agent_control_plane.atomic_write import write_bytes_atomic
from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination
from agent_control_plane.persistence import FileSystemPersistenceAdapter
from agent_control_plane.records import RunRecorder
from agent_control_plane.strict_json import dumps_bytes, strict_loads

BAD = [pytest.param("lone\ud800surrogate", id="lone-surrogate"),
       pytest.param(float("nan"), id="nan"),
       pytest.param(float("inf"), id="infinity"),
       pytest.param(float("-inf"), id="neg-infinity")]


def _tree_snapshot(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file() and not p.name.endswith(".lock")}


@pytest.mark.parametrize("bad", BAD)
def test_dumps_bytes_refuses(bad):
    with pytest.raises(ValueError, match="output_json_unserialisable"):
        dumps_bytes({"k": [bad]})
    with pytest.raises(ValueError, match="output_json_unserialisable"):
        dumps_bytes({"k": [bad]}, ensure_ascii=True)


@pytest.mark.parametrize("bad", BAD)
def test_record_store_refused_write_leaves_store_intact_and_readable(tmp_path, bad):
    path = tmp_path / "store" / "records.json"
    store = BoundedRecordStore(path, "run-1")
    before = path.read_bytes()
    with store._transaction():
        document = store._read_document()
        document["decisions"] = [{"note": bad}]
        with pytest.raises(ValueError, match="output_json_unserialisable"):
            store._write(document)
    assert path.read_bytes() == before
    assert not [p for p in path.parent.iterdir() if p.name not in {path.name, path.name + ".lock"}]  # no temp left behind
    reopened = BoundedRecordStore(path, "run-1")
    with reopened._transaction():
        assert reopened._read_document()["run_id"] == "run-1"


def test_record_store_output_is_strict_readable_and_private(tmp_path):
    path = tmp_path / "records.json"
    store = BoundedRecordStore(path, "run-1")
    with store._transaction():
        document = store._read_document()
        document["decisions"] = [{"note": "café \U0001F600"}]
        store._write(document)
    assert strict_loads(path.read_bytes())["decisions"][0]["note"] == "café \U0001F600"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("bad", BAD)
def test_destination_refused_write_leaves_state_intact(tmp_path, bad):
    path = tmp_path / "dest" / "state.json"
    dest = LocalRefundDestination(path)
    before = path.read_bytes()
    with dest._transaction():
        with pytest.raises(ValueError, match="output_json_unserialisable"):
            dest._write({"effects": {"e": bad}, "grant_effect_counts": {}})
    assert path.read_bytes() == before
    assert strict_loads(path.read_bytes())["effects"] == {}


def _recorder(task="Writer test", payload=None):
    recorder = RunRecorder()
    recorder.start_run(task=task, actor="a", environment="test", allowed_tools=["crm_read"], blocked_tools=[], policy_version="v1")
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="customer:1", **({"payload": payload} if payload else {}))
    recorder.evaluate_action(action)
    recorder.complete_run("done")
    return recorder


def test_adapter_refused_save_leaves_existing_record_intact(tmp_path):
    good = _recorder()
    record = good.to_run_record()
    adapter = FileSystemPersistenceAdapter(tmp_path, overwrite=True)
    path = Path(adapter.save_run_record(record))
    before = path.read_bytes()
    bad = record.model_copy(update={"task": "lone\ud800surrogate"})
    with pytest.raises(ValueError, match="output_json_unserialisable"):
        adapter.save_run_record(bad)
    assert path.read_bytes() == before
    assert adapter.load_run_record(record.run_id) == record
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_adapter_default_is_exclusive_create_with_explicit_overwrite(tmp_path):
    record = _recorder().to_run_record()
    adapter = FileSystemPersistenceAdapter(tmp_path)
    path = Path(adapter.save_run_record(record))
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        adapter.save_run_record(record.model_copy(update={"task": "other"}))
    assert path.read_bytes() == before
    adapter.save_run_record(record.model_copy(update={"task": "other"}), overwrite=True)
    assert adapter.load_run_record(record.run_id).task == "other"


def test_export_json_refused_write_leaves_existing_file_and_output_is_strict(tmp_path):
    out = tmp_path / "run.json"
    recorder = _recorder(payload={"amount": float("inf"), "n": float("nan")})
    recorder.export_json(out)  # python-mode dump would have written Infinity; mode="json" writes null
    text = out.read_bytes()
    strict_loads(text)  # accepted by the strict reader
    assert b"Infinity" not in text and b"NaN" not in text
    before = out.read_bytes()
    bad = _recorder(task="lone\ud800surrogate")
    with pytest.raises(ValueError, match="output_json_unserialisable"):
        bad.export_json(out)
    assert out.read_bytes() == before
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_write_bytes_atomic_exclusive_and_overwrite(tmp_path):
    path = tmp_path / "x.json"
    write_bytes_atomic(path, b"1", overwrite=False)
    with pytest.raises(FileExistsError):
        write_bytes_atomic(path, b"2", overwrite=False)
    assert path.read_bytes() == b"1"
    write_bytes_atomic(path, b"3", overwrite=True)
    assert path.read_bytes() == b"3"
    assert sorted(os.listdir(tmp_path)) == ["x.json"]
