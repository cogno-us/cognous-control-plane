"""Tests for persistence adapters."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_control_plane.persistence import FileSystemPersistenceAdapter
from agent_control_plane.records import RunRecorder


def _build_run_record_and_bundle():
    recorder = RunRecorder()
    recorder.start_run(
        task="Persistence test run",
        actor="test-agent",
        environment="test",
        allowed_tools=["crm_read"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    action = recorder.propose_action(
        tool_name="crm_read",
        action_type="read",
        target="customer:2",
    )
    recorder.evaluate_action(action)
    recorder.complete_run("Persistence complete.")
    return recorder.to_run_record(), recorder.generate_replay_bundle()


def test_save_and_load_run_record_round_trip(tmp_path: Path) -> None:
    record, _ = _build_run_record_and_bundle()
    adapter = FileSystemPersistenceAdapter(tmp_path)

    saved_path = adapter.save_run_record(record)
    loaded = adapter.load_run_record(record.run_id)

    assert Path(saved_path).exists()
    assert loaded == record


def test_save_and_load_replay_bundle_round_trip(tmp_path: Path) -> None:
    _, bundle = _build_run_record_and_bundle()
    adapter = FileSystemPersistenceAdapter(tmp_path)

    saved_path = adapter.save_replay_bundle(bundle)
    loaded = adapter.load_replay_bundle(bundle.replay_bundle_id)

    assert Path(saved_path).exists()
    assert loaded == bundle


def test_load_run_record_missing_file_raises(tmp_path: Path) -> None:
    adapter = FileSystemPersistenceAdapter(tmp_path)

    with pytest.raises(FileNotFoundError, match="Run record not found"):
        adapter.load_run_record("missing-run")


def test_load_replay_bundle_missing_file_raises(tmp_path: Path) -> None:
    adapter = FileSystemPersistenceAdapter(tmp_path)

    with pytest.raises(FileNotFoundError, match="Replay bundle not found"):
        adapter.load_replay_bundle("missing-bundle")


@pytest.mark.parametrize("unsafe_id", ["../escaped", "../../escaped", "nested/escaped", "<absolute>", ""])
def test_run_record_ids_cannot_escape_store_root(tmp_path: Path, unsafe_id: str) -> None:
    record, _ = _build_run_record_and_bundle()
    store = tmp_path / "store"
    adapter = FileSystemPersistenceAdapter(store)
    outside = tmp_path / "escaped.json"
    outside.write_text("{}", encoding="utf-8")
    if unsafe_id == "<absolute>":
        unsafe_id = str(tmp_path / "escaped")

    with pytest.raises(ValueError, match="Unsafe record identifier"):
        adapter.save_run_record(record.model_copy(update={"run_id": unsafe_id}))
    with pytest.raises(ValueError, match="Unsafe record identifier"):
        adapter.load_run_record(unsafe_id)
    assert outside.read_text(encoding="utf-8") == "{}"
    assert not (store / "escaped.json").exists()


@pytest.mark.parametrize("unsafe_id", ["../escaped", "../../escaped", "nested/escaped", "<absolute>", ""])
def test_replay_bundle_ids_cannot_escape_store_root(tmp_path: Path, unsafe_id: str) -> None:
    _, bundle = _build_run_record_and_bundle()
    store = tmp_path / "store"
    adapter = FileSystemPersistenceAdapter(store)
    outside = tmp_path / "escaped.json"
    outside.write_text("{}", encoding="utf-8")
    if unsafe_id == "<absolute>":
        unsafe_id = str(tmp_path / "escaped")

    with pytest.raises(ValueError, match="Unsafe record identifier"):
        adapter.save_replay_bundle(bundle.model_copy(update={"replay_bundle_id": unsafe_id}))
    with pytest.raises(ValueError, match="Unsafe record identifier"):
        adapter.load_replay_bundle(unsafe_id)
    assert outside.read_text(encoding="utf-8") == "{}"
    assert not (store / "escaped.json").exists()
