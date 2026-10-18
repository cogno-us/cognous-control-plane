"""Lock files are owner-only and run directories are 0700, including when the path already existed with broader modes."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination

from tests.test_cli_run import _inputs, _invoke, NOW


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture
def open_umask():
    old = os.umask(0)
    try:
        yield
    finally:
        os.umask(old)


def test_record_store_lock_and_lease_files_are_owner_only(tmp_path, open_umask):
    store = BoundedRecordStore(tmp_path / "run.json", "run-1")
    assert _mode(tmp_path / "run.json.lock") == 0o600
    with store.check_lease("check-1"):
        pass
    assert _mode(tmp_path / "run.json.check-check-1.lock") == 0o600


def test_record_store_narrows_preexisting_broad_lock_files(tmp_path, open_umask):
    lock = tmp_path / "run.json.lock"
    lease = tmp_path / "run.json.check-check-1.lock"
    for path in (lock, lease):
        path.write_bytes(b"")
        os.chmod(path, 0o666)
    store = BoundedRecordStore(tmp_path / "run.json", "run-1")
    with store.check_lease("check-1"):
        pass
    assert _mode(lock) == 0o600 and _mode(lease) == 0o600


def test_destination_lock_file_is_owner_only(tmp_path, open_umask):
    LocalRefundDestination(tmp_path / "destination.json")
    assert _mode(tmp_path / "destination.json.lock") == 0o600


def test_destination_narrows_preexisting_broad_lock_file(tmp_path, open_umask):
    lock = tmp_path / "destination.json.lock"
    lock.write_bytes(b"")
    os.chmod(lock, 0o666)
    LocalRefundDestination(tmp_path / "destination.json")
    assert _mode(lock) == 0o600


def test_run_directories_are_0700_and_outputs_still_written(tmp_path, open_umask):
    code, stdout, _ = _invoke_run(tmp_path)
    assert code == 0, stdout
    assert _mode(tmp_path / "store") == 0o700 and _mode(tmp_path / "out") == 0o700
    assert (tmp_path / "out" / "result.json").is_file()


def test_preexisting_empty_run_directories_are_narrowed(tmp_path, open_umask):
    for name in ("store", "out"):
        (tmp_path / name).mkdir()
        os.chmod(tmp_path / name, 0o777)
    code, stdout, _ = _invoke_run(tmp_path)
    assert code == 0, stdout
    assert _mode(tmp_path / "store") == 0o700 and _mode(tmp_path / "out") == 0o700


def _invoke_run(tmp_path: Path):
    inputs = _inputs(tmp_path, "authorized")
    return _invoke(
        "run",
        "--manifest", str(inputs["manifest"]),
        "--proposal", str(inputs["proposal"]),
        "--authority-context", str(inputs["authority-context"]),
        "--resolver-state", str(inputs["resolver-state"]),
        "--store-dir", str(tmp_path / "store"),
        "--out-dir", str(tmp_path / "out"),
        "--now", NOW,
    )


def test_witness_lock_file_is_owner_only_even_when_it_existed_broader(tmp_path, open_umask):
    import agent_control_plane.witness as W

    lock = tmp_path / "w.jsonl.lock"
    lock.write_bytes(b"")
    os.chmod(lock, 0o666)
    W.publish_head({"run_id": "r", "decisions": [{"decision_id": "d1"}]}, W.LocalFileWitness(tmp_path / "w.jsonl"))
    assert _mode(lock) == 0o600
