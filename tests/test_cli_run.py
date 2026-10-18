"""Tests for `acp run` (declared bounded operation against a local throwaway store)."""

from __future__ import annotations

import io
import json
import shutil
import socket
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from agent_control_plane.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "acp_run"
NOW = "2026-10-05T19:00:00Z"


def _invoke(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(args)
    return code, out.getvalue(), err.getvalue()


def _inputs(tmp_path: Path, case: str) -> dict[str, Path]:
    """Copy a declared example into tmp_path/inputs so tests can mutate it."""
    base = tmp_path / "inputs"
    base.mkdir(exist_ok=True)
    shutil.copy(EXAMPLES / "manifest.json", base / "manifest.json")
    for name in ("proposal", "authority-context", "resolver-state"):
        shutil.copy(EXAMPLES / case / f"{name}.json", base / f"{name}.json")
    return {name: base / f"{name}.json" for name in ("manifest", "proposal", "authority-context", "resolver-state")}


def _run(tmp_path: Path, case: str = "authorized", *extra: str, inputs=None, now: str | None = NOW):
    inputs = inputs or _inputs(tmp_path, case)
    args = [
        "run",
        "--manifest", str(inputs["manifest"]),
        "--proposal", str(inputs["proposal"]),
        "--authority-context", str(inputs["authority-context"]),
        "--resolver-state", str(inputs["resolver-state"]),
        "--store-dir", str(tmp_path / "store"),
        "--out-dir", str(tmp_path / "out"),
        *extra,
    ]
    if now:
        args += ["--now", now]
    return _invoke(*args)


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_authorized_and_applied_exit_0_and_record_validates(tmp_path):
    code, stdout, _ = _run(tmp_path)
    assert code == 0, stdout
    out = tmp_path / "out"
    result = _json(out / "result.json")
    assert result["envelope_version"] == "1" and result["outcome"] == "pass" and result["exit_code"] == 0
    assert result["does_not_prove"] and "does not prove" in stdout
    assert result["verdict_source"]["component"] == "control-plane"
    assert result["extensions"]["x-acp-run"]["time_source"] == "test_override"
    destination = _json(tmp_path / "store" / "destination.json")
    assert len(destination["effects"]) == 1
    native = _json(out / "bounded-run-record.json")
    assert native["decisions"][0]["result"] == "authorized"
    assert native["attempts"][-1]["status"] == "acknowledged"
    assert not (out / "ci-diagnostics.json").exists()
    vcode, vout, _ = _invoke("validate-run", str(out / "run-record.json"))
    assert vcode == 0 and "valid (0 errors" in vout


def test_held_exit_1_with_refusal_rows_and_record_validates(tmp_path):
    code, stdout, _ = _run(tmp_path, "held")
    assert code == 1, stdout
    out = tmp_path / "out"
    result = _json(out / "result.json")
    assert result["outcome"] == "fail" and result["exit_code"] == 1
    assert "grant_scope_mismatch" in result["reason_codes"]
    native = _json(out / "bounded-run-record.json")
    assert native["decisions"][0]["result"] == "hold"
    assert native["decisions"][0]["reasons"] == result["reason_codes"]
    assert native["attempts"] == []
    assert _json(tmp_path / "store" / "destination.json")["effects"] == {}
    record = _json(out / "run-record.json")
    assert len(record["blocked_actions"]) == 1
    assert record["decisions"][0]["result"] == "block"
    assert record["decisions"][0]["decision_id"] == native["decisions"][0]["decision_id"]
    assert _json(out / "ci-diagnostics.json")["exit_code"] == 1
    vcode, _, _ = _invoke("validate-run", str(out / "run-record.json"))
    assert vcode == 0


def test_real_clock_without_now_holds_on_stale_inputs(tmp_path):
    code, _, _ = _run(tmp_path, now=None)
    assert code == 1
    result = _json(tmp_path / "out" / "result.json")
    assert result["extensions"]["x-acp-run"]["time_source"] == "control_plane"
    assert _json(tmp_path / "store" / "destination.json")["effects"] == {}


def test_json_format_prints_only_the_envelope(tmp_path):
    code, stdout, _ = _run(tmp_path, "authorized", "--format", "json")
    assert code == 0
    assert json.loads(stdout)["command"] == "run"


@pytest.mark.parametrize("mutate", ["bad_json", "unknown_member", "digest", "missing_file", "bad_now", "unknown_section"])
def test_invalid_input_exit_2(tmp_path, mutate):
    inputs = _inputs(tmp_path, "authorized")
    now = NOW
    if mutate == "bad_json":
        inputs["proposal"].write_text("{nope", encoding="utf-8")
    elif mutate == "unknown_member":
        doc = _json(inputs["proposal"]); doc["tenant_id"] = "t"
        inputs["proposal"].write_text(json.dumps(doc), encoding="utf-8")
    elif mutate == "digest":
        doc = _json(inputs["manifest"]); doc["note"] = "changed"
        inputs["manifest"].write_text(json.dumps(doc), encoding="utf-8")
    elif mutate == "missing_file":
        inputs["resolver-state"].unlink()
    elif mutate == "bad_now":
        now = "2026-10-05T19:00:00"
    else:
        doc = _json(inputs["resolver-state"]); doc["extra"] = {}
        inputs["resolver-state"].write_text(json.dumps(doc), encoding="utf-8")
    code, _, stderr = _run(tmp_path, inputs=inputs, now=now)
    assert code == 2 and "invalid input" in stderr
    assert not (tmp_path / "store").exists() and not (tmp_path / "out").exists()


def test_symlink_and_crlf_paths_refused(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    link = tmp_path / "link.json"
    link.symlink_to(inputs["proposal"])
    linked = dict(inputs, proposal=link)
    assert _run(tmp_path, inputs=linked)[0] == 2
    linked_dir = tmp_path / "linkdir"
    linked_dir.symlink_to(tmp_path / "inputs")
    via_dir = {k: linked_dir / v.name for k, v in inputs.items()}
    assert _run(tmp_path, inputs=via_dir)[0] == 2
    crlf = dict(inputs, proposal=Path(str(inputs["proposal"]) + "\r\nx"))
    assert _run(tmp_path, inputs=crlf)[0] == 2
    # output dir through a symlink
    real = tmp_path / "real"; real.mkdir()
    (tmp_path / "outlink").symlink_to(real)
    code, _, err = _invoke(
        "run", "--manifest", str(inputs["manifest"]), "--proposal", str(inputs["proposal"]),
        "--authority-context", str(inputs["authority-context"]), "--resolver-state", str(inputs["resolver-state"]),
        "--store-dir", str(tmp_path / "outlink" / "s"), "--out-dir", str(tmp_path / "o"), "--now", NOW,
    )
    assert code == 2 and "symlink" in err
    assert list(real.iterdir()) == []


def test_output_dir_confinement(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "keep.txt").write_text("x")
    assert _run(tmp_path, inputs=inputs)[0] == 2  # non-empty out dir
    shutil.rmtree(tmp_path / "out")
    base = ["run", "--manifest", str(inputs["manifest"]), "--proposal", str(inputs["proposal"]),
            "--authority-context", str(inputs["authority-context"]), "--resolver-state", str(inputs["resolver-state"]), "--now", NOW]
    # missing parent: parents are never created
    assert _invoke(*base, "--store-dir", str(tmp_path / "nope" / "s"), "--out-dir", str(tmp_path / "o"))[0] == 2
    # nested store/out
    assert _invoke(*base, "--store-dir", str(tmp_path / "a"), "--out-dir", str(tmp_path / "a" / "b"))[0] == 2
    # input inside an output dir
    assert _invoke(*base, "--store-dir", str(tmp_path / "inputs"), "--out-dir", str(tmp_path / "o"))[0] == 2


def test_writes_only_inside_declared_dirs(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    before = {p for p in tmp_path.rglob("*")}
    assert _run(tmp_path, inputs=inputs)[0] == 0
    created = {p for p in tmp_path.rglob("*")} - before
    for p in created:
        assert (tmp_path / "store") in p.parents or (tmp_path / "out") in p.parents or p in {tmp_path / "store", tmp_path / "out"}
    assert {p.name for p in inputs.values()} == {p.name for p in (tmp_path / "inputs").iterdir()}


@pytest.mark.parametrize("case,expected", [("authorized", 0), ("held", 1)])
def test_no_network(tmp_path, monkeypatch, case, expected):
    def blocked(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    code, _, _ = _run(tmp_path, case)
    assert code == expected
    assert _json(tmp_path / "out" / "result.json")["extensions"]["x-acp-run"]["network"] == "none"


def test_internal_error_exit_4(tmp_path, monkeypatch):
    from agent_control_plane import cli_run
    def boom(self, *a, **k):
        raise RuntimeError("synthetic failure")
    monkeypatch.setattr(cli_run.BoundedAuthorizationWorkflow, "decide", boom)
    code, _, _ = _run(tmp_path)
    assert code == 4
    result = _json(tmp_path / "out" / "result.json")
    assert result["exit_code"] == 4 and result["reason_codes"] == ["internal_error"]
    assert _json(tmp_path / "out" / "ci-diagnostics.json")["exit_code"] == 4


def test_effect_time_refusal_exit_1(tmp_path, monkeypatch):
    """Authority withdrawn between decide and execute: refused, refusal row recorded."""
    from agent_control_plane import cli_run
    original = cli_run.BoundedAuthorizationWorkflow.execute
    def revoke_then_execute(self, *a, **k):
        for status in self.resolver.statuses.values():
            status.status = "revoked"
        return original(self, *a, **k)
    monkeypatch.setattr(cli_run.BoundedAuthorizationWorkflow, "execute", revoke_then_execute)
    code, _, _ = _run(tmp_path)
    assert code == 1
    native = _json(tmp_path / "out" / "bounded-run-record.json")
    assert native["refusals"] and "grant_not_active" in native["refusals"][0]["reasons"]
    assert _json(tmp_path / "store" / "destination.json")["effects"] == {}
    assert _invoke("validate-run", str(tmp_path / "out" / "run-record.json"))[0] == 0
