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


# ---------------------------------------------------------------------------------------------------------------------
# F1 (independent review R1): untrusted names, path-character refusal, hard links, nesting, and check-to-use races.
# Each test below fails on main 128eaa5 (or kills a mutant R1 showed surviving) and passes with the hardening.
# ---------------------------------------------------------------------------------------------------------------------
from agent_control_plane import cli_run  # noqa: E402


def _argv(inputs, store, out, *, now=NOW):
    return ["run", "--manifest", str(inputs["manifest"]), "--proposal", str(inputs["proposal"]),
            "--authority-context", str(inputs["authority-context"]), "--resolver-state", str(inputs["resolver-state"]),
            "--store-dir", str(store), "--out-dir", str(out), "--now", now]


def test_untrusted_member_names_are_escaped_and_truncated_on_stderr(tmp_path):
    """R1: an unknown member named 'x\\nacp run: pass (exit 0)\\x1b[2J' forged a stderr line and an ANSI sequence."""
    inputs = _inputs(tmp_path, "authorized")
    doc = _json(inputs["proposal"])
    doc["x\nacp run: pass (exit 0)\x1b[2J"] = 1
    doc["‮txt.exe"] = 2           # bidi override
    doc["A" * 5000] = 3                # unbounded name
    inputs["proposal"].write_text(json.dumps(doc), encoding="utf-8")
    code, stdout, stderr = _run(tmp_path, inputs=inputs)
    assert code == 2 and stdout == ""
    assert stderr.count("\n") == 1, repr(stderr)                     # one line: the newline in the name did not forge another
    assert "\x1b" not in stderr and "‮" not in stderr and "\r" not in stderr
    assert "\\x0a" in stderr and "\\x1b" in stderr and "\\u202e" in stderr
    assert len(stderr) < 600                                          # 5000-character name truncated


def test_untrusted_resolver_keys_are_escaped_on_stderr(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    doc = _json(inputs["resolver-state"])
    doc["statuses"] = {"k\ney\x1b[31m": {"bogus": 1}}
    inputs["resolver-state"].write_text(json.dumps(doc), encoding="utf-8")
    code, _, stderr = _run(tmp_path, inputs=inputs)
    assert code == 2 and stderr.count("\n") == 1 and "\x1b" not in stderr


def test_safe_escapes_controls_and_truncates():
    assert cli_run._safe("a\nb\x00c\x1b") == "a\\x0ab\\x00c\\x1b"
    assert cli_run._safe("é") == "é"
    assert cli_run._safe("z" * 300, 20) == "z" * 17 + "..."
    names = [f"n{i}" for i in range(9)]
    assert cli_run._names(names).endswith("(+4 more)")


def test_cr_lf_in_the_name_of_an_existing_path_is_refused_for_that_reason(tmp_path):
    """R1 mutant 'crlf check removed' survived: the old test named a path that did not exist, so another check refused it."""
    inputs = _inputs(tmp_path, "authorized")
    for bad in ("p\nq.json", "p\rq.json"):
        existing = tmp_path / "inputs" / bad
        shutil.copy(inputs["proposal"], existing)
        assert existing.is_file()
        code, _, stderr = _run(tmp_path, inputs=dict(inputs, proposal=existing))
        assert code == 2 and "CR, LF or NUL" in stderr, stderr
        assert not (tmp_path / "store").exists()


def test_nul_in_a_path_is_refused_for_that_reason(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    code, _, stderr = _run(tmp_path, inputs=dict(inputs, proposal=Path(str(inputs["proposal"]) + "\0x")))
    assert code == 2 and "CR, LF or NUL" in stderr, stderr
    with pytest.raises(cli_run.InvalidInput, match="CR, LF or NUL"):
        cli_run._lexical_abs("a\0b")
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / "s\0", tmp_path / "o"))
    assert code == 2 and "CR, LF or NUL" in stderr


def test_hard_linked_input_is_refused_for_that_reason(tmp_path):
    """R1 mutant 'hardlink check removed' survived: no test created a real hard link."""
    import os
    inputs = _inputs(tmp_path, "authorized")
    os.link(inputs["proposal"], tmp_path / "second-name.json")
    assert os.stat(inputs["proposal"]).st_nlink == 2
    code, _, stderr = _run(tmp_path, inputs=inputs)
    assert code == 2 and "hard-linked" in stderr, stderr
    assert not (tmp_path / "store").exists() and not (tmp_path / "out").exists()


@pytest.mark.parametrize("store_rel,out_rel", [("a", "a/b"), ("a/b", "a")])
def test_nested_store_and_out_dirs_refused_in_both_directions_with_an_existing_parent(tmp_path, store_rel, out_rel):
    """R1: with `a` absent the old test failed on the missing parent and never reached the nesting rule."""
    inputs = _inputs(tmp_path, "authorized")
    (tmp_path / "a").mkdir()
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / store_rel, tmp_path / out_rel))
    assert code == 2 and "non-nested" in stderr, stderr
    assert list((tmp_path / "a").iterdir()) == []


@pytest.mark.parametrize("which", ["store", "out"])
def test_input_inside_either_output_dir_is_refused(tmp_path, monkeypatch, which):
    """The emptiness rule makes 'input inside an output dir' unreachable for a real directory (an input inside it would make it
    non-empty), so R1's out-dir mutant is equivalent in practice. This test removes the emptiness rule to exercise the
    containment rule itself, for both directories."""
    inputs = _inputs(tmp_path, "authorized")
    original = cli_run._output_dir

    def no_emptiness(raw, label):
        return cli_run._lexical_abs(raw), None
    monkeypatch.setattr(cli_run, "_output_dir", no_emptiness)
    inside = tmp_path / "inputs"
    store, out = (inside, tmp_path / "o") if which == "store" else (tmp_path / "s", inside)
    code, _, stderr = _invoke(*_argv(inputs, store, out))
    assert code == 2 and "must not live inside" in stderr, stderr
    monkeypatch.setattr(cli_run, "_output_dir", original)


def test_output_dir_that_appears_after_validation_is_not_reused(tmp_path, monkeypatch):
    """TOCTOU: a new output directory is created without exist_ok; one that appeared since validation is refused."""
    inputs = _inputs(tmp_path, "authorized")
    original = cli_run._output_dir

    def racing(raw, label):
        path, seen = original(raw, label)
        if label == "--out-dir":
            path.mkdir()                       # an attacker (or another process) creates it between check and use
            (path / "planted.txt").write_text("x")
        return path, seen
    monkeypatch.setattr(cli_run, "_output_dir", racing)
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / "store", tmp_path / "out"))
    assert code == 2 and "appeared after validation" in stderr, stderr
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["planted.txt"]


def test_empty_output_dir_swapped_for_a_symlink_after_validation_is_refused(tmp_path, monkeypatch):
    inputs = _inputs(tmp_path, "authorized")
    (tmp_path / "out").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    original = cli_run._output_dir

    def racing(raw, label):
        path, seen = original(raw, label)
        if label == "--out-dir":
            path.rmdir()
            path.symlink_to(elsewhere)
        return path, seen
    monkeypatch.setattr(cli_run, "_output_dir", racing)
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / "store", tmp_path / "out"))
    assert code == 2 and "symlink" in stderr, stderr
    assert list(elsewhere.iterdir()) == []


def test_empty_output_dir_replaced_by_another_directory_after_validation_is_refused(tmp_path, monkeypatch):
    inputs = _inputs(tmp_path, "authorized")
    (tmp_path / "out").mkdir()
    original = cli_run._output_dir

    def racing(raw, label):
        path, seen = original(raw, label)
        if label == "--out-dir":
            path.rename(path.with_name("out.old"))   # keep the old inode alive so the new one cannot reuse its number
            path.mkdir()                       # a different directory at the same name
        return path, seen
    monkeypatch.setattr(cli_run, "_output_dir", racing)
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / "store", tmp_path / "out"))
    assert code == 2 and "changed after validation" in stderr, stderr


def test_input_swapped_for_a_symlink_after_validation_is_not_read(tmp_path, monkeypatch):
    import os
    inputs = _inputs(tmp_path, "authorized")
    secret = tmp_path / "secret.json"
    secret.write_text("{}")
    original = cli_run._input_file

    def racing(raw, label):
        path = original(raw, label)
        if label == "--proposal":
            os.unlink(path)
            os.symlink(secret, path)           # swapped after the lstat/stat checks
        return path
    monkeypatch.setattr(cli_run, "_input_file", racing)
    code, _, stderr = _invoke(*_argv(inputs, tmp_path / "store", tmp_path / "out"))
    assert code == 2 and "cannot open input safely" in stderr, stderr
    assert not (tmp_path / "store").exists() and not (tmp_path / "out").exists()


# --- strict input parsing (duplicate members, NaN/Infinity, non-UTF-8) -----------------------------------------------------


def _dup_member(path: Path, key: str, value) -> None:
    text = path.read_text(encoding="utf-8").rstrip()
    assert text.endswith("}")
    path.write_text(text[:-1] + f", {json.dumps(key)}: {json.dumps(value)}}}", encoding="utf-8")


@pytest.mark.parametrize("name", ["proposal", "authority-context", "resolver-state", "manifest"])
@pytest.mark.parametrize("same_value", [True, False])
def test_duplicate_object_member_is_refused_in_every_input(tmp_path, name, same_value):
    inputs = _inputs(tmp_path, "authorized")
    doc = _json(inputs[name])
    key = next(iter(doc))
    _dup_member(inputs[name], key, doc[key] if same_value else "other")
    code, _, err = _run(tmp_path, inputs=inputs)
    assert code == 2 and "[input_json_duplicate_member]" in err and not (tmp_path / "out").exists()


def test_duplicate_member_in_a_nested_object_is_refused(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    path = inputs["proposal"]
    path.write_text(path.read_text(encoding="utf-8").replace('"customer_id": "customer-001",', '"customer_id": "a", "customer_id": "b",', 1))
    code, _, err = _run(tmp_path, inputs=inputs)
    assert code == 2 and "[input_json_duplicate_member]" in err


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_are_refused_with_their_own_code(tmp_path, token):
    inputs = _inputs(tmp_path, "authorized")
    path = inputs["proposal"]
    # in a free-form member, where the model would not otherwise reject the value
    path.write_text(path.read_text(encoding="utf-8").replace('"risk_metadata": {}', f'"risk_metadata": {{"x": {token}}}'))
    code, _, err = _run(tmp_path, inputs=inputs)
    assert code == 2 and "[input_json_non_finite_number]" in err


def test_non_utf8_input_is_refused_with_its_own_code(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    inputs["proposal"].write_bytes(b'{"a": "\xe9"}')
    code, _, err = _run(tmp_path, inputs=inputs)
    assert code == 2 and "[input_not_utf8]" in err


def test_strict_loads_accepts_ordinary_documents_and_keeps_values():
    from agent_control_plane.cli_run import strict_loads

    assert strict_loads(b'{"a": [1, 2.5, null, true], "b": {"c": "\\u00e9"}}') == {"a": [1, 2.5, None, True], "b": {"c": "é"}}
    assert strict_loads(b'{"a": 1, "b": 1}') == {"a": 1, "b": 1}  # same value under different keys is fine
