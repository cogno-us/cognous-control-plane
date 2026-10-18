"""Strict JSON at every stored-file and operator-file read (follow-up to the strict ``acp run`` inputs).

Refused at each site, with a stable ``[code]`` and without changing the file or creating state: non-UTF-8 bytes, a duplicate
object member, NaN, Infinity, -Infinity. Valid input reads exactly as before. ``ReplayBundle.from_json`` stays lenient on purpose:
``to_json`` writes the python-mode dump, which can hold NaN/Infinity in free-form ``dict`` members, so strict reading there would refuse
a file this project wrote. A test below pins that.
"""
from __future__ import annotations

import io
import json
import math
from pathlib import Path

import pytest

import agent_control_plane.witness as W
from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination
from agent_control_plane.cli import main as acp_main
from agent_control_plane.persistence import FileSystemPersistenceAdapter
from agent_control_plane.policy_config import load_policy_config
from agent_control_plane.records import RunRecorder
from agent_control_plane.replay import from_json, to_json
from agent_control_plane.strict_json import strict_loads

POLICY = Path(__file__).resolve().parent.parent / "examples" / "policy_config.json"

# (id, expected code, function turning valid object-JSON bytes into a damaged document)
def _inject(member: bytes):
    return lambda data: data.replace(b"{", b"{" + member + b",", 1)


DAMAGE = [
    ("duplicate", "input_json_duplicate_member", _inject(b'"zz": 1, "zz": 2')),
    ("nan", "input_json_non_finite_number", _inject(b'"zz": NaN')),
    ("infinity", "input_json_non_finite_number", _inject(b'"zz": Infinity')),
    ("neg_infinity", "input_json_non_finite_number", _inject(b'"zz": -Infinity')),
    ("not_utf8", "input_not_utf8", _inject(b'"zz": "\xe9"')),
]
DAMAGE_PARAMS = [pytest.param(code, fn, id=name) for name, code, fn in DAMAGE]


def _recorder():
    recorder = RunRecorder()
    recorder.start_run(task="t", actor="a", environment="test", allowed_tools=["crm_read"], blocked_tools=[], policy_version="v1")
    recorder.evaluate_action(recorder.propose_action(tool_name="crm_read", action_type="read", target="c:1"))
    recorder.complete_run("done")
    return recorder


def _damage(path: Path, fn) -> bytes:
    path.write_bytes(fn(path.read_bytes()))
    return path.read_bytes()


# -- the shared loader ------------------------------------------------------------------------------------------------

def test_valid_documents_parse_exactly_as_json_loads_does():
    text = '{"a": [1, 2.5, -0.0, null, true], "b": {"c": "\\u00e9\\ud800"}, "d": 1e3, "e": {}, "f": []}'
    assert strict_loads(text) == json.loads(text)
    assert strict_loads(text.encode()) == json.loads(text)
    assert strict_loads(b'{"a": 1, "b": 1}') == {"a": 1, "b": 1}


# -- cli.py (_load_json_model: validate-run and its siblings) ---------------------------------------------------------

@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_cli_model_loader_refuses_damage_with_exit_2_and_leaves_file_alone(tmp_path, capsys, code, fn):
    path = tmp_path / "run-record.json"
    path.write_text(json.dumps(_recorder().to_run_record().model_dump(mode="json")), encoding="utf-8")
    assert acp_main(["validate-run", str(path)]) == 0
    before = _damage(path, fn)
    capsys.readouterr()
    assert acp_main(["validate-run", str(path)]) == 2
    err = capsys.readouterr().err
    assert f"[{code}]" in err and "Traceback" not in err
    assert path.read_bytes() == before


# -- persistence.py ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_persistence_load_refuses_damage_and_changes_nothing(tmp_path, code, fn):
    record = _recorder().to_run_record()
    adapter = FileSystemPersistenceAdapter(tmp_path)
    saved = Path(adapter.save_run_record(record))
    assert adapter.load_run_record(record.run_id) == record
    before = _damage(saved, fn)
    snapshot = sorted(p.name for p in tmp_path.rglob("*"))
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        adapter.load_run_record(record.run_id)
    assert saved.read_bytes() == before and sorted(p.name for p in tmp_path.rglob("*")) == snapshot


def test_persistence_round_trip_holds_a_nan_in_a_free_form_member(tmp_path):
    # Writers use ``model_dump(mode="json")``, which turns NaN into null, so strict reading never refuses a file this project wrote.
    recorder = _recorder()
    record = recorder.to_run_record()
    record.actions[0].payload["x"] = math.nan
    adapter = FileSystemPersistenceAdapter(tmp_path)
    saved = Path(adapter.save_run_record(record))
    assert b"NaN" not in saved.read_bytes()
    assert adapter.load_run_record(record.run_id).actions[0].payload["x"] is None


# -- policy_config.py -------------------------------------------------------------------------------------------------

def test_policy_config_valid_file_loads():
    assert load_policy_config(POLICY).policy_version == "v1.1"


@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_policy_config_refuses_damage(tmp_path, code, fn):
    path = tmp_path / "policy.json"
    path.write_bytes(fn(POLICY.read_bytes()))
    with pytest.raises(ValueError, match=rf"Failed to parse policy config JSON: \[{code}\]"):
        load_policy_config(path)


# -- witness.py: record document and witness file ---------------------------------------------------------------------

def _doc():
    return {"run_id": "run-1", "decisions": [{"decision_id": "d1"}], "refusals": [], "attempts": []}


@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_witness_cli_refuses_a_damaged_record_document(tmp_path, code, fn):
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(_doc()), encoding="utf-8")
    wit = tmp_path / "w.jsonl"
    before = _damage(path, fn)
    for sub in ("digest", "publish", "verify"):
        argv = ["witness", sub, str(path)] + ([] if sub == "digest" else ["--witness", str(wit)])
        err = io.StringIO()
        assert W.witness_command(_parse(argv), io.StringIO(), err) == 2
        assert f"[{code}]" in err.getvalue()
    assert path.read_bytes() == before and not wit.exists()


def _parse(argv):
    import argparse

    parser = argparse.ArgumentParser()
    W.add_witness_parser(parser.add_subparsers(dest="command"))
    return parser.parse_args(argv)


@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_damaged_witness_file_refuses_history_and_publish_without_appending(tmp_path, code, fn):
    witness = W.LocalFileWitness(tmp_path / "w.jsonl")
    W.publish_head(_doc(), witness)
    path = witness.path
    # damage the one JSON-lines record; the record is a single object on one line
    before = _damage(path, fn)
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        witness.history()
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        W.publish_head(_doc(), witness)
    assert path.read_bytes() == before


def test_witness_valid_file_reads_back_unchanged(tmp_path):
    witness = W.LocalFileWitness(tmp_path / "w.jsonl")
    record = W.publish_head(_doc(), witness)
    assert witness.history() == [json.loads(line) for line in witness.path.read_text().splitlines()]
    assert witness.latest() == record


# -- bounded.py: record store and destination ledger ------------------------------------------------------------------

@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_record_store_refuses_damage_on_load_and_on_reopen(tmp_path, code, fn):
    path = tmp_path / "store" / "bounded-run-record.json"
    store = BoundedRecordStore(path, "run-1")
    assert store.load().run_id == "run-1"
    before = _damage(path, fn)
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        store.load()
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        BoundedRecordStore(path, "run-1")  # corruption must not re-initialize an empty store
    assert path.read_bytes() == before


@pytest.mark.parametrize("code,fn", DAMAGE_PARAMS)
def test_destination_ledger_refuses_damage_and_applies_nothing(tmp_path, code, fn):
    path = tmp_path / "destination.json"
    destination = LocalRefundDestination(path)
    assert destination.snapshot()["effects"] == {}
    before = _damage(path, fn)
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        destination.snapshot()
    with pytest.raises(ValueError, match=rf"\[{code}\]"):
        destination.apply(effect_id="e1", grant_id="g1", max_effects=1, target="t", amount=1.0, unit="USD", payload={})
    assert path.read_bytes() == before


# -- replay.py stays lenient (kept as is, with the reason) ------------------------------------------------------------

def test_replay_bundle_from_json_still_reads_what_to_json_wrote_including_nan():
    recorder = _recorder()
    bundle = recorder.generate_replay_bundle()
    bundle.actions[0].payload["x"] = math.nan
    text = to_json(bundle)
    assert "NaN" in text  # python-mode dump: written by this project, so reading must accept it
    assert math.isnan(from_json(text).actions[0].payload["x"])
