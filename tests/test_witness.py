"""witness-digest/0.1: opt-in outside-held head digest (verifier side and a local file witness).

The composed scenario (the same drop accepted today under HMAC, signature and store, rejected with a witness) lives in the
qualification suite suites/outside-holder. These tests cover the module's own rules. Synthetic data only; no network, tag or release.

Limit asserted below, not hidden: the digest gives visibility to a reader holding the witness digest, not tamper evidence against the
witness holder.
"""
import copy
import io
import json

import pytest

import agent_control_plane.witness as W
from agent_control_plane.bounded import BoundedRecordStore
from agent_control_plane.cli import main as acp_main


def document():
    return {"run_id": "run-1", "input_time_floors": {"k": "2026-10-05T19:00:00+00:00"},
            "decisions": [{"decision_id": "d1"}, {"decision_id": "d2"}],
            "refusals": [{"refusal_id": "r1", "reasons": ["grant_revoked"]}],
            "attempts": []}


def held(tmp_path, doc=None, name="w.jsonl"):
    witness = W.LocalFileWitness(tmp_path / name)
    W.publish_head(doc or document(), witness)
    return witness


def test_chain_covers_every_nonempty_list_ledger_and_not_scalars_or_dicts():
    digest = W.head_digest(document())
    assert set(digest) == {"decisions", "refusals"}          # empty ledger omitted; run_id and input_time_floors not covered
    assert digest["decisions"]["count"] == 2 and digest["refusals"]["count"] == 1
    assert W.chain_head([]) == W.GENESIS


def test_chain_is_order_and_content_sensitive_and_prefix_stable():
    rows = [{"a": 1}, {"a": 2}]
    assert W.chain_head(rows) != W.chain_head(list(reversed(rows)))
    assert W.chain_head(rows) != W.chain_head([{"a": 1}, {"a": 3}])
    assert W.chain_heads(rows + [{"a": 3}])[:3] == W.chain_heads(rows)     # appending keeps the covered prefix valid


def test_untouched_and_appended_record_sets_verify_and_appends_are_unwitnessed(tmp_path):
    witness = held(tmp_path)
    assert W.verify_against_witness(document(), witness).ok
    grown = document()
    grown["decisions"].append({"decision_id": "d3"})
    grown["attempts"].append({"attempt_id": "a1"})
    verdict = W.verify_against_witness(grown, witness)
    assert verdict.ok and verdict.unwitnessed_rows == {"attempts": 1, "decisions": 1}
    assert verdict.witnessed_through == {"decisions": 2, "refusals": 1}
    assert "not tamper evidence against the witness holder" in verdict.scope


def test_dropped_rewritten_and_replaced_rows_are_rejected(tmp_path):
    witness = held(tmp_path)
    dropped = document()
    dropped["decisions"].pop()
    v = W.verify_against_witness(dropped, witness)
    assert not v.ok and v.reasons == [W.CODE_SHRUNK] and v.findings[0]["ledger"] == "decisions"
    rewritten = document()
    rewritten["refusals"][0]["reasons"] = ["status_unreadable"]
    v = W.verify_against_witness(rewritten, witness)
    assert not v.ok and v.reasons == [W.CODE_HEAD_MISMATCH]
    replaced = document()
    replaced["decisions"].pop(0)
    replaced["decisions"].append({"decision_id": "forged"})
    assert W.verify_against_witness(replaced, witness).reasons == [W.CODE_HEAD_MISMATCH]
    emptied = document()
    emptied.pop("refusals")                                  # a ledger that disappears counts as emptied
    assert W.verify_against_witness(emptied, witness).reasons == [W.CODE_SHRUNK]


def test_other_run_and_empty_witness_are_not_a_pass(tmp_path):
    witness = held(tmp_path)
    other = {**document(), "run_id": "run-2"}
    assert W.verify_against_witness(other, witness).reasons == [W.CODE_RUN_MISMATCH]
    empty = W.LocalFileWitness(tmp_path / "empty.jsonl")
    v = W.verify_against_witness(document(), empty)
    assert not v.ok and v.reasons == [W.CODE_NO_DIGEST]


def test_every_held_digest_is_checked(tmp_path):
    doc = document()
    witness = held(tmp_path, doc)
    grown = copy.deepcopy(doc)
    grown["decisions"].append({"decision_id": "d3"})
    W.publish_head(grown, witness)
    rewritten_early = copy.deepcopy(grown)
    rewritten_early["decisions"][0]["decision_id"] = "x"
    v = W.verify_against_witness(rewritten_early, witness)
    assert not v.ok and {f["sequence"] for f in v.findings} == {0, 1}


def test_publish_is_append_only_and_refuses_a_rewrite(tmp_path):
    witness = held(tmp_path)
    rewritten = document()
    rewritten["refusals"][0]["reasons"] = ["x"]
    with pytest.raises(W.WitnessRefused):
        W.publish_head(rewritten, witness)
    assert len(witness.history()) == 1
    # the witness itself refuses a record that does not extend its chain, whatever the publisher did
    forged = W.make_record(rewritten)                         # sequence 0 again
    with pytest.raises(W.WitnessRefused) as exc:
        witness.publish(forged)
    assert exc.value.code == W.CODE_CHAIN_INVALID
    shrunk = W.make_record({**document(), "decisions": [{"decision_id": "d1"}]}, previous=witness.latest())
    with pytest.raises(W.WitnessRefused):
        witness.publish(shrunk)                               # covers fewer rows than the record before it


def test_witness_chain_tampering_is_reported(tmp_path):
    witness = held(tmp_path)
    lines = (tmp_path / "w.jsonl").read_text().splitlines()
    record = json.loads(lines[0])
    record["ledgers"]["decisions"]["count"] = 1               # digest no longer recomputes
    (tmp_path / "w.jsonl").write_text(json.dumps(record) + "\n")
    v = W.verify_against_witness(document(), witness)
    assert not v.ok and W.CODE_CHAIN_INVALID in v.reasons


def test_witness_holder_limit_a_rewritten_witness_matching_a_tampered_set_verifies(tmp_path):
    """Stated limit: whoever controls the witness can substitute a chain that matches a tampered set."""
    tampered = document()
    tampered["refusals"] = []
    substitute = W.LocalFileWitness(tmp_path / "substitute.jsonl")
    substitute.publish(W.make_record(tampered))
    assert W.verify_against_witness(tampered, substitute).ok
    assert not W.verify_against_witness(tampered, held(tmp_path)).ok     # an independent copy of the original digest catches it


def test_real_bounded_store_document_round_trips(tmp_path):
    store = BoundedRecordStore(tmp_path / "run.json", "run-1")
    witness = W.LocalFileWitness(tmp_path / "w.jsonl")
    W.publish_head(store.path, witness)                       # a path is read as a record document
    assert W.verify_against_witness(store.path, witness).ok
    assert W.verify_against_witness(store.load(), witness).ok  # and so is the validated model


def test_cli_digest_publish_verify(tmp_path, capsys):
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(document()))
    wfile = str(tmp_path / "w.jsonl")
    assert acp_main(["witness", "digest", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["run_id"] == "run-1"
    assert acp_main(["witness", "verify", str(path), "--witness", wfile]) == 1       # nothing held yet
    capsys.readouterr()
    assert acp_main(["witness", "publish", str(path), "--witness", wfile]) == 0
    assert acp_main(["witness", "verify", str(path), "--witness", wfile]) == 0
    capsys.readouterr()
    tampered = document()
    tampered["decisions"].pop()
    path.write_text(json.dumps(tampered))
    assert acp_main(["witness", "verify", str(path), "--witness", wfile]) == 1
    assert json.loads(capsys.readouterr().out)["reasons"] == [W.CODE_SHRUNK]
    assert acp_main(["witness", "publish", str(path), "--witness", wfile]) == 1      # refused to publish over a drop
    assert acp_main(["witness", "verify", str(tmp_path / "missing.json"), "--witness", wfile]) == 2


def test_module_makes_no_network_or_publication_call():
    import ast
    import pathlib
    tree = ast.parse(pathlib.Path(W.__file__).read_text(encoding="utf-8"))
    imported = {n.names[0].name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import)} | \
               {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"socket", "urllib", "http", "requests", "subprocess", "ssl", "smtplib"}
