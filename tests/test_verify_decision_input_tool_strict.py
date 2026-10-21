"""tools/verify_decision_input_commitment.py reads its record strictly (scan 3, DIP-1): a duplicate member is refused, not last-wins."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
TOOL = ROOT / "tools" / "verify_decision_input_commitment.py"
BASELINE = json.loads((ROOT / "conformance" / "decision-input-commitment-vectors.json").read_text())["baseline_record"]


def _run(tmp_path, data: bytes):
    path = tmp_path / "record.json"
    path.write_bytes(data)
    done = subprocess.run([sys.executable, "-I", str(TOOL), str(path)], capture_output=True, text=True, cwd=tmp_path)
    return done.returncode, json.loads(done.stdout)


def test_baseline_record_still_verifies(tmp_path):
    code, out = _run(tmp_path, json.dumps(BASELINE, sort_keys=True).encode())
    assert code == 0 and out["valid"] is True


def test_duplicate_member_is_refused_not_last_wins(tmp_path):
    text = json.dumps(BASELINE, sort_keys=True)
    dup = text.replace('"decision": {', '"decision": {"result": "deny", ', 1)  # a second "result" member inside decision
    assert dup.count('"result"') > text.count('"result"')
    code, out = _run(tmp_path, dup.encode())
    assert code == 2 and out["valid"] is False and out["code"] == "INPUT_INVALID"
    assert "input_json_duplicate_member" in out["message"]


@pytest.mark.parametrize("data", [b'{"a": NaN}', b'{"a": 1e999}', b"\xff\xfe", b'{"a": 1'])
def test_other_non_strict_input_is_refused(tmp_path, data):
    code, out = _run(tmp_path, data)
    assert code == 2 and out["code"] == "INPUT_INVALID"
