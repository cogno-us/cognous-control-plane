#!/usr/bin/env python3
"""Validate one proposed Decision Input Commitment Record.

This tool checks only the proposed sidecar profile. Success is not proof that
current Control Plane runtime enforcement implements the profile, that a source
was authenticated, or that an external assertion is true.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path


def _load_module(name: str, filename: str):
    module_path = Path(__file__).parents[1] / "src" / "agent_control_plane" / filename
    spec = importlib.util.spec_from_file_location(name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_profile():
    return _load_module("decision_input_profile", "decision_input_profile.py")


def _load_strict_json():
    # strict_json is a leaf module (it imports nothing from the package), so it loads by path like the profile does.
    return _load_module("_acp_strict_json", "strict_json.py")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record", type=Path, help="JSON file containing one proposed-profile record")
    args = parser.parse_args()
    profile = _load_profile()
    strict_json = _load_strict_json()
    try:
        # Strict read: UTF-8 only, a duplicate object member, NaN/Infinity and an unpaired surrogate are refused, not last-wins.
        record = strict_json.strict_loads(args.record.read_bytes())
        result = profile.verify_record(record)
    except profile.ProfileValidationError as exc:
        print(json.dumps({"valid": False, "code": exc.code, "message": str(exc)}, sort_keys=True))
        return 1
    except (OSError, ValueError, RecursionError) as exc:  # includes json.JSONDecodeError and the strict refusals
        print(json.dumps({"valid": False, "code": "INPUT_INVALID", "message": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
