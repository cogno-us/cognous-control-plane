#!/bin/bash
# Developer runner (not a qualification): runs each junit-gated step of .github/workflows/tests.yml locally, exactly as the workflow names the pin, files and pytest args.
# Usage: run_gates.sh <worktree> <python> <ci_pins_dir> <outdir>      (prints "<step>: n run, skipped, failed" per gate; thresholds are in the workflow)
W=$1; PY=$2; PINS=$3; OUT=$4; mkdir -p "$OUT"; cd "$W"; export PYTHONPATH=src:. OCS_REQUIRE_REGISTRY_PIN=1
gate() { # name pin files...
  name=$1; pin=$2; shift 2
  OCS_REGISTRY_PIN_DIR=$PINS/$pin $PY -m pytest -q -p no:cacheprovider "$@" --junitxml=$OUT/$name.xml > $OUT/$name.log 2>&1
  $PY - "$OUT/$name.xml" "$name" <<'PY'
import sys, xml.etree.ElementTree as ET
suite = ET.parse(sys.argv[1]).getroot(); suite = suite if suite.tag == "testsuite" else suite[0]
print(f"{sys.argv[2]}: {suite.get('tests')} run, {suite.get('skipped')} skipped, {int(suite.get('failures')) + int(suite.get('errors'))} failed")
PY
}
gate f4        6f600ab tests/test_f4_age_governance.py
gate f5age     6f600ab tests/test_f5_class_age_governance.py
gate unreadable 6c3e5e4 tests/test_f5_class_unreadable_governance.py
gate composed  6c3e5e4 tests/test_governed_policy_composition.py
gate revocation 42a6663 tests/test_revocation_families_governance.py tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py
gate irreversibility b73c59e tests/test_irreversibility_governance.py tests/test_irreversibility_unit.py tests/test_revocation_families_governance.py tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py
# NEW gate (this work package): the FINAL3 consumer tests, plus every earlier governed suite re-run unchanged under the r08-v8 pin (r08-v1..v7 behaviour unchanged).
gate final3 a40fe75 tests/test_final3_anchor.py tests/test_final3_observation.py tests/test_final3_composed_binding.py tests/test_irreversibility_governance.py tests/test_irreversibility_unit.py tests/test_revocation_families_governance.py tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py
