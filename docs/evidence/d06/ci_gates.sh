#!/bin/bash
# Local reproduction of the gated steps of .github/workflows/tests.yml (same pytest args, pins, env and junit gate script). Developer evidence; not CI.
# usage: ci_gates.sh <repo-root> <out-dir> ; env PY (python with PyNaCl), PINS (dir holding 6f600ab 6c3e5e4 42a6663 b73c59e worktrees)
R=$1; O=$2; export PYTHONPATH=src:.; mkdir -p "$O"; cd "$R" || exit 1
gate() { # name pin min files...
  local name=$1 pin=$2 min=$3; shift 3
  OCS_REGISTRY_PIN_DIR=$PINS/$pin OCS_REQUIRE_REGISTRY_PIN=1 $PY -m pytest -q "$@" --junitxml="$O/$name.xml" > "$O/$name.txt" 2>&1
  $PY - "$O/$name.xml" "$min" "$name" >> "$O/$name.txt" <<'PYG'
import sys, xml.etree.ElementTree as ET
suite = ET.parse(sys.argv[1]).getroot(); suite = suite if suite.tag == "testsuite" else suite[0]
n, skipped, failed = int(suite.get("tests")), int(suite.get("skipped")), int(suite.get("failures")) + int(suite.get("errors"))
ok = skipped == 0 and failed == 0 and n >= int(sys.argv[2])
print(f"GATE {sys.argv[3]}: {n} run, {skipped} skipped, {failed} failed (minimum {sys.argv[2]}) -> {'PASS' if ok else 'FAIL'}")
PYG
  tail -n 1 "$O/$name.txt"
}
gate f4 6f600ab 70 tests/test_f4_age_governance.py
gate f5-class-age 6f600ab 105 tests/test_f5_class_age_governance.py
gate f5-unreadable 6c3e5e4 148 tests/test_f5_class_unreadable_governance.py
gate governed-policy 6c3e5e4 99 tests/test_governed_policy_composition.py
gate revocation-families 42a6663 388 tests/test_revocation_families_governance.py tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py
gate irreversibility b73c59e 576 tests/test_irreversibility_governance.py tests/test_irreversibility_unit.py tests/test_revocation_families_governance.py tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py
# plain `pytest` step: no pin env
env -u OCS_REGISTRY_PIN_DIR -u OCS_REQUIRE_REGISTRY_PIN $PY -m pytest > "$O/plain.txt" 2>&1; echo "plain pytest exit $?" >> "$O/plain.txt"; tail -n 2 "$O/plain.txt"
$PY tools/adversarial_mutations.py > "$O/removal-probes.txt" 2>&1; echo "removal probes exit $?" >> "$O/removal-probes.txt"; tail -n 2 "$O/removal-probes.txt"
