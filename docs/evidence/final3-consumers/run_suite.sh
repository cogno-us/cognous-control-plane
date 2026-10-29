#!/bin/bash
# Developer runner (not a qualification). Usage: run_suite.sh <worktree> <python> <scratch>
# Group A: everything except the pin-6f600ab files and the r08-v8-only FINAL3 files, against the r08-v7 pin (the baseline pattern of docs/evidence/d07/run_suite.sh).
# Group B: F4 and F5 class-age governance against 6f600ab. Group C: the whole suite (except the 6f600ab files) against the r08-v8 pin, which also runs the FINAL3 files.
W=$1; PY=$2; S=$3
cd "$W"; export PYTHONPATH=src:. OCS_REQUIRE_REGISTRY_PIN=1
echo "### group A (OCS_REGISTRY_PIN_DIR=pin_v7)"
OCS_REGISTRY_PIN_DIR=$S/pin_v7 $PY -m pytest -q -rf -p no:cacheprovider tests --ignore=tests/test_f4_age_governance.py --ignore=tests/test_f5_class_age_governance.py --ignore=tests/test_final3_anchor.py --ignore=tests/test_final3_observation.py --ignore=tests/test_final3_composed_binding.py 2>&1
echo "### group B (OCS_REGISTRY_PIN_DIR=regpin @6f600ab)"
OCS_REGISTRY_PIN_DIR=$S/regpin $PY -m pytest -q -p no:cacheprovider tests/test_f4_age_governance.py tests/test_f5_class_age_governance.py 2>&1
echo "### group C (OCS_REGISTRY_PIN_DIR=pin_v8 @a40fe75: whole suite incl. FINAL3)"
OCS_REGISTRY_PIN_DIR=$S/pin_v8 $PY -m pytest -q -rf -p no:cacheprovider tests --ignore=tests/test_f4_age_governance.py --ignore=tests/test_f5_class_age_governance.py 2>&1
