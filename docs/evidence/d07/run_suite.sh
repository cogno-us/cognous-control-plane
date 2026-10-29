#!/bin/bash
# Developer runner (not a qualification). Usage: run_suite.sh <worktree> <python> <scratch> <outdir-prefix>
# Pin-specific suites need their own Registry checkout (each test file hard-codes its exact pin); the rest run against the r08-v7 pin.
W=$1; PY=$2; S=$3; OUT=$4
cd "$W"; export PYTHONPATH=src:. OCS_REQUIRE_REGISTRY_PIN=1
echo "### group A: everything except the pin-6f600ab files (OCS_REGISTRY_PIN_DIR=pin_v7)"
OCS_REGISTRY_PIN_DIR=$S/pin_v7 $PY -m pytest -q -rf -p no:cacheprovider tests --ignore=tests/test_f4_age_governance.py --ignore=tests/test_f5_class_age_governance.py 2>&1
echo "### group B: f4/f5 class age governance (OCS_REGISTRY_PIN_DIR=regpin @6f600ab)"
OCS_REGISTRY_PIN_DIR=$S/regpin $PY -m pytest -q -p no:cacheprovider tests/test_f4_age_governance.py tests/test_f5_class_age_governance.py 2>&1
