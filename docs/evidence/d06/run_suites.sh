#!/bin/bash
# Developer evidence runner (BUILDER_TESTED; not independent qualification).
# usage: run_suites.sh <repo-root> <out-prefix>
# Env: SCRATCH (scratchpad root), PY (python). Registry pins: pin_v7 for most suites; regpin (6f600ab) for the two older-pin suites.
S=${SCRATCH:?}; PY=${PY:?}; R=$1; O=$2
cd "$R" || exit 1
export PYTHONPATH=src:. OCS_REQUIRE_REGISTRY_PIN=1
OCS_REGISTRY_PIN_DIR=$S/m12/regpin $PY -m pytest -q -p no:cacheprovider -rfEs tests/test_f4_age_governance.py tests/test_f5_class_age_governance.py > "$O-oldpin.log" 2>&1
echo "exit $?" >> "$O-oldpin.log"
OCS_REGISTRY_PIN_DIR=$S/m12/pin_v7 $PY -m pytest -q -p no:cacheprovider -rfEs \
  tests/test_governed_policy_composition.py tests/test_f5_class_unreadable_governance.py tests/test_irreversibility_governance.py tests/test_irreversibility_unit.py \
  tests/test_revocation_families_governance.py tests/test_authorization_pin_export.py tests/test_bounded_authorization.py tests/test_runtime_authority.py \
  tests/test_local_authority_effect_profile.py tests/test_policy_binding_approval_generation.py $(ls tests/test_effective_configuration_binding*.py 2>/dev/null) > "$O-v7pin.log" 2>&1
echo "exit $?" >> "$O-v7pin.log"
