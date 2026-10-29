#!/bin/bash
# Whole-suite run of the r7_cp branch on Python 3.12 and 3.11 (same venvs as the main baseline ../ev_r/cp-full-main-3.1[12].log); also the #92 head (r6_cp) for classification.
S=/tmp/claude-0/-home-claude/139dd095-4028-5533-a993-4a7fc4b564f0/scratchpad
R=$S/m12/r7_cp
EV=$R/docs/workstreams/effective-policy-irreversibility/evidence
mkdir -p $EV
for v in 3.12 3.11; do
  (cd $R && git rev-parse HEAD > $EV/cp-full-branch-$v.head; PYTHONPATH=$R/src:$R $S/venv-cp$v/bin/python -m pytest -q -p no:cacheprovider -ra --maxfail=100000 > $EV/cp-full-branch-$v.log 2>&1)
  $S/venv-cp$v/bin/python -m pip freeze > $EV/cp-freeze-$v.txt 2>/dev/null
done
echo done > $S/m12/ev_r/branch7.done
