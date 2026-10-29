"""D-07 mutation harness (DEVELOPER evidence; not independent qualification).

Copies src/, schemas/, tests/ and pyproject.toml of this worktree into a scratch directory, applies ONE mutant to the copy (never to the
worktree), and runs the D-07 test set against it. A mutant is KILLED if any test fails. Behavioral kills are measured with the two static
pins deselected (byte pin and AST pin), so the static pins cannot hide a behavioural gap; the static pins are then run on their own.
Usage: python docs/evidence/d07/mutation_harness.py <python> <registry-pin-dir> <scratch-dir> <out.json> [mutant-id ...]
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
RA, BD = "src/agent_control_plane/runtime_authority.py", "src/agent_control_plane/bounded.py"
ANCHOR_OLD = '''                from .bounded import _FRESH_DEADLINES
                collector = _FRESH_DEADLINES.get()
                if collector is not None and cl is not None:
                    anchor_bound = int(extra["age_bound_seconds"]) if extra is not None else cl.max_status_age_seconds
                    collector.append(_parse(observed.observed_at) + timedelta(seconds=anchor_bound))
'''
RESTORED_GUARD = '''                if binding is not None:
                    from .bounded import _FRESH_DEADLINES
                    collector = _FRESH_DEADLINES.get()
                    if collector is not None and cl is not None:
                        anchor_bound = int(extra["age_bound_seconds"]) if extra is not None else cl.max_status_age_seconds
                        collector.append(_parse(observed.observed_at) + timedelta(seconds=anchor_bound))
'''
MUTANTS = [
    ("M01", "restore the PolicyBinding guard (the original defect)", RA, ANCHOR_OLD, RESTORED_GUARD),
    ("M02", "anchor only the live observation, not the cached snapshot", RA, "if collector is not None and cl is not None:\n                    anchor_bound",
     "if collector is not None and cl is not None and extra is None:\n                    anchor_bound"),
    ("M03", "anchor only the cached snapshot, not the live observation", RA, "if collector is not None and cl is not None:\n                    anchor_bound",
     "if collector is not None and cl is not None and extra is not None:\n                    anchor_bound"),
    ("M04", "drop the cached recorded bound (always the class bound)", RA, 'int(extra["age_bound_seconds"]) if extra is not None else cl.max_status_age_seconds',
     "cl.max_status_age_seconds"),
    ("M05", "anchor bound off by +1 s", RA, "timedelta(seconds=anchor_bound))\n", "timedelta(seconds=anchor_bound + 1))\n"),
    ("M06", "anchor at observed_at (bound forgotten)", RA, "collector.append(_parse(observed.observed_at) + timedelta(seconds=anchor_bound))",
     "collector.append(_parse(observed.observed_at))"),
    ("M07", "anchor bound doubled", RA, "timedelta(seconds=anchor_bound))\n", "timedelta(seconds=2 * anchor_bound))\n"),
    ("M08", "anchor a live observation with an extension-sized bound (+60 s)", RA, "else cl.max_status_age_seconds\n", "else cl.max_status_age_seconds + 60\n"),
    ("M09", "max instead of min over the collected anchors", BD, "earliest = min(anchors)", "earliest = max(anchors)"),
    ("M10", "invert the anchor-flag test (collector only when the flag is False)", BD,
     "anchors = [] if (fr is not None and fr.anchor_deadline_to_inputs) else None", "anchors = [] if (fr is not None and not fr.anchor_deadline_to_inputs) else None"),
    ("M11", "flag ignored: collector whenever a freshness profile exists", BD,
     "anchors = [] if (fr is not None and fr.anchor_deadline_to_inputs) else None", "anchors = [] if fr is not None else None"),
    ("M12", "strict boundary becomes inclusive (now >= deadline)", BD, "if now > _fparse(deadline):\n            return deadline", "if now >= _fparse(deadline):\n            return deadline"),
    ("M13", "the later of opening deadline and anchored deadline wins", BD, "if later is not None and _fparse(later) < _fparse(deadline):",
     "if later is not None and _fparse(later) > _fparse(deadline):"),
    ("M14", "anchored deadline never replaces the opening deadline", BD, 'if earliest < _fparse(clocks["deadline"]):', 'if earliest > _fparse(clocks["deadline"]):'),
    ("M15", "monotonic allowance not tightened to the anchored window", BD, "self._mono_open[check_id] = (mono[0], min(mono[1], remaining))",
     "self._mono_open[check_id] = (mono[0], mono[1])"),
    ("M16", "cached snapshot records an extension-sized bound (+60 s)", BD, '"age_bound_seconds": str(bound), "reversibility"', '"age_bound_seconds": str(bound + 60), "reversibility"'),
]
STATIC = ["tests/test_freshness_purpose_anchor_successor.py::test_d07_only_runtime_authority_changed_among_the_protected_evaluators",
          "tests/test_freshness_purpose_anchor_successor.py::test_d07_the_deadline_registration_is_no_longer_guarded_by_the_policy_binding",
          "tests/test_governed_policy_composition.py"]
FILES = ["tests/test_freshness_purpose_anchor_successor.py", "tests/test_freshness_purpose_residual.py",
         "tests/test_policy_binding_approval_generation.py", "tests/test_freshness.py"]


def run(py, pin, work, args):
    env = dict(os.environ, PYTHONPATH="src:.", OCS_REGISTRY_PIN_DIR=pin, OCS_REQUIRE_REGISTRY_PIN="1")
    p = subprocess.run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", "-rf", *args], cwd=work, env=env, capture_output=True, text=True)
    lines = [x for x in p.stdout.splitlines() if x.startswith("FAILED")]
    return p.returncode, lines[:3], p.stdout.splitlines()[-1] if p.stdout else ""


def main():
    py, pin, scratch, out = sys.argv[1:5]
    only = set(sys.argv[5:])
    results = []
    for mid, desc, rel, old, new in MUTANTS:
        if only and mid not in only:
            continue
        work = pathlib.Path(scratch) / mid
        shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        for d in ("src", "schemas", "tests"):
            shutil.copytree(ROOT / d, work / d)
        shutil.copy(ROOT / "pyproject.toml", work / "pyproject.toml")
        target = work / rel
        text = target.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{mid}: pattern must occur exactly once in {rel}, found {text.count(old)}"
        target.write_text(text.replace(old, new), encoding="utf-8")
        deselect = [f"--deselect={s}" for s in STATIC[:2]] + ["--deselect=tests/test_governed_policy_composition.py"]
        rc, failed, tail = run(py, pin, work, FILES + deselect)
        rc_static, failed_static, _ = run(py, pin, work, [STATIC[0], STATIC[1]])
        results.append({"id": mid, "description": desc, "file": rel, "behavioral": "KILLED" if rc else "SURVIVED", "first_failures": failed, "summary": tail,
                        "static_pins": "caught" if rc_static else "not caught"})
        print(json.dumps(results[-1]), flush=True)
        shutil.rmtree(work, ignore_errors=True)
    pathlib.Path(out).write_text(json.dumps(results, indent=1) + "\n", encoding="utf-8")


main()
