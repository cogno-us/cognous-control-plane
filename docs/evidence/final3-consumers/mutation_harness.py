"""Mutation harness for the FINAL3 consumers (developer evidence only; NOT independent qualification).

Each mutant is applied to a SCRATCH COPY of the repository (never to the working tree) and the three tests/test_final3_*.py files are run with `-x`. A mutant is
  KILLED   when the run fails (non-zero exit),
  SURVIVED when every test passes (reported honestly, with the reason where it is an equivalent mutant),
  INVALID  when the mutation text did not apply exactly once (a harness defect, never counted as killed).
A CONTROL run of the unmutated copy must pass first (the copy has no .git, so `test_f03` -- which reads git -- is deselected in the copy and is covered by the real runs).
Usage:  python mutation_harness.py <repo-root> <out-dir> [mutant-id ...]      env: OCS_REGISTRY_PIN_DIR (the r08-v8 pin), OCS_REQUIRE_REGISTRY_PIN=1.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

F3 = "src/agent_control_plane/registry_final3_governance.py"
POL = "src/agent_control_plane/registry_governed_policy.py"
EFF = "src/agent_control_plane/registry_effective_policy.py"
LIFE = "src/agent_control_plane/registry_governed_lifecycle.py"
TESTS = ["tests/test_final3_anchor.py", "tests/test_final3_observation.py", "tests/test_final3_composed_binding.py"]
M = []


def mut(mid, desc, file, old, new, equivalent=None, also=None):
    M.append(dict(id=mid, desc=desc, file=file, old=old, new=new, equivalent=equivalent, also=also))


# ---------------------------------------------------------------- anchor family (module)
mut("anchor-missing-freshness-treated-as-no_change", "a host without a FreshnessProfile is read as `no_change` instead of refused", F3,
    "    if freshness is None:\n        return None, HOST_FRESHNESS_MISSING\n", "    if freshness is None:\n        return NO_CHANGE, None\n")
mut("anchor-invents-a-freshness-profile", "compose_anchor creates a FreshnessProfile when the host has none (and the precondition is dropped)", F3,
    '        if freshness is None:\n            raise ValueError(HOST_FRESHNESS_MISSING)\n', '        if freshness is None:\n            freshness = doc["freshness"] = {"version": "freshness/0.1"}\n',
    also=dict(file=F3, old="    if freshness is None:\n        return None, HOST_FRESHNESS_MISSING\n", new="    if freshness is None:\n        return NO_CHANGE, None\n"))
mut("anchor-compose-can-clear-the-flag", "compose_anchor writes the effective value either way (True -> False possible)", F3,
    '    if effective[FIELD_ANCHOR] == ANCHOR:\n        freshness = doc.get("freshness")\n        if freshness is None:\n            raise ValueError(HOST_FRESHNESS_MISSING)\n        freshness["anchor_deadline_to_inputs"] = True\n',
    '    if True:\n        freshness = doc.get("freshness")\n        if freshness is None:\n            raise ValueError(HOST_FRESHNESS_MISSING)\n        freshness["anchor_deadline_to_inputs"] = effective[FIELD_ANCHOR] == ANCHOR\n')
mut("anchor-rank-inverted", "no_change is treated as stricter than anchor", F3, "_RANK_ANCHOR = {ANCHOR: 0, NO_CHANGE: 1}", "_RANK_ANCHOR = {ANCHOR: 1, NO_CHANGE: 0}")
mut("anchor-skip-registry-record-check", "the second strict parse of the Registry record is not compared", F3,
    '    if not _anchor_value(registry) or effective != stricter_anchor(host_value, registry):\n        return None, Refusal("effective_policy_invalid", None, kind)\n', "")
mut("anchor-skip-widening-check", "an effective value looser than the host is not refused in the derivation", F3,
    '    if _RANK_ANCHOR[effective] > _RANK_ANCHOR[host_value]:\n        return None, Refusal("effective_policy_widens_host", None, kind)\n', "")
mut("anchor-caller-always-no_change", "the caller handed to the Registry always says no_change", F3, "{FIELD_ANCHOR: host_value}, material, verifier, now)", "{FIELD_ANCHOR: NO_CHANGE}, material, verifier, now)",
    equivalent="expected equivalent for host False; for host True the Registry composes anchor if EITHER side is anchor and the consumer's second strict parse recomputes stricter(host, record)")
# ---------------------------------------------------------------- observation families (module)
mut("obs-effective-uses-max", "the consumer expects max(host, registry) instead of min", F3, "effective != min(host_value, registry)", "effective != max(host_value, registry)")
mut("obs-skip-min-check", "the consumer does not re-derive min(host, registry)", F3,
    '    if not _int_in(registry, lowest) or effective != min(host_value, registry):\n        return None, Refusal("effective_policy_invalid", None, kind)\n', "")
mut("obs-skip-widening-check", "an effective value above the host is not refused in the derivation", F3,
    '    if effective > host_value:\n        return None, Refusal("effective_policy_widens_host", None, kind)\n', "",
    equivalent="partly redundant with the final composition check (observation_defect); a forged value above the host is still refused there (test_g02/g03 use the layers separately)")
mut("obs-synthesize-missing-policy", "a missing host ObservationPolicy is replaced by a default instead of refused", F3,
    "    if policy is None:\n        return None, HOST_OBS_MISSING\n", "    if policy is None:\n        return {\"max_age_seconds\": 300, \"clock_tolerance_seconds\": 5}, None\n")
mut("obs-skip-original-host-validation", "the original host policy values are not range/type checked", F3,
    '    if not _int_in(values["max_age_seconds"], 1) or not _int_in(values["clock_tolerance_seconds"], 0):\n        return None, HOST_OBS_INVALID\n', "")
mut("obs-host-policy-subclass-allowed", "a subclass or non-ObservationPolicy host object is accepted", F3,
    "    if type(policy) is not ObservationPolicy:\n        return None, HOST_OBS_INVALID\n", "")
mut("obs-token-range-off-by-one", "the structural upper range excludes 2147483647", F3, "return type(v) is int and lo <= v <= TOKEN_MAX", "return type(v) is int and lo <= v < TOKEN_MAX")
mut("obs-tolerance-floor-one", "tolerance 0 is not admitted", F3, 'FAMILY_OBS_TOL: ("clock_tolerance_seconds", 0),', 'FAMILY_OBS_TOL: ("clock_tolerance_seconds", 1),')
mut("obs-age-floor-zero", "max age 0 is admitted", F3, 'FAMILY_OBS_AGE: ("max_age_seconds", 1),', 'FAMILY_OBS_AGE: ("max_age_seconds", 0),')
mut("obs-bool-allowed", "a bool passes the exact-int rule", F3, "return type(v) is int and lo <= v <= TOKEN_MAX", "return isinstance(v, int) and lo <= v <= TOKEN_MAX")
mut("obs-defect-allows-equal-plus-one", "the final check lets a value exceed the host by one", F3, "        if final[attr] > host[attr]:\n", "        if final[attr] > host[attr] + 1:\n")
mut("obs-defect-skips-undeclared-equality", "an undeclared field may differ from the host", F3,
    '        if not declared[attr] and final[attr] != host[attr]:\n            return "composed_observation_invalid"\n', "")
mut("obs-defect-skips-range", "the final check does not re-check exact ints / range", F3,
    '    if not _int_in(final["max_age_seconds"], 1) or not _int_in(final["clock_tolerance_seconds"], 0):\n        return "composed_observation_invalid"\n', "")
mut("obs-effective-uses-host-for-declared", "the effective policy keeps the host value of a declared field", F3, "            out[attr] = slot[0][_MEMBER[family]]\n", "            pass\n")
mut("obs-table-swapped-members", "max-age and tolerance members are swapped", F3, 'FIELD_OBS_AGE = "observation_max_age_seconds"', 'FIELD_OBS_AGE = "observation_clock_tolerance_seconds"')
mut("obs-alias-to-constructor-tolerance", "the tolerance member name is the held constructor name", F3, 'FIELD_OBS_TOL = "observation_clock_tolerance_seconds"', 'FIELD_OBS_TOL = "clock_tolerance_seconds"')
mut("contract-version-v7", "the consumer asks the Registry identity for r08-v7", F3, 'CONTRACT_V8 = "r08-v8"', 'CONTRACT_V8 = "r08-v7"')
mut("schema-revision-check-dropped", "the family schema revision is not read from the Registry table", F3,
    "        if identity.registered_family_version(family, CONTRACT_V8) != FAMILY_SCHEMA_REVISION:\n            return None, Refusal(\"effective_policy_digest_unavailable\", None, kind)\n", "",
    equivalent="expected equivalent: the Registry digest preimage itself carries the revision; the local check is defence in depth")
mut("verified-skips-verifier-admission", "any verifier object is accepted", F3, '    if type(verifier) is not verifier_cls:\n        return None, Refusal("verifier_not_admitted")\n', "")
mut("verified-skips-deny-all-check", "a deny_all decision is not refused", F3, 'if kind != "applied" or decision.deny_all is not False:', 'if kind != "applied":')
mut("verified-skips-operational-check", "operationally_authorized is not checked", F3, " or decision.operationally_authorized is not False:\n        return None, Refusal(\"registry_decision_invalid\")",
    ":\n        return None, Refusal(\"registry_decision_invalid\")")
mut("verified-wrong-consumer-in-context", "the Registry context uses the tenant as consumer", F3, "ExpectedContext(scope.consumer_id, scope.tenant_id,", "ExpectedContext(scope.tenant_id, scope.tenant_id,")
mut("verified-participation-optional", "participation `optional` instead of `required`", F3, 'verify_and_decide_v8("required",', 'verify_and_decide_v8("optional",',
    equivalent="expected equivalent: every optional-participation refusal is `overlay_not_applied`, which this module refuses as `registry_not_applied`")
# ---------------------------------------------------------------- composed workflow wiring
mut("pol-anchor-not-profile-bearing", "anchor does not count as a profile-bearing family (profile may be absent)", POL, " or families.class_irreversible is not None or families.anchor_deadline is not None)", " or families.class_irreversible is not None)")
mut("pol-policy-binding-lifted-for-anchor", "the policy_binding refusal is lifted when the anchor family is declared", POL,
    "            if profile_families and host.policy_binding is not None:", "            if profile_families and host.policy_binding is not None and families.anchor_deadline is None:")
mut("pol-anchor-precondition-dropped", "the construction-time anchor host precondition is dropped", POL,
    '            host_anchor, code = f3mod.host_anchor_value(host)\n            if host_anchor is None:\n                raise _refuse(code, "construction")\n',
    '            host_anchor = f3mod.NO_CHANGE\n', equivalent="expected equivalent: derive_anchor re-checks the precondition (after the source read); the tests also pin 'no source read'")
mut("pol-observation-precondition-dropped", "the construction-time host observation precondition is dropped", POL,
    '            host_observation, code = f3mod.host_observation_values(workflow_kwargs.get("observation_policy"))\n            if host_observation is None:\n                raise _refuse(code, "construction")\n',
    '            host_observation = {"max_age_seconds": 300, "clock_tolerance_seconds": 5}\n')
mut("pol-effective-policy-not-passed-to-bounded", "the host ObservationPolicy (not the effective one) is given to the bounded workflow", POL,
    '            workflow_kwargs["observation_policy"] = ObservationPolicy(**effective_obs)\n', "            pass\n")
mut("pol-ctor-tolerance-narrowed", "the observation tolerance is also applied to the constructor clock_tolerance_seconds", POL,
    '            workflow_kwargs["observation_policy"] = ObservationPolicy(**effective_obs)\n',
    '            workflow_kwargs["observation_policy"] = ObservationPolicy(**effective_obs)\n            workflow_kwargs["clock_tolerance_seconds"] = effective_obs["clock_tolerance_seconds"]\n')
mut("pol-obs-final-validation-skipped", "the final observation validation is skipped", POL, "        if defect is not None:\n            return None, Refusal(defect)\n    pdigest", "        pass\n    pdigest")
mut("pol-profile-final-validation-skipped", "the final profile validation result is ignored", POL,
    "    defect = final_composition_defect(host, base, host_scalars,", "    defect = None and final_composition_defect(host, base, host_scalars,")
mut("pol-anchor-not-declared-in-final-validation", "the anchor carve-out is not passed to the final composition check", POL, ", anchor_declared=families.anchor_deadline is not None)", ")")
mut("pol-anchor-carveout-always-on", "the anchor flag may always differ (even when the family is not declared)", POL, "        if anchor_declared:  # the ONLY allowed difference", "        if True:  # the ONLY allowed difference")
mut("pol-anchor-widening-allowed", "True -> False passes the final composition check", POL,
    '            if fh.get("anchor_deadline_to_inputs", False) and not ff.get("anchor_deadline_to_inputs", False):\n                return "composed_widens_host"\n', "")
mut("pol-freshness-missing-not-checked-in-final", "the defence-in-depth host-freshness check in the final composition is dropped", POL,
    '    if anchor_declared and not dh.get("freshness"):  # the anchor family never invents a FreshnessProfile\n        return f3mod.HOST_FRESHNESS_MISSING\n', "")
mut("pol-name-order-anchor-last", "the three slots are ordered after terminal revocation", POL,
    '"class_irreversible", "anchor_deadline", "observation_max_age",\n                "observation_clock_tolerance", "terminal_revocation")', '"class_irreversible", "terminal_revocation", "anchor_deadline", "observation_max_age",\n                "observation_clock_tolerance")')
mut("pol-name-dropped-tolerance", "the tolerance slot is missing from the family names (declared but never governed)", POL, '"observation_max_age",\n                "observation_clock_tolerance", "terminal_revocation")', '"observation_max_age",\n                "terminal_revocation")')
mut("pol-swapped-observation-families", "max-age slot is verified as the tolerance family", POL, '("observation_max_age", f3mod.FAMILY_OBS_AGE, "max_age_seconds")', '("observation_max_age", f3mod.FAMILY_OBS_TOL, "max_age_seconds")')
mut("pol-observation-host-value-swapped", "the tolerance derivation is handed the host max age", POL, '("observation_clock_tolerance", f3mod.FAMILY_OBS_TOL, "clock_tolerance_seconds")', '("observation_clock_tolerance", f3mod.FAMILY_OBS_TOL, "max_age_seconds")')
mut("pol-held-observation-check-dropped", "the live ObservationPolicy is not compared with the bound effective one", POL,
    "        if self._gp_host_observation is not None:  # the LIVE ObservationPolicy must still be the bound effective one (not the host's)\n", "        if False:\n")
mut("pol-held-config-check-dropped", "the shared scalar guard is skipped for this workflow", POL, "        code = self._gl_config_defect()  # D-06 new coverage", "        code = None  # D-06 new coverage",
    equivalent="partly redundant: the dedicated observation guard fires first for the observation values; the constructor tolerance edit (test_c03) is caught only by the shared guard")
mut("pol-configuration-digest-without-new-host-values", "the activation-ledger configuration digest ignores the host anchor / observation values", POL,
    'configuration = commitment({"base": configuration, "host_anchor_deadline": host_anchor, "host_observation_policy": host_observation})', 'pass')
mut("pol-configuration-digest-wrap-always", "every configuration (even without the new families) gets the wrapped digest", POL,
    "        if families.anchor_deadline is not None or host_observation is not None:", "        if True:")
mut("pol-rederive-without-host-observation", "boundary re-derivation forgets the host observation values", POL,
    "host_irreversible=self._gp_host_irreversible, host_observation=self._gp_host_observation)", "host_irreversible=self._gp_host_irreversible)")
mut("pol-bound-slot-not-recorded", "the anchor part is not recorded in the bound identity", POL,
    'for slot, part in (("anchor_deadline", anchor), ("observation_max_age", obs_age), ("observation_clock_tolerance", obs_tol)):', 'for slot, part in (("observation_max_age", obs_age), ("observation_clock_tolerance", obs_tol)):')
mut("pol-profile-digest-ignores-anchor", "the effective-profile digest is not computed when only the anchor family is declared", POL,
    "(age_part or unreadable or assurance or irreversible or anchor or terminal)", "(age_part or unreadable or assurance or irreversible or terminal)")
# ---------------------------------------------------------------- tables, binding and snapshot
mut("eff-anchor-row-missing", "the anchor slot is missing from the family table (binding cannot represent it)", EFF, '    "anchor_deadline": ("f5-anchor-deadline-to-inputs-policy", "r08-v8"),\n', "")
mut("eff-anchor-contract-v7", "the anchor row names contract r08-v7", EFF, '("f5-anchor-deadline-to-inputs-policy", "r08-v8")', '("f5-anchor-deadline-to-inputs-policy", "r08-v7")')
mut("eff-age-family-id-typo", "the max-age row carries another family id", EFF, '("f5-observation-max-age-policy", "r08-v8")', '("f5-observation-age-policy", "r08-v8")')
mut("eff-tolerance-row-is-max-age", "the tolerance row carries the max-age family id", EFF, '("f5-observation-clock-tolerance-policy", "r08-v8")', '("f5-observation-max-age-policy", "r08-v8")')
mut("eff-schema-revision-2", "the anchor schema revision is 2", EFF, '"anchor_deadline": 1, "observation_max_age": 1', '"anchor_deadline": 2, "observation_max_age": 1')
mut("eff-schema-revision-missing", "no schema revision for the tolerance row", EFF, ', "observation_clock_tolerance": 1}', "}")
mut("eff-snapshot-drops-anchor", "the snapshot omits the anchor family", EFF, "        if part is None:\n            continue\n        family_id, contract = FAMILY_TABLE[slot]",
    '        if part is None or slot == "anchor_deadline":\n            continue\n        family_id, contract = FAMILY_TABLE[slot]')
mut("eff-resolve-without-host-observation", "the pure resolver forgets the host observation values", EFF, "                                         host_observation=host_observation)\n    if refusal", "                                         )\n    if refusal")
# ---------------------------------------------------------------- shared lifecycle (existing file): the new slots must reach every boundary
mut("life-commit-gate-skips-reverify", "the pre-apply commit gate does not re-verify", LIFE, '            self._gl_reverify("effect_commit", self._evaluation_time(_EXEC_NOW.get()))', "            pass")
mut("life-execute-entry-skips-reverify", "execute entry does not re-verify the selections", LIFE, "        self._gl_revalidate(proposal, \"effect\", entry_time)\n", "")
mut("life-decision-entry-skips-reverify", "decision entry does not re-verify the selections", LIFE, '        self._gl_revalidate(proposal, "decision", self._evaluation_time(now))\n', "")


def run(cmd, cwd, env, timeout):
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)


def main(root, out, only):
    root, out = Path(root).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH="src:.", OCS_REQUIRE_REGISTRY_PIN="1")
    cmd = [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "--deselect", "tests/test_final3_composed_binding.py::test_f03_the_protected_evaluators_are_byte_identical_to_the_integration_base", *TESTS]

    def scratch():
        d = Path(tempfile.mkdtemp(prefix="final3-mut-"))
        for name in ("src", "tests", "schemas"):
            shutil.copytree(root / name, d / name, ignore=shutil.ignore_patterns("__pycache__"))
        (d / "docs/evidence").mkdir(parents=True)
        shutil.copytree(root / "docs/evidence/d06", d / "docs/evidence/d06", ignore=shutil.ignore_patterns("mutation*"))
        for f in ("pyproject.toml",):
            shutil.copy(root / f, d / f)
        return d

    d = scratch()
    rc, log = run(cmd, d, env, 1800)
    (out / "control.log").write_text(log)
    shutil.rmtree(d, ignore_errors=True)
    results = [dict(id="CONTROL", status="PASS" if rc == 0 else "FAIL", tail=log.strip().splitlines()[-1] if log.strip() else "")]
    if rc != 0:
        print("CONTROL FAILED"); (out / "results.json").write_text(json.dumps(results, indent=1)); sys.exit(2)

    def one(m):
        d = scratch()
        try:
            for spec in [m] + ([m["also"]] if m.get("also") else []):
                f = d / spec["file"]
                src = f.read_text()
                if src.count(spec["old"]) != 1:
                    return dict(id=m["id"], status="INVALID", desc=m["desc"], tail=f"old text found {src.count(spec['old'])} times in {spec['file']}")
                f.write_text(src.replace(spec["old"], spec["new"]))
            rc, log = run(cmd, d, env, 1800)
            (out / f"{m['id']}.log").write_text(log)
            tail = [l for l in log.strip().splitlines() if l.startswith(("FAILED", "ERROR")) or " passed" in l or " failed" in l]
            return dict(id=m["id"], status="SURVIVED" if rc == 0 else "KILLED", desc=m["desc"], equivalent=m["equivalent"], by=tail[0][:200] if tail else "")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    todo = [m for m in M if not only or m["id"] in only]
    with ThreadPoolExecutor(max_workers=int(os.environ.get("MUT_WORKERS", "4"))) as ex:
        for r in ex.map(one, todo):
            results.append(r)
            print(r["status"], r["id"], flush=True)
    (out / "results.json").write_text(json.dumps(results, indent=1))
    k = sum(r["status"] == "KILLED" for r in results); s = sum(r["status"] == "SURVIVED" for r in results); i = sum(r["status"] == "INVALID" for r in results)
    print(f"killed {k} survived {s} invalid {i} of {len(todo)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], set(sys.argv[3:]))
