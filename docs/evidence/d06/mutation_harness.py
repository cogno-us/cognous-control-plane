"""Mutation harness for the D-06 effective-configuration binding (developer evidence only; NOT independent qualification).

Each mutant is applied to a SCRATCH COPY of the repository (never to the working tree), the three D-06 test files are run with `-x`, and a mutant is
  KILLED   when the run fails (non-zero exit),
  SURVIVED when every test passes (reported honestly, together with why where it is an equivalent mutant),
  INVALID  when the mutation text did not apply exactly once (a harness defect, never counted as killed).
Usage:  python mutation_harness.py <repo-root> <out-dir> [mutant-id ...]      env: OCS_REGISTRY_PIN_DIR, OCS_REQUIRE_REGISTRY_PIN=1, PYTHONPATH is set here.
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

ECB = "src/agent_control_plane/effective_configuration_binding.py"
LIFE = "src/agent_control_plane/registry_governed_lifecycle.py"
POL = "src/agent_control_plane/registry_governed_policy.py"
TESTS = ["tests/test_effective_configuration_binding_unit.py", "tests/test_effective_configuration_binding.py", "tests/test_effective_configuration_binding_legacy.py",
         "tests/test_effective_configuration_binding_dedicated.py"]

M = []


def mut(mid, desc, file, old, new, equivalent=None):
    M.append(dict(id=mid, desc=desc, file=file, old=old, new=new, equivalent=equivalent))


# --- drop each member from the digest preimage ---------------------------------------------------------------------------------------------------------------
for name in ("scope", "host_profile_digest", "effective_profile_digest", "f4_scalars", "other_scalars", "observation_policy", "families"):
    mut(f"drop-{name}-from-preimage", f"the digest is computed without the `{name}` member",
        ECB, 'return commitment({"domain": DOMAIN, "version": version, **members})',
        'return commitment({"domain": DOMAIN, "version": version, **{k: v for k, v in members.items() if k != "%s"}})' % name)
mut("preimage-without-domain", "the domain separator is dropped from the preimage", ECB, 'return commitment({"domain": DOMAIN, "version": version, **members})',
    'return commitment({"version": version, **members})')
mut("preimage-without-version", "the version is dropped from the preimage", ECB, 'return commitment({"domain": DOMAIN, "version": version, **members})',
    'return commitment({"domain": DOMAIN, **members})')
# --- reader rules --------------------------------------------------------------------------------------------------------------------------------------------
mut("skip-digest-recomputation", "a persisted digest is not recomputed from its members", ECB, '    if digest_of(record["version"], record["members"]) != record["digest"]:\n        return "invalid:digest_mismatch"\n',
    "")
mut("skip-members-validation", "persisted members are not validated for type and range", ECB, '    defect = members_defect(record["members"])\n    if defect is not None:\n        return "invalid:" + defect\n', "")
mut("accept-unknown-version", "an unknown version is treated like the supported one", ECB, '    if record["version"] != VERSION:\n        return "version_unsupported"\n', "")
mut("compare-only-digest", "the live comparison uses the digest alone (members still validated against it)", ECB, "return BOUND if record == live else MISMATCH",
    'return BOUND if record["digest"] == live["digest"] else MISMATCH',
    equivalent="expected equivalent: `record_defect` already proves digest == recomputation(members), so digest equality implies member equality")
mut("compare-only-digest-and-skip-recompute", "digest-only comparison AND no recomputation (a pasted live digest over other members is accepted)", ECB,
    'return BOUND if record == live else MISMATCH', 'return BOUND if record["digest"] == live["digest"] else MISMATCH')
M[-1]["also"] = dict(file=ECB, old='    if digest_of(record["version"], record["members"]) != record["digest"]:\n        return "invalid:digest_mismatch"\n', new="")
mut("missing-is-legacy-without-cutoff", "an absent member is legacy whatever the cutoff", ECB,
    "legacy = (legacy_cutoff_defect(cutoff) is None and type(index) is int and type(decision_count) is int and 0 <= index < cutoff <= decision_count)", "legacy = True")
mut("cutoff-off-by-one", "index <= cutoff instead of index < cutoff", ECB, "0 <= index < cutoff <= decision_count", "0 <= index <= cutoff <= decision_count")
mut("cutoff-not-validated", "the cutoff type/range check is dropped (a bool True is read as 1)", ECB,
    "legacy = (legacy_cutoff_defect(cutoff) is None and type(index) is int", "legacy = (type(index) is int")
mut("cutoff-beyond-store-accepted", "a cutoff larger than the decisions in the store still enables legacy", ECB, "0 <= index < cutoff <= decision_count", "0 <= index < cutoff")
mut("unknown-position-is-legacy", "an unknown decision position is treated as legacy", ECB, "type(index) is int and type(decision_count) is int and 0 <= index", "(index is None or type(index) is int) and type(decision_count) is int and (index is None or 0 <= index)")
mut("digest-allows-all-zero", "an all-zero digest is accepted as a digest", ECB, "return type(v) is str and _DIGEST.match(v) is not None and v != _ZERO", "return type(v) is str and _DIGEST.match(v) is not None")
mut("scalar-allows-bool", "a bool passes the exact-int scalar rule", ECB, "return type(v) is int and 0 <= v <= SCALAR_MAX", "return isinstance(v, int) and 0 <= v <= SCALAR_MAX")
mut("scalar-no-upper-range", "the scalar range has no upper bound", ECB, "return type(v) is int and 0 <= v <= SCALAR_MAX", "return type(v) is int and 0 <= v")
mut("build-members-skips-validation", "build_members and mint do not validate", ECB, "    defect = members_defect(members)\n    if defect is not None:\n        raise BindingInvalid(defect)\n    return members\n",
    "    return members\n")
mut("family-unknown-slot-skipped", "a governed slot unknown to the family table is silently left out", ECB,
    '        if slot not in known or slot not in family_table:\n            raise BindingInvalid("family_slot_unknown")\n', "")
mut("record-extra-keys-allowed", "extra keys inside the persisted record are tolerated", ECB, "    if not _exact(record, RECORD_FIELDS):\n        return \"invalid:record\"\n", "")
# --- lifecycle -----------------------------------------------------------------------------------------------------------------------------------------------
mut("skip-check-on-claim-path", "the pin-export / claim path is not checked", LIFE, "        target = decision if decision is not None else _EXEC_DECISION.get()\n",
    '        if stage == "claim":\n            return reasons, binding\n        target = decision if decision is not None else _EXEC_DECISION.get()\n')
mut("skip-check-on-execute", "execute is not checked (member only minted)", LIFE, "            status = self.configuration_binding_status(target) if target is not None else ecb.UNBOUND_AFTER_CUTOFF\n",
    "            return reasons, binding\n            status = None\n")
mut("legacy-ignores-other-keys", "a legacy decision is accepted by replacing the whole live binding with the persisted one", LIFE,
    "        if status == ecb.LEGACY:  # previous semantics: ONLY the new key is left out of the live side; nothing else is ignored\n            return reasons, binding\n",
    "        if status == ecb.LEGACY:\n            return reasons, target.binding\n")
mut("stamp-persisted-member", "the check stamps the PERSISTED member onto the live binding (a mismatch becomes equal)", LIFE,
    "        stamped = self._gl_with_member(binding, live)\n        persisted_ra",
    "        stamped = self._gl_with_member(binding, (getattr(getattr(target, 'binding', None), 'runtime_authority', None) or {}).get(ecb.KEY, live))\n        persisted_ra")
mut("never-stamp-live-member", "the live member is never added in the check (a bound decision can never match)", LIFE,
    "        stamped = self._gl_with_member(binding, live)\n        persisted_ra", "        stamped = binding\n        persisted_ra")
mut("hold-becomes-authorization", "the binding layer returns no reasons for a hold (a hold would be authorized)", LIFE,
    "        if reasons or binding is None:\n            return reasons, binding\n", "        if reasons or binding is None:\n            return [], binding\n")
mut("no-mint-on-decide", "authorized decisions are not stamped with the member", LIFE,
    "                return reasons, self._gl_with_member(binding, live)\n", "                return reasons, binding\n")
mut("binding-invalid-falls-back-to-unbound", "an unbindable live configuration silently falls back to the unbound path", LIFE,
    '            raise self._gl_refuse("configuration_binding_invalid", "decision" if stage == "decision" else "effect") from None',
    "            return reasons, binding")
mut("execute-does-not-carry-the-decision", "the execute entry does not carry the decision (no-profile path treated as a fresh mint)", LIFE,
    "token, dtoken = _EXEC_NOW.set(now), _EXEC_DECISION.set(decision)", "token, dtoken = _EXEC_NOW.set(now), _EXEC_DECISION.set(None)")
# --- added after the first run, to explain the `stamp-persisted-member` survivor (run separately into mutation-extra/) ----------------------------------------------------
GUARD = "        if status not in ecb.ACCEPTED and stamped.runtime_authority == persisted_ra:  # LOAD-BEARING: Python equality conflates 60.0 == 60 and True == 1, so a malformed member can compare EQUAL to the live one; the classification still refuses\n            return sorted(set(reasons) | {BINDING_CHANGED}), stamped\n"
STAMP_OLD = "        stamped = self._gl_with_member(binding, live)\n        persisted_ra"
STAMP_NEW = "        stamped = self._gl_with_member(binding, (getattr(getattr(target, 'binding', None), 'runtime_authority', None) or {}).get(ecb.KEY, live))\n        persisted_ra"
mut("redundant-guard-removed", "the defensive 'stamped equals persisted although not accepted' guard is removed (alone)", LIFE, GUARD, "",
    equivalent="first assumed equivalent (unreachable); the run showed it is LOAD-BEARING: Python equality conflates 60.0 == 60 and True == 1, so a malformed persisted member can compare equal to the live one")
mut("stamp-persisted-member-and-no-guard", "the persisted member is stamped AND the defensive guard is removed (a mismatch would be accepted)", LIFE, STAMP_OLD, STAMP_NEW)
M[-1]["also"] = dict(file=LIFE, old=GUARD, new="")
# --- shared lifecycle step / held state (follow-up: the logic moved from the composed workflow into GovernedLifecycle so the dedicated workflows reuse it) -----------------------
mut("held-guard-ignores-observation-policy", "the held-state guard does not cover the ObservationPolicy", LIFE,
    "        return scalars, (None if obs is None else tuple((type(v), v) for v in (obs.max_age_seconds, obs.clock_tolerance_seconds)))",
    "        return scalars, None")
mut("held-guard-ignores-other-scalars", "the held-state guard covers only the F4 scalars", LIFE,
    "        scalars = tuple((type(v), v) for v in (self.status_max_age_seconds, self.approval_max_age_seconds, self.clock_tolerance_seconds, self.identity_max_age_seconds,\n                                               self.mandate_max_age_seconds))",
    "        scalars = tuple((type(v), v) for v in (self.status_max_age_seconds, self.approval_max_age_seconds))")
mut("held-guard-disabled", "the new held-state comparison is removed", LIFE, '            return None if self._gl_config_view() == self._gl_held_config else "scalars_modified"', "            return None")
mut("construction-skips-binding-validation", "the scalars are not validated at construction", LIFE, "            self._gl_configuration_members()\n        except ecb.BindingInvalid as exc:",
    "            pass\n        except ecb.BindingInvalid as exc:")
mut("legacy-cutoff-not-validated", "the shared cutoff check accepts any legacy_cutoff", LIFE, "    if ecb.legacy_cutoff_defect(cutoff) is not None:", "    if False:")
mut("legacy-cutoff-not-applied", "the shared bind step ignores legacy_cutoff", LIFE, "        self._gl_legacy_cutoff = legacy_cutoff\n", "        self._gl_legacy_cutoff = 0\n")
mut("members-f4-scalars-constant", "the F4 scalars are not read live (constant 0)", LIFE,
    'f4_scalars={"status_max_age_seconds": self.status_max_age_seconds, "approval_max_age_seconds": self.approval_max_age_seconds},',
    'f4_scalars={"status_max_age_seconds": 0, "approval_max_age_seconds": 0},')
mut("members-omit-constructor-tolerance", "the constructor tolerance is not read live (constant 5)", LIFE,
    '"clock_tolerance_seconds": self.clock_tolerance_seconds, "identity_max_age_seconds"', '"clock_tolerance_seconds": 5, "identity_max_age_seconds"')
mut("members-use-host-profile-for-effective", "the composed effective profile digest is replaced by the host digest", POL,
    "ed = agemod.profile_digest(held) if held is not None else None", "ed = hd")
mut("members-scope-fixed-tenant", "the tenant in the scope member is a constant", LIFE, "ecb.scope_identity(scope.consumer_id, scope.tenant_id,", 'ecb.scope_identity(scope.consumer_id, "tenant",')
mut("members-families-empty", "the declared family set is not bound", LIFE, "families=ecb.family_rows(bound, order or tuple(FAMILY_TABLE), FAMILY_TABLE, SCHEMA_REVISIONS))", "families=[])")
mut("members-families-skip-schema-revisions", "the family schema revisions are not bound", LIFE, "FAMILY_TABLE, SCHEMA_REVISIONS))", "FAMILY_TABLE, {}))")
mut("members-observation-policy-null", "the ObservationPolicy is not bound (explicit null)", LIFE,
    'observation_policy=None if obs is None else {"max_age_seconds": obs.max_age_seconds, "clock_tolerance_seconds": obs.clock_tolerance_seconds})',
    "observation_policy=None)")
# --- the dedicated single-family hooks (follow-up) ---------------------------------------------------------------------------------------------------------------------------
F4M, AGEM, UNRM = ("src/agent_control_plane/registry_f4_age_governance.py", "src/agent_control_plane/registry_f5_class_age_governance.py",
                   "src/agent_control_plane/registry_f5_class_unreadable_governance.py")
F4_HOOK = '        return self._gl_build_members(host_profile_digest=None, effective_profile_digest=None, bound={"f4_ages": self._gl_bound})'
AGE_HOOK = "profile_digest(self._f5_host), effective_profile_digest=profile_digest(held), bound={\"class_age\": self._gl_bound})"
UNR_HOOK = "        return self._gl_build_members(host_profile_digest=profile_digest(self._fu_host), effective_profile_digest=profile_digest(held),\n                                      bound={\"class_age\": age_part, \"class_unreadable\": (effective, digest)})"
mut("dedicated-f4-hook-binds-nothing", "the dedicated F4 workflow mints/checks no binding", F4M, F4_HOOK, "        return None")
mut("dedicated-age-hook-binds-nothing", "the dedicated class-age workflow mints/checks no binding", AGEM,
    "        return self._gl_build_members(host_profile_digest=" + AGE_HOOK, "        return None  # (" + AGE_HOOK)
mut("dedicated-unr-hook-binds-nothing", "the dedicated class-unreadable workflow mints/checks no binding", UNRM, UNR_HOOK, "        return None")
mut("dedicated-f4-held-guard-missing", "the dedicated F4 held-state guard does not cover the other scalars / ObservationPolicy", F4M,
    "        return self._gl_config_defect()  # D-06: the other scalars and the ObservationPolicy", "        return None")
mut("dedicated-age-held-guard-missing", "the dedicated class-age held-state guard does not cover the scalars / ObservationPolicy", AGEM,
    "        return self._gl_config_defect()  # D-06: the five scalars and the ObservationPolicy", "        return None")
mut("dedicated-unr-held-guard-missing", "the dedicated class-unreadable held-state guard does not cover the scalars / ObservationPolicy", UNRM,
    "        return self._gl_config_defect()  # D-06: the five scalars and the ObservationPolicy", "        return None")
for _tag, _f in (("f4", F4M), ("age", AGEM), ("unr", UNRM)):
    mut(f"dedicated-{_tag}-cutoff-not-validated", f"the dedicated {_tag} constructor does not validate legacy_cutoff", _f,
        "        check_cutoff(legacy_cutoff, _refuse)", "        pass  # check_cutoff")
    mut(f"dedicated-{_tag}-bind-step-skipped", f"the dedicated {_tag} constructor skips the shared bind step (no scalar validation, no held snapshot, no cutoff)", _f,
        "        self._gl_bind_configuration(legacy_cutoff, _refuse)", "        self._gl_legacy_cutoff = legacy_cutoff; self._gl_held_config = self._gl_config_view()  # bind step reduced")
mut("dedicated-age-host-digest-is-effective", "the dedicated class-age host digest is replaced by the effective digest", AGEM, "profile_digest(self._f5_host), effective_profile_digest",
    "profile_digest(held), effective_profile_digest")
mut("dedicated-unr-host-digest-is-effective", "the dedicated class-unreadable host digest is replaced by the effective digest", UNRM, "host_profile_digest=profile_digest(self._fu_host)",
    "host_profile_digest=profile_digest(held)")
mut("dedicated-unr-joint-age-slot-dropped", "the joint workflow does not bind the class-age family", UNRM, 'bound={"class_age": age_part, "class_unreadable": (effective, digest)}',
    'bound={"class_unreadable": (effective, digest)}')


def apply(root: Path, m: dict) -> bool:
    for spec in (m, m.get("also")):
        if not spec:
            continue
        path = root / spec["file"]
        text = path.read_text()
        if text.count(spec["old"]) != 1:
            return False
        path.write_text(text.replace(spec["old"], spec["new"]))
    return True


def run_one(args):
    src, work, m, out = args
    root = Path(work) / m["id"]
    shutil.copytree(src, root, ignore=shutil.ignore_patterns(".git", ".base", "__pycache__", ".mut", "*.pyc", "mutation"))
    if m["id"] != "__control__" and not apply(root, m):
        res = dict(id=m["id"], verdict="INVALID", detail="mutation text did not apply exactly once")
    else:
        env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(root / "src"), str(root)]), OCS_REQUIRE_REGISTRY_PIN="1")
        proc = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "--no-header", *TESTS], cwd=root, env=env, capture_output=True, text=True, timeout=1500)
        tail = proc.stdout[-6000:]
        failed = [ln for ln in proc.stdout.splitlines() if ln.startswith("FAILED") or ln.startswith("ERROR")]
        res = dict(id=m["id"], verdict=("KILLED" if proc.returncode != 0 else "SURVIVED") if m["id"] != "__control__" else ("PASS" if proc.returncode == 0 else "FAIL"), exit=proc.returncode, first_failure=(failed[0][:240] if failed else None))
        (out / f"{m['id']}.log").write_text(f"# {m['id']}: {m['desc']}\n# file: {m['file']}\n# verdict: {res['verdict']} (exit {proc.returncode})\n\n" + tail)
    shutil.rmtree(root, ignore_errors=True)
    res.update(desc=m["desc"], file=m["file"], note=m.get("equivalent"))
    print(json.dumps(res), flush=True)
    return res


def main() -> None:
    src, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    only = set(sys.argv[3:])
    out.mkdir(parents=True, exist_ok=True)
    (src / ".mut").mkdir(exist_ok=True)
    work = tempfile.mkdtemp(prefix="d06mut-", dir=str(src / ".mut"))
    control = dict(id="__control__", desc="unmutated copy", file="-", old="", new="", equivalent=None)
    results = []
    todo = [control] + [m for m in M if not only or m["id"] in only]
    # the control must pass: a harness whose unmutated copy fails would "kill" everything
    with ThreadPoolExecutor(max_workers=2) as pool:
        for r in pool.map(run_one, [(src, work, m, out) for m in todo]):
            results.append(r)
    shutil.rmtree(work, ignore_errors=True)
    summary = dict(total=len(results) - 1, killed=sum(r["verdict"] == "KILLED" for r in results[1:]), survived=[r["id"] for r in results[1:] if r["verdict"] == "SURVIVED"],
                   invalid=[r["id"] for r in results[1:] if r["verdict"] == "INVALID"], control=results[0]["verdict"], results=results)
    (out / "summary.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps({k: v for k, v in summary.items() if k != "results"}))


if __name__ == "__main__":
    main()
