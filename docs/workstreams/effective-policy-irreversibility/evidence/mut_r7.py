"""Mutation check of the NEW critical guards of the r08-v7 irreversibility increment (registry_irreversibility_governance.py, registry_effective_policy.py and the new parts of
registry_governed_policy.py). Each mutant is first run against tests/test_irreversibility_unit.py (no Registry), then against tests/test_irreversibility_governance.py (real Ed25519,
Registry r7_reg worktree); a survivor of both is retried against the three older suites and reported as KILLED-BY-OTHER, else SURVIVED. argv[1] = source root (the r7_cp worktree)."""
import subprocess, sys, pathlib, shutil, json, os
S = "/tmp/claude-0/-home-claude/139dd095-4028-5533-a993-4a7fc4b564f0/scratchpad"
src_root = pathlib.Path(sys.argv[1]); work = pathlib.Path(S) / "m12" / "mutroot_r7"
if work.exists(): shutil.rmtree(work)
shutil.copytree(src_root, work, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
D = work / "src/agent_control_plane"
IR, EF, PO = "registry_irreversibility_governance.py", "registry_effective_policy.py", "registry_governed_policy.py"
M = [
 ("I01 stricter() inverted", IR, "    return a if _RANK_IR[a] <= _RANK_IR[b] else b", "    return a if _RANK_IR[a] >= _RANK_IR[b] else b"),
 ("I02 host flag mapping inverted", IR, "val = IRREVERSIBLE if flag else NO_CHANGE", "val = NO_CHANGE if flag else IRREVERSIBLE"),
 ("I03 compose never sets the flag", IR, 'action["irreversible"] = True', 'action["irreversible"] = False'),
 ("I04 compose clears a host true when effective says no_change", IR, '        if effective[action["class_id"]] == IRREVERSIBLE:\n            action["irreversible"] = True', '        action["irreversible"] = effective[action["class_id"]] == IRREVERSIBLE'),
 ("I05 widening check removed", IR, '    if any(_RANK_IR[effective[k]] > _RANK_IR[host_values[k]] for k in host_values):\n        return None, Refusal("effective_policy_widens_host", None, kind)\n', ""),
 ("I06 stricter-of-host-and-registry check removed", IR, "any(effective[k] != stricter_irreversible(host_values[k], registry[k]) for k in registry)", "False"),
 ("I07 unnamed-class-keeps-host check removed", IR, '    if any(k not in registry and effective[k] != host_values[k] for k in host_values):\n        return None, Refusal("effective_policy_invalid", None, kind)\n', ""),
 ("I08 scoped class need not be governed", IR, '    if scoped.class_id not in registry:\n        return None, Refusal("scoped_class_not_governed", None, kind)\n', ""),
 ("I09 scoped action may be unknown", IR, '    if scoped is None:\n        return None, Refusal("action_class_unknown", None, kind)\n', ""),
 ("I10 registry class unknown to host accepted", IR, "not set(registry) <= set(host_values) or ", ""),
 ("I11 effective class-set check removed", IR, "if set(effective) != set(host_values) or not all(_ir_value(v) for v in effective.values()):", "if not all(_ir_value(v) for v in effective.values()):"),
 ("I12 effective value domain check removed", IR, "if set(effective) != set(host_values) or not all(_ir_value(v) for v in effective.values()):", "if set(effective) != set(host_values):"),
 ("I13 flip pre-check removed", IR, "    conflict = flip_conflict(host, host_values, effective)\n    if conflict is not None:\n        return None, Refusal(conflict, None, kind)\n", ""),
 ("I14 flip pre-check ignores whether the class flips", IR, "if host_values.get(cl.class_id) == NO_CHANGE and effective.get(cl.class_id) == IRREVERSIBLE:", "if effective.get(cl.class_id) == IRREVERSIBLE:"),
 ("I15 flip pre-check also fires without a requested flip", IR, "if host_values.get(cl.class_id) == NO_CHANGE and effective.get(cl.class_id) == IRREVERSIBLE:", "if host_values.get(cl.class_id) == NO_CHANGE:"),
 ("I16 cause reversibility not checked", IR, 'if getattr(cl, "reversibility", None) is not None:', "if False:"),
 ("I17 cause reversible_until not checked", IR, 'if getattr(cl, "reversible_until", None) is not None:', "if False:"),
 ("I18 cause reversal_cost not checked", IR, 'if getattr(cl, "reversal_cost", None) is not None:', "if False:"),
 ("I19 cause on_unreadable not checked", IR, 'if getattr(cl, "on_unreadable", None) != "refuse":', "if False:"),
 ("I20 cause reads_protected_data not checked", IR, 'if getattr(cl, "reads_protected_data", False) is not False:', "if False:"),
 ("I21 cause counterparty_observable not checked", IR, 'if getattr(cl, "counterparty_observable", True) is not True:', "if False:"),
 ("I22 cause on_unreadable inverted", IR, 'if getattr(cl, "on_unreadable", None) != "refuse":', 'if getattr(cl, "on_unreadable", None) == "refuse":'),
 ("I23 first cause not reported (last instead)", IR, 'return FLIP_CONFLICT + ":" + causes[0]', 'return FLIP_CONFLICT + ":" + causes[-1]'),
 ("I24 conflict code unnamed", IR, 'return FLIP_CONFLICT + ":" + causes[0]', "return FLIP_CONFLICT"),
 ("I25 actions not visited in sorted order", IR, "for aid in sorted(host.actions):", "for aid in sorted(host.actions, reverse=True):"),
 ("I26 verifier admission removed", IR, '    if type(verifier) is not verifier_cls:\n        return None, Refusal("verifier_not_admitted")\n', ""),
 ("I27 operationally_authorized not checked", IR, " or decision.operationally_authorized is not False:", ":"),
 ("I28 non-applied decision kinds accepted", IR, '    if kind != "applied" or decision.deny_all is not False:\n        return None, Refusal("registry_decision_invalid", None, kind)\n', ""),
 ("I29 deny_all not checked", IR, 'if kind != "applied" or decision.deny_all is not False:', 'if kind != "applied":'),
 ("I30 digest computed for the wrong family", IR, "identity.effective_policy_digest(FAMILY_IR,", 'identity.effective_policy_digest("f5-terminal-revocation-enablement-policy",'),
 ("I31 digest computed for the wrong contract version", IR, "{FIELD_IR: dict(effective)}, CONTRACT_V7)", '{FIELD_IR: dict(effective)}, "r08-v6")'),
 ("I32 caller values not passed to the Registry", IR, "{FIELD_IR: dict(host_values)}, material", "{FIELD_IR: {}}, material"),
 ("I33 participation not required", IR, 'decision7.verify_and_decide_v7("required",', 'decision7.verify_and_decide_v7("optional",'),
 ("I35 non-exact str values accepted", IR, "def _ir_value(v: Any) -> bool:\n    return type(v) is str and v in _RANK_IR", "def _ir_value(v: Any) -> bool:\n    return v in _RANK_IR"),
 ("I36 material type check removed", IR, '    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:\n        return None, Refusal("material_invalid")\n', ""),
 ("I37 non-bool host flag accepted", IR, "or type(flag) is not bool:", ":"),
 ("I38 ambiguous class accepted", IR, '        if cid in values and values[cid] != val:\n            return None, "class_irreversible_ambiguous"\n', ""),
 ("I39 record map must be non-empty check removed", IR, "if type(m) is not dict or not m or not all(type(k) is str and _ir_value(v) for k, v in m.items()):", "if type(m) is not dict or not all(type(k) is str and _ir_value(v) for k, v in m.items()):"),
 ("I40 registry-unavailable not a refusal", IR, '        return None, Refusal("registry_unavailable")', "        raise"),
 ("I41 digest failure not a refusal", IR, '        return None, Refusal("effective_policy_digest_unavailable", None, kind)', "        raise"),
 ("I42 call failure not a refusal", IR, '        return None, Refusal("registry_call_failed")', "        raise"),
 ("E01 snapshot family table: wrong contract version", EF, '"class_irreversible": ("f5-action-class-irreversibility-policy", "r08-v7"),', '"class_irreversible": ("f5-action-class-irreversibility-policy", "r08-v6"),'),
 ("E02 snapshot schema revision dropped", EF, 'SCHEMA_REVISIONS = {"class_irreversible": 1}', "SCHEMA_REVISIONS = {}"),
 ("E03 selection_ref accepts duplicate keys", EF, '        raise ValueError("duplicate key")', "        pass"),
 ("E04 selection_ref accepts floats", EF, 'def _reject_number(_):\n    raise ValueError("non-integer number")', "def _reject_number(_):\n    return 0"),
 ("E06 selection_ref accepts an empty selection id", EF, "type(sid) is not str or not sid or", "type(sid) is not str or"),
 ("E07 effective pairs not sorted", EF, "return tuple(sorted((str(k), _frozen(v)) for k, v in value.items()))", "return tuple((str(k), _frozen(v)) for k, v in value.items())"),
 ("E08 identity omits the epoch", EF, "f.selection_id, f.selection_epoch]", "f.selection_id]"),
 ("E09 identity omits the host profile digest", EF, '"host_profile_digest": self.host_profile_digest, ', ""),
 ("E10 identity omits the effective policy digest", EF, "f.family_schema_revision, f.effective_policy_digest, _jsonable(f.effective)", "f.family_schema_revision, _jsonable(f.effective)"),
 ("E11 identity omits the evaluation time", EF, '            "evaluated_at": self.evaluated_at,\n', ""),
 ("E12 resolve: missing mandatory material not refused", EF, '    if any(name not in materials or materials[name] is None for name, _ in declared):  # a declared family is mandatory: no fallback to a smaller set\n        raise pol.RegistryGovernedPolicyRefused(Refusal("selection_missing"), "resolution")\n', ""),
 ("E13 resolve: empty declaration not refused", EF, '    if not declared:\n        raise pol.RegistryGovernedPolicyRefused(Refusal("no_family_declared"), "resolution")\n', ""),
 ("E14 resolve: a refusal is swallowed", EF, '    if refusal is not None:\n        raise pol.RegistryGovernedPolicyRefused(refusal, "resolution")', "    if refusal is not None:\n        return None"),
 ("E15 snapshot ignores the selection ref", EF, "ref[0] if ref else None, ref[1] if ref else None))", "None, None))"),
 ("E16 snapshot families not in composition order", EF, "    for slot in order:", "    for slot in sorted(order):"),
 ("E17 snapshot omits the scope operation ids", EF, '                   ("operation_ids", tuple(sorted(operation_ids.items()))))', '                   ("operation_ids", ()))'),
 ("E18 snapshot effective profile digest dropped", EF, 'EffectivePolicySnapshot(host_profile_digest, bound.get("effective_profile_digest"),', "EffectivePolicySnapshot(host_profile_digest, None,"),
 ("P01 irreversibility not composed into the profile", PO, "            base = irmod.compose_irreversible(base, effective)", "            pass"),
 ("P02 irreversibility missing from the composition order", PO, '"class_irreversible", "terminal_revocation")  # deterministic composition order', '"terminal_revocation")  # deterministic composition order'),
 ("P03 irreversibility ordered before assurance", PO, '"class_unreadable", "class_revocation_assurance", "class_irreversible", "terminal_revocation")  # deterministic', '"class_unreadable", "class_irreversible", "class_revocation_assurance", "terminal_revocation")  # deterministic'),
 ("P04 lowering a host true is not a widening", PO, 'if ch.get("irreversible", True) and not cf.get("irreversible", True):', "if False:"),
 ("P05 flip over a host on_unreadable not refuse is not refused (final validator)", PO, 'and ch["on_unreadable"] != "refuse":', "and False:"),
 ("P06 irreversible compared away even when the family is not declared", PO, "        if irreversible_declared:  # only a DECLARED family may differ in this field; otherwise any difference is a foreign change\n            ch.pop(\"irreversible\", None), cf.pop(\"irreversible\", None)", "        ch.pop(\"irreversible\", None), cf.pop(\"irreversible\", None)"),
 ("P07 host ambiguity not read early", PO, "            host_irreversible, code = irmod.host_class_irreversible(host)\n            if host_irreversible is None:\n                raise _refuse(code, \"construction\")", "            host_irreversible = {}"),
 ("P08 the family does not count as profile-bearing", PO, "or families.terminal_revocation is not None or families.class_irreversible is not None)", "or families.terminal_revocation is not None)"),
 ("P09 bound identity omits the irreversibility part", PO, '    if irreversible is not None:  # present only when declared', '    if False:  # present only when declared'),
 ("P10 profile digest not bound for irreversibility-only governance", PO, "(age_part or unreadable or assurance or irreversible or terminal)", "(age_part or unreadable or assurance or terminal)"),
 ("P11 configuration identity omits the host irreversible values", PO, '"host_class_irreversible": host_irreversible})', '"host_class_irreversible": None})'),
 ("P12 refusal not prefixed with the family", PO, '            return None, _prefixed("class_irreversible", refusal)', "            return None, refusal"),
 ("P13 re-derivation ignores the host irreversible values", PO, "                                         host_irreversible=self._gp_host_irreversible)", "                                         host_irreversible=None)"),
 ("P14 declared irreversible tolerated although not declared", PO, "irreversible_declared=families.class_irreversible is not None)", "irreversible_declared=True)"),
 ("P15 original host validity not checked early for the new family", PO, "or families.terminal_revocation is not None or families.class_irreversible is not None:\n            defect", "or families.terminal_revocation is not None:\n            defect"),
 ("P16 snapshot exposes no irreversibility refs", PO, 'refs={name: selection_ref(materials[name].selection_text) for name, _ in declared}', "refs={}"),
 ("P17 snapshot host digest dropped", PO, "self._gp_snapshot = build_snapshot(bound=bound, host_profile_digest=agemod.profile_digest(host) if host is not None else None,", "self._gp_snapshot = build_snapshot(bound=bound, host_profile_digest=None,"),
 ("P18 identity omits the host irreversible values", PO, '                         "class_irreversible": dict(self._gp_host_irreversible) if self._gp_host_irreversible else None},', "                         },"),
 ("P19 derive: irreversibility derivation skipped", PO, "    if families.class_irreversible is not None:\n        derived_i, refusal", "    if False:\n        derived_i, refusal"),
 ("P20 host class defect not applied to the flipped final profile", PO, '    if unrmod.host_class_defect(final) is not None:\n        return "composed_profile_invalid"', "    if False:\n        return \"composed_profile_invalid\""),
]
ONLY = [x for x in os.environ.get('MUT_ONLY', '').split(',') if x]
OUT = os.environ.get('MUT_OUT', 'mutation-results-r7-cp.json')
PY = f"{S}/venv-g1-212/bin/python"
def run(tests, pin):
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": f"{work}:{work}/src", "OCS_REGISTRY_PIN_DIR": f"{S}/m12/{pin}", "OCS_REQUIRE_REGISTRY_PIN": "1"}
    return subprocess.run([PY, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests], cwd=work, capture_output=True, text=True, env=env)
res = []
for name, fn, a, b in M:
    if ONLY and name.split()[0] not in ONLY: continue
    F = D / fn; orig = F.read_text()
    if orig.count(a) != 1:
        res.append((name, "PATTERN COUNT %d" % orig.count(a), "")); print(res[-1], flush=True); continue
    F.write_text(orig.replace(a, b))
    try:
        r = run(["tests/test_irreversibility_unit.py"], "r7_reg")
        if r.returncode:
            tail = [l for l in r.stdout.splitlines() if l.startswith("FAILED") or l.startswith("ERROR")]
            status, detail = "KILLED", "unit: " + (tail[0][:140] if tail else r.stdout.strip().splitlines()[-1][:140])
        else:
            r = run(["tests/test_irreversibility_governance.py"], "r7_reg")
            if r.returncode:
                tail = [l for l in r.stdout.splitlines() if l.startswith("FAILED") or l.startswith("ERROR")]
                status, detail = "KILLED", "governance: " + (tail[0][:140] if tail else r.stdout.strip().splitlines()[-1][:140])
            else:
                status, detail = "SURVIVED", "irreversibility tests pass"
                for t, pin in (("tests/test_revocation_families_governance.py", "r7_reg"), ("tests/test_governed_policy_composition.py", "r7_reg"), ("tests/test_f5_class_unreadable_governance.py", "r7_reg")):
                    r2 = run([t], pin)
                    if r2.returncode:
                        status, detail = "KILLED-BY-OTHER", t; break
    finally:
        F.write_text(orig)
    res.append((name, status, detail)); print(*res[-1], flush=True)
json.dump(res, open(f"{S}/m12/{OUT}", "w"), indent=1)
print("TOTAL", len(res), "KILLED", sum(1 for x in res if x[1].startswith("KILLED")), "SURVIVED", [x[0] for x in res if x[1] == "SURVIVED"], "PATTERN", [x[0] for x in res if x[1].startswith("PATTERN")])
