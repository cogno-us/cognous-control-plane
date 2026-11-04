"""RW-01-F4-PoC E-1 deliverables for the narrow, Architect-authorized edit of the protected `src/agent_control_plane/bounded.py` (Register #259, parent #254).

BUILDER_TESTED developer evidence. NOT independently qualified. Needs no Registry checkout, no PyNaCl and no git (bytes only, so it runs in shallow CI).

What this file proves (and what it deliberately does not weaken):
  * the edited `bounded.py` is EXACTLY the pre-edit file (sha256 / git blob below) plus the six authorized added lines and nothing else: reverse-applying those six lines
    to the current bytes reproduces the OLD hash and the OLD git blob, and a line diff shows 6 additions and 0 removals;
  * the OLD hash/blob and the NEW hash/blob are both kept as named constants (the crosswalk); each of the six pinned assertions still pins ONE exact value (the new one);
  * the updated tripwire still detects an unrelated modification (one-byte and one-line mutations, a changed authorized line, a dropped authorized line, a reordered or
    duplicated authorized line);
  * no other protected file changed (git blob ids pinned at CP b19c47dd).
"""
from __future__ import annotations

import difflib
import hashlib
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "agent_control_plane"
BOUNDED = SRC / "bounded.py"

# --- the crosswalk (OLD = Control Plane b19c47dd, NEW = after the E-1 edit) ------------------------------------------------------------------------------------------
OLD_SHA256 = "c219f8825a8ddf9da1fe6771ae575af0a9069ac8a04eadd40f093a9adb13655b"
NEW_SHA256 = "4052ff87bfc90d3a4092ee690969354cd58769a9b542c4e5d1fa74ce821856ae"
OLD_BLOB = "2cc8d998ff0a8fec3112a8b0634111fcf8fbef17"
NEW_BLOB = "b5329804b05a83990af1a3ca17eb61c13080c12f"

#: The six pinned assertions: (file, kind, old constant name, new constant name or None, old value, new value)
CROSSWALK = (
    ("tests/test_f4_age_governance.py", "sha256", "BOUNDED_SHA256_AT_D66AE07", "BOUNDED_SHA256_RW01_F4_POC", OLD_SHA256, NEW_SHA256),
    ("tests/test_final3_composed_binding.py", "sha256", "BOUNDED_SHA256_BEFORE_RW01_F4_POC", "BOUNDED_SHA256_RW01_F4_POC", OLD_SHA256, NEW_SHA256),
    ("tests/test_f5_class_unreadable_governance.py", "sha256", "BOUNDED_SHA256_BEFORE_RW01_F4_POC", "BOUNDED_SHA256_RW01_F4_POC", OLD_SHA256, NEW_SHA256),
    ("tests/test_freshness_purpose_anchor_successor.py", "sha256", "BOUNDED_SHA256_BEFORE_RW01_F4_POC", "BOUNDED_SHA256_RW01_F4_POC", OLD_SHA256, NEW_SHA256),
    ("tests/test_governed_policy_composition.py", "sha256", "BOUNDED_SHA256_BEFORE_RW01_F4_POC", "BOUNDED_SHA256_RW01_F4_POC", OLD_SHA256, NEW_SHA256),
    ("tests/test_v02_legacy_claim_vector.py", "git-blob", "BOUNDED_BLOB_BEFORE_RW01_F4_POC", "BOUNDED_BLOB_RW01_F4_POC", OLD_BLOB, NEW_BLOB),
)

# --- P1 CP-2 (Architect-authorized strict tenant-binding generation, csf_4a764c7437e3bd47679c7b44): the SECOND, deliberate re-pin ------------------------------------------
CP2_SHA256 = "1b4a5f8fc6d64723da8f60cfe495736f4a92acb593e88787643fb9cba5f376ba"
CP2_BLOB = "946109410c5cf662e1a97cb0db46c08f3644e08e"
#: Exact (new_text, old_text) pairs; reverse-applying every pair (each new_text occurs exactly once) to the current bytes must reproduce the E-1 file (NEW_SHA256 / NEW_BLOB).
CP2_HUNKS = [('MANIFEST_VERSION = "1.1"\n'
  '# Tenant-binding generations of a tenant-aware decision. LEGACY is the published bounded-authorization-effect/0.2 semantics, in which\n'
  '# tenantless evidence is accepted for a tenant proposal (legacy/deprecated for tenant-aware use, retained for compatibility and selected\n'
  '# only explicitly). STRICT requires evidence.tenant_id to equal proposal.tenant_id exactly; None is never a wildcard. The generation is\n'
  '# persisted in TenantAuthorizationBinding, so a decision keeps the generation it was made under at effect, claim and pin time.\n'
  'TENANT_GENERATION_LEGACY = "bounded-authorization-effect/0.2"\n'
  'TENANT_GENERATION_STRICT = "bounded-authorization-effect/0.3-strict-tenant"\n'
  'TENANT_GENERATIONS = (TENANT_GENERATION_LEGACY, TENANT_GENERATION_STRICT)\n'
  '_PINNED_GENERATION: ContextVar = ContextVar("bounded_pinned_tenant_generation", default=None)\n',
  'MANIFEST_VERSION = "1.1"\n'),
 ('class TenantAuthorizationBinding(AuthorizationBinding):\n'
  '    """Tenant-aware binding. ``generation`` is the tenant-binding generation the decision was made under (legacy 0.2 by default so\n'
  '    previously persisted bindings keep their meaning; a workflow stamps the strict generation explicitly)."""\n',
  'class TenantAuthorizationBinding(AuthorizationBinding):\n    """Tenant-aware bounded-authorization-effect/0.2 binding."""\n'),
 ('\n    generation: Literal["bounded-authorization-effect/0.2", "bounded-authorization-effect/0.3-strict-tenant"] = TENANT_GENERATION_LEGACY\n',
  '\n    generation: Literal["bounded-authorization-effect/0.2"] = "bounded-authorization-effect/0.2"\n'),
 ('        rule_revision_profile=None,\n        tenant_binding_generation: str = TENANT_GENERATION_STRICT,\n',
  '        rule_revision_profile=None,\n'),
 ('    ):\n'
  '        if type(tenant_binding_generation) is not str or tenant_binding_generation not in TENANT_GENERATIONS:\n'
  '            raise ValueError("tenant_binding_generation must be an exact supported generation string")\n'
  '        # Applies to NEW decisions of tenant-aware proposals only; a persisted decision is always judged under its own generation.\n'
  '        self.tenant_binding_generation = tenant_binding_generation\n',
  '    ):\n'),
 ('        check_ref: list[str] = []\n'
  '        with self._generation_pin(persisted):\n'
  '            reasons, current = self._resolve(frozen, now, inputs=inputs, **({"stage":"effect", "decision":persisted} if '
  'self.runtime_authority_profile else {}),\n'
  '                                             **({"check_ref": check_ref} if (self._identity or self._freshness) else {}))\n',
  '        check_ref: list[str] = []\n'
  '        reasons, current = self._resolve(frozen, now, inputs=inputs, **({"stage":"effect", "decision":persisted} if '
  'self.runtime_authority_profile else {}),\n'
  '                                         **({"check_ref": check_ref} if (self._identity or self._freshness) else {}))\n'),
 ('    def _effect_id(self, binding: AuthorizationBinding) -> str:\n        identity = {\n',
  '    def _effect_id(self, binding: AuthorizationBinding) -> str:\n        return commitment({\n'),
 ('            "grant_revision": binding.grant_revision,\n'
  '        }\n'
  '        if getattr(binding, "generation", TENANT_GENERATION_LEGACY) == TENANT_GENERATION_STRICT:\n'
  '            identity["tenant_generation"] = TENANT_GENERATION_STRICT  # a stored strict<->legacy flip changes the identity and is refused\n'
  '        return commitment(identity)\n',
  '            "grant_revision": binding.grant_revision,\n        })\n'),
 ('\n'
  '    @staticmethod\n'
  '    def _persisted_generation(decision) -> str | None:\n'
  '        """The tenant-binding generation a persisted decision was made under (None for a tenantless or unauthorized one)."""\n'
  '        binding = getattr(decision, "binding", None)\n'
  '        return binding.generation if isinstance(binding, TenantAuthorizationBinding) else None\n'
  '\n'
  '    @contextmanager\n'
  '    def _generation_pin(self, decision):\n'
  '        """Evaluate the enclosed resolution under the generation persisted in ``decision`` (no upgrade, no downgrade)."""\n'
  '        token = _PINNED_GENERATION.set(self._persisted_generation(decision))\n'
  '        try:\n'
  '            yield\n'
  '        finally:\n'
  '            _PINNED_GENERATION.reset(token)\n'
  '\n',
  '\n'),
 ('    def _resolve(self, proposal, now, *, inputs=None, stage="decision", decision=None, check_ref=None):\n'
  '        if decision is not None:\n'
  '            with self._generation_pin(decision):\n'
  '                return self._resolve_pinned(proposal, now, inputs=inputs, stage=stage, decision=decision, check_ref=check_ref)\n'
  '        return self._resolve_pinned(proposal, now, inputs=inputs, stage=stage, decision=decision, check_ref=check_ref)\n'
  '\n'
  '    def _resolve_pinned(self, proposal, now, *, inputs=None, stage="decision", decision=None, check_ref=None):\n',
  '    def _resolve(self, proposal, now, *, inputs=None, stage="decision", decision=None, check_ref=None):\n'),
 ('        tenant_aware = isinstance(proposal, TenantRuntimeProposal)\n'
  '        generation = _PINNED_GENERATION.get() or self.tenant_binding_generation\n'
  '        strict_tenant = generation == TENANT_GENERATION_STRICT\n',
  '        tenant_aware = isinstance(proposal, TenantRuntimeProposal)\n'),
 ('                current = None\n'
  '            if current is not None and tenant_aware and strict_tenant:\n'
  "                # STRICT generation: the evidence must name exactly this proposal's tenant. Exact type and value (a str subclass, a\n"
  '                # padded or case-variant string is a different tenant); None is never a wildcard. A signed validation record that\n'
  '                # participates must carry the same exact tenant.\n'
  '                record = current.validation_record\n'
  '                statement = record.get("statement") if isinstance(record, dict) else None\n'
  '                signed_ok = (not isinstance(statement, dict) or "tenant_id" not in statement\n'
  '                             or (type(statement["tenant_id"]) is str and statement["tenant_id"] == tenant_id))\n'
  '                if (type(current.tenant_id) is not str or type(tenant_id) is not str or current.tenant_id != tenant_id\n'
  '                        or not signed_ok):\n'
  '                    reasons.append("evidence_binding_mismatch")\n'
  '                    current = None\n'
  '            elif current is not None:\n'
  '                # LEGACY 0.2 compatibility: tenantless evidence is still accepted for a tenant-aware proposal (documented limit);\n',
  '                current = None\n'
  '            if current is not None:\n'
  '                # Compatibility: tenantless evidence is still accepted for a tenant-aware proposal (documented limit);\n'),
 ('        binding_type = TenantAuthorizationBinding if tenant_aware else AuthorizationBinding\n'
  '        binding_extra = {"tenant_id": tenant_id, "generation": generation} if tenant_aware else {}\n',
  '        binding_type = TenantAuthorizationBinding if tenant_aware else AuthorizationBinding\n'
  '        binding_extra = {"tenant_id": tenant_id} if tenant_aware else {}\n')]


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


#: The complete authorized addition as (anchor, inserted) pairs: exactly these six lines, each inserted once directly after its anchor, nothing removed.
HUNKS = (
    ("from .strict_json import dumps_bytes, strict_loads\n",
     "from .selection_evidence import SelectionEvidence\n"),
    ("    resolution_inputs: list[ResolutionInput] = Field(default_factory=list)\n",
     "    selection_evidence: SelectionEvidence | None = Field(default=None, exclude_if=lambda v: v is None)  # RW-01-F4-PoC E-1: top-level, outside `binding`, read by no gate\n"),
    ("            recorded_at=self._write_time(now), time_source=self.time_source, **self._eval_stamp(now)))\n\n",
     "    def _decision_selection_evidence(self, reasons: list[str]) -> SelectionEvidence | None:  # RW-01-F4-PoC E-1 hook; governed lifecycles override\n"
     "        return None\n\n"),
    ("            resolution_inputs=inputs,\n",
     "            selection_evidence=self._decision_selection_evidence(reasons),\n"),
)
ADDED_LINES = 6  # 1 import + 1 field + (hook def, hook body, blank separator) + 1 constructor keyword


def cp2_reverse(current: bytes) -> bytes:
    """Undo the CP-2 hunks (each must occur exactly once). Returns the reconstructed E-1 bytes, or raises AssertionError."""
    text = current.decode("utf-8")
    for new_text, old_text in CP2_HUNKS:
        assert text.count(new_text) == 1, ("CP-2 hunk is not present exactly once", new_text[:80])
        text = text.replace(new_text, old_text)
    return text.encode("utf-8")


def reverse_apply(current: bytes) -> bytes:
    """Current bytes -> CP-2 hunks undone -> E-1 hunks undone = the OLD file. Remove each authorized E-1 insertion (it must occur exactly once, directly after its anchor). Returns the reconstructed OLD bytes, or raises AssertionError."""
    text = cp2_reverse(current).decode("utf-8")
    for anchor, inserted in HUNKS:
        needle = anchor + inserted
        assert text.count(needle) == 1, ("authorized hunk is not present exactly once", inserted)
        text = text.replace(needle, anchor)
    return text.encode("utf-8")


def tripwire_ok(data: bytes) -> bool:
    """The check every one of the six assertions performs on bounded.py: ONE exact value, no prefix, regex or any-hash match."""
    return sha(data) == CP2_SHA256


# ---------------------------------------------------------------------------------------------------------------------------------------------- inventory + crosswalk
def test_e1_current_bounded_py_matches_the_new_pins_exactly():
    """CP-2: the current file is pinned by the CP-2 value; undoing the CP-2 hunks reproduces the E-1 pins exactly."""
    data = BOUNDED.read_bytes()
    assert sha(data) == CP2_SHA256 and blob_id(data) == CP2_BLOB
    e1 = cp2_reverse(data)
    assert sha(e1) == NEW_SHA256 and blob_id(e1) == NEW_BLOB
    assert len({CP2_SHA256, NEW_SHA256, OLD_SHA256}) == 3 and len({CP2_BLOB, NEW_BLOB, OLD_BLOB}) == 3


def test_cp2_line_diff_over_e1_is_the_listed_hunks_only():
    e1 = cp2_reverse(BOUNDED.read_bytes()).decode("utf-8").splitlines(keepends=True)
    new = BOUNDED.read_text(encoding="utf-8").splitlines(keepends=True)
    ops = [line for line in difflib.unified_diff(e1, new, n=0) if not line.startswith(("---", "+++", "@@"))]
    assert len(CP2_HUNKS) == 13
    assert (len([x for x in ops if x.startswith("+")]), len([x for x in ops if x.startswith("-")])) == (63, 10)
    # only the strict-tenant generation machinery was touched: no E-1 symbol, no selection-evidence line changed
    assert not any("selection_evidence" in x or "SelectionEvidence" in x for x in ops)


def test_e1_reverse_applying_the_authorized_hunks_reproduces_the_old_pins():
    """Diff-shape test: current == OLD + exactly the authorized hunks (the OLD hash is reproduced, so nothing else changed, in the 4,000+ other lines or in whitespace)."""
    old = reverse_apply(BOUNDED.read_bytes())
    assert sha(old) == OLD_SHA256 and blob_id(old) == OLD_BLOB
    assert OLD_SHA256 != NEW_SHA256 and OLD_BLOB != NEW_BLOB


def test_e1_line_diff_is_six_additions_and_zero_removals():
    old = reverse_apply(BOUNDED.read_bytes()).decode("utf-8").splitlines(keepends=True)
    new = cp2_reverse(BOUNDED.read_bytes()).decode("utf-8").splitlines(keepends=True)
    ops = [line for line in difflib.unified_diff(old, new, n=0) if not line.startswith(("---", "+++", "@@"))]
    assert [line for line in ops if line.startswith("-")] == []
    assert len([line for line in ops if line.startswith("+")]) == ADDED_LINES
    assert len(new) - len(old) == ADDED_LINES <= 10  # E-1: at most ~10 changed lines


def test_e1_only_the_authorized_symbols_were_added():
    lines = [ln for ln in BOUNDED.read_text(encoding="utf-8").splitlines() if "selection_evidence" in ln or "SelectionEvidence" in ln]
    assert lines == [
        "from .selection_evidence import SelectionEvidence",
        "    selection_evidence: SelectionEvidence | None = Field(default=None, exclude_if=lambda v: v is None)  # RW-01-F4-PoC E-1: top-level, outside `binding`, read by no gate",
        "    def _decision_selection_evidence(self, reasons: list[str]) -> SelectionEvidence | None:  # RW-01-F4-PoC E-1 hook; governed lifecycles override",
        "            selection_evidence=self._decision_selection_evidence(reasons),",
    ]


CP2_CROSSWALK = tuple(
    (path, kind, "BOUNDED_BLOB_RW01_F4_POC" if kind == "git-blob" else "BOUNDED_SHA256_RW01_F4_POC",
     "BOUNDED_BLOB_CP2_STRICT_TENANT" if kind == "git-blob" else "BOUNDED_SHA256_CP2_STRICT_TENANT", NEW_BLOB if kind == "git-blob" else NEW_SHA256,
     CP2_BLOB if kind == "git-blob" else CP2_SHA256)
    for path, kind, *_ in CROSSWALK)


@pytest.mark.parametrize("path,kind,old_name,new_name,old_value,new_value", CP2_CROSSWALK)
def test_cp2_crosswalk_every_pinned_assertion_keeps_the_e1_value_as_history_and_pins_exactly_one_new_value(path, kind, old_name, new_name, old_value, new_value):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert re.search(rf'^{old_name} = "{old_value}"', text, re.M), (path, "E-1 pin must stay as a named constant")
    assert re.search(rf'^{new_name} = "{new_value}"', text, re.M), (path, "CP-2 pin must be a named constant")
    assert text.count(old_value) == 1 and text.count(new_value) == 1
    assert new_name in text.replace(f'{new_name} = "{new_value}"', "")  # and it is actually used by an assertion/table
    assert len(new_value) == (64 if kind == "sha256" else 40)
    assert not re.search(r"startswith\(.*(BOUNDED|bounded)|re\.(match|search)\(.*BOUNDED", text), "the pin must not be loosened to a prefix or regex"


@pytest.mark.parametrize("path,kind,old_name,new_name,old_value,new_value", CROSSWALK)
def test_e1_crosswalk_old_and_e1_values_stay_as_named_history(path, kind, old_name, new_name, old_value, new_value):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert re.search(rf'^{old_name} = "{old_value}"', text, re.M) and re.search(rf'^{new_name} = "{new_value}"', text, re.M), path
    assert text.count(old_value) == 1 and text.count(new_value) == 1


def test_e1_crosswalk_new_values_are_the_real_hashes_of_the_edited_file():
    data = cp2_reverse(BOUNDED.read_bytes())  # the E-1 file, reconstructed from the current bytes
    for path, kind, _o, _n, _old, new_value in CROSSWALK:
        assert (sha(data) if kind == "sha256" else blob_id(data)) == new_value, path
    cur = BOUNDED.read_bytes()
    for path, kind, _o, _n, _old, new_value in CP2_CROSSWALK:
        assert (sha(cur) if kind == "sha256" else blob_id(cur)) == new_value, path


# ---------------------------------------------------------------------------------------------------------------------------------------------- negative mutation tests
def _mutations(data: bytes):
    text = data.decode("utf-8")
    yield "one byte flipped in unrelated code", text.replace("def _now() -> datetime:", "def _nox() -> datetime:", 1).encode()
    yield "trailing newline appended", (text + "\n").encode()
    yield "one unrelated line deleted", text.replace("import copy\n", "", 1).encode()
    yield "a comment line inserted", text.replace("import copy\n", "import copy\n# x\n", 1).encode()
    yield "an authorized line altered by one character", text.replace("exclude_if=lambda v: v is None)  # RW-01-F4-PoC", "exclude_if=lambda v: v is not None)  # RW-01-F4-PoC", 1).encode()
    yield "an authorized hook call dropped", text.replace("            selection_evidence=self._decision_selection_evidence(reasons),\n", "", 1).encode()
    yield "the hook body changed to carry something else", text.replace("        return None\n\n    def decide(self, proposal: RuntimeProposal", "        return object()\n\n    def decide(self, proposal: RuntimeProposal", 1).encode()
    yield "a second authorized line duplicated", text.replace(HUNKS[0][1], HUNKS[0][1] * 2, 1).encode()
    yield "a CP-2 strict-tenant line altered", text.replace("or not signed_ok):", "and not signed_ok):", 1).encode()
    yield "a CP-2 hunk dropped (strict branch disabled)", text.replace("if current is not None and tenant_aware and strict_tenant:", "if False:", 1).encode()
    yield "the old file restored (edit reverted)", reverse_apply(data)


def test_e1_negative_mutation_the_updated_tripwire_detects_unrelated_modification():
    data = BOUNDED.read_bytes()
    assert tripwire_ok(data)  # control: the unmodified file passes
    seen = 0
    for name, mutated in _mutations(data):
        assert mutated != data, name  # the mutation really changed something
        assert not tripwire_ok(mutated), name  # the pinned-hash check FAILS
        assert blob_id(mutated) != CP2_BLOB, name
        seen += 1
        if name != "the old file restored (edit reverted)":
            # and the diff-shape check also rejects it: it either cannot be reverse-applied or does not reproduce the OLD file
            try:
                reproduced = sha(reverse_apply(mutated)) == OLD_SHA256
            except AssertionError:
                reproduced = False
            assert not reproduced, name
    assert seen == 11


def _copy_tree(dest: Path, bounded_bytes: bytes) -> Path:
    import shutil
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
    shutil.copytree(ROOT / "src", dest / "src", ignore=ignore)
    shutil.copytree(ROOT / "tests", dest / "tests", ignore=ignore)
    for extra in ("schemas", "pyproject.toml"):
        if (ROOT / extra).is_dir():
            shutil.copytree(ROOT / extra, dest / extra)
        elif (ROOT / extra).is_file():
            shutil.copy(ROOT / extra, dest / extra)
    (dest / "src" / "agent_control_plane" / "bounded.py").write_bytes(bounded_bytes)
    return dest


def _run_real_assertion(tree: Path, nodeid: str, env_extra: dict | None = None):
    import os
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTEST")}
    env.update({"PYTHONPATH": f"{tree / 'src'}{os.pathsep}{tree}{os.pathsep}" + env.get("PYTHONPATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(env_extra or {})
    return subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", "-x", nodeid], cwd=tree, env=env, capture_output=True, text=True)


def test_e1_negative_mutation_runs_the_real_git_blob_assertion_against_a_mutated_copy(tmp_path):
    """The real `test_v02_legacy_claim_vector.py::test_l05_...[bounded.py]` assertion (bytes + `git hash-object`, no Registry needed), run in a copy of the tree: it PASSES
    on the unmodified copy and FAILS when bounded.py differs by one byte."""
    node = "tests/test_v02_legacy_claim_vector.py::test_l05_protected_sources_are_byte_identical_to_the_base[src/agent_control_plane/bounded.py-%s]" % CP2_BLOB
    good = _run_real_assertion(_copy_tree(tmp_path / "good", BOUNDED.read_bytes()), node)
    assert good.returncode == 0 and "1 passed" in good.stdout, good.stdout[-800:]
    mutated = BOUNDED.read_bytes().replace(b"execute one finite declared operation.", b"execute one finite declared operatiox.", 1)  # docstring byte: still importable
    assert mutated != BOUNDED.read_bytes()
    bad = _run_real_assertion(_copy_tree(tmp_path / "bad", mutated), node)
    assert bad.returncode == 1 and "1 failed" in bad.stdout and "changed: V02 must not edit it" in bad.stdout, bad.stdout[-800:]


def test_e1_negative_mutation_runs_the_real_sha256_assertion_against_a_mutated_copy(tmp_path):
    """Same for the F4 file's real `test_s02` sha256 assertion. It needs the Registry pin (module import), so without OCS_REGISTRY_PIN_DIR this is reported NOT RUN."""
    import os
    if not os.environ.get("OCS_REGISTRY_PIN_DIR"):
        pytest.skip("NOT RUN: OCS_REGISTRY_PIN_DIR is not set (the F4 test module needs the Registry pin)")
    node = "tests/test_f4_age_governance.py::test_s02_bounded_module_is_unmodified_by_this_increment"
    good = _run_real_assertion(_copy_tree(tmp_path / "good", BOUNDED.read_bytes()), node)
    assert good.returncode == 0 and "1 passed" in good.stdout, good.stdout[-800:]
    mutated = BOUNDED.read_bytes().replace(b"execute one finite declared operation.", b"execute one finite declared operatiox.", 1)  # docstring byte: still importable
    bad = _run_real_assertion(_copy_tree(tmp_path / "bad", mutated), node)
    assert bad.returncode == 1 and "1 failed" in bad.stdout and "AssertionError" in bad.stdout, bad.stdout[-800:]


# ---------------------------------------------------------------------------------------------------------------------------------------------- no other protected file changed
#: git blob ids of the protected evaluators and the governed F4/F5 consumers at Control Plane b19c47dd (the base of this branch).
PROTECTED_BLOBS_AT_B19C47DD = {
    "runtime_authority.py": "03b4efdfd67c2e384c00ac7342ef3bbf18160811",
    "freshness.py": "0c4647f69ed5bb52d8e1e0e607faf6da061634f2",
    "policy_binding.py": "426d47797e92f19690a21b4e8b5dc1c35d1b579c",
    "rule_revision.py": "9ca71a8db3f790b0dde3127c4f34b563463859cb",
    "reversibility.py": "a6be4bfe555d16b7d40289cef113ae156fd8c843",
    "holder_inventory.py": "248e930437cd6dec682a43bb626ceccf83804b68",
    "registry_f4_age_governance.py": "9f4532ab0df92ace75a5d3020eefe8306494c1fb",
    "registry_f5_class_age_governance.py": "86076b4a3d20c4dd72c26c313c074660cd1a5ee6",
    "registry_f5_class_unreadable_governance.py": "dae2cf5c1c53d93573342dab382bd88806266b1b",
    "registry_governed_policy.py": "e677b80abe47ec51467a32b43158949d47c03416",
    "effective_configuration_binding.py": "0e2ab1d2fe8917ec9ec6bdd5a47a966880ab2fb0",
}


@pytest.mark.parametrize("name,blob", sorted(PROTECTED_BLOBS_AT_B19C47DD.items()))
def test_e1_no_other_protected_file_changed(name, blob):
    assert blob_id((SRC / name).read_bytes()) == blob, name


def test_e1_exactly_the_authorized_source_inventory_is_new_or_changed():
    """The authorized inventory: one new module and two edited modules. The edited lifecycle module and the new module are checked by content tests elsewhere (they are not
    byte-pinned: they are the implementation). This test pins that bounded.py is the ONLY protected evaluator edited and that the F4 consumer module is byte-unchanged."""
    assert (SRC / "selection_evidence.py").is_file()
    assert blob_id((SRC / "registry_f4_age_governance.py").read_bytes()) == PROTECTED_BLOBS_AT_B19C47DD["registry_f4_age_governance.py"]


# ---------------------------------------------------------------------------------------------------------------------------------------------- addendum: a SEVENTH pin
def test_e1_addendum_the_seventh_pinned_assertion_found_in_test_f5_class_age_governance_keeps_its_old_value():
    """`tests/test_f5_class_age_governance.py` (PROTECTED['bounded.py']) also pinned bounded.py; it was not in the Phase-0 list of six. Re-pinned the same way; needs ratification."""
    text = (ROOT / "tests/test_f5_class_age_governance.py").read_text(encoding="utf-8")
    assert re.search(rf'^BOUNDED_SHA256_BEFORE_RW01_F4_POC = "{OLD_SHA256}"', text, re.M)
    assert re.search(rf'^BOUNDED_SHA256_RW01_F4_POC = "{NEW_SHA256}"', text, re.M)
    assert text.count(OLD_SHA256) == 1 and text.count(NEW_SHA256) == 1
