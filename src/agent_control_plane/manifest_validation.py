"""Error rules of the action-manifest validator, applied to the manifest dict the decision gate holds (scan 6, CP-5).

The action-manifest runtime consumption contract (cognous-action-manifest, ``docs/runtime_consumption_contract.md``) says a consumer
runs ``validate_manifest`` and treats an invalid manifest as a mismatch (``invalid_manifest``). The Control Plane holds the manifest
as a plain dict and does not depend on the ``agent_action_manifest`` package, so this module is an in-tree port of that validator's
**error** rules (E001-E025; warnings are advisory and are not ported). ``tests/test_scan6_manifest_validator_parity.py`` compares it
with the real validator when that package is installed.

Not ported: the Pydantic schema (unknown members, wrong member types). A member of the wrong type is skipped by the rule that would
read it; the gate's own checks already refuse the shapes they consume. Identity strings are compared exactly, never normalised.
A member of the wrong type never raises: membership tests are guarded by type, and ``manifest_errors`` maps any unexpected exception to
``E999`` (a port-internal code, not a validator rule) so the gate fails closed with ``invalid_manifest``.
Returns codes only; it never authorizes anything.
"""
from __future__ import annotations

SUPPORTED_VERSIONS = frozenset({"1.0", "1.1"})
_EFFECTFUL = frozenset({"write", "external_send", "delete", "export", "purchase", "approve"})
_HIGH_RISK = frozenset({"external_send", "delete", "export", "purchase", "approve"})
_UNMATCHED = object()  # a tool_name of the wrong type matches no tool (E006)
_PRIVILEGED = frozenset({"write", "delete", "export", "purchase", "approve"})


def is_exact_identifier(value: object) -> bool:
    """Non-blank, no surrounding whitespace, no control characters (the action-manifest predicate)."""
    return (isinstance(value, str) and bool(value) and value == value.strip()
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))


def _dicts(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _blank(value: object) -> bool:
    """A present string that is empty or whitespace. An absent or non-string member is a schema error, which this port does not model."""
    return isinstance(value, str) and not value.strip()


def _has_required_authority(action: dict) -> bool:
    return any(item.get("required", True) is True and isinstance(item.get("scope"), str) and item["scope"].strip()
               for item in _dicts(action.get("authority_required")))


def _str_or_none(value: object) -> str | None:
    """The value when it is a string, else None: an unhashable or non-string member never reaches a membership test."""
    return value if isinstance(value, str) else None


def _field_set(value: object) -> set:
    """A payload-policy field list as a set; a non-list, or a list with a non-string entry, is a schema error this port does not model."""
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def manifest_errors(manifest: dict) -> list[str]:
    """Sorted, de-duplicated validator error codes (``E001``...) for a manifest dict; empty when the validator reports none.

    Fails closed: an unexpected exception from a malformed manifest is reported as ``E999``, never raised.
    """
    try:
        return _manifest_errors(manifest)
    except Exception:  # noqa: BLE001 - fail closed on any malformed shape
        return ["E999"]


def _manifest_errors(manifest: dict) -> list[str]:
    errors: set[str] = set()
    version = manifest.get("manifest_version")
    if _blank(version):
        errors.add("E001")
    elif not isinstance(version, str) or version not in SUPPORTED_VERSIONS:
        errors.add("E016")
    if _blank(manifest.get("manifest_id")):
        errors.add("E002")
    if _blank(manifest.get("agent_name")):
        errors.add("E003")

    actions, tools = _dicts(manifest.get("actions")), _dicts(manifest.get("tools"))
    action_names = [a.get("action_name") for a in actions if isinstance(a.get("action_name"), str)]
    if len(action_names) != len(set(map(repr, action_names))):
        errors.add("E004")
    tool_names = [t.get("tool_name") for t in tools if isinstance(t.get("tool_name"), str)]
    if len(tool_names) != len(set(map(repr, tool_names))):
        errors.add("E005")
    tools_by_name: dict = {}
    for tool in tools:
        if tool.get("tool_name") is None or isinstance(tool.get("tool_name"), str):
            tools_by_name.setdefault(tool.get("tool_name"), tool)
    manifest_default = manifest.get("default_action", "escalate")

    v11 = version == "1.1"
    if v11:
        ids = [a.get("action_id") for a in actions if a.get("action_id")]
        if len(ids) != len(set(map(repr, ids))):
            errors.add("E017")

    for action in actions:
        default = action.get("default_action") or manifest_default
        action_type = _str_or_none(action.get("action_type"))
        action_tool_name = action.get("tool_name")
        action_tool_name = action_tool_name if action_tool_name is None or isinstance(action_tool_name, str) else _UNMATCHED
        tool = tools_by_name.get(action_tool_name)
        if v11:
            if not action.get("action_id"):
                errors.add("E018")
            if action.get("action_id") and not is_exact_identifier(action.get("action_id")):
                errors.add("E024")
            policy = action.get("target_policy")
            if isinstance(policy, dict):
                targets = policy.get("allowed_targets", [])
                if isinstance(targets, list):
                    if not all(is_exact_identifier(t) for t in targets):
                        errors.add("E024")
                    if len(targets) != len(set(map(repr, targets))):
                        errors.add("E025")
            if tool is not None and tool.get("adapter_id") and not is_exact_identifier(tool.get("adapter_id")):
                errors.add("E024")
            if tool is not None and not tool.get("adapter_id"):
                errors.add("E019")
            if action_type in _EFFECTFUL and default != "block":
                targets = policy.get("allowed_targets", []) if isinstance(policy, dict) else []
                if (not isinstance(policy, dict) or policy.get("allow_any_target", False) is not False or not targets):
                    errors.add("E020")
                if action.get("authority_context") is None:
                    errors.add("E021")
                limits = action.get("effect_limits")
                if limits is None:
                    errors.add("E022")
                elif isinstance(limits, dict):
                    unit = limits.get("unit")
                    has_unit = isinstance(unit, str) and unit.strip() != ""
                    max_amount = limits.get("max_amount")
                    if max_amount is None or not (has_unit or max_amount == 0):
                        errors.add("E023")

        if action_tool_name not in tools_by_name:
            errors.add("E006")
        elif tools_by_name[action_tool_name].get("allowed", True) is False and default != "block":
            errors.add("E015")

        if action_type == "external_send" and not _has_required_authority(action) and default != "block":
            errors.add("E007")
        if action_type in _PRIVILEGED and not _has_required_authority(action) and default != "block":
            errors.add("E008")

        policy = action.get("payload_policy")
        if isinstance(policy, dict):
            fields = {name: _field_set(policy.get(name))
                      for name in ("required_fields", "optional_fields", "sensitive_fields", "forbidden_fields")}
            if fields["forbidden_fields"] & fields["required_fields"]:
                errors.add("E009")
            if fields["forbidden_fields"] & fields["optional_fields"]:
                errors.add("E010")
            allowed_fields = fields["required_fields"] | fields["optional_fields"]
            if allowed_fields and fields["sensitive_fields"] - allowed_fields:
                errors.add("E011")

        for hint in _dicts(action.get("redaction_hints")):
            if _blank(hint.get("field_path")):
                errors.add("E012")

        review = action.get("review_requirement")
        if isinstance(review, dict) and review.get("mode") == "approval_required" and not review.get("reviewer_role"):
            errors.add("E013")

        if default == "allow" and action_type in _HIGH_RISK:
            review_mode = review.get("mode", "none") if isinstance(review, dict) else "none"
            if not _has_required_authority(action) or review_mode == "none":
                errors.add("E014")
    return sorted(errors)
