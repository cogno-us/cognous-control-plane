"""``acp run``: execute one declared bounded operation against a local throwaway store.

Runs the real :class:`BoundedAuthorizationWorkflow` (decide, effect-time
revalidation, execute, reconcile) with a :class:`SyntheticResolver` built from
declared JSON files and the repository's :class:`LocalRefundDestination`. It
contacts no network and writes only inside the declared store and output
directories.

Exit codes: 0 authorized and applied; 1 held or refused (the blocking
decision); 2 invalid input or path refusal; 4 internal or execution error.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from agent_control_plane.bounded import (
    ApprovalStatus,
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    ConflictStatus,
    EvidenceStatus,
    GrantStatus,
    IdentityStatus,
    LocalRefundDestination,
    MandateStatus,
    ObservationPolicy,
    PolicyStatus,
    RoleMappingStatus,
    RuntimeProposal,
    SyntheticResolver,
    commitment,
)
from agent_control_plane.models import (
    ActionProposal,
    AuthorityRecord,
    BlockedAction,
    Frame,
    PolicyDecision,
    RunRecord,
)

ENVELOPE_VERSION = "1"
MAX_INPUT_BYTES = 1024 * 1024
VERDICT_SOURCE = {
    "component": "control-plane",
    "contract": "bounded-authorization-effect",
    "contract_version": "0.1",
}
DOES_NOT_PROVE = [
    "institutional authority: the resolver is synthetic and not authenticated",
    "real-world effect: the destination is a local file, not a provider",
    "exactly-once delivery or a safe retry",
    "producer authenticity of the input files",
    "that run-record.json is anything more than a projection of bounded-run-record.json",
]

RESOLVER_SECTIONS: dict[str, type[BaseModel]] = {
    "statuses": GrantStatus,
    "identities": IdentityStatus,
    "mandates": MandateStatus,
    "approvals": ApprovalStatus,
    "policies": PolicyStatus,
    "conflicts": ConflictStatus,
    "evidence": EvidenceStatus,
    "role_mappings": RoleMappingStatus,
}


class InvalidInput(ValueError):
    """Declared input or path refused; maps to exit code 2."""


def add_run_parser(subparsers: Any) -> None:
    run = subparsers.add_parser(
        "run",
        help="Execute one declared bounded operation against a local throwaway store.",
    )
    run.add_argument("--manifest", required=True, help="Manifest JSON the proposal is bound to.")
    run.add_argument("--proposal", required=True, help="RuntimeProposal JSON.")
    run.add_argument("--authority-context", required=True, help="Authority Context JSON (carries the grant).")
    run.add_argument(
        "--resolver-state",
        required=True,
        help="JSON with statuses, identities, mandates, approvals, policies, conflicts, evidence, role_mappings.",
    )
    run.add_argument("--store-dir", required=True, help="New or empty directory for the throwaway store.")
    run.add_argument("--out-dir", required=True, help="New or empty directory for run-record.json and result.json.")
    run.add_argument(
        "--now",
        default=None,
        help="Timezone-aware ISO-8601 evaluation time; recorded as time_source=test_override. "
        "Default is the real clock.",
    )
    run.add_argument("--format", choices=("text", "json"), default="text")


class _ClockedDestination(LocalRefundDestination):
    """Local destination whose observations carry the declared evaluation time.

    Used only with ``--now``: the destination otherwise stamps observations with
    the real clock, which a declared test time cannot reconcile against.
    """

    def __init__(self, path: Path, clock: datetime):
        super().__init__(path)
        self._clock = clock

    def observe(self, effect_id: str):
        observation = super().observe(effect_id)
        return observation.model_copy(update={"observed_at": self._clock.isoformat()})


# --------------------------------------------------------------------------- #
# Path discipline                                                              #
# --------------------------------------------------------------------------- #


def _lexical_abs(raw: str) -> Path:
    if "\r" in raw or "\n" in raw or "\0" in raw:
        raise InvalidInput("path contains a CR, LF or NUL character")
    return Path(os.path.abspath(raw))


def _refuse_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise InvalidInput(f"path has a symlink component: {current}")


def _input_file(raw: str, label: str) -> Path:
    path = _lexical_abs(raw)
    _refuse_symlink_components(path)
    if not path.is_file():
        raise InvalidInput(f"{label}: file not found or not a regular file")
    if path.stat().st_nlink > 1:
        raise InvalidInput(f"{label}: hard-linked file refused")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InvalidInput(f"{label}: file larger than {MAX_INPUT_BYTES} bytes")
    return path


def _output_dir(raw: str, label: str) -> Path:
    path = _lexical_abs(raw)
    _refuse_symlink_components(path)
    if not path.parent.is_dir():
        raise InvalidInput(f"{label}: parent directory does not exist (parents are not created)")
    if path.exists():
        if not path.is_dir():
            raise InvalidInput(f"{label}: exists and is not a directory")
        if any(path.iterdir()):
            raise InvalidInput(f"{label}: directory is not empty")
    return path


def _inside(child: Path, parent: Path) -> bool:
    return child == parent or parent in child.parents


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidInput(f"{label}: invalid JSON: {exc}") from exc


def _model(model_type: type[BaseModel], payload: Any, label: str) -> Any:
    if not isinstance(payload, dict):
        raise InvalidInput(f"{label}: expected a JSON object")
    unknown = sorted(set(payload) - set(model_type.model_fields))
    if unknown:
        raise InvalidInput(f"{label}: unknown members refused: {', '.join(unknown)}")
    try:
        return model_type.model_validate(payload)
    except ValidationError as exc:
        raise InvalidInput(f"{label}: {exc.error_count()} validation error(s): {exc.errors()[0]['loc']}") from exc


def _resolver(state: Any, context: dict, proposal: RuntimeProposal) -> SyntheticResolver:
    if not isinstance(state, dict):
        raise InvalidInput("resolver-state: expected a JSON object")
    unknown = sorted(set(state) - set(RESOLVER_SECTIONS))
    if unknown:
        raise InvalidInput(f"resolver-state: unknown sections refused: {', '.join(unknown)}")
    sections: dict[str, dict] = {}
    for name, model_type in RESOLVER_SECTIONS.items():
        raw = state.get(name, {})
        if not isinstance(raw, dict):
            raise InvalidInput(f"resolver-state.{name}: expected a JSON object")
        sections[name] = {
            key: _model(model_type, value, f"resolver-state.{name}[{key!r}]") for key, value in raw.items()
        }
    if not proposal.authority_context_ref:
        raise InvalidInput("proposal: authority_context_ref is required")
    return SyntheticResolver(
        contexts={proposal.authority_context_ref: context},
        statuses=sections["statuses"],
        identities=sections["identities"],
        mandates=sections["mandates"],
        approvals=sections["approvals"],
        policies=sections["policies"],
        conflicts=sections["conflicts"],
        evidence=sections["evidence"],
        role_mappings=sections["role_mappings"],
    )


def _parse_now(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise InvalidInput(f"--now: not an ISO-8601 time: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidInput("--now: must be timezone-aware")
    return parsed.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# Output                                                                       #
# --------------------------------------------------------------------------- #


def _write_atomic(directory: Path, name: str, document: Any) -> Path:
    target = directory / name
    fd, tmp = tempfile.mkstemp(prefix=name + ".", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def _projection(proposal: RuntimeProposal, decision, native: dict, outcome: dict) -> RunRecord:
    """Project the bounded rows onto a RunRecord that `acp validate-run` accepts."""
    run_id = native["run_id"]
    blocked_reasons = outcome["reason_codes"]
    allowed = decision.result == "authorized" and not blocked_reasons
    fingerprint = commitment(
        {"effect_id": decision.effect_id, "result": decision.result, "reasons": decision.reasons}
    ).removeprefix("sha256:")
    policy_name = f"{VERDICT_SOURCE['contract']}/{VERDICT_SOURCE['contract_version']}"
    action = ActionProposal(
        action_id=proposal.action_id,
        run_id=run_id,
        tool_name=proposal.adapter_id,
        action_type="bounded_effect",
        target=proposal.target,
        payload=proposal.payload,
        proposed_at=decision.decided_at,
        reason="; ".join(proposal.requested_permissions) or None,
    )
    policy_decision = PolicyDecision(
        decision_id=decision.decision_id,
        action_id=proposal.action_id,
        run_id=run_id,
        result="allow" if allowed else "block",
        policy_name=policy_name,
        reason="authorized and applied" if allowed else ("; ".join(blocked_reasons) or "blocked"),
        decided_at=decision.decided_at,
        deterministic_fingerprint=fingerprint,
    )
    blocked = []
    if not allowed:
        blocked.append(BlockedAction(
            blocked_id=(native["refusals"][-1]["refusal_id"] if native["refusals"] else str(uuid.uuid4())),
            action_id=proposal.action_id,
            run_id=run_id,
            reason="; ".join(blocked_reasons) or "blocked",
            policy_name=policy_name,
            blocked_at=decision.decided_at,
        ))
    authority = []
    binding = decision.binding
    if binding is not None:
        authority.append(AuthorityRecord(
            authority_id=f"{binding.grant_id}@{binding.grant_revision}",
            run_id=run_id,
            actor=proposal.actor,
            scope=list(proposal.requested_permissions),
            expires_at=None,
            source="bounded-grant",
            created_at=decision.decided_at,
        ))
    return RunRecord(
        run_id=run_id,
        task=f"bounded operation {proposal.action_id}",
        created_at=decision.decided_at,
        frame=Frame(
            frame_id=f"frame-{run_id}",
            task=f"bounded operation {proposal.action_id}",
            actor=proposal.actor,
            environment="synthetic-local",
            allowed_tools=(proposal.adapter_id,),
            blocked_tools=(),
            policy_version=policy_name,
            created_at=decision.decided_at,
        ),
        actions=[action],
        decisions=[policy_decision],
        authority_records=authority,
        blocked_actions=blocked,
        completed=True,
        final_output=outcome["summary"],
    )


def _envelope(exit_code: int, outcome: dict, proposal_path: str, extensions: dict) -> dict:
    return {
        "envelope_version": ENVELOPE_VERSION,
        "command": "run",
        "outcome": {0: "pass", 1: "fail", 2: "invalid", 4: "fail"}[exit_code],
        "exit_code": exit_code,
        "reason_codes": outcome["reason_codes"],
        "subject": {"kind": "bounded-run-input", "path": os.path.basename(proposal_path)},
        "verdict_source": dict(VERDICT_SOURCE),
        "does_not_prove": list(DOES_NOT_PROVE),
        "messages": [outcome["summary"]],
        "extensions": {"x-acp-run": extensions},
    }


def _emit(envelope: dict, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(envelope, indent=2, ensure_ascii=False))
        return
    print(f"acp run: {envelope['outcome']} (exit {envelope['exit_code']})")
    for message in envelope["messages"]:
        print(f"  {message}")
    if envelope["reason_codes"]:
        print("  reason codes: " + ", ".join(envelope["reason_codes"]))
    ext = envelope["extensions"]["x-acp-run"]
    for key in ("time_source", "effect_id", "attempt_status", "out_dir"):
        if ext.get(key) is not None:
            print(f"  {key}: {ext[key]}")
    print("  does not prove:")
    for item in envelope["does_not_prove"]:
        print(f"    - {item}")


# --------------------------------------------------------------------------- #
# Command                                                                      #
# --------------------------------------------------------------------------- #


def run_command(args: Any, stderr: Any) -> int:
    """Return the exit code; never raises for declared-input problems."""
    try:
        paths = {
            "manifest": _input_file(args.manifest, "--manifest"),
            "proposal": _input_file(args.proposal, "--proposal"),
            "context": _input_file(args.authority_context, "--authority-context"),
            "state": _input_file(args.resolver_state, "--resolver-state"),
        }
        store_dir = _output_dir(args.store_dir, "--store-dir")
        out_dir = _output_dir(args.out_dir, "--out-dir")
        if _inside(store_dir, out_dir) or _inside(out_dir, store_dir):
            raise InvalidInput("--store-dir and --out-dir must be separate, non-nested directories")
        for label, path in paths.items():
            if _inside(path, store_dir) or _inside(path, out_dir):
                raise InvalidInput(f"input {label} must not live inside a declared output directory")
        now = _parse_now(args.now)
        manifest = _load_json(paths["manifest"], "manifest")
        if not isinstance(manifest, dict):
            raise InvalidInput("manifest: expected a JSON object")
        proposal = _model(RuntimeProposal, _load_json(paths["proposal"], "proposal"), "proposal")
        context = _load_json(paths["context"], "authority-context")
        if not isinstance(context, dict):
            raise InvalidInput("authority-context: expected a JSON object")
        resolver = _resolver(_load_json(paths["state"], "resolver-state"), context, proposal)
        if proposal.manifest_digest != commitment(manifest):
            raise InvalidInput("proposal.manifest_digest does not match the supplied manifest")
    except InvalidInput as exc:
        print(f"acp run: invalid input: {exc}", file=stderr)
        return 2
    except OSError as exc:
        print(f"acp run: cannot read input: {type(exc).__name__}", file=stderr)
        return 2

    ext: dict[str, Any] = {
        "time_source": "test_override" if now else "control_plane",
        "resolver": "synthetic (SyntheticResolver, not authenticated)",
        "destination": "LocalRefundDestination (local file in store dir)",
        "network": "none",
        "out_dir": str(out_dir),
        "store_dir": str(store_dir),
        "effect_id": None,
        "decision_id": None,
        "attempt_status": None,
    }
    exit_code = 4
    outcome = {"reason_codes": ["internal_error"], "summary": "internal error before a decision"}
    try:
        store_dir.mkdir(exist_ok=True)
        out_dir.mkdir(exist_ok=True)
        run_id = proposal.run_id or f"run-{uuid.uuid4()}"
        records = BoundedRecordStore(store_dir / "bounded-run-record.json", run_id)
        destination = (
            _ClockedDestination(store_dir / "destination.json", now)
            if now is not None
            else LocalRefundDestination(store_dir / "destination.json")
        )
        workflow = BoundedAuthorizationWorkflow(
            manifest=manifest,
            resolver=resolver,
            destination=destination,
            records=records,
            observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
            allow_test_time=now is not None,
        )
        decision = workflow.decide(proposal, now=now)
        ext["effect_id"] = decision.effect_id
        ext["decision_id"] = decision.decision_id
        if decision.result != "authorized":
            exit_code = 1
            outcome = {
                "reason_codes": list(decision.reasons),
                "summary": "held: the control plane did not authorize the operation; nothing was applied",
            }
        else:
            try:
                attempt, observation = workflow.execute(
                    proposal, decision, adapter_id=proposal.adapter_id, now=now
                )
            except PermissionError as exc:
                refusals = records.load().refusals
                exit_code = 1
                outcome = {
                    "reason_codes": sorted(set(refusals[-1].reasons)) if refusals else ["execution_refused"],
                    "summary": f"refused at effect time ({exc}); nothing was applied",
                }
            else:
                ext["attempt_status"] = attempt.status
                if attempt.status == "acknowledged" and observation is not None and observation.state == "applied":
                    exit_code = 0
                    outcome = {
                        "reason_codes": [],
                        "summary": "authorized and applied to the local synthetic destination",
                    }
                elif attempt.status == "failed":
                    exit_code = 1
                    outcome = {
                        "reason_codes": [attempt.error or "destination_rejected"],
                        "summary": "authorized, but the destination definitively rejected the effect",
                    }
                else:
                    exit_code = 4
                    outcome = {
                        "reason_codes": [attempt.error or f"attempt_{attempt.status}"],
                        "summary": f"authorized; effect outcome is {attempt.status}, not an applied effect",
                    }
        native = json.loads(records.path.read_text(encoding="utf-8"))
        ext["destination_effects"] = len(destination.snapshot()["effects"])
        projection = _projection(proposal, decision, native, outcome)
        _write_atomic(out_dir, "bounded-run-record.json", native)
        _write_atomic(out_dir, "run-record.json", projection.model_dump(mode="json"))
        ext["files"] = ["bounded-run-record.json", "run-record.json", "result.json"]
        ext["run_record_hash"] = "sha256:" + hashlib.sha256(
            json.dumps(projection.model_dump(mode="json"), sort_keys=True).encode()
        ).hexdigest()
    except Exception as exc:  # noqa: BLE001 - exit 4 is the internal-error contract
        exit_code = 4
        outcome = {"reason_codes": ["internal_error"], "summary": f"internal error: {type(exc).__name__}"}
        ext["error_type"] = type(exc).__name__

    envelope = _envelope(exit_code, outcome, args.proposal, ext)
    try:
        _write_atomic(out_dir, "result.json", envelope)
        if exit_code != 0:
            _write_atomic(out_dir, "ci-diagnostics.json", {
                "envelope_version": ENVELOPE_VERSION,
                "outcome": envelope["outcome"],
                "exit_code": exit_code,
                "reason_codes": envelope["reason_codes"],
                "report_paths": ["result.json"],
            })
    except OSError:
        print("acp run: could not write result.json", file=stderr)
        exit_code = 4
        envelope["exit_code"] = 4
    _emit(envelope, args.format)
    return exit_code
