"""Command-line utilities for exported run records and replay bundles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence, TypeVar

from pydantic import BaseModel, ValidationError

from agent_control_plane.cli_run import add_run_parser, run_command
from agent_control_plane.strict_json import strict_loads
from agent_control_plane.witness import add_witness_parser, witness_command
from agent_control_plane.models import (
    RedactionConfig,
    ReplayBundle,
    RunRecord,
    SignedReplayBundle,
    ValidationReport,
)
from agent_control_plane.redaction import redact_replay_bundle, redact_run_record
from agent_control_plane.signing import (
    sign_replay_bundle,
    verify_signed_replay_bundle,
)
from agent_control_plane.validation import validate_replay_bundle, validate_run_record

ModelT = TypeVar("ModelT", bound=BaseModel)


class _InvalidJsonError(ValueError):
    pass


class _ModelValidationError(ValueError):
    pass


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="acp")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_run = subparsers.add_parser("validate-run")
    validate_run.add_argument("path")

    validate_replay = subparsers.add_parser("validate-replay")
    validate_replay.add_argument("path")

    redact_run = subparsers.add_parser("redact-run")
    redact_run.add_argument("path")
    redact_run.add_argument("--out", required=True)
    _add_redaction_flags(redact_run)

    redact_replay = subparsers.add_parser("redact-replay")
    redact_replay.add_argument("path")
    redact_replay.add_argument("--out", required=True)
    _add_redaction_flags(redact_replay)

    sign_replay = subparsers.add_parser("sign-replay")
    sign_replay.add_argument("path")
    sign_replay.add_argument("--secret", required=True)
    sign_replay.add_argument("--out", required=True)

    verify_signed = subparsers.add_parser("verify-signed-replay")
    verify_signed.add_argument("path")
    verify_signed.add_argument("--secret", required=True)

    add_run_parser(subparsers)
    add_witness_parser(subparsers)

    return parser


def _add_redaction_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--targets", action="store_true")
    parser.add_argument("--final-output", action="store_true")
    parser.add_argument("--reasons", action="store_true")
    parser.add_argument("--replacement", default="[REDACTED]")


def _load_json_model(path: str | Path, model_type: type[ModelT]) -> ModelT:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        payload = strict_loads(file_path.read_bytes())
    except (ValueError, RecursionError) as exc:  # includes json.JSONDecodeError and the strict refusals
        raise _InvalidJsonError(f"Invalid JSON in {file_path}: {exc}") from exc
    try:
        return model_type.model_validate(payload)
    except ValidationError as exc:
        raise _ModelValidationError(
            f"Validation failed for {file_path}: {exc}"
        ) from exc


def _write_json_model(path: str | Path, model: BaseModel) -> Path:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(model.model_dump(mode="json"), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def _redaction_config_from_args(args: argparse.Namespace) -> RedactionConfig:
    return RedactionConfig(
        redact_payloads=True,
        redact_targets=args.targets,
        redact_final_output=args.final_output,
        redact_reasons=args.reasons,
        replacement=args.replacement,
    )


def _print_validation_report(report: ValidationReport) -> None:
    error_count = sum(1 for issue in report.issues if issue.severity == "error")
    warning_count = sum(1 for issue in report.issues if issue.severity == "warning")
    status = "valid" if report.valid else "invalid"
    print(
        f"{report.checked_object_type} {report.checked_id}: {status} "
        f"({error_count} errors, {warning_count} warnings)"
    )
    for issue in report.issues:
        location = f" {issue.path}" if issue.path else ""
        print(f"{issue.severity.upper()} {issue.code}{location}: {issue.message}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    if args.command == "run":
        return run_command(args, sys.stderr)
    if args.command == "witness":
        return witness_command(args, sys.stdout, sys.stderr)

    try:
        if args.command == "validate-run":
            record = _load_json_model(args.path, RunRecord)
            report = validate_run_record(record)
            _print_validation_report(report)
            return 0 if report.valid else 1

        if args.command == "validate-replay":
            bundle = _load_json_model(args.path, ReplayBundle)
            report = validate_replay_bundle(bundle)
            _print_validation_report(report)
            return 0 if report.valid else 1

        if args.command == "redact-run":
            record = _load_json_model(args.path, RunRecord)
            output_path = _write_json_model(
                args.out,
                redact_run_record(record, _redaction_config_from_args(args)),
            )
            print(f"Redacted run record written to {output_path}.")
            return 0

        if args.command == "redact-replay":
            bundle = _load_json_model(args.path, ReplayBundle)
            output_path = _write_json_model(
                args.out,
                redact_replay_bundle(bundle, _redaction_config_from_args(args)),
            )
            print(f"Redacted replay bundle written to {output_path}.")
            return 0

        if args.command == "sign-replay":
            bundle = _load_json_model(args.path, ReplayBundle)
            signed_bundle = sign_replay_bundle(bundle, args.secret)
            output_path = _write_json_model(args.out, signed_bundle)
            print(f"Signed replay bundle written to {output_path}.")
            return 0

        if args.command == "verify-signed-replay":
            signed_bundle = _load_json_model(args.path, SignedReplayBundle)
            if verify_signed_replay_bundle(signed_bundle, args.secret):
                print("Signed replay bundle is valid.")
                return 0
            print("Signed replay bundle verification failed.", file=sys.stderr)
            return 1
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except _InvalidJsonError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except _ModelValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    parser.print_help(sys.stderr)
    return 2
