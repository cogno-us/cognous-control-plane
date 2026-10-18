"""Helpers for loading lightweight JSON policy configuration."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from agent_control_plane.frame import create_frame
from agent_control_plane.models import AuthorityRecord, Frame
from agent_control_plane.strict_json import strict_loads


class PolicyConfig(BaseModel):
    """Simple JSON-backed policy configuration."""

    policy_version: str
    allowed_tools: list[str]
    blocked_tools: list[str]
    authority_required: dict[str, list[str]] = Field(default_factory=dict)
    default_action: Literal["allow", "block", "escalate"] = "escalate"


def load_policy_config(path: str | Path) -> PolicyConfig:
    """Load and validate a policy config from JSON."""

    config_path = Path(path)
    try:
        raw = strict_loads(config_path.read_bytes())
    except FileNotFoundError:
        raise
    except (ValueError, RecursionError) as exc:  # includes json.JSONDecodeError and the strict refusals
        raise ValueError(f"Failed to parse policy config JSON: {exc}") from exc

    try:
        return PolicyConfig.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"Invalid policy config: {exc}") from exc


def frame_from_policy_config(
    config: PolicyConfig,
    *,
    task: str,
    actor: str,
    environment: str,
) -> Frame:
    """Create a frame from a validated policy config."""

    return create_frame(
        task=task,
        actor=actor,
        environment=environment,
        allowed_tools=config.allowed_tools,
        blocked_tools=config.blocked_tools,
        policy_version=config.policy_version,
    )


def authority_records_from_policy_config(
    config: PolicyConfig,
    *,
    run_id: str,
    actor: str,
    source: str = "policy_config",
    expires_at: str | None = None,
) -> list[AuthorityRecord]:
    """Create authority records from the authority requirements in a policy config."""

    return [
        AuthorityRecord(
            authority_id=str(uuid.uuid4()),
            run_id=run_id,
            actor=actor,
            scope=list(scopes),
            source=source,
            expires_at=expires_at,
        )
        for _action_type, scopes in config.authority_required.items()
    ]
