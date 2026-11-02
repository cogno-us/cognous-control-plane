"""Optional carriage of the exact Registry F4 selection bytes inside a `RuntimeDecision` (RW-01-F4-PoC, Register #259, parent #254).

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authentication mechanism and NOT an authorization input.

What this is: a frozen, closed (`extra="forbid"`) record of the two texts a host selection source returned and that Registry verified in the SAME `decide()` call
(`record_text`, `selection_text`), plus the identifiers a later independent verifier needs to replay Registry on exactly those bytes (`contract_version`, `family`,
`operation_id`) and the instant passed to Registry (`verified_at`, informational).

What this is not (claim scope, stated so nobody reads more into the field):
  * CARRIAGE IS NOT AUTHENTICATION. The Control Plane decision that carries these bytes is NOT authenticated by them: a Registry signature covers the selection statement, not
    any Control Plane decision member. Claim A only ("this exact signed selection governed this decision at `verified_at`"), and only for a party that re-verifies the
    bytes with its OWN trust inputs, verification time and host ages. Claim B (the decision is authentic) is not made.
  * Nothing here is a trust snapshot, a verdict, an `authenticated` flag, an issuer claim or any signature-derived value. The model has no such field and refuses
    unknown members, so none can ride along.
  * The field is read by no gate: `execute`, the commit gate, the effect identity and the authorization binding never inspect it.

Texts are exact `str`; each must be UTF-8 encodable and at most `MAX_TEXT_BYTES` (= Registry `MAX_DOCUMENT_BYTES`, so a text Registry accepted always fits).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, StrictStr, ValidationError, field_validator

VERSION = "selection-evidence/0.1"
CONTRACT_VERSION = "r08-v2"
FAMILY_F4 = "f4-control-plane-age-bounds"
MAX_TEXT_BYTES = 65536

CODE_MALFORMED = "selection_evidence_malformed"
CODE_TOO_LARGE = "selection_evidence_too_large"


class SelectionEvidenceRefused(ValueError):
    """Typed refusal to construct evidence. `code` is one of `CODE_MALFORMED`, `CODE_TOO_LARGE`; the message is the code only (no input is echoed)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _checked_text(value: str) -> str:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError(CODE_MALFORMED) from None
    if size > MAX_TEXT_BYTES:
        raise ValueError(CODE_TOO_LARGE)
    return value


class SelectionEvidence(BaseModel):
    """The exact selection bytes that governed one authorized decision. Unauthenticated by itself; see the module docstring."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal["selection-evidence/0.1"] = VERSION
    contract_version: Literal["r08-v2"]
    family: Literal["f4-control-plane-age-bounds"]
    operation_id: StrictStr
    verified_at: StrictStr
    record_text: StrictStr
    selection_text: StrictStr

    def __init__(self, **data: Any):
        try:
            super().__init__(**data)
        except ValidationError as exc:
            msgs = " ".join(str(err.get("msg", "")) for err in exc.errors())
            raise SelectionEvidenceRefused(CODE_TOO_LARGE if CODE_TOO_LARGE in msgs and CODE_MALFORMED not in msgs else CODE_MALFORMED) from None

    @field_validator("operation_id")
    @classmethod
    def _operation_id(cls, value: str) -> str:
        if not value:
            raise ValueError(CODE_MALFORMED)
        return _checked_text(value)

    @field_validator("verified_at")
    @classmethod
    def _verified_at(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            raise ValueError(CODE_MALFORMED) from None
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            raise ValueError(CODE_MALFORMED)
        return value

    @field_validator("record_text", "selection_text")
    @classmethod
    def _texts(cls, value: str) -> str:
        return _checked_text(value)


def for_f4(*, record_text: Any, selection_text: Any, operation_id: Any, verified_at: datetime) -> SelectionEvidence:
    """Build the F4 evidence from the two verified texts. Raises `SelectionEvidenceRefused` (never an untyped exception) when they cannot be represented."""
    if not isinstance(verified_at, datetime) or verified_at.tzinfo is None:
        raise SelectionEvidenceRefused(CODE_MALFORMED)
    return SelectionEvidence(contract_version=CONTRACT_VERSION, family=FAMILY_F4, operation_id=operation_id,
                             verified_at=verified_at.astimezone(timezone.utc).isoformat(), record_text=record_text, selection_text=selection_text)
