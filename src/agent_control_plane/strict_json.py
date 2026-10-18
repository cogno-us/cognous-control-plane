"""Strict JSON reading for operator-supplied and stored documents (a leaf module: imports nothing from this package).

Refused, fail closed, with a stable ``[code]`` in the message: input that is not UTF-8, an object with a duplicate member name,
and the non-JSON constants ``NaN``, ``Infinity`` and ``-Infinity``. Valid input parses to exactly what ``json.loads`` returns.
"""

from __future__ import annotations

import json
from typing import Any

INPUT_DUPLICATE_MEMBER = "input_json_duplicate_member"
INPUT_NON_FINITE_NUMBER = "input_json_non_finite_number"
INPUT_NOT_UTF8 = "input_not_utf8"

MAX_TEXT = 200


def safe_text(value: Any, limit: int = MAX_TEXT) -> str:
    """Escape and truncate text that may carry untrusted bytes before it reaches stderr or a message.

    Control, format and other non-printable characters (CR, LF, NUL, ESC, bidi overrides, U+2028) become ``\\xNN``/``\\uNNNN``
    escapes, so a member name cannot forge a line or an ANSI sequence in a terminal or a CI log.
    """
    text = "".join(
        c if c.isprintable() else (f"\\x{ord(c):02x}" if ord(c) < 256 else f"\\u{ord(c):04x}") for c in str(value)
    )
    return text if len(text) <= limit else text[: max(limit - 3, 0)] + "..."


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"[{INPUT_DUPLICATE_MEMBER}] duplicate object member {safe_text(key, 60)!s}")
        seen[key] = value
    return seen


def _no_constant(token: str) -> Any:
    raise ValueError(f"[{INPUT_NON_FINITE_NUMBER}] {token} is not valid JSON")


def decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"[{INPUT_NOT_UTF8}] input is not valid UTF-8 (byte offset {exc.start})") from None


def strict_loads(data: bytes | str) -> Any:
    """Parse JSON fail-closed: UTF-8 only, no duplicate object members, no NaN/Infinity/-Infinity."""
    text = data if isinstance(data, str) else decode_utf8(data)
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
