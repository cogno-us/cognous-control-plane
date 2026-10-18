"""Strict JSON reading for operator-supplied and stored documents (a leaf module: imports nothing from this package).

Refused, fail closed, with a stable ``[code]`` in the message: input that is not UTF-8, an object with a duplicate member name,
the non-JSON constants ``NaN``, ``Infinity`` and ``-Infinity``, a number too large to be a finite float (``1e400``), and a string
or member name holding an unpaired UTF-16 surrogate (``"\\ud800"``). Valid input parses to exactly what ``json.loads`` returns.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

INPUT_DUPLICATE_MEMBER = "input_json_duplicate_member"
INPUT_NON_FINITE_NUMBER = "input_json_non_finite_number"
INPUT_NOT_UTF8 = "input_not_utf8"
INPUT_LONE_SURROGATE = "input_json_lone_surrogate"
OUTPUT_UNSERIALISABLE = "output_json_unserialisable"

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


def _finite_float(token: str) -> float:
    value = float(token)  # exactly what json.loads does with a number token
    if not math.isfinite(value):
        raise ValueError(f"[{INPUT_NON_FINITE_NUMBER}] number {safe_text(token, 40)} is outside the finite range")
    return value


# Only text that holds a surrogate code point or a surrogate escape can decode to one; everything else skips the walk.
_SURROGATE_HINT = re.compile("[\ud800-\udfff]|\\\\u[dD][89a-fA-F]")


def _is_lone_surrogate_text(text: str) -> bool:
    return any(0xD800 <= ord(c) <= 0xDFFF for c in text)


def _has_lone_surrogate(document: Any) -> bool:
    """Iterative walk (no recursion limit) over every string and member name of a parsed document."""
    stack = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _is_lone_surrogate_text(item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


def decode_utf8(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"[{INPUT_NOT_UTF8}] input is not valid UTF-8 (byte offset {exc.start})") from None


def strict_loads(data: bytes | str) -> Any:
    """Parse JSON fail-closed: UTF-8 only, no duplicate object members, no NaN/Infinity/-Infinity, finite numbers only, no
    unpaired surrogates."""
    text = data if isinstance(data, str) else decode_utf8(data)
    value = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_float=_finite_float)
    if _SURROGATE_HINT.search(text) and _has_lone_surrogate(value):
        raise ValueError(f"[{INPUT_LONE_SURROGATE}] a string holds an unpaired UTF-16 surrogate")
    return value


def dumps_bytes(
    value: Any,
    *,
    indent: int | None = 2,
    sort_keys: bool = False,
    ensure_ascii: bool = False,
    newline: bool = False,
) -> bytes:
    """Serialise ``value`` to UTF-8 JSON bytes that :func:`strict_loads` accepts, or refuse before anything is written.

    Refused with a stable ``[output_json_unserialisable]`` message: a non-finite number (``NaN``, ``Infinity``), a string or member name
    holding an unpaired UTF-16 surrogate, and a value that is not JSON-serialisable. Every file writer calls this *before* it opens or
    replaces a file, so a refused write leaves an existing record intact and readable. ``ensure_ascii=True`` keeps the escaped form
    (byte-identical to ``json.dumps`` for well-formed text); the surrogate check then runs on the value, not the output.
    """
    try:
        if ensure_ascii and _has_lone_surrogate(value):
            raise ValueError("an unpaired UTF-16 surrogate")
        text = json.dumps(value, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii, allow_nan=False)
        data = (text + ("\n" if newline else "")).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeEncodeError) as exc:
        raise ValueError(f"[{OUTPUT_UNSERIALISABLE}] the value cannot be written as strict JSON ({type(exc).__name__})") from None
    return data
