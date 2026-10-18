"""Strict instant parsing (a leaf module: imports nothing from this package).

Implements section 1 of the ODES time semantics (docs/engineering/ODES-TIME-SEMANTICS.md in open-decision-evidence-standard).
An instant is an RFC 3339 ``date-time`` with an explicit offset::

    YYYY-MM-DDThh:mm:ss[.f]  then  Z | +hh:mm | -hh:mm

ASCII digits only, upper-case ``T`` and ``Z``, seconds mandatory, one to six fraction digits, the whole string matched (no
surrounding space, no trailing line break). Refused, with a stable ``[code]`` in the message (``InstantError`` is a
``ValueError``, so every caller keeps the refusal path it already had for a malformed time):

* ``time_instant_naive``: an otherwise valid instant with no offset. It is never read as UTC or as local time.
* ``time_instant_invalid``: anything else that is not an instant: a seventh fraction digit (never truncated), a leap second
  ``:60``, hour ``24``, an impossible date, year ``0000``, offset hour above ``23`` or offset minute above ``59``, an instant that
  leaves years 0001 to 9999 when moved to UTC, and every form ``datetime.fromisoformat`` accepts beyond RFC 3339 (date only,
  no seconds, space separator, basic format, comma fraction, hour-only offset).

A valid instant parses to exactly what ``datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)``
returned before; ``-00:00`` is read as ``+00:00``. A non-string raises ``TypeError``.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

TIME_INSTANT_INVALID = "time_instant_invalid"
TIME_INSTANT_NAIVE = "time_instant_naive"

# The offset is optional here only so that a naive instant can be told apart from a malformed one; it is refused below.
_INSTANT = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?(Z|[+-][0-9]{2}:[0-9]{2})?"
)


class InstantError(ValueError):
    """A string that is not an instant under the ODES time semantics. ``code`` is one of the two module codes."""

    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code


def parse_instant(value: str) -> datetime:
    """Parse an instant strictly and return it as an aware UTC datetime."""
    if not isinstance(value, str):
        raise TypeError("an instant must be a string")
    match = _INSTANT.fullmatch(value)
    if match is None:
        raise InstantError(TIME_INSTANT_INVALID, "not an RFC 3339 date-time with seconds and at most six fraction digits")
    year, month, day, hour, minute, second = (int(match.group(i)) for i in range(1, 7))
    fraction, offset = match.group(7), match.group(8)
    if second == 60:
        raise InstantError(TIME_INSTANT_INVALID, "a leap second is not an instant")
    if year == 0 or hour > 23 or minute > 59 or second > 59:
        raise InstantError(TIME_INSTANT_INVALID, "date or time field out of range")
    microsecond = int(fraction.ljust(6, "0")) if fraction else 0
    if offset is None or offset == "Z":
        tz = timezone.utc
    else:
        off_hour, off_minute = int(offset[1:3]), int(offset[4:6])
        if off_hour > 23 or off_minute > 59:
            raise InstantError(TIME_INSTANT_INVALID, "offset out of range")
        delta = timedelta(hours=off_hour, minutes=off_minute)
        tz = timezone(-delta if offset[0] == "-" else delta)
    try:
        parsed = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=tz)
    except ValueError:
        raise InstantError(TIME_INSTANT_INVALID, "date or time field out of range") from None
    if offset is None:
        raise InstantError(TIME_INSTANT_NAIVE, "an instant needs an explicit UTC offset")
    try:
        return parsed.astimezone(timezone.utc)
    except OverflowError:
        raise InstantError(TIME_INSTANT_INVALID, "instant outside years 0001 to 9999") from None


def aware_utc(value: datetime) -> datetime:
    """An aware datetime in UTC; a naive datetime is refused (``time_instant_naive``), never read as UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise InstantError(TIME_INSTANT_NAIVE, "an instant needs an explicit UTC offset")
    return value.astimezone(timezone.utc)
