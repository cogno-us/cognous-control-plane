"""Opt-in freshness/0.1: three named clocks, a deadline at opening, an overdue state, a reaper and a recorded age basis.

Selected only by the host-governed ``RuntimeAuthorityProfile.freshness`` field. With it unset nothing here runs, every stored
and hashed byte is unchanged (all new fields are omitted while unset) and the blocking check lease keeps its legacy behaviour.

Three clocks, named in every record that carries them:

* ``evaluated_at``  the evaluation pass: ``now`` is fixed once at the start of ``decide``/``execute``.
* ``recorded_at``   the service clock, re-read when the row is written (each journal event is stamped at its own write).
* ``observed_at``   the status source's stamp, as the party being checked asserted it.

Limits (read before relying on it):
* A deadline checked immediately before ``destination.apply`` narrows the window between check and commit. It does not close it.
* The lease is a same-host ``flock``. Cross-host takeover needs a fencing token checked at the destination (not built here).
* ``age_basis = nonce_bound`` proves only that a response was produced after the reader issued its nonce, which needs a resolver
  that echoes it. Without that the age is what the source asserts (``source_asserted``).
* Everything is a join over rows in the record store, which is a plain JSON file under a same-host lock with no keyed integrity
  check: anyone who can write the file can rewrite rows. Visibility for an honest reader, not tamper evidence. Signer and issuer
  fields are asserted names, not authenticated identities.
* By default the deadline is anchored at the opening of the check, not at the status's own timestamp. A status that was already
  close to the class bound when read can be dispatched until the deadline, so the status age at dispatch can reach twice the bound
  (tests/test_freshness.py::test_status_age_at_dispatch_can_reach_twice_the_bound pins this). With
  ``FreshnessProfile.anchor_deadline_to_inputs=True`` the deadline is the earliest of that value and ``observed_at + own bound``
  over every input judged for freshness (carried on the ``completed`` event; the recovery pass still reports against the opening
  deadline).
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

from .time_instant import parse_instant
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE_ID = "freshness/0.1"
#: A resolver that declares this capability implements ``nonce_read(nonce, method_name, *args) -> (record, echoed_nonce)``.
NONCE_CAPABILITY = "status-nonce/0.1"

#: Reason / refusal codes emitted by this profile (all registered in the reason registry).
CODE_EXPIRED_BEFORE_DISPATCH = "check_expired_before_dispatch"
CODE_OVERDUE = "check_overdue"
CODE_LEASE_UNAVAILABLE = "check_lease_unavailable"
CODE_NONCE_MISMATCH = "status_nonce_mismatch"
CODE_EXT_UNSIGNED = "age_extension_unsigned"
CODE_EXT_SELF_SIGNED = "age_extension_self_signed"
CODE_EXT_SIGNER_NOT_CONFIGURED = "age_extension_signer_not_configured"
CODE_EXT_EXCEEDS_LIMIT = "age_extension_exceeds_limit"
CODE_EXT_INVALID = "age_extension_invalid"
CODE_EXT_AUTHORITY_UNCONFIGURED = "age_extension_authority_unconfigured"

AgeBasis = Literal["nonce_bound", "source_asserted"]


class FreshnessProfile(BaseModel):
    """Trusted host configuration. Covered by the approval commitment once set (it is part of the profile dump)."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["freshness/0.1"] = PROFILE_ID
    #: Check-lease acquisition is non-blocking and gives up after this long (legacy: blocks forever).
    lease_acquire_timeout_seconds: float = Field(default=5.0, gt=0)
    #: Declared interval of the reaper (recovery pass) after its start-up run.
    reaper_interval_seconds: int = Field(default=30, ge=1)
    #: Send a nonce with every resolver read where the resolver supports it.
    nonce: bool = True
    #: Largest extension of a class age bound a signer may record. 0 refuses every extension.
    max_age_extension_seconds: int = Field(default=0, ge=0)
    #: Opt-in (omitted from the profile dump while False, so existing profile commitments are unchanged). When True the dispatch
    #: deadline is the earliest of ``opened + class bound`` and ``observed_at + its own bound`` for every status input the
    #: evaluation judged for freshness, so a read that was already old at opening cannot be dispatched for another full bound.
    anchor_deadline_to_inputs: bool = Field(default=False, exclude_if=lambda v: not v)


class ReaperFailed(RuntimeError):
    """The reaper thread stopped on an error (or died). Recovery is not running, so the workflow refuses to decide or dispatch."""


class CheckLeaseUnavailable(RuntimeError):
    """The per-check lease could not be taken before the profile's acquisition deadline."""


class AgeBoundExtension(BaseModel):
    """A recorded decision to extend one action class's age bound during a checker outage, with its authority."""

    model_config = ConfigDict(extra="forbid")
    extension_id: str = Field(min_length=1)
    class_id: str = Field(min_length=1)
    from_max_age_seconds: int = Field(ge=0)
    to_max_age_seconds: int = Field(ge=0)
    not_before: str
    expires_at: str
    outage_ref: str = Field(min_length=1)       # the declared checker outage this decision answers
    requested_by: str = Field(min_length=1)
    signer: str | None = None                    # None = unsigned; never counts
    authority_ref: str | None = None
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)


class AgeBoundExtensionRefusal(BaseModel):
    """A refused extension attempt, retained so the refusal is visible."""

    model_config = ConfigDict(extra="forbid")
    refusal_id: str
    extension: dict
    reasons: list[str]
    recorded_at: str


class AgeExtensionRefused(ValueError):
    def __init__(self, reasons: list[str]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


class RecoveryRun(BaseModel):
    """One pass of the recovery/reaper, with the counts it saw."""

    model_config = ConfigDict(extra="forbid")
    run_id: str
    trigger: Literal["startup", "interval", "manual"]
    recorded_at: str
    interrupted: list[str] = Field(default_factory=list)   # abandoned checks the pass closed
    overdue: list[str] = Field(default_factory=list)       # live checks past their deadline (reported, not closed)
    open_count: int = 0
    oldest_open_age_seconds: float | None = None


class RecoveryReport(BaseModel):
    """What a recovery pass found. ``overdue`` checks are alive and are never closed by the pass."""

    model_config = ConfigDict(extra="forbid")
    as_of: str
    interrupted: list[str] = Field(default_factory=list)
    overdue: list[dict] = Field(default_factory=list)      # {check_id, deadline, overdue_seconds, reasons: [check_overdue]}
    open_within_deadline: list[str] = Field(default_factory=list)
    oldest_open_age_seconds: float | None = None


def parse_time(value: str) -> datetime:
    """Strict instant (ODES time semantics section 1); a naive or malformed time raises ``InstantError`` (a ValueError)."""
    return parse_instant(value)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _row(x) -> dict:
    return x.model_dump(mode="json") if isinstance(x, BaseModel) else dict(x)


# ------------------------------------------------------------------------------------------------ age extensions
def extension_defects(rule_profile, row, *, max_extension_seconds: int, base_seconds: int | None = None) -> list[str]:
    """Why an extension row does not count. Empty means it counts. Signers are those of the rule-revision profile (N2).

    ``base_seconds`` is the class bound from the trusted host profile. When given, the row's own ``from_max_age_seconds`` is not
    trusted: the limit is measured from ``base_seconds`` and a row whose recorded base differs from it is invalid (fail closed).
    A rewritten row cannot launder an oversized extension by lowering its own recorded base.
    """
    r = _row(row)
    out: list[str] = []
    from_seconds = r["from_max_age_seconds"]  # equals base_seconds whenever base_seconds is given (else the row is invalid)
    base_mismatch = base_seconds is not None and r["from_max_age_seconds"] != base_seconds
    if rule_profile is None:
        out.append(CODE_EXT_AUTHORITY_UNCONFIGURED)
    if (base_mismatch or r["to_max_age_seconds"] <= from_seconds or parse_time(r["expires_at"]) <= parse_time(r["not_before"])
            or not r.get("outage_ref")):
        out.append(CODE_EXT_INVALID)
    elif r["to_max_age_seconds"] - from_seconds > max_extension_seconds:
        out.append(CODE_EXT_EXCEEDS_LIMIT)
    if not r.get("signer"):
        out.append(CODE_EXT_UNSIGNED)
    elif r["signer"] == r["requested_by"]:
        out.append(CODE_EXT_SELF_SIGNED)
    elif rule_profile is not None and r["signer"] not in rule_profile.signers:
        out.append(CODE_EXT_SIGNER_NOT_CONFIGURED)
    return out


def effective_age_bound(rule_profile, extensions, *, class_id: str, base_seconds: int, now: datetime,
                        max_extension_seconds: int) -> tuple[int, str | None, list[str]]:
    """The class age bound at ``now``: (bound, extension_id that raised it or None, defect codes of active rows that do not count).

    A row counts only if it re-validates against the signer set configured *now* and its window is active; a signer removed from
    the configured set withdraws the authority of rows that named it earlier. The limit is measured from ``base_seconds`` (the trusted
    class bound), never from the base the row records about itself.
    """
    bound, used, defects = base_seconds, None, []
    for raw in extensions:
        r = _row(raw)
        if r["class_id"] != class_id or not (parse_time(r["not_before"]) <= now < parse_time(r["expires_at"])):
            continue
        row_defects = extension_defects(rule_profile, r, max_extension_seconds=max_extension_seconds,
                                        base_seconds=base_seconds)
        if row_defects:
            defects.extend(d for d in row_defects if d not in defects)
        elif r["to_max_age_seconds"] > bound:
            bound, used = r["to_max_age_seconds"], r["extension_id"]
    return bound, used, defects


# ------------------------------------------------------------------------------------------------ journal reading
def _checks(events: list) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for e in map(_row, events):
        out.setdefault(e["check_id"], []).append(e)
    return out


def freshness_counts(check_events: list, *, as_of: str | datetime) -> dict:
    """Counts the Evidence Pack reports next to refusal counts, derived from the retained journal alone.

    * ``abandoned_open_count``  checks that were opened and never completed (closed ``interrupted`` by recovery),
    * ``open_count``            checks with no terminal event as of ``as_of``,
    * ``overdue_count``         open checks past their deadline as of ``as_of`` (the recovery pass also wrote ``overdue``),
    * ``oldest_open_age_seconds``  age of the oldest open check by its opening ``recorded_at`` (None when none is open),
    * ``expired_before_dispatch_count``  checks whose licence was withdrawn at the dispatch gate.
    A check opened by the legacy path carries no deadline: it is open but can never be counted overdue.
    """
    now = parse_time(as_of) if isinstance(as_of, str) else as_of
    terminal = {"completed", "interrupted", "expired"}
    open_checks, abandoned, expired, overdue = [], 0, 0, 0
    for check_id, events in _checks(check_events).items():
        opening = next((e for e in events if e["phase"] == "opened"), None)
        phases = {e["phase"] for e in events}
        if "interrupted" in phases:
            abandoned += 1
        if "expired" in phases:
            expired += 1
        if opening is None or phases & terminal:
            continue
        open_checks.append(opening)
        deadline = opening.get("deadline")
        if deadline and now > parse_time(deadline):
            overdue += 1
    ages = [(now - parse_time(o["recorded_at"])).total_seconds() for o in open_checks]
    return {"as_of": iso(now), "open_count": len(open_checks), "abandoned_open_count": abandoned,
            "overdue_count": overdue, "expired_before_dispatch_count": expired,
            "oldest_open_age_seconds": max(ages) if ages else None}


# ------------------------------------------------------------------------------------------------ reaper
class Reaper:
    """The host's recovery runner: one pass at start-up, then one per declared interval.

    ``run_due()`` is the deterministic entry (a host loop or a test calls it); ``start()`` runs the start-up pass synchronously
    and then drives ``run_due`` from a daemon thread. A pass closes abandoned checks (dead lease) and reports live checks past
    their deadline as ``check_overdue`` without closing them.
    """

    def __init__(self, records, profile: FreshnessProfile, *, clock: Callable[[], datetime] | None = None):
        self.records, self.profile = records, profile
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.last_run: datetime | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        #: The error that stopped the background thread, if any. Never cleared: a failed reaper stays failed until replaced.
        self.failure: BaseException | None = None

    @property
    def failed(self) -> bool:
        """True after the thread raised, or when it ended without ``stop()`` having been called (it died)."""
        if self.failure is not None:
            return True
        return self._thread is not None and not self._thread.is_alive() and not self._stop.is_set()

    def check(self) -> None:
        """Raise ``ReaperFailed`` when the background recovery is no longer running (fail closed)."""
        if self.failed:
            raise ReaperFailed(f"freshness reaper stopped: {type(self.failure).__name__ if self.failure else 'thread ended'}")

    def run_startup(self) -> RecoveryReport:
        return self._run("startup")

    def run_due(self) -> RecoveryReport | None:
        now = self.clock()
        # A wall clock stepped back below the last run would otherwise stall the reaper for the size of the step: run instead.
        if (self.last_run is not None and now >= self.last_run
                and (now - self.last_run).total_seconds() < self.profile.reaper_interval_seconds):
            return None
        return self._run("interval" if self.last_run is not None else "startup")

    def _run(self, trigger: str) -> RecoveryReport:
        report = self.records.recovery_pass(trigger=trigger, now=self.clock(), record_run=True)
        self.last_run = self.clock()
        return report

    def start(self) -> RecoveryReport:
        report = self.run_startup()
        self._stop.clear()

        def loop():
            while not self._stop.wait(min(1.0, self.profile.reaper_interval_seconds)):
                try:
                    self.run_due()
                except Exception as exc:  # noqa: BLE001 - surfaced, never swallowed: the pass is the recovery guarantee
                    self.failure = exc
                    logging.getLogger(__name__).error("freshness reaper stopped: %s: %s", type(exc).__name__, exc)
                    return
        self._thread = threading.Thread(target=loop, name="acp-freshness-reaper", daemon=True)
        self._thread.start()
        return report

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


def acquire_lease_nonblocking(fd: int, timeout_seconds: float, *, poll_seconds: float = 0.01) -> None:
    """Take an exclusive flock without blocking forever. Raises ``CheckLeaseUnavailable`` at the deadline."""
    import fcntl
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise CheckLeaseUnavailable(CODE_LEASE_UNAVAILABLE) from None
            time.sleep(poll_seconds)
