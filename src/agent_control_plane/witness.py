"""Opt-in outside-held digest (witness-digest/0.1): the verifier side and a local witness interface.

A ledger head digest can be held by someone other than whoever can write the record store (a plain JSON file; it has no keyed
integrity check). A reader who holds that digest can then tell that a row covered by it was dropped or rewritten afterwards, even
if the record set was re-sealed or re-signed (for example a replay bundle HMAC) by the writer. Nothing here runs unless a host calls it: the default path, the stored record and every
commitment are unchanged, and no profile or contract is touched.

What is built here:

* ``head_digest`` / ``chain_head``  a hash chain over the rows of every list-valued ledger of a record document (one chain per
  ledger, rows in stored order). A ledger head covers exactly the first ``count`` rows; appending rows later keeps the head of
  the covered prefix valid.
* ``make_record``  the record a witness holds: per-ledger ``{count, head}``, a ``sequence``, the ``previous_digest`` of the witness's
  own chain, and its own ``digest``.
* ``Witness``  the protocol (``publish(digest)`` / ``latest()``; ``history()`` optional) and ``LocalFileWitness``, an append-only
  JSON-lines file for tests and local use.
* ``verify_against_witness``  rejects a record set whose covered rows were dropped or rewritten after a digest the witness holds.
* ``publish_head``  verifies the record set against the witness first, then publishes the new head (so a rewrite is never
  laundered into a fresh digest by an honest publisher).

Limits (read before relying on it):

* This gives visibility to a reader who holds the witness digest. It is NOT tamper evidence against the witness holder: whoever
  controls the witness can withhold, replace or back-date a digest, and a reader with no independent copy of the witness cannot
  tell. Nor does it protect rows appended after the latest published digest: they are reported as ``unwitnessed_rows`` until the
  next publication.
* Only list-valued ledgers are covered. Top-level scalars and mutable dictionaries (for example ``input_time_floors``, which
  advances by design) are not append-only and are not covered.
* A local file witness is held on the same machine as the store in tests. For the control to work, the real witness must be held
  somewhere the store writer cannot write. The owner default for that location is a signed tag in the hub repository. Publishing
  there is a deployment step the owner must trigger; this module makes no network call, creates no tag and writes only the path
  it is given.
"""
from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel

from .atomic_write import open_private_lock
from .bounded import commitment
from .strict_json import decode_utf8, strict_loads

PROFILE_ID = "witness-digest/0.1"
GENESIS = "sha256:" + "0" * 64

#: Verdict codes of the verifier. They describe a record set against a witness; they are not decision reason codes.
CODE_NO_DIGEST = "witness_holds_no_digest"
CODE_CHAIN_INVALID = "witness_chain_invalid"
CODE_RUN_MISMATCH = "witness_run_mismatch"
CODE_SHRUNK = "witness_ledger_shrunk"            # a covered row was dropped (fewer rows than the digest covers)
CODE_HEAD_MISMATCH = "witness_ledger_head_mismatch"  # a covered row was rewritten, or dropped and replaced

SCOPE = ("visibility to a reader who holds the witness digest; not tamper evidence against the witness holder, and rows appended "
         "after the latest published digest are not covered")


class WitnessRefused(ValueError):
    """The witness refused a publication (it would not extend the held chain)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------------------------------------- digest chain

def _as_document(document: Any) -> dict:
    if isinstance(document, BaseModel):
        return document.model_dump(mode="json")
    if isinstance(document, (str, Path)):
        return strict_loads(Path(document).read_bytes())
    return document


def ledgers(document: Any) -> dict[str, list]:
    """The append-only ledgers of a record document: every list-valued top-level member, in name order."""
    doc = _as_document(document)
    return {name: value for name, value in sorted(doc.items()) if isinstance(value, list)}


def chain_heads(rows: list) -> list[str]:
    """``heads[i]`` is the chain head after the first ``i`` rows (``heads[0]`` is the genesis value)."""
    heads = [GENESIS]
    for row in rows:
        heads.append(commitment({"prev": heads[-1], "row": commitment(row)}))
    return heads


def chain_head(rows: list) -> str:
    return chain_heads(rows)[-1]


def head_digest(document: Any) -> dict[str, dict]:
    """Per-ledger ``{count, head}`` for every non-empty ledger. Empty ledgers are omitted (a missing ledger counts as empty)."""
    return {name: {"count": len(rows), "head": chain_head(rows)} for name, rows in ledgers(document).items() if rows}


def _record_digest(record: dict) -> str:
    return commitment({k: v for k, v in record.items() if k != "digest"})


def make_record(document: Any, *, previous: dict | None = None) -> dict:
    """The record to publish: the document's head digest chained after ``previous`` (the witness's latest record, if any)."""
    doc = _as_document(document)
    run_id = doc.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("record document has no run_id")
    if previous is not None and previous.get("run_id") != run_id:
        raise WitnessRefused(CODE_RUN_MISMATCH, "the witness holds a chain for a different run")
    record = {
        "version": PROFILE_ID,
        "run_id": run_id,
        "sequence": 0 if previous is None else int(previous["sequence"]) + 1,
        "previous_digest": None if previous is None else previous["digest"],
        "ledgers": head_digest(doc),
    }
    record["digest"] = _record_digest(record)
    return record


# ---------------------------------------------------------------------------------------------------- witness

class Witness(Protocol):
    """Who holds the digest. ``publish`` must be append-only; ``latest`` returns the newest record or None.

    ``history()`` (oldest first) is optional: with it the verifier also checks every earlier digest and the witness's own chain.
    """

    def publish(self, digest: dict) -> dict: ...

    def latest(self) -> dict | None: ...


def check_witness_chain(records: list[dict]) -> list[str]:
    """Defects in a witness's own chain: digest recomputation, contiguity, linkage, one run, non-decreasing counts."""
    defects: list[str] = []
    previous: dict | None = None
    for index, record in enumerate(records):
        if record.get("version") != PROFILE_ID:
            defects.append(f"record {index}: unsupported version {record.get('version')!r}")
            break
        if record.get("digest") != _record_digest(record):
            defects.append(f"record {index}: digest does not recompute")
        if record.get("sequence") != index:
            defects.append(f"record {index}: sequence {record.get('sequence')!r} is not contiguous")
        want_prev = None if previous is None else previous.get("digest")
        if record.get("previous_digest") != want_prev:
            defects.append(f"record {index}: previous_digest does not link to the record before it")
        if previous is not None:
            if record.get("run_id") != previous.get("run_id"):
                defects.append(f"record {index}: run_id differs from the record before it")
            for name, old in (previous.get("ledgers") or {}).items():
                new = (record.get("ledgers") or {}).get(name)
                if new is None or new["count"] < old["count"]:
                    defects.append(f"record {index}: ledger {name} covers fewer rows than the record before it")
        previous = record
    return defects


class LocalFileWitness:
    """Append-only JSON-lines witness on the local filesystem, for tests and local use only.

    It is held where the process that writes the store can usually write too, so by itself it gives no protection against that
    process; it exists to exercise the verifier and to be replaced by a location the store writer cannot write.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def history(self) -> list[dict]:
        if not self.path.exists():
            return []
        return [strict_loads(line) for line in decode_utf8(self.path.read_bytes()).splitlines() if line.strip()]

    def latest(self) -> dict | None:
        records = self.history()
        return records[-1] if records else None

    def publish(self, digest: dict) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = open_private_lock(self.path.with_name(self.path.name + ".lock"))
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            defects = check_witness_chain(self.history() + [digest])
            if defects:
                raise WitnessRefused(CODE_CHAIN_INVALID, "; ".join(defects))
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o644)
            try:
                os.write(fd, (json.dumps(digest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            os.close(lock)
        return digest


# ---------------------------------------------------------------------------------------------------- verification

@dataclass
class WitnessVerdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    witnessed_through: dict[str, int] = field(default_factory=dict)   # ledger -> rows covered by the latest digest
    unwitnessed_rows: dict[str, int] = field(default_factory=dict)    # ledger -> rows appended since (not covered)
    published_records: int = 0
    scope: str = SCOPE

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reasons": self.reasons, "findings": self.findings, "witnessed_through": self.witnessed_through,
                "unwitnessed_rows": self.unwitnessed_rows, "published_records": self.published_records, "scope": self.scope}


def verify_against_witness(document: Any, witness: Witness) -> WitnessVerdict:
    """Reject a record set whose covered rows were dropped or rewritten after a digest the witness holds.

    Checks every digest the witness can list (``history()``; otherwise only ``latest()``). A ledger the digest covers must still
    hold at least that many rows, and the chain head over those rows must equal the published head. The verdict never says a
    record set is intact beyond ``witnessed_through``.
    """
    doc = _as_document(document)
    history = getattr(witness, "history", None)
    records = list(history()) if callable(history) else ([witness.latest()] if witness.latest() is not None else [])
    if not records:
        return WitnessVerdict(False, [CODE_NO_DIGEST], [{"code": CODE_NO_DIGEST, "detail": "the witness holds no digest; nothing is verified"}])
    verdict = WitnessVerdict(True, published_records=len(records))

    def reject(code: str, **detail: Any) -> None:
        verdict.ok = False
        if code not in verdict.reasons:
            verdict.reasons.append(code)
        verdict.findings.append({"code": code, **detail})

    for defect in check_witness_chain(records):
        reject(CODE_CHAIN_INVALID, detail=defect)
    if any(r.get("run_id") != doc.get("run_id") for r in records):
        reject(CODE_RUN_MISMATCH, record_set_run_id=doc.get("run_id"), witness_run_id=records[-1].get("run_id"))
    if not verdict.ok:
        verdict.reasons.sort()
        return verdict

    rows_by_ledger = ledgers(doc)
    heads_cache: dict[str, list[str]] = {}
    for record in records:
        for name, held in sorted((record.get("ledgers") or {}).items()):
            rows = rows_by_ledger.get(name, [])
            if name not in heads_cache:
                heads_cache[name] = chain_heads(rows)
            count = int(held["count"])
            if len(rows) < count:
                reject(CODE_SHRUNK, ledger=name, sequence=record["sequence"], published_count=count, found_count=len(rows))
            elif heads_cache[name][count] != held["head"]:
                reject(CODE_HEAD_MISMATCH, ledger=name, sequence=record["sequence"], published_count=count, found_count=len(rows))
    latest = records[-1]
    verdict.witnessed_through = {name: int(v["count"]) for name, v in sorted((latest.get("ledgers") or {}).items())}
    for name, rows in rows_by_ledger.items():
        extra = len(rows) - verdict.witnessed_through.get(name, 0)
        if extra > 0:
            verdict.unwitnessed_rows[name] = extra
    verdict.reasons.sort()
    return verdict


def publish_head(document: Any, witness: Witness) -> dict:
    """Publish the document's current head digest after verifying it extends everything the witness already holds.

    Refuses (``WitnessRefused``) if the record set no longer matches a held digest: publishing over a rewrite would turn it into
    the new baseline. With an empty witness there is nothing to check and the first digest is published as the baseline, which
    vouches for nothing before it.
    """
    previous = witness.latest()
    if previous is not None:
        verdict = verify_against_witness(document, witness)
        if not verdict.ok:
            raise WitnessRefused(verdict.reasons[0], "; ".join(sorted(set(verdict.reasons))))
    return witness.publish(make_record(document, previous=previous))


# ---------------------------------------------------------------------------------------------------- command line

def add_witness_parser(subparsers) -> None:
    witness = subparsers.add_parser("witness", help="outside-held head digest: digest, publish, verify (local file witness only)")
    sub = witness.add_subparsers(dest="witness_command", required=True)
    digest = sub.add_parser("digest", help="print the head digest chain of a record store document")
    digest.add_argument("path")
    publish = sub.add_parser("publish", help="verify the record set against the witness file, then append its head digest")
    publish.add_argument("path")
    publish.add_argument("--witness", required=True, help="local witness file (JSON lines)")
    verify = sub.add_parser("verify", help="reject a record set whose covered rows were dropped or rewritten")
    verify.add_argument("path")
    verify.add_argument("--witness", required=True, help="local witness file (JSON lines)")


def witness_command(args, stdout, stderr) -> int:
    """0 verified / published, 1 rejected, 2 usage or unreadable input."""
    try:
        doc = _as_document(args.path)
        if args.witness_command == "digest":
            print(json.dumps(make_record(doc), indent=2, sort_keys=True), file=stdout)
            return 0
        witness = LocalFileWitness(args.witness)
        if args.witness_command == "publish":
            try:
                record = publish_head(doc, witness)
            except WitnessRefused as exc:
                print(f"refused: {exc}", file=stderr)
                return 1
            print(json.dumps({"published": record["digest"], "sequence": record["sequence"]}), file=stdout)
            return 0
        verdict = verify_against_witness(doc, witness)
        print(json.dumps(verdict.as_dict(), indent=2, sort_keys=True), file=stdout)
        return 0 if verdict.ok else 1
    except (OSError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=stderr)
        return 2
