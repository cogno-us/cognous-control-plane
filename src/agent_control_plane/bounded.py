"""Bounded authorization-to-effect workflow for the synthetic pilot."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
import tempfile
import sys
from contextlib import contextmanager

try:
    import fcntl
except ImportError:  # Unsupported platforms must fail closed, not use thread-only writes.
    fcntl = None
import uuid
from datetime import datetime, timedelta, timezone
from time import monotonic as _monotonic
from pathlib import Path
from typing import Iterator, Literal, Protocol

from pydantic import BaseModel, Field

from .runtime_authority import (RuntimeAuthorityProfile, VOCABULARY_VERSION_0_2, reopen_conditions,
                                vocabulary_for)
from .strict_json import strict_loads
from .rule_revision import RuleRevision, RuleRevisionProfile, RuleRevisionRefusal, resolve_rule, rule_identity
from .operation_identity import (
    DESTINATION_CAPABILITY as OPERATION_IDENTITY_CAPABILITY, AttemptJoin, OperationAdmissionRow,
    OperationRenewalRow, licensed_revisions, operation_status,
)
from . import freshness as _fresh_profile
from . import merge as _merge
from .dedupe import (DedupeEscalation, DestinationInProgress, applied_under_other_effect, blocks_new_key, dedupe_mode, due_escalations,
                     classify as _dedupe_classify, ERROR_IN_PROGRESS)
from .merge import CompensationObligation, MergeRecord
from .reversibility import SnapshotUse, effectively_irreversible, effective_reversibility, judge_cached_purpose, recorded_closures
from .freshness import (
    AgeBoundExtension, AgeBoundExtensionRefusal, AgeExtensionRefused, CheckLeaseUnavailable, Reaper, RecoveryReport, RecoveryRun,
    acquire_lease_nonblocking, effective_age_bound, extension_defects, parse_time as _fparse,
)

MANIFEST_VERSION = "1.1"
AUTHORITY_CONTEXT_VERSION = "0.1.0"
AUTHORITY_CONTEXT_STATUS = "proposed_pending_governor_review"
MANIFEST_UPSTREAM_COMMIT = "46c950bed37fe3812000895430bc0312d29e37ce"
ALVORADA_UPSTREAM_COMMIT = "fb3d97938969a89e149e8ff8db2756091d1233fc"
BITREP_UPSTREAM_COMMIT = "5b5077dafde232a7801cb425c4efddcffb468723"
INDEX_UPSTREAM_COMMIT = "d5e45d275cb301d9684b543e93b05997991d1cf2"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _canonical_bytes(value: object) -> bytes:
    """Manifest v1.1 canonical bytes, byte-compatible with the pinned helper."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def commitment(value: object) -> str:
    """Return the Manifest v1.1-compatible SHA-256 commitment."""
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact_strings(value: object) -> frozenset[str] | None:
    """The members of a declared string list, or None when the value is not a list (or tuple or set) of strings.

    Membership against the result is exact string equality. Any other shape (a single string, a mapping, a number, a list with
    a non-string item) is malformed, and callers treat it as declaring nothing, so the check it feeds refuses.
    """
    if not isinstance(value, (list, tuple, set, frozenset)):
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return frozenset(value)


class RuntimeProposal(BaseModel):
    """Historical bounded-authorization-effect/0.1 proposal."""
    manifest_id: str
    manifest_version: str
    manifest_digest: str
    actor: str
    principal: str
    action_id: str
    adapter_id: str
    target: str
    payload: dict
    payload_commitment: str
    requested_permissions: list[str] = Field(default_factory=list)
    amount: float = Field(default=0, ge=0, allow_inf_nan=False)
    unit: str = ""
    effects: int = Field(default=1, ge=0)
    authority_context_ref: str | None = None
    requirement_id: str | None = None
    risk_metadata: dict = Field(default_factory=dict)
    not_before: str | None = None
    expires_at: str | None = None
    correlation_id: str | None = None
    run_id: str | None = None
    expected_side_effects: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class TenantRuntimeProposal(RuntimeProposal):
    """Tenant-aware bounded-authorization-effect/0.2 proposal."""

    tenant_id: str = Field(min_length=1, max_length=128)


class GrantStatus(BaseModel):
    grant_id: str
    revision: str
    status: Literal["active", "suspended", "revoked", "unknown"]
    observed_at: str
    version: str
    status_ref: str
    authority_basis_ref: str
    institution_id: str
    authority_domain: str
    tenant_id: str | None = None
    superseded_by: str | None = None


class ApprovalStatus(BaseModel):
    runtime_authority_commitment: str | None = Field(default=None, exclude_if=lambda v: v is None)
    approval_ref: str
    role_id: str
    approver: str
    grant_id: str
    grant_revision: str
    proposal_commitment: str
    policy_versions: list[dict]
    status: Literal["active", "revoked", "unknown"] = "active"
    observed_at: str
    institution_id: str
    authority_domain: str
    tenant_id: str | None = None


class EvidenceStatus(BaseModel):
    validation_record: dict | None = Field(default=None, exclude_if=lambda v: v is None)
    obligation_id: str
    state: Literal["current", "stale", "unknown"]
    observed_at: str
    source_ref: str
    institution_id: str
    authority_domain: str


class PolicyStatus(BaseModel):
    ref: str
    version: str
    digest: str | None = Field(default=None, exclude_if=lambda v: v is None)  # opt-in rule-revision/0.1 content pin
    status: Literal["active", "superseded", "unknown"]
    observed_at: str
    institution_id: str
    authority_domain: str
    tenant_id: str | None = None


class ConflictStatus(BaseModel):
    requirement_id: str
    state: Literal["clear", "conflict", "unknown"]
    observed_at: str
    institution_id: str
    authority_domain: str
    conflict_refs: list[str] = Field(default_factory=list)


class IdentityStatus(BaseModel):
    identity: str
    principal: str
    authenticated: bool
    delegation_valid: bool
    observed_at: str
    institution_id: str
    authority_domain: str
    chain: list[str] = Field(default_factory=list)


class MandateStatus(BaseModel):
    issuer: str
    issuer_role: str
    issuance_record_ref: str
    mandate_valid: bool
    observed_at: str
    institution_id: str
    authority_domain: str


class RoleMappingStatus(BaseModel):
    """Versioned institution-scoped mapping from legacy labels to canonical URN role IDs."""

    institution_id: str
    version: str
    digest: str
    aliases: dict[str, list[str]] = Field(default_factory=dict)


class Resolver(Protocol):
    authenticated: bool
    def authority_context(self, ref: str) -> dict | None: ...
    def grant_status(self, grant_id: str) -> GrantStatus | None: ...
    def identity_status(self, acting_identity: str, principal: str) -> IdentityStatus: ...
    def issuer_mandate(self, issuer: str, issuer_role: str) -> MandateStatus: ...
    def approval_status(self, approval_ref: str) -> ApprovalStatus | None: ...
    def policy_status(self, ref: str) -> PolicyStatus | None: ...
    def conflict_status(self, requirement_id: str) -> ConflictStatus | None: ...
    def evidence_status(self, obligation_id: str) -> EvidenceStatus | None: ...
    def role_mapping(self, institution_id: str) -> RoleMappingStatus | None: ...
    def authority_effect_handoff(self, ref: str): ...
    def authority_effect_snapshot(self, ref: str) -> dict | None: ...


class AuthorizationBinding(BaseModel):
    runtime_authority: dict | None = Field(default=None, exclude_if=lambda v: v is None)
    proposal_commitment: str
    manifest_id: str
    manifest_version: str
    manifest_digest: str
    actor: str
    principal: str
    action_id: str
    adapter_id: str
    target: str
    payload_commitment: str
    requested_permissions: list[str]
    amount: float
    unit: str
    effects: int
    authority_context_id: str
    authority_context_version: str
    authority_context_status: str
    requirement_id: str
    requirement_commitment: str
    grant_id: str
    grant_revision: str
    policy_versions: list[dict]
    role_mapping_version: str
    role_mapping_digest: str
    effective_max_effects: int


class TenantAuthorizationBinding(AuthorizationBinding):
    """Tenant-aware bounded-authorization-effect/0.2 binding."""

    generation: Literal["bounded-authorization-effect/0.2"] = "bounded-authorization-effect/0.2"
    tenant_id: str = Field(min_length=1, max_length=128)


class DefinitiveDestinationRejection(RuntimeError):
    """Trusted adapter assertion of non-acceptance, never an inferred network error.

    Use only when the adapter can prove no dispatch or definitive provider
    rejection. Unknown/possibly accepted outcomes must use ordinary exceptions.
    """

    def __init__(self, reason_code: str):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", reason_code):
            raise ValueError("definitive rejection requires a bounded reason code")
        self.reason_code = reason_code
        super().__init__(reason_code)


class OperationHorizon(BaseModel):
    """Validity values supplied with one proposal, not a new grant of authority."""

    source: Literal["runtime_proposal"] = "runtime_proposal"
    proposal_commitment: str
    not_before: str | None = None
    expires_at: str | None = None


class ResolutionInput(BaseModel):
    """Non-authorizing, minimized evidence of one actual resolution read.

    A digest identifies the full record without retaining its raw contents.
    Missing records are explicit; an absent row means the input was not read.
    """

    input_type: Literal["manifest", "authority_context", "grant", "policy", "approval",
                        "evidence", "role_mapping", "identity", "mandate", "conflict", "purpose"]
    input_id: str
    expected: dict[str, str] = Field(default_factory=dict)
    observed: dict[str, str] = Field(default_factory=dict)
    record_commitment: str | None = None
    missing: bool = False
    previous_observed_at: str | None = None
    read_state: str | None = Field(default=None, exclude_if=lambda v: v is None)
    # freshness/0.1 only: how the age of this read is known. Omitted while unset (default path unchanged).
    age_basis: Literal["nonce_bound", "source_asserted"] | None = Field(default=None, exclude_if=lambda v: v is None)


class RuntimeDecision(BaseModel):
    reason_vocabulary_version: str | None = Field(default=None, exclude_if=lambda v: v is None)
    rule_identity: dict | None = Field(default=None, exclude_if=lambda v: v is None)
    reopen_conditions: list[dict] = Field(default_factory=list, exclude_if=lambda v: not v)
    decision_id: str
    effect_id: str
    result: Literal["authorized", "hold", "deny"]
    reasons: list[str]
    decided_at: str
    # freshness/0.1 only: the named clocks (``decided_at`` stays the evaluation time).
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)
    recorded_at: str | None = Field(default=None, exclude_if=lambda v: v is None)
    time_source: Literal["unrecorded", "control_plane", "test_override"] = "unrecorded"
    operation_horizon: OperationHorizon | None = None
    binding: TenantAuthorizationBinding | AuthorizationBinding | None = None
    resolution_inputs: list[ResolutionInput] = Field(default_factory=list)


class EffectAttempt(BaseModel):
    attempt_id: str
    effect_id: str
    decision_id: str
    started_at: str
    # freshness/0.1 only: ``started_at`` stays the evaluation time; ``recorded_at`` is re-stamped at every write of the row.
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)
    recorded_at: str | None = Field(default=None, exclude_if=lambda v: v is None)
    time_source: Literal["unrecorded", "control_plane", "test_override"] = "unrecorded"
    status: Literal["attempted", "acknowledged", "unknown", "failed", "partial"]
    acknowledgement: dict = Field(default_factory=dict)
    error: str | None = None


class RefusalInputVersion(BaseModel):
    """Minimized effect-time input attribution; never contains raw proposal payload."""

    input_type: Literal["grant", "policy", "approval", "evidence", "role_mapping"]
    input_id: str
    expected_version: str
    observed_version: str


class EffectTimeRefusal(BaseModel):
    reason_vocabulary_version: str | None = Field(default=None, exclude_if=lambda v: v is None)
    rule_identity: dict | None = Field(default=None, exclude_if=lambda v: v is None)
    reopen_conditions: list[dict] = Field(default_factory=list, exclude_if=lambda v: not v)
    check_id: str | None = Field(default=None, exclude_if=lambda v: v is None)
    refusal_id: str
    decision_id: str
    effect_id: str
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only
    deadline: str | None = Field(default=None, exclude_if=lambda v: v is None)       # freshness/0.1 only
    time_source: Literal["unrecorded", "control_plane", "test_override"] = "unrecorded"
    original_operation_horizon: OperationHorizon | None = None
    operation_horizon: OperationHorizon | None = None
    stage: Literal["effect_time_revalidation"] = "effect_time_revalidation"
    reasons: list[str]
    changed_inputs: list[RefusalInputVersion] = Field(default_factory=list)
    resolution_inputs: list[ResolutionInput] = Field(default_factory=list)


class EffectObservation(BaseModel):
    effect_id: str
    observed_at: str | None = None
    state: Literal["absent", "applied", "partial", "unknown"]
    destination_state: dict = Field(default_factory=dict)


class ObservationPolicy(BaseModel):
    """Required temporal policy for accepting destination observations."""

    max_age_seconds: int = Field(gt=0)
    clock_tolerance_seconds: int = Field(default=5, ge=0)


class ReconciliationResult(BaseModel):
    effect_id: str
    reconciled_at: str
    result: Literal["applied", "observed_absent", "safe_to_retry", "hold"]
    observation: EffectObservation | None = None
    observation_accepted: bool = False
    retry_eligible: bool = False
    reasons: list[str] = Field(default_factory=list)
    evaluation_time: str | None = None
    observation_max_age_seconds: int | None = None
    observation_clock_tolerance_seconds: int | None = None


class ResolutionCheck(BaseModel):
    """Durable read-time checkpoint; no authority or independent custody claim."""

    check_id: str
    stage: Literal["decision", "effect", "claim"]
    evaluated_at: str
    recorded_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only
    time_source: Literal["control_plane", "test_override"]
    inputs: list[ResolutionInput]
    reasons: list[str]


class AttemptCloseout(BaseModel):
    """Append-only observation linked to an original uncertain or failed attempt."""

    attempt_id: str
    effect_id: str
    original_status: str
    observed_state: Literal["applied", "partial"]
    observed_at: str
    reconciled_at: str


class CheckEvent(BaseModel):
    """Append-only local resolution journal; no external commit assertion."""
    check_id: str
    # freshness/0.1 adds ``overdue`` (a live check past its deadline; not terminal) and ``expired`` (the licence of a completed
    # check withdrawn at the dispatch gate; terminal).
    phase: Literal["opened", "input", "completed", "interrupted", "overdue", "expired"]
    stage: Literal["decision", "effect", "claim"]
    recorded_at: str
    # freshness/0.1 only, all omitted while unset: the evaluation clock, the deadline fixed at opening, the age bound that
    # produced it (with the extension that raised it, if any) and the nonce sent with this check's reads.
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)
    deadline: str | None = Field(default=None, exclude_if=lambda v: v is None)
    age_bound_seconds: int | None = Field(default=None, exclude_if=lambda v: v is None)
    extension_id: str | None = Field(default=None, exclude_if=lambda v: v is None)
    nonce: str | None = Field(default=None, exclude_if=lambda v: v is None)
    owner: dict[str, str]
    proposal_commitment: str
    decision_id: str | None = None
    effect_id: str | None = None
    action_class: dict = Field(default_factory=dict)
    input: ResolutionInput | None = None
    reasons: list[str] = Field(default_factory=list)
    reason_vocabulary_version: str = "runtime-authority-reasons/0.1"


def _process_owner() -> dict[str, str]:
    """Diagnostic identity only; liveness is enforced by a kernel file lease."""
    return {"pid": str(os.getpid()), "token": str(uuid.uuid4())}


class _ResolverReadFailure(Exception):
    pass


class _JournalInputs(list):
    def __init__(self, values, on_input, *, nonce=None, freshness=False):
        super().__init__(values)
        self.records = {}
        self.read_states = {}
        self.on_input = on_input
        # freshness/0.1: the check's nonce, how each read's age is known, and reads whose echoed nonce did not match.
        self.nonce, self.freshness = nonce, freshness
        self.age_bases = {}
        self.mismatches = {}

    def append(self, item):
        key = (item.input_type, item.input_id)
        item.read_state = item.read_state or self.read_states.get(key)
        if self.freshness and item.input_type != "manifest":
            item.age_basis = item.age_basis or self.age_bases.get(key, "source_asserted")
            if key in self.mismatches:
                requested, echoed = self.mismatches[key]
                item.expected = {**item.expected, "nonce": requested}
                item.observed = {**item.observed, "nonce": str(echoed)}
        self.on_input(item)  # persist before exposing the completed read
        super().append(item)


from .reason_vocabulary import VocabularyChange


class BoundedRunRecord(BaseModel):
    # operation-identity/0.1 ledgers; omitted from the document while empty (default path unchanged).
    operations: list[OperationAdmissionRow] = Field(default_factory=list, exclude_if=lambda v: not v)
    operation_renewals: list[OperationRenewalRow] = Field(default_factory=list, exclude_if=lambda v: not v)
    attempt_joins: list[AttemptJoin] = Field(default_factory=list, exclude_if=lambda v: not v)
    vocabulary_changes: list[VocabularyChange] = Field(default_factory=list, exclude_if=lambda v: not v)
    age_extensions: list[AgeBoundExtension] = Field(default_factory=list, exclude_if=lambda v: not v)
    age_extension_refusals: list[AgeBoundExtensionRefusal] = Field(default_factory=list, exclude_if=lambda v: not v)
    recovery_runs: list[RecoveryRun] = Field(default_factory=list, exclude_if=lambda v: not v)
    rule_revisions: list[RuleRevision] = Field(default_factory=list, exclude_if=lambda v: not v)
    rule_revision_refusals: list[RuleRevisionRefusal] = Field(default_factory=list, exclude_if=lambda v: not v)
    # merge-record/0.1, reversibility/0.1 and dedupe-ttl/0.1 ledgers (stream N4); omitted while empty (default path unchanged).
    merge_records: list[MergeRecord] = Field(default_factory=list, exclude_if=lambda v: not v)
    compensation_obligations: list[CompensationObligation] = Field(default_factory=list, exclude_if=lambda v: not v)
    snapshot_uses: list[SnapshotUse] = Field(default_factory=list, exclude_if=lambda v: not v)
    dedupe_escalations: list[DedupeEscalation] = Field(default_factory=list, exclude_if=lambda v: not v)
    check_events: list[CheckEvent] = Field(default_factory=list, exclude_if=lambda v: not v)
    run_id: str
    input_time_floors: dict[str, str] = Field(default_factory=dict)
    resolution_checks: list[ResolutionCheck] = Field(default_factory=list)
    closeouts: list[AttemptCloseout] = Field(default_factory=list)
    decisions: list[RuntimeDecision] = Field(default_factory=list)
    refusals: list[EffectTimeRefusal] = Field(default_factory=list)
    attempts: list[EffectAttempt] = Field(default_factory=list)
    observations: list[EffectObservation] = Field(default_factory=list)
    reconciliations: list[ReconciliationResult] = Field(default_factory=list)


class BoundedRecordStore:
    """Same-host JSON records with Linux local-filesystem transaction protection.

    All writers must use this implementation and the same canonical path. The
    persistent sidecar lock must never be unlinked while clients may be active.
    This transaction covers records only, not destination execution.
    """

    def __init__(self, path: str | Path, run_id: str):
        self.path = Path(path).resolve()
        self.run_id = run_id
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._require_local_locking()
        with self._transaction():
            if self.path.exists():
                self._read_document()  # Corruption must not initialize an empty store.
            else:
                self._write(BoundedRunRecord(run_id=run_id).model_dump(mode="json"))

    def _require_local_locking(self) -> None:
        if sys.platform != "linux" or fcntl is None:
            raise RuntimeError("BoundedRecordStore requires Linux local filesystem flock support")
        # Fail closed for network/FUSE/unknown filesystems rather than assuming
        # their flock/rename/fsync semantics match a local filesystem.
        supported = {"ext2", "ext3", "ext4", "xfs", "btrfs", "tmpfs", "overlay"}
        mounts = []
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            mount = left.split()[4]
            for code, char in (("\\040", " "), ("\\011", "\t"), ("\\012", "\n"), ("\\134", "\\")):
                mount = mount.replace(code, char)
            mount_path = Path(mount)
            if self.path.parent == mount_path or mount_path in self.path.parent.parents:
                mounts.append((len(mount_path.parts), right.split()[0]))
        if not mounts or max(mounts, key=lambda item: item[0])[1] not in supported:
            raise RuntimeError("BoundedRecordStore filesystem is not supported for local locking")

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with self._lock:
            # No persistent descriptor survives between transactions.
            # Lock the stable sidecar inode, never the atomically replaced data inode.
            fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)  # Kernel also releases the lock when a process dies.

    def _read_document(self) -> dict:
        document = strict_loads(self.path.read_bytes())
        BoundedRunRecord.model_validate(document)
        return document

    def load(self) -> BoundedRunRecord:
        """Read a complete, validated record under the same interprocess lock."""
        with self._transaction():
            return BoundedRunRecord.model_validate(self._read_document())

    def decision(self, decision_id: str) -> RuntimeDecision | None:
        matches = [d for d in self.load().decisions if d.decision_id == decision_id]
        return matches[0] if len(matches) == 1 else None

    def append_decision(self, value: RuntimeDecision) -> None:
        self._append("decisions", value)

    def append_refusal(self, value: EffectTimeRefusal) -> None:
        self._append("refusals", value)

    def append_attempt(self, value: EffectAttempt) -> None:
        self._append("attempts", value)

    def append_observation(self, value: EffectObservation) -> None:
        self._append("observations", value)

    def append_reconciliation(self, value: ReconciliationResult) -> None:
        self._append("reconciliations", value)

    def record_resolution_check(
        self, *, inputs: list[ResolutionInput], now: datetime,
        stage: Literal["decision", "effect", "claim"],
        time_source: Literal["control_plane", "test_override"],
        reasons: list[str], tolerance_seconds: int, check_id: str | None = None,
        recorded_at: str | None = None,
    ) -> list[str]:
        """Compare and advance local per-input time floors in one transaction."""
        with self._transaction():
            document = self._read_document()
            floors = document.setdefault("input_time_floors", {})
            result = list(reasons)
            for item in inputs:
                stamp = item.observed.get("observed_at")
                if not stamp:
                    continue
                observed = _parse(stamp)
                key = commitment([item.input_type, item.input_id])
                previous = floors.get(key)
                item.previous_observed_at = previous
                if previous is not None and observed < _parse(previous):
                    result.append("input_observation_time_regressed")
                # Invalid future timestamps cannot poison the durable floor.
                elif observed <= now + timedelta(seconds=tolerance_seconds):
                    floors[key] = _iso(observed)
            result = sorted(set(result))
            check = ResolutionCheck(
                check_id=check_id or str(uuid.uuid4()), stage=stage, evaluated_at=_iso(now),
                time_source=time_source, inputs=inputs, reasons=result,
                **({"recorded_at": recorded_at} if recorded_at else {}),
            )
            document.setdefault("resolution_checks", []).append(check.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)
            return result

    def close_uncertain_attempts(self, reconciliation: ReconciliationResult) -> None:
        """Retain contrary/later accepted observations without rewriting attempts."""
        observation = reconciliation.observation
        if not reconciliation.observation_accepted or observation is None or observation.state not in {"applied", "partial"}:
            return
        with self._transaction():
            document = self._read_document()
            latest = {item["attempt_id"]: item for item in document.get("attempts", [])
                      if item["effect_id"] == reconciliation.effect_id}
            closeouts = document.setdefault("closeouts", [])
            for attempt_id, attempt in latest.items():
                if attempt["status"] not in {"attempted", "unknown", "failed"}:
                    continue
                if any(c["attempt_id"] == attempt_id and c["observed_state"] == observation.state for c in closeouts):
                    continue
                closeouts.append(AttemptCloseout(
                    attempt_id=attempt_id, effect_id=reconciliation.effect_id,
                    original_status=attempt["status"], observed_state=observation.state,
                    observed_at=observation.observed_at,
                    reconciled_at=reconciliation.reconciled_at,
                ).model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    def _append(self, field: str, value: BaseModel) -> None:
        with self._transaction():
            # Reload inside the transaction: stale instances cannot overwrite a
            # newer successful append. Preserve historical/extension fields raw.
            document = self._read_document()
            document.setdefault(field, []).append(value.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    def _check_lease_path(self, check_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", check_id):
            raise ValueError("invalid check identity")
        return self.path.with_name(self.path.name + ".check-" + check_id + ".lock")

    @contextmanager
    def check_lease(self, check_id: str, *, acquire_timeout: float | None = None):
        """Hold a stable per-check kernel lease; process death releases it.

        Legacy (``acquire_timeout`` None): a blocking flock with no timeout. freshness/0.1 passes its acquisition deadline:
        the lease is then taken non-blocking and ``CheckLeaseUnavailable`` is raised when the deadline passes.
        """
        fd = os.open(self._check_lease_path(check_id), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            if acquire_timeout is None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            else:
                acquire_lease_nonblocking(fd, acquire_timeout)
            yield
        finally:
            os.close(fd)

    def _check_is_live(self, check_id: str) -> bool:
        fd = os.open(self._check_lease_path(check_id), os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
            except BlockingIOError:
                return True
        finally:
            os.close(fd)

    def admit_operation(self, row: OperationAdmissionRow) -> str:
        """Admit an operation on its first authorized decision, or judge a later binding.

        Atomic. Returns ``ok``, ``collision`` (the id is bound to another principal,
        domain, issuer or grant) or ``renewal_unrecorded`` (a new grant revision that no
        accepted renewal row names).
        """
        with self._transaction():
            document = self._read_document()
            status = operation_status(
                document, operation_id=row.operation_id, principal_id=row.principal_id,
                authority_domain=row.authority_domain, issuer=row.issuer, grant_id=row.grant_id,
                grant_revision=row.first_grant_revision)
            if status != "not_admitted":
                return status
            document.setdefault("operations", []).append(row.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)
            return "ok"

    def operation_status(self, **binding) -> str:
        """Read-only ledger judgement of a binding (see ``operation_identity.operation_status``)."""
        with self._transaction():
            return operation_status(self._read_document(), **binding)

    def record_renewal(self, *, operation_id: str, to_revision: str, written_by: str,
                       recorded_at: str, evaluated_at: str | None = None) -> OperationRenewalRow:
        """Record a renewal row. Only the issuer recorded at admission may write an accepted one.

        Any other writer, an unknown operation or a revision that is not new yields a
        ``refused`` row, which is retained: refusals are recorded, never silent.
        """
        from .operation_identity import CODE_NOT_ADMITTED, CODE_NOT_BY_ISSUER, CODE_REVISION_NOT_NEW
        with self._transaction():
            document = self._read_document()
            admitted = next((x for x in document.get("operations", []) if x["operation_id"] == operation_id), None)
            code = None
            if admitted is None:
                code = CODE_NOT_ADMITTED
            elif written_by != admitted["issuer"]:
                code = CODE_NOT_BY_ISSUER
            elif to_revision in licensed_revisions(document, operation_id):
                code = CODE_REVISION_NOT_NEW
            accepted = [x["to_revision"] for x in document.get("operation_renewals", [])
                        if x["operation_id"] == operation_id and x["outcome"] == "accepted"]
            row = OperationRenewalRow(
                renewal_id=str(uuid.uuid4()), operation_id=operation_id,
                grant_id=admitted["grant_id"] if admitted else None,
                from_revision=(accepted[-1] if accepted else admitted["first_grant_revision"]) if admitted else None,
                to_revision=to_revision, written_by=written_by,
                outcome="refused" if code else "accepted", refusal_code=code, recorded_at=recorded_at,
                **({"evaluated_at": evaluated_at} if evaluated_at else {}))
            document.setdefault("operation_renewals", []).append(row.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)
            return row

    def append_attempt_join(self, value: AttemptJoin) -> None:
        with self._transaction():
            document = self._read_document()
            if any(x["attempt_id"] == value.attempt_id for x in document.get("attempt_joins", [])):
                raise ValueError("attempt already joined")
            document.setdefault("attempt_joins", []).append(value.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    def document_snapshot(self) -> dict:
        """One consistent read of the whole retained document (a copy; nothing is written)."""
        with self._transaction():
            return self._read_document()

    def record_merge(self, *, profile: _merge.MergeProfile, rule_profile, survivor: str, folded: list[str],
                     equivalence_rule_ref: str, equivalence_rule_digest: str, merged_by: str, authority_ref: str | None,
                     reason: str, recorded_at: str, evaluated_at: str | None = None) -> MergeRecord:
        """Judge and append one merge (and its compensation obligation, if two effects already landed) in one transaction.

        Every outcome is appended as a row (``merged``, ``held``, ``unknown`` or ``refused``); only ``merged`` has effect. Nothing
        already written is edited.
        """
        with self._transaction():
            document = self._read_document()
            record, obligation = _merge.resolve_merge(
                document, profile=profile, rule_profile=rule_profile, survivor=survivor, folded=folded,
                equivalence_rule_ref=equivalence_rule_ref, equivalence_rule_digest=equivalence_rule_digest,
                merged_by=merged_by, authority_ref=authority_ref, reason=reason, recorded_at=recorded_at, evaluated_at=evaluated_at)
            document.setdefault("merge_records", []).append(record.model_dump(mode="json"))
            if obligation is not None:
                document.setdefault("compensation_obligations", []).append(obligation.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)
            return record

    def append_snapshot_use(self, value: SnapshotUse) -> None:
        self._append("snapshot_uses", value)

    def append_escalations(self, build) -> list[DedupeEscalation]:
        """Append the escalation rows ``build(document)`` says are due, once per effect, in one transaction."""
        with self._transaction():
            document = self._read_document()
            rows = [x for x in build(document) if not any(e["effect_id"] == x.effect_id for e in document.get("dedupe_escalations", []))]
            if rows:
                document.setdefault("dedupe_escalations", []).extend(x.model_dump(mode="json") for x in rows)
                BoundedRunRecord.model_validate(document)
                self._write(document)
            return rows

    def append_vocabulary_change(self, event: VocabularyChange) -> None:
        """Persist a governed change without reinterpreting existing refusal rows."""
        _parse(event.acknowledged_at)
        if event.version == event.previous_version or (event.kind == "split" and len(event.codes) < 2):
            raise ValueError("invalid vocabulary transition")
        with self._transaction():
            document = self._read_document()
            changes = document.setdefault("vocabulary_changes", [])
            if any(x["change_id"] == event.change_id for x in changes):
                raise ValueError("vocabulary change already recorded")
            changes.append(event.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    @staticmethod
    def _enforce_check_event_rules(events: list, event: CheckEvent) -> None:
        """Journal opening, ownership and terminality rules for one new event over the existing ones."""
        previous = [x for x in events if x["check_id"] == event.check_id]
        if event.phase == "opened":
            if previous:
                raise ValueError("check already opened")
        elif not previous or previous[0]["phase"] != "opened":
            raise ValueError("check opening missing")
        elif event.phase == "expired":
            # freshness/0.1: withdraw the licence of a completed (or still open) check, once; never after recovery closed it.
            if any(x["phase"] in {"interrupted", "expired"} for x in previous):
                raise ValueError("check already closed")
        elif any(x["phase"] in {"completed", "interrupted", "expired"} for x in previous):
            raise ValueError("check already closed")
        elif event.phase == "overdue" and any(x["phase"] == "overdue" for x in previous):
            raise ValueError("check already reported overdue")
        if previous and event.phase != "opened" and event.owner != previous[0]["owner"]:
            raise ValueError("check owner mismatch")

    def append_check_event(self, event: CheckEvent) -> None:
        """Atomically enforce journal opening, ownership and terminality."""
        with self._transaction():
            document = self._read_document()
            events = document.setdefault("check_events", [])
            self._enforce_check_event_rules(events, event)
            events.append(event.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    def record_gate_refusal(self, attempt: EffectAttempt, refusal: EffectTimeRefusal, event: CheckEvent) -> None:
        """Persist a dispatch-gate refusal (failed attempt, effect-time refusal, ``expired`` journal event) in ONE write.

        Three separate appends left a record the coupling rules refuse if the process died between them. Here the journal
        rules are checked first and the document is replaced once, so a reader sees all three rows or none.
        """
        with self._transaction():
            document = self._read_document()
            events = document.setdefault("check_events", [])
            self._enforce_check_event_rules(events, event)
            document.setdefault("attempts", []).append(attempt.model_dump(mode="json"))
            document.setdefault("refusals", []).append(refusal.model_dump(mode="json"))
            events.append(event.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)

    def recover_interrupted_checks(self) -> int:
        """Close only checks whose recorded local process identity is gone."""
        recovered = 0
        with self._transaction():
            document = self._read_document()
            events = document.get("check_events", [])
            closed = {x["check_id"] for x in events if x["phase"] in {"completed", "interrupted"}}
            for opening in list(events):
                if opening["phase"] != "opened" or opening["check_id"] in closed or self._check_is_live(opening["check_id"]):
                    continue
                end = dict(opening, phase="interrupted", recorded_at=_iso(_now()), reasons=["check_interrupted"])
                events.append(end)
                recovered += 1
            if recovered:
                BoundedRunRecord.model_validate(document)
                self._write(document)
        return recovered

    def check_opening(self, check_id: str) -> dict | None:
        """The opening journal event of one check (raw), or None."""
        with self._transaction():
            return next((x for x in self._read_document().get("check_events", [])
                         if x["check_id"] == check_id and x["phase"] == "opened"), None)

    def recovery_pass(self, *, trigger: Literal["startup", "interval", "manual"] = "manual",
                      now: datetime | None = None, record_run: bool = False) -> RecoveryReport:
        """freshness/0.1 recovery pass: close abandoned checks, report live checks past their deadline, close nothing alive.

        * dead lease, no terminal event: closed ``interrupted`` (as ``recover_interrupted_checks`` does);
        * live lease past its deadline: reported ``check_overdue`` and a non-terminal ``overdue`` event is written once. The
          process is alive, so the check is NOT closed;
        * live lease within its deadline, or a legacy check with no deadline: open.
        With ``record_run`` a ``RecoveryRun`` row (counts, trigger, service time) is appended in the same transaction.
        """
        at = (now or _now()).astimezone(timezone.utc)
        report = RecoveryReport(as_of=_iso(at))
        oldest: float | None = None
        with self._transaction():
            document = self._read_document()
            events = document.get("check_events", [])
            terminal = {"completed", "interrupted", "expired"}
            closed = {x["check_id"] for x in events if x["phase"] in terminal}
            overdue_written = {x["check_id"] for x in events if x["phase"] == "overdue"}
            for opening in list(events):
                if opening["phase"] != "opened" or opening["check_id"] in closed:
                    continue
                check_id = opening["check_id"]
                if not self._check_is_live(check_id):
                    end = dict(opening, phase="interrupted", recorded_at=_iso(at), reasons=["check_interrupted"])
                    end.pop("evaluated_at", None)
                    events.append(end)
                    report.interrupted.append(check_id)
                    continue
                age = (at - _parse(opening["recorded_at"])).total_seconds()
                oldest = age if oldest is None else max(oldest, age)
                deadline = opening.get("deadline")
                if deadline and at > _parse(deadline):
                    report.overdue.append({"check_id": check_id, "deadline": deadline, "reasons": [_fresh_profile.CODE_OVERDUE],
                                           "overdue_seconds": (at - _parse(deadline)).total_seconds()})
                    if check_id not in overdue_written:
                        mark = dict(opening, phase="overdue", recorded_at=_iso(at), reasons=["check_overdue"],
                                    reason_vocabulary_version=VOCABULARY_VERSION_0_2)
                        mark.pop("evaluated_at", None)
                        events.append(mark)
                else:
                    report.open_within_deadline.append(check_id)
            report.oldest_open_age_seconds = oldest
            if record_run:
                document.setdefault("recovery_runs", []).append(RecoveryRun(
                    run_id=str(uuid.uuid4()), trigger=trigger, recorded_at=_iso(at), interrupted=report.interrupted,
                    overdue=[x["check_id"] for x in report.overdue],
                    open_count=len(report.overdue) + len(report.open_within_deadline),
                    oldest_open_age_seconds=oldest).model_dump(mode="json"))
            if report.interrupted or report.overdue or record_run:
                BoundedRunRecord.model_validate(document)
                self._write(document)
        return report

    def record_age_extension(self, extension: AgeBoundExtension, *, rule_profile: RuleRevisionProfile | None,
                             max_extension_seconds: int, base_seconds: int | None = None) -> AgeBoundExtension:
        """Append an outage extension of a class age bound, or persist a refusal row and raise ``AgeExtensionRefused``.

        The signer must belong to the signer set configured in the rule-revision profile (N2) and must not be the requester;
        the extension may not exceed the freshness profile's declared limit. Authority is re-checked every time the row is used.
        """
        _parse(extension.not_before), _parse(extension.expires_at), _parse(extension.recorded_at)
        reasons = extension_defects(rule_profile, extension, max_extension_seconds=max_extension_seconds,
                                    base_seconds=base_seconds)
        with self._transaction():
            document = self._read_document()
            rows = document.setdefault("age_extensions", [])
            if any(x["extension_id"] == extension.extension_id for x in rows):
                reasons.append("age_extension_invalid")
            if not reasons:
                rows.append(extension.model_dump(mode="json"))
                BoundedRunRecord.model_validate(document)
                self._write(document)
                return extension
            refusal = AgeBoundExtensionRefusal(
                refusal_id=str(uuid.uuid4()), extension=extension.model_dump(mode="json"),
                reasons=sorted(set(reasons)), recorded_at=extension.recorded_at)
            document.setdefault("age_extension_refusals", []).append(refusal.model_dump(mode="json"))
            BoundedRunRecord.model_validate(document)
            self._write(document)
        raise AgeExtensionRefused(refusal.reasons)

    def _write(self, document: dict) -> None:
        """Replace the JSON document; caller must hold the transaction lock."""
        directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except FileNotFoundError:
                    pass


class SyntheticResolver:
    """Deterministic synthetic resolver; not institutionally authenticated."""

    authenticated = False

    def __init__(self, *, contexts, statuses, identities, mandates, approvals, policies,
                 conflicts, evidence, role_mappings):
        self.contexts = contexts
        self.statuses = statuses
        self.identities = identities
        self.mandates = mandates
        self.approvals = approvals
        self.policies = policies
        self.conflicts = conflicts
        self.evidence = evidence
        self.role_mappings = role_mappings
        self._authority_effect_lock = threading.RLock()

    #: freshness/0.1 (opt-in, CI only): when True this synthetic resolver declares ``status-nonce/0.1`` and echoes the reader's nonce.
    echo_nonce = False

    @property
    def nonce_capability(self) -> str | None:
        return _fresh_profile.NONCE_CAPABILITY if self.echo_nonce else None

    def nonce_read(self, nonce: str, method: str, *args):
        """Serve one read and echo the reader's nonce, so the reader can bind the response's age to its own check."""
        return getattr(self, method)(*args), nonce

    def authority_context(self, ref: str) -> dict | None:
        return copy.deepcopy(self.contexts.get(ref))

    def grant_status(self, grant_id: str) -> GrantStatus | None:
        value = self.statuses.get(grant_id)
        return value.model_copy(deep=True) if value else None

    def identity_status(self, acting_identity: str, principal: str) -> IdentityStatus:
        value = self.identities.get(acting_identity)
        return value.model_copy(deep=True) if value else IdentityStatus(
            identity=acting_identity,
            principal=principal,
            authenticated=False,
            delegation_valid=False,
            observed_at=_iso(_now()),
            institution_id="urn:cognous:institution:unknown",
            authority_domain="unknown",
        )

    def issuer_mandate(self, issuer: str, issuer_role: str) -> MandateStatus:
        value = self.mandates.get(f"{issuer}|{issuer_role}")
        return value.model_copy(deep=True) if value else MandateStatus(
            issuer=issuer,
            issuer_role=issuer_role,
            issuance_record_ref="urn:cognous:issuance:unknown",
            mandate_valid=False,
            observed_at=_iso(_now()),
            institution_id="urn:cognous:institution:unknown",
            authority_domain="unknown",
        )

    def approval_status(self, approval_ref: str) -> ApprovalStatus | None:
        value = self.approvals.get(approval_ref)
        return value.model_copy(deep=True) if value else None

    def policy_status(self, ref: str) -> PolicyStatus | None:
        value = self.policies.get(ref)
        return value.model_copy(deep=True) if value else None

    def conflict_status(self, requirement_id: str) -> ConflictStatus | None:
        value = self.conflicts.get(requirement_id)
        return value.model_copy(deep=True) if value else None

    def evidence_status(self, obligation_id: str) -> EvidenceStatus | None:
        value = self.evidence.get(obligation_id)
        return value.model_copy(deep=True) if value else None

    def role_mapping(self, institution_id: str) -> RoleMappingStatus | None:
        value = self.role_mappings.get(institution_id)
        return value.model_copy(deep=True) if value else None

    @contextmanager
    def authority_effect_handoff(self, ref: str):
        """Hold the synthetic authority snapshot stable through trusted provisioning.

        This is a same-process test implementation. A real resolver claiming this
        handoff contract must ensure every authority-invalidating writer
        participates in the same exclusion mechanism.
        """
        with self._authority_effect_lock:
            yield

    def authority_effect_snapshot(self, ref: str) -> dict | None:
        """Return one coherent projection for local claim issuance."""
        context = self.contexts.get(ref)
        if context is None:
            return None
        grant = context.get("grant") or {}
        requirement = context.get("requirement") or {}
        return {
            "context": copy.deepcopy(context),
            "grant_status": (
                self.statuses[grant["grant_id"]].model_copy(deep=True)
                if grant.get("grant_id") in self.statuses else None
            ),
            "approvals": {
                approval_ref: self.approvals[approval_ref].model_copy(deep=True)
                for approval_ref in grant.get("approval_refs", [])
                if approval_ref in self.approvals
            },
            "policies": {
                item["ref"]: self.policies[item["ref"]].model_copy(deep=True)
                for item in grant.get("policy_versions", [])
                if item.get("ref") in self.policies
            },
            "evidence": {
                item["obligation_id"]: self.evidence[item["obligation_id"]].model_copy(deep=True)
                for item in requirement.get("evidence", [])
                if item.get("obligation_id") in self.evidence
            },
        }


class LocalRefundDestination:
    """Durable synthetic destination with effect dedupe and local cumulative cap.

    With ``operation_id`` (operation-identity/0.1 only) the destination also refuses a
    second effect for the same operation under a different ``effect_id``.
    """

    operation_identity_capability = OPERATION_IDENTITY_CAPABILITY

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        with self._transaction():
            if not self.path.exists():
                self._write({"effects": {}, "grant_effect_counts": {}})

    def apply(self, *, effect_id: str, grant_id: str, max_effects: int, target: str,
              amount: float, unit: str, payload: dict, lose_ack: bool = False,
              partial: bool = False, operation_id: str | None = None) -> dict:
        with self._transaction():
            state = self._load()
            if effect_id in state["effects"]:
                return {"duplicate": True, "effect": copy.deepcopy(state["effects"][effect_id])}
            if operation_id is not None and operation_id in state.get("operations", {}):
                raise DefinitiveDestinationRejection("operation_already_committed")
            used = int(state["grant_effect_counts"].get(grant_id, 0))
            if used >= max_effects:
                raise DefinitiveDestinationRejection("cumulative_grant_max_effects_exhausted")
            effect = {
                "effect_id": effect_id,
                "grant_id": grant_id,
                "target": target,
                "amount": amount,
                "unit": unit,
                "payload": copy.deepcopy(payload),
                "state": "partial" if partial else "applied",
            }
            state["effects"][effect_id] = effect
            state["grant_effect_counts"][grant_id] = used + 1
            if operation_id is not None:
                state.setdefault("operations", {})[operation_id] = effect_id
            self._write(state)
            if lose_ack:
                raise TimeoutError("synthetic acknowledgement lost after commit")
            return {"duplicate": False, "effect": copy.deepcopy(effect)}

    def observe(self, effect_id: str) -> EffectObservation:
        with self._transaction():
            effect = self._load()["effects"].get(effect_id)
            if effect is None:
                return EffectObservation(effect_id=effect_id, observed_at=_iso(_now()), state="absent")
            state = "partial" if effect["state"] == "partial" else "applied"
            return EffectObservation(
                effect_id=effect_id,
                observed_at=_iso(_now()),
                state=state,
                destination_state=copy.deepcopy(effect),
            )

    def snapshot(self) -> dict:
        with self._transaction():
            return copy.deepcopy(self._load())

    def _load(self) -> dict:
        return strict_loads(self.path.read_bytes())

    @contextmanager
    def _transaction(self):
        """Serialize initialization, reads and writes across cooperating processes."""
        if fcntl is None:
            raise RuntimeError("inter-process destination locking unavailable")
        with self._lock:
            with self.path.with_name(self.path.name + ".lock").open("a+b") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _write(self, state: dict) -> None:
        """Persist before acknowledging; caller holds the destination transaction."""
        directory_fd = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        temporary = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=self.path.name + ".", dir=self.path.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
            if temporary is not None:
                try: os.unlink(temporary)
                except FileNotFoundError: pass


class BoundedAuthorizationWorkflow:
    """Resolve, decide, revalidate and execute one finite declared operation."""

    def __init__(
        self,
        *,
        manifest: dict,
        resolver: Resolver,
        destination: LocalRefundDestination,
        records: BoundedRecordStore,
        status_max_age_seconds: int = 60,
        identity_max_age_seconds: int = 60,
        mandate_max_age_seconds: int = 60,
        approval_max_age_seconds: int = 60,
        clock_tolerance_seconds: int = 5,
        observation_policy: ObservationPolicy | None = None,
        allow_test_time: bool = False,
        runtime_authority_profile=None,
        rule_revision_profile=None,
    ):
        self.allow_test_time = allow_test_time
        self._reaper = None  # the reaper this workflow handed out; a failed one makes decide/execute refuse
        self._mono_open: dict[str, tuple[float, int]] = {}  # check_id -> (monotonic at opening, age bound) under freshness/0.1
        self.rule_revision_profile = (RuleRevisionProfile.model_validate(rule_revision_profile)
                                      if rule_revision_profile is not None else None)
        self.runtime_authority_profile = (RuntimeAuthorityProfile.model_validate(runtime_authority_profile).snapshot()
                                          if runtime_authority_profile is not None else None)
        if (self.runtime_authority_profile and self.runtime_authority_profile.allow_synthetic_resolver
                and not allow_test_time):
            raise ValueError("synthetic authority profile requires explicit test clock")
        self.manifest = copy.deepcopy(manifest)
        self.resolver = resolver
        self.destination = destination
        self.records = records
        self.status_max_age_seconds = status_max_age_seconds
        self.identity_max_age_seconds = identity_max_age_seconds
        self.mandate_max_age_seconds = mandate_max_age_seconds
        self.approval_max_age_seconds = approval_max_age_seconds
        self.clock_tolerance_seconds = clock_tolerance_seconds
        self.observation_policy = observation_policy.model_copy(deep=True) if observation_policy else None

    @property
    def time_source(self) -> Literal["control_plane", "test_override"]:
        """Identify the configured clock trust boundary in retained records."""
        return "test_override" if self.allow_test_time else "control_plane"

    def _evaluation_time(self, supplied: datetime | None) -> datetime:
        value = (supplied or _now()) if self.allow_test_time else _now()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evaluation time must be timezone-aware")
        return value.astimezone(timezone.utc)

    def _rule_identity(self, inputs) -> dict | None:
        """Digests (not only versions) of the rules a row relied on; None unless rule-revision/0.1 is configured."""
        if self.rule_revision_profile is None:
            return None
        digests = {x.input_id: x.observed.get("digest") for x in inputs if x.input_type == "policy"}
        return rule_identity(self.rule_revision_profile, self.records.load().rule_revisions, digests)

    @staticmethod
    def _horizon(proposal: RuntimeProposal) -> OperationHorizon:
        return OperationHorizon(
            proposal_commitment=commitment(proposal.model_dump(mode="json", exclude_none=False)),
            not_before=proposal.not_before, expires_at=proposal.expires_at,
        )

    def _record_check(self, inputs: list[ResolutionInput], now: datetime,
                      reasons: list[str], stage: Literal["decision", "effect", "claim"],
                      check_id: str | None = None) -> list[str]:
        return self.records.record_resolution_check(
            inputs=inputs, now=now, reasons=reasons, stage=stage,
            time_source=self.time_source, tolerance_seconds=self.clock_tolerance_seconds,
            **({"check_id": check_id} if check_id else {}),
            **({"recorded_at": self._svc()} if self._freshness else {}),
        )

    @property
    def _freshness(self):
        """The opt-in freshness/0.1 configuration, or None on the default path."""
        profile = self.runtime_authority_profile
        return profile.freshness if profile is not None else None

    def _svc(self) -> str:
        """The service clock, re-read now (``recorded_at``)."""
        return _iso(_now())

    def _write_time(self, now: datetime) -> str:
        """Value for a legacy ``*_at`` write field: the evaluation time by default, the service clock under freshness/0.1."""
        return self._svc() if self._freshness else _iso(now)

    def _eval_stamp(self, now: datetime) -> dict:
        return {"evaluated_at": _iso(now)} if self._freshness else {}

    def _stamp_attempt(self, attempt: EffectAttempt, now: datetime) -> None:
        if self._freshness:
            attempt.evaluated_at, attempt.recorded_at = _iso(now), self._svc()

    def _class_age_bound(self, action_id: str, now: datetime) -> tuple[int | None, str | None, list[str]]:
        """The class status-age bound: (seconds, extension_id that raised it, defects of active extensions that do not count)."""
        profile = self.runtime_authority_profile
        cl = profile.actions.get(action_id) if profile is not None else None
        if cl is None:
            return None, None, []
        fr = profile.freshness
        if fr is None:
            return cl.max_status_age_seconds, None, []
        bound, used, defects = effective_age_bound(
            self.rule_revision_profile, self.records.load().age_extensions, class_id=cl.class_id,
            base_seconds=cl.max_status_age_seconds, now=now, max_extension_seconds=fr.max_age_extension_seconds)
        if used is not None and self._reversibility is not None and effective_reversibility(cl, now)[0] == "irreversible":
            # reversibility/0.1: an outage extension never raises the bound of an irreversible class (nor of a class whose
            # reversal window has passed), whatever its signer's authority.
            return cl.max_status_age_seconds, None, [*defects, "age_extension_irreversible_class"]
        return bound, used, defects

    def record_age_extension(self, *, class_id: str, to_max_age_seconds: int, not_before: str, expires_at: str,
                             outage_ref: str, requested_by: str, signer: str | None,
                             authority_ref: str | None = None, now: datetime | None = None) -> AgeBoundExtension:
        """Record an outage extension of one class's age bound as a decision with its authority.

        The signer must be in the signer set configured in the rule-revision profile (N2). A refused attempt is persisted and
        ``AgeExtensionRefused`` raised. Without a freshness profile there is nothing to extend.
        """
        fr = self._freshness
        if fr is None:
            raise PermissionError("freshness profile is not enabled")
        cl = next((c for c in self.runtime_authority_profile.actions.values() if c.class_id == class_id), None)
        if cl is None:
            raise ValueError("unknown action class")
        return self.records.record_age_extension(
            AgeBoundExtension(extension_id=str(uuid.uuid4()), class_id=class_id, from_max_age_seconds=cl.max_status_age_seconds,
                              to_max_age_seconds=to_max_age_seconds, not_before=not_before, expires_at=expires_at,
                              outage_ref=outage_ref, requested_by=requested_by, signer=signer, authority_ref=authority_ref,
                              recorded_at=self._svc(), evaluated_at=_iso(self._evaluation_time(now))),
            rule_profile=self.rule_revision_profile, max_extension_seconds=fr.max_age_extension_seconds,
            base_seconds=cl.max_status_age_seconds)

    def reaper(self, *, clock=None):
        """The host's recovery runner (start-up pass, then the declared interval). Requires the freshness profile."""
        if self._freshness is None:
            raise PermissionError("freshness profile is not enabled")
        self._reaper = Reaper(self.records, self._freshness, clock=clock)
        return self._reaper

    def _require_reaper_alive(self) -> None:
        """Fail closed: once the reaper this workflow started has stopped on an error, no decision or dispatch is made."""
        if self._reaper is not None:
            self._reaper.check()

    def _expired_before_dispatch(self, check_id: str) -> str | None:
        """The check's deadline if the service clock, re-read now, has passed it; else None."""
        opening = self.records.check_opening(check_id)
        deadline = opening.get("deadline") if opening else None
        if not deadline:
            return None
        now = _now()
        if now > _fparse(deadline):
            return deadline
        # Monotonic guard: the wall clock can be stepped back (NTP, operator, VM restore), which would make a stalled check
        # look young. The process monotonic clock cannot go back: elapsed time since this process opened the check, and a
        # wall clock earlier than the recorded opening, both withdraw the licence (fail closed).
        opened = self._mono_open.get(check_id)
        if opened is not None and _monotonic() - opened[0] > opened[1]:
            return deadline
        recorded = opening.get("recorded_at")
        if recorded and now < _fparse(recorded) - timedelta(seconds=self.clock_tolerance_seconds):
            return deadline
        return None

    def _refuse_expired_before_dispatch(self, *, check_id: str, deadline: str, attempt: EffectAttempt,
                                        persisted: RuntimeDecision, frozen, inputs, now: datetime) -> None:
        """Withdraw the licence of a check whose deadline passed before dispatch: nothing is sent to the destination."""
        code = _fresh_profile.CODE_EXPIRED_BEFORE_DISPATCH
        assert code == "check_expired_before_dispatch"
        attempt.status, attempt.error = "failed", code  # definitive: never dispatched (see prior-attempt filter in execute)
        self._stamp_attempt(attempt, now)
        refusal = EffectTimeRefusal(
            check_id=check_id, refusal_id=str(uuid.uuid4()), decision_id=persisted.decision_id, effect_id=persisted.effect_id,
            recorded_at=self._svc(), evaluated_at=_iso(now), deadline=deadline, time_source=self.time_source,
            original_operation_horizon=persisted.operation_horizon, operation_horizon=self._horizon(frozen),
            reason_vocabulary_version=VOCABULARY_VERSION_0_2, rule_identity=self._rule_identity(inputs),
            reasons=["check_expired_before_dispatch"], changed_inputs=[], resolution_inputs=inputs)
        opening = self.records.check_opening(check_id)
        event = CheckEvent.model_validate(
            dict(opening, phase="expired", recorded_at=self._svc(), reasons=["check_expired_before_dispatch"], input=None,
                 reason_vocabulary_version=VOCABULARY_VERSION_0_2))
        self.records.record_gate_refusal(attempt, refusal, event)  # one write: all three rows or none
        raise PermissionError(code)

    @property
    def _identity(self):
        """The opt-in operation-identity/0.1 configuration, or None on the default path."""
        profile = self.runtime_authority_profile
        return profile.operation_identity if profile is not None else None

    @property
    def _merge_profile(self):
        """The opt-in merge-record/0.1 configuration, or None on the default path."""
        profile = self.runtime_authority_profile
        return profile.merge if profile is not None else None

    @property
    def _reversibility(self):
        """The opt-in reversibility/0.1 configuration, or None on the default path."""
        profile = self.runtime_authority_profile
        return profile.reversibility if profile is not None else None

    @property
    def _dedupe(self):
        """The opt-in dedupe-ttl/0.1 configuration, or None on the default path."""
        profile = self.runtime_authority_profile
        return profile.dedupe if profile is not None else None

    def record_merge(self, *, survivor_operation_id: str, folded_operation_ids: list[str], equivalence_rule_ref: str,
                     equivalence_rule_digest: str, merged_by: str, authority_ref: str | None = None, reason: str,
                     now: datetime | None = None) -> MergeRecord:
        """Fold ``folded_operation_ids`` into ``survivor_operation_id`` (operation ids only, never attempt ids).

        Always appends a row and returns it; only an ``outcome == "merged"`` row has effect. A merge by an authority that is not
        funded is ``held``; one whose equivalence-rule digest is not adopted by a signed, independent ``merge_equivalence_rule``
        revision is ``unknown``; a structurally invalid one is ``refused``. The compensation obligation (record only) is written in
        the same transaction when two effects had already been applied.
        """
        profile = self._merge_profile
        if profile is None or self._identity is None:
            raise PermissionError("merge profile is not enabled")
        evaluated = self._evaluation_time(now)
        return self.records.record_merge(
            profile=profile, rule_profile=self.rule_revision_profile, survivor=survivor_operation_id,
            folded=list(folded_operation_ids), equivalence_rule_ref=equivalence_rule_ref,
            equivalence_rule_digest=equivalence_rule_digest, merged_by=merged_by, authority_ref=authority_ref, reason=reason,
            recorded_at=self._write_time(evaluated), **({"evaluated_at": _iso(evaluated)} if self._freshness else {}))

    def dedupe_report(self, *, now: datetime | None = None, destination=None) -> list[dict]:
        """State of every unresolved attempt against the dedupe-ttl/0.1 profile at ``now`` (reads only).

        ``destination`` is the destination that dispatches (its declared capability decides the mode). It defaults to this
        workflow's own; a runtime executor route dispatches through another object, which the host passes here.
        """
        profile = self._dedupe
        if profile is None:
            raise PermissionError("dedupe profile is not enabled")
        return _dedupe_classify(self.records.document_snapshot(), profile,
                                dedupe_mode(destination if destination is not None else self.destination, profile),
                                self._evaluation_time(now))

    def escalation_pass(self, *, now: datetime | None = None, destination=None) -> list[DedupeEscalation]:
        """Record an escalation for every unresolved attempt past its deadline that has none yet.

        A host runs this on its reaper interval. The attempts stay ``unknown``: this only records that someone must look, and
        flags a row that fired after the key TTL (``escalation_after_key_ttl``).
        """
        profile = self._dedupe
        if profile is None:
            raise PermissionError("dedupe profile is not enabled")
        evaluated = self._evaluation_time(now)
        mode = dedupe_mode(destination if destination is not None else self.destination, profile)
        return self.records.append_escalations(lambda document: due_escalations(
            document, profile, mode, evaluated, recorded_at=self._write_time(evaluated),
            evaluated_at=_iso(evaluated) if self._freshness else None))

    def _admit_operation(self, binding: AuthorizationBinding, now: datetime, reasons: list[str]) -> None:
        extension = binding.runtime_authority or {}
        outcome = self.records.admit_operation(OperationAdmissionRow(
            operation_id=extension["operation_id"], principal_id=binding.principal,
            authority_domain=self._authority_domain(binding), issuer=extension["operation_issuer"],
            grant_id=binding.grant_id, first_grant_revision=binding.grant_revision, admitted_at=self._write_time(now),
            **self._eval_stamp(now)))
        if outcome == "collision":
            reasons.append("operation_grant_mismatch")
        elif outcome == "renewal_unrecorded":
            reasons.append("operation_renewal_unrecorded")

    def _operation_gate(self, binding: AuthorizationBinding, reasons: list[str]) -> None:
        extension = binding.runtime_authority or {}
        outcome = self.records.operation_status(
            operation_id=extension["operation_id"], principal_id=binding.principal,
            authority_domain=self._authority_domain(binding), issuer=extension["operation_issuer"],
            grant_id=binding.grant_id, grant_revision=binding.grant_revision)
        if outcome == "not_admitted":
            reasons.append("operation_not_admitted")
        elif outcome == "collision":
            reasons.append("operation_grant_mismatch")
        elif outcome == "renewal_unrecorded":
            reasons.append("operation_renewal_unrecorded")
        elif self._merge_profile is not None or self._dedupe is not None:
            self._effect_gate_n4(binding, extension["operation_id"], reasons)

    def _effect_gate_n4(self, binding: AuthorizationBinding, operation_id: str, reasons: list[str]) -> None:
        """merge-record/0.1 and dedupe-ttl/0.1 effect-time gates (opt-in; reached only when one of them is configured)."""
        document = self.records.document_snapshot()
        effect_id = self._effect_id(binding)
        members = _merge.merge_members(document, operation_id) if self._merge_profile is not None else [operation_id]
        if self._merge_profile is not None:
            merge_code = _merge.merge_gate(document, operation_id, effect_id)
            if merge_code is not None:
                reasons.append(merge_code)
        if self._dedupe is not None and blocks_new_key(document, members, effect_id):
            reasons.append("dedupe_unresolved_attempt_blocks_new_key")
        if self._dedupe is not None and applied_under_other_effect(document, members, effect_id):
            reasons.append("dedupe_operation_effect_applied")

    def _authority_domain(self, binding: AuthorizationBinding) -> str:
        action = next((x for x in self.manifest.get("actions", []) if x.get("action_id") == binding.action_id), {})
        return (action.get("authority_context") or {}).get("authority_domain", "")

    def record_renewal(self, operation_id: str, *, to_revision: str, written_by: str,
                       now: datetime | None = None) -> OperationRenewalRow:
        """Record that ``to_revision`` of the grant continues ``operation_id``.

        Only the grant issuer recorded at admission writes an accepted renewal. A worker
        extending its own envelope is refused: the refusal row is persisted, then raised.
        """
        if self._identity is None:
            raise PermissionError("operation identity profile is not enabled")
        evaluated = self._evaluation_time(now)
        row = self.records.record_renewal(operation_id=operation_id, to_revision=to_revision, written_by=written_by,
                                          recorded_at=self._write_time(evaluated),
                                          **({"evaluated_at": _iso(evaluated)} if self._freshness else {}))
        if row.outcome == "refused":
            raise PermissionError(row.refusal_code)
        return row

    def _join_attempt(self, attempt: EffectAttempt, persisted: RuntimeDecision,
                      current: AuthorizationBinding, check_id: str, now: datetime) -> None:
        """Write-ahead join row: operation, attempt and licensing check share these ids."""
        identity = self._identity
        if identity is None:
            return
        extension = current.runtime_authority or {}
        self.records.append_attempt_join(AttemptJoin(
            join_id=str(uuid.uuid4()), operation_id=extension["operation_id"],
            attempt_id=attempt.attempt_id, check_id=check_id, effect_id=attempt.effect_id,
            decision_id=attempt.decision_id, grant_id=current.grant_id,
            grant_revision=current.grant_revision, resolver_id=identity.resolver_id,
            resolver_version=identity.resolver_version,
            class_max_age=self.runtime_authority_profile.actions[current.action_id].max_status_age_seconds,
            expected_effective_grant_digest=extension.get("expected_effective_grant_digest"),
            **({"merged_into": _merge.merged_into(self.records.document_snapshot(), extension["operation_id"])}
               if self._merge_profile is not None else {}),
            recorded_at=self._write_time(now), time_source=self.time_source, **self._eval_stamp(now)))

    def decide(self, proposal: RuntimeProposal, *, now: datetime | None = None) -> RuntimeDecision:
        self._require_reaper_alive()
        now = self._evaluation_time(now)
        frozen = proposal.model_copy(deep=True)
        inputs: list[ResolutionInput] = []
        check_ref: list[str] = []
        reasons, binding = self._resolve(frozen, now, inputs=inputs, **({"stage":"decision"} if self.runtime_authority_profile else {}),
                                         **({"check_ref": check_ref} if (self._identity or self._freshness) else {}))
        if self._identity and binding is not None and not reasons:
            self._admit_operation(binding, now, reasons)
        reasons = self._record_check(inputs, now, reasons, "decision", check_id=check_ref[0] if check_ref else None)
        effect_id = self._effect_id(binding) if binding else commitment({
            "proposal": commitment(frozen.model_dump(mode="json", exclude_none=False)),
            "grant_id": None,
            "grant_revision": None,
        })
        decision = RuntimeDecision(
            decision_id=str(uuid.uuid4()),
            effect_id=effect_id,
            result="authorized" if not reasons else "hold",
            reasons=reasons,
            decided_at=_iso(now),
            **({"evaluated_at": _iso(now), "recorded_at": self._svc()} if self._freshness else {}),
            time_source=self.time_source, operation_horizon=self._horizon(frozen),
            reason_vocabulary_version=(vocabulary_for(reasons) if self.runtime_authority_profile else None),
            rule_identity=self._rule_identity(inputs),
            reopen_conditions=(reopen_conditions(reasons, inputs) if self.runtime_authority_profile else []),
            binding=binding if not reasons else None,
            resolution_inputs=inputs,
        )
        self.records.append_decision(decision)
        return decision

    def execute(
        self,
        proposal: RuntimeProposal,
        decision: RuntimeDecision,
        *,
        adapter_id: str,
        now: datetime | None = None,
        lose_ack: bool = False,
        partial: bool = False,
    ) -> tuple[EffectAttempt, EffectObservation | None]:
        self._require_reaper_alive()
        now = self._evaluation_time(now)
        persisted = self.records.decision(decision.decision_id)
        if persisted is None or persisted != decision:
            raise PermissionError("decision is not the immutable persisted decision")
        if persisted.result != "authorized" or persisted.binding is None:
            raise PermissionError("decision is not authorized")
        if persisted.effect_id != self._effect_id(persisted.binding):
            raise PermissionError("decision effect identity is invalid")

        frozen = proposal.model_copy(deep=True)
        inputs: list[ResolutionInput] = []
        check_ref: list[str] = []
        reasons, current = self._resolve(frozen, now, inputs=inputs, **({"stage":"effect", "decision":persisted} if self.runtime_authority_profile else {}),
                                         **({"check_ref": check_ref} if (self._identity or self._freshness) else {}))
        if self._identity and current is not None and not reasons:
            self._operation_gate(current, reasons)
        reasons = self._record_check(inputs, now, reasons, "effect", check_id=check_ref[0] if check_ref else None)
        if reasons or current is None or current != persisted.binding:
            refusal_reasons = sorted(set(reasons))
            if not refusal_reasons and current != persisted.binding:
                refusal_reasons = ["authorization_binding_changed"]
            self.records.append_refusal(EffectTimeRefusal(
                **({"check_id": check_ref[0]} if check_ref else {}),
                refusal_id=str(uuid.uuid4()),
                decision_id=persisted.decision_id,
                effect_id=persisted.effect_id,
                recorded_at=self._write_time(now),
                **self._eval_stamp(now),
                time_source=self.time_source,
                original_operation_horizon=persisted.operation_horizon,
                operation_horizon=self._horizon(frozen),
                reason_vocabulary_version=(vocabulary_for(refusal_reasons) if self.runtime_authority_profile else None),
                rule_identity=self._rule_identity(inputs),
                reopen_conditions=(reopen_conditions(refusal_reasons, inputs) if self.runtime_authority_profile else []),
                reasons=refusal_reasons,
                changed_inputs=self._effect_time_changed_inputs(inputs, persisted.binding),
                resolution_inputs=inputs,
            ))
            raise PermissionError("authorization-critical inputs changed before effect")
        if current.runtime_authority and current.runtime_authority.get("expected_effective_grant_digest"):
            if getattr(self.destination, "runtime_authority_capability", None) != "sqlite-effective-grant/0.1":
                raise PermissionError("atomic_authority_capability_unavailable")
        if self._identity is not None and getattr(self.destination, "operation_identity_capability", None) != OPERATION_IDENTITY_CAPABILITY:
            raise PermissionError("operation_identity_capability_unavailable")
        if adapter_id != current.adapter_id:
            raise PermissionError("adapter substitution detected")

        effect_id = persisted.effect_id
        prior_attempts = [
            item for item in self.records.load().attempts
            if item.effect_id == effect_id
        ]
        if self._freshness is not None:
            # An attempt refused at the dispatch gate never reached the destination: it must not poison a later retry.
            latest = {item.attempt_id: item for item in prior_attempts}
            prior_attempts = [item for item in latest.values()
                              if not (item.status == "failed" and item.error == _fresh_profile.CODE_EXPIRED_BEFORE_DISPATCH)]
        rec = self._observe_and_reconcile(effect_id, now=now)
        existing = rec.observation
        if rec.result == "applied":
            attempt = EffectAttempt(
                attempt_id=str(uuid.uuid4()),
                effect_id=effect_id,
                decision_id=persisted.decision_id,
                started_at=_iso(now),
                time_source=self.time_source,
                status="acknowledged",
                acknowledgement={"reconciled_existing": True},
            )
            if check_ref:
                self._join_attempt(attempt, persisted, current, check_ref[0], now)
            self._stamp_attempt(attempt, now)
            self.records.append_attempt(attempt)
            return attempt, existing
        if existing is not None and existing.state == "partial" and rec.observation_accepted:
            attempt = EffectAttempt(
                attempt_id=str(uuid.uuid4()),
                effect_id=effect_id,
                decision_id=persisted.decision_id,
                started_at=_iso(now),
                time_source=self.time_source,
                status="partial",
                acknowledgement={"reconciled_existing": True},
            )
            if check_ref:
                self._join_attempt(attempt, persisted, current, check_ref[0], now)
            self._stamp_attempt(attempt, now)
            self.records.append_attempt(attempt)
            return attempt, existing
        if rec.result != "observed_absent":
            raise PermissionError("destination observation is not valid for effect dispatch")
        if prior_attempts:
            raise PermissionError(
                "observed absence does not establish retry eligibility after a prior attempt"
            )

        attempt = EffectAttempt(
            attempt_id=str(uuid.uuid4()),
            effect_id=effect_id,
            decision_id=persisted.decision_id,
            started_at=_iso(now),
            time_source=self.time_source,
            status="attempted",
        )
        if check_ref:
            self._join_attempt(attempt, persisted, current, check_ref[0], now)
        self._stamp_attempt(attempt, now)
        self.records.append_attempt(attempt)

        if self._freshness is not None and check_ref:
            # freshness/0.1: re-read the service clock immediately before dispatch. A passed deadline refuses and closes the
            # check. This narrows the window between check and commit; it does not close it.
            deadline = self._expired_before_dispatch(check_ref[0])
            self._mono_open.pop(check_ref[0], None)  # the gate has run for this check
            if deadline is not None:
                self._refuse_expired_before_dispatch(check_id=check_ref[0], deadline=deadline, attempt=attempt,
                                                     persisted=persisted, frozen=frozen, inputs=inputs, now=now)

        # No authority-context or grant reread occurs after validation. The destination
        # receives only the frozen proposal plus values in the validated binding.
        try:
            ack = self.destination.apply(
                effect_id=effect_id,
                grant_id=current.grant_id,
                max_effects=current.effective_max_effects,
                target=frozen.target,
                amount=frozen.amount,
                unit=frozen.unit,
                payload=copy.deepcopy(frozen.payload),
                lose_ack=lose_ack,
                partial=partial,
                **({"expected_effective_grant_digest": current.runtime_authority["expected_effective_grant_digest"],
                    "effective_grant_derivation_version": current.runtime_authority["effective_grant_derivation_version"]}
                   if current.runtime_authority and current.runtime_authority.get("expected_effective_grant_digest") else {}),
                **({"operation_id": (_merge.dispatch_operation_id(self.records.document_snapshot(),
                                                                  current.runtime_authority["operation_id"])
                                     if self._merge_profile is not None else current.runtime_authority["operation_id"])}
                   if self._identity else {}),
            )
            attempt.status = "partial" if partial else "acknowledged"
            attempt.acknowledgement = ack
        except DefinitiveDestinationRejection as exc:
            attempt.status = "failed"
            attempt.error = exc.reason_code
        except DestinationInProgress as exc:
            # dedupe-ttl/0.1: the destination holds our key and is still processing it. Unknown, never a reason for a new key.
            # Without the profile this is an ordinary unknown outcome, exactly as before.
            attempt.status = "unknown"
            if self._dedupe is not None:
                attempt.error, attempt.acknowledgement = ERROR_IN_PROGRESS, {"in_progress": True}
            else:
                attempt.error = "destination_outcome_unknown:" + type(exc).__name__
        except Exception as exc:
            # Exception classes do not prove that the provider did not accept.
            attempt.status = "unknown"
            attempt.error = "destination_outcome_unknown:" + type(exc).__name__

        self._stamp_attempt(attempt, now)
        self.records.append_attempt(attempt)
        post = self._observe_and_reconcile(effect_id, now=now)
        return attempt, post.observation if post.observation_accepted else None

    def reconcile(
        self,
        effect_id: str,
        *,
        now: datetime | None = None,
    ) -> ReconciliationResult:
        """Classify one observation without renewing authority or dispatching an effect."""
        return self._observe_and_reconcile(effect_id, now=now)

    def _observe_and_reconcile(
        self,
        effect_id: str,
        *,
        now: datetime | None,
    ) -> ReconciliationResult:
        """Observe once and retain either validated state or rejection diagnostics."""
        try:
            observation = self.destination.observe(effect_id)
        except Exception as exc:
            reasons: list[str] = []
            evaluation_time = self._trusted_evaluation_time(now, reasons)
            policy = self.observation_policy
            if policy is None:
                reasons.append("observation_policy_missing")
            value = ReconciliationResult(
                effect_id=effect_id,
                reconciled_at=_iso(_now()),
                result="hold",
                observation=None,
                observation_accepted=False,
                retry_eligible=False,
                reasons=sorted(set(reasons + [f"observation_unavailable:{type(exc).__name__}"])),
                evaluation_time=_iso(evaluation_time) if evaluation_time else None,
                observation_max_age_seconds=policy.max_age_seconds if policy else None,
                observation_clock_tolerance_seconds=policy.clock_tolerance_seconds if policy else None,
            )
            self.records.append_reconciliation(value)
            return value
        return self._reconcile_observation(effect_id, observation, now=now)

    def _trusted_evaluation_time(
        self,
        now: datetime | None,
        reasons: list[str],
    ) -> datetime | None:
        if not self.allow_test_time:
            return self._evaluation_time(None)
        if now is None:
            reasons.append("evaluation_time_missing")
            return None
        if now.tzinfo is None or now.utcoffset() is None:
            reasons.append("evaluation_time_timezone_missing")
            return None
        return now.astimezone(timezone.utc)

    def _reconcile_observation(
        self,
        effect_id: str,
        observation: EffectObservation,
        *,
        now: datetime | None,
    ) -> ReconciliationResult:
        reasons: list[str] = []
        evaluation_time = self._trusted_evaluation_time(now, reasons)
        policy = self.observation_policy
        if policy is None:
            reasons.append("observation_policy_missing")

        if observation.effect_id != effect_id:
            reasons.append("observation_effect_id_mismatch")

        raw_time = observation.observed_at
        observed_at: datetime | None = None
        if not isinstance(raw_time, str) or not raw_time.strip():
            reasons.append("observation_time_missing")
        else:
            try:
                observed_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except (TypeError, ValueError):
                reasons.append("observation_time_malformed")
            else:
                if observed_at.tzinfo is None or observed_at.utcoffset() is None:
                    reasons.append("observation_time_timezone_missing")
                    observed_at = None
                else:
                    observed_at = observed_at.astimezone(timezone.utc)

        if observed_at is not None and evaluation_time is not None and policy is not None:
            # freshness/0.1 decouples the observation clock from the evaluation pass: "future" is judged against the service
            # clock re-read now (an observation stamped by the checked party after the pass began is not future), while
            # staleness stays relative to the evaluation. Elapsed time since the check opened is the dispatch deadline's job.
            reference = max(evaluation_time, _now()) if self._freshness is not None else evaluation_time
            future_limit = reference + timedelta(seconds=policy.clock_tolerance_seconds)
            if observed_at > future_limit:
                reasons.append("observation_time_future")
            elif (evaluation_time - observed_at).total_seconds() > policy.max_age_seconds:
                reasons.append("observation_stale")

        if observation.state in {"applied", "partial"}:
            destination_effect_id = observation.destination_state.get("effect_id")
            destination_state = observation.destination_state.get("state")
            if destination_effect_id != effect_id:
                reasons.append("destination_effect_id_mismatch")
            if destination_state != observation.state:
                reasons.append("destination_state_contradiction")
        elif observation.state == "absent":
            if observation.destination_state:
                reasons.append("absence_has_destination_state")
        else:
            reasons.append("observation_state_unknown")

        accepted = not reasons
        if accepted:
            self.records.append_observation(observation)

        if not accepted:
            result = "hold"
        elif observation.state == "applied":
            result = "applied"
        elif observation.state == "absent":
            result = "observed_absent"
        else:
            result = "hold"

        value = ReconciliationResult(
            effect_id=effect_id,
            reconciled_at=_iso(_now()),
            result=result,
            observation=observation,
            observation_accepted=accepted,
            retry_eligible=False,
            reasons=sorted(set(reasons)),
            evaluation_time=_iso(evaluation_time) if evaluation_time else None,
            observation_max_age_seconds=policy.max_age_seconds if policy else None,
            observation_clock_tolerance_seconds=policy.clock_tolerance_seconds if policy else None,
        )
        self.records.append_reconciliation(value)
        self.records.close_uncertain_attempts(value)
        return value

    def _effect_time_changed_inputs(
        self, inputs: list[ResolutionInput], binding: AuthorizationBinding,
    ) -> list[RefusalInputVersion]:
        """Project changed inputs from actual reads, without resolving them again."""
        changed = []
        for item in inputs:
            if item.input_type not in {"grant", "policy", "approval", "evidence", "role_mapping"}:
                continue
            if item.read_state == "nonce_mismatch":
                # freshness/0.1: the response echoed a nonce other than this check's: record both, whatever else it says
                changed.append(RefusalInputVersion(
                    input_type=item.input_type, input_id=item.input_id,
                    expected_version="nonce=" + item.expected.get("nonce", "none"),
                    observed_version="nonce=" + item.observed.get("nonce", "none")))
                continue
            expected = dict(item.expected)
            if item.input_type == "grant":
                expected = {"revision": binding.grant_revision, "status": "active"}
            elif item.input_type == "policy":
                versions = {p["ref"]: p["version"] for p in binding.policy_versions}
                expected = {"version": versions.get(item.input_id, "not_in_original_binding"), "status": "active"}
            elif item.input_type == "role_mapping":
                expected = {"version": binding.role_mapping_version, "digest": binding.role_mapping_digest}
            elif item.input_type == "approval":
                expected.update(grant_revision=binding.grant_revision, grant_id=binding.grant_id,
                                proposal=binding.proposal_commitment,
                                policies=commitment(binding.policy_versions))
            if not expected:
                continue
            if not item.missing and all(item.observed.get(k) == v for k, v in expected.items()):
                continue
            changed.append(RefusalInputVersion(
                input_type=item.input_type,
                input_id=item.input_id,
                expected_version=";".join(f"{k}={v}" for k, v in expected.items()),
                observed_version=("missing" if item.missing else
                                  ";".join(f"{k}={v}" for k, v in item.observed.items())),
            ))
        return changed

    def _effect_id(self, binding: AuthorizationBinding) -> str:
        return commitment({
            "proposal": binding.proposal_commitment,
            "grant_id": binding.grant_id,
            "grant_revision": binding.grant_revision,
        })

    def _fresh(self, observed_at: str, now: datetime, max_age_seconds: int) -> bool:
        observed = _parse(observed_at)
        if observed > now + timedelta(seconds=self.clock_tolerance_seconds):
            return False
        return (now - observed).total_seconds() <= max_age_seconds

    def _same_institution(self, record: BaseModel, context: dict) -> bool:
        institution = context["institution"]
        return (
            getattr(record, "institution_id", None) == institution["institution_id"]
            and getattr(record, "authority_domain", None) == institution["authority_domain"]
        )

    def _resolve_role(
        self,
        *,
        declared_role: str | None,
        required_roles: set[str],
        institution_id: str,
        mapping: RoleMappingStatus | None,
    ) -> str | None:
        if declared_role is None:
            return None
        if declared_role.startswith("urn:"):
            return declared_role if declared_role in required_roles else None
        if mapping is None or mapping.institution_id != institution_id:
            return None
        candidates = mapping.aliases.get(declared_role, [])
        if len(candidates) != 1:
            return None
        canonical = candidates[0]
        if not canonical.startswith("urn:"):
            return None
        return canonical if canonical in required_roles else None

    def _resolve(self, proposal, now, *, inputs=None, stage="decision", decision=None, check_ref=None):
        if self.runtime_authority_profile is None:
            return self._resolve_inputs(proposal, now, inputs=inputs)
        check_id = str(uuid.uuid4())
        if check_ref is not None:
            check_ref.append(check_id)  # lets the caller record the ResolutionCheck under the journal id
        fr = self._freshness
        try:
            with self.records.check_lease(check_id, **({"acquire_timeout": fr.lease_acquire_timeout_seconds} if fr else {})):
                return self._resolve_journal(proposal, now, inputs=inputs, stage=stage,
                                             decision=decision, check_id=check_id)
        except CheckLeaseUnavailable:
            return ["check_lease_unavailable"], None

    def _resolve_journal(self, proposal, now, *, inputs, stage, decision, check_id):
        """Opt-in write-ahead recording, with no shared per-call mutable state."""
        profile = self.runtime_authority_profile
        if profile is None:
            return self._resolve_inputs(proposal, now, inputs=inputs)
        action_class = profile.actions.get(proposal.action_id)
        fr = profile.freshness
        clocks = {}
        nonce = None
        if fr is not None:
            # Three named clocks: recorded_at is the service clock at THIS write; evaluated_at is the shared evaluation pass.
            # The deadline is fixed at opening: opened_at + the class age bound (plus a recorded, authorised extension).
            opened = _now()
            bound, extension_id, _ = self._class_age_bound(proposal.action_id, now)
            clocks = {"evaluated_at": _iso(now), "recorded_at": _iso(opened)}
            if bound is not None:
                if len(self._mono_open) >= 4096:  # decision-stage checks never reach the gate: keep the map bounded
                    self._mono_open.pop(next(iter(self._mono_open)))
                self._mono_open[check_id] = (_monotonic(), bound)
                clocks.update(deadline=_iso(opened + timedelta(seconds=bound)), age_bound_seconds=bound,
                              **({"extension_id": extension_id} if extension_id else {}))
            nonce = uuid.uuid4().hex if fr.nonce else None
            if nonce:
                clocks["nonce"] = nonce
        event = CheckEvent(
            check_id=check_id, phase="opened", stage=stage, recorded_at=clocks.pop("recorded_at", _iso(now)),
            owner=_process_owner(), proposal_commitment=commitment(proposal.model_dump(mode="json")),
            decision_id=decision.decision_id if decision else None,
            effect_id=decision.effect_id if decision else None,
            action_class=action_class.model_dump() if action_class else {},
            **clocks,
        )
        self.records.append_check_event(event)
        def retain(item):
            self.records.append_check_event(event.model_copy(update={
                "phase": "input", "input": item, **({"recorded_at": self._svc()} if fr else {})}))
        reads = _JournalInputs([], retain, nonce=nonce, freshness=fr is not None)
        reads.check_id = check_id  # lets a cached-snapshot use (reversibility/0.1) join to its check by id
        try:
            if action_class is None:
                reasons, binding = ["action_class_unknown"], None
            elif action_class.irreversible and action_class.on_unreadable != "refuse":
                reasons, binding = ["action_class_invalid"], None
            elif not getattr(self.resolver, "authenticated", False) and not profile.allow_synthetic_resolver:
                reasons, binding = ["resolver_not_authenticated"], None
            else:
                reasons, binding = self._resolve_inputs(proposal, now, inputs=reads)
                if reads.mismatches:  # a replayed or foreign response: its age cannot be bound to this check
                    reasons, binding = sorted(set(reasons + ["status_nonce_mismatch"])), None
        except _ResolverReadFailure:
            reasons, binding = ["status_unreadable"], None
        except (ValueError, KeyError, TypeError, AttributeError):
            # Malformed trusted-source data is not authority; raw error text is never exported.
            reasons, binding = ["resolution_record_invalid"], None
        finally:
            if inputs is not None:
                inputs.extend(reads)
        self.records.append_check_event(event.model_copy(update={
            "phase": "completed", "reasons": reasons, "reason_vocabulary_version": vocabulary_for(reasons),
            **({"recorded_at": self._svc()} if fr else {})}))
        return reasons, binding

    def _cached_purpose(self, purpose: dict, ref: str, cl, proposal, now: datetime, inputs):
        """reversibility/0.1: may a cached "open" purpose snapshot stand in for an unreadable purpose status?

        Returns ``(accepted PurposeStatus or None, specific reason codes, observed extras)`` and appends a ``snapshot_use`` row
        either way. Accepted only for a reversible class, within its age bound (a signed N3 extension may raise the bound for a
        reversible class only), with no recorded closure of this purpose.
        """
        from .runtime_authority import PurposeStatus
        if cl is None:
            return None, [], None
        cached = None
        provider = getattr(self.resolver, "cached_purpose_status", None)
        if provider is not None:
            try:
                cached = PurposeStatus.model_validate(provider(copy.deepcopy(purpose)))
            except Exception:
                cached = None
        bound, extension_id, _ = self._class_age_bound(proposal.action_id, now)
        use, accepted = judge_cached_purpose(
            action_class=cl, now=now, purpose_ref=ref, cached=cached, bound_seconds=bound,
            extension_id=extension_id, check_id=getattr(inputs, "check_id", None),
            closures=recorded_closures(self.records.document_snapshot(), ref), recorded_at=self._write_time(now))
        self.records.append_snapshot_use(use)
        if accepted is None:
            return None, [x for x in use.reasons if x != "purpose_unreadable"], None
        inputs.read_states[("purpose", ref)] = "cached_positive"
        inputs.age_bases[("purpose", ref)] = "source_asserted"  # a cached read is never nonce bound
        return accepted, [], {"age_seconds": str(use.age_seconds), "age_bound_seconds": str(bound), "reversibility": use.reversibility}

    def _read_grant(self, inputs, grant_id, action_id, now=None):
        """Only governed reversible classes may use a trusted cached positive."""
        if self.runtime_authority_profile is None:
            return self.resolver.grant_status(grant_id)
        failed = False
        try:
            status = self._read_via_resolver(inputs, "grant", grant_id, self.resolver.grant_status, grant_id)
        except Exception:
            status, failed = None, True
        if status is None:
            inputs.append(ResolutionInput(input_type="grant", input_id=grant_id,
                                          missing=True, read_state="unreadable"))
            cl = self.runtime_authority_profile.actions[action_id]
            cached = getattr(self.resolver, "cached_grant_status", None)
            if not effectively_irreversible(cl, now) and cl.on_unreadable == "bounded_tolerance" and cached:
                try:
                    candidate = cached(grant_id)
                except Exception:
                    candidate = None
                known_denial = (candidate is not None and any(
                    item.input_type == "grant" and item.input_id == grant_id
                    and item.observed.get("revision") == candidate.revision
                    and item.observed.get("status") in {"revoked", "suspended"}
                    for check in self.records.load().resolution_checks for item in check.inputs
                ))
                if candidate is not None and candidate.status == "active" and not known_denial:
                    status = candidate
                    inputs.read_states[("grant", grant_id)] = "cached_positive"
                    inputs.age_bases[("grant", grant_id)] = "source_asserted"  # a cached positive is never nonce bound
            if status is None and failed:
                raise _ResolverReadFailure()
        inputs.records[("grant", grant_id)] = copy.deepcopy(status)
        return status

    _READ_METHODS = {"authority_context": "authority_context", "role_mapping": "role_mapping", "identity": "identity_status",
                     "mandate": "issuer_mandate", "grant": "grant_status", "conflict": "conflict_status",
                     "policy": "policy_status", "approval": "approval_status", "evidence": "evidence_status"}

    def _read_via_resolver(self, inputs, kind, ref, method, *args):
        """One resolver read. Under freshness/0.1, where the resolver supports it, the reader sends this check's nonce and
        compares the echo: an echoed nonce makes the age ``nonce_bound``, a different one is recorded as a mismatch (the read
        is not accepted). No echo support, or no freshness profile: the plain read, age ``source_asserted``."""
        nonce = getattr(inputs, "nonce", None)
        if (not nonce or getattr(self.resolver, "nonce_capability", None) != _fresh_profile.NONCE_CAPABILITY
                or kind not in self._READ_METHODS):
            return method(*args)
        value, echoed = self.resolver.nonce_read(nonce, self._READ_METHODS[kind], *args)
        if value is not None:
            if echoed == nonce:
                inputs.age_bases[(kind, ref)] = "nonce_bound"
            else:
                inputs.mismatches[(kind, ref)] = (nonce, echoed)
                inputs.read_states[(kind, ref)] = "nonce_mismatch"
        return value

    def _read_input(self, inputs, kind, ref, method, *args):
        """Wrap resolver exceptions and preserve an actual missing-read diagnostic."""
        if self.runtime_authority_profile is None:
            return method(*args)
        try:
            value = self._read_via_resolver(inputs, kind, ref, method, *args)
        except Exception:
            inputs.append(ResolutionInput(input_type=kind, input_id=ref, missing=True,
                                          read_state="unreadable"))
            raise _ResolverReadFailure() from None
        inputs.records[(kind, ref)] = copy.deepcopy(value)
        return value

    def _resolve_inputs(
        self, proposal: RuntimeProposal, now: datetime,
        *, inputs: list[ResolutionInput] | None = None,
    ) -> tuple[list[str], AuthorizationBinding | None]:
        def capture(kind: str, ref: str, record: BaseModel | dict | None,
                    expected: dict[str, str] | None = None, extra: dict[str, str] | None = None) -> None:
            if inputs is None:
                return
            data = record.model_dump(mode="json") if isinstance(record, BaseModel) else record
            # Explicit scalar allowlist: no payload, identity chain, approver,
            # mandate body, policy body, or evidence contents in diagnostics.
            fields = ("revision", "status", "version", "state", "observed_at",
                      "schema_version", "interface_status", "digest", "grant_revision",
                      "runtime_authority_commitment", "epoch", "epoch_capability")
            observed = {key: str(data[key]) for key in fields if data is not None and key in data}
            observed.update(extra or {})  # reversibility/0.1: age and bound of a cached purpose snapshot
            if kind == "approval" and data is not None:
                observed["proposal"] = data["proposal_commitment"]
                observed["policies"] = commitment(data["policy_versions"])
                observed["grant_id"] = data["grant_id"]
            inputs.append(ResolutionInput(
                input_type=kind, input_id=ref, expected=expected or {}, observed=observed,
                record_commitment=commitment(data) if data is not None else None,
                missing=data is None,
            ))

        capture("manifest", proposal.manifest_id, self.manifest)
        reasons = self._manifest_mismatches(proposal, now)
        context = self._read_input(inputs, "authority_context", proposal.authority_context_ref or "", self.resolver.authority_context, proposal.authority_context_ref or "")
        capture("authority_context", proposal.authority_context_ref or "", context)
        if context is None:
            return sorted(set(reasons + ["authority_context_missing"])), None

        institution = context.get("institution", {})
        institution_id = institution.get("institution_id")
        authority_domain = institution.get("authority_domain")
        tenant_id = getattr(proposal, "tenant_id", None)
        tenant_aware = isinstance(proposal, TenantRuntimeProposal)
        if tenant_aware and context.get("tenant_id") != tenant_id:
            reasons.append("tenant_context_mismatch")
        # A historical 0.1 proposal carries no tenant, so it cannot establish
        # tenant equality; tenant-bearing authority state must fail closed.
        if not tenant_aware and context.get("tenant_id") is not None:
            reasons.append("tenant_proposal_required")

        if context.get("schema_version") != AUTHORITY_CONTEXT_VERSION:
            reasons.append("authority_context_version_mismatch")
        if context.get("interface_status") != AUTHORITY_CONTEXT_STATUS:
            reasons.append("authority_context_status_mismatch")
        if context.get("requirement", {}).get("requirement_id") != proposal.requirement_id:
            reasons.append("authority_requirement_mismatch")
        if context.get("principal") != proposal.principal or context.get("acting_identity") != proposal.actor:
            reasons.append("proposal_identity_binding_mismatch")

        action = next(
            (x for x in self.manifest.get("actions", []) if x.get("action_id") == proposal.action_id),
            None,
        )
        declared_auth = (action or {}).get("authority_context") or {}
        if institution_id != declared_auth.get("institution_id"):
            reasons.append("institution_mismatch")
        if authority_domain != declared_auth.get("authority_domain"):
            reasons.append("authority_domain_mismatch")
        if context.get("requirement", {}).get("consequence", {}).get("tier") != declared_auth.get("consequence_tier"):
            reasons.append("consequence_tier_mismatch")

        mapping = self._read_input(inputs, "role_mapping", institution_id or "", self.resolver.role_mapping, institution_id or "")
        capture("role_mapping", institution_id or "", mapping)
        if mapping is None:
            reasons.append("role_mapping_missing")
            mapping_version = ""
            mapping_digest = ""
        else:
            expected_mapping_digest = commitment({
                "institution_id": mapping.institution_id,
                "version": mapping.version,
                "aliases": mapping.aliases,
            })
            if mapping.institution_id != institution_id or mapping.digest != expected_mapping_digest:
                reasons.append("role_mapping_invalid")
            mapping_version = mapping.version
            mapping_digest = mapping.digest

        review = (action or {}).get("review_requirement") or {}
        if review.get("mode") in {"human_review", "approval_required"}:
            required_roles = {
                x.get("role_id")
                for x in context.get("requirement", {}).get("approvals", [])
                if x.get("role_id")
            }
            canonical_role = self._resolve_role(
                declared_role=review.get("reviewer_role"),
                required_roles=required_roles,
                institution_id=institution_id or "",
                mapping=mapping,
            )
            if canonical_role is None:
                reasons.append("review_requirement_not_resolved")

        grant = context.get("grant")
        if not grant:
            return sorted(set(reasons + ["issued_grant_missing"])), None

        identity = self._read_input(inputs, "identity", context["acting_identity"], self.resolver.identity_status, context["acting_identity"], context["principal"])
        capture("identity", context["acting_identity"], identity)
        if (
            identity.identity != context["acting_identity"]
            or identity.principal != context["principal"]
            or not self._same_institution(identity, context)
        ):
            reasons.append("identity_binding_mismatch")
        if not identity.authenticated or not identity.delegation_valid:
            reasons.append("identity_or_delegation_invalid")
        if not self._fresh(identity.observed_at, now, self.identity_max_age_seconds):
            reasons.append("identity_status_stale_or_future")

        mandate = self._read_input(inputs, "mandate", grant["issuance_record_ref"], self.resolver.issuer_mandate, grant["issuer"], grant["issuer_role"])
        capture("mandate", grant["issuance_record_ref"], mandate)
        if (
            mandate.issuer != grant["issuer"]
            or mandate.issuer_role != grant["issuer_role"]
            or mandate.issuance_record_ref != grant["issuance_record_ref"]
            or not self._same_institution(mandate, context)
        ):
            reasons.append("issuer_mandate_binding_mismatch")
        if not mandate.mandate_valid:
            reasons.append("issuer_mandate_invalid")
        if not self._fresh(mandate.observed_at, now, self.mandate_max_age_seconds):
            reasons.append("issuer_mandate_stale_or_future")

        status = self._read_grant(inputs, grant["grant_id"], proposal.action_id, now)
        capture("grant", grant["grant_id"], status, {"revision": grant["revision"], "status": "active"})
        if status is None:
            reasons.append("status_unreadable" if self.runtime_authority_profile else "grant_not_active")
        else:
            if (
                status.grant_id != grant["grant_id"]
                or status.status_ref != grant["status_ref"]
                or status.authority_basis_ref != institution.get("authority_basis_ref")
                or not self._same_institution(status, context)
            ):
                reasons.append("grant_status_binding_mismatch")
            if tenant_aware and status.tenant_id != tenant_id:
                reasons.append("grant_tenant_mismatch")
            if not tenant_aware and status.tenant_id is not None:
                reasons.append("tenant_proposal_required")
            if status.status != "active":
                reasons.append(("grant_revoked" if status.status == "revoked" else "grant_" + status.status)
                               if self.runtime_authority_profile else "grant_not_active")
            if status.revision != grant["revision"]:
                reasons.append("grant_revision_stale")
            if self._freshness is not None:
                bound, _, defects = self._class_age_bound(proposal.action_id, now)
                if not self._fresh(status.observed_at, now, bound):
                    reasons.append("grant_status_stale_or_future")
                    reasons.extend(defects)  # an active extension that does not count (e.g. its signer lost authority)
            elif not self._fresh(status.observed_at, now, (self.runtime_authority_profile.actions[proposal.action_id].max_status_age_seconds
                    if self.runtime_authority_profile else self.status_max_age_seconds)):
                reasons.append("grant_status_stale_or_future")

        requirement = context["requirement"]
        if grant["requirement_id"] != requirement["requirement_id"]:
            reasons.append("grant_requirement_mismatch")
        if grant["grantee"] != context["principal"] or grant["acting_identity"] != context["acting_identity"]:
            reasons.append("grant_identity_mismatch")
        if tenant_aware and grant.get("tenant_id") != tenant_id:
            reasons.append("grant_tenant_mismatch")
        if not tenant_aware and grant.get("tenant_id") is not None:
            reasons.append("tenant_proposal_required")
        if not grant.get("expires_at") or _parse(grant["not_before"]) > now or _parse(grant["expires_at"]) <= now:
            reasons.append("grant_outside_validity")

        requirement_permission = self._matching_permission(requirement, proposal)
        grant_permission = self._matching_permission(grant, proposal)
        if requirement_permission is None:
            reasons.append("requirement_scope_mismatch")
        if grant_permission is None:
            reasons.append("grant_scope_mismatch")

        delegation = grant.get("delegation", {})
        if delegation.get("parent_grant_id") is not None:
            # No ancestor revocation walk or shared ancestor budget exists in this profile.
            reasons.append("delegation_profile_unsupported")
            if not identity.chain:
                reasons.append("delegation_chain_missing")

        conflict = self._read_input(inputs, "conflict", requirement["requirement_id"], self.resolver.conflict_status, requirement["requirement_id"])
        capture("conflict", requirement["requirement_id"], conflict)
        if conflict is None:
            reasons.append("authority_conflict_unresolved")
        else:
            if (
                conflict.requirement_id != requirement["requirement_id"]
                or sorted(conflict.conflict_refs) != sorted(context.get("conflicts", {}).get("precedence_refs", []))
                or not self._same_institution(conflict, context)
            ):
                reasons.append("conflict_status_binding_mismatch")
            if conflict.state != "clear":
                reasons.append("authority_conflict_unresolved")
            if not self._fresh(conflict.observed_at, now, self.status_max_age_seconds):
                reasons.append("conflict_status_stale_or_future")

        policy_versions = grant.get("policy_versions", [])
        for item in policy_versions:
            current = self._read_input(inputs, "policy", item["ref"], self.resolver.policy_status, item["ref"])
            capture("policy", item["ref"], current, {"version": item["version"], "status": "active"})
            if current is None:
                reasons.extend(["policy_stale_or_changed", "policy_missing"])
                continue
            if current.ref != item["ref"] or not self._same_institution(current, context):
                reasons.append("policy_binding_mismatch")
            if tenant_aware and current.tenant_id != tenant_id:
                reasons.append("policy_tenant_mismatch")
            if not tenant_aware and current.tenant_id is not None:
                reasons.append("tenant_proposal_required")
            if current.status != "active" or current.version != item["version"]:
                reasons.append("policy_stale_or_changed")
            if current.status == "superseded":
                reasons.append("policy_superseded")
            elif current.status != "active":
                reasons.append("policy_status_unknown")
            if current.version != item["version"]:
                reasons.append("policy_version_changed")
            if not self._fresh(current.observed_at, now, self.status_max_age_seconds):
                reasons.append("policy_status_stale_or_future")
            if self.rule_revision_profile is not None:  # opt-in: an unadopted policy digest resolves unknown
                if resolve_rule(self.rule_revision_profile, self.records.load().rule_revisions,
                                item["ref"], current.digest)["state"] != "adopted":
                    reasons.append("policy_status_unknown")

        proposal_commitment = commitment(proposal.model_dump(mode="json", exclude_none=False))
        for req in requirement.get("approvals", []):
            matches: list[ApprovalStatus] = []
            for ref in grant.get("approval_refs", []):
                approval = self._read_input(inputs, "approval", ref, self.resolver.approval_status, ref)
                capture("approval", ref, approval, {
                    "grant_revision": grant["revision"], "status": "active",
                    "proposal": proposal_commitment, "policies": commitment(policy_versions),
                    "grant_id": grant["grant_id"],
                })
                if approval is None:
                    continue
                if approval.approval_ref != ref or not self._same_institution(approval, context):
                    reasons.append("approval_binding_mismatch")
                    continue
                if tenant_aware and approval.tenant_id != tenant_id:
                    reasons.append("approval_tenant_mismatch")
                    continue
                if not tenant_aware and approval.tenant_id is not None:
                    reasons.append("tenant_proposal_required")
                    continue
                if approval.role_id == req["role_id"]:
                    matches.append(approval)
            if not matches:
                reasons.append("required_approval_missing")
                continue
            for approval in matches:
                if approval.status != "active":
                    reasons.append("approval_not_active")
                if not self._fresh(approval.observed_at, now, self.approval_max_age_seconds):
                    reasons.append("approval_status_stale_or_future")
                if approval.grant_id != grant["grant_id"] or approval.grant_revision != grant["revision"]:
                    reasons.append("approval_grant_binding_mismatch")
                if approval.proposal_commitment != proposal_commitment:
                    reasons.append("approval_operation_binding_mismatch")
                if approval.policy_versions != policy_versions:
                    reasons.append("approval_policy_binding_mismatch")
                if req.get("independent_of_actor") and approval.approver in {proposal.actor, proposal.principal, *identity.chain}:
                    reasons.append("approval_independence_violation")

        for obligation in requirement.get("evidence", []):
            current = self._read_input(inputs, "evidence", obligation["obligation_id"], self.resolver.evidence_status, obligation["obligation_id"])
            capture("evidence", obligation["obligation_id"], current,
                    {"state": "current"} if obligation["required"] and obligation["kind"] == "authorization" else {})
            if current is not None and (
                current.obligation_id != obligation["obligation_id"]
                or current.source_ref != obligation["source_ref"]
                or not self._same_institution(current, context)
            ):
                reasons.append("evidence_binding_mismatch")
                current = None

            if obligation["required"] and obligation["kind"] == "authorization":
                if current is None or current.state != "current":
                    reasons.append("required_evidence_not_current")
                elif not self._fresh(current.observed_at, now, int(obligation["max_age_seconds"])):
                    reasons.append("required_evidence_stale_or_future")
            elif obligation.get("unknown_behavior") == "hold_effect":
                if current is None or current.state != "current" or not self._fresh(
                    current.observed_at, now, int(obligation["max_age_seconds"])
                ):
                    reasons.append("context_unknown_requires_hold")

        extension = None
        if self.runtime_authority_profile:
            from .runtime_authority import validate_extensions
            extra_reasons, extension = validate_extensions(
                self.runtime_authority_profile, proposal, context, inputs, self.resolver, now, capture,
                **({"purpose_cache": lambda purpose, ref, cl: self._cached_purpose(purpose, ref, cl, proposal, now, inputs)}
                   if self._reversibility is not None else {}))
            reasons.extend(extra_reasons)
        if reasons:
            return sorted(set(reasons)), None

        effective_max_effects = min(
            int(requirement_permission["max_effects"]),
            int(grant_permission["max_effects"]),
            int((action.get("effect_limits") or {}).get("max_effects", proposal.effects)),
        )

        binding_type = TenantAuthorizationBinding if tenant_aware else AuthorizationBinding
        binding_extra = {"tenant_id": tenant_id} if tenant_aware else {}
        return [], binding_type(
            **binding_extra,
            runtime_authority=extension,
            proposal_commitment=proposal_commitment,
            manifest_id=proposal.manifest_id,
            manifest_version=proposal.manifest_version,
            manifest_digest=proposal.manifest_digest,
            actor=proposal.actor,
            principal=proposal.principal,
            action_id=proposal.action_id,
            adapter_id=proposal.adapter_id,
            target=proposal.target,
            payload_commitment=proposal.payload_commitment,
            requested_permissions=copy.deepcopy(proposal.requested_permissions),
            amount=proposal.amount,
            unit=proposal.unit,
            effects=proposal.effects,
            authority_context_id=context["context_id"],
            authority_context_version=context["schema_version"],
            authority_context_status=context["interface_status"],
            requirement_id=proposal.requirement_id or "",
            requirement_commitment=commitment(requirement),
            grant_id=grant["grant_id"],
            grant_revision=grant["revision"],
            policy_versions=copy.deepcopy(policy_versions),
            role_mapping_version=mapping_version,
            role_mapping_digest=mapping_digest,
            effective_max_effects=effective_max_effects,
        )

    def _manifest_mismatches(self, proposal: RuntimeProposal, now: datetime) -> list[str]:
        mismatches: list[str] = []
        if proposal.manifest_version != MANIFEST_VERSION:
            mismatches.append("unsupported_manifest_version")
        if self.manifest.get("manifest_version") != MANIFEST_VERSION:
            mismatches.append("manifest_version_mismatch")
        if proposal.manifest_id != self.manifest.get("manifest_id"):
            mismatches.append("manifest_id_mismatch")
        if proposal.manifest_digest != commitment(self.manifest):
            mismatches.append("manifest_digest_mismatch")
        if proposal.payload_commitment != commitment(proposal.payload):
            mismatches.append("payload_commitment_mismatch")

        action = next(
            (x for x in self.manifest.get("actions", []) if x.get("action_id") == proposal.action_id),
            None,
        )
        if action is None:
            return sorted(set(mismatches + ["unknown_action"]))

        tool = next(
            (x for x in self.manifest.get("tools", []) if x.get("tool_name") == action.get("tool_name")),
            None,
        )
        if tool is None or tool.get("adapter_id") != proposal.adapter_id:
            mismatches.append("adapter_mismatch")

        target_policy = action.get("target_policy")
        allowed_targets = (_exact_strings(target_policy.get("allowed_targets", []))
                           if isinstance(target_policy, dict) else None)
        if (
            not target_policy
            or allowed_targets is None  # malformed target policy: declares no target
            or target_policy.get("allow_any_target")
            or proposal.target not in allowed_targets
        ):
            mismatches.append("target_out_of_scope")

        payload_policy = action.get("payload_policy")
        payload_fields = ([_exact_strings(payload_policy.get(name, [])) for name in
                           ("required_fields", "optional_fields", "forbidden_fields")]
                          if isinstance(payload_policy, dict) else [None])
        if payload_policy is None or any(item is None for item in payload_fields):
            mismatches.append("missing_payload_policy")  # absent or malformed: no usable payload policy
        else:
            keys = set(proposal.payload)
            required, optional, forbidden = (set(item) for item in payload_fields)
            if required - keys:
                mismatches.append("missing_required_payload_field")
            if keys & forbidden:
                mismatches.append("forbidden_payload_field")
            if keys - required - optional:
                mismatches.append("undeclared_payload_field")

        limits = action.get("effect_limits")
        if limits:
            if proposal.effects > int(limits.get("max_effects", 0)):
                mismatches.append("effect_count_exceeded")
            if limits.get("max_amount") is not None and proposal.amount > float(limits["max_amount"]):
                mismatches.append("amount_exceeded")
            if limits.get("unit") is not None and proposal.unit != limits["unit"]:
                mismatches.append("amount_unit_mismatch")

        needed = {
            x["scope"]
            for x in action.get("authority_required", [])
            if x.get("required", True)
        }
        if not needed.issubset(set(proposal.requested_permissions)):
            mismatches.append("missing_requested_permission")

        auth = action.get("authority_context")
        if auth:
            if proposal.authority_context_ref != auth.get("profile_ref"):
                mismatches.append("authority_profile_mismatch")
            if proposal.requirement_id != auth.get("requirement_id"):
                mismatches.append("authority_requirement_mismatch")

        if proposal.not_before and _parse(proposal.not_before) > now:
            mismatches.append("proposal_not_yet_valid")
        if proposal.expires_at and _parse(proposal.expires_at) <= now:
            mismatches.append("proposal_expired")
        return sorted(set(mismatches))

    def _matching_permission(self, container: dict, proposal: RuntimeProposal) -> dict | None:
        action = next(
            (x for x in self.manifest["actions"] if x["action_id"] == proposal.action_id),
            None,
        )
        if action is None:
            return None
        permissions = container.get("permissions", [])
        if not isinstance(permissions, list):
            return None
        for permission in permissions:
            if not isinstance(permission, dict) or permission.get("action") != action["action_name"]:
                continue
            targets = _exact_strings(permission.get("targets"))
            if targets is None or proposal.target not in targets:
                continue  # a malformed target list grants nothing
            data_scopes = _exact_strings(permission.get("data_scopes"))
            if data_scopes is None or not set(proposal.requested_permissions).issubset(data_scopes):
                continue  # a malformed data-scope list grants nothing
            if proposal.amount > float(permission["max_amount"]):
                continue
            if proposal.unit != permission["unit"]:
                continue
            if proposal.effects > int(permission["max_effects"]):
                continue
            return permission
        return None
