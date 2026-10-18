"""Minimal persistence interfaces and filesystem adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import BaseModel

from agent_control_plane.models import ReplayBundle, RunRecord
from agent_control_plane.strict_json import strict_loads

ModelT = TypeVar("ModelT", bound=BaseModel)


class PersistenceAdapter(Protocol):
    """Persistence interface for run records and replay bundles."""

    def save_run_record(self, record: RunRecord) -> str: ...

    def load_run_record(self, run_id: str) -> RunRecord: ...

    def save_replay_bundle(self, bundle: ReplayBundle) -> str: ...

    def load_replay_bundle(self, bundle_id: str) -> ReplayBundle: ...


class FileSystemPersistenceAdapter:
    """Store run records and replay bundles as validated JSON files."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._runs_dir.mkdir(parents=True, exist_ok=True)
        self._replay_bundles_dir.mkdir(parents=True, exist_ok=True)

    @property
    def _runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def _replay_bundles_dir(self) -> Path:
        return self.root / "replay_bundles"

    def save_run_record(self, record: RunRecord) -> str:
        path = self._record_path(self._runs_dir, record.run_id)
        self._write_model(path, record)
        return str(path)

    def load_run_record(self, run_id: str) -> RunRecord:
        path = self._record_path(self._runs_dir, run_id)
        return self._load_model(path, RunRecord, f"Run record not found: {run_id}")

    def save_replay_bundle(self, bundle: ReplayBundle) -> str:
        path = self._record_path(self._replay_bundles_dir, bundle.replay_bundle_id)
        self._write_model(path, bundle)
        return str(path)

    def load_replay_bundle(self, bundle_id: str) -> ReplayBundle:
        path = self._record_path(self._replay_bundles_dir, bundle_id)
        return self._load_model(
            path,
            ReplayBundle,
            f"Replay bundle not found: {bundle_id}",
        )

    @staticmethod
    def _record_path(directory: Path, record_id: str) -> Path:
        """Return ``directory/<record_id>.json``, refusing paths outside ``directory``.

        Identifiers containing path separators, parent references or absolute
        paths would otherwise read or write JSON outside the store root.
        """
        path = directory / f"{record_id}.json"
        if (
            not record_id
            or "\x00" in record_id
            or path.resolve().parent != directory.resolve()
        ):
            raise ValueError(f"Unsafe record identifier: {record_id!r}")
        return path

    def _write_model(self, path: Path, model: BaseModel) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(model.model_dump(mode="json"), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _load_model(
        self,
        path: Path,
        model_type: type[ModelT],
        missing_message: str,
    ) -> ModelT:
        if not path.exists():
            raise FileNotFoundError(missing_message)
        payload = strict_loads(path.read_bytes())
        return model_type.model_validate(payload)
