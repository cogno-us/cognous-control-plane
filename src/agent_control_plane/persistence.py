"""Minimal persistence interfaces and filesystem adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol, TypeVar

from pydantic import BaseModel

from agent_control_plane.models import ReplayBundle, RunRecord
from agent_control_plane.atomic_write import make_private_dir, write_bytes_atomic
from agent_control_plane.strict_json import dumps_bytes, strict_loads

ModelT = TypeVar("ModelT", bound=BaseModel)


class PersistenceAdapter(Protocol):
    """Persistence interface for run records and replay bundles."""

    def save_run_record(self, record: RunRecord) -> str: ...

    def load_run_record(self, run_id: str) -> RunRecord: ...

    def save_replay_bundle(self, bundle: ReplayBundle) -> str: ...

    def load_replay_bundle(self, bundle_id: str) -> ReplayBundle: ...


class FileSystemPersistenceAdapter:
    """Store run records and replay bundles as validated JSON files.

    Files are written atomically (temporary file, fsync, rename) with mode 0600 in directories created with mode 0700. A record is
    serialised and checked as strict JSON before any file is touched, so a refused write leaves an existing record intact. Saving
    under an identifier that already exists raises ``FileExistsError`` and changes nothing, unless ``overwrite=True`` was given
    to the constructor or to the save call (an explicit replacement; the old file is replaced atomically).
    """

    def __init__(self, root: str | Path, *, overwrite: bool = False) -> None:
        self.root = Path(root)
        self.overwrite = overwrite
        make_private_dir(self.root)
        make_private_dir(self._runs_dir)
        make_private_dir(self._replay_bundles_dir)

    @property
    def _runs_dir(self) -> Path:
        return self.root / "runs"

    @property
    def _replay_bundles_dir(self) -> Path:
        return self.root / "replay_bundles"

    def save_run_record(self, record: RunRecord, *, overwrite: bool | None = None) -> str:
        path = self._record_path(self._runs_dir, record.run_id)
        self._write_model(path, record, overwrite)
        return str(path)

    def load_run_record(self, run_id: str) -> RunRecord:
        path = self._record_path(self._runs_dir, run_id)
        return self._load_model(path, RunRecord, f"Run record not found: {run_id}")

    def save_replay_bundle(self, bundle: ReplayBundle, *, overwrite: bool | None = None) -> str:
        path = self._record_path(self._replay_bundles_dir, bundle.replay_bundle_id)
        self._write_model(path, bundle, overwrite)
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

    def _write_model(self, path: Path, model: BaseModel, overwrite: bool | None = None) -> None:
        data = dumps_bytes(model.model_dump(mode="json"), indent=2)  # refuses before any file is opened
        make_private_dir(path.parent)
        write_bytes_atomic(path, data, overwrite=self.overwrite if overwrite is None else overwrite)

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
