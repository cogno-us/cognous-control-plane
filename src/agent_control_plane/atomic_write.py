"""Atomic, private file writes for stored records (a leaf module: imports nothing from this package)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def make_private_dir(path: Path) -> None:
    """Create ``path`` (and missing parents) with mode 0700 for the final directory; an existing directory is left as it is."""
    path.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)


def open_private_lock(path: Path) -> int:
    """Open (creating if needed) a lock file for read/write and return the descriptor; its mode is narrowed to 0600.

    A lock file that already existed with a broader mode is narrowed through the open descriptor (a file this process cannot
    chmod raises ``PermissionError``: the lock is not used).
    """
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, PRIVATE_FILE_MODE)
    try:
        if os.fstat(fd).st_mode & 0o077:
            os.fchmod(fd, PRIVATE_FILE_MODE)
    except BaseException:
        os.close(fd)
        raise
    return fd


def narrow_dir_mode(path: Path) -> None:
    """Narrow an existing directory to 0700 through a descriptor opened without following a final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.fstat(fd).st_mode & 0o077:
            os.fchmod(fd, PRIVATE_DIR_MODE)
    finally:
        os.close(fd)


def write_bytes_atomic(path: Path, data: bytes, *, overwrite: bool = True) -> None:
    """Write ``data`` to ``path`` through a temporary file in the same directory, mode 0600, fsynced.

    With ``overwrite=False`` the target is created exclusively and ``FileExistsError`` is raised when it exists (the existing file
    is never touched). With ``overwrite=True`` the target is replaced atomically. A failure at any step leaves an existing target
    exactly as it was and removes the temporary file. ``data`` is already encoded, so nothing is opened before encoding succeeded.
    """
    directory = path.parent
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), PRIVATE_FILE_MODE)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(tmp, path)
        else:
            os.link(tmp, path)  # atomic; raises FileExistsError when the target exists
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
