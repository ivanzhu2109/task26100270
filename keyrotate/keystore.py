"""Local-directory master key storage.

Master keys live as files inside one managed directory; they are never
written to the database. Exactly one generation is "current" at a time.
After a rotation completes, only the current generation's key material
may remain in the directory.
"""

import os
import re
from pathlib import Path

from . import crypto
from .errors import MasterKeyError

_KEY_FILE_RE = re.compile(r"^master-(\d+)\.key$")


class KeyStore:
    """Manages master key files inside a dedicated directory."""

    CURRENT_POINTER = "CURRENT"
    KEY_PREFIX = "master-"
    KEY_SUFFIX = ".key"
    TEMP_SUFFIX = ".tmp"

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def key_path(self, generation: int) -> Path:
        return self.directory / f"{self.KEY_PREFIX}{generation}{self.KEY_SUFFIX}"

    def current_generation(self) -> int | None:
        """Return the current generation number, or None if uninitialised."""
        pointer = self.directory / self.CURRENT_POINTER
        if not pointer.exists():
            return None
        try:
            return int(pointer.read_text().strip())
        except ValueError as exc:
            raise MasterKeyError(f"corrupt CURRENT pointer: {pointer}") from exc

    def load(self, generation: int) -> bytes:
        """Load the raw key bytes for a generation."""
        path = self.key_path(generation)
        if not path.exists():
            raise MasterKeyError(f"master key file missing: {path}")
        data = path.read_bytes()
        if len(data) != 32:
            raise MasterKeyError(f"master key file has wrong length: {path}")
        return data

    def create_next_generation(self) -> int:
        """Generate and install a new master key; return its generation."""
        current = self.current_generation()
        generation = (current or 0) + 1
        key = crypto.generate_master_key()
        self._atomic_write(self.key_path(generation), key)
        self._atomic_write(
            self.directory / self.CURRENT_POINTER, f"{generation}\n".encode()
        )
        return generation

    def generations_on_disk(self) -> list[int]:
        """List all generations with key files present."""
        generations = []
        for entry in self.directory.iterdir():
            match = _KEY_FILE_RE.match(entry.name)
            if match:
                generations.append(int(match.group(1)))
        return sorted(generations)

    def remove_generation(self, generation: int) -> None:
        """Delete the key file for a retired generation."""
        try:
            self.key_path(generation).unlink()
        except FileNotFoundError:
            pass

    def remove_temp_files(self) -> None:
        """Delete any leftover temporary copies of key material."""
        for entry in self.directory.iterdir():
            if entry.name.endswith(self.TEMP_SUFFIX) or self.TEMP_SUFFIX in entry.name:
                entry.unlink(missing_ok=True)

    def _atomic_write(self, path: Path, data: bytes) -> None:
        tmp = path.with_name(f"{path.name}{self.TEMP_SUFFIX}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        finally:
            tmp.unlink(missing_ok=True)
