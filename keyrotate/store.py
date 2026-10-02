"""SQLite persistence for encrypted secret versions and rotation state.

Only ciphertext and wrapped key material are stored here; plaintext
secrets and master keys never touch the database.
"""

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from .errors import RecordNotFound

_SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    record TEXT NOT NULL,
    version INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    key_generation INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (record, version)
);
CREATE TABLE IF NOT EXISTS rotations (
    rotation_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL,
    old_generation INTEGER NOT NULL,
    new_generation INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'complete')),
    total_pending INTEGER NOT NULL,
    migrated INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
"""


@dataclass(frozen=True)
class VersionRow:
    record: str
    version: int
    ciphertext: bytes
    wrapped_dek: bytes
    key_generation: int
    created_at: str


@dataclass(frozen=True)
class RotationRow:
    rotation_id: str
    seq: int
    old_generation: int
    new_generation: int
    status: str  # "active" | "complete"
    total_pending: int
    migrated: int


def _to_version_row(row: sqlite3.Row) -> VersionRow:
    return VersionRow(
        record=row[0],
        version=row[1],
        ciphertext=bytes(row[2]),
        wrapped_dek=bytes(row[3]),
        key_generation=row[4],
        created_at=row[5],
    )


def _to_rotation_row(row: sqlite3.Row) -> RotationRow:
    return RotationRow(
        rotation_id=row[0],
        seq=row[1],
        old_generation=row[2],
        new_generation=row[3],
        status=row[4],
        total_pending=row[5],
        migrated=row[6],
    )


class Store:
    def __init__(self, db_path: str | Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def close(self) -> None:
        self._conn.close()

    def _create_schema(self) -> None:
        with self._conn:
            self._conn.executescript(_SCHEMA)

    # --- secret versions -------------------------------------------------
    def insert_version(
        self,
        record: str,
        ciphertext: bytes,
        wrapped_dek: bytes,
        key_generation: int,
    ) -> int:
        """Append a new version for ``record``; return its version number."""
        with self._conn:
            cursor = self._conn.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM versions WHERE record = ?",
                (record,),
            )
            version = cursor.fetchone()[0]
            self._conn.execute(
                "INSERT INTO versions (record, version, ciphertext, wrapped_dek,"
                " key_generation) VALUES (?, ?, ?, ?, ?)",
                (record, version, ciphertext, wrapped_dek, key_generation),
            )
        return version

    def get_version(self, record: str, version: int | None = None) -> VersionRow:
        """Fetch one version; ``None`` selects the latest."""
        if version is None:
            cursor = self._conn.execute(
                "SELECT record, version, ciphertext, wrapped_dek, key_generation,"
                " created_at FROM versions WHERE record = ?"
                " ORDER BY version DESC LIMIT 1",
                (record,),
            )
        else:
            cursor = self._conn.execute(
                "SELECT record, version, ciphertext, wrapped_dek, key_generation,"
                " created_at FROM versions WHERE record = ? AND version = ?",
                (record, version),
            )
        row = cursor.fetchone()
        if row is None:
            raise RecordNotFound(f"no version found for record {record!r}")
        return _to_version_row(row)

    def list_versions(self, record: str) -> list[VersionRow]:
        cursor = self._conn.execute(
            "SELECT record, version, ciphertext, wrapped_dek, key_generation,"
            " created_at FROM versions WHERE record = ? ORDER BY version",
            (record,),
        )
        return [_to_version_row(row) for row in cursor.fetchall()]

    def pending_generations(self, current_generation: int) -> list[int]:
        """Generations other than ``current_generation`` still in use."""
        cursor = self._conn.execute(
            "SELECT DISTINCT key_generation FROM versions"
            " WHERE key_generation != ? ORDER BY key_generation",
            (current_generation,),
        )
        return [row[0] for row in cursor.fetchall()]

    def pending_versions(self, current_generation: int, limit: int) -> list[VersionRow]:
        """Up to ``limit`` versions not yet protected by the current key."""
        cursor = self._conn.execute(
            "SELECT record, version, ciphertext, wrapped_dek, key_generation,"
            " created_at FROM versions WHERE key_generation != ?"
            " ORDER BY record, version LIMIT ?",
            (current_generation, limit),
        )
        return [_to_version_row(row) for row in cursor.fetchall()]

    def count_pending(self, current_generation: int) -> int:
        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM versions WHERE key_generation != ?",
            (current_generation,),
        )
        return cursor.fetchone()[0]

    def rewrap_version(
        self, record: str, version: int, wrapped_dek: bytes, key_generation: int
    ) -> None:
        """Replace only the wrapping metadata of a version (ciphertext stays)."""
        with self._conn:
            self._conn.execute(
                "UPDATE versions SET wrapped_dek = ?, key_generation = ?"
                " WHERE record = ? AND version = ?",
                (wrapped_dek, key_generation, record, version),
            )

    # --- rotation bookkeeping --------------------------------------------
    def begin_rotation(
        self, rotation_id: str, old_generation: int, new_generation: int, total_pending: int
    ) -> None:
        with self._conn:
            cursor = self._conn.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM rotations"
            )
            seq = cursor.fetchone()[0]
            self._conn.execute(
                "INSERT INTO rotations (rotation_id, seq, old_generation,"
                " new_generation, status, total_pending, migrated)"
                " VALUES (?, ?, ?, ?, 'active', ?, 0)",
                (rotation_id, seq, old_generation, new_generation, total_pending),
            )

    def get_rotation(self, rotation_id: str) -> RotationRow | None:
        cursor = self._conn.execute(
            "SELECT rotation_id, seq, old_generation, new_generation, status,"
            " total_pending, migrated FROM rotations WHERE rotation_id = ?",
            (rotation_id,),
        )
        row = cursor.fetchone()
        return _to_rotation_row(row) if row else None

    def active_rotation(self) -> RotationRow | None:
        cursor = self._conn.execute(
            "SELECT rotation_id, seq, old_generation, new_generation, status,"
            " total_pending, migrated FROM rotations WHERE status = 'active'"
        )
        row = cursor.fetchone()
        return _to_rotation_row(row) if row else None

    def latest_rotation(self) -> RotationRow | None:
        """Most recently created rotation row, regardless of status."""
        cursor = self._conn.execute(
            "SELECT rotation_id, seq, old_generation, new_generation, status,"
            " total_pending, migrated FROM rotations ORDER BY seq DESC LIMIT 1"
        )
        row = cursor.fetchone()
        return _to_rotation_row(row) if row else None

    def advance_rotation(self, rotation_id: str, migrated_delta: int) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE rotations SET migrated = migrated + ? WHERE rotation_id = ?",
                (migrated_delta, rotation_id),
            )

    def complete_rotation(self, rotation_id: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE rotations SET status = 'complete' WHERE rotation_id = ?",
                (rotation_id,),
            )
