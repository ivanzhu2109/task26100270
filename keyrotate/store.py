"""SQLite 持久化层：秘密版本、轮换状态。只存密文与加密元信息。"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS secret_versions (
    record_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    wrap_nonce BLOB NOT NULL,
    wrapped_dek BLOB NOT NULL,
    key_generation INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    PRIMARY KEY (record_id, version)
);
CREATE TABLE IF NOT EXISTS rotations (
    rotation_id TEXT PRIMARY KEY,
    from_generation INTEGER NOT NULL,
    to_generation INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('in_progress','completed')),
    pending INTEGER NOT NULL,
    migrated INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    completed_at TEXT
);
"""


@dataclass(frozen=True)
class SecretVersionRow:
    record_id: str
    version: int
    nonce: bytes
    ciphertext: bytes
    wrap_nonce: bytes
    wrapped_dek: bytes
    key_generation: int


@dataclass(frozen=True)
class RotationRow:
    rotation_id: str
    from_generation: int
    to_generation: int
    status: str  # "in_progress" | "completed"
    pending: int
    migrated: int


def _to_version_row(row: sqlite3.Row) -> SecretVersionRow:
    return SecretVersionRow(
        record_id=row["record_id"],
        version=row["version"],
        nonce=row["nonce"],
        ciphertext=row["ciphertext"],
        wrap_nonce=row["wrap_nonce"],
        wrapped_dek=row["wrapped_dek"],
        key_generation=row["key_generation"],
    )


def _to_rotation_row(row: sqlite3.Row) -> RotationRow:
    return RotationRow(
        rotation_id=row["rotation_id"],
        from_generation=row["from_generation"],
        to_generation=row["to_generation"],
        status=row["status"],
        pending=row["pending"],
        migrated=row["migrated"],
    )


class Store:
    """SQLite 存取。构造时建表。"""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('current_generation', '1')"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- 秘密版本 ----
    def next_version(self, record_id: str) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(MAX(version), 0) + 1 AS v FROM secret_versions WHERE record_id = ?",
            (record_id,),
        ).fetchone()
        return int(row["v"])

    def insert_version(self, row: SecretVersionRow) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO secret_versions"
                " (record_id, version, nonce, ciphertext, wrap_nonce, wrapped_dek, key_generation)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    row.record_id,
                    row.version,
                    row.nonce,
                    row.ciphertext,
                    row.wrap_nonce,
                    row.wrapped_dek,
                    row.key_generation,
                ),
            )

    def get_version(self, record_id: str, version: int) -> SecretVersionRow | None:
        row = self._conn.execute(
            "SELECT * FROM secret_versions WHERE record_id = ? AND version = ?",
            (record_id, version),
        ).fetchone()
        return _to_version_row(row) if row else None

    def latest_version(self, record_id: str) -> SecretVersionRow | None:
        row = self._conn.execute(
            "SELECT * FROM secret_versions WHERE record_id = ? ORDER BY version DESC LIMIT 1",
            (record_id,),
        ).fetchone()
        return _to_version_row(row) if row else None

    def list_versions(self, record_id: str) -> list[int]:
        rows = self._conn.execute(
            "SELECT version FROM secret_versions WHERE record_id = ? ORDER BY version",
            (record_id,),
        ).fetchall()
        return [int(r["version"]) for r in rows]

    # ---- 轮换状态 ----
    def current_generation(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key = 'current_generation'"
        ).fetchone()
        return int(row["value"])

    def set_current_generation(self, generation: int) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE meta SET value = ? WHERE key = 'current_generation'",
                (str(generation),),
            )

    def active_rotation(self) -> RotationRow | None:
        row = self._conn.execute(
            "SELECT * FROM rotations WHERE status = 'in_progress'"
            " ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        return _to_rotation_row(row) if row else None

    def get_rotation(self, rotation_id: str) -> RotationRow | None:
        row = self._conn.execute(
            "SELECT * FROM rotations WHERE rotation_id = ?", (rotation_id,)
        ).fetchone()
        return _to_rotation_row(row) if row else None

    def begin_rotation(self, rotation_id: str, from_gen: int, to_gen: int, pending: int) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO rotations (rotation_id, from_generation, to_generation, status, pending)"
                " VALUES (?, ?, ?, 'in_progress', ?)",
                (rotation_id, from_gen, to_gen, pending),
            )
            self._conn.execute(
                "UPDATE meta SET value = ? WHERE key = 'current_generation'",
                (str(to_gen),),
            )

    def count_pending(self, from_gen: int) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM secret_versions WHERE key_generation = ?",
            (from_gen,),
        ).fetchone()
        return int(row["c"])

    def fetch_pending_batch(self, from_gen: int, limit: int) -> list[SecretVersionRow]:
        rows = self._conn.execute(
            "SELECT * FROM secret_versions WHERE key_generation = ?"
            " ORDER BY record_id, version LIMIT ?",
            (from_gen, limit),
        ).fetchall()
        return [_to_version_row(r) for r in rows]

    def mark_migrated(
        self, row: SecretVersionRow, wrap_nonce: bytes, wrapped_dek: bytes, to_gen: int
    ) -> None:
        with self._conn:
            cur = self._conn.execute(
                "UPDATE secret_versions SET wrap_nonce = ?, wrapped_dek = ?, key_generation = ?"
                " WHERE record_id = ? AND version = ? AND key_generation = ?",
                (wrap_nonce, wrapped_dek, to_gen, row.record_id, row.version, row.key_generation),
            )
            if cur.rowcount != 1:
                raise RuntimeError(f"迁移行不存在或代际已变化: {row.record_id} v{row.version}")
            self._conn.execute(
                "UPDATE rotations SET pending = pending - 1, migrated = migrated + 1"
                " WHERE status = 'in_progress'"
            )

    def complete_rotation(self, rotation_id: str) -> None:
        with self._conn:
            self._conn.execute(
                "UPDATE rotations SET status = 'completed',"
                " completed_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')"
                " WHERE rotation_id = ?",
                (rotation_id,),
            )
