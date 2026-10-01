"""上层 API：写入新版本、按记录及版本读取、推进主密钥轮换。

轮换语义：
- 每轮由调用方提供唯一 rotation_id；重复同一标识继续该轮或返回其完成结果。
- 当前轮未完成时拒绝新标识；后续轮开始后重放更早标识不改变当前状态。
- 轮换可跨多次调用分批推进，调用之间可正常读写。
- 轮换开始后写入的新版本直接使用新一代主密钥，不增加待迁移数量。
- 仅当所有历史版本均不再依赖旧主密钥、旧主密钥文件及临时副本已移除，
  才将该轮标记为 completed。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .keystore import MasterKeyStore
from .store import RotationRow, SecretVersionRow, Store


class RotationInProgressError(RuntimeError):
    """当前轮未完成时提交了新的轮换标识。"""


@dataclass(frozen=True)
class RotationStatus:
    rotation_id: str
    from_generation: int
    to_generation: int
    status: str  # "in_progress" | "completed"
    pending: int
    migrated: int


def _status(row: RotationRow) -> RotationStatus:
    return RotationStatus(
        rotation_id=row.rotation_id,
        from_generation=row.from_generation,
        to_generation=row.to_generation,
        status=row.status,
        pending=row.pending,
        migrated=row.migrated,
    )


class SecretManager:
    """托管秘密的写入/读取与主密钥轮换。"""

    def __init__(self, db_path: str | Path, key_dir: str | Path) -> None:
        self._store = Store(str(db_path))
        self._keys = MasterKeyStore(key_dir)
        # 确保当前代主密钥材料存在（首次运行创建第 1 代；崩溃恢复时幂等）。
        self._keys.create(self._store.current_generation())

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "SecretManager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def put(self, record_id: str, secret: bytes) -> int:
        """写入秘密的新版本，返回版本号。"""
        if not isinstance(secret, (bytes, bytearray)):
            raise TypeError("秘密必须是不透明字节")
        generation = self._store.current_generation()
        master_key = self._keys.load(generation)
        dek = crypto.generate_key()
        nonce, ciphertext = crypto.encrypt(dek, bytes(secret))
        wrap_nonce, wrapped_dek = crypto.wrap(master_key, dek)
        version = self._store.next_version(record_id)
        self._store.insert_version(
            SecretVersionRow(
                record_id=record_id,
                version=version,
                nonce=nonce,
                ciphertext=ciphertext,
                wrap_nonce=wrap_nonce,
                wrapped_dek=wrapped_dek,
                key_generation=generation,
            )
        )
        return version

    def get(self, record_id: str, version: int | None = None) -> bytes:
        """按记录及版本读取秘密明文；version 为 None 时取最新。"""
        row = (
            self._store.latest_version(record_id)
            if version is None
            else self._store.get_version(record_id, version)
        )
        if row is None:
            raise KeyError(f"秘密不存在: {record_id} version={version}")
        master_key = self._keys.load(row.key_generation)
        dek = crypto.unwrap(master_key, row.wrap_nonce, row.wrapped_dek)
        return crypto.decrypt(dek, row.nonce, row.ciphertext)

    def rotate(self, rotation_id: str, batch_size: int = 100) -> RotationStatus:
        """推进一轮主密钥轮换（幂等，可多次调用直至 completed）。"""
        if batch_size < 1:
            raise ValueError("batch_size 必须 >= 1")
        existing = self._store.get_rotation(rotation_id)
        if existing is not None and existing.status == "completed":
            # 重放已完成标识（包括后续轮开始后的更早标识）：只返回结果。
            return _status(existing)
        if existing is None:
            active = self._store.active_rotation()
            if active is not None:
                raise RotationInProgressError(
                    f"轮换 {active.rotation_id} 未完成，拒绝新标识 {rotation_id}"
                )
            from_gen = self._store.current_generation()
            to_gen = from_gen + 1
            self._keys.create(to_gen)
            self._store.begin_rotation(
                rotation_id, from_gen, to_gen, self._store.count_pending(from_gen)
            )
            existing = self._store.active_rotation()
        assert existing is not None
        return self._advance(existing, batch_size)

    def _advance(self, rotation: RotationRow, batch_size: int) -> RotationStatus:
        batch = self._store.fetch_pending_batch(rotation.from_generation, batch_size)
        if batch:
            old_master = self._keys.load(rotation.from_generation)
            new_master = self._keys.load(rotation.to_generation)
            for row in batch:
                dek = crypto.unwrap(old_master, row.wrap_nonce, row.wrapped_dek)
                wrap_nonce, wrapped_dek = crypto.wrap(new_master, dek)
                self._store.mark_migrated(row, wrap_nonce, wrapped_dek, rotation.to_generation)
        if self._store.count_pending(rotation.from_generation) == 0:
            # 全部历史版本均已脱离旧主密钥：移除旧密钥材料后才报告完成。
            self._keys.remove(rotation.from_generation)
            self._store.complete_rotation(rotation.rotation_id)
            done = self._store.get_rotation(rotation.rotation_id)
            assert done is not None
            return _status(done)
        active = self._store.active_rotation()
        assert active is not None
        return _status(active)
