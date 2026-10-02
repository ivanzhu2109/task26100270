"""High-level facade used by NomadPay: versioned secrets + key rotation."""

import logging
from dataclasses import dataclass
from pathlib import Path

from . import crypto
from .errors import RotationInProgress
from .keystore import KeyStore
from .store import RotationRow, Store

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RotationReport:
    rotation_id: str
    status: str  # "active" | "complete"
    old_generation: int
    new_generation: int
    migrated: int
    remaining: int


class SecretManager:
    """Writes/reads versioned secrets and advances master-key rotation.

    Rotation is driven by repeated :meth:`rotate` calls carrying a
    caller-supplied unique rotation id. Re-submitting the same id continues
    that round (or returns its finished result); a different id is rejected
    while a round is active; replaying an id from an already completed round
    never mutates state.
    """

    def __init__(self, db_path: str | Path, key_dir: str | Path) -> None:
        self._store = Store(db_path)
        self._keys = KeyStore(key_dir)
        if self._keys.current_generation() is None:
            generation = self._keys.create_next_generation()
            logger.info("initialised master key generation %d", generation)

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "SecretManager":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- secret operations ------------------------------------------------
    def put(self, record: str, secret: bytes) -> int:
        """Encrypt and append a new version of ``record``; return version no."""
        if not isinstance(secret, (bytes, bytearray)):
            raise TypeError("secret must be bytes")
        generation = self._keys.current_generation()
        master_key = self._keys.load(generation)
        dek = crypto.generate_dek()
        ciphertext = crypto.seal(dek, bytes(secret))
        wrapped_dek = crypto.wrap_dek(master_key, dek)
        version = self._store.insert_version(record, ciphertext, wrapped_dek, generation)
        logger.info("record %r: stored version %d (key gen %d)", record, version, generation)
        return version

    def get(self, record: str, version: int | None = None) -> bytes:
        """Decrypt one version (latest when ``version`` is None)."""
        row = self._store.get_version(record, version)
        master_key = self._keys.load(row.key_generation)
        dek = crypto.unwrap_dek(master_key, row.wrapped_dek)
        return crypto.open_sealed(dek, row.ciphertext)

    # --- rotation ----------------------------------------------------------
    def rotate(self, rotation_id: str, batch_size: int = 100) -> RotationReport:
        """Begin or continue the rotation round identified by ``rotation_id``."""
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        existing = self._store.get_rotation(rotation_id)
        if existing is not None and existing.status == "complete":
            # Replay of a finished round: report the stored result, change nothing.
            return self._report(existing, remaining=0)

        active = self._store.active_rotation()
        if active is None:
            if existing is not None:  # pragma: no cover - defensive
                raise RotationInProgress(
                    f"rotation {rotation_id!r} is in an inconsistent state"
                )
            active = self._begin_round(rotation_id)
        elif existing is None or existing.rotation_id != active.rotation_id:
            raise RotationInProgress(
                f"rotation {active.rotation_id!r} is still active; "
                f"cannot start {rotation_id!r}"
            )

        self._ensure_round_key(active)
        self._migrate_batch(active, batch_size)
        remaining = self._store.count_pending(active.new_generation)
        if remaining == 0:
            self._finalize_round(active)
            return self._report(self._store.get_rotation(rotation_id), remaining=0)
        return self._report(self._store.get_rotation(rotation_id), remaining)

    # --- rotation internals --------------------------------------------------
    def _begin_round(self, rotation_id: str) -> RotationRow:
        current = self._keys.current_generation()
        new_generation = current + 1
        total_pending = self._store.count_pending(new_generation)
        self._store.begin_rotation(
            rotation_id, current, new_generation, total_pending
        )
        # Key is installed after the row so a crash leaves a recoverable
        # active row whose key can be (re)created on the next call.
        installed = self._keys.create_next_generation()
        assert installed == new_generation
        logger.info(
            "rotation %r: begun, gen %d -> %d, %d version(s) pending",
            rotation_id, current, new_generation, total_pending,
        )
        return self._store.get_rotation(rotation_id)

    def _ensure_round_key(self, rotation: RotationRow) -> None:
        if self._keys.current_generation() != rotation.new_generation:
            # Crash between recording the round and installing its key.
            installed = self._keys.create_next_generation()
            assert installed == rotation.new_generation

    def _migrate_batch(self, rotation: RotationRow, batch_size: int) -> int:
        batch = self._store.pending_versions(rotation.new_generation, batch_size)
        if not batch:
            return 0
        new_master = self._keys.load(rotation.new_generation)
        old_masters: dict[int, bytes] = {}
        migrated = 0
        for row in batch:
            if row.key_generation not in old_masters:
                old_masters[row.key_generation] = self._keys.load(row.key_generation)
            dek = crypto.unwrap_dek(old_masters[row.key_generation], row.wrapped_dek)
            rewrapped = crypto.wrap_dek(new_master, dek)
            self._store.rewrap_version(
                row.record, row.version, rewrapped, rotation.new_generation
            )
            migrated += 1
        self._store.advance_rotation(rotation.rotation_id, migrated)
        logger.info(
            "rotation %r: migrated %d version(s) to gen %d",
            rotation.rotation_id, migrated, rotation.new_generation,
        )
        return migrated

    def _finalize_round(self, rotation: RotationRow) -> None:
        # All versions now depend only on the current generation; retire the
        # old key material and any temporary copies before reporting done.
        for generation in self._keys.generations_on_disk():
            if generation != rotation.new_generation:
                self._keys.remove_generation(generation)
        self._keys.remove_temp_files()
        self._store.complete_rotation(rotation.rotation_id)
        logger.info(
            "rotation %r: complete; only key gen %d remains",
            rotation.rotation_id, rotation.new_generation,
        )

    @staticmethod
    def _report(rotation: RotationRow, remaining: int) -> RotationReport:
        return RotationReport(
            rotation_id=rotation.rotation_id,
            status=rotation.status,
            old_generation=rotation.old_generation,
            new_generation=rotation.new_generation,
            migrated=rotation.migrated,
            remaining=remaining,
        )
