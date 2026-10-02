"""End-to-end tests for the keyrotate library."""

import os
import sqlite3
from pathlib import Path

import pytest

from keyrotate import (
    RecordNotFound,
    RotationInProgress,
    SecretManager,
)


@pytest.fixture()
def env(tmp_path):
    db = tmp_path / "secrets.db"
    key_dir = tmp_path / "keys"
    manager = SecretManager(db, key_dir)
    yield manager, db, key_dir
    manager.close()


def raw_ciphertexts(db_path, record):
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT version, ciphertext, wrapped_dek, key_generation"
            " FROM versions WHERE record = ? ORDER BY version",
            (record,),
        ).fetchall()
    finally:
        conn.close()
    return rows


def key_files(key_dir):
    return sorted(p.name for p in Path(key_dir).iterdir())


class TestBatchedRotation:
    def test_batched_migration_with_interleaved_writes(self, env):
        manager, db, key_dir = env
        record = "wallet/seed"
        secrets = [f"seed-value-{i}".encode() for i in range(1, 6)]
        for secret in secrets:
            manager.put(record, secret)

        before = raw_ciphertexts(db, record)
        assert len(before) == 5
        assert {row[3] for row in before} == {1}  # all under generation 1

        # Advance one batch of 2; round stays active.
        report = manager.rotate("rot-batch-1", batch_size=2)
        assert report.status == "active"
        assert report.migrated == 2
        assert report.remaining == 3

        # New write between batches uses the new generation and must not
        # increase the old key's pending count.
        extra = b"seed-value-6"
        manager.put(record, extra)
        pending_row = raw_ciphertexts(db, record)[-1]
        assert pending_row[3] == report.new_generation

        report = manager.rotate("rot-batch-1", batch_size=2)
        assert report.status == "active"
        assert report.migrated == 4
        assert report.remaining == 1  # only the original backlog counts down

        # Mid-rotation: migrated, unmigrated and freshly written all readable.
        for index, secret in enumerate(secrets, start=1):
            assert manager.get(record, index) == secret
        assert manager.get(record, 6) == extra

        report = manager.rotate("rot-batch-1", batch_size=2)
        assert report.status == "complete"
        assert report.remaining == 0

        # All versions still readable after completion.
        for index, secret in enumerate(secrets, start=1):
            assert manager.get(record, index) == secret
        assert manager.get(record, 6) == extra
        assert manager.get(record) == extra  # latest by default

        # Ciphertext bodies of pre-existing versions are byte-identical.
        after = raw_ciphertexts(db, record)
        for before_row, after_row in zip(before, after[:5]):
            assert before_row[1] == after_row[1]
        # Wrapping metadata did move to the new generation.
        assert {row[3] for row in after} == {report.new_generation}

        # Only the current generation's key material remains on disk.
        files = key_files(key_dir)
        assert f"master-{report.new_generation}.key" in files
        assert not any(name.endswith(".tmp") or ".tmp" in name for name in files)
        masters = [n for n in files if n.startswith("master-")]
        assert masters == [f"master-{report.new_generation}.key"]


class TestConsecutiveRounds:
    def test_two_rounds_with_duplicate_ids(self, env):
        manager, db, key_dir = env
        record = "wallet/seed"
        manager.put(record, b"round0-a")
        manager.put(record, b"round0-b")

        first = manager.rotate("round-1", batch_size=100)
        assert first.status == "complete"
        gen_after_first = first.new_generation

        # Duplicate submission of the finished id: same result, no new round.
        again = manager.rotate("round-1", batch_size=100)
        assert again.status == "complete"
        assert again.new_generation == gen_after_first
        assert key_files(key_dir) == [
            "CURRENT",
            f"master-{gen_after_first}.key",
        ]

        manager.put(record, b"round1-a")

        # Second round proceeds in two batches; duplicate id mid-round
        # continues the same round instead of creating another generation.
        second = manager.rotate("round-2", batch_size=1)
        assert second.status == "active"
        assert second.new_generation == gen_after_first + 1
        dup = manager.rotate("round-2", batch_size=1)
        assert dup.new_generation == second.new_generation
        done = manager.rotate("round-2", batch_size=100)
        assert done.status == "complete"
        assert done.new_generation == gen_after_first + 1

        # No extra key generation was ever created.
        assert key_files(key_dir) == [
            "CURRENT",
            f"master-{gen_after_first + 1}.key",
        ]

        # Replaying the older id after the newer round finished changes
        # nothing and restores nothing.
        replay = manager.rotate("round-1")
        assert replay.status == "complete"
        assert replay.new_generation == gen_after_first
        assert key_files(key_dir) == [
            "CURRENT",
            f"master-{gen_after_first + 1}.key",
        ]

        # Every historical version is still readable.
        assert manager.get(record, 1) == b"round0-a"
        assert manager.get(record, 2) == b"round0-b"
        assert manager.get(record, 3) == b"round1-a"

    def test_conflicting_id_rejected_while_active(self, env):
        manager, db, key_dir = env
        manager.put("wallet/seed", b"v1")
        manager.put("wallet/seed", b"v2")
        report = manager.rotate("round-a", batch_size=1)
        assert report.status == "active"
        with pytest.raises(RotationInProgress):
            manager.rotate("round-b")
        # Same id still continues the original round.
        done = manager.rotate("round-a", batch_size=10)
        assert done.status == "complete"


class TestStorageHygiene:
    def test_no_plaintext_in_database_or_key_material(self, env, tmp_path):
        manager, db, key_dir = env
        secret = b"super-secret-wallet-seed-0001"
        manager.put("wallet/seed", secret)
        manager.rotate("hygiene-1", batch_size=10)
        manager.close()

        db_bytes = Path(db).read_bytes()
        assert secret not in db_bytes
        # Master keys live only in the key directory, never in the DB.
        key_name = next(n for n in key_files(key_dir) if n.startswith("master-"))
        master = (Path(key_dir) / key_name).read_bytes()
        assert master not in db_bytes
        # The plaintext is nowhere in the key directory either.
        for path in Path(key_dir).iterdir():
            assert secret not in path.read_bytes()

        # Reopen and read back: persistence works across instances.
        manager2 = SecretManager(db, key_dir)
        assert manager2.get("wallet/seed", 1) == secret
        manager2.close()

    def test_missing_record_raises(self, env):
        manager, _, _ = env
        with pytest.raises(RecordNotFound):
            manager.get("no/such-record")
