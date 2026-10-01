"""keyrotate 轮换行为与安全约束的自动化测试。"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from keyrotate import SecretManager
from keyrotate.manager import RotationInProgressError


@pytest.fixture()
def env(tmp_path: Path):
    db_path = tmp_path / "secrets.db"
    key_dir = tmp_path / "keys"
    manager = SecretManager(db_path, key_dir)
    yield manager, db_path, key_dir
    manager.close()


def seed_wallets(manager: SecretManager, count: int, versions: int) -> dict[str, list[bytes]]:
    secrets: dict[str, list[bytes]] = {}
    for i in range(count):
        rid = f"wallet-{i}"
        secrets[rid] = []
        for v in range(versions):
            value = f"seed-{rid}-v{v + 1}".encode()
            manager.put(rid, value)
            secrets[rid].append(value)
    return secrets


def read_ciphertext_bodies(db_path: Path) -> dict[tuple[str, int], bytes]:
    conn = sqlite3.connect(str(db_path))
    rows = conn.execute(
        "SELECT record_id, version, nonce, ciphertext FROM secret_versions"
    ).fetchall()
    conn.close()
    return {(rid, ver): nonce + ct for rid, ver, nonce, ct in rows}


def key_files(key_dir: Path) -> list[str]:
    return sorted(p.name for p in key_dir.iterdir())


def test_batched_rotation_with_interleaved_writes(env):
    """分批迁移 + 批次间写入：待迁移不增、全部可读、密文主体不变、只留当前代密钥。"""
    manager, db_path, key_dir = env
    secrets = seed_wallets(manager, count=4, versions=3)  # 12 个历史版本
    bodies_before = read_ciphertext_bodies(db_path)

    st = manager.rotate("rot-1", batch_size=5)
    assert st.status == "in_progress"
    assert (st.from_generation, st.to_generation) == (1, 2)
    assert st.pending == 12 - 5 and st.migrated == 5
    assert key_files(key_dir) == ["master_v1.key", "master_v2.key"]

    # 批次之间新增版本：必须使用新一代密钥，不增加旧代待迁移数量。
    manager.put("wallet-0", b"seed-wallet-0-v4")
    secrets["wallet-0"].append(b"seed-wallet-0-v4")
    manager.put("wallet-new", b"seed-wallet-new-v1")
    secrets["wallet-new"] = [b"seed-wallet-new-v1"]
    st = manager.rotate("rot-1", batch_size=5)
    assert st.status == "in_progress"
    assert st.pending == 2 and st.migrated == 10  # 新写入未计入待迁移

    # 迁移中：已迁移、未迁移、新写入的版本全部可读。
    for rid, values in secrets.items():
        for idx, value in enumerate(values, start=1):
            assert manager.get(rid, idx) == value

    st = manager.rotate("rot-1", batch_size=5)
    assert st.status == "completed" and st.pending == 0
    assert key_files(key_dir) == ["master_v2.key"]  # 只留当前一代

    # 完成后所有版本仍可读，且既有版本密文主体逐字节不变。
    for rid, values in secrets.items():
        for idx, value in enumerate(values, start=1):
            assert manager.get(rid, idx) == value
    bodies_after = read_ciphertext_bodies(db_path)
    for key, body in bodies_before.items():
        assert bodies_after[key] == body


def test_two_rounds_with_replayed_ids(env):
    """连续两轮 + 重复标识：不多生成密钥、不恢复旧密钥、历史版本全部可读。"""
    manager, db_path, key_dir = env
    secrets = seed_wallets(manager, count=3, versions=2)

    st1 = manager.rotate("round-a", batch_size=100)
    assert st1.status == "completed" and st1.to_generation == 2
    # 重放已完成标识：返回同一结果，不产生新一轮。
    again = manager.rotate("round-a", batch_size=100)
    assert again == st1
    assert key_files(key_dir) == ["master_v2.key"]

    manager.put("wallet-0", b"seed-wallet-0-v3")
    secrets["wallet-0"].append(b"seed-wallet-0-v3")

    st2 = manager.rotate("round-b", batch_size=2)
    assert st2.status == "in_progress" and (st2.from_generation, st2.to_generation) == (2, 3)
    # 第二轮进行中重放更早标识：不改变当前状态。
    assert manager.rotate("round-a") == st1
    active = manager.rotate("round-b", batch_size=2)
    assert active.status == "in_progress" and active.to_generation == 3
    # 当前轮未完成时拒绝新标识。
    with pytest.raises(RotationInProgressError):
        manager.rotate("round-c")
    # 重复当前标识：继续该轮而非新开一轮。
    done2 = manager.rotate("round-b", batch_size=100)
    assert done2.status == "completed" and done2.to_generation == 3
    assert key_files(key_dir) == ["master_v3.key"]  # 旧密钥未恢复、无多余代

    for rid, values in secrets.items():
        for idx, value in enumerate(values, start=1):
            assert manager.get(rid, idx) == value


def test_no_plaintext_in_db_or_temp_files(env):
    """数据库与受管目录中不出现秘密明文；主密钥不入库。"""
    manager, db_path, key_dir = env
    marker = b"super-secret-seed-0xdeadbeef"
    manager.put("wallet-x", marker)
    manager.put("wallet-x", b"super-secret-seed-v2-cafebabe")
    manager.rotate("rot-privacy", batch_size=100)

    raw_db = db_path.read_bytes()
    assert marker not in raw_db
    assert b"super-secret-seed" not in raw_db
    for path in key_dir.iterdir():
        assert marker not in path.read_bytes()
    # 主密钥只存在于受管目录，不在数据库中。
    key_bytes = (key_dir / "master_v2.key").read_bytes()
    assert key_bytes not in raw_db
    # 轮换完成后无临时副本残留。
    assert not list(key_dir.glob("*.tmp"))


def test_history_versions_always_readable(env):
    """更新只新增版本，所有历史版本始终可读。"""
    manager, _, _ = env
    for v in range(1, 6):
        assert manager.put("wallet-h", f"seed-v{v}".encode()) == v
    for v in range(1, 6):
        assert manager.get("wallet-h", v) == f"seed-v{v}".encode()
    assert manager.get("wallet-h") == b"seed-v5"  # 缺省取最新
    with pytest.raises(KeyError):
        manager.get("wallet-h", 99)
