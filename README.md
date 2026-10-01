# keyrotate — 托管秘密的密钥轮换库

供 NomadPay 上层直接调用的 Python 库。秘密（如钱包种子）以信封加密存入
SQLite 并保留全部历史版本；主密钥按代保存在本地目录，可分批轮换，
轮换期间读写不中断，完成后旧主密钥材料彻底移除。

## 设计

- **信封加密**：每个秘密版本使用独立 DEK（AES-256-GCM）加密；DEK 由当前代
  主密钥包裹后随版本存入数据库。轮换只做"换裹"——用新主密钥重新包裹 DEK，
  因此每个既有版本的密文主体（nonce + ciphertext）逐字节不变，仅保护其
  解密能力的加密元信息（wrapped_dek）更新。
- **存储**：SQLite 存密文与元信息（`secret_versions` / `rotations` / `meta`）；
  主密钥存 `<key_dir>/master_v<n>.key`（0600，临时文件 + `os.replace` 原子落盘）。
  数据库、临时文件、日志中均不出现秘密明文，主密钥不入库。
- **轮换状态机**：每轮由调用方提供唯一 `rotation_id`。重复同一标识继续该轮
  或返回其完成结果；当前轮未完成时拒绝新标识（`RotationInProgressError`）；
  后续轮开始后重放更早标识只返回其历史结果，不改变当前状态。仅当所有历史
  版本均不再依赖旧主密钥、旧主密钥文件及临时副本已移除，才报告 `completed`。

## 使用

```python
from keyrotate import SecretManager

mgr = SecretManager(db_path="secrets.db", key_dir="keys")

# 写入秘密的新版本（不透明字节），返回版本号
v1 = mgr.put("wallet-001", seed_bytes)
v2 = mgr.put("wallet-001", new_seed_bytes)   # 更新只新增版本

# 按记录及版本读取；缺省取最新版本，所有历史版本始终可读
mgr.get("wallet-001", v1)
mgr.get("wallet-001")          # 最新

# 推进主密钥轮换：可多次调用，分批迁移；调用之间可正常 put/get
status = mgr.rotate("2026-10-rotation", batch_size=100)
while status.status != "completed":
    status = mgr.rotate("2026-10-rotation", batch_size=100)
# status.pending / status.migrated 反映进度；轮换开始后写入的新版本
# 直接由新一代主密钥保护，不增加旧一代待迁移数量。

mgr.close()
```

`rotate` 返回 `RotationStatus(rotation_id, from_generation, to_generation,
status, pending, migrated)`。轮换完成后受管目录中只保留当前一代主密钥材料。

## 测试

```bash
python3 -m pytest tests/ -q
```

覆盖：分批迁移并在批次间新增版本（待迁移不增、全部可读、密文主体不变、
完成后只留当前代密钥）；连续两轮并穿插重复轮换标识（不多生成密钥、不恢复
旧密钥、历史版本全部可读）；数据库与目录中无明文、主密钥不入库、无临时
副本残留；历史版本始终可读。

## 依赖

- Python ≥ 3.10，`cryptography`（AES-256-GCM），标准库 `sqlite3`。
- 无 Docker / 外部服务 / 监听端口，持久化仅 SQLite 与本地文件。
