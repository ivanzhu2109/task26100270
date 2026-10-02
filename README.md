# keyrotate

供 NomadPay 上层直接调用的托管秘密密钥轮换库。秘密以加密历史版本存入
SQLite，主密钥仅存本地受管目录，支持通过多次维护调用分批推进主密钥轮换。

## 安全模型

- 每个秘密版本用独立的随机 DEK（AES-256-GCM）加密，DEK 再由当前代主密钥
  包裹后入库（envelope encryption）。
- 数据库中只有密文与包裹后的 DEK；秘密明文、主密钥均不入库，日志只记录
  记录名、版本号与密钥代号，不含明文。
- 轮换只做"重包裹"：每个既有版本的密文主体逐字节不变，仅更新保护其解密
  能力的加密元信息（wrapped DEK 与密钥代号），历史审计凭据保持稳定。
- 轮换完成后，受管目录中只保留当前一代主密钥材料，旧代密钥文件与临时
  副本全部移除。

## 安装与依赖

- Python 3.10+，依赖 `cryptography`（`pip install cryptography`）。
- 仅使用 SQLite 与本地文件，无需任何外部服务。

## 快速开始

```python
from keyrotate import SecretManager

# db_path: SQLite 数据库路径；key_dir: 主密钥受管目录（自动创建）
with SecretManager("secrets.db", "keys/") as sm:
    # 写入秘密的新版本（不透明字节），返回版本号
    v1 = sm.put("wallet/seed", b"\x00\x11...seed-bytes...")
    v2 = sm.put("wallet/seed", b"\x22\x33...new-seed-bytes...")

    # 按记录及版本读取；省略版本号则读最新版本
    latest = sm.get("wallet/seed")
    first = sm.get("wallet/seed", 1)

    # 推进主密钥轮换：调用方提供唯一轮换标识，可分批多次调用
    report = sm.rotate("2026-10-rotation-1", batch_size=500)
    while report.status != "complete":
        report = sm.rotate("2026-10-rotation-1", batch_size=500)
```

## 轮换语义

- `rotate(rotation_id, batch_size)` 每次调用最多迁移 `batch_size` 个历史
  版本；返回 `RotationReport(status, old_generation, new_generation,
  migrated, remaining)`。
- 重复提交同一标识：继续该轮；若该轮已完成，返回其完成结果，不产生新轮。
- 当前轮未完成时提交新标识：抛出 `RotationInProgress`，状态不变。
- 后续轮开始或完成后重放更早的标识：返回该轮已存结果，不改变当前状态。
- 轮换期间可正常 `put`/`get`：新版本直接由新一代主密钥保护，不增加旧代
  待迁移数量；已迁移、未迁移与新写入的版本全程可读。
- 仅当所有历史版本均不再依赖旧主密钥、旧密钥文件及临时副本已移除时，
  报告 `status="complete"`。

## 运行测试

```bash
python3 -m pytest tests/ -q
```

覆盖：分批迁移并在批次间写入新版本、密文主体逐字节不变、连续两轮穿插
重复标识、数据库与日志无明文、主密钥不入库、完成后仅保留当前代密钥。
