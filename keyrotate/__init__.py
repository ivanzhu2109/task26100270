"""keyrotate: 托管秘密的密钥轮换库（信封加密 + SQLite 版本化存储）。"""

from .manager import RotationStatus, SecretManager

__all__ = ["SecretManager", "RotationStatus"]
