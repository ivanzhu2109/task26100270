"""keyrotate: versioned secret storage with master-key rotation."""

from .errors import (
    KeyRotateError,
    MasterKeyError,
    RecordNotFound,
    RotationInProgress,
    StaleRotationId,
)
from .manager import RotationReport, SecretManager

__all__ = [
    "KeyRotateError",
    "MasterKeyError",
    "RecordNotFound",
    "RotationInProgress",
    "StaleRotationId",
    "RotationReport",
    "SecretManager",
]
