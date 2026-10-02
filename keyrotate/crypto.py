"""Envelope encryption primitives.

Each secret version is encrypted with a fresh random data-encryption key
(DEK) using AES-256-GCM. The DEK is wrapped (encrypted) by the current
master key. Rotation only re-wraps DEKs, so the ciphertext body of every
existing version stays byte-for-byte identical.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_KEY_LEN = 32
_NONCE_LEN = 12


@dataclass(frozen=True)
class SealedVersion:
    """Encrypted form of one secret version."""

    ciphertext: bytes  # AES-GCM(nonce || ciphertext || tag) under the DEK
    wrapped_dek: bytes  # DEK wrapped by a master key (nonce || body || tag)


def generate_master_key() -> bytes:
    """Return a fresh 256-bit master key."""
    return os.urandom(_KEY_LEN)


def generate_dek() -> bytes:
    """Return a fresh 256-bit data-encryption key."""
    return os.urandom(_KEY_LEN)


def seal(dek: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext under the DEK, returning nonce||ct||tag."""
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(dek).encrypt(nonce, plaintext, None)


def open_sealed(dek: bytes, sealed: bytes) -> bytes:
    """Decrypt a value produced by ``seal``."""
    nonce, body = sealed[:_NONCE_LEN], sealed[_NONCE_LEN:]
    return AESGCM(dek).decrypt(nonce, body, None)


def wrap_dek(master_key: bytes, dek: bytes) -> bytes:
    """Wrap a DEK under the master key."""
    return seal(master_key, dek)


def unwrap_dek(master_key: bytes, wrapped: bytes) -> bytes:
    """Unwrap a DEK previously wrapped by ``wrap_dek``."""
    return open_sealed(master_key, wrapped)
