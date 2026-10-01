"""信封加密原语：DEK 加解密数据，主密钥包裹/解裹 DEK。

全部使用 AES-256-GCM。nonce 随机 96 位，密文含 GCM 认证标签。
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
NONCE_LEN = 12


def generate_key() -> bytes:
    """生成 256 位随机密钥。"""
    return os.urandom(KEY_LEN)


def encrypt(dek: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """用 DEK 加密明文，返回 (nonce, ciphertext)。"""
    nonce = os.urandom(NONCE_LEN)
    return nonce, AESGCM(dek).encrypt(nonce, plaintext, None)


def decrypt(dek: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """用 DEK 解密，返回明文。"""
    return AESGCM(dek).decrypt(nonce, ciphertext, None)


def wrap(master_key: bytes, dek: bytes) -> tuple[bytes, bytes]:
    """用主密钥包裹 DEK，返回 (wrap_nonce, wrapped_dek)。"""
    return encrypt(master_key, dek)


def unwrap(master_key: bytes, wrap_nonce: bytes, wrapped_dek: bytes) -> bytes:
    """用主密钥解裹 DEK。"""
    return decrypt(master_key, wrap_nonce, wrapped_dek)
