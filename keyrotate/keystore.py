"""主密钥本地目录管理：每代一个文件，临时副本原子替换。

文件布局：<key_dir>/master_v<n>.key（原始 32 字节密钥，权限 0600）。
创建时先写临时文件再 os.replace 原子落盘；remove 会连同临时副本一起清除。
"""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from . import crypto

_NAME_RE = re.compile(r"^master_v(\d+)\.key$")


class MasterKeyStore:
    """管理目录下的主密钥文件 master_v{n}.key。"""

    def __init__(self, key_dir: str | Path) -> None:
        self._dir = Path(key_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, generation: int) -> Path:
        return self._dir / f"master_v{generation}.key"

    def exists(self, generation: int) -> bool:
        return self._path(generation).is_file()

    def load(self, generation: int) -> bytes:
        data = self._path(generation).read_bytes()
        if len(data) != crypto.KEY_LEN:
            raise ValueError(f"主密钥文件损坏: {self._path(generation)}")
        return data

    def create(self, generation: int) -> bytes:
        """原子地创建新一代主密钥并返回；已存在则直接读出（幂等）。"""
        path = self._path(generation)
        if path.is_file():
            return self.load(generation)
        key = crypto.generate_key()
        fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=self._dir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return key

    def remove(self, generation: int) -> None:
        """移除该代主密钥文件及其临时副本。"""
        prefix = self._path(generation).name
        for entry in self._dir.iterdir():
            if entry.name == prefix or (
                entry.name.startswith(prefix + ".") and entry.name.endswith(".tmp")
            ):
                entry.unlink(missing_ok=True)

    def generations_present(self) -> list[int]:
        gens = []
        for entry in self._dir.iterdir():
            match = _NAME_RE.match(entry.name)
            if match:
                gens.append(int(match.group(1)))
        return sorted(gens)
