"""Pre-scan source bindings for exact native range verification."""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from types import MappingProxyType
from typing import Mapping


def _read(root: Path, relative: str) -> bytes:
    parts = PurePosixPath(relative).parts
    if not parts or PurePosixPath(relative).is_absolute() or any(p in (".", "..") for p in parts):
        raise ValueError("not a source-relative path")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("not a regular source file")
            return stream.read()
    finally:
        os.close(fd)


@dataclass(frozen=True)
class FrozenSource:
    """Source hashes captured before native execution; unavailable paths stay unknown.

    Store hashes, never source text, in this binding. Verification reads through directory
    descriptors without symlinks, then requires the original hash before using any bytes.
    """
    root: Path
    hashes: Mapping[str, str]

    @classmethod
    def capture(cls, root: Path) -> "FrozenSource":
        root = Path(root).absolute()
        hashes = {}
        if root.is_dir() and not root.is_symlink():
            for directory, dirs, names in os.walk(root, followlinks=False):
                dirs[:] = [d for d in dirs if d != ".git" and not (Path(directory) / d).is_symlink()]
                for name in names:
                    relative = (Path(directory) / name).relative_to(root).as_posix()
                    try:
                        hashes[relative] = hashlib.sha256(_read(root, relative)).hexdigest()
                    except (OSError, ValueError):
                        pass
        return cls(root, MappingProxyType(hashes))

    def verified_bytes(self, relative: str) -> bytes | None:
        expected = self.hashes.get(relative)
        if expected is None:
            return None
        try:
            raw = _read(self.root, relative)
        except (OSError, ValueError):
            return None
        return raw if hashlib.sha256(raw).hexdigest() == expected else None
