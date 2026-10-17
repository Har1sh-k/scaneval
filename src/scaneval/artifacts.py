"""Create-only artifact writes with ownership-aware failure cleanup."""

from pathlib import Path


def _remove_owned(path: Path) -> None:
    try:
        path.unlink()
    except BaseException:
        # Recovery is best effort and must not replace the original write error.
        pass


def write_new(path: Path, content: str | bytes) -> None:
    """Write a new artifact, removing our partial file if writing or closing fails.

    Ownership starts only once exclusive open succeeds. An existing file or
    symlink is refused by open and is never considered ours to remove.
    """
    if isinstance(content, str):
        handle = path.open("x", encoding="utf-8", newline="\n")
    else:
        handle = path.open("xb")
    try:
        handle.write(content)
        handle.flush()
    except BaseException:
        try:
            handle.close()
        except BaseException:
            pass
        _remove_owned(path)
        raise
    try:
        handle.close()
    except BaseException:
        _remove_owned(path)
        raise
