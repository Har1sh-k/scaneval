"""Bounded filesystem fault injection used by artifact recovery tests."""

import errno
from pathlib import Path

import pytest


@pytest.fixture
def fail_created_write(monkeypatch):
    """Inject an error after a real exclusive open, never by filling the disk."""
    def install(filename, phase, *, close_also_fails=False):
        real_open = Path.open
        failure = OSError(errno.ENOSPC, f"injected {phase} failure")

        class Writer:
            def __init__(self, handle):
                self.handle = handle

            def write(self, content):
                if phase == "write":
                    self.handle.write(content[:16])
                    self.handle.flush()
                    raise failure
                return self.handle.write(content)

            def flush(self):
                self.handle.flush()
                if phase == "flush":
                    raise failure

            def close(self):
                self.handle.close()
                if phase == "close":
                    raise failure
                if close_also_fails:
                    raise OSError(errno.EIO, "secondary close failure")

        def opened(path, *args, **kwargs):
            handle = real_open(path, *args, **kwargs)
            mode = args[0] if args else kwargs.get("mode", "r")
            if path.name == filename and "x" in mode:
                return Writer(handle)
            return handle

        monkeypatch.setattr(Path, "open", opened)
        return failure

    return install
