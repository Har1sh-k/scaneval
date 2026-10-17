"""Create-only writer ownership and preservation of the primary failure."""

import pytest

from scaneval import review, sarif


@pytest.mark.parametrize("writer,content", [(review._write_new, "new text"), (sarif._write_new, b"new bytes")])
@pytest.mark.parametrize("existing", ["file", "symlink"])
def test_exclusive_open_failure_never_removes_an_existing_path(tmp_path, writer, content, existing):
    path = tmp_path / "artifact"
    target = tmp_path / "original"
    target.write_bytes(b"original bytes")
    if existing == "file":
        path.write_bytes(b"original bytes")
    else:
        path.symlink_to(target)
    with pytest.raises(FileExistsError):
        writer(path, content)
    assert path.read_bytes() == target.read_bytes() == b"original bytes"
    assert path.is_symlink() == (existing == "symlink")


@pytest.mark.parametrize("writer,content", [(review._write_new, "new text"), (sarif._write_new, b"new bytes")])
@pytest.mark.parametrize("phase", ["write", "flush"])
def test_cleanup_close_failure_preserves_the_original_exception(
        tmp_path, fail_created_write, writer, content, phase):
    path = tmp_path / "artifact"
    failure = fail_created_write(path.name, phase, close_also_fails=True)
    with pytest.raises(OSError) as caught:
        writer(path, content)
    assert caught.value is failure
    assert not path.exists()


@pytest.mark.parametrize("writer,content", [(review._write_new, "new text"), (sarif._write_new, b"new bytes")])
def test_cleanup_unlink_failure_preserves_the_original_exception(
        tmp_path, monkeypatch, fail_created_write, writer, content):
    path = tmp_path / "artifact"
    failure = fail_created_write(path.name, "write")

    def cannot_unlink(*args, **kwargs):
        raise PermissionError("injected unlink failure")

    monkeypatch.setattr(type(path), "unlink", cannot_unlink)
    with pytest.raises(OSError) as caught:
        writer(path, content)
    assert caught.value is failure
    assert path.exists(), "cleanup is best effort when unlink itself is refused"
