"""History audits allow Git stat-cache refreshes while preserving semantic and path checks."""

import hashlib
import os
import subprocess

import pytest

from scaneval.materialize import (MaterializationError, git_command, git_index_semantic_sha256,
                                  prepare_synthetic_history)
from test_v2_conditions import Offline, invoke


def git(source, *arguments):
    argv, env = git_command(list(arguments))
    return subprocess.run(argv, cwd=source, env=env, capture_output=True, text=True, check=True).stdout


@pytest.mark.parametrize("enforced,expected", [(True, "attested"), (False, "declared_only")])
def test_real_git_status_stat_refresh_does_not_change_neutral_history(tmp_path, enforced, expected):
    def refresh(source):
        path = source / "app.py"
        stamp = path.stat().st_mtime_ns + 2_000_000_000
        os.utime(path, ns=(stamp, stamp))
        assert git(source, "status", "--short") == ""
    _bundle, record = invoke(tmp_path, Offline(git=True, mutate=refresh), enforced=enforced)
    assert record["status"] == expected and record["history"] == "neutral_synthetic"


@pytest.fixture
def index_bytes(tmp_path):
    source = tmp_path / "index-source"
    source.mkdir()
    (source / "app.py").write_text("print(1)\n")
    prepare_synthetic_history(source)
    return (source / ".git" / "index").read_bytes()


def checksum(raw):
    return raw[:-20] + hashlib.sha1(raw[:-20], usedforsecurity=False).digest()


@pytest.mark.parametrize("field", [0, 4, 8, 12, 16, 20, 28, 32, 36])
def test_only_entry_stat_cache_fields_are_normalized(index_bytes, field):
    changed = bytearray(index_bytes)
    changed[12 + field] ^= 1
    assert git_index_semantic_sha256(checksum(changed)) == git_index_semantic_sha256(index_bytes)


@pytest.mark.parametrize("field", [24, 40, 60, 62])
def test_mode_blob_flags_and_path_remain_bound(index_bytes, field):
    changed = bytearray(index_bytes)
    changed[12 + field] ^= 1 if field != 24 else 0
    if field == 24:
        changed[12 + 24:12 + 28] = (0o100755).to_bytes(4, "big")
    if field == 60:
        changed[12 + 60] ^= 0x81  # preserve the name length while changing assume-valid/stage bits
    assert git_index_semantic_sha256(checksum(changed)) != git_index_semantic_sha256(index_bytes)


def test_unknown_index_formats_extensions_and_checksums_are_refused(index_bytes):
    version = bytearray(index_bytes)
    version[4:8] = (4).to_bytes(4, "big")
    with pytest.raises(MaterializationError, match="version"):
        git_index_semantic_sha256(checksum(version))
    unknown = index_bytes[:-20] + b"XXXX" + (0).to_bytes(4, "big") + index_bytes[-20:]
    with pytest.raises(MaterializationError, match="unknown"):
        git_index_semantic_sha256(checksum(unknown))
    corrupt = bytearray(index_bytes)
    corrupt[-1] ^= 1
    with pytest.raises(MaterializationError, match="checksum"):
        git_index_semantic_sha256(corrupt)


def test_staged_index_change_fails_even_when_source_bytes_do_not_change(tmp_path):
    def stage(source):
        path = source / ".git" / "index"
        changed = bytearray(path.read_bytes())
        changed[12 + 40] ^= 1
        path.write_bytes(checksum(changed))
    _bundle, record = invoke(tmp_path, Offline(git=True, mutate=stage))
    assert record["history"] == "unexpected" and record["status"] == "failed"


def test_bare_repository_is_recorded_as_unexpected_history(tmp_path):
    def bare(source):
        git(source, "init", "--bare", "-q", "upstream.git")
    _bundle, record = invoke(tmp_path, Offline(mutate=bare))
    assert record["history"] == "unexpected" and record["status"] == "failed"


@pytest.mark.parametrize("version", [2, 3])
def test_bundle_magic_is_detected_without_relying_on_filename_suffix(tmp_path, version):
    def bundle(source):
        (source / "ordinary.data").write_bytes(f"# v{version} git bundle\n".encode() + b"history fixture\n")
    _bundle, record = invoke(tmp_path, Offline(mutate=bundle))
    assert record["history"] == "unexpected" and record["status"] == "failed"
