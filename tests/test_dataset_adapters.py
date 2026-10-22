from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from io import BytesIO
import tomllib

import pytest

from scaneval import datasets
from scaneval.cli import main
from scaneval.contracts import ContractError
from scaneval.datasets import builtin
from scaneval.datasets.base import DatasetAdapter, validate_dataset


@pytest.fixture
def native():
    return {"schema_version": "1.0", "dataset_id": "example", "mode": "pr-review",
            "source": {"name": "local labels", "revision": "v1", "license": "MIT"},
            "tasks": [{"task_id": "change-1", "case_id": "case-1", "repository_url": "https://example.org/repo",
                       "commit": "b" * 40, "base_commit": "a" * 40, "variant": "pr", "languages": ["cpp"],
                       "annotations": [{"annotation_id": "issue-1", "label": "positive", "text": "An issue",
                                        "locations": [{"path": "src/a.cpp", "start_line": 2, "end_line": 2}],
                                        "category": "correctness", "severity": "high"}]}]}


def release(tmp_path, monkeypatch, name, sources, **extra):
    lock = {"dataset_id": name, "repository": "owner/repo", "revision": "e" * 40, "license": "MIT",
            "mode": "cve-detection" if name == "openssf" else "pr-review", "files": [], **extra}
    for path, value in sources.items():
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(value).encode()
        target.write_bytes(data)
        lock["files"].append({"path": path, "bytes": len(data), "sha256": "sha256:" + hashlib.sha256(data).hexdigest()})
    monkeypatch.setattr(builtin, "source_lock", lambda _: lock)
    return tmp_path


def test_aacr_preserves_negative_and_flags_bad_span(tmp_path, monkeypatch):
    row = {"githubPrUrl": "https://github.com/owner/repo/pull/1", "source_commit": "a" * 40,
           "target_commit": "b" * 40, "project_main_language": "Python", "category": "fix",
           "comments": [{"note": "issue", "path": "a.py", "from_line": 7, "to_line": 2,
                         "side": "left", "category": "Code Defect"}]}
    negative = deepcopy(row)
    negative["comments"][0].update(note="rejected allegation", from_line=1, to_line=2)
    root = release(tmp_path, monkeypatch, "aacr-bench", {
        "dataset/positive_samples.json": [row], "dataset/negative_samples.json": [negative]})
    document = datasets.import_dataset("aacr-bench", root)
    assert len(document["tasks"]) == 1
    annotations = document["tasks"][0]["annotations"]
    assert [a["label"] for a in annotations] == ["positive", "negative"]
    assert annotations[0]["locations"] == [{"path": "a.py", "side": "base"}]
    assert annotations[0]["metadata"]["original"]["from_line"] == 7
    assert annotations[0]["metadata"]["warnings"]
    assert datasets.summary(document)["annotations"] == {"negative": 1, "positive": 1}


def test_aacr_rejects_disagreeing_pr_identity(tmp_path, monkeypatch):
    row = {"githubPrUrl": "https://github.com/owner/repo/pull/1", "source_commit": "a" * 40,
           "target_commit": "b" * 40, "project_main_language": "Python", "comments": []}
    negative = {**row, "target_commit": "c" * 40}
    root = release(tmp_path, monkeypatch, "aacr-bench", {
        "dataset/positive_samples.json": [row], "dataset/negative_samples.json": [negative]})
    with pytest.raises(ContractError, match="disagree"):
        datasets.import_dataset("aacr-bench", root)


def test_reviewbench_keeps_rejected_labels_scope_and_producer(tmp_path, monkeypatch):
    row = {"repo": "https://github.com/owner/repo", "pr_number": 1, "base": "a" * 40, "head": "b" * 40,
           "nwo": "owner/repo", "language": "C#", "pr_url": "https://github.com/owner/repo/pull/1"}
    key = "owner_repo_1-bbbbbbbb"
    finding = {"file": "a.cs", "start_line": 3, "end_line": 3, "message": "rejected",
               "tp_fp": "fp", "severity": "low", "category": "security", "scope": "pre-existing",
               "producer": "external-reviewer"}
    root = release(tmp_path, monkeypatch, "reviewbench", {"corpus/manifest.json": [row],
        f"golden/{key}.json": {"pr_key": key, "pr": {k: row[k] for k in ("repo", "pr_number", "base", "head")},
                             "findings": [finding]}})
    task = datasets.import_dataset("reviewbench", root)["tasks"][0]
    assert task["languages"] == ["csharp"]
    assert task["mirror_urls"] == ["https://github.com/review-bench/owner_repo"]
    assert task["annotations"][0]["label"] == "negative"
    assert task["annotations"][0]["metadata"]["original"] == finding


def test_martian_uses_frozen_pins_and_preserves_unknown_locations(tmp_path, monkeypatch):
    url = "https://github.com/owner/repo/pull/2"
    sources = {f"offline/golden_comments/{name}.json": [] for name in
               ("cal_dot_com", "discourse", "grafana", "keycloak", "sentry")}
    sources["offline/golden_comments/sentry.json"] = [{"url": url, "pr_title": "change", "comments": [
        {"comment": "issue", "severity": "Critical", "category": "bug"}]}]
    root = release(tmp_path, monkeypatch, "martian", sources, supplemental_pins={"pull_requests": [
        {"pr_url": url, "base_commit": "a" * 40, "head_commit": "b" * 40,
         "base_repository_url": "https://github.com/owner/moved"}]})
    task = datasets.import_dataset("martian", root)["tasks"][0]
    assert task["repository_url"] == "https://github.com/owner/moved"
    assert task["annotations"][0]["locations"] == []
    assert task["annotations"][0]["severity"] == "critical"


def test_openssf_pairs_named_cve_and_expands_only_recorded_pin(tmp_path, monkeypatch):
    cve = "CVE-2020-12345"
    row = {"CVE": cve, "state": "PUBLISHED", "repository": "https://github.com/owner/repo",
           "prePatch": {"commit": "a" * 40, "weaknesses": [
               {"location": {"file": "/index.js", "line": 2}, "explanation": "unsafe path"}]},
           "postPatch": {"commit": "bbbbbbb"}, "CWEs": ["CWE-22"]}
    root = release(tmp_path, monkeypatch, "openssf", {f"CVEs/{cve}.json": row},
                   supplemental_pins={"commits": [{"cve": cve, "original_commit": "bbbbbbb", "commit": "b" * 40}]})
    document = datasets.import_dataset("openssf", root)
    vulnerable, fixed = document["tasks"]
    assert vulnerable["annotations"][0]["locations"][0]["path"] == "index.js"
    assert fixed["commit"] == "b" * 40
    assert fixed["annotations"][0]["label"] == "fixed-control"
    assert fixed["annotations"][0]["locations"] == []
    assert fixed["annotations"][0]["metadata"]["original"] == row
    assert datasets.summary(document)["cves"] == 1


@pytest.mark.parametrize("path", ["../a.py", "/tmp/a.py", "a/../../x", "a\\x", "C:/a.py", "./a.py"])
def test_native_rejects_escaping_locations(native, path):
    native["tasks"][0]["annotations"][0]["locations"][0]["path"] = path
    with pytest.raises(ContractError, match="relative POSIX"):
        validate_dataset(native)


@pytest.mark.parametrize("mutation", [
    lambda d: d["tasks"].append(deepcopy(d["tasks"][0])),
    lambda d: d["tasks"][0].update(commit="main"),
    lambda d: d["tasks"][0].update(commit="a" * 40),
    lambda d: d["tasks"][0].update(repository_url="https://user:secret@example.org/repo"),
    lambda d: d["tasks"][0]["annotations"][0].update(label="fixed-control"),
    lambda d: d["tasks"][0]["annotations"][0]["locations"][0].update(end_line=1),
    lambda d: d["tasks"][0]["annotations"].append(deepcopy(d["tasks"][0]["annotations"][0])),
])
def test_native_rejects_unusable_or_ambiguous_data(native, mutation):
    mutation(native)
    with pytest.raises(ContractError):
        validate_dataset(native)


def test_native_refuses_case_collisions_before_creating_task_directories(native):
    first = native["tasks"][0]
    native["tasks"].append({**deepcopy(first), "task_id": first["task_id"].upper()})
    with pytest.raises(ContractError, match="case-insensitive"):
        validate_dataset(native)


@pytest.mark.parametrize("location", [
    ("dataset_id",), ("tasks", 0, "task_id"), ("tasks", 0, "case_id"),
    ("tasks", 0, "commit"), ("tasks", 0, "base_commit"),
    ("tasks", 0, "annotations", 0, "annotation_id"),
])
def test_native_refuses_trailing_newline_in_ids_and_commits(native, location):
    parent = native
    for key in location[:-1]:
        parent = parent[key]
    parent[location[-1]] += "\n"
    with pytest.raises(ContractError, match="does not match"):
        validate_dataset(native)


def test_source_hash_mismatch_is_not_a_new_dataset(tmp_path, monkeypatch):
    release(tmp_path, monkeypatch, "aacr-bench", {"file.json": {"data": "original"}})
    (tmp_path / "file.json").write_text('{"data":"changed"}')
    with pytest.raises(ContractError, match="mismatch"):
        builtin.verify_source("aacr-bench", tmp_path)


def test_dataset_plugin_needs_no_core_edit(native, tmp_path, monkeypatch):
    class Example(DatasetAdapter):
        name = "company"
        def load(self, source):
            assert source == tmp_path
            return deepcopy(native)
    entry = SimpleNamespace(name="company", load=lambda: Example)
    monkeypatch.setattr(datasets.metadata, "entry_points", lambda **_: [entry])
    assert "company" in datasets.adapter_names()
    assert datasets.import_dataset("company", tmp_path) == native


def test_plugin_cannot_bypass_common_validation(native, tmp_path, monkeypatch):
    class Broken(DatasetAdapter):
        name = "broken"
        def load(self, source):
            return {**native, "tasks": []}
    monkeypatch.setattr(datasets.metadata, "entry_points", lambda **_: [SimpleNamespace(name="broken", load=lambda: Broken)])
    with pytest.raises(ContractError):
        datasets.import_dataset("broken", tmp_path)


def test_cli_native_roundtrip_and_no_overwrite(native, tmp_path, capsys):
    source, target = tmp_path / "input.json", tmp_path / "dataset.json"
    source.write_text(json.dumps(native))
    args = ["dataset", "import", "--adapter", "native", "--source", str(source), "--output", str(target)]
    assert main(args) == 0
    assert main(["dataset", "validate", str(target)]) == 0
    assert main(args) == 2
    assert json.loads(target.read_text()) == native


def test_native_duplicate_json_keys_refused(tmp_path):
    source = tmp_path / "input.json"
    source.write_text('{"dataset_id":"one","dataset_id":"two"}')
    with pytest.raises(ContractError, match="duplicate JSON key"):
        datasets.import_dataset("native", source)


def test_cli_does_not_write_labels_into_trial(native, tmp_path):
    (tmp_path / "provenance.json").write_text('{}')
    (tmp_path / "source").mkdir()
    with pytest.raises(ContractError, match="inside the trial"):
        datasets.write_json(tmp_path / "source/dataset.json", native)


def test_fetch_checks_locked_bytes_and_never_overwrites(tmp_path, monkeypatch):
    data = b'{"pinned":true}'
    lock = {"repository": "owner/repo", "revision": "a" * 40, "files": [
        {"path": "dataset.json", "url": "https://raw.githubusercontent.com/owner/repo/" + "a" * 40 + "/dataset.json",
         "bytes": len(data), "sha256": "sha256:" + hashlib.sha256(data).hexdigest()}]}
    monkeypatch.setattr(builtin, "source_lock", lambda _: lock)
    monkeypatch.setattr(builtin, "urlopen", lambda *a, **kw: BytesIO(data))
    output = tmp_path / "release"
    builtin.fetch_source("example", output)
    assert (output / "dataset.json").read_bytes() == data
    with pytest.raises(FileExistsError):
        builtin.fetch_source("example", output)
    monkeypatch.setattr(builtin, "urlopen", lambda *a, **kw: BytesIO(b"wrong"))
    bad = tmp_path / "bad"
    with pytest.raises(ContractError, match="mismatch"):
        builtin.fetch_source("example", bad)
    assert not bad.exists()


def test_installable_example_registers_and_imports_jsonl(native, tmp_path, monkeypatch):
    example = Path(__file__).resolve().parents[1] / "examples/dataset_plugin"
    project = tomllib.loads((example / "pyproject.toml").read_text())["project"]
    entrypoints = project["entry-points"]["scaneval.datasets"]
    distribution = tmp_path / "scaneval_example_dataset-0.1.0.dist-info"
    distribution.mkdir()
    (distribution / "METADATA").write_text("Metadata-Version: 2.1\nName: scaneval-example-dataset\nVersion: 0.1.0\n")
    (distribution / "entry_points.txt").write_text("[scaneval.datasets]\n" + "\n".join(
        f"{name} = {target}" for name, target in entrypoints.items()) + "\n")
    monkeypatch.syspath_prepend(str(example))
    monkeypatch.syspath_prepend(str(tmp_path))
    source = tmp_path / "source"
    source.mkdir()
    (source / "dataset.json").write_text(json.dumps({k: v for k, v in native.items() if k != "tasks"}))
    (source / "tasks.jsonl").write_text("\n".join(json.dumps(t) for t in native["tasks"]) + "\n")
    assert "example-jsonl" in datasets.adapter_names()
    assert datasets.import_dataset("example-jsonl", source) == native
