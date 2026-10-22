"""Lossless, offline adapters for four pinned public benchmark releases."""
from __future__ import annotations

from copy import deepcopy
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import re
import shutil
from urllib.error import URLError
from urllib.request import Request, urlopen

from ..contracts import ContractError, canonical_sha256, refuse_trial_path
from .base import DatasetAdapter, read_json, relative_path, validate_dataset


def source_lock(name: str) -> dict:
    from . import BUILTINS
    if name not in BUILTINS:
        raise ContractError(f"{name!r} has no built-in source lock; supply its source directly")
    return json.loads(files("scaneval.datasets").joinpath(f"locks/{name}.json").read_text())


def _check_bytes(row: dict, data: bytes) -> None:
    if len(data) != row["bytes"] or "sha256:" + hashlib.sha256(data).hexdigest() != row["sha256"]:
        raise ContractError(f"source hash/size mismatch: {row['path']}")
    if "git_blob" in row:
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != row["git_blob"]:
            raise ContractError(f"source Git blob mismatch: {row['path']}")


def verify_source(name: str, source: Path) -> dict:
    lock = source_lock(name)
    root = source.resolve()
    for row in lock["files"]:
        path = source / relative_path(row["path"])
        if not path.resolve().is_relative_to(root) or not path.is_file():
            raise ContractError(f"source file missing or outside source directory: {row['path']}")
        _check_bytes(row, path.read_bytes())
    return lock


def fetch_source(name: str, output: Path) -> dict:
    """Fetch a locked data release, never execute upstream scripts or target code."""
    lock = source_lock(name)
    refuse_trial_path(output)
    output.mkdir(parents=True, exist_ok=False)
    try:
        for row in lock["files"]:
            path = output / relative_path(row["path"])
            expected = f"https://raw.githubusercontent.com/{lock['repository']}/{lock['revision']}/{row['path']}"
            if row["url"] != expected:
                raise ContractError(f"unversioned or unexpected source URL: {row['url']}")
            request = Request(expected, headers={"User-Agent": "ScanEval-dataset-adapter/1"})
            with urlopen(request, timeout=45) as response:
                data = response.read(row["bytes"] + 1)
            _check_bytes(row, data)
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as handle:
                handle.write(data)
    except Exception:
        # Only our newly created output is removed; a partial release is never usable.
        shutil.rmtree(output)
        raise
    return lock


def _document(name: str, lock: dict, tasks: list[dict]) -> dict:
    return validate_dataset({
        "schema_version": "1.0", "dataset_id": name, "mode": lock["mode"],
        "source": {"name": lock["repository"], "revision": lock["revision"],
                   "license": lock["license"], "source_lock_sha256": canonical_sha256(lock),
                   "adapter_version": "1.0", "label_authority": "upstream publisher",
                   "repository_url": f"https://github.com/{lock['repository']}"},
        "tasks": tasks,
    })


def _language(value: str) -> str:
    return {"C++": "cpp", "C#": "csharp"}.get(value, value.lower())


def _pr_task(url: str, base: str, head: str, language: str, metadata: dict, *, repo: str | None = None) -> dict:
    match = re.fullmatch(r"https://github.com/([^/]+)/([^/]+)/pull/([0-9]+)", url)
    if not match:
        raise ContractError(f"invalid PR URL: {url!r}")
    identity = "pr-" + canonical_sha256(url).split(":")[1][:24]
    return {"task_id": identity, "case_id": identity,
            "repository_url": repo or f"https://github.com/{match[1]}/{match[2]}",
            "commit": head, "base_commit": base, "variant": "pr", "languages": [_language(language)],
            "annotations": [], "metadata": {"pr_url": url, **metadata}}


def _annotation(index: int, text: str, label: str, category: str, severity: str,
                original: dict, *, path: str | None = None, start=None, end=None, side: str = "head") -> dict:
    metadata = {"original": original}
    locations = []
    if path:
        location = {"path": relative_path(path), "side": side}
        if start is not None or end is not None:
            if type(start) is int and type(end) is int and 1 <= start <= end:
                location.update(start_line=start, end_line=end)
            else:
                metadata["warnings"] = ["invalid upstream line range retained in original; no normalized line anchor"]
        locations.append(location)
    return {"annotation_id": f"a{index:05d}", "label": label, "text": text,
            "locations": locations, "category": category, "severity": severity.lower(), "metadata": metadata}


class AacrBenchAdapter(DatasetAdapter):
    name = "aacr-bench"

    def load(self, source: Path) -> dict:
        lock = verify_source(self.name, source)
        by_url = {}
        for filename, label in (("positive_samples.json", "positive"), ("negative_samples.json", "negative")):
            for row in read_json(source / "dataset" / filename):
                url = row["githubPrUrl"]
                metadata = {key: value for key, value in row.items() if key != "comments"}
                if url not in by_url:
                    by_url[url] = _pr_task(url, row["source_commit"], row["target_commit"],
                                          row["project_main_language"], {"original": metadata})
                task = by_url[url]
                if task["metadata"]["original"] != metadata:
                    raise ContractError(f"AACR positive/negative metadata disagree: {url}")
                for comment in row["comments"]:
                    if comment["side"] not in ("left", "right"):
                        raise ContractError(f"invalid AACR diff side: {comment['side']!r}")
                    task["annotations"].append(_annotation(
                        len(task["annotations"]) + 1, comment["note"], label, comment["category"], "unspecified",
                        comment, path=comment["path"], start=comment["from_line"], end=comment["to_line"],
                        side="base" if comment["side"] == "left" else "head"))
        return _document(self.name, lock, [by_url[url] for url in sorted(by_url)])


class ReviewBenchAdapter(DatasetAdapter):
    name = "reviewbench"

    def load(self, source: Path) -> dict:
        lock = verify_source(self.name, source)
        tasks = []
        for row in read_json(source / "corpus/manifest.json"):
            key = f"{row['nwo'].replace('/', '_')}_{row['pr_number']}-{row['head'][:8]}"
            golden = read_json(source / "golden" / f"{relative_path(key)}.json")
            expected = {k: row[k] for k in ("repo", "pr_number", "base", "head")}
            if golden["pr"] != expected or golden["pr_key"] != key:
                raise ContractError(f"ReviewBench manifest/golden identity mismatch: {key}")
            task = _pr_task(row["pr_url"], row["base"], row["head"], row["language"], {"original": row})
            task["mirror_urls"] = [f"https://github.com/review-bench/{row['nwo'].replace('/', '_')}"]
            for index, finding in enumerate(golden["findings"], 1):
                if finding["tp_fp"] not in ("tp", "fp"):
                    raise ContractError(f"unknown ReviewBench label: {finding['tp_fp']!r}")
                task["annotations"].append(_annotation(
                    index, finding["message"], "positive" if finding["tp_fp"] == "tp" else "negative",
                    finding["category"], finding["severity"], finding,
                    path=finding["file"], start=finding["start_line"], end=finding["end_line"]))
            tasks.append(task)
        return _document(self.name, lock, tasks)


class MartianAdapter(DatasetAdapter):
    name = "martian"

    def load(self, source: Path) -> dict:
        lock = verify_source(self.name, source)
        pins = {p["pr_url"]: p for p in lock["supplemental_pins"]["pull_requests"]}
        languages = {"cal_dot_com": "TypeScript", "discourse": "Ruby", "grafana": "Go",
                     "keycloak": "Java", "sentry": "Python"}
        tasks = []
        for name, language in languages.items():
            for row in read_json(source / f"offline/golden_comments/{name}.json"):
                pin = pins[row["url"]]
                task = _pr_task(row["url"], pin["base_commit"], pin["head_commit"], language,
                                {"original": {k: v for k, v in row.items() if k != "comments"},
                                 "commit_pin": pin}, repo=pin["base_repository_url"])
                for index, comment in enumerate(row["comments"], 1):
                    task["annotations"].append(_annotation(index, comment["comment"], "positive",
                                                           comment["category"], comment["severity"], comment))
                tasks.append(task)
        return _document(self.name, lock, tasks)


class OpenSSFAdapter(DatasetAdapter):
    name = "openssf"

    def load(self, source: Path) -> dict:
        lock = verify_source(self.name, source)
        pins = {p["cve"]: p for p in lock["supplemental_pins"]["commits"]}
        tasks = []
        for entry in lock["files"]:
            if not entry["path"].startswith("CVEs/") or not entry["path"].endswith(".json"):
                continue
            row = read_json(source / entry["path"])
            cve = row["CVE"]
            if row["state"] != "PUBLISHED" or not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                raise ContractError(f"unsupported OpenSSF CVE identity/state in {entry['path']}")
            weaknesses = row["prePatch"]["weaknesses"]
            locations = [{"path": relative_path(w["location"]["file"].removeprefix("/")), "side": "snapshot",
                          "start_line": w["location"]["line"], "end_line": w["location"]["line"]}
                         for w in weaknesses]
            language = "typescript" if any(loc["path"].endswith(".ts") for loc in locations) else "javascript"
            text = cve + ": " + "; ".join(dict.fromkeys(w["explanation"] for w in weaknesses))
            for variant, field, label in (("vulnerable", "prePatch", "positive"),
                                           ("fixed", "postPatch", "fixed-control")):
                commit = row[field]["commit"]
                pin = pins.get(cve) if variant == "fixed" else None
                if pin:
                    if pin["original_commit"] != commit or not pin["commit"].startswith(commit):
                        raise ContractError(f"OpenSSF supplemental commit pin contradicts {cve}")
                    commit = pin["commit"]
                annotation = _annotation(1, text, label, "security", "unspecified", row)
                if any(w["location"]["file"].startswith("/") for w in weaknesses):
                    annotation["metadata"]["warnings"] = [
                        "upstream repository-root slash removed from location; original path retained"]
                # A pre-patch line number does not identify a line after the patch.
                annotation["locations"] = deepcopy(locations) if variant == "vulnerable" else []
                tasks.append({"task_id": f"{cve}-{variant}", "case_id": cve,
                              "repository_url": row["repository"], "commit": commit, "variant": variant,
                              "languages": [language], "annotations": [annotation],
                              "metadata": {"cve": cve, "cwes": row["CWEs"], "original": row,
                                           "language_basis": "upstream JS/TS corpus; annotated file extension",
                                           **({"commit_pin": pin} if pin else {})}})
        return _document(self.name, lock, tasks)
