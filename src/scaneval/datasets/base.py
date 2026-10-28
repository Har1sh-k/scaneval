"""The dataset boundary: adapter output is data, never an executable evaluator.

Dataset adapters only translate annotations. They do not run repository code, choose
scanner settings, infer new labels, or certify their publishers' judgments.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from importlib.resources import files
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator

from ..contracts import ContractError, canonical_sha256, refuse_trial_path


def read_json(path: Path):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ContractError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ContractError(f"invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, value: dict) -> None:
    refuse_trial_path(path)
    data = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    with path.open("xb") as handle:
        handle.write(data)


def relative_path(value: str) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or value.startswith("/") or re.match(r"^[A-Za-z]:", value)
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ContractError(f"expected a relative POSIX file path, got {value!r}")
    return value


def repository_url(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or not parsed.path.strip("/")
            or any(part == ".." for part in parsed.path.split("/"))):
        raise ContractError(f"repository URL must be an HTTPS URL without credentials: {value!r}")
    return value


def validate_dataset(document: dict) -> dict:
    schema = json.loads(files("scaneval").joinpath("schemas/dataset.schema.json").read_text())
    errors = sorted(Draft202012Validator(schema).iter_errors(document), key=lambda e: str(list(e.path)))
    if errors:
        error = errors[0]
        raise ContractError(f"dataset {'.'.join(map(str, error.path))}: {error.message}")
    seen = set()
    for task in document["tasks"]:
        identifier = task["task_id"]
        if identifier.casefold() in seen:
            raise ContractError(f"duplicate task_id on a case-insensitive filesystem: {identifier}")
        seen.add(identifier.casefold())
        repository_url(task["repository_url"])
        for url in task.get("mirror_urls", []):
            repository_url(url)
        if document["mode"] == "pr-review":
            if task["variant"] != "pr" or "base_commit" not in task or task["commit"] == task["base_commit"]:
                raise ContractError(f"PR task {identifier} needs different pinned base and head commits")
        elif task["variant"] == "pr" or "base_commit" in task:
            raise ContractError(f"CVE task {identifier} must be a vulnerable or fixed snapshot")
        annotations = set()
        for annotation in task["annotations"]:
            aid = annotation["annotation_id"]
            if aid in annotations:
                raise ContractError(f"duplicate annotation_id {aid} in {identifier}")
            annotations.add(aid)
            if not annotation["text"].strip():
                raise ContractError(f"blank annotation text: {identifier}/{aid}")
            if annotation["label"] == "fixed-control" and task["variant"] != "fixed":
                raise ContractError("fixed-control annotations require a fixed snapshot")
            if task["variant"] == "fixed" and annotation["label"] != "fixed-control":
                raise ContractError("fixed snapshots contain only named fixed-control annotations")
            for location in annotation["locations"]:
                relative_path(location["path"])
                if ("end_line" in location and ("start_line" not in location
                        or location["end_line"] < location["start_line"])):
                    raise ContractError(f"invalid annotation line range: {identifier}/{aid}")
    canonical_sha256(document)  # finite, encodable JSON, including free-form metadata
    return document


def summary(document: dict) -> dict:
    validate_dataset(document)
    tasks = document["tasks"]
    annotations = [a for t in tasks for a in t["annotations"]]
    positive = [a for a in annotations if a["label"] == "positive"]
    return {
        "dataset_id": document["dataset_id"], "mode": document["mode"],
        "dataset_sha256": canonical_sha256(document), "source": document["source"],
        "cases": len({t["case_id"] for t in tasks}), "tasks": len(tasks),
        "cves": len({t["case_id"] for t in tasks if re.fullmatch(r"CVE-\d{4}-\d{4,}", t["case_id"])}),
        "repositories": len({t["repository_url"].removesuffix(".git") for t in tasks}),
        "languages": sorted({lang for t in tasks for lang in t["languages"]}),
        "annotations": dict(sorted(Counter(a["label"] for a in annotations).items())),
        "positive_severity": dict(sorted(Counter(a["severity"] for a in positive).items())),
        "positive_categories": dict(sorted(Counter(a["category"] for a in positive).items())),
        "annotation_warnings": sum(bool(a.get("metadata", {}).get("warnings")) for a in annotations),
        "source_code_materialized": False,
        "label_authority": "publisher-supplied; importing does not independently validate labels",
    }


class DatasetAdapter(ABC):
    """Implement ``load(Path) -> dict`` and register in ``scaneval.datasets``.

    ``load`` should be deterministic and offline. Network acquisition belongs in
    the caller's preparation step. Every output passes the same common contract.
    """
    name: str

    @abstractmethod
    def load(self, source: Path) -> dict:
        raise NotImplementedError


class NativeAdapter(DatasetAdapter):
    name = "native"

    def load(self, source: Path) -> dict:
        return validate_dataset(read_json(source))
