"""An installable adapter example: header JSON plus one common-format task per line."""
import json
from pathlib import Path

from scaneval.contracts import ContractError
from scaneval.datasets import DatasetAdapter, read_json


class JsonlDataset(DatasetAdapter):
    name = "example-jsonl"

    def load(self, source: Path) -> dict:
        header = read_json(source / "dataset.json")
        if not isinstance(header, dict) or "tasks" in header:
            raise ContractError("dataset.json must contain header fields only; put tasks in tasks.jsonl")
        tasks = []
        for number, line in enumerate((source / "tasks.jsonl").read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                tasks.append(json.loads(line))
            except ValueError as exc:
                raise ContractError(f"tasks.jsonl line {number}: {exc}") from exc
        # The public registry validates the complete output after this method returns.
        return {**header, "tasks": tasks}
