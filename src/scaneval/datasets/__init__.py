"""Built-in and installed dataset adapters, independent of scanner adapters."""
from importlib import import_module, metadata
from pathlib import Path

from ..contracts import ContractError
from .base import DatasetAdapter, NativeAdapter, read_json, summary, validate_dataset, write_json

BUILTINS = {"aacr-bench": "AacrBenchAdapter", "reviewbench": "ReviewBenchAdapter",
            "martian": "MartianAdapter", "openssf": "OpenSSFAdapter"}


def adapter_names() -> list[str]:
    return sorted({"native", *BUILTINS, *(p.name for p in metadata.entry_points(group="scaneval.datasets"))})


def get_adapter(name: str) -> DatasetAdapter:
    if name == "native":
        return NativeAdapter()
    if name in BUILTINS:
        return getattr(import_module("scaneval.datasets.builtin"), BUILTINS[name])()
    entries = [p for p in metadata.entry_points(group="scaneval.datasets") if p.name == name]
    if len(entries) != 1:
        raise ContractError(f"expected one installed dataset adapter named {name!r}; found {len(entries)}")
    adapter = entries[0].load()()
    if not isinstance(adapter, DatasetAdapter):
        raise ContractError(f"dataset adapter {name!r} must implement DatasetAdapter")
    return adapter


def import_dataset(name: str, source: Path) -> dict:
    return validate_dataset(get_adapter(name).load(source))


__all__ = ["DatasetAdapter", "adapter_names", "get_adapter", "import_dataset", "read_json",
           "summary", "validate_dataset", "write_json"]
