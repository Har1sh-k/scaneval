"""Adapter registry. Adapters are looked up by name and constructed without arguments."""

from __future__ import annotations

from importlib import import_module

from .base import Adapter, AdapterError, NativeOutcome, SystemSpec

_REGISTRY = {
    "semgrep": ("scaneval.adapters.semgrep", "SemgrepAdapter"),
    "llm-harness": ("scaneval.adapters.llm_harness", "LlmHarnessAdapter"),
    "deepsec": ("scaneval.adapters.deepsec", "DeepsecAdapter"),
}


def adapter_names() -> list[str]:
    return sorted(_REGISTRY)


def get_adapter(name: str) -> Adapter:
    try:
        module_name, class_name = _REGISTRY[name]
    except KeyError as exc:
        raise AdapterError(f"unknown adapter {name!r}; expected one of {adapter_names()}") from exc
    module = import_module(module_name)
    return getattr(module, class_name)()


__all__ = ["Adapter", "AdapterError", "NativeOutcome", "SystemSpec", "adapter_names", "get_adapter"]
