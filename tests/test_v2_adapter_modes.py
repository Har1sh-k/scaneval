"""The scan modes an adapter implements, and how a PR request is read.

Nothing here starts a scanner. The git the workspace tests use is a scratch repository built
with a neutral identity, the same shape as the two-commit history the runner builds for a PR
input: a base commit, a head commit, ``HEAD`` at head, and a clean status.
"""

from __future__ import annotations

from scaneval.adapters.base import Adapter, NativeOutcome


class BareAdapter(Adapter):
    """An adapter that declares nothing beyond what the protocol requires."""

    name = "bare"

    def scan(self, *, request, source_dir, raw_dir, spec, preparation, timeout_seconds, trace_mode, trace_dir):
        return NativeOutcome(status="success", exit_code=0, command=[])


def test_an_adapter_that_declares_no_modes_implements_full_scans_only():
    """A PR request must never reach an adapter that did not say it reads one.

    The default is the whole reason the runner can refuse a PR input for an adapter that never
    heard of the mode, instead of handing it a request whose ``pr`` it would ignore.
    """
    assert BareAdapter.scan_modes == frozenset({"full"})
    assert BareAdapter().scan_modes == frozenset({"full"})
    assert isinstance(Adapter.scan_modes, frozenset)
