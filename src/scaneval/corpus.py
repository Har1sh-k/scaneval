"""ScanEval Corpus: case packs, pinned snapshots, mechanical checks, and admission.

This is the public entry point for corpus work. It re-exports the case-pack core rather
than wrapping it, so the behavior is exactly what :mod:`scaneval.cases` implements, and
adds the materialization helpers a pack needs to pin and export a snapshot.

Nothing here approves anything. Code can draft a case and run mechanical checks; only an
explicitly named human reviewer recorded through :func:`approve_case` can raise a case
beyond that, and no function infers approval from a passing check.
"""

from __future__ import annotations

from .cases import (
    PACK_KIND,
    accepted_paths_for_targets,
    add_case,
    add_snapshot,
    admit_case,
    alias_problem,
    approve_case,
    build_plan,
    case_by_id,
    cases_for_snapshot,
    control_paths,
    draft_case,
    draft_case_from_legacy,
    evidence,
    field_state,
    load_pack,
    mechanical_checks,
    new_pack,
    not_reviewed,
    pack_sha256,
    pack_summary,
    save_pack,
    set_disposition,
    snapshot_by_id,
)
from .materialize import (
    MaterializationError,
    export_snapshot,
    fetch_snapshot,
    hash_exported_tree,
    inspect_commit,
    tree_hash,
    write_provenance,
)

__all__ = [
    "PACK_KIND", "new_pack", "load_pack", "save_pack", "pack_sha256", "pack_summary",
    "add_snapshot", "snapshot_by_id", "add_case", "case_by_id", "cases_for_snapshot",
    "draft_case", "draft_case_from_legacy", "evidence", "field_state", "not_reviewed",
    "alias_problem", "mechanical_checks", "approve_case", "admit_case", "set_disposition",
    "build_plan", "accepted_paths_for_targets", "control_paths",
    "fetch_snapshot", "export_snapshot", "write_provenance", "hash_exported_tree",
    "tree_hash", "inspect_commit", "MaterializationError",
]
