#!/usr/bin/env python3
"""Bounded generated conformance for the SV review-workflow completion boundary.

This calls the production ``read_review_workflow`` and ``read_completion`` entrypoints for every
case.  Its oracle is intentionally stated over abstract inventories, obligation/receipt
multisets, terminal pairs, and health flags rather than production parser predicates.
"""

from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
import hashlib
from itertools import product
import json
from pathlib import Path
import subprocess
from typing import Callable, Iterable

from scaneval.adapters.llm_harness import read_completion, read_review_workflow


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/sv-review-workflow-summary.json"
ADAPTER = ROOT / "src/scaneval/adapters/llm_harness.py"
DESIGN = ROOT / "docs/designs/sv-completion-bounded-verification.md"
SOURCE_REF = "a" * 40
PROCEDURES = ("security-review", "category:configuration")
HEALTH_NAMES = ("model", "delivery", "lint", "markers", "specialists")
STAGE_NAMES = ("modelCalls", "structural", "lint", "markers", "specialists")
ALLOWED_REASONS = frozenset({"source_analysis_completion_not_established", "structural_coverage_not_recorded"})


@dataclass(frozen=True)
class FileState:
    index: int
    disposition: str = "supported"
    procedure_count: int = 1

    @property
    def path(self) -> str:
        if self.disposition == "excluded":
            return f"README{self.index + 1}.md"
        prefix = "config" if self.procedure_count == 2 else "src"
        return f"{prefix}/file{self.index + 1}.ts"

    @property
    def procedures(self) -> tuple[str, ...]:
        return PROCEDURES[: self.procedure_count] if self.disposition in ("supported", "unassigned") else ()

    @property
    def source_capable(self) -> bool:
        return self.disposition in ("supported", "unassigned")


@dataclass(frozen=True)
class ObligationState:
    index: int
    files: tuple[int, ...]


@dataclass(frozen=True)
class ReceiptState:
    obligation: int
    copy: int = 0
    binding: str = "exact"
    terminals: tuple[tuple[int, str, str], ...] = ()  # file index, procedure, status


@dataclass(frozen=True)
class CompletionState:
    mode: str = "workflow"
    call_health: str = "healthy"
    reasons: tuple[str, ...] = (
        "structural_coverage_not_recorded",
        "source_analysis_completion_not_established",
    )
    source_delivery: str = "analysis"
    structural: str = "not-recorded"


@dataclass(frozen=True)
class AbstractState:
    status: str
    files: tuple[FileState, ...]
    obligations: tuple[ObligationState, ...]
    receipts: tuple[ReceiptState, ...]
    stages: tuple[bool, ...] = (True, True, True, True, True)
    native_health: tuple[bool, ...] = (True, True, True, True, True)
    completion: CompletionState = CompletionState()
    finding_count: int = 0
    well_formed: bool = True


@dataclass
class Case:
    name: str
    family: str
    state: AbstractState
    tags: set[str] = field(default_factory=set)
    mutate: Callable[[dict], None] | None = None


@dataclass(frozen=True)
class Decision:
    accepted: bool
    workflow_status: str | None
    workflow_code: str | None
    completion_code: str | None


def _identity(index: int) -> dict:
    return {
        "invocationId": f"invocation-{index + 1}",
        "model": "openai-codex/gpt-5.6-sol",
        "hypothesisId": f"TM-{index + 1:03d}",
        "shardIndex": 1,
        "sourceRef": SOURCE_REF,
        "requestDigest": f"{(index + 4) % 10}" * 64,
    }


def _file_wire(file: FileState) -> dict:
    return {
        "path": file.path,
        "sha256": chr(ord("c") + file.index) * 64,
        "bytes": 40 + file.index,
        "requiredProcedures": list(file.procedures),
    }


def _inventory_wire(file: FileState) -> dict:
    source = _file_wire(file)
    if not file.source_capable:
        source.update(sha256=None, bytes=None, requiredProcedures=[])
    return {
        "path": file.path,
        "sourceRef": SOURCE_REF,
        "objectId": str(file.index + 1) * 40,
        "sha256": source["sha256"],
        "bytes": source["bytes"],
        "disposition": file.disposition,
        "reason": {
            "supported": "supported-code-extension",
            "unassigned": "eligible-source-not-assigned",
            "unsupported": "unsupported-bootstrap-source:extension",
            "excluded": "known-non-code-filename",
        }[file.disposition],
        "requiredProcedures": source["requiredProcedures"],
    }


def _terminals_for(obligation: ObligationState, files: tuple[FileState, ...], status: str = "completed") -> tuple[tuple[int, str, str], ...]:
    return tuple((file_index, procedure, status)
                 for file_index in obligation.files for procedure in files[file_index].procedures)


def _receipt_wire(receipt: ReceiptState, obligations: tuple[ObligationState, ...], files: tuple[FileState, ...]) -> dict:
    obligation = obligations[receipt.obligation]
    wire = {
        "schemaVersion": 1,
        **_identity(obligation.index),
        "responseDigest": f"{(obligation.index + 7) % 10}" * 64,
        "files": [],
    }
    terminals = {(file_index, procedure): status for file_index, procedure, status in receipt.terminals}
    for file_index in obligation.files:
        file_wire = _file_wire(files[file_index])
        file_wire["terminals"] = [
            {"procedure": procedure, "status": terminals[(file_index, procedure)],
             "reason": "Reviewed the complete pinned source for the required procedure."}
            for procedure in files[file_index].procedures if (file_index, procedure) in terminals
        ]
        wire["files"].append(file_wire)
    swaps = {
        "invocation": lambda: wire.update(invocationId="invocation-swapped"),
        "model": lambda: wire.update(model="other/model"),
        "hypothesis": lambda: wire.update(hypothesisId="TM-SWAPPED"),
        "shard": lambda: wire.update(shardIndex=2),
        "source": lambda: wire.update(sourceRef="b" * 40),
        "request": lambda: wire.update(requestDigest="0" * 64),
        "file": lambda: wire["files"][0].update(sha256="0" * 64),
    }
    if receipt.binding != "exact":
        swaps[receipt.binding]()
    return wire


def _scope(total: int, source_count: int, unsupported_count: int = 0, excluded_count: int = 0) -> dict:
    return {
        "totalChangedFiles": total,
        "changedFilesInScope": source_count,
        "unsupportedChangedFiles": unsupported_count,
        "excludedChangedFiles": excluded_count,
        "knownNonCodeChangedFiles": excluded_count,
        "unknownUnsupportedChangedFiles": unsupported_count,
        "unsupportedExtensionHistogram": {},
    }


def materialize(state: AbstractState) -> dict:
    """Turn an abstract state into native JSON without consulting production validators."""
    summary = json.loads(FIXTURE.read_text(encoding="utf-8"))
    report = summary["reviewWorkflow"]
    report.update(status=state.status, reasons=[])
    report["inventory"] = [_inventory_wire(file) for file in state.files]
    report["obligations"] = []
    for obligation in state.obligations:
        report["obligations"].append({
            **_identity(obligation.index),
            "files": [_file_wire(state.files[index]) for index in obligation.files],
        })
    report["receipts"] = [_receipt_wire(receipt, state.obligations, state.files) for receipt in state.receipts]
    healthy_stages = {
        "modelCalls": "complete", "structural": "not-applicable", "lint": "complete",
        "markers": "complete", "specialists": "complete",
    }
    failing_stages = {
        "modelCalls": "incomplete", "structural": "incomplete", "lint": "incomplete",
        "markers": "incomplete", "specialists": "incomplete",
    }
    report["stages"] = {name: healthy_stages[name] if state.stages[index] else failing_stages[name]
                        for index, name in enumerate(STAGE_NAMES)}

    selections = []
    for obligation in state.obligations:
        identity = _identity(obligation.index)
        paths = [state.files[index].path for index in obligation.files]
        delivered = list(paths)
        omitted: list[dict] = []
        if not state.native_health[1] and obligation.index == state.obligations[0].index:
            delivered = []
            omitted = [{"path": path, "reason": "budget"} for path in paths]
        selections.append({
            "model": identity["model"], "hypothesisId": identity["hypothesisId"],
            "vulnerabilityClass": "inputvalidation", "priority": "high",
            "filesConsidered": len(paths), "selectedFiles": paths, "validatedFiles": delivered,
            "relationshipExtractionFailures": [], "relationshipExtractionFailuresTruncated": 0,
            "fileCoverage": {
                "hypothesisId": identity["hypothesisId"], "assignedFiles": paths,
                "requestedFiles": paths, "deliveredFiles": delivered, "partialFiles": [],
                "omittedAssignedFiles": omitted, "coverage": "complete" if not omitted else "incomplete",
                "fileOutcomes": [{"path": path, "outcome": "unassessed",
                                  "reason": "analysis_completion_not_established"} for path in paths],
                "calls": [{"shardIndex": identity["shardIndex"], "requestedFiles": paths,
                           "deliveredFiles": delivered, "partialFiles": [], "omittedFiles": omitted,
                           "transport": "succeeded"}],
            },
        })
    scan = summary["bootstrapScan"]
    count = len(selections)
    scan.update(
        status="ok" if state.native_health[0] else "inconclusive",
        reasons=[] if state.native_health[0] else ["model_invocations_failed"],
        llmCalls=count, failedCalls=0 if state.native_health[0] else 1,
        quotaFailureCount=0, hypothesesPlanned=count, hypothesesAttempted=count,
        hypothesesEvaluated=count if state.native_health[0] else max(0, count - 1),
        hypothesisCoverage=1 if state.native_health[0] else 0,
        evaluatedHypothesisIds=[item["hypothesisId"] for item in selections] if state.native_health[0] else [],
        failedHypothesisIds=[] if state.native_health[0] else ([selections[0]["hypothesisId"]] if selections else ["TM-FAILED"]),
        unevaluatedHypothesisIds=[], focusedFiles=sum(len(item["selectedFiles"]) for item in selections),
        actualLlmFilesScanned=sum(len(item["validatedFiles"]) for item in selections),
        hypothesisSelections=selections,
    )
    summary["repositoryLint"] = {"status": "ok", "failures": 0, "failureSamples": []}
    if not state.native_health[2]:
        summary["repositoryLint"] = {"status": "inconclusive", "failures": 1, "failureSamples": ["lint failed"]}
    summary["repositoryLintRules"] = []
    summary["reviewAssessment"] = {
        "scope": "marker-reviews", "status": "none-pending", "pendingReviews": 0,
        "pendingSites": 0, "pendingInspectionGaps": 0, "carriedForwardReviews": 0,
        "ledgerPath": ".securevibes/review-ledger.json",
    }
    if not state.native_health[3]:
        summary["reviewAssessment"].update(status="pending", pendingReviews=1, pendingSites=1)
    summary["specialistsActivated"] = []
    summary["specialistScans"] = []
    if not state.native_health[4]:
        summary["specialistsActivated"] = [{"id": "auth", "workflowHint": "auth"}]
        summary["specialistScans"] = [{
            "id": "auth", "status": "inconclusive", "assessmentStatus": "not-assessed",
            "failedCalls": 1, "quotaFailureCount": 0,
        }]

    completion = summary["completion"]
    supported = [file for file in state.files if file.disposition == "supported"]
    completion["sourceAssessment"] = {
        "status": "unassessed",
        "files": [{"path": file.path, "outcome": "unassessed",
                   "reason": "analysis_completion_not_established" if state.completion.source_delivery == "analysis"
                             else "not_fully_delivered"} for file in supported],
    }
    completion["structuralCoverage"]["status"] = state.completion.structural
    completion["coverage"] = {"status": "unknown", "reasons": list(state.completion.reasons)}
    completion["hypothesisEvaluation"].update(
        status="complete", planned=len(state.obligations), evaluated=len(state.obligations),
        failedIds=[], unevaluatedIds=[])
    calls = completion["modelCalls"]
    if state.completion.call_health == "healthy":
        calls.update(status="no-recorded-failures", attempted=max(1, len(state.obligations)),
                     succeeded=max(1, len(state.obligations)), failed=0, pending=0,
                     failureSamples=[], truncatedFailureSamples=0)
    elif state.completion.call_health == "failed":
        calls.update(status="failures-recorded", attempted=1, succeeded=0, failed=1, pending=0,
                     failureSamples=[{"callId": 1, "phase": "hypothesis-validation",
                                      "kind": "nonzero-exit", "code": 1}], truncatedFailureSamples=0)
    else:
        calls.update(status="no-recorded-failures", attempted=1, succeeded=0, failed=0, pending=1,
                     failureSamples=[], truncatedFailureSamples=0)

    if state.completion.mode == "not-required":
        completion["modelCalls"].update(status="not-run", attempted=0, succeeded=0, failed=0, pending=0,
                                        failureSamples=[], truncatedFailureSamples=0)
        completion["changedFileSupport"] = {
            "status": "not-required",
            "scope": _scope(len(state.files), 0, excluded_count=len(state.files)),
        }
        completion["hypothesisEvaluation"].update(status="not-required", planned=0, evaluated=0,
                                                   failedIds=[], unevaluatedIds=[])
        completion["sourceAssessment"] = {"status": "not-required", "files": []}
        completion["coverage"] = {"status": "not-required", "reasons": []}
    summary["newFindings"] = [
        {"id": f"SV-GENERATED-{index + 1}", "cweIds": ["CWE-20"]}
        for index in range(state.finding_count)
    ]
    return summary


def oracle(state: AbstractState) -> bool:
    """Independent finite acceptance property over abstract sets and multisets."""
    if not state.well_formed or not state.files or state.status not in ("complete", "not-required"):
        return False
    if state.status == "not-required":
        return (all(file.disposition == "excluded" for file in state.files)
                and not state.obligations and not state.receipts
                and state.completion.mode == "not-required")
    if (any(file.disposition != "supported" for file in state.files)
            or not all(state.stages) or not all(state.native_health)):
        return False
    obligation_indices = [obligation.index for obligation in state.obligations]
    if len(obligation_indices) != len(set(obligation_indices)):
        return False
    assigned = Counter()
    for obligation in state.obligations:
        if not obligation.files or len(obligation.files) != len(set(obligation.files)):
            return False
        if any(index < 0 or index >= len(state.files) for index in obligation.files):
            return False
        assigned.update(obligation.files)
    if any(assigned[index] == 0 for index in range(len(state.files))):
        return False
    receipts = Counter(receipt.obligation for receipt in state.receipts)
    if set(receipts) - set(obligation_indices):
        return False
    for obligation in state.obligations:
        matching = [receipt for receipt in state.receipts if receipt.obligation == obligation.index]
        if len(matching) != 1 or matching[0].binding != "exact":
            return False
        expected_pairs = {(file_index, procedure) for file_index in obligation.files
                          for procedure in state.files[file_index].procedures}
        observed = Counter((file_index, procedure) for file_index, procedure, _status in matching[0].terminals)
        if set(observed) != expected_pairs or any(observed[pair] != 1 for pair in expected_pairs):
            return False
        if any(status != "completed" for _file_index, _procedure, status in matching[0].terminals):
            return False
    completion = state.completion
    return (completion.mode == "workflow" and completion.call_health == "healthy"
            and bool(completion.reasons) and set(completion.reasons) <= ALLOWED_REASONS
            and completion.source_delivery == "analysis"
            and completion.structural in ("not-recorded", "complete"))


def production_decision(summary: dict) -> Decision:
    workflow = read_review_workflow(summary)
    _notes, completion_code, _message = read_completion(summary, required=True, workflow=workflow)
    accepted = (workflow.status in ("complete", "not-required")
                and workflow.code is None and completion_code is None)
    return Decision(accepted, workflow.status, workflow.code, completion_code)


def _case(name: str, family: str, state: AbstractState, *tags: str,
          mutate: Callable[[dict], None] | None = None) -> Case:
    return Case(name, family, state, set(tags), mutate)


def inventory_assignment_cases() -> Iterable[Case]:
    for file_count in (1, 2):
        for procedure_count in (1, 2):
            for dispositions in product(("supported", "unassigned", "unsupported"), repeat=file_count):
                files = tuple(FileState(index, disposition, procedure_count) for index, disposition in enumerate(dispositions))
                eligible = tuple(index for index, file in enumerate(files) if file.source_capable)
                subsets = tuple(tuple(eligible[offset] for offset in range(len(eligible)) if mask & (1 << offset))
                                for mask in range(1, 1 << len(eligible)))
                plans: list[tuple[tuple[int, ...], ...]] = [()]
                plans.extend((subset,) for subset in subsets)
                plans.extend(product(subsets, repeat=2))
                for plan_index, plan in enumerate(plans):
                    obligations = tuple(ObligationState(index, tuple(file_indices)) for index, file_indices in enumerate(plan))
                    receipts = tuple(ReceiptState(obligation.index, terminals=_terminals_for(obligation, files))
                                     for obligation in obligations)
                    state = AbstractState("complete", files, obligations, receipts)
                    tags = {f"inventory:{disposition}" for disposition in dispositions}
                    if file_count == 2:
                        tags.add("reach:two_files")
                    if procedure_count == 2:
                        tags.add("reach:two_procedures")
                    yield _case(f"inventory-f{file_count}-p{procedure_count}-d{'-'.join(dispositions)}-a{plan_index}",
                                "inventory_assignment", state, *tags)


def pairing_binding_cases() -> Iterable[Case]:
    bindings = ("exact", "invocation", "model", "hypothesis", "shard", "source", "request", "file")
    for obligation_count in (1, 2):
        files = tuple(FileState(index) for index in range(obligation_count))
        obligations = tuple(ObligationState(index, (index,)) for index in range(obligation_count))
        for multiplicities in product((0, 1, 2), repeat=obligation_count):
            for binding in bindings:
                for terminal_mode in ("completed", "inconclusive", "missing"):
                    receipts = []
                    for obligation, multiplicity in zip(obligations, multiplicities):
                        terminals = () if terminal_mode == "missing" else _terminals_for(obligation, files, terminal_mode)
                        receipts.extend(ReceiptState(obligation.index, copy, binding, terminals)
                                        for copy in range(multiplicity))
                    tags = {f"binding:{binding}", f"terminal:{terminal_mode}"}
                    if 0 in multiplicities:
                        tags.add("receipt:missing")
                    if 2 in multiplicities:
                        tags.add("receipt:duplicate")
                    if (multiplicities.count(0) == 1 and all(value == 1 for value in multiplicities if value != 0)
                            and binding == "exact" and terminal_mode == "completed"):
                        tags.add("fault:missing_receipt_only")
                    if (multiplicities.count(2) == 1 and all(value == 1 for value in multiplicities if value != 2)
                            and binding == "exact" and terminal_mode == "completed"):
                        tags.add("fault:duplicate_receipt_only")
                    state = AbstractState("complete", files, obligations, tuple(receipts))
                    yield _case(f"pairing-o{obligation_count}-m{''.join(map(str, multiplicities))}-b{binding}-t{terminal_mode}",
                                "pairing_binding", state, *tags)


def terminal_cases() -> Iterable[Case]:
    for file_count in (1, 2):
        for procedure_count in (1, 2):
            files = tuple(FileState(index, procedure_count=procedure_count) for index in range(file_count))
            obligation = ObligationState(0, tuple(range(file_count)))
            pairs = tuple((file.index, procedure) for file in files for procedure in file.procedures)
            for ordinal, statuses in enumerate(product(("completed", "inconclusive", "missing"), repeat=len(pairs))):
                terminals = tuple((file_index, procedure, status) for (file_index, procedure), status in zip(pairs, statuses)
                                  if status != "missing")
                receipt = ReceiptState(0, terminals=terminals)
                tags = {f"terminal:{status}" for status in statuses}
                yield _case(f"terminals-f{file_count}-p{procedure_count}-{ordinal}", "terminal_product",
                            AbstractState("complete", files, (obligation,), (receipt,)), *tags)


def workflow_stage_cases() -> Iterable[Case]:
    files = (FileState(0),)
    obligation = ObligationState(0, (0,))
    receipt = ReceiptState(0, terminals=_terminals_for(obligation, files))
    for bits in product((False, True), repeat=5):
        tags = {f"stage:{name}:failing" for name, healthy in zip(STAGE_NAMES, bits) if not healthy}
        yield _case("stages-" + "".join("1" if bit else "0" for bit in bits), "workflow_stages",
                    AbstractState("complete", files, (obligation,), (receipt,), stages=bits), *tags)


def native_health_cases() -> Iterable[Case]:
    files = (FileState(0),)
    obligation = ObligationState(0, (0,))
    receipt = ReceiptState(0, terminals=_terminals_for(obligation, files))
    for bits in product((False, True), repeat=5):
        tags = {f"native:{name}:failing" for name, healthy in zip(HEALTH_NAMES, bits) if not healthy}
        if sum(bits) == 4:
            tags.add("fault:native_failure_only")
        yield _case("native-" + "".join("1" if bit else "0" for bit in bits), "native_health",
                    AbstractState("complete", files, (obligation,), (receipt,), native_health=bits), *tags)


def completion_cases() -> Iterable[Case]:
    reason_values = (
        ("structural_coverage_not_recorded", "source_analysis_completion_not_established"),
        ("source_analysis_completion_not_established",),
        ("structural_coverage_not_recorded",),
        ("execution_anchor:src/:unsupported",),
        (),
    )
    files = (FileState(0),)
    obligation = ObligationState(0, (0,))
    receipt = ReceiptState(0, terminals=_terminals_for(obligation, files))
    for call_health, reasons, source_delivery, structural in product(
            ("healthy", "failed", "pending"), reason_values, ("analysis", "partial"),
            ("not-recorded", "complete", "incomplete")):
        completion = CompletionState("workflow", call_health, reasons, source_delivery, structural)
        tags = {f"completion:call:{call_health}", f"completion:source:{source_delivery}",
                f"completion:structural:{structural}"}
        if not reasons or not set(reasons) <= ALLOWED_REASONS:
            tags.add("completion:reasons:invalid")
        yield _case(f"completion-{call_health}-r{reason_values.index(reasons)}-{source_delivery}-{structural}",
                    "completion_compatibility", AbstractState("complete", files, (obligation,), (receipt,),
                                                               completion=completion), *tags)


def reachability_cases() -> Iterable[Case]:
    excluded = AbstractState("not-required", (FileState(0, "excluded"),), (), (),
                             completion=CompletionState(mode="not-required"))
    yield _case("all-excluded-not-required", "all_excluded", excluded, "reach:all_excluded")
    files = (FileState(0, procedure_count=2), FileState(1, procedure_count=2))
    obligations = (ObligationState(0, (0,)), ObligationState(1, (1,)))
    receipts = tuple(ReceiptState(obligation.index, terminals=_terminals_for(obligation, files))
                     for obligation in obligations)
    for findings in (0, 1):
        state = AbstractState("complete", files, obligations, receipts, finding_count=findings)
        yield _case(f"two-independent-files-findings-{findings}", "finding_reachability", state,
                    "reach:two_independent_files", f"reach:findings:{findings}")


def malformed_cases() -> Iterable[Case]:
    files = (FileState(0),)
    obligation = ObligationState(0, (0,))
    receipt = ReceiptState(0, terminals=_terminals_for(obligation, files))
    base = AbstractState("complete", files, (obligation,), (receipt,), well_formed=False)

    def mutation(name: str, function: Callable[[dict], None]) -> Case:
        return _case(name, "malformed_boundaries", base, "malformed", f"malformed:{name}", mutate=function)

    cases = [
        mutation("report-not-object", lambda s: s.update(reviewWorkflow="bad")),
        mutation("schema-bool", lambda s: s["reviewWorkflow"].update(schemaVersion=True)),
        mutation("schema-version", lambda s: s["reviewWorkflow"].update(schemaVersion=2)),
        mutation("inventory-container", lambda s: s["reviewWorkflow"].update(inventory={})),
        mutation("duplicate-inventory", lambda s: s["reviewWorkflow"]["inventory"].append(
            deepcopy(s["reviewWorkflow"]["inventory"][0]))),
        mutation("duplicate-obligation", lambda s: s["reviewWorkflow"]["obligations"].append(
            deepcopy(s["reviewWorkflow"]["obligations"][0]))),
        mutation("bytes-bool", lambda s: s["reviewWorkflow"]["inventory"][0].update(bytes=True)),
        mutation("bytes-negative", lambda s: s["reviewWorkflow"]["inventory"][0].update(bytes=-1)),
        mutation("bytes-too-large", lambda s: s["reviewWorkflow"]["inventory"][0].update(bytes=8 * 1024 * 1024 + 1)),
        mutation("shard-bool", lambda s: s["reviewWorkflow"]["obligations"][0].update(shardIndex=True)),
        mutation("shard-zero", lambda s: s["reviewWorkflow"]["obligations"][0].update(shardIndex=0)),
        mutation("shard-too-large", lambda s: s["reviewWorkflow"]["obligations"][0].update(shardIndex=2**53)),
        mutation("procedures-container", lambda s: s["reviewWorkflow"]["inventory"][0].update(requiredProcedures="security-review")),
        mutation("procedures-duplicate", lambda s: s["reviewWorkflow"]["inventory"][0].update(requiredProcedures=["security-review", "security-review"])),
        mutation("receipt-files-container", lambda s: s["reviewWorkflow"]["receipts"][0].update(files={})),
        mutation("terminals-container", lambda s: s["reviewWorkflow"]["receipts"][0]["files"][0].update(terminals={})),
        mutation("duplicate-terminal", lambda s: s["reviewWorkflow"]["receipts"][0]["files"][0]["terminals"].append(
            deepcopy(s["reviewWorkflow"]["receipts"][0]["files"][0]["terminals"][0]))),
        mutation("completion-schema-bool", lambda s: s["completion"].update(schemaVersion=True)),
        mutation("completion-count-bool", lambda s: s["completion"]["modelCalls"].update(attempted=True)),
        mutation("completion-count-too-large", lambda s: s["completion"]["modelCalls"].update(attempted=2**53)),
    ]
    yield from cases


def generated_cases() -> list[Case]:
    cases = [
        *inventory_assignment_cases(), *pairing_binding_cases(), *terminal_cases(),
        *workflow_stage_cases(), *native_health_cases(), *completion_cases(),
        *reachability_cases(), *malformed_cases(),
    ]
    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise AssertionError("generated case names are not unique")
    if len(cases) != 711:
        raise AssertionError(f"finite-domain drift: expected 711 cases, generated {len(cases)}")
    return cases


def case_summary(case: Case) -> dict:
    summary = materialize(case.state)
    if case.mutate:
        case.mutate(summary)
    return summary


def required_witnesses(cases: list[Case], decisions: dict[str, Decision]) -> dict[str, str]:
    requirements = {
        "accepted_complete": lambda case: oracle(case.state) and case.state.status == "complete",
        "accepted_all_excluded": lambda case: "reach:all_excluded" in case.tags,
        "accepted_two_independent_files": lambda case: "reach:two_independent_files" in case.tags,
        "accepted_zero_findings": lambda case: "reach:findings:0" in case.tags,
        "accepted_findings": lambda case: "reach:findings:1" in case.tags,
        "rejected_unassigned": lambda case: "inventory:unassigned" in case.tags and not oracle(case.state),
        "rejected_unsupported": lambda case: "inventory:unsupported" in case.tags,
        "rejected_missing_receipt": lambda case: "fault:missing_receipt_only" in case.tags,
        "rejected_duplicate_receipt": lambda case: "fault:duplicate_receipt_only" in case.tags,
        "rejected_inconclusive_terminal": lambda case: "terminal:inconclusive" in case.tags,
        "rejected_missing_terminal": lambda case: "terminal:missing" in case.tags,
        "rejected_workflow_stage": lambda case: any(tag.startswith("stage:") for tag in case.tags),
        "rejected_native_health": lambda case: any(tag.startswith("native:") for tag in case.tags),
        "rejected_failed_call": lambda case: "completion:call:failed" in case.tags,
        "rejected_pending_call": lambda case: "completion:call:pending" in case.tags,
        "rejected_bad_legacy_reason": lambda case: "completion:reasons:invalid" in case.tags,
        "rejected_partial_source": lambda case: "completion:source:partial" in case.tags,
        "rejected_malformed": lambda case: "malformed" in case.tags,
        "rejected_duplicate_inventory": lambda case: "malformed:duplicate-inventory" in case.tags,
        "rejected_duplicate_obligation": lambda case: "malformed:duplicate-obligation" in case.tags,
        "rejected_duplicate_terminal": lambda case: "malformed:duplicate-terminal" in case.tags,
    }
    witnesses: dict[str, str] = {}
    for requirement, predicate in requirements.items():
        for case in cases:
            if predicate(case) and decisions[case.name].accepted == oracle(case.state):
                witnesses[requirement] = case.name
                break
        else:
            raise AssertionError(f"no non-vacuity witness for {requirement}")
    return witnesses


def _production_acceptor(case: Case, summary: dict) -> bool:
    return production_decision(summary).accepted


def mutant_results(cases: list[Case]) -> dict[str, dict]:
    """Concrete witnesses against intentionally faulty abstract acceptance functions.

    These functions are checker self-tests, not compiled source mutants of llm_harness.py.
    """
    def always_accept(_case: Case, _summary: dict) -> bool:
        return True

    def always_reject(_case: Case, _summary: dict) -> bool:
        return False

    def ignore_missing_receipt(case: Case, summary: dict) -> bool:
        return True if "fault:missing_receipt_only" in case.tags else _production_acceptor(case, summary)

    def collapse_duplicate_receipts(case: Case, summary: dict) -> bool:
        return True if "fault:duplicate_receipt_only" in case.tags else _production_acceptor(case, summary)

    def ignore_native_failure(case: Case, summary: dict) -> bool:
        return True if "fault:native_failure_only" in case.tags else _production_acceptor(case, summary)

    mutants = {
        "always_accept": always_accept,
        "always_reject": always_reject,
        "ignore_missing_receipt": ignore_missing_receipt,
        "collapse_duplicate_receipts": collapse_duplicate_receipts,
        "ignore_native_failure": ignore_native_failure,
    }
    results = {}
    for name, acceptor in mutants.items():
        witness = None
        for case in cases:
            actual = acceptor(case, case_summary(case))
            expected = oracle(case.state)
            if actual != expected:
                witness = {"case": case.name, "expected": expected, "faulty_accepted": actual}
                break
        results[name] = {"kind": "abstract_acceptance_function", "detected": witness is not None,
                         "witness": witness}
    return results


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_binding() -> dict:
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                                capture_output=True, text=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    return {
        "git_commit": commit,
        "sha256": {
            str(ADAPTER.relative_to(ROOT)): _sha256(ADAPTER),
            str(FIXTURE.relative_to(ROOT)): _sha256(FIXTURE),
            str(Path(__file__).resolve().relative_to(ROOT)): _sha256(Path(__file__).resolve()),
            str(DESIGN.relative_to(ROOT)): _sha256(DESIGN),
        },
    }


def run_checker() -> dict:
    cases = generated_cases()
    decisions: dict[str, Decision] = {}
    mismatches = []
    for case in cases:
        decision = production_decision(case_summary(case))
        decisions[case.name] = decision
        expected = oracle(case.state)
        if decision.accepted != expected:
            mismatches.append({
                "case": case.name, "family": case.family, "expected": expected,
                "actual": decision.accepted, "workflow_status": decision.workflow_status,
                "workflow_code": decision.workflow_code, "completion_code": decision.completion_code,
                "tags": sorted(case.tags),
            })
    mutants = mutant_results(cases)
    witnesses = required_witnesses(cases, decisions) if not mismatches else {}
    family_counts = Counter(case.family for case in cases)
    accepted = sum(oracle(case.state) for case in cases)
    return {
        "checker": "sv-completion-properties/v1",
        "claim": "bounded generated verification and concrete conformance; no full formal proof artifact",
        "checked": len(cases),
        "expected_accepted": accepted,
        "expected_rejected": len(cases) - accepted,
        "family_counts": dict(sorted(family_counts.items())),
        "production_mismatches": mismatches,
        "non_vacuity_witnesses": witnesses,
        "faulty_acceptance_checks": mutants,
        "source_binding": source_binding(),
        "limitations": [
            "finite domains are exhaustive only over the dimensions documented in docs/designs/sv-completion-bounded-verification.md",
            "no proof of Git inventory completeness or classification, producer truthfulness, actual source delivery, or semantic model understanding",
            "no proof of network/container behavior, hash security, provider identity, or arbitrary Python/TypeScript executions",
            "faulty acceptance functions are abstract checker self-tests, not compiled source-level mutants",
            "the current upstream producer does not demonstrate a bootstrap all-excluded completion report; this checker materializes the wire contract's valid not-required form",
        ],
        "ok": not mismatches and all(item["detected"] for item in mutants.values()),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="also write the JSON result to this path")
    args = parser.parse_args()
    result = run_checker()
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    print(encoded, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
