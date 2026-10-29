---
name: scanner-adapter-builder
description: Build or review scanner execution adapters that invoke native scanner workflows and produce evidence-backed, replayable outcomes. Use for scanner integration, runtime provenance, capability/status handling, and live-smoke readiness; not for dataset import or corpus-label adjudication.
---

# Scanner Adapter Builder

Build the narrowest adapter that runs the scanner's real workflow without changing its meaning. Preserve native evidence, normalize only what the contract requires, and make unsupported or incomplete work visible. The adapter executes a scanner; it does not receive labels, decide whether findings are true, or turn failure into an empty successful scan.

Read [references/failure-patterns.md](references/failure-patterns.md) before designing completion evidence, live diagnostics, open-context support, model/runtime identity, native kind mappings, or multi-stage process handling.

## Establish the native contract

Inspect the repository's adapter protocol, schemas, runner, existing adapters, scanner CLI help/source, and real saved payloads. Record decisions before implementation:

- Pin an immutable scanner build or commit and inventory the actual runtime it bundles: model SDK/client, lockfile, plugins, rules, and helper binaries. Distinguish requested route, scanner-reported effective route, client-reported served model, and provider-attested identity; do not collapse them.
- List supported languages, full/PR modes, stages, agents/providers, network conditions, trace levels, and execution backends. Unsupported combinations must remain `unsupported`, never fall back to a different mode, route, model, or host execution.
- Define the source boundary: what tree, diff, generated files, Git objects/refs, history, and evaluator data the scanner can read. Labels, fixes, future commits, and ground truth stay outside scanner input.
- Define the network claim separately from configuration. A declaration is not enforcement; open-context claims need admitted public egress plus observer evidence, and history claims need authentic scoped ancestor Git history.

## Define evidence and outcomes first

Write a versioned evidence contract with one obligation per claim of completion: native stage receipts, source inventory/scope, model-call health, import conservation, omissions, runtime identity, and cleanup. Make the positive success criterion observable before launching an expensive run.

Require at least:

- one successful fixture that uses real source and satisfies every completion obligation;
- meaningful failure fixtures for timeout, nonzero stage exit, malformed/missing export, partial batch, unsupported mode, unknown native kind, and scope omission where applicable;
- explicit outcomes for `success`, `partial`, `unsupported`, `error`, and `timeout`, preserving usable findings on incomplete runs;
- visible omitted scope and unresolved/unknown completion. Unknown is not a zero-finding success.

If the scanner cannot provide positive evidence for an obligation, keep that obligation unknown and the run partial. Do not infer review completeness from successful calls, delivered findings, process exit, or an empty result.

## Implement the native path

- Run the scanner's own stages and preserve their raw artifacts. For a native `scan -> process -> export` flow, all required stages must finish; regex candidates, model-selected candidates, and exported findings are different populations.
- Route every child process through the repository's execution seam. Apply a bounded shared deadline, cancellation, process-group/descendant cleanup, and exact per-stage receipts. Process or container exit alone does not prove children stopped or every stage succeeded.
- Use fresh create-only run directories and immutable run/guard identifiers. A retry is a new attempt, not a rewrite of a terminal record.
- Preserve native IDs, rule/class/kind strings, evidence, and raw payload bindings. Map only exact, versioned native vocabulary supported by source or real payloads; leave unknown values explicitly unmapped.
- Record configured and effective runtime/model data without silently substituting host tools for scanner-embedded SDKs. Never infer provider identity from a requested model string.
- Keep source, credentials, prompts, raw findings, and traces out of committed documentation and fixtures unless deliberately fabricated and sanitized.

## Verify from cheap to expensive

1. Run deterministic unit/contract tests with synthetic scanners or providers. These establish adapter logic, not real integration.
2. Exercise realistic native payloads and every failure path. Check count conservation, status precedence, omitted scope, artifact bindings, and mapping provenance.
3. Validate request/result schemas and exact offline replay before publishing any number. In ScanEval-style repositories, confirm current syntax with CLI help, then use `validate` on saved contracts and `replay` on the completed bundle.
4. Obtain an independent review of the adapter boundary, evidence contract, cleanup, and unsupported paths. Fix substantiated findings and rerun affected checks.
5. With explicit authorization, run one bounded live smoke in a fresh directory. Make the intended probe part of the actual scanner/model input and require its recorded calls and matching receipts. Stop after the smoke; expand only when separately authorized and the success criterion holds.

Report deterministic test results, live-smoke evidence, detection outcomes, and label/readiness status as separate statements. Keep partial and unsupported assignments in the denominator required by the evaluator; never quietly drop them. State remaining evidence gaps and do not claim the adapter prevents future integration failures.
