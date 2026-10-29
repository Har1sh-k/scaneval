# Scanner adapter builder skill

## Boundary

Create a portable public skill for engineering and reviewing **scanner execution adapters**: integrations that invoke a scanner, preserve native evidence, and translate one invocation into truthful normalized outcomes. The skill does not cover dataset import, corpus-label review, finding adjudication, or benchmark publication.

The entrypoint will keep the reusable workflow concise. A focused failure-pattern reference will hold the substantial lessons from the current `llm-harness`/SV-Agent and DeepSec integrations. Repository paths may be suggested as search starting points, but the copied skill must not depend on files outside its own directory.

## Acceptance

The skill is acceptable when it:

- distinguishes immutable scanner, bundled SDK/runtime, route, and effective model evidence;
- requires declared capabilities and native full/PR behavior without hidden fallback;
- preserves source, Git/history, network, process, timeout, and artifact boundaries;
- defines a positive successful-source criterion before any expensive run, plus meaningful failure fixtures, and documents a capability gap instead of fabricating a positive fixture when success is unattainable;
- keeps successful, partial, unsupported, error, and timeout outcomes distinct while preserving findings;
- validates normalized schemas and exact offline replay before reporting numbers;
- separates deterministic tests, authorized live smoke, detection results, and label readiness;
- requires independent review and permits only one bounded authorized smoke before expansion, using a model/tool probe only when that boundary exists and a native positive criterion for rule-based scanners;
- records that current local legacy `llm-harness` completion-report absence is historically tolerated while the distinct OCI image route rejects it, presenting stricter completion policy as guidance rather than a claim about every current path;
- offers optional bounded property verification for completion soundness, scoped to the production acceptance path and careful not to relabel tests or finite exhaustive checks as whole-implementation proof;
- records observed failures as symptom, cause, corrective action, and regression/acceptance check, without claiming pending upstream fixes are merged or resolved.

Verification is documentation-focused: run the skill creator's `quick_validate.py` with the repository Python, parse the UI YAML, verify every relative skill link exists, inspect the rendered changes, and check any ScanEval command examples against current CLI documentation/help. No prose-matching test, formal-tool enrollment, or external scanner/model run is required.
