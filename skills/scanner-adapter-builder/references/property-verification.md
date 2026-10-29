# Optional property verification for adapter acceptance

Use this only where a small checker materially strengthens a high-risk acceptance state machine. It is not a requirement to adopt formal tooling, enroll with an external service, or submit every adapter for proof.

Anthropic's [Formal verification at Anthropic](https://www.anthropic.com/research/formal-verification) describes using explicit properties and machine-checked evidence to supplement testing. For an adapter, specify the real acceptance invariants first; do not begin with a proof tool or with an easier duplicate of production logic.

## Completion-soundness properties

Check the actual production acceptance entrypoint. For required evidence:

- missing, failed, unsupported, unassigned, stale, cross-bound, duplicate, or inconclusive evidence cannot produce `success`;
- genuine complete evidence can produce `success`, including a valid zero-finding result, so the policy is not vacuous;
- usable findings survive incomplete outcomes;
- cancellation and status precedence remain as specified.

Use an independent oracle rather than restating the implementation. Give every critical property a concrete positive witness and a failing mutation. A machine checker decides the property; an LLM prose judgment may review the design but is not proof evidence. Fix discovered counterexamples and retain them as regressions. Never weaken the property or remove required error paths merely to make the checker pass.

## Scope the claim exactly

A small finite-domain exhaustive checker is appropriate when it states:

- the exact properties, expected outcomes, production entrypoint, and version checked;
- the modeled evidence fields and status rules;
- the runtime and checker used;
- the finite input bounds and combinations enumerated;
- the trusted base and any assumptions or unmodeled behavior.

Call fuzzing, property tests, and finite-domain exhaustive enumeration what they are. They can provide strong bounded evidence, but they are not a formal proof of the whole implementation. Likewise, a proved abstract contract plus differential tests still leaves an implementation-correspondence gap unless the link from production code to the model is itself proved. Do not claim bug-free behavior, complete formal verification, or guarantees beyond the stated bounds.

## Distinguish fault checks

Abstract fault-function self-tests—always accept, always reject, ignore a required receipt, collapse duplicates, or ignore native failure—show that the checker detects deliberately faulty models. Runtime suppression of a real production rejection guard instead yields a concrete implementation counterexample. Neither is compiled source mutation or a whole-program formal proof.

For either method, state the exact production entrypoint and version, bounds, fixture provenance, trusted base, and unmodeled domain; retain counterexamples as regressions. Do not hardcode changing case totals or link private run artifacts. [ScanEval issue #104](https://github.com/Har1sh-k/scaneval/issues/104) and [securevibes-agent PR #206](https://github.com/anshumanbh/securevibes-agent/pull/206) are ongoing work, not evidence that an upstream change is merged, accepted, or approved.
