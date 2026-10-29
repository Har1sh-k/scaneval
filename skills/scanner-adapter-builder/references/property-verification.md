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
