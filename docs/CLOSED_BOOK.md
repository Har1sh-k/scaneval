# Closed-book standard

`closed_book_standard` asks how a scanner detects a vulnerability from an ordinary source
snapshot while repository identity remains visible, without original Git history or public-web
retrieval clues. It uses the `standard` full-scan profile. Paths, package metadata, documentation,
instruction files, and source identifiers remain present. This condition does not establish
that a pretrained model has never seen or memorized the source.

An explicit declaration in a 2.1 run configuration is:

```json
{"snapshot_id":"snapshot-a","profile":"standard","condition":{"name":"closed_book_standard","policy":{}}}
```

New standard full scans default to that condition. The declaration requests classification; it
does not attest the run. A condition is independent of a source profile: an open-context input
also keeps ordinary repository identity, and an identity-reduced input requires its own
transformation evidence. Condition names and policy are frozen in the schedule and manifest
when explicitly configured, and vulnerable/fixed pairs require the same condition declaration.

Each invocation saves `condition.json`, validated as a `condition-record`. It binds exact bytes
of the request, result, execution record, configuration, input provenance, condition policy,
mechanical history audits, and any observed trace or referenced provider assertion. It also
shows retained instruction, metadata, and documentation paths. Reclassification checks those
files and refuses a stale record. Hashes detect changes to saved evidence; they do not
authenticate its author or stop an operator from rewriting every artifact.

The states are:

| Status | Meaning |
| --- | --- |
| `attested` | All required evidence establishes the condition, including enforced isolation. |
| `declared_only` | An eligible invocation declares the condition but has enforcement, capture, or provider verification gaps. |
| `failed` | Evidence violates the condition, contradicts its bindings, or differs from its saved condition record. |
| `unavailable` | Required legacy evidence is absent, the scanner did not support the invocation, or the condition cannot be classified. |

The ordinary export removes original `.git` entries and controller state. A scanner requiring
Git gets one neutral snapshot commit with fixed identity and date. Before and after audits
record every Git path, fingerprint all synthetic repository files and entry types, and reject
unexpected history, modified metadata, symlinks, and special entries. No upstream commits are
copied for this condition.

Offline scanners declare `network_policy: none`. Remote inference declares
`network_policy: model_provider_only`; when enforcement is claimed, the recorded OCI proxy
allowlist must be bound to inference hosts and unrelated egress must remain denied. A local
network declaration is always unenforced. Unrestricted network or explicitly enabled browser,
web-search, remote-fetch, package-install, or scanner-update tools fails classification.

`Adapter.condition_controls` describes actual adapter controls in machine-readable form;
Semgrep OSS records its local pinned rules, disabled version checks, and absent retrieval tools.
Unknown adapters provide no such evidence by default. Complete local tool observation may
establish `observed_none`; incomplete capture and opaque shell calls produce `capture_gap`.
Missing events do not establish that no retrieval occurred. Tool identities identify retrieval
operations; quoted text or filenames mentioning browsers or curl do not.

Provider capability, requested retrieval control, and provider attestation are recorded
separately from local network enforcement. A registered JSON assertion can be bound to the
invocation but remains self-reported. This build has no trusted provider-attestation verifier,
so remote-model observations remain `declared_only` even with enforced inference-only egress
and a saved assertion that retrieval was disabled. It never infers absence of hidden provider
retrieval.

Read saved bundles without executing a scanner or consulting the network:

```console
scaneval condition runs/example/invocations/input-a__scanner__r1
scaneval condition bundle-a bundle-b --output condition-coverage.json
scaneval validate condition-record bundle-a/condition.json
```

The command returns every observation's status and reasons plus separate condition/status
coverage counts. Aggregation includes condition coverage and refuses a mode/profile view
containing readable observations from different condition/status strata. Aggregate those
strata separately; use the condition command to inspect mixed collections. Missing or skipped
assignments stay in operational denominators and appear as unavailable condition evidence.
Existing standard runs remain readable and conservatively classify as unavailable when their
saved artifacts cannot establish the condition. Detection matching and credit are unchanged.
