# Native DeepSec kind mapping

Issue: [#100](https://github.com/Har1sh-k/scaneval/issues/100).

The DeepSec importer preserves native slugs but only consults the shared harness
class table. Add a producer-specific table in the versioned kind mapping for
three native DeepSec 2.3.10 identities:

| Native slug | Canonical kind | Native meaning |
| --- | --- | --- |
| `missing-auth` | `auth_bypass` | Endpoints missing authentication |
| `acl-check` | `authz_bypass` | Missing or incorrect permission checks |
| `go-command-injection` | `command_injection` | Go command-injection findings |

The evidence is the published DeepSec 2.3.10 CLI distribution: its known-category
prompt, Go command-injection matcher, and corresponding processor guidance. The
inspected distribution's SHA-256 is
`b967138cbe6156d1d50877a8b0200afccb5a1c91e6672d0010d789b9d7acabb2`.
These are classifications of the producer's allegations, not truth judgments.

Increment the mapping version to 1.2.0. Match these producer-specific slugs
exactly before the existing separator-normalized harness-class fallback. Do not
add them to the shared harness table, infer classes from titles, strip `other-`
prefixes, or map broad `rce` findings to command injection. Preserve native IDs,
raw evidence, the canonical vocabulary, and frozen historical results. Existing
execution records already include the kind-mapping version.

Verification uses fabricated native export records and existing offline adapter
tests. Assert canonical kind and native identity together, compatibility with
existing common slugs, and unknown/near-match behavior. A structural mapping test
checks that the new table references existing canonical kinds without changing
the shared harness classification. No scanner or model execution is required.

Keep specification, implementation, and verification changes in logical commits;
obtain a fresh Opus 5.5 review before publishing the PR.
