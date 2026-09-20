# Rename to ScanEval

The project was called SASTbench. It is now ScanEval. This note records what changed, what
deliberately did not, and what a reader should check if something still looks wrong.

The rename also removes a collision: a separately published paper already uses the name
SastBench. That citation is still in the design document and refers to that other project,
not to this one.

## Names

The umbrella name is ScanEval, with five named parts:

| Part | What it covers |
|---|---|
| ScanEval Corpus | Public and private cases, pinned snapshots, and validated controls. |
| ScanEval Runner | Scanner execution, run configuration, and budgets. |
| ScanEval Evaluator | Finding assessment and performance metrics. |
| ScanEval Observer | Harness instrumentation. |
| ScanEval Reports | Scorecards, comparisons, and traces. |

Developer-facing names:

| Thing | Before | Now |
|---|---|---|
| GitHub repository | `Har1sh-k/sast-bench` | `Har1sh-k/scaneval` |
| Python distribution | `sastbench` | `scaneval` |
| Python import namespace | `sastbench` | `scaneval` |
| Console command | `sastbench` | `scaneval` |
| TypeScript package | `@sastbench/observer-sdk` | `@scaneval/observer` |
| Python observer import | none existed | `from scaneval.observer import Observer` |

Four entry points name the parts of the system. Two of them, `scaneval.evaluator` and
`scaneval.corpus`, are new modules that re-export their existing cores rather than wrapping
them, so no behavior changed with the rename.

```python
from scaneval.runner import run_from_config      # execution
from scaneval.evaluator import score             # assessment, no model call
from scaneval.corpus import new_pack, build_plan # cases and snapshots
from scaneval.observer import Observer           # instrumentation
```

## What changed

Source directories, imports, the console entry point, package manifests, package data
paths, schema identifiers, tests, fixtures, examples, adapter driver references, the two
authoring skills, docs, and legacy scripts. Also the workspace prefixes for trial and
inspection directories, the state directory stripped from an export, the synthetic commit
identity used when a scanner requires git, and the pilot pack namespace.

No environment variable needed renaming: the project defined none of its own. Any new one
uses the `SCANEVAL_` prefix. Variables the adapters forward to a harness, such as
`ANTHROPIC_API_KEY`, belong to that harness and were left alone.

Versions were not invented. The Python distribution stays at `2.0.0a1` and the TypeScript
package at `0.1.0-experimental`, because nothing about the rename changes compatibility for
an installed user: there are no installed users, since neither package has been published.

## What deliberately did not change

### Run bundles were regenerated, never relabeled

Committed run bundles are evidence of what executed. Their documents bind to each other by
content hash: `evaluation.json` records the canonical hash of the plan and the decisions,
`review-record.json` binds to both, and `decisions.json` binds to the result. Editing the
project name inside one of those documents changes its hash, so the references no longer
resolve. Measured before deciding, on a bundle produced under the old name:

```
plan provenance namespace: sastbench.public
recomputed plan hash == evaluation.json plan_sha256: True
after renaming namespace, hash still matches: False
```

Rewriting them would also have been a lie: an old record would claim to be a ScanEval run.
So the bundles produced under the former name were removed from the repository rather than
edited, and replaced by a fresh execution of the same frozen configuration on the same
three pinned snapshots. The committed evidence is therefore genuinely ScanEval-produced.

`tests/test_v2_preserved_runs.py` enforces this for whatever is committed: every bundle
must still hash-verify, still replay byte for byte, and still show no approved decision.

If you hold a bundle produced under the old name and want it in the corpus, regenerate it.
Do not edit it. A migration that rewrote those documents would need to recompute every
binding, and the result would still misstate which build produced the run.

### Three mentions of the old name remain on purpose

| Where | Why |
|---|---|
| `docs/DESIGN_DECISIONS.md` | A citation of SastBench, arXiv 2601.02941, a different published project. |
| `docs/CLAUDE_HANDOFF.md`, `docs/REPOSITORY_INVENTORY.md` | `/Volumes/Untitled/sastbench-research/2026-09-19/` is a directory that exists under that name on an external drive. It is a machine path, not a project identifier. |

`docs/archive/` is untracked and was not touched.

## Repository and checkout

The GitHub repository was renamed in place with `gh repo rename`, so branches, issues,
pull requests, history and settings are preserved. Nothing was deleted, recreated,
force-pushed, or merged.

- Repository: <https://github.com/Har1sh-k/scaneval>
- Remote: `https://github.com/Har1sh-k/scaneval.git`, keeping the HTTPS transport it had.
- GitHub keeps a redirect, so the old URL still resolves for anyone who has it.

## Installation

The evaluator is a Python command. There is no Node.js CLI and none is planned, so there is
nothing to run with `npx`.

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
scaneval --version
```

The TypeScript Observer is a separate package under `sdk/typescript`, installable on its
own by a harness written in TypeScript:

```sh
cd sdk/typescript && npm ci && npm run build
```

Neither package is published. `scaneval` on PyPI, `scaneval` on npm, and
`@scaneval/observer` on npm were all unregistered when checked on 2026-09-20, and ownership
of the `@scaneval` npm scope is not confirmed. Nothing was published, reserved, or created
to hold a name. Publishing would need, at minimum, a decision on the scope, a release
version, and a license review for the corpus material that ships with the package.

## References in other repositories

Other repositories may link to the old name, including the portfolio website. Those were
not modified: changing another repository needs its own authorization. Search for
`sast-bench` and `sastbench` there when you are ready.
