# Contributing to ScanEval

Thank you for helping. ScanEval is an alpha, so its code, contracts and docs still change quickly. Bug reports, fixes, documentation, scanner adapters, dataset adapters and corpus cases are all welcome.

## Before you start

Open an issue before you write a larger change: a new feature, adapter, dataset or corpus case, or a change to a versioned contract or a scoring rule. Describe the problem, how to reproduce it, and what you expected. A small fix, such as a typo or a broken link, can go straight to a pull request.

If you think you have found a security vulnerability in ScanEval itself, don't post the details in a public issue. Open an issue asking for a private way to report it, and leave the details out.

## Set up a checkout

You need Git, Python 3.11 or newer, and Node.js with npm for the TypeScript SDK. CI uses Node 24. On macOS, use Python 3.13 or newer to run the tests that need `os.waitid`; see [expected skips](#expected-skips).

```bash
git clone https://github.com/Har1sh-k/scaneval.git
cd scaneval
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]" "semgrep==1.177.0"
npm ci --prefix sdk/typescript
```

Semgrep is optional; `1.177.0` is the version CI uses. Without it, the tests that run or import Semgrep are skipped. So are the `ruamel.yaml` C-parser comparisons in `tests/test_v2_blinding.py`, because Semgrep is what installs `ruamel.yaml.clib`; install that package to run them without Semgrep.

## Run the tests

Run them in this order, as CI does:

```bash
npm test --prefix sdk/typescript
python -m pytest -q -rs
```

`npm test` runs the TypeScript tests and also builds `sdk/typescript/dist`. Some Python tests use that build and fail without it. `-rs` prints the reason for each skip.

Tests use local fixtures and fake model runners, and never call a paid model. New tests should do the same: use fixtures and fakes, not live scanners, models or network services.

### Expected skips

A full local run reports some skips, and each names what is missing:

- **Docker.** The OCI backend tests need a Docker engine and the pinned images. CI runs `tests/test_v2_isolation_docker.py`, `tests/test_v2_open_context_docker.py` and `tests/test_v2_experiment_docker.py` with `SCANEVAL_REQUIRE_DOCKER=1`, which turns a missing engine or image into an error instead of a skip. `tests/test_v2_sv_open_context_docker.py` also needs `SCANEVAL_SV_IMAGE` set to the digest-pinned reference (`name@sha256:…` or `sha256:…`) of a locally built SV-Agent image, and CI does not run it.
- **External checkouts and private bundles.** Tests that need a harness checkout or a preserved private bundle are skipped without one.
- **RunSortie conformance.** This test is opt-in through `SCANEVAL_RUNSORTIE_CONFORMANCE_ROOT`.
- **File names.** Two tests need a filesystem that accepts file names that are not valid UTF-8. The default macOS filesystem refuses them.
- **`os.waitid` on macOS.** Python 3.11 and 3.12 on macOS have no `os.waitid`, so the tests that need it, in RunSortie's retained native path, process-group cleanup, and the Codex quota guard, are skipped. Python 3.13 or newer runs them.

A few more skip with reasons pytest prints, such as a platform-specific check, or a check parametrized over corpus run configurations when none is committed.

CI runs on Linux with Python 3.11, 3.13 and 3.14.

## Make the change

- Keep each commit small and focused on one change, with a message that says what it does.
- Add or update tests for what you change. A fix should come with a test that fails without it.
- Update the docs that describe the behaviour you changed.
- Don't commit generated runs (they belong under the ignored `results/`), source caches (under the ignored `.repos/`), scanner outputs, private findings, credentials or content traces.
- Don't commit absolute paths from your own machine. `tests/test_v2_repository_hygiene.py` reads the working tree. It fails on a path into a real user's home directory and on any run record outside `results/` and the build, cache and environment directories it skips, committed or not, so keep generated runs under `results/`.

## Open a pull request

- Link the issue it resolves, for example `Fixes #123`.
- Say what changed and how you checked it: the tests you ran, their results, and anything you could not test.
- CI must pass before a merge, and a review may ask for changes.

## Where to start

- **Scanner adapters:** the [scanner adapter builder skill](skills/scanner-adapter-builder/SKILL.md) and [current capabilities](docs/INITIAL_BUILD.md).
- **Corpus cases:** [bring your own corpus](docs/BRING_YOUR_OWN_CORPUS.md) and the [CVE corpus](corpus/diverse/README.md).
- **Datasets:** [dataset adapters](docs/DATASET_ADAPTERS.md).
- **Tracing:** the [Observer SDK](docs/OBSERVER_SDK.md).

## License

By contributing, you agree that your contributions are licensed under the project's [MIT License](LICENSE).
