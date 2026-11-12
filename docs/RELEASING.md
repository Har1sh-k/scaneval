# Publishing the Python alpha

The alpha `scaneval==2.0.0a2` is [available on PyPI](https://pypi.org/project/scaneval/2.0.0a2/),
distributed as a Python wheel and source archive. The package exposes
`scaneval.evaluate(plan, result, decisions)`, the CLI, and optional tracing through
`scaneval.observer` in the same distribution. The Observer emits trace schema `2.0`.

Only the Python `scaneval` distribution is in this release. The TypeScript Observer
remains available as repository source; no npm package or separate Python Observer
distribution is being published. The README's scanner, corpus-label, and live-runtime
limits still apply.

## Build and inspect locally

Use a clean checkout of the reviewed release commit:

```sh
python -m pip install build twine
python -m build --outdir /tmp/scaneval-python-dist
python -m twine check --strict /tmp/scaneval-python-dist/*
for artifact in /tmp/scaneval-python-dist/*; do
  python scripts/check_python_package.py "$artifact"
done
```

The package check installs each exact artifact into a new environment, verifies the
evaluation API, Observer, and packaged resources, and runs the fabricated demo/replay
from an empty directory. No model is called by these checks.

Inspect archive contents before upload. Source caches, run bundles, credentials, traces,
local dependency trees, and generated output do not belong in the distribution.

## One-time PyPI setup

GitHub authentication does not grant PyPI project ownership. In the publishing account's
PyPI settings, add a pending GitHub Trusted Publisher for a new project, or add a
publisher on the existing project:

| Field | Value |
|---|---|
| PyPI project | `scaneval` |
| Owner | `Har1sh-k` |
| Repository | `scaneval` |
| Workflow filename | `publish-packages.yml` |
| Environment | `pypi` |

The GitHub environment must be named `pypi`. Configure it to allow deployments from
`main` only. The workflow uses OIDC, so no long-lived PyPI token is needed. The first
successful pending-publisher upload creates the project; configuring a pending publisher
alone does not reserve its name. See
[PyPI's first-release instructions](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

Do not commit registry credentials or paste passwords or tokens into issues or chat.

## Release workflow

`.github/workflows/publish-packages.yml` builds and verifies the Python wheel and source
archive on relevant pull requests and pushes. Both artifacts are installed and exercised
independently. The unprivileged build jobs retain the exact verified files for publication.

Publication happens only on a manual dispatch with `publish=true`, from `main`, after
the regular `CI` workflow has passed for that exact main commit. The publish job receives
OIDC permission separately from the build jobs and uses the `pypi` environment.

```sh
# Build and verify only; no upload.
gh workflow run publish-packages.yml --ref main -F publish=false

# Publish after the one-time PyPI setup is complete.
gh workflow run publish-packages.yml --ref main -F publish=true
```

There is no registry-selection input. Package versions are immutable once published;
increment the version for every subsequent release.

After publication, verify the PyPI version and install it in a fresh environment:

```sh
python -m pip install --no-cache-dir scaneval
# Or pin this alpha: python -m pip install --no-cache-dir "scaneval==2.0.0a2"
python -c "import scaneval; print(scaneval.__version__)"
```

Then evaluate structured saved records with `scaneval.evaluate(plan, result, decisions)`
and verify the offline demo/replay. Pin an exact alpha version for reproducible integrations.

## Tag the release

Once PyPI lists the new files, tag the commit they were built from and create a GitHub
release for it. That commit is the head of the newest dispatch run whose
`Publish Python alpha to PyPI` job succeeded; the PyPI attestations for both files name
it too. A dispatch with `publish=false` skips that job, yet the run still succeeds, so
check the job rather than the run. Then confirm that the commit's `pyproject.toml` has the
version you are tagging:

```sh
gh run list --workflow publish-packages.yml --event workflow_dispatch --limit 5 \
  --json databaseId,headSha,createdAt
gh run view <run id> --json jobs --jq '.jobs[] | "\(.name): \(.conclusion)"'
git fetch origin
git show <full commit SHA>:pyproject.toml | grep '^version'
```

Write the release notes to a file: the changes since the previous tag, the pinned install,
and the SHA-256 digest PyPI lists for each file. `--target` makes GitHub create the tag
at that commit:

```sh
gh release create v2.0.0a2 --target <full commit SHA> --prerelease \
  --title "scaneval 2.0.0a2" --notes-file <notes file>
```

Each tag is `v` followed by the published version. Alphas are GitHub pre-releases.
