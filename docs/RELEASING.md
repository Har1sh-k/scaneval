# Publishing alpha packages

The release artifacts are the `scaneval` Python wheel/source archive and the
`@scaneval/observer` npm tarball. The Python Observer ships in the Python distribution;
the TypeScript Observer has its own package version. Both currently emit trace schema `2.0`.

The first release versions are `scaneval==2.0.0a1` and
`@scaneval/observer@0.1.0-alpha.1`. npm publication uses the `next` tag. These are alpha
packages; the README's scanner, corpus-label, and live-runtime limits still apply.

## Build and inspect locally

Use a clean checkout of the reviewed release commit:

```sh
python -m pip install build twine
python -m build --outdir /tmp/scaneval-python-dist
python -m twine check --strict /tmp/scaneval-python-dist/*
for artifact in /tmp/scaneval-python-dist/*; do
  python scripts/check_python_package.py "$artifact"
done

npm ci --prefix sdk/typescript --ignore-scripts
npm test --prefix sdk/typescript
npm run test:package --prefix sdk/typescript
```

The Python check installs each exact artifact into a new environment, verifies the Observer
and packaged resources, and runs the fabricated demo/replay from an empty directory. The npm
check packs the SDK, installs that tarball into an isolated consumer with scripts disabled,
runs the package README example, and checks ESM behavior and TypeScript declarations.
The SDK's `prepack` hook builds `dist/`; the tarball contains JavaScript, declarations, README,
LICENSE, and package metadata. No model is called by these checks.

Inspect archive contents before upload. Source caches, run bundles, credentials, traces,
local dependency trees, and generated output do not belong in either distribution.

## One-time registry ownership and authentication

The repository's GitHub authentication does not grant access to npm or PyPI. Confirm control
of the npm `@scaneval` scope and the PyPI `scaneval` project name with the publishing accounts.
Do not commit registry credentials or paste passwords/tokens into issues or chat.

### PyPI, including the first release

In the publishing account's PyPI settings, add a pending GitHub Trusted Publisher for a new
project (or a publisher on the existing project):

| Field | Value |
|---|---|
| PyPI project | `scaneval` |
| Owner | `Har1sh-k` |
| Repository | `scaneval` |
| Workflow filename | `publish-packages.yml` |
| Environment | `pypi` |

The GitHub environment is `pypi`. No long-lived PyPI token is needed by the workflow. The
first successful pending-publisher upload creates the project; configuring a pending publisher
alone does not reserve its name. See [PyPI's first-release instructions](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

### npm

For the initial npm package creation, an account with access to `@scaneval` must authenticate
with npm and complete its required two-factor challenge. Publish the verified tarball with
public access and `next` explicitly selected:

```sh
npm login --registry=https://registry.npmjs.org/
npm publish /path/to/scaneval-observer-0.1.0-alpha.1.tgz --ignore-scripts --access public --tag next
```

Once the npm package exists, configure a GitHub Trusted Publisher in its package settings:

| Field | Value |
|---|---|
| Organization or user | `Har1sh-k` |
| Repository | `scaneval` |
| Workflow filename | `publish-packages.yml` |
| Environment | `npm` |
| Allowed action | Direct `npm publish` |

The workflow's publish job uses Node 24 and an explicitly selected OIDC-capable npm CLI.
Trusted publishing generates provenance for this public repository/package. See
[npm's trusted-publishing guide](https://docs.npmjs.com/trusted-publishers/).
If setup was created but not used promptly, check npm's expiry policy before a later release.

## Release workflow

`.github/workflows/publish-packages.yml` builds and tests artifacts on relevant pull requests
and pushes. SDK artifact checks run on Node 22, 24, and 26. Both Python artifacts are installed
and exercised independently. The unprivileged build jobs upload the exact verified files.

Publication happens only on a manual workflow dispatch with `publish=true`, from `main`,
after the regular `CI` workflow has passed for that exact main commit. Publish jobs receive
OIDC permission separately from build jobs and use their registry's GitHub environment.
Configure those environments to allow deployments from `main` only.

```sh
# Build/verify only; no registry upload.
gh workflow run publish-packages.yml --ref main -f registry=both -F publish=false

# Publish after the one-time registry setup is complete.
gh workflow run publish-packages.yml --ref main -f registry=both -F publish=true
```

Use `registry=pypi` when bootstrapping PyPI after a successful manual npm upload, or
`registry=npm` for an npm-only follow-up. Package versions are immutable once published;
increment the version for every subsequent release. A second successful upload of the same
version is not a verification strategy.

After publication, verify registry versions/tags and perform fresh installs using the public
registry names. Pin an exact alpha version for reproducible integrations.
