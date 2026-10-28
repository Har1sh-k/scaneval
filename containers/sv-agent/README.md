# SV-Agent open-context runtime image

The OCI image the SV-Agent adapter runs in when the open-context Pi runtime is selected
(issue #88, [design](../../docs/designs/sv-agent-open-context.md)). Everything a scan executes
is owned by the image. The host provides only the read-only source and history, the writable
state and output mounts, and the credentials declared for that run.

## Layout

| Path | Contents | Pinned by |
|---|---|---|
| `/opt/scaneval/harness` | Clean upstream SV-Agent checkout (`.git` kept: shallow when fetched online, full history from a bundle) with `npm ci` dependencies | `HARNESS_COMMIT` (default `f959cbcf010c7e41f780c718b65b1724d3aecb43`) and the harness's own `package-lock.json` |
| `/opt/scaneval/harness/node_modules/.bin/tsx` | The tsx the driver runs under | harness lockfile (tsx 4.21.0) |
| `/opt/scaneval/node_modules` | `@earendil-works/pi-coding-agent` 1.4.0 and dependencies; `pi` is on `PATH` | `package.json` / `package-lock.json` in this directory |
| `/opt/scaneval/observer/` | Built `sdk/typescript` dist (`index.js`, `index.d.ts`, `package.json`) | `sdk/typescript/package-lock.json` |
| `/opt/scaneval/*.mts`, `*.mjs` | `llm_harness_driver.mts`, `pi_oci_runner.mts`, `pi_open_context.mts` and any sibling Node helpers from `src/scaneval/adapters/` | the commit the image is built from |
| `/opt/scaneval/runtime.json` | Build receipt read by the driver | written at build time from installed files |
| `/usr/bin/git`, `rg`, `fdfind` | Git for original ancestry, and ripgrep/fd so Pi never downloads tools | Debian archive at build time (see below) |

The driver is started as
`/opt/scaneval/harness/node_modules/.bin/tsx /opt/scaneval/llm_harness_driver.mts --config <file>`,
and the research extension is loaded from `/opt/scaneval/pi_open_context.mts`.

### runtime.json

Every value is read from the built filesystem and checked against the build arguments, so
an image is never built when its pieces disagree with what was requested. The file has no
timestamps; identical inputs produce identical bytes.

```json
{
  "schema_version": 1,
  "harness": { "commit": "f959cbcf…", "package_version": "0.1.0", "package_name": "securevibes-agent",
               "repository": "https://github.com/anshumanbh/securevibes-agent.git", "history": "shallow",
               "lockfile_sha256": "sha256:…", "tsx_version": "4.21.0" },
  "pi": { "package": "@earendil-works/pi-coding-agent", "version": "1.4.0",
          "integrity": "sha512-…", "lockfile_sha256": "sha256:…" },
  "node": { "version": "v26.7.0", "platform": "linux", "arch": "arm64",
            "base_image": "node:26.7.0-trixie-slim@sha256:…",
            "base_os": { "id": "debian", "version_id": "13", "codename": "trixie" } },
  "observer": { "package_version": "0.1.0-experimental", "files": { "index.js": "sha256:…" } },
  "adapters": { "llm_harness_driver.mts": "sha256:…", "pi_oci_runner.mts": "sha256:…",
                "pi_open_context.mts": "sha256:…" },
  "os_packages": { "ca-certificates": "…", "fd-find": "…", "git": "…", "ripgrep": "…" }
}
```

The build fails if the harness `HEAD` differs from `HARNESS_COMMIT`, the installed Pi version
differs from 1.4.0 or from the lockfile, `node --version` is not v26.7.0, or any of the three
required adapter files is missing.

## Building

Prerequisites:

1. The adapter integration has landed, so `src/scaneval/adapters/` contains
   `llm_harness_driver.mts`, `pi_oci_runner.mts` and `pi_open_context.mts`. Before then
   `build.sh` and the Dockerfile refuse to build: an image without the research extension
   would misrepresent open_context.
2. The digest of the Node base. There is no default and no moving tag. Resolve it once and
   record it with the run:

   ```sh
   docker buildx imagetools inspect node:26.7.0-trixie-slim --format '{{.Manifest.Digest}}'
   # or: docker pull node:26.7.0-trixie-slim && docker image inspect --format '{{index .RepoDigests 0}}' node:26.7.0-trixie-slim
   ```

   This gives the multi-platform index digest. The build selects the platform from it, so pass
   `--platform` (or `PLATFORM=` to `build.sh`) when the build host differs from the scan host.
   If the digest belongs to another Debian-based `node:26.7.0-*` tag, for example
   `bookworm-slim`, also pass `--build-arg NODE_IMAGE=<that tag>` (or `NODE_IMAGE=` to
   `build.sh`). Otherwise the receipt names the wrong tag. `base_os` in the receipt is read from
   the image itself either way.
3. Network access during the build to the Debian archive and registry.npmjs.org. The harness
   commit is fetched with `git fetch --depth 1 origin <sha>`, which works whenever the
   repository is publicly reachable from the builder. Otherwise supply it as a Git bundle (see
   [Harness from a Git bundle](#harness-from-a-git-bundle)). Scans themselves install nothing.
4. BuildKit (the default builder in current Docker), which provides the
   `Dockerfile.dockerignore` allowlist and the build-time bind mount for the receipt script.

Build from the repository root:

```sh
NODE_DIGEST=sha256:<digest> containers/sv-agent/build.sh            # tag scaneval-sv-agent:f959cbc-pi1.4.0
# equivalent to:
docker build -f containers/sv-agent/Dockerfile \
  --build-arg NODE_DIGEST=sha256:<digest> \
  -t scaneval-sv-agent:f959cbc-pi1.4.0 .
```

### Harness from a Git bundle

When the builder cannot fetch the harness anonymously (the build has no GitHub credentials and
must not be given any), create a bundle on a host that can, from a clean, authenticated,
full-history checkout:

```sh
cd /path/to/securevibes-agent                       # clean checkout with full history
test "$(git rev-parse --is-shallow-repository)" = false || git fetch --unshallow
git checkout --detach f959cbcf010c7e41f780c718b65b1724d3aecb43
git rev-parse HEAD                                  # must print the HARNESS_COMMIT pin
git bundle create /some/private/path/harness.bundle HEAD
git bundle list-heads /some/private/path/harness.bundle   # <HARNESS_COMMIT> HEAD
```

Then build with it:

```sh
HARNESS_BUNDLE=/some/private/path/harness.bundle NODE_DIGEST=sha256:<digest> containers/sv-agent/build.sh
# equivalent to adding: --secret id=harness_bundle,src=/some/private/path/harness.bundle
```

- The build fetches `HEAD` from the bundle and fails unless it is exactly `HARNESS_COMMIT`;
  there is no way to substitute another commit. The checkout is the bundle's actual Git
  objects, and `runtime.json` records the commit read from it plus `"history": "full"`.
- A bundle made from a shallow clone lists prerequisite commits that the build cannot have, so
  the fetch fails its connectivity check. Run `git fetch --unshallow` before bundling.
  `git bundle verify <path>` on the host reports such prerequisites.
- The bundle reaches the build only as a BuildKit secret mount for the single fetch step. It is
  not in the build context (`Dockerfile.dockerignore` excludes everything not listed), not in
  any layer, and not in the image config. No `.git/config`, credential store or token is
  involved. Keep the bundle outside this repository and never commit it.
- `build.sh` requires an existing readable regular file and rejects paths containing `,` or
  `"`, which docker's `--secret` option cannot carry.

With a `docker-container` buildx driver, add `--load` so the image lands in the local engine.
Never push the image. The OCI backend runs with `--pull never` and only uses images already
present locally.

### Pinning the built image

A tag is a convenience and can move. Pin the image ID in the run config:

```sh
docker image inspect --format '{{.Id}}' scaneval-sv-agent:f959cbc-pi1.4.0   # sha256:…
```

The OCI backend accepts the bare `sha256:<id>` as the image reference and checks it against
the engine's image ID. Check the receipt the scan will see with:

```sh
docker run --rm --read-only --user 65534:65534 --network none \
  --entrypoint cat sha256:<id> /opt/scaneval/runtime.json
```

## Runtime contract

The image's defaults match what `scaneval.isolation.oci` imposes on every worker: `--read-only`,
`--user 65534:65534`, all capabilities dropped, and a `nosuid,nodev,noexec` tmpfs on `/tmp`.

- `ENTRYPOINT` is cleared and `CMD` is `node --version`. The backend always supplies
  `--entrypoint`, so nothing runs implicitly.
- `HOME=/tmp`, `PI_CODING_AGENT_DIR=/tmp/pi-agent` and `WORKDIR /tmp`. uid 65534 has no home
  directory, and the rest of the filesystem is read-only. The runner should still give Pi its
  own per-call agent directory and session directory on the tmpfs.
- `/tmp` is `noexec`. Nothing may need to execute from it. Pi's `grep`/`find` tools find the
  system `rg` and `fdfind`, so they never try to download binaries. tsx only writes its
  compile cache there, which is fine.
- `PI_SKIP_VERSION_CHECK=1`, so Pi makes no latest-version request during a scan. Two other
  settings are deliberately left to the runner because they change what Pi sends:
  - `PI_TELEMETRY`: in Pi 1.4.0 it decides whether provider requests carry Pi's attribution
    headers (`core/client-identity.js`), as well as interactive install telemetry. Leaving it
    unset keeps upstream's default request shape. If the runner sets it, record it as a
    transport difference.
  - `PI_OFFLINE` / `--offline`: this also stops the remote model-catalog refresh, so the route
    resolves from Pi 1.4.0's built-in catalog. That fits "never auto-update inside a scan",
    provided the requested model is in that catalog.
- Git has `safe.directory = *` in `/etc/gitconfig`. Bind-mounted sources are owned by a host
  uid, and git under uid 65534 would otherwise refuse to read their history.
- The upstream harness checkout contains `.pi/extensions/securevibes/`. Pi must not run with
  `/opt/scaneval/harness` as its working directory unless discovery is disabled. The runner
  disables ambient extension discovery and loads only `/opt/scaneval/pi_open_context.mts`.

### Proxy

Node v26.7.0 needs no extra flags.

- Pi installs undici's `EnvHttpProxyAgent` as its global dispatcher, so provider inference
  follows `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` as set by the OCI backend.
- The image sets `NODE_USE_ENV_PROXY=1`, so Node's built-in `fetch`/`http` honor the same
  variables in the driver and in any process that has not replaced the global dispatcher.
  This is the env form of `node --use-env-proxy`.
- A host-local `SCANEVAL_RETRIEVAL_URL` is reached only if `NO_PROXY` lists it. The backend
  manages `NO_PROXY` itself.

### Credentials

The image contains no credentials, Pi `auth.json`, settings or sessions. Pi auth arrives per
run through the backend's declared credential injection (`--env NAME`, value from the host
environment). Never mount the operator's `~/.pi/agent`. Any auth file the runner materializes
lives under `/tmp` and disappears with the container.

## Reproducibility

- **Pinned exactly:** the Node base (digest), the harness commit and its npm lockfile, Pi and
  every transitive package (this directory's lockfile, verified by `npm ci`), the observer
  SDK's dev toolchain (its lockfile), and the adapter sources (the build commit, hashed into
  `runtime.json`). Pi's own `protobufjs` 7.6.6 override is repeated in `package.json`, because
  npm applies overrides only from the root manifest.
- **Not individually reproducible:** the Debian packages `git`, `ca-certificates`, `ripgrep`
  and `fd-find` come from the live archive at build time. Their installed versions are
  recorded in `runtime.json`.
- **The final image ID freezes the actual bytes.** Two builds from the same inputs may differ,
  but a scan pinned to an image ID always runs the same runtime.

To regenerate the Pi lockfile after a deliberate version change, edit `package.json` and run
`npm install --package-lock-only --ignore-scripts` in this directory.
