# SV-Agent open-context runtime image (issue #88).
#
# Build from the repository root so the observer SDK and adapter sources are in context:
#   docker build -f containers/sv-agent/Dockerfile \
#     --build-arg NODE_DIGEST=sha256:<index digest of node:26.7.0-trixie-slim> \
#     -t scaneval-sv-agent:f959cbc-pi1.4.0 .
# See README.md next to this file for resolving the digest and pinning the built image id.
#
# Everything the scan executes is image-owned under /opt/scaneval:
#   harness/                  clean upstream SV-Agent checkout at HARNESS_COMMIT, npm ci'd
#   harness/node_modules/.bin/tsx
#   node_modules/             Pi 1.4.0 and its locked dependencies (bin on PATH)
#   observer/                 built sdk/typescript dist
#   *.mts, *.mjs              driver, OCI runner, research extension and sibling helpers
#   runtime.json              build receipt read by the driver
# No credentials, Pi auth, host node_modules, evaluator code, corpus or results enter a layer.

# The base must be pinned by digest. There is deliberately no default: an empty NODE_DIGEST
# makes the reference below invalid and the build stops.
ARG NODE_IMAGE=node:26.7.0-trixie-slim
ARG NODE_DIGEST

FROM ${NODE_IMAGE}@${NODE_DIGEST} AS base
# Debian packages come from the live archive and are not individually reproducible; their
# installed versions are recorded in runtime.json and the final image digest freezes the bytes.
# ripgrep and fd-find are installed so Pi's grep/find tools never download binaries at scan time.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git ripgrep fd-find \
 && rm -rf /var/lib/apt/lists/*

FROM base AS harness
ARG HARNESS_REPOSITORY=https://github.com/anshumanbh/securevibes-agent.git
ARG HARNESS_COMMIT=f959cbcf010c7e41f780c718b65b1724d3aecb43
WORKDIR /opt/scaneval/harness
# Fetch exactly one immutable commit; no branch name is resolved.
RUN git init -q . \
 && git remote add origin "$HARNESS_REPOSITORY" \
 && git fetch -q --depth 1 origin "$HARNESS_COMMIT" \
 && git -c advice.detachedHead=false checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$HARNESS_COMMIT" \
 && test -z "$(git status --porcelain)"
# The upstream lockfile pins the tree. tsx is a devDependency, so dev packages stay. Install
# scripts are skipped: the only ones are esbuild's binary check and fsevents (macOS only), and
# esbuild resolves its locked @esbuild/linux-* package at run time.
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && test -x node_modules/.bin/tsx \
 && test -z "$(git status --porcelain)" \
 && rm -rf /root/.npm

FROM base AS observer
WORKDIR /build/observer
COPY sdk/typescript/package.json sdk/typescript/package-lock.json sdk/typescript/tsconfig.json ./
COPY sdk/typescript/src ./src
RUN npm ci --ignore-scripts --no-audit --no-fund \
 && npm run build \
 && cp package.json dist/

FROM base AS pi
WORKDIR /opt/scaneval
COPY containers/sv-agent/package.json containers/sv-agent/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund --engine-strict \
 && rm -rf /root/.npm

FROM base AS adapters
# Dockerfile.dockerignore admits only the top-level *.mts/*.mjs adapter sources; the find
# below keeps the runtime image to exactly those even if the ignore file drifts.
COPY src/scaneval/adapters/ /build/adapters/
RUN mkdir /build/out \
 && find /build/adapters -maxdepth 1 -type f \( -name '*.mts' -o -name '*.mjs' \) -exec cp {} /build/out/ \; \
 && for name in llm_harness_driver.mts pi_oci_runner.mts pi_open_context.mts; do \
      test -f "/build/out/$name" || { echo "missing src/scaneval/adapters/$name" >&2; exit 1; }; \
    done

FROM base AS runtime
ARG NODE_IMAGE
ARG NODE_DIGEST
ARG HARNESS_REPOSITORY=https://github.com/anshumanbh/securevibes-agent.git
ARG HARNESS_COMMIT=f959cbcf010c7e41f780c718b65b1724d3aecb43
ARG EXPECT_NODE_VERSION=v26.7.0
ARG EXPECT_PI_VERSION=1.4.0

COPY --from=pi /opt/scaneval/ /opt/scaneval/
COPY --from=harness /opt/scaneval/harness/ /opt/scaneval/harness/
COPY --from=observer /build/observer/dist/ /opt/scaneval/observer/
COPY --from=adapters /build/out/ /opt/scaneval/

# Bind-mounted sources are owned by a host uid, and git refuses a repository owned by another
# user unless it is listed here. Only system/global/command-line config can set this.
RUN git config --system --add safe.directory '*'

# Verifies every pinned identity against what was installed, then writes runtime.json. Pi runs
# once, and tsx transforms one TypeScript file so the esbuild binary is actually loaded, both
# with a throwaway HOME so no config or cache lands in the layer. Ownership and modes are fixed
# only where they deviate, so the subtree is not rewritten into a second layer.
RUN --mount=type=bind,source=containers/sv-agent/write-runtime-receipt.mjs,target=/run/scaneval/write-runtime-receipt.mjs \
    NODE_IMAGE="$NODE_IMAGE" NODE_DIGEST="$NODE_DIGEST" \
    HARNESS_REPOSITORY="$HARNESS_REPOSITORY" HARNESS_COMMIT="$HARNESS_COMMIT" \
    EXPECT_NODE_VERSION="$EXPECT_NODE_VERSION" EXPECT_PI_VERSION="$EXPECT_PI_VERSION" \
    node /run/scaneval/write-runtime-receipt.mjs \
 && scratch="$(mktemp -d)" \
 && test "$(HOME="$scratch" PI_CODING_AGENT_DIR="$scratch/pi" PI_OFFLINE=1 /opt/scaneval/node_modules/.bin/pi --version)" = "$EXPECT_PI_VERSION" \
 && printf 'const n: number = 1;\nconsole.log(n);\n' > "$scratch/check.ts" \
 && test "$(HOME="$scratch" TMPDIR="$scratch" /opt/scaneval/harness/node_modules/.bin/tsx "$scratch/check.ts")" = 1 \
 && rm -rf "$scratch" \
 && find /opt/scaneval ! -user root -exec chown -h root:root {} + \
 && find /opt/scaneval ! -type l -perm /022 -exec chmod go-w {} + \
 && find /opt/scaneval -type f ! -perm -444 -exec chmod a+r {} + \
 && find /opt/scaneval -type d ! -perm -555 -exec chmod a+rx {} +

LABEL org.opencontainers.image.title="scaneval-sv-agent" \
      org.opencontainers.image.description="SV-Agent harness with Pi for ScanEval open-context scans" \
      dev.scaneval.harness.commit="${HARNESS_COMMIT}" \
      dev.scaneval.pi.version="${EXPECT_PI_VERSION}" \
      dev.scaneval.node.base="${NODE_IMAGE}@${NODE_DIGEST}"

# The OCI backend runs with --read-only, a noexec /tmp tmpfs and --user 65534:65534; the defaults
# below match that. Pi's provider traffic goes through undici's EnvHttpProxyAgent, which already
# honors HTTP(S)_PROXY/NO_PROXY; NODE_USE_ENV_PROXY makes Node's own fetch/http do the same for
# the driver and extension. PI_TELEMETRY is deliberately not set: in Pi 1.4.0 it also decides
# whether provider requests carry attribution headers, which is the runner's transport choice.
# Pi auth is never set here: it arrives per run as a declared credential environment variable.
ENV PATH=/opt/scaneval/node_modules/.bin:$PATH \
    HOME=/tmp \
    PI_CODING_AGENT_DIR=/tmp/pi-agent \
    PI_SKIP_VERSION_CHECK=1 \
    NODE_USE_ENV_PROXY=1 \
    NPM_CONFIG_UPDATE_NOTIFIER=false

USER 65534:65534
WORKDIR /tmp
# The OCI backend always supplies --entrypoint; clear the base image's wrapper so nothing runs
# implicitly when the image is used directly.
ENTRYPOINT []
CMD ["node", "--version"]
