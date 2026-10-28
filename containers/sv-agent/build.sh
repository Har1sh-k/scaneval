#!/bin/sh
# Builds the SV-Agent runtime image into the local engine and prints the image id to pin.
# It never pushes and never pulls anything but the digest-pinned base.
#
#   NODE_DIGEST=sha256:<64 hex> containers/sv-agent/build.sh [tag]
#
# Optional: PLATFORM=linux/arm64 (or linux/amd64) to build for a specific platform; the image
# id it prints is specific to that platform.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
tag=${1:-scaneval-sv-agent:f959cbc-pi1.4.0}

: "${NODE_DIGEST:?set NODE_DIGEST to the digest of node:26.7.0-trixie-slim; see containers/sv-agent/README.md}"
if ! printf '%s\n' "$NODE_DIGEST" | grep -Eq '^sha256:[0-9a-f]{64}$'; then
  echo "NODE_DIGEST must be sha256:<64 lowercase hex>, got: $NODE_DIGEST" >&2
  exit 2
fi

missing=
for name in llm_harness_driver.mts pi_oci_runner.mts pi_open_context.mts; do
  [ -f "$root/src/scaneval/adapters/$name" ] || missing="$missing $name"
done
if [ -n "$missing" ]; then
  echo "src/scaneval/adapters is missing:$missing (the adapter integration must land first)" >&2
  exit 2
fi

iidfile=$(mktemp)
trap 'rm -f "$iidfile"' EXIT

docker build \
  ${PLATFORM:+--platform "$PLATFORM"} \
  -f "$here/Dockerfile" \
  --build-arg "NODE_DIGEST=$NODE_DIGEST" \
  --iidfile "$iidfile" \
  -t "$tag" \
  "$root"

image_id=$(cat "$iidfile")
echo
echo "built $tag"
echo "image id (pin this in the run config): $image_id"
