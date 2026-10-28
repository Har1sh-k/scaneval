#!/bin/sh
# Builds the SV-Agent runtime image into the local engine and prints the image id to pin.
# It never pushes and never pulls anything but the digest-pinned base.
#
#   NODE_DIGEST=sha256:<64 hex> containers/sv-agent/build.sh [tag]
#
# Optional: PLATFORM=linux/arm64 (or linux/amd64) to build for a specific platform; the image
# id it prints is specific to that platform. NODE_IMAGE=node:26.7.0-bookworm-slim (or another
# Debian-based node:26.7.0 tag) when the digest belongs to a tag other than the default
# node:26.7.0-trixie-slim, so the receipt names the tag the digest was resolved from.
# HARNESS_BUNDLE=/private/path/harness.bundle to take the harness commit from a full-history
# `git bundle` instead of fetching it from GitHub; see README.md. It is passed as a BuildKit
# secret, so it never enters the build context or a layer.
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

if [ -n "${HARNESS_BUNDLE:-}" ]; then
  if [ ! -f "$HARNESS_BUNDLE" ] || [ ! -r "$HARNESS_BUNDLE" ]; then
    echo "HARNESS_BUNDLE must be a readable regular file, got: $HARNESS_BUNDLE" >&2
    exit 2
  fi
  # docker parses --secret as CSV, so these characters would split or quote the path.
  case $HARNESS_BUNDLE in
    *,* | *\"*) echo "HARNESS_BUNDLE must not contain ',' or '\"', got: $HARNESS_BUNDLE" >&2; exit 2 ;;
  esac
fi

iidfile=$(mktemp)
trap 'rm -f "$iidfile"' EXIT

docker build \
  ${PLATFORM:+--platform "$PLATFORM"} \
  -f "$here/Dockerfile" \
  ${NODE_IMAGE:+--build-arg "NODE_IMAGE=$NODE_IMAGE"} \
  --build-arg "NODE_DIGEST=$NODE_DIGEST" \
  ${HARNESS_BUNDLE:+--secret "id=harness_bundle,src=$HARNESS_BUNDLE"} \
  --iidfile "$iidfile" \
  -t "$tag" \
  "$root"

image_id=$(cat "$iidfile")
echo
echo "built $tag"
echo "image id (pin this in the run config): $image_id"
