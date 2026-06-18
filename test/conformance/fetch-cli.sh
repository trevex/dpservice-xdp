#!/usr/bin/env bash
# Build dpservice-cli from source (dpservice v0.3.22 cli/dpservice-cli).
# Requires: go (available via nix develop)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DST="$(cd "$(dirname "$0")" && pwd)/bin"
mkdir -p "$DST"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

git clone --depth 1 --branch v0.3.22 https://github.com/ironcore-dev/dpservice "$TMP/dpservice"
( cd "$TMP/dpservice/cli/dpservice-cli" && nix develop "$REPO_ROOT" -c go build -o "$DST/dpservice-cli" . )
"$DST/dpservice-cli" -v
