#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CACHE_DIR="${1:-$ROOT_DIR/.npm-cache}"

mkdir -p "$CACHE_DIR"

docker run --rm \
  -v "$ROOT_DIR:/workspace" \
  -v "$CACHE_DIR:/npm-cache" \
  -w /workspace/dashboard \
  node:22-bookworm-slim \
  bash -lc "npm ci --cache /npm-cache --prefer-offline --no-audit --no-fund"

echo "Offline npm cache prepared in: $CACHE_DIR"
echo "To build dashboard offline with Docker:"
echo "  NPM_INSTALL_MODE=offline docker compose build dashboard"
