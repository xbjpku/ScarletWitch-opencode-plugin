#!/bin/bash
# Build ScarletWitch supervisor + preload from source.
# Runs automatically after `bun install` / `npm install`.

set -e

DIR="$(cd "$(dirname "$0")/.." && pwd)"
SW="$DIR/scarletwitch"

if [ ! -d "$SW/supervisor" ]; then
  echo "[scarletwitch-opencode] ScarletWitch submodule not found. Run: git submodule update --init"
  exit 0
fi

echo "[scarletwitch-opencode] Building ScarletWitch..."
cd "$SW"

# Build supervisor (Rust) + preload (C)
if command -v make &>/dev/null; then
  make 2>&1 | sed 's/^/  /'
  echo "[scarletwitch-opencode] Build complete: $SW/build/"
else
  echo "[scarletwitch-opencode] 'make' not found — skipping build. Pre-built binaries in build/ will be used if available."
fi
