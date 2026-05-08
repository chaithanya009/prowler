#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/dev_scripts/local_env.sh"
load_local_env

cd "$repo_root/ui"

echo "Installing UI dependencies..."
pnpm install

echo "Starting UI on port ${UI_HOST_PORT:-13000}..."
PORT="${UI_HOST_PORT:-13000}" pnpm run dev
