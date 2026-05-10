#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/dev_scripts/local_env.sh"
load_local_env

cd "$repo_root/mcp_server"

echo "Starting MCP server on port ${MCP_HOST_PORT:-18000}..."
PROWLER_MCP_TRANSPORT_MODE=http uv run ./entrypoint.sh uvicorn --host 0.0.0.0 --port "${MCP_HOST_PORT:-18000}"
