#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

load_local_env() {
  set -a
  source "$repo_root/.env"
  set +a

  export DJANGO_SETTINGS_MODULE=config.django.devel
  export DJANGO_PORT="${DJANGO_HOST_PORT:-18080}"
  export POSTGRES_HOST=127.0.0.1
  export POSTGRES_PORT="${POSTGRES_HOST_PORT:-15432}"
  export VALKEY_HOST=127.0.0.1
  export VALKEY_PORT="${VALKEY_HOST_PORT:-16379}"
  export NEO4J_HOST=127.0.0.1
  export NEO4J_PORT="${NEO4J_HOST_PORT:-17687}"
  export API_BASE_URL="http://127.0.0.1:${DJANGO_PORT}/api/v1"
  export NEXT_PUBLIC_API_BASE_URL="$API_BASE_URL"
  export NEXT_PUBLIC_API_DOCS_URL="${API_BASE_URL}/docs"
  export PROWLER_MCP_SERVER_URL="http://127.0.0.1:${MCP_HOST_PORT:-18000}/mcp"
}

read_env_value() {
  local key="$1"
  local fallback="$2"
  local value

  value="$(grep -E "^${key}=" "$repo_root/.env" 2>/dev/null | tail -n 1 | cut -d= -f2- | tr -d '"')" || true

  if [[ -n "$value" ]]; then
    printf "%s" "$value"
    return
  fi

  printf "%s" "$fallback"
}
