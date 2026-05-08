#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$repo_root"

set -a
source "$repo_root/.env"
set +a

echo "Starting Docker backing services..."
COMPOSE_PROJECT_NAME=prowler-upstream docker compose -f docker-compose-dev.yml up -d --force-recreate postgres valkey neo4j

echo "Waiting for PostgreSQL..."
until docker exec prowler-upstream-postgres-1 pg_isready -U "$POSTGRES_ADMIN_USER" -d "$POSTGRES_DB" >/dev/null 2>&1; do
  sleep 1
done

echo "Backing services are ready."
