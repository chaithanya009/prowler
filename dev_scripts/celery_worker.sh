#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/dev_scripts/local_env.sh"
load_local_env

cd "$repo_root/api/src/backend"

echo "Starting Celery worker..."
poetry run python -m celery -A config.celery worker \
  -l "${DJANGO_LOGGING_LEVEL:-info}" \
  -Q celery,scans,scan-reports,deletion,backfill,overview,integrations,compliance,attack-paths-scans \
  -E --max-tasks-per-child 1
