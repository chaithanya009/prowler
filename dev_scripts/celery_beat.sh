#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$repo_root/dev_scripts/local_env.sh"
load_local_env

cd "$repo_root/api/src/backend"

echo "Starting Celery beat..."
poetry run python -m celery -A config.celery beat -l "${DJANGO_LOGGING_LEVEL:-info}" --scheduler django_celery_beat.schedulers:DatabaseScheduler
