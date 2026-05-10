#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$repo_root/dev_scripts/local_env.sh"
load_local_env

cd "$repo_root/api"

echo "Installing API dependencies..."
"$repo_root/dev_scripts/use_local_prowler_package.sh"
poetry install --no-root

echo "Applying API migrations..."
poetry run python src/backend/manage.py check_and_fix_socialaccount_sites_migration --database admin
poetry run python src/backend/manage.py migrate --database admin

echo "Loading API dev fixtures..."
for fixture in src/backend/api/fixtures/dev/*.json; do
  if [[ -f "$fixture" ]]; then
    poetry run python src/backend/manage.py loaddata "$fixture" --database admin
  fi
done

echo "Starting API on port ${DJANGO_PORT}..."
poetry run python src/backend/manage.py runserver 0.0.0.0:"$DJANGO_PORT"
