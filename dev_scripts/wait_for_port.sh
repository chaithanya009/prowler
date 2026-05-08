#!/usr/bin/env bash

set -euo pipefail

port="$1"
label="${2:-service}"

echo "Waiting for ${label} on port ${port}..."

for attempt in $(seq 1 600); do
  if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then
    echo "${label} is ready."
    exit 0
  fi

  echo "Attempt ${attempt}: ${label} not ready yet..."
  sleep 1
done

echo "Timed out waiting for ${label} on port ${port}."
exit 1
