#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
api_dir="$repo_root/api"
repo_url="file://${repo_root}"

cd "$api_dir"

perl -0pi -e "s#\"prowler \\(==[^\"]+\\)\"#\"prowler \@ ${repo_url}\"#" pyproject.toml
perl -0pi -e 's#prowler = \{version = "==[^"]+", source = "codeartifact-prowler"\}#prowler = {path = "..", develop = true}#' pyproject.toml

poetry lock
