#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
api_dir="$repo_root/api"

cd "$api_dir"

perl -0pi -e 's#"prowler \(==[^"]+"\)#"prowler @ ../"#; s#prowler = \{version = "==[^"]+", source = "codeartifact-prowler"\}#prowler = {path = "..", develop = true}#' pyproject.toml

poetry lock
