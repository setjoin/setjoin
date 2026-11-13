#!/usr/bin/env bash
# Shared preamble for all scripts in this directory.
# Source at the top of each script: source "$(dirname "$0")/_base.sh"
set -euo pipefail
# Consumers use ROOT after sourcing this file; ShellCheck cannot see across that boundary.
# shellcheck disable=SC2034
ROOT="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"
