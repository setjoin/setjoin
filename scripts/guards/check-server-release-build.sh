#!/usr/bin/env bash
# Fail closed before downloading an inventory onto the signing runner.
set -euo pipefail
: "${GITHUB_REPOSITORY:?repository is required}" "${BUILD_RUN_ID:?build run is required}"
[[ "$BUILD_RUN_ID" =~ ^[0-9]+$ ]] || { echo 'invalid build run ID' >&2; exit 1; }
run=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$BUILD_RUN_ID")
jq -e --arg repo "$GITHUB_REPOSITORY" '
    .path == ".github/workflows/server-build.yml" and
    (.event == "push" or .event == "release") and
    (.head_branch == "main" or (.head_branch | startswith("v"))) and
    .head_repository.full_name == $repo and
    .conclusion == "success"
  ' <<< "$run" > /dev/null
branch=$(jq -r '.head_branch' <<< "$run")
if [[ "$branch" != main ]]; then
  # A v-prefixed branch alone is insufficient: resolve the actual repository tag
  # (including annotated tags) and bind it to this run's commit.
  tag=$(jq -r '.head_branch | @uri' <<< "$run")
  ref=$(gh api "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag")
  for _ in {1..8}; do
    kind=$(jq -er '.object.type' <<< "$ref")
    sha=$(jq -er '.object.sha' <<< "$ref")
    [[ "$sha" =~ ^[0-9a-f]+$ ]] || exit 1
    if [[ "$kind" == commit ]]; then
      [[ "$sha" == "$(jq -r '.head_sha' <<< "$run")" ]]
      exit
    fi
    [[ "$kind" == tag ]] || exit 1
    ref=$(gh api "repos/$GITHUB_REPOSITORY/git/tags/$sha")
  done
  echo 'release tag could not be resolved to a commit' >&2
  exit 1
fi
