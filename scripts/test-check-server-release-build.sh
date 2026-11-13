#!/usr/bin/env bash
# Exercise the workflow's provenance gate with GitHub API responses, offline.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
stage=$(mktemp -d "${TMPDIR:-/tmp}/gofree-rel1-provenance.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
cat > "$stage/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == api ]] || exit 99
case "$2" in
  repos/setjoin/setjoin/actions/runs/123) cat "$FAKE_RUN" ;;
  repos/setjoin/setjoin/git/ref/tags/v1.2.3)
    [[ ${FAKE_TAG:-} != missing ]] || exit 1
    printf '{"object":{"type":"%s","sha":"%s"}}\n' "${FAKE_TAG_TYPE:-commit}" "${FAKE_TAG_SHA:-abc}" ;;
  repos/setjoin/setjoin/git/tags/def) printf '{"object":{"type":"commit","sha":"abc"}}\n' ;;
  *) exit 99 ;;
esac
SH
chmod +x "$stage/gh"
export PATH="$stage:$PATH" GITHUB_REPOSITORY=setjoin/setjoin BUILD_RUN_ID=123 FAKE_RUN="$stage/run.json"
valid='{"path":".github/workflows/server-build.yml","event":"push","head_branch":"main","head_sha":"abc","head_repository":{"full_name":"setjoin/setjoin"},"conclusion":"success"}'
printf '%s\n' "$valid" > "$FAKE_RUN"
bash "$ROOT/scripts/check-server-release-build.sh"
echo 'PASS: accepts successful same-repository main push from the server build workflow'
for mutation in \
  '.path = ".github/workflows/other.yml"' \
  '.event = "pull_request"' \
  '.event = "workflow_dispatch"' \
  '.head_branch = "feature"' \
  '.head_repository.full_name = "attacker/setjoin"' \
  '.conclusion = "failure"' \
  '.conclusion = null' \
  'del(.head_repository)' \
  'del(.path)'; do
  jq "$mutation" <<< "$valid" > "$FAKE_RUN"
  if bash "$ROOT/scripts/check-server-release-build.sh"; then
    echo "FAIL: accepted $mutation" >&2
    exit 1
  fi
done
printf 'invalid JSON\n' > "$FAKE_RUN"
if bash "$ROOT/scripts/check-server-release-build.sh" 2>/dev/null; then
  echo 'FAIL: accepted invalid API response' >&2
  exit 1
fi
echo 'PASS: rejects wrong workflow, event, branch, repository, conclusion and malformed responses'
jq '.head_branch = "v1.2.3"' <<< "$valid" > "$FAKE_RUN"
bash "$ROOT/scripts/check-server-release-build.sh"
echo 'PASS: accepts a release tag pointing to the build commit'
FAKE_TAG_TYPE=tag FAKE_TAG_SHA=def bash "$ROOT/scripts/check-server-release-build.sh"
jq '.event = "release" | .head_branch = "v1.2.3"' <<< "$valid" > "$FAKE_RUN"
bash "$ROOT/scripts/check-server-release-build.sh"
for scenario in missing wrong-commit; do
  if FAKE_TAG="$scenario" FAKE_TAG_SHA=bad bash "$ROOT/scripts/check-server-release-build.sh"; then
    echo "FAIL: accepted tag $scenario" >&2
    exit 1
  fi
done
# API failure, missing ID and path/shell injection must never authorize a download.
printf '%s\n' "$valid" > "$FAKE_RUN"
for id in '' '123/../456' '123;exit 0' '456'; do
  if BUILD_RUN_ID="$id" bash "$ROOT/scripts/check-server-release-build.sh" 2>/dev/null; then
    echo "FAIL: accepted run ID $id" >&2
    exit 1
  fi
done
echo 'PASS: annotated tags and release events; rejects missing/mismatched tags and invalid run IDs/API failures'
