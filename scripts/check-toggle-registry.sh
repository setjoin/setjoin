#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-toggle-registry.sh — feature-toggle default-registry invariants.
#
# WHY. Every feature toggle's default is declared ONCE in the immutable sorted
# shared/toggle Definition registry and read through ONE path
# (FeatureFlags.IsEnabled). Before the registry, the default lived at every
# call site as IsEnabledDefault(key, false) — one site reading the same flag
# through IsEnabled (unknown→true) produced a split-brain read of a single
# security toggle (the FeatureConditionalAccess divergence, fixed f3599f40).
#
# INVARIANTS:
#  1. REGISTRY — every toggle-key constant declared in toggle.go has
#     an entry in definitions (the complementary direction — a registry
#     key with no constant — is TestRegistryCoversAllConstants in Go).
#  2. LITERALS — no non-test Go file outside shared/toggle/ passes a raw
#     registered-prefix string literal to IsEnabled/IsEnabledDefault. All
#     current families, including auth providers, are finite and typed.
#     _test.go files are exempt.
#
# Usage: scripts/check-toggle-registry.sh [--self-test]
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

TOGGLE_GO="$ROOT/shared/toggle/toggle.go"
GO_TREE="$ROOT"

fail=0

# Invariant 1: every Feature* constant name in toggle.go appears in registryDefaults.
check_registry_coverage() {
  local consts registry missing rc=0
  consts=$(grep -oE '^\s*[A-Z][A-Za-z0-9]+\s*=\s*"(feature|approval|chat|dengbao|device|drive|meet|rbac|sharing)[._]' "$TOGGLE_GO" | grep -oE '^[[:space:]]*[A-Z][A-Za-z0-9]+' | sed 's/^[[:space:]]*//' | sort -u)
  registry=$(sed -n '/^var definitions = \[\]Definition{/,/^}/p' "$TOGGLE_GO" \
               | grep -oE '^\s*\{[A-Z][A-Za-z0-9]+,' | sed 's/^[[:space:]]*{//; s/,$//' | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$consts") <(printf '%s\n' "$registry"))
  if [ -n "$missing" ]; then
    while IFS= read -r c; do
      echo "  [TOGGLE] constant $c is declared in shared/toggle/toggle.go but missing from definitions — declare its exact default in the registry." >&2
    done <<< "$missing"
    rc=1
  fi
  return $rc
}

# Invariant 2: raw feature.*/dengbao.* literal passed to IsEnabled/IsEnabledDefault
# outside shared/toggle/ (non-test files).
# File walk is find-based (NOT `grep -r`): the recursive mode of some grep
# builds (ugrep) silently truncates the tree, which would let offenders pass.
check_raw_literals() {
  local files hits line key rc=0
  files=$(find "$GO_TREE" \
            -type d \( -name node_modules -o -name .git -o -name worktrees -o -name _archive \) -prune \
            -o -type f -name '*.go' ! -name '*_test.go' ! -path '*/shared/toggle/*' -print)
  [ -z "$files" ] && return 0
  hits=$(printf '%s\n' "$files" \
         | xargs grep -nE 'IsEnabled(Default)?\(\s*"(feature|approval|chat|dengbao|device|drive|meet|rbac|sharing)[._][a-z_.]*"?' 2>/dev/null) || true
  [ -z "$hits" ] && return 0
  while IFS= read -r line; do
    key=$(printf '%s' "$line" | grep -oE '"(feature|approval|chat|dengbao|device|drive|meet|rbac|sharing)[._][a-z_.]*' | head -1 | tr -d '"')
    echo "  [TOGGLE] raw toggle-key literal used with IsEnabled: ${line%%:*}:$(printf '%s' "$line" | cut -d: -f2) key=$key — use the declared toggle constant." >&2
    rc=1
  done <<< "$hits"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/tree/pkg"
  # Synthetic toggle.go: FeatureOrphan declared but absent from the registry.
  cat > "$tmp/toggle.go" <<'EOF'
const (
	FeatureAlpha  = "feature.alpha"
	FeatureOrphan = "feature.orphan"
)
var definitions = []Definition{
	{FeatureAlpha, true},
}
EOF
  # Synthetic offenders: a raw declared-style key (must fire) and an
  # a second raw key (must also fire).
  cat > "$tmp/tree/pkg/offender.go" <<'EOF'
package pkg
func x(t T) bool { return t.IsEnabled("feature.orphan") }
func y(t T) bool { return t.IsEnabledDefault("dengbao.sod_mode", false) }
func z(t T) bool { return t.IsEnabled("feature.spf") }
EOF
  TOGGLE_GO="$tmp/toggle.go" GO_TREE="$tmp/tree"
  cov_rc=0; check_registry_coverage >/dev/null 2>&1 || cov_rc=$?
  lit_rc=0; check_raw_literals >/dev/null 2>&1 || lit_rc=$?
  # And a clean constant-based tree must pass.
  cat > "$tmp/tree/pkg/offender.go" <<'EOF'
package pkg
func z(t T) bool { return t.IsEnabled(toggle.FeatureSPF) }
EOF
  clean_rc=0; check_raw_literals >/dev/null 2>&1 || clean_rc=$?
  if [ $cov_rc -ne 0 ] && [ $lit_rc -ne 0 ] && [ $clean_rc -eq 0 ]; then
    echo "E_TOGGLE_REGISTRY_DRIFT problem=planted_unregistered_key cause=definition_or_callsite_bypasses_registry value=feature.orphan fix='register the finite key and use its typed constant' rerun='bash scripts/check-toggle-registry.sh'" >&2
    echo "check-toggle-registry self-test: OK (fires on unregistered constant + every raw literal; constant use passes)"
    exit 0
  fi
  echo "check-toggle-registry SELF-TEST FAILED: coverage=$cov_rc(want!=0) literals=$lit_rc(want!=0) clean=$clean_rc(want 0)" >&2
  exit 1
fi

echo "==> Toggle-registry guard: constant→registry coverage + raw-literal reads"
check_registry_coverage || fail=1
check_raw_literals || fail=1
if ! (cd "$ROOT" && go run ./shared/toggle/cmd/feature-registry-gen --check); then
  fail=1
fi
if [ $fail -ne 0 ]; then
  echo "Toggle-registry guard FAILED (see above)." >&2
  exit 1
fi
echo "    Toggle-registry guard: clean."
