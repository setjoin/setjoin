#!/usr/bin/env bash
source "$(dirname "$0")/_base.sh"
set -euo pipefail

(cd "$ROOT/mailserver" && go run ./cmd/unit-catalog-gen --check)
(cd "$ROOT/mailserver" && go test ./internal/deploycatalog -count=1)

# shellcheck source=../mailserver/deploy/generated/unit-catalog.sh
source "$ROOT/mailserver/deploy/generated/unit-catalog.sh"
for unit in "${SETJOIN_ALL_UNITS[@]}"; do
  template="$ROOT/mailserver/deploy/${SETJOIN_UNIT_TEMPLATE[$unit]}"
  renderer="${SETJOIN_UNIT_RENDERER[$unit]}"
  [ -f "$template" ] || { echo "E_ARCH_R4_UNITS_TEMPLATE missing=$template" >&2; exit 1; }
  grep -Eq "^${renderer}\(\)" "$ROOT/mailserver/deploy/scripts/lib-livekit.sh" || {
    echo "E_ARCH_R4_UNITS_RENDERER missing=$renderer unit=$unit" >&2
    exit 1
  }
done

bash "$ROOT/mailserver/deploy/scripts/test-setjoin-lifecycle.sh"

if [[ "${1:-}" == "--self-test" ]]; then
  mutant_dir="$(mktemp -d)"
  trap 'rm -rf "$mutant_dir"' EXIT
  cp "$ROOT/mailserver/deploy/generated/unit-catalog.sh" "$mutant_dir/unit-catalog.sh"
  # Mutant arm: delete one associative-array line and expect --check to fail.
  # Kept in lockstep with the generator's emission format — unit-catalog-gen
  # now emits bash single-quoted literals (D-MAILSERVER-CMD-UNIT-CATALOG-GEN-001),
  # so the deletion pattern targets the single-quoted key/value line.
  sed -i.bak "/^[[:space:]]*\['setjoin-updater'\]='setjoin-updater.service.template'\$/d" "$mutant_dir/unit-catalog.sh"
  if (cd "$ROOT/mailserver" && go run ./cmd/unit-catalog-gen --check --output "$mutant_dir/unit-catalog.sh") >/dev/null 2>&1; then
    echo "E_ARCH_R4_UNITS_MUTANT stale projection was accepted" >&2
    exit 1
  fi
  echo "deploy unit catalog self-test: PASS"
fi

echo "deploy unit catalog: PASS (${#SETJOIN_ALL_UNITS[@]} units)"
