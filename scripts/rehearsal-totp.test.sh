#!/usr/bin/env bash
# R5_REHEARSAL_BOOTSTRAP_BOUNDARY
# Deterministic RFC vector, malformed-input, structural-deletion and planted
# arithmetic mutant tests for the pure rehearsal TOTP leaf.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

HELPER="$ROOT/scripts/rehearsal-totp.sh"
CALLERS=(
  scripts/unified-deployment-d3.sh
  scripts/unified-deployment-d4.sh
  scripts/unified-deployment-d5.sh
  scripts/unified-deployment-d4-oidc-flow.sh
  scripts/transactional-updater-rehearsal.sh
  scripts/transactional-continuity-rewind.sh
)
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

secret="$(sh "$HELPER" secret 'otpauth://totp/Setjoin:test?issuer=Setjoin&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')"
[[ "$secret" == GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ ]] || { echo 'E_ARCH_R5_REHEARSAL_TOTP secret parse mismatch' >&2; exit 1; }
[[ "$(sh "$HELPER" code "$secret" 59)" == 287082 ]] || { echo 'E_ARCH_R5_REHEARSAL_TOTP RFC vector mismatch' >&2; exit 1; }
[[ "$(sh "$HELPER" code 'jbswy3dpehpk3pxp' 0)" =~ ^[0-9]{6}$ ]] || { echo 'E_ARCH_R5_REHEARSAL_TOTP lowercase/unpadded secret failed' >&2; exit 1; }

for invalid_uri in 'otpauth://totp/no-query' 'otpauth://totp/empty?secret=' 'otpauth://totp/two?secret=A&secret=B'; do
  if sh "$HELPER" secret "$invalid_uri" >"$tmp/invalid.out" 2>"$tmp/invalid.err"; then
    echo "E_ARCH_R5_REHEARSAL_TOTP invalid URI accepted: $invalid_uri" >&2
    exit 1
  fi
done
if sh "$HELPER" code invalid-base32 59 >/dev/null 2>&1; then
  echo 'E_ARCH_R5_REHEARSAL_TOTP invalid secret accepted' >&2
  exit 1
fi

for caller in "${CALLERS[@]}"; do
  grep -Fq 'scripts/rehearsal-totp.sh' "$ROOT/$caller" || grep -Fq 'rehearsal-totp.sh' "$ROOT/$caller" || {
    echo "E_ARCH_R5_REHEARSAL_TOTP caller is not routed through helper: $caller" >&2
    exit 1
  }
  if grep -Eq 'base64\.b32decode|hmac\.new\(' "$ROOT/$caller"; then
    echo "E_ARCH_R5_REHEARSAL_TOTP duplicate generator remains: $caller" >&2
    exit 1
  fi
done

sed 's/% 1000000/% 100000/' "$HELPER" >"$tmp/mutant.sh"
if [[ "$(sh "$tmp/mutant.sh" code "$secret" 59)" == 287082 ]]; then
  echo 'E_ARCH_R5_REHEARSAL_TOTP planted modulo mutant escaped detection' >&2
  exit 1
fi

echo 'architecture-r5 rehearsal TOTP: PASS (six callers, RFC vector, malformed URI/secret, duplicate deletion, planted mutant)'
