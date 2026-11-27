#!/usr/bin/env bash
# Self-test for scripts/check-openapi-proc-macro-ban.sh (#561).
# Proves planted utoipa / schemars / aide / ToSchema / IntoParams / OperationIo
# in crates/domains/*, crates/contracts/*, crates/pg/*, and crates/edge-contract/*
# are all caught.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-openapi-proc-macro-ban.sh"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/openapi-proc-macro-ban-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

setup_clean() {
  rm -rf "$tmp/crates"
  mkdir -p \
    "$tmp/crates/domains/demo/src" \
    "$tmp/crates/contracts/src" \
    "$tmp/crates/pg/src" \
    "$tmp/crates/edge-contract/src"
  cat >"$tmp/crates/domains/demo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.0.0"

[dependencies]
# utoipa is banned here; comments must not trigger false positives.
serde = "1.0"
EOF
  cat >"$tmp/crates/domains/demo/src/lib.rs" <<'EOF'
// utoipa and ToSchema are banned in domain crates.
pub struct CleanDto {
    pub id: i64,
}
EOF
  cat >"$tmp/crates/contracts/Cargo.toml" <<'EOF'
[package]
name = "setjoin-contracts"
version = "0.0.0"
EOF
  cat >"$tmp/crates/contracts/src/lib.rs" <<'EOF'
pub struct CleanCommand;
EOF
  cat >"$tmp/crates/pg/Cargo.toml" <<'EOF'
[package]
name = "setjoin-pg"
version = "0.0.0"
EOF
  cat >"$tmp/crates/pg/src/lib.rs" <<'EOF'
pub struct CleanPool;
EOF
  cat >"$tmp/crates/edge-contract/Cargo.toml" <<'EOF'
[package]
name = "setjoin-edge-contract"
version = "0.0.0"

[dependencies]
serde = "1.0"
EOF
  cat >"$tmp/crates/edge-contract/src/lib.rs" <<'EOF'
pub struct PlainSerdeDto;
EOF
}

expect_fail() {
  local label="$1"
  if bash "$GUARD" --root "$tmp" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $label was NOT caught by check-openapi-proc-macro-ban" >&2
    exit 1
  fi
}

# 0. Clean fixture passes (including comments mentioning banned crates).
setup_clean
if ! bash "$GUARD" --root "$tmp" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: clean fixture was rejected" >&2
  exit 1
fi

# 1. Planted utoipa in crates/domains/*/Cargo.toml
setup_clean
echo 'utoipa = "5.0"' >>"$tmp/crates/domains/demo/Cargo.toml"
expect_fail "utoipa in crates/domains/*/Cargo.toml"

# 2. Planted #[derive(ToSchema)] in crates/domains/*/src/lib.rs
setup_clean
printf '#[derive(ToSchema)]\npub struct Leak;\n' >>"$tmp/crates/domains/demo/src/lib.rs"
expect_fail "#[derive(ToSchema)] in crates/domains/*/src/lib.rs"

# 3. Planted schemars in crates/contracts/Cargo.toml
setup_clean
printf '\n[dependencies]\nschemars = "1.0"\n' >>"$tmp/crates/contracts/Cargo.toml"
expect_fail "schemars in crates/contracts/Cargo.toml"

# 4. Planted #[derive(IntoParams)] in crates/contracts/src/lib.rs
setup_clean
printf '#[derive(IntoParams)]\npub struct BadParams;\n' >>"$tmp/crates/contracts/src/lib.rs"
expect_fail "#[derive(IntoParams)] in crates/contracts/src/lib.rs"

# 5. Planted aide in crates/pg/Cargo.toml
setup_clean
printf '\n[dependencies]\naide = "0.14"\n' >>"$tmp/crates/pg/Cargo.toml"
expect_fail "aide in crates/pg/Cargo.toml"

# 6. Planted #[derive(OperationIo)] in crates/pg/src/lib.rs
setup_clean
printf '#[derive(OperationIo)]\npub struct BadPgIo;\n' >>"$tmp/crates/pg/src/lib.rs"
expect_fail "#[derive(OperationIo)] in crates/pg/src/lib.rs"

# 7. Planted utoipa in crates/edge-contract/Cargo.toml
setup_clean
echo 'utoipa = "5.0"' >>"$tmp/crates/edge-contract/Cargo.toml"
expect_fail "utoipa in crates/edge-contract/Cargo.toml"

# 8. Planted #[derive(ToSchema)] in crates/edge-contract/src/lib.rs
setup_clean
printf '#[derive(ToSchema)]\npub struct BadEdgeDto;\n' >>"$tmp/crates/edge-contract/src/lib.rs"
expect_fail "#[derive(ToSchema)] in crates/edge-contract/src/lib.rs"

echo "check-openapi-proc-macro-ban self-test: PASS (8 planted violations caught across domains/contracts/pg/edge-contract; clean fixture & comments allowed)"
