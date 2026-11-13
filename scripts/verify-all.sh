#!/usr/bin/env bash
# Complete, fail-closed verification matrix for Setjoin.
#
# Every lane declares its inputs and side effects in `list`. No lane deploys,
# changes production state, or chooses an implicit remote origin. The browser
# lane accepts exactly one explicit http(s) origin through E2E_SERVER. Database
# lanes are limited to the disposable mailserver_test database owned by the
# existing test harness. Runtime artifacts stay in the documented project-local
# output directories.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:-all}"

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-all.sh <mode>

Modes and boundaries:
  list      Print this matrix; reads no project state and writes nothing.
  static    Lint, build, injection/structure guards, the -tags xinchuang
            tagged lane (build/vet/test), and Linux arm64/loong64
            cross-compiles. Writes only normal compiler/package-manager caches
            and project build outputs.
  core      Go, Webmail unit+coverage, DB-backed tests, pgTAP, and vulnerability
            checks. Recreates ONLY the disposable local database mailserver_test.
  clients   Host-runnable Rust workspace, Electron, desktop-native, and the
            HarmonyOS cross-build/package lane. Writes only package caches and
            project build outputs; no network service.
  harmony   Cross-build ohos-native, copy that exact .so into the ArkTS package,
            then clean-build the unsigned HAP with DevEco/Hvigor.
  security  Go symbol-level vuln scans, npm audits, and RustSec audits. The only
            vulnerability exceptions are guarded to the Windows-only Tauri
            toast dependency; an unsound glib warning is accepted only while
            absent from both shipped mobile target graphs. Tauri desktop is
            retired and the shipped desktop is Electron.
  protocol  Docker-backed IMAP connector E2E plus SMTP/LDAP Go surface suites
            and the explicit local protocol contract. The external
            link-protect Safe Browsing lane is not part of `all`; run it only
            with its credentials/services through `scripts/e2e.sh link-protect`.
  browser   Full Playwright against exactly E2E_SERVER, followed by the
            self-contained strict-CSP suite against its static-build loopback
            server. E2E_SERVER must be an exact http(s) origin. The full suite
            mutates only the explicitly named *_e2e or *_test database and its
            matching test service, then writes Playwright artifacts below
  browser-complete  Build disposable loopback ordinary + LiveKit stacks and run
            the default, CA/device, CSP, onboarding, and real-meeting matrices.
            E2E_SERVER, E2E_GATEWAY_PORT, and E2E_DB_NAME must identify that
            exact local stack; remote origins are rejected.
            mailserver/webmail/test-results/.
  onboarding Disposable uninitialized-stack browser journey. Uses loopback
            ports 18081/18444/19001 and database mailserver_onboarding_e2e by
            default; never targets an external origin.
  mobile    iOS and Android runtime probes (or MOBILE_PLATFORM=ios|android).
            Uses local simulator/emulator and writes clients/desktop/e2e-artifacts.
  continuity
            U5-U8 server, reducer, native-vault, Web, OpenAPI, lifecycle, and
            OFF-by-default contract gates. Uses a unique local evidence prefix
            unless RUN_PREFIX is explicitly supplied; never closes the physical
            iOS/Android release gate.
  performance
            Real Go-gateway Webmail readiness/compression/cache browser lane.
            Uses the disposable mailserver_performance_e2e database and loopback
            ports; defaults to the five-sample CI surrogate.
  all       static + core + clients + protocol + continuity. Does not silently
            select a URL or launch device simulators.
  extended  all + browser + mobile. Requires explicit E2E_SERVER and installed
            iOS/Android toolchains; fails closed when either is unavailable.

Inputs:
  DB_DSN / TEST_DB_DSN    Local test PostgreSQL; defaults target mailserver_test.
  E2E_SERVER              Exact browser-test origin, required by browser/extended.
  E2E_DB_DSN              Disposable *_e2e or *_test database used by browser tests.
  E2E_ALLOW_REMOTE_MUTATION=1
                          Required when E2E_SERVER is not a loopback origin.
  PLAYWRIGHT_BROWSER_RUNTIME
                          auto (default), host, connect, or container. Auto
                          fails closed outside the supported host matrix unless
                          PLAYWRIGHT_CONNECT_WS_ENDPOINT is supplied.
  PLAYWRIGHT_CONNECT_WS_ENDPOINT
                          Loopback ws(s) endpoint for a supported browser host.
  MOBILE_PLATFORM         ios, android, or both (default both).
  HVIGORW                 Hvigor executable (defaults to DevEco Studio bundle).
  DEVECO_SDK_HOME         OpenHarmony SDK (defaults to DevEco Studio bundle).
  RACE=1                  Enable Go race detector in core.

Outputs:
  mailserver/webmail/test-results/ and playwright-report/
  clients/desktop/e2e-artifacts/<platform>-<UTC timestamp>/
  clients/harmonyos/entry/build/default/outputs/default/entry-default-unsigned.hap
  ordinary language/package build caches and project build directories
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "verify-all: required command not found: $1" >&2
    exit 1
  }
}

validate_origin() {
  : "${E2E_SERVER:?E2E_SERVER is required for the browser lane (for example http://127.0.0.1:4173)}"
  E2E_DB_DSN="${E2E_DB_DSN:-postgres://mail:mail@127.0.0.1:5432/mailserver_e2e}"
  export E2E_DB_DSN
  E2E_SERVER_VALUE="$E2E_SERVER" E2E_DB_DSN_VALUE="$E2E_DB_DSN" node -e '
    try {
      const origin = process.env.E2E_SERVER_VALUE;
      const dsn = process.env.E2E_DB_DSN_VALUE;
      let url;
      let db;
      try { url = new URL(origin); } catch { throw new Error("E2E_SERVER must be a valid URL"); }
      if (!["http:", "https:"].includes(url.protocol) || url.origin !== origin || url.username || url.password) {
        throw new Error("E2E_SERVER must be one exact http(s) origin without credentials, path, query, or fragment");
      }
      try { db = new URL(dsn); } catch { throw new Error("E2E_DB_DSN must be a valid PostgreSQL URL"); }
      if (!["postgres:", "postgresql:"].includes(db.protocol) || !/^\/(?:[^/]*_e2e|[^/]*_test)$/.test(db.pathname)) {
        throw new Error("E2E_DB_DSN must name a disposable *_e2e or *_test database");
      }
      if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) && process.env.E2E_ALLOW_REMOTE_MUTATION !== "1") {
        throw new Error("non-loopback E2E_SERVER requires E2E_ALLOW_REMOTE_MUTATION=1");
      }
    } catch (error) {
      console.error(`verify-all: ${error.message}`);
      process.exit(2);
    }
  '
}

run_static() {
  echo "==> [static] build"
  bash "$ROOT/scripts/build.sh"
  echo "==> [static] xinchuang tagged lane (-tags xinchuang build/vet/test)"
  # Triage row 005: the tagged xinchuang/db package (notify.go) must compile
  # and its tests must gate — mirrors the xinchuang-tagged-lane CI job.
  (cd "$ROOT/mailserver" \
    && go build -tags xinchuang ./... \
    && go vet -tags xinchuang ./... \
    && go test -tags xinchuang ./internal/xinchuang/... -count=1)
  echo "==> [static] local CI without database"
  bash "$ROOT/scripts/ci-local.sh" --no-db
}

run_core() {
  echo "==> [core] canonical tests"
  bash "$ROOT/scripts/test.sh"
  echo "==> [core] Webmail dependency audit"
  (cd "$ROOT/mailserver/webmail" && npm audit --audit-level=moderate)
}

run_clients() {
  require_command cargo
  require_command npm

  echo "==> [clients] Rust workspace tests"
  # ohos-native is an ArkTS-hosted N-API cdylib. A macOS test executable cannot
  # resolve its OHOS napi symbols, so execute every host-runnable crate here and
  # verify the OHOS crate through its own cross-build/package lane below.
  (cd "$ROOT/clients" && cargo test --workspace --all-targets --exclude ohos-native)
  echo "==> [clients] Rust workspace clippy"
  (cd "$ROOT/clients" && cargo clippy --workspace --all-targets --exclude ohos-native -- -D warnings)
  (cd "$ROOT/clients" && cargo clippy -p ohos-native --lib -- -D warnings)

  echo "==> [clients] RustSec workspace audit"
  require_command cargo-audit
  (cd "$ROOT/clients" && cargo audit -D unsound)

  echo "==> [clients] Tauri mobile host tests, clippy, and delivery-target audit"
  (cd "$ROOT" && cargo test --manifest-path clients/desktop/src-tauri/Cargo.toml)
  (cd "$ROOT" && cargo clippy --manifest-path clients/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings)
  audit_tauri_mobile

  echo "==> [clients] Electron unit, type, build, and patch-cadence gates"
  (cd "$ROOT/clients/desktop/electron" && npm test && npm run typecheck && npm run build && npm run check:patch-cadence && npm audit --audit-level=moderate)

  echo "==> [clients] desktop native-addon tests and export guard"
  (cd "$ROOT/clients/rust/desktop-native" && npm run build && npm test && npm audit --audit-level=moderate)
  echo "==> [clients] Tauri mobile JavaScript-tooling audit"
  (cd "$ROOT/clients/desktop" && npm audit --audit-level=moderate)

  run_harmony
}

tauri_quick_xml_tree_allowed() {
  local tree="$1"
  local crate

  # Every member of the one accepted reverse-dependency chain must be present
  # as its own cargo-tree line. Substring matches are insufficient here: an
  # unrelated crate whose name merely contains one of these tokens must not
  # authorize a RustSec exception.
  for crate in tauri-winrt-notification notify-rust tauri-plugin-notification setjoin-desktop; do
    printf '%s\n' "$tree" | grep -E "^[[:space:]│├└─]*${crate} v" >/dev/null || return 1
  done
  # Reject every unknown intermediate/sibling line. This is deliberately an
  # allowlist over the complete `cargo tree -i` output, not a presence check.
  if printf '%s\n' "$tree" | grep -Ev '^(quick-xml v0\.37\.5|[[:space:]│├└─]*(tauri-winrt-notification|notify-rust|tauri-plugin-notification|setjoin-desktop) v[^[:space:]]+( \([^)]*\))?|[[:space:]]*)$' | grep -q .; then
    return 1
  fi
}

audit_tauri_mobile() {
  local tree poisoned mobile_glib target lock
  local -a quick_xml_ignores=()
  lock="$ROOT/clients/desktop/src-tauri/Cargo.lock"

  # Tauri 2.11.5 removed this vulnerable Windows-only parser chain. Keep the
  # narrowly reviewed exceptions only while the exact old package remains in
  # the lock; once it is gone, auditing must run without those exceptions so a
  # future reintroduction is visible rather than silently grandfathered.
  if awk 'BEGIN { RS = ""; found = 0 }
          $0 ~ /^\[\[package\]\]\nname = "quick-xml"\nversion = "0\.37\.5"(\n|$)/ { found = 1 }
          END { exit found ? 0 : 1 }' "$lock"; then
    tree="$(cargo tree --manifest-path "$ROOT/clients/desktop/src-tauri/Cargo.toml" --target all -i quick-xml@0.37.5)"
    # These two advisories remain only in tauri-winrt-notification's Windows
    # XML parser. Fail if the reverse tree ever moves outside that retired
    # desktop path; otherwise record only the exact exceptions.
    if ! tauri_quick_xml_tree_allowed "$tree"; then
      echo "verify-all: quick-xml 0.37.5 escaped the Windows-only notification chain" >&2
      printf '%s\n' "$tree" >&2
      exit 1
    fi
    poisoned="${tree}"$'\n''    └── some-new-crate v1.0.0'
    if tauri_quick_xml_tree_allowed "$poisoned"; then
      echo "verify-all: Tauri RustSec tree guard self-test failed to reject an unknown crate" >&2
      exit 1
    fi
    quick_xml_ignores=(--ignore RUSTSEC-2026-0194 --ignore RUSTSEC-2026-0195)
  else
    echo "verify-all: quick-xml 0.37.5 absent; obsolete RUSTSEC-2026-0194/0195 exceptions disabled"
  fi
  # glib's advisory is an unsound warning in Tauri's retired Linux desktop
  # graph. Prove it is absent from both shipped mobile target graphs before
  # allowing that one warning; every other current or future unsound advisory
  # remains fatal via `-D unsound` below.
  for target in aarch64-apple-ios aarch64-linux-android; do
    mobile_glib="$(cargo tree --manifest-path "$ROOT/clients/desktop/src-tauri/Cargo.toml" --target "$target" -i glib@0.18.5 2>/dev/null || true)"
    if [ -n "$mobile_glib" ]; then
      echo "verify-all: glib 0.18.5 entered shipped mobile target $target" >&2
      printf '%s\n' "$mobile_glib" >&2
      exit 1
    fi
  done
  cargo audit --file "$lock" \
    -D unsound \
    --ignore RUSTSEC-2024-0429 \
    "${quick_xml_ignores[@]}"
}

run_security() {
  local govulncheck
  govulncheck="$(command -v govulncheck 2>/dev/null || true)"
  [ -n "$govulncheck" ] || govulncheck="$(go env GOPATH)/bin/govulncheck"
  [ -x "$govulncheck" ] || { echo "verify-all: govulncheck is required" >&2; exit 1; }
  require_command cargo-audit

  for mod in authserver mailserver shared mailctl; do
    echo "==> [security] govulncheck $mod"
    (cd "$ROOT/$mod" && "$govulncheck" ./...)
  done
  echo "==> [security] govulncheck asrbot"
  (cd "$ROOT/asrbot" && GOWORK=off "$govulncheck" -tags nolibopusfile ./...)

  for dir in mailserver/webmail clients/desktop/electron clients/desktop clients/rust/desktop-native; do
    echo "==> [security] npm audit $dir"
    (cd "$ROOT/$dir" && npm audit --audit-level=moderate)
  done

  echo "==> [security] RustSec workspace"
  (cd "$ROOT/clients" && cargo audit -D unsound)
  echo "==> [security] RustSec Tauri mobile"
  audit_tauri_mobile
}

run_harmony() {
  local hvigorw="${HVIGORW:-/Applications/DevEco-Studio.app/Contents/tools/hvigor/bin/hvigorw}"
  local deveco_sdk="${DEVECO_SDK_HOME:-/Applications/DevEco-Studio.app/Contents/sdk}"
  local built_so="$ROOT/clients/target/aarch64-unknown-linux-ohos/release/libohos_native.so"
  local packaged_so="$ROOT/clients/harmonyos/entry/libs/arm64-v8a/libohos_native.so"
  local hap="$ROOT/clients/harmonyos/entry/build/default/outputs/default/entry-default-unsigned.hap"

  [ -x "$hvigorw" ] || { echo "verify-all: HVIGORW is not executable: $hvigorw" >&2; exit 1; }
  [ -d "$deveco_sdk" ] || { echo "verify-all: DEVECO_SDK_HOME is not a directory: $deveco_sdk" >&2; exit 1; }

  echo "==> [harmony] cross-building ohos-native for aarch64"
  (cd "$ROOT/clients" && cargo build --release --target aarch64-unknown-linux-ohos -p ohos-native)
  mkdir -p "$(dirname "$packaged_so")"
  install -m 0644 "$built_so" "$packaged_so"

  echo "==> [harmony] clean-building unsigned HAP"
  (cd "$ROOT/clients/harmonyos" && DEVECO_SDK_HOME="$deveco_sdk" "$hvigorw" clean --no-daemon)
  (cd "$ROOT/clients/harmonyos" && DEVECO_SDK_HOME="$deveco_sdk" "$hvigorw" assembleHap --mode module -p product=default --no-daemon)
  [ -s "$hap" ] || { echo "verify-all: Hvigor reported success but HAP is missing/empty: $hap" >&2; exit 1; }
}

run_protocol() {
  require_command docker
  echo "==> [protocol] Docker IMAP connector E2E + SMTP/LDAP Go surface suites"
  bash "$ROOT/scripts/e2e.sh" all
}

run_browser() {
  require_command npm
  validate_origin
  echo "==> [browser] origin=$E2E_SERVER"
  (cd "$ROOT/mailserver/webmail" && \
    E2E_SERVER="$E2E_SERVER" E2E_CSP_REQUIRE_GATEWAY_HEADER=1 \
    GUEST_E2E_EVIDENCE="$ROOT/mailserver/webmail/test-results/guest-e2e-evidence" \
    bash "$ROOT/scripts/playwright-supported.sh" -- npm run test:e2e)
  echo "==> [browser] strict CSP static-build origin=http://127.0.0.1:8199"
  (cd "$ROOT/mailserver/webmail" && \
    E2E_CSP_REQUIRE_GATEWAY_HEADER=0 \
    bash "$ROOT/scripts/playwright-supported.sh" -- npm run test:e2e:csp)
  echo "==> [browser] verifying named Playwright release evidence"
  TEST_EVIDENCE_ORIGIN="$E2E_SERVER" \
  TEST_EVIDENCE_CSP_ORIGIN="http://127.0.0.1:8199" \
  TEST_EVIDENCE_OUTPUT="mailserver/webmail/test-results/playwright-evidence.json" \
    bash "$ROOT/scripts/check-test-evidence-results.sh" --verify playwright-json
}

run_onboarding() {
  require_command curl
  require_command npm
  echo "==> [onboarding] disposable first-boot browser journey"
  bash "$ROOT/scripts/e2e-onboarding.sh"
}

run_browser_complete() {
  require_command curl
  require_command docker
  require_command npm
  echo "==> [browser-complete] isolated complete browser matrix"
  bash "$ROOT/scripts/e2e-browser-complete.sh"
}

run_mobile() {
  case "${MOBILE_PLATFORM:-both}" in
    ios|android|both) ;;
    *) echo "verify-all: MOBILE_PLATFORM must be ios, android, or both" >&2; exit 2 ;;
  esac
  echo "==> [mobile] platform=${MOBILE_PLATFORM:-both}"
  bash "$ROOT/clients/desktop/scripts/mobile-e2e.sh" "${MOBILE_PLATFORM:-both}"
}

run_continuity() {
  local prefix="${RUN_PREFIX:-continuity-$(date -u +%Y%m%d-%H%M%S)-$$}"
  echo "==> [continuity] prefix=$prefix"
  RUN_PREFIX="$prefix" FORCE="${FORCE:-1}" \
    bash "$ROOT/scripts/transactional-upgrade-rehearsal.sh" deterministic
}

run_performance() {
  echo "==> [performance] real Go-gateway Webmail CI surrogate"
  bash "$ROOT/scripts/verify-webmail-performance.sh" ci
}

run_all() {
  run_static
  run_core
  run_clients
  run_protocol
  run_continuity
}

case "$MODE" in
  list|-h|--help) usage ;;
  static) run_static ;;
  core) run_core ;;
  clients) run_clients ;;
  harmony) run_harmony ;;
  security) run_security ;;
  protocol) run_protocol ;;
  browser) run_browser ;;
  browser-complete) run_browser_complete ;;
  onboarding) run_onboarding ;;
  mobile) run_mobile ;;
  continuity) run_continuity ;;
  performance) run_performance ;;
  all) run_all ;;
  extended) run_all; run_browser; run_mobile ;;
  *) echo "verify-all: unknown mode: $MODE" >&2; usage >&2; exit 2 ;;
esac
