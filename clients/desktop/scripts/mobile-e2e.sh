#!/usr/bin/env bash
# Queue B #6 (mobile-runtime e2e) — repeatable harness around the C2 gate proof.
#
# Boots a real iOS Simulator / Android emulator, (re)builds the Tauri mobile
# debug app with the `mobile-e2e-probe` Cargo feature (see
# `src-tauri/src/bridge_js.rs::e2e_probe_js`), installs it fresh, launches it,
# and drives the offline-core bridge round trip the app self-runs on load:
# vault.unlock -> db.open('mail') -> partial recovery-blob write -> app kill /
# restart -> exact-offset resume -> commit/read/ref/unref -> exec/query -> wipe.
# That is the exact runtime path `OfflineDb.swift`/`OfflineDb.kt` document as
# "build-checked, never device/simulator-runtime-tested" (clients/AGENTS.md,
# TODOS.md:220) — this harness is what closes that gap, repeatably.
#
# Evidence captured per run (not machine-checkable in CI — sim/AVD state is
# local-machine-only, per the plan's own acceptance framing — but this script
# IS machine-checkable for exit code, and the artifacts are the durable
# record a human or a later run can inspect):
#   clients/desktop/e2e-artifacts/<platform>-<UTC timestamp>/
#     screenshot.png        — visual proof (on-screen PASS/FAIL banner)
#     probe-result.json     — {ok, steps[], error, pageDiag} from the device
#     restart-phase.json    — first-launch acknowledged offset before app kill
#     device.log            — OS-level log captured around the run
#     summary.txt           — PASS/FAIL one-liner + the exact commands used
#
# Usage:
#   bash clients/desktop/scripts/mobile-e2e.sh ios
#   bash clients/desktop/scripts/mobile-e2e.sh android
#   bash clients/desktop/scripts/mobile-e2e.sh both
#   bash clients/desktop/scripts/mobile-e2e.sh ios --rebuild   # force a fresh build
#
# Exit code: 0 iff every requested platform's probe reports ok:true. Nonzero
# on any build/install/launch/timeout/probe failure, with the reason printed.
#
# Env (all optional; defaults match the documented working setup in
# clients/AGENTS.md "Mobile shell" / this repo's CI-analog dev machine):
#   ANDROID_HOME, NDK_HOME, JAVA_HOME, IOS_SIMULATOR_NAME (default "iPhone 17")

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
APP_BUNDLE_ID="com.setjoin.desktop"
IOS_APP_PATH="$DESKTOP_DIR/src-tauri/gen/apple/build/arm64-sim/SetJoin.app"
ANDROID_APK_PATH="$DESKTOP_DIR/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
PROBE_TIMEOUT=60 # seconds to wait for e2e-probe-result.json to appear after launch

: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${NDK_HOME:=$ANDROID_HOME/ndk/27.0.12077973}"
: "${JAVA_HOME:=/opt/homebrew/opt/openjdk@17}"
: "${IOS_SIMULATOR_NAME:=iPhone 17}"
export ANDROID_HOME NDK_HOME JAVA_HOME
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"

log() { echo "[mobile-e2e] $*" >&2; }
die() { log "FAIL: $*"; exit 1; }

verify_visible_shell() {
  local result="$1" platform="$2"
  python3 - "$result" "$platform" <<'PY'
import json, sys

path, platform = sys.argv[1:]
diag = json.load(open(path, encoding="utf-8")).get("pageDiag") or {}
kind = diag.get("shellKind")
page = diag.get("shell") or {}
title = diag.get("shellTitle") or {}
page_rect = page.get("rect") or {}
title_rect = title.get("rect") or {}
width = float(page_rect.get("width") or 0)
title_x = float(title_rect.get("x") or -1)
title_width = float(title_rect.get("width") or 0)
problems = []
if kind not in {"login", "auth-unavailable"}:
    problems.append(f"unexpected unauthenticated shell kind {kind!r}")
if kind == "login" and "Sign In" not in (diag.get("bodyText") or ""):
    problems.append("login shell body text does not contain Sign In")
if kind == "auth-unavailable" and "Sign-in service unavailable" not in (diag.get("bodyText") or ""):
    problems.append("auth-unavailable shell body text lacks its explicit failure title")
if not 200 <= width <= 600:
    problems.append(f"mobile viewport width is {width}, expected 200..600 CSS px")
if title_width <= 0 or title_x < 0 or title_x + title_width > width:
    problems.append(f"shell title rect {title_rect} is outside viewport width {width}")
if page.get("display") == "none" or page.get("visibility") != "visible" or page.get("opacity") == "0":
    problems.append(f"application surface is not visibly styled: {page}")
if problems:
    raise SystemExit(f"{platform} visible-shell contract failed: " + "; ".join(problems))
PY
}

REBUILD=0
PLATFORM="${1:-}"
for arg in "$@"; do
  [ "$arg" = "--rebuild" ] && REBUILD=1
done
case "$PLATFORM" in
  ios|android) PLATFORMS=("$PLATFORM") ;;
  both) PLATFORMS=(ios android) ;;
  *) die "usage: $0 <ios|android|both> [--rebuild]" ;;
esac

run_artifacts_dir() {
  local platform="$1"
  local dir
  dir="$DESKTOP_DIR/e2e-artifacts/${platform}-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dir"
  echo "$dir"
}

probe_phase() {
  python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('phase',''))" "$1" 2>/dev/null || true
}

# ── iOS ──────────────────────────────────────────────────────────────────

ios_build() {
  if [ "$REBUILD" = 1 ] || [ ! -d "$IOS_APP_PATH" ]; then
    log "building iOS debug app (--features mobile-e2e-probe)..."
    rm -rf "$IOS_APP_PATH"
    ( cd "$DESKTOP_DIR" && npx tauri ios build --debug --target aarch64-sim --no-sign --features mobile-e2e-probe ) \
      || die "iOS build failed"
  else
    log "reusing existing iOS build at $IOS_APP_PATH (pass --rebuild to force)"
  fi
  [ -d "$IOS_APP_PATH" ] || die "iOS app not found after build: $IOS_APP_PATH"
}

ios_boot_simulator() {
  # Prefer an already-booted device (any iPhone); otherwise boot the named one.
  local udid
  udid="$(xcrun simctl list devices booted | grep -m1 -Eo '[0-9A-F-]{36}' || true)"
  if [ -z "$udid" ]; then
    log "booting simulator '$IOS_SIMULATOR_NAME'..."
    udid="$(xcrun simctl list devices available | grep "$IOS_SIMULATOR_NAME (" | grep -m1 -Eo '[0-9A-F-]{36}')"
    [ -n "$udid" ] || die "no '$IOS_SIMULATOR_NAME' simulator found (xcrun simctl list devices)"
    xcrun simctl boot "$udid"
    # This function is consumed via command substitution, so stdout is a
    # machine-readable channel containing only the UDID. Keep boot progress on
    # stderr or it becomes part of the device identifier passed to simctl.
    xcrun simctl bootstatus "$udid" -b >&2
  fi
  echo "$udid"
}

ios_run() {
  local artifacts udid app_data result_file elapsed phase
  artifacts="$(run_artifacts_dir ios)"
  ios_build
  udid="$(ios_boot_simulator)"
  log "iOS: udid=$udid app=$IOS_APP_PATH artifacts=$artifacts"

  # Fresh install every run: deterministic vault/offline-store state, and
  # guarantees any e2e-probe-result.json we read back is from THIS run, not
  # a stale one left over from a prior pass.
  xcrun simctl terminate "$udid" "$APP_BUNDLE_ID" >/dev/null 2>&1 || true
  xcrun simctl uninstall "$udid" "$APP_BUNDLE_ID" >/dev/null 2>&1 || true
  xcrun simctl install "$udid" "$IOS_APP_PATH" || die "iOS install failed"
  app_data="$(xcrun simctl get_app_container "$udid" "$APP_BUNDLE_ID" data)"
  result_file="$app_data/Library/Application Support/$APP_BUNDLE_ID/e2e-probe-result.json"

  ( xcrun simctl spawn "$udid" log stream --level debug --style compact \
      --predicate 'processImagePath contains "SetJoin"' \
      > "$artifacts/device.log" 2>&1 & echo $! > "$artifacts/.logpid" )
  xcrun simctl launch "$udid" "$APP_BUNDLE_ID" >/dev/null || die "iOS launch failed"

  elapsed=0
  while [ ! -f "$result_file" ] && [ "$elapsed" -lt "$PROBE_TIMEOUT" ]; do
    sleep 2; elapsed=$((elapsed + 2))
  done
  [ -f "$result_file" ] || die "iOS: first-launch probe result never appeared after ${PROBE_TIMEOUT}s (artifacts: $artifacts)"
  phase="$(probe_phase "$result_file")"
  [ "$phase" = "restart-required" ] || die "iOS: first launch did not request the mandatory restart (phase=${phase:-missing})"
  cp "$result_file" "$artifacts/restart-phase.json"

  xcrun simctl terminate "$udid" "$APP_BUNDLE_ID" >/dev/null || die "iOS: mandatory probe termination failed"
  xcrun simctl launch "$udid" "$APP_BUNDLE_ID" >/dev/null || die "iOS: relaunch failed"
  elapsed=0
  while [ "$(probe_phase "$result_file")" != "complete" ] && [ "$elapsed" -lt "$PROBE_TIMEOUT" ]; do
    sleep 2; elapsed=$((elapsed + 2))
  done

  # The report is emitted only after two WebView animation frames. Give the
  # simulator compositor one additional bounded beat before framebuffer capture.
  sleep 1
  xcrun simctl io "$udid" screenshot "$artifacts/screenshot.png" >/dev/null
  kill "$(cat "$artifacts/.logpid" 2>/dev/null)" >/dev/null 2>&1 || true
  rm -f "$artifacts/.logpid"

  [ "$(probe_phase "$result_file")" = "complete" ] || die "iOS: restarted probe never completed after ${PROBE_TIMEOUT}s (artifacts: $artifacts)"
  cp "$result_file" "$artifacts/probe-result.json"
  ios_report "$artifacts"
}

ios_report() {
  local artifacts="$1" ok
  ok="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['ok'])" "$artifacts/probe-result.json")"
  {
    echo "platform: ios"
    echo "app: $IOS_APP_PATH"
    echo "probe: $ok"
    echo "restart_resume: PASS"
    echo "commands:"
    echo "  npx tauri ios build --debug --target aarch64-sim --no-sign --features mobile-e2e-probe"
    echo "  xcrun simctl install <udid> \"$IOS_APP_PATH\""
    echo "  xcrun simctl launch <udid> $APP_BUNDLE_ID"
  } > "$artifacts/summary.txt"
  cat "$artifacts/probe-result.json" | tee -a "$artifacts/summary.txt" >&2
  [ "$ok" = "True" ] || die "iOS probe reported failure (see $artifacts/probe-result.json)"
  verify_visible_shell "$artifacts/probe-result.json" ios || die "iOS visible shell contract failed"
  log "iOS PASS — artifacts: $artifacts"
}

# ── Android ──────────────────────────────────────────────────────────────

android_build() {
  if [ "$REBUILD" = 1 ] || [ ! -f "$ANDROID_APK_PATH" ]; then
    log "building Android debug APK (--features mobile-e2e-probe)..."
    ( cd "$DESKTOP_DIR" && npx tauri android build --debug --features mobile-e2e-probe ) \
      || die "Android build failed"
  else
    log "reusing existing Android APK at $ANDROID_APK_PATH (pass --rebuild to force)"
  fi
  [ -f "$ANDROID_APK_PATH" ] || die "Android APK not found after build: $ANDROID_APK_PATH"
}

android_boot_emulator() {
  if adb devices | grep -q "^emulator-.*device$"; then
    log "reusing already-running emulator"
    return
  fi
  local avd
  avd="$(emulator -list-avds | head -1)"
  [ -n "$avd" ] || die "no AVD found (emulator -list-avds is empty)"
  log "booting emulator '$avd' headless..."
  nohup emulator -avd "$avd" -no-window -no-audio -no-boot-anim -gpu swiftshader_indirect \
    > /tmp/setjoin-mobile-e2e-emulator.log 2>&1 &
  disown
  adb wait-for-device
  local elapsed=0
  while [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]; do
    sleep 3; elapsed=$((elapsed + 3))
    [ "$elapsed" -lt 180 ] || die "Android emulator did not finish booting in 180s"
  done
}

android_run() {
  local artifacts elapsed got phase
  artifacts="$(run_artifacts_dir android)"
  android_build
  android_boot_emulator
  log "Android: artifacts=$artifacts"

  adb install -r "$ANDROID_APK_PATH" >/dev/null || die "Android install failed"
  adb shell am force-stop "$APP_BUNDLE_ID" || true
  adb shell pm clear "$APP_BUNDLE_ID" >/dev/null || true # fresh vault/store each run
  adb logcat -c

  adb shell am start -n "$APP_BUNDLE_ID/.MainActivity" >/dev/null || die "Android launch failed"

  elapsed=0; got=1
  while [ "$elapsed" -lt "$PROBE_TIMEOUT" ]; do
    sleep 2; elapsed=$((elapsed + 2))
    if adb shell run-as "$APP_BUNDLE_ID" cat "/data/data/$APP_BUNDLE_ID/e2e-probe-result.json" \
        > "$artifacts/probe-result.json" 2>/dev/null; then
      got=0; break
    fi
  done
  [ "$got" -eq 0 ] || die "Android: first-launch probe result never appeared after ${PROBE_TIMEOUT}s (artifacts: $artifacts)"
  phase="$(probe_phase "$artifacts/probe-result.json")"
  [ "$phase" = "restart-required" ] || die "Android: first launch did not request the mandatory restart (phase=${phase:-missing})"
  cp "$artifacts/probe-result.json" "$artifacts/restart-phase.json"

  adb shell am force-stop "$APP_BUNDLE_ID" || die "Android: mandatory probe termination failed"
  adb shell am start -n "$APP_BUNDLE_ID/.MainActivity" >/dev/null || die "Android relaunch failed"
  elapsed=0; got=1
  while [ "$elapsed" -lt "$PROBE_TIMEOUT" ]; do
    sleep 2; elapsed=$((elapsed + 2))
    if adb shell run-as "$APP_BUNDLE_ID" cat "/data/data/$APP_BUNDLE_ID/e2e-probe-result.json" \
        > "$artifacts/probe-result.json" 2>/dev/null &&
       [ "$(probe_phase "$artifacts/probe-result.json")" = "complete" ]; then
      got=0; break
    fi
  done

  adb exec-out screencap -p > "$artifacts/screenshot.png"
  adb logcat -d > "$artifacts/device.log" || true

  [ "$got" -eq 0 ] || die "Android: restarted probe never completed after ${PROBE_TIMEOUT}s (artifacts: $artifacts)"
  android_report "$artifacts"
}

android_report() {
  local artifacts="$1" ok
  ok="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['ok'])" "$artifacts/probe-result.json")"
  {
    echo "platform: android"
    echo "apk: $ANDROID_APK_PATH"
    echo "probe: $ok"
    echo "restart_resume: PASS"
    echo "commands:"
    echo "  npx tauri android build --debug --features mobile-e2e-probe"
    echo "  adb install -r \"$ANDROID_APK_PATH\""
    echo "  adb shell am start -n $APP_BUNDLE_ID/.MainActivity"
  } > "$artifacts/summary.txt"
  cat "$artifacts/probe-result.json" | tee -a "$artifacts/summary.txt" >&2
  [ "$ok" = "True" ] || die "Android probe reported failure (see $artifacts/probe-result.json)"
  verify_visible_shell "$artifacts/probe-result.json" android || die "Android visible shell contract failed"
  log "Android PASS — artifacts: $artifacts"
}

# ── Main ─────────────────────────────────────────────────────────────────

for p in "${PLATFORMS[@]}"; do
  case "$p" in
    ios) ios_run ;;
    android) android_run ;;
  esac
done

log "all requested platforms PASS"
