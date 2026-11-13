#!/usr/bin/env bash
# apply-android-integration.sh — inject the TRACKED DESKTOP-007 Kotlin glue
# (setFlagSecure / clearFlagSecure on MainActivity) into the generated Tauri
# Android project.
# =============================================================================
#
# WHY THIS EXISTS (DESKTOP-007 r2, Astra Finding 1): `src-tauri/gen/android`
# is generated output and gitignored (clients/desktop/.gitignore), so the
# FLAG_SECURE shim previously lived only in ignored state — a fresh checkout
# produced an app whose JNI `setFlagSecure` call had no Kotlin implementation.
# The authoritative source is now the tracked file
#
#     android-integration/src/com/setjoin/desktop/MainActivity.kt
#
# and THIS script is the documented, scripted injection/regeneration step that
# consumes it. It is wired into the build via `build.beforeBuildCommand` and
# `build.beforeDevCommand` in `src-tauri/tauri.conf.json`, so every
# `tauri android build` / `tauri android dev` re-applies + re-verifies the
# injection BEFORE gradle compiles Kotlin.
#
# Fresh-checkout contract (must produce the method):
#   1. cd clients/desktop && npx tauri android init   # generates gen/android
#   2. npx tauri android build                        # runs this script first
# (Running this script manually between those steps is equivalent.)
#
# On desktop targets (no gen/android) the script exits 0 without doing
# anything, so the shared before*Command stays valid for every tauri lane.
#
# Behaviour:
#   - idempotent: previously injected marker regions are stripped and re-applied
#     byte-identically from the tracked file; unrelated generated content is
#     preserved (marker-delimited patch, not a whole-file clobber);
#   - drift-guarded: refuses to run against a generated MainActivity that
#     declares a FOREIGN setFlagSecure (one it did not inject), and sanity-
#     checks the generated template shape before patching — a tauri template
#     change surfaces as a loud error + a rebase task for this directory, not
#     as silent drift;
#   - self-verifying: after patching it asserts the JNI contract surface
#     (`setFlagSecure(on: Boolean)`, `clearFlagSecure`, FLAG_SECURE flag APIs,
#     the WindowManager import) is present, and that a second application is a
#     byte-level no-op.
#
# BUILD-GATE HONESTY (2026-09-16, r2): this task ran NO Gradle/Kotlin build.
# This script's patch mechanics and idempotency were tested against the local
# generated project copy, but Kotlin COMPILATION and on-device behavior remain
# gated on the next `npx tauri android build` / the orchestrator's
# device-verified phase. Do not treat a green host-side `cargo` run as Kotlin
# evidence.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRACKED_MAIN="$SCRIPT_DIR/src/com/setjoin/desktop/MainActivity.kt"
GEN_ROOT="$SCRIPT_DIR/../gen/android"
GEN_MAIN="$GEN_ROOT/app/src/main/java/com/setjoin/desktop/MainActivity.kt"

die() {
  echo "apply-android-integration: ERROR: $*" >&2
  exit 1
}
note() { echo "apply-android-integration: $*" >&2; }

# ── Desktop / pre-init skip ──────────────────────────────────────────────────
# No generated Android project: nothing to inject. Exit 0 (NOT an error) so
# the shared tauri before*Command works on every target lane.
if [ ! -d "$GEN_ROOT" ]; then
  note "no gen/android project (desktop target or 'tauri android init' not run) — skipping"
  exit 0
fi

[ -f "$TRACKED_MAIN" ] ||
  die "tracked integration source missing: $TRACKED_MAIN"
[ -f "$GEN_MAIN" ] ||
  die "gen/android exists but $GEN_MAIN is missing — unexpected generated layout; re-run 'npx tauri android init' or rebase android-integration/"

# ── Tracked source sanity: the marker regions must exist ────────────────────
# Marker detection is prefix-based (index > 0) so the METHODS markers match
# at their indented position inside the class body too.
extract_region() { # $1 = region key (IMPORT|METHODS); emits region INCLUDING markers
  awk -v key="$1" '
    index($0, "// >>> DESKTOP-007:FLAG_SECURE:" key " >>>") > 0 { seen = 1 }
    seen { print }
    seen && index($0, "// <<< DESKTOP-007:FLAG_SECURE:" key " <<<") > 0 { exit }
  ' "$TRACKED_MAIN"
}
IMPORT_FILE="$(mktemp "${TMPDIR:-/tmp}/sj-ai-import.XXXXXX")"
METHODS_FILE="$(mktemp "${TMPDIR:-/tmp}/sj-ai-methods.XXXXXX")"
trap 'rm -f "$IMPORT_FILE" "$METHODS_FILE" "${STRIPPED:-}" "${PATCHED:-}" "${IDEMPOTENT:-}"' EXIT

extract_region IMPORT >"$IMPORT_FILE"
extract_region METHODS >"$METHODS_FILE"
[ "$(wc -l <"$IMPORT_FILE")" -ge 3 ] ||
  die "tracked MainActivity.kt lost its >>> DESKTOP-007:FLAG_SECURE:IMPORT <<< marker region"
[ "$(wc -l <"$METHODS_FILE")" -ge 5 ] ||
  die "tracked MainActivity.kt lost its >>> DESKTOP-007:FLAG_SECURE:METHODS <<< marker region"
grep -q "fun setFlagSecure(on: Boolean)" "$METHODS_FILE" ||
  die "tracked METHODS region no longer declares setFlagSecure(on: Boolean) — the JNI contract (mam_android.rs, \"(Z)V\") depends on it"
grep -q "fun clearFlagSecure" "$METHODS_FILE" ||
  die "tracked METHODS region no longer declares clearFlagSecure()"
grep -q "WindowManager.LayoutParams.FLAG_SECURE" "$METHODS_FILE" ||
  die "tracked METHODS region no longer touches WindowManager.LayoutParams.FLAG_SECURE"

# ── Generated-project sanity: template shape we know how to patch ────────────
grep -q "^class MainActivity : TauriActivity()" "$GEN_MAIN" ||
  die "generated MainActivity.kt does not declare 'class MainActivity : TauriActivity()' — tauri template changed; rebase android-integration/ against the new template"
grep -q "fun onCreate" "$GEN_MAIN" ||
  die "generated MainActivity.kt has no onCreate — tauri template changed; rebase android-integration/ against the new template"

# ── Strip previously injected regions (idempotent re-apply) ──────────────────
# Prefix-based matching (index > 0) so indented METHODS markers match too.
strip_regions() {
  awk '
    index($0, "// >>> DESKTOP-007:FLAG_SECURE:IMPORT >>>") > 0 { skip = 1; next }
    index($0, "// <<< DESKTOP-007:FLAG_SECURE:IMPORT <<<") > 0 { skip = 0; next }
    index($0, "// >>> DESKTOP-007:FLAG_SECURE:METHODS >>>") > 0 { skip = 1; next }
    index($0, "// <<< DESKTOP-007:FLAG_SECURE:METHODS <<<") > 0 { skip = 0; next }
    !skip
  ' "$1"
}
STRIPPED="$(mktemp "${TMPDIR:-/tmp}/sj-ai-stripped.XXXXXX")"
strip_regions "$GEN_MAIN" >"$STRIPPED"

# A setFlagSecure that survives stripping is FOREIGN (hand-edited or shipped
# by a future tauri template). Never clobber code we did not inject.
if grep -q "fun setFlagSecure" "$STRIPPED"; then
  die "generated MainActivity.kt declares setFlagSecure OUTSIDE the tracked injection markers — refusing to overwrite a foreign shim; move the change into android-integration/src/com/setjoin/desktop/MainActivity.kt and re-run"
fi

# ── Patch: import region after the last import; methods before the final } ───
PATCHED="$(mktemp "${TMPDIR:-/tmp}/sj-ai-patched.XXXXXX")"
# 1 = the WindowManager import is absent and must be injected with the region.
NEEDS_IMPORT=0
grep -q "^import android.view.WindowManager$" "$STRIPPED" || NEEDS_IMPORT=1

awk -v imp="$IMPORT_FILE" -v met="$METHODS_FILE" -v needs_import="$NEEDS_IMPORT" '
  { lines[NR] = $0; if ($0 ~ /^import /) lastimport = NR }
  function emit(path) { while ((getline line < path) > 0) print line; close(path) }
  END {
    lastbrace = 0
    for (i = NR; i >= 1; i--) if (lines[i] == "}") { lastbrace = i; break }
    if (lastbrace == 0) { print "no class-closing brace in generated MainActivity" > "/dev/stderr"; exit 1 }
    if (lastimport == 0) { print "no import lines in generated MainActivity" > "/dev/stderr"; exit 1 }
    for (i = 1; i <= NR; i++) {
      print lines[i]
      if (i == lastimport && needs_import == 1) emit(imp)
      if (i == lastbrace - 1) emit(met)
    }
  }
' "$STRIPPED" >"$PATCHED" ||
  die "patching failed (see awk error above)"

# ── Verify the patched result carries the full JNI contract surface ─────────
grep -q "fun setFlagSecure(on: Boolean)" "$PATCHED" ||
  die "post-patch verification failed: setFlagSecure(on: Boolean) missing"
grep -q "fun clearFlagSecure" "$PATCHED" ||
  die "post-patch verification failed: clearFlagSecure missing"
grep -q "WindowManager.LayoutParams.FLAG_SECURE" "$PATCHED" ||
  die "post-patch verification failed: FLAG_SECURE flag APIs missing"
grep -q "^import android.view.WindowManager$" "$PATCHED" ||
  die "post-patch verification failed: WindowManager import missing"

# ── Idempotency: applying to our own output must be a byte-level no-op ───────
IDEMPOTENT="$(mktemp "${TMPDIR:-/tmp}/sj-ai-idem.XXXXXX")"
strip_regions "$PATCHED" >"$IDEMPOTENT"
if ! cmp -s "$STRIPPED" "$IDEMPOTENT"; then
  die "internal idempotency check failed: a second application would change the file"
fi

if cmp -s "$GEN_MAIN" "$PATCHED"; then
  note "already applied — $GEN_MAIN matches the tracked integration source (no change)"
else
  cat "$PATCHED" >"$GEN_MAIN"
  note "injected DESKTOP-007 FLAG_SECURE glue from tracked source into $GEN_MAIN"
fi
note "Kotlin compilation is build-gated: verified only by the next 'npx tauri android build' (see header)"
