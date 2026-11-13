#!/usr/bin/env bash
# MEET renderer re-qualification lane body — linux-ci-host (linux/amd64).
#
# Non-required, manually-triggered lane (wave-1 unit B3; accepted opus-5.5
# module-B fix plan, step 3). The ONLY GitHub entry point is
# .github/workflows/meet-renderer-qualification.yml (workflow_dispatch ONLY,
# pinned ubuntu-24.04). GUARD: this lane is never required CI — do not wire
# it into .github/workflows/xinchuang-ci.yml and never gate merges on it.
#
# Consumes (does NOT re-decide) the recorded decisions:
#   - docs/verification/2026-09-20-meet-renderer-qualification.md §11/§11.1
#     (linux-ci-host re-qualification follow-up; receipt conventions with
#     platform-marked rows): the darwin/arm64 pins stay; linux/amd64 pins
#     land BESIDE them.
#   - retired-docs:verification/2026-09-22-portfolio-execution.md wave-1 module B:
#     the frozen rev-2 corpus stays renderer input everywhere; the Linux
#     capture lands in platform-marked rows at manifest rev 3. THIS LANE
#     ONLY RECORDS run-scoped receipts; it never edits
#     docs/verification/meet-m0-corpus.json and never commits.
#
# Protocol (review-ordered: download artifacts first, measure after, and
# prove the network denial bites BEFORE any measurement):
#   A1 corpus verify      — the frozen manifest must verify on the checkout.
#   A2 pinned engine      — LibreOffice (TDF deb tarball, sidecar-pinned
#                           sha256); post-install `soffice --version` MUST
#                           equal the engine pin.
#   A3 pinned pdfium      — bblanchon/pdfium-binaries release asset,
#                           digest-verified download.
#   A4 producer capture   — scripts/gen-meet-m0-corpus.sh acquire (staging
#                           only; its JSON fragment is the receipt input for
#                           the future rev-3 platform-marked rows).
#   B  net-denial canary  — bwrap smoke (MUST start), denied probes (MUST
#                           fail), control probe (MUST pass). Any other
#                           outcome fails loudly: on Ubuntu 24.04 AppArmor
#                           can stop bubblewrap entirely, and "bwrap failed
#                           to start" is NEVER reported as "denial works".
#   C  measurement        — poppler CLI and pdfium (offline C harness),
#                           3 runs x every frozen corpus PDF, all under
#                           `bwrap --unshare-net`: per-run page-asset
#                           determinism, page-count fidelity vs the frozen
#                           manifest, non-blank + text correctness,
#                           whole-document latency, peak RSS.
#
# Receipts (run-scoped, same conventions as the 2026-09-20 record §1/§11.1):
#   $MEET_QUAL_RUN_DIR/receipt/ — status.txt, engine.json, pdfium.json,
#   canary.txt, producer-capture-fragment.json, measurement.json, run.json.
#   The CI lane uploads the whole directory as a workflow artifact. The run
#   receipt is platform-marked (linux/amd64) and references the consumed
#   decisions; the rev-3 manifest re-pin itself stays with the owning
#   authority, never with this lane.
#
# Usage:
#   scripts/run-meet-renderer-qualification.sh --dry-run
#       Validate inputs, print the resolved step plan, WRITE NOTHING.
#       Never fails on host tooling (the full run is linux-only); input or
#       pin errors still fail with a nonzero exit.
#   scripts/run-meet-renderer-qualification.sh
#       Full run (linux/amd64 only).
#
# Environment (all optional; defaults are the qualified pins):
#   MEET_QUAL_ENGINE_VERSION        LibreOffice engine pin; the post-install
#                                   `soffice --version` must match.
#                                   [default: 26.8.0.3]
#   MEET_QUAL_ENGINE_TARBALL_SHA256 engine tarball sha256 override — only
#                                   for a NEW owner-approved engine pin
#                                   (normally add it to engine_tarball_pin).
#   MEET_QUAL_SOFFICE               use an already-installed soffice binary;
#                                   its version must still match the pin
#                                   (skips A2 download/install).
#   MEET_QUAL_PDFIUM_REF            [default: chromium/8057]
#   MEET_QUAL_PDFIUM_ASSET          [default: pdfium-linux-x64.tgz]
#   MEET_QUAL_PDFIUM_SHA256         asset sha256 override — only for a NEW
#                                   owner-approved pin (normally add it to
#                                   pdfium_pin).
#   MEET_QUAL_RUN_DIR               output/receipt dir
#                                   [default: /tmp/setjoin-meet-renderer-qual-<utc>]

source "$(dirname "$0")/_base.sh"

# /usr/bin/time -v labels its fields in the host locale, and the decimal point
# in the elapsed field follows LC_NUMERIC. Pin the C locale so time_parse.py
# matches the English labels and float() reads the seconds field.
export LC_ALL=C

# ---------------------------------------------------------------------------
# Pins (digest-verified downloads; fail-closed: an unpinned input is refused)
# ---------------------------------------------------------------------------

ENGINE_VERSION="${MEET_QUAL_ENGINE_VERSION:-26.8.0.3}"
PDFIUM_REF="${MEET_QUAL_PDFIUM_REF:-chromium/8057}"
PDFIUM_ASSET="${MEET_QUAL_PDFIUM_ASSET:-pdfium-linux-x64.tgz}"
DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1 ;;
  "") : ;;
  --help | -h)
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    echo "run-meet-renderer-qualification: unknown argument '$1' (use --dry-run or nothing)" >&2
    exit 2
    ;;
esac
RUN_DIR="${MEET_QUAL_RUN_DIR:-/tmp/setjoin-meet-renderer-qual-$(date -u +%Y%m%dT%H%M%SZ)}"

CORPUS_DIR="$ROOT/mailserver/internal/meet/presentation/testdata/corpus"
MANIFEST="$ROOT/docs/verification/meet-m0-corpus.json"
GEN="$ROOT/scripts/gen-meet-m0-corpus.sh"
TDF_BASE="https://download.documentfoundation.org/libreoffice/stable"
PDFIUM_DL_BASE="https://github.com/bblanchon/pdfium-binaries/releases/download"

# Engine pin: sha256 of the TDF deb tarball (TDF-published .sha256 sidecar,
# captured 2026-09-23), keyed by engine micro version. TDF names the
# fresh-stable tarball by the three-component version; the fourth (micro)
# component is the build inside — 26.8.0.3 ships as stable/26.8.0/, which is
# how the 2026-09-20 darwin run got cask "26.8.0" with soffice 26.8.0.3.
engine_tarball_pin() {
  case "$1" in
    26.8.0.3) echo "d0a6031a3837e48f9854e6d2da6489b9fadbd814afa4741fa32a197741663a22" ;;
    *) return 1 ;;
  esac
}

# pdfium pin: sha256 of the release asset (GitHub-published asset digest,
# captured 2026-09-23 via the releases API), keyed by "<ref>/<asset>".
pdfium_pin() {
  case "$1" in
    chromium/8057/pdfium-linux-x64.tgz)
      echo "7788fa57a2996ebd21afc4090eb0a42b9f95ef3a72e7ef4c0756f1ea703c0415"
      ;;
    *) return 1 ;;
  esac
}

# ---------------------------------------------------------------------------
# Input resolution + validation
# ---------------------------------------------------------------------------

is_hex256() {
  case "$1" in *[!0-9a-f]* | '') return 1 ;; esac
  [ ${#1} -eq 64 ]
}

case "$ENGINE_VERSION" in
  [0-9]*) : ;;
  *)
    echo "input error: MEET_QUAL_ENGINE_VERSION '$ENGINE_VERSION' is not a version" >&2
    exit 1
    ;;
esac
n_engine_dots=$(printf %s "$ENGINE_VERSION" | tr -cd . | wc -c)
if [ "$n_engine_dots" -ne 3 ]; then
  echo "input error: MEET_QUAL_ENGINE_VERSION '$ENGINE_VERSION' must be micro-qualified (major.minor.patch.micro, e.g. 26.8.0.3)" >&2
  exit 1
fi
ENGINE_TARBALL_VERSION="${ENGINE_VERSION%.*}"

ENGINE_SHA256="${MEET_QUAL_ENGINE_TARBALL_SHA256:-}"
if [ -z "$ENGINE_SHA256" ]; then
  ENGINE_SHA256=$(engine_tarball_pin "$ENGINE_VERSION") || {
    echo "input error: no pinned TDF tarball digest for engine $ENGINE_VERSION; add an owner-approved pin to engine_tarball_pin or set MEET_QUAL_ENGINE_TARBALL_SHA256" >&2
    exit 1
  }
fi
is_hex256 "$ENGINE_SHA256" || {
  echo "input error: engine tarball digest is not 64 lowercase hex chars" >&2
  exit 1
}

case "$PDFIUM_REF" in
  [A-Za-z0-9]*) : ;;
  *)
    echo "input error: MEET_QUAL_PDFIUM_REF '$PDFIUM_REF' has an unsafe shape" >&2
    exit 1
    ;;
esac
case "$PDFIUM_REF" in *[!A-Za-z0-9._/-]*)
  echo "input error: MEET_QUAL_PDFIUM_REF '$PDFIUM_REF' has an unsafe character" >&2
  exit 1
  ;;
esac
case "$PDFIUM_ASSET" in
  [A-Za-z0-9]*) : ;;
  *)
    echo "input error: MEET_QUAL_PDFIUM_ASSET '$PDFIUM_ASSET' has an unsafe shape" >&2
    exit 1
    ;;
esac
case "$PDFIUM_ASSET" in *[!A-Za-z0-9._-]*)
  echo "input error: MEET_QUAL_PDFIUM_ASSET '$PDFIUM_ASSET' has an unsafe character" >&2
  exit 1
  ;;
esac

PDFIUM_SHA256="${MEET_QUAL_PDFIUM_SHA256:-}"
if [ -z "$PDFIUM_SHA256" ]; then
  PDFIUM_SHA256=$(pdfium_pin "$PDFIUM_REF/$PDFIUM_ASSET") || {
    echo "input error: no pinned digest for pdfium asset $PDFIUM_REF/$PDFIUM_ASSET; add an owner-approved pin to pdfium_pin or set MEET_QUAL_PDFIUM_SHA256" >&2
    exit 1
  }
fi
is_hex256 "$PDFIUM_SHA256" || {
  echo "input error: pdfium digest is not 64 lowercase hex chars" >&2
  exit 1
}

ENGINE_TARBALL_URL="$TDF_BASE/$ENGINE_TARBALL_VERSION/deb/x86_64/LibreOffice_${ENGINE_TARBALL_VERSION}_Linux_x86-64_deb.tar.gz"
PDFIUM_URL="$PDFIUM_DL_BASE/$PDFIUM_REF/$PDFIUM_ASSET"

for f in "$GEN" "$MANIFEST"; do
  [ -f "$f" ] || {
    echo "input error: missing $f (run from a setjoin checkout)" >&2
    exit 1
  }
done

# Manifest sanity: revision + frozen pdf rows (the measurement inputs).
MANIFEST_JSON=$(
  python3 - "$MANIFEST" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as f:
    m = json.load(f)
pdf_rows = [e for e in m["entries"]
            if e.get("format") == "pdf"
            and not (e.get("class") == "producer-pinned" and e.get("status") == "acquisition-pending")]
print(json.dumps({"revision": m.get("revision"), "pdfRows": len(pdf_rows),
                  "pdfFiles": [e["file"] for e in pdf_rows],
                  "pdfCounts": [e.get("count") for e in pdf_rows]}))
PY
) || {
  echo "input error: cannot parse $MANIFEST" >&2
  exit 1
}
MANIFEST_REVISION=$(printf %s "$MANIFEST_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["revision"])')
MANIFEST_PDF_ROWS=$(printf %s "$MANIFEST_JSON" | python3 -c 'import json,sys;print(json.load(sys.stdin)["pdfRows"])')

# Host tooling: informational in --dry-run, hard-required in the full run.
TOOLS="python3 curl tar sha256sum bwrap pdftoppm pdftotext cc dpkg /usr/bin/time"
TOOL_REPORT=""
TOOLS_OK=1
for t in $TOOLS; do
  if command -v "$t" >/dev/null 2>&1; then
    TOOL_REPORT="$TOOL_REPORT  ok      $t
"
  else
    TOOL_REPORT="$TOOL_REPORT  MISSING $t
"
    TOOLS_OK=0
  fi
done

if [ "$DRY_RUN" -eq 1 ]; then
  cat <<EOF
run-meet-renderer-qualification --dry-run
=========================================
DRY RUN: validated inputs only; nothing has been written.

Inputs / pins (fail-closed; defaults are the qualified pins):
  engine pin (soffice --version)   $ENGINE_VERSION
  engine tarball                   $ENGINE_TARBALL_URL
  engine tarball sha256            $ENGINE_SHA256  (TDF sidecar pin, captured 2026-09-23)
  pdfium                           $PDFIUM_URL
  pdfium sha256                    $PDFIUM_SHA256  (GitHub asset digest pin, captured 2026-09-23)
  manifest                         docs/verification/meet-m0-corpus.json (revision $MANIFEST_REVISION, $MANIFEST_PDF_ROWS frozen pdf rows)
  output dir (full run)            $RUN_DIR

Guard: non-required, manually-triggered lane ONLY (workflow_dispatch);
never wire into .github/workflows/xinchuang-ci.yml; never gate merges on it.

Step plan (downloads first, measure after, canary before measurement):
  A1  corpus verify        bash scripts/gen-meet-m0-corpus.sh verify
  A2  pinned engine        download $ENGINE_TARBALL_VERSION debs + sha256 verify + dpkg install;
                           post-install 'soffice --version' must equal $ENGINE_VERSION
                           (skipped when MEET_QUAL_SOFFICE is provided and matches)
  A3  pinned pdfium        download $PDFIUM_ASSET ($PDFIUM_REF) + sha256 verify + extract
  A4  producer capture     scripts/gen-meet-m0-corpus.sh acquire (staging only;
                           fragment -> receipt/producer-capture-fragment.json for the
                           future manifest rev-3 platform-marked rows — recorded, never re-pinned here)
  B   net-denial canary    bwrap smoke (must start); 'bwrap --unshare-net' probes (must FAIL);
                           control probe without sandbox (must pass). Any other outcome
                           fails loudly — 'bwrap failed to start' is never 'denial works'.
  C   measurement          under 'bwrap --unshare-net': poppler CLI + pdfium C harness,
                           3 runs x $MANIFEST_PDF_ROWS frozen corpus PDFs @150 dpi:
                           determinism (per-page sha256), page-count fidelity vs the
                           frozen manifest, non-blank + text correctness, latency, peak RSS.
  R   receipts             $RUN_DIR/receipt/ (run.json platform-marked linux/amd64;
                           the CI lane uploads it as a run-scoped artifact; nothing is
                           committed and the frozen manifest is never edited)

Host tooling (informational in dry-run; the full run enforces every entry):
$TOOL_REPORT
EOF
  exit 0
fi

# ---------------------------------------------------------------------------
# Full run (linux/amd64 only)
# ---------------------------------------------------------------------------

die() {
  echo "run-meet-renderer-qualification: FAIL: $*" >&2
  exit 1
}
[ "$(uname -s)" = "Linux" ] || die "full run requires linux/amd64 (this host: $(uname -s)); use --dry-run elsewhere"
[ "$(uname -m)" = "x86_64" ] || die "full run requires linux/amd64 (this host: $(uname -s)/$(uname -m))"
[ "$TOOLS_OK" -eq 1 ] || {
  printf '%s' "run-meet-renderer-qualification: FAIL: missing host tools:
$TOOL_REPORT" >&2
  exit 1
}

mkdir -p "$RUN_DIR/receipt" "$RUN_DIR/tools"
RECEIPT="$RUN_DIR/receipt"
status() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$RECEIPT/status.txt"; }
status "lane start (linux/amd64); run dir $RUN_DIR"
status "consumes: frozen rev-$MANIFEST_REVISION corpus stays renderer input everywhere; Linux capture -> platform-marked rows at manifest rev 3 (2026-09-20 record §11/§11.1; wave-1 module-B decision). This lane records receipts only."

# --- A1: corpus verify -----------------------------------------------------
status "A1 corpus verify"
(cd "$ROOT" && bash scripts/gen-meet-m0-corpus.sh verify) || die "A1: frozen manifest verify failed on this checkout"

# --- A2: pinned engine ------------------------------------------------------
SOFFICE_BIN="${MEET_QUAL_SOFFICE:-}"
ENGINE_JSON="$RECEIPT/engine.json"
if [ -n "$SOFFICE_BIN" ]; then
  status "A2 engine: using provided soffice $SOFFICE_BIN (no download/install)"
else
  status "A2 engine: downloading $ENGINE_TARBALL_URL"
  TARBALL="$RUN_DIR/LibreOffice_${ENGINE_TARBALL_VERSION}_Linux_x86-64_deb.tar.gz"
  curl -fsSL -o "$TARBALL" "$ENGINE_TARBALL_URL" || die "A2: engine tarball download failed"
  (cd "$(dirname "$TARBALL")" && echo "$ENGINE_SHA256  $(basename "$TARBALL")" | sha256sum -c - >/dev/null) ||
    die "A2: engine tarball sha256 mismatch (expected $ENGINE_SHA256)"
  status "A2 engine: sha256 verified ($ENGINE_SHA256); installing debs"
  ENGINE_SRC="$RUN_DIR/engine-src"
  mkdir -p "$ENGINE_SRC"
  tar -xzf "$TARBALL" -C "$ENGINE_SRC" || die "A2: engine tarball extract failed"
  find "$ENGINE_SRC" -type f -name '*.deb' -print0 | xargs -0 sudo dpkg -i --force-confold ||
    die "A2: dpkg install of the pinned engine failed"
  rm -rf "$ENGINE_SRC" "$TARBALL"
  SOFFICE_BIN="/opt/libreoffice$(printf %s "$ENGINE_TARBALL_VERSION" | sed 's/^\([0-9]*\)\.\([0-9]*\)$/\1.\2/')/program/soffice"
  if [ ! -x "$SOFFICE_BIN" ]; then
    SOFFICE_BIN=$(find /opt -maxdepth 3 -type f -path '*program/soffice' 2>/dev/null | head -1)
  fi
  [ -n "$SOFFICE_BIN" ] && [ -x "$SOFFICE_BIN" ] || die "A2: installed soffice binary not found under /opt"
fi
ENGINE_OBSERVED=$("$SOFFICE_BIN" --version 2>/dev/null | head -1) || die "A2: soffice --version failed"
case "$ENGINE_OBSERVED" in
  "LibreOffice $ENGINE_VERSION" | "LibreOffice $ENGINE_VERSION "*) : ;;
  *) die "A2: engine pin mismatch: observed '$ENGINE_OBSERVED', pinned 'LibreOffice $ENGINE_VERSION'" ;;
esac
status "A2 engine: verbatim '$ENGINE_OBSERVED' matches pin"
python3 - "$ENGINE_JSON" "$ENGINE_VERSION" "$ENGINE_OBSERVED" "$ENGINE_TARBALL_URL" "$ENGINE_SHA256" <<'PY'
import json, sys
path, pin, observed, url, sha = sys.argv[1:6]
doc = {
    "kind": "pinned-producer-engine",
    "platform": "linux/amd64",
    "enginePin": pin,
    "observedVersionVerbatim": observed,
    "tarballUrl": url,
    "tarballSha256": sha,
    "tarballPinProvenance": "TDF-published .sha256 sidecar, captured 2026-09-23, pinned in scripts/run-meet-renderer-qualification.sh",
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
status "A2 engine: receipt engine.json written"

# --- A3: pinned pdfium ------------------------------------------------------
status "A3 pdfium: downloading $PDFIUM_URL"
PDFIUM_TGZ="$RUN_DIR/$PDFIUM_ASSET"
curl -fsSL -o "$PDFIUM_TGZ" "$PDFIUM_URL" || die "A3: pdfium asset download failed"
echo "$PDFIUM_SHA256  $(basename "$PDFIUM_TGZ")" | (cd "$(dirname "$PDFIUM_TGZ")" && sha256sum -c - >/dev/null) ||
  die "A3: pdfium asset sha256 mismatch (expected $PDFIUM_SHA256)"
status "A3 pdfium: sha256 verified ($PDFIUM_SHA256); extracting"
PDFIUM_DIR="$RUN_DIR/pdfium"
mkdir -p "$PDFIUM_DIR"
tar -xzf "$PDFIUM_TGZ" -C "$PDFIUM_DIR" || die "A3: pdfium extract failed"
rm -f "$PDFIUM_TGZ"
[ -f "$PDFIUM_DIR/include/fpdfview.h" ] || die "A3: unexpected pdfium tarball layout (no include/fpdfview.h)"
[ -f "$PDFIUM_DIR/lib/libpdfium.so" ] || die "A3: unexpected pdfium tarball layout (no lib/libpdfium.so)"
python3 - "$RECEIPT/pdfium.json" "$PDFIUM_REF" "$PDFIUM_ASSET" "$PDFIUM_SHA256" "$PDFIUM_URL" <<'PY'
import json, sys
path, ref, asset, sha, url = sys.argv[1:6]
doc = {
    "kind": "pinned-paging-primitive-artifact",
    "platform": "linux/amd64",
    "ref": ref,
    "asset": asset,
    "assetSha256": sha,
    "assetUrl": url,
    "digestProvenance": "GitHub-published release asset digest, captured 2026-09-23, pinned in scripts/run-meet-renderer-qualification.sh",
    "buildPins": {"pdf_enable_v8": False, "pdf_enable_xfa": False},
}
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
status "A3 pdfium: receipt pdfium.json written"

# --- A4: producer capture (staging only; fragment recorded) -----------------
status "A4 producer capture via scripts/gen-meet-m0-corpus.sh acquire (staging dir, never the corpus)"
(cd "$ROOT" && SOFFICE="$SOFFICE_BIN" bash scripts/gen-meet-m0-corpus.sh acquire) \
  >"$RECEIPT/producer-capture-fragment.json" ||
  die "A4: producer capture failed"
status "A4 producer capture: fragment written (platform-marked linux/amd64 rows for the rev-3 re-pin owner; recorded, not applied)"

# --- B: network-denial canary ----------------------------------------------
# Distinguish the three outcomes the review required:
#   1. bwrap cannot start at all (Ubuntu 24.04 AppArmor unprivileged-userns
#      restriction) -> LOUD failure, never a pass.
#   2. bwrap runs, network denial does NOT bite -> LOUD failure.
#   3. denial bites AND control passes -> proven; measurement may proceed.
status "B canary: proving bubblewrap network denial actually blocks"
CANARY="$RECEIPT/canary.txt"
CANARY_PROBE='import socket, sys
try:
    s = socket.create_connection(("github.com", 443), timeout=10)
    s.close()
    sys.exit(0)
except Exception as exc:
    print("probe denied: %r" % (exc,), file=sys.stderr)
    sys.exit(1)'
BWRAP=(bwrap --die-with-parent --unshare-net --dev-bind / / --dev /dev --proc /proc)

{
  echo "canary evidence (network denial must be proven BEFORE measurement)"
  echo "sysctl kernel.apparmor_restrict_unprivileged_userns = $(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 'n/a')"
} >"$CANARY"

if ! "${BWRAP[@]}" true 2>>"$CANARY"; then
  {
    echo "SMOKE FAIL: bubblewrap could not start a trivial sandbox."
    echo "On GitHub-hosted/Ubuntu 24.04, AppArmor (kernel.apparmor_restrict_unprivileged_userns=1)"
    echo "can stop bwrap entirely. 'bwrap failed to start' is NOT 'network denial works'."
    echo "Resolve the host userns/AppArmor posture for the runner, then re-run this manual lane."
  } >>"$CANARY"
  status "B canary: FAILED — bwrap cannot start (see receipt/canary.txt)"
  die "B: bubblewrap failed to start; network denial unproven — refusing to measure"
fi
echo "SMOKE PASS: bwrap starts a trivial sandbox" >>"$CANARY"
status "B canary: bwrap smoke passed (bwrap itself is functional)"

DENIED_RC=0
"${BWRAP[@]}" python3 -c "$CANARY_PROBE" >>"$CANARY" 2>&1 || DENIED_RC=$?
if [ "$DENIED_RC" -eq 0 ]; then
  echo "DENIED-CANARY FAIL: socket connect SUCCEEDED under --unshare-net; denial does not bite" >>"$CANARY"
  status "B canary: FAILED — denial did not bite"
  die "B: network denial did not bite inside bwrap --unshare-net — refusing to measure"
fi
echo "DENIED-CANARY PASS: socket connect failed under --unshare-net (rc=$DENIED_RC)" >>"$CANARY"

DENIED_CURL_RC=0
"${BWRAP[@]}" curl -fsS --max-time 10 -o /dev/null https://github.com >>"$CANARY" 2>&1 || DENIED_CURL_RC=$?
if [ "$DENIED_CURL_RC" -eq 0 ]; then
  echo "DENIED-CURL FAIL: curl SUCCEEDED under --unshare-net; denial does not bite" >>"$CANARY"
  status "B canary: FAILED — curl denial did not bite"
  die "B: curl network denial did not bite inside bwrap — refusing to measure"
fi
echo "DENIED-CURL PASS: curl failed under --unshare-net (rc=$DENIED_CURL_RC)" >>"$CANARY"

CONTROL_RC=0
python3 -c "$CANARY_PROBE" >>"$CANARY" 2>&1 || CONTROL_RC=$?
if [ "$CONTROL_RC" -ne 0 ]; then
  echo "CONTROL FAIL: same probe WITHOUT the sandbox also failed (rc=$CONTROL_RC); canary inconclusive" >>"$CANARY"
  status "B canary: FAILED — control probe failed (environment lacks the network the denial denies)"
  die "B: control probe failed — cannot prove the denial is the cause — refusing to measure"
fi
echo "CONTROL PASS: same probe without the sandbox succeeded (denial, not breakage, is the difference)" >>"$CANARY"
status "B canary: PROVEN (smoke + denied-fails + control-passes); measurement may proceed"

# --- C: measurement under bubblewrap network denial ------------------------
status "C measurement: building offline pdfium harness"
cat >"$RUN_DIR/tools/pdfium_harness.c" <<'C'
/* Offline MEET renderer-qualification pdfium harness (wave-1 unit B3).
   Renders every page of one PDF to P6 PPM at a fixed DPI over an opaque
   white background (annotations on, FPDF_ANNOT), prints page/text/rss
   counters, exits nonzero on any pdfium failure. Network-free by
   construction; the qualification runs it under bwrap --unshare-net
   (canary-proven). The pin is the pristine upstream libpdfium.so digest —
   this harness only links it, never modifies it. */
#include <fpdf_text.h>
#include <fpdfview.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

static void die(const char *msg) {
  fprintf(stderr, "pdfium_harness: %s\n", msg);
  exit(2);
}

int main(int argc, char **argv) {
  if (argc != 4) die("usage: pdfium_harness <in.pdf> <outdir> <dpi>");
  const char *pdf = argv[1], *outdir = argv[2];
  const double dpi = atof(argv[3]);
  if (dpi <= 0.0) die("bad dpi");

  FPDF_LIBRARY_CONFIG cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.version = 2;
  FPDF_InitLibraryWithConfig(&cfg);

  FPDF_DOCUMENT doc = FPDF_LoadDocument(pdf, NULL);
  if (!doc) die("FPDF_LoadDocument failed");
  const int n = FPDF_GetPageCount(doc);
  const double scale = dpi / 72.0;
  long chars_total = 0;

  for (int i = 0; i < n; i++) {
    FPDF_PAGE page = FPDF_LoadPage(doc, i);
    if (!page) die("FPDF_LoadPage failed");
    const double pw = FPDF_GetPageWidth(page), ph = FPDF_GetPageHeight(page);
    const int w = (int)(pw * scale + 0.5), h = (int)(ph * scale + 0.5);
    if (w < 1 || h < 1 || w > 16384 || h > 16384) die("implausible page size");
    FPDF_BITMAP bmp = FPDFBitmap_Create(w, h, 0);
    if (!bmp) die("FPDFBitmap_Create failed");
    FPDFBitmap_FillRect(bmp, 0, 0, w, h, 0xFFFFFFFFu);
    FPDF_RenderPageBitmap(bmp, page, 0, 0, w, h, 0, FPDF_ANNOT);
    FPDF_TEXTPAGE tp = FPDFText_LoadPage(page);
    if (tp) {
      chars_total += FPDFText_CountChars(tp);
      FPDFText_ClosePage(tp);
    }

    char path[4096];
    snprintf(path, sizeof(path), "%s/page-%06d.ppm", outdir, i + 1);
    FILE *f = fopen(path, "wb");
    if (!f) die("fopen(outdir) failed — create the run dir first");
    fprintf(f, "P6\n%d %d\n255\n", w, h);
    const int fmt = FPDFBitmap_GetFormat(bmp);
    const int bpp = (fmt == FPDFBitmap_BGRA || fmt == FPDFBitmap_BGRx) ? 4 : 3;
    const uint8_t *buf = (const uint8_t *)FPDFBitmap_GetBuffer(bmp);
    const int stride = FPDFBitmap_GetStride(bmp);
    static uint8_t row[16384 * 3];
    if (w * 3 > (int)sizeof(row)) die("page too wide for row buffer");
    for (int y = 0; y < h; y++) {
      const uint8_t *src = buf + (size_t)y * (size_t)stride;
      for (int x = 0; x < w; x++) { /* BGRA/BGR -> PPM RGB */
        row[x * 3 + 0] = src[x * bpp + 2];
        row[x * 3 + 1] = src[x * bpp + 1];
        row[x * 3 + 2] = src[x * bpp + 0];
      }
      fwrite(row, 3, (size_t)w, f);
    }
    fclose(f);
    FPDFBitmap_Destroy(bmp);
    FPDF_ClosePage(page);
  }

  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  printf("PAGES %d\nCHARS %ld\nRSS_KB %ld\n", n, chars_total, ru.ru_maxrss);
  FPDF_CloseDocument(doc);
  FPDF_DestroyLibrary();
  return 0;
}
C
(cd "$RUN_DIR/tools" && cc -O2 -I"$PDFIUM_DIR/include" -o pdfium_harness pdfium_harness.c \
  -L"$PDFIUM_DIR/lib" -lpdfium -Wl,-rpath,"$PDFIUM_DIR/lib" -lm) ||
  die "C: pdfium harness build failed"

status "C measurement: rendering under bwrap --unshare-net (3 runs x $MANIFEST_PDF_ROWS docs x 2 candidates)"
python3 - "$RUN_DIR/tools" <<'PY'
import json, os, sys
tools = sys.argv[1]

# page_digests.py: identity digest over the sorted page assets of one run.
with open(os.path.join(tools, "page_digests.py"), "w", encoding="utf-8") as f:
    f.write('''import hashlib, json, os, sys
d = sys.argv[1]
entries = []
for name in sorted(os.listdir(d)):
    if not name.endswith(".ppm"):
        continue
    with open(os.path.join(d, name), "rb") as f:
        entries.append((name, hashlib.sha256(f.read()).hexdigest()))
blob = "".join("%s %s\\n" % (h, n) for n, h in sorted(entries))
print(json.dumps({"pages": len(entries),
                  "identitySha256": hashlib.sha256(blob.encode()).hexdigest(),
                  "perPageSha256": dict(entries)}))
''')

# dark_fraction.py: non-blank probe over a 1/4 pixel-grid sample
# (every 2nd row x every 2nd pixel), P6 input, luminance proxy r+g+b < 384.
with open(os.path.join(tools, "dark_fraction.py"), "w", encoding="utf-8") as f:
    f.write('''import sys
path = sys.argv[1]
with open(path, "rb") as f:
    assert f.read(2) == b"P6", "not a P6 PPM"
    vals = []
    while len(vals) < 3:
        line = f.readline()
        if not line or line.startswith(b"#"):
            continue
        vals += [int(x) for x in line.split()]
    w, h, _maxv = vals[0], vals[1], vals[2]
    data = f.read(w * h * 3)
dark = total = 0
for y in range(0, h, 2):
    base = y * w * 3
    for x in range(0, w, 2):
        o = base + x * 3
        if data[o] + data[o + 1] + data[o + 2] < 384:
            dark += 1
        total += 1
print("%.6f" % (dark / total if total else 0.0))
''')

# time_parse.py: /usr/bin/time -v output -> elapsed ms + max rss KB.
with open(os.path.join(tools, "time_parse.py"), "w", encoding="utf-8") as f:
    f.write('''import json, sys
txt = open(sys.argv[1], encoding="utf-8", errors="replace").read()
elapsed = rss = None
for raw in txt.splitlines():
    # /usr/bin/time -v indents every field with a tab; without stripping, the
    # startswith tests below never match and both counters stay null.
    line = raw.strip()
    if line.startswith("Elapsed (wall clock) time"):
        v = line.split("): ", 1)[1].strip()
        parts = v.split(":")
        sec = float(parts[-1])
        if len(parts) > 1:
            sec += int(parts[-2]) * 60
        if len(parts) > 2:
            sec += int(parts[-3]) * 3600
        elapsed = int(round(sec * 1000))
    elif line.startswith("Maximum resident set size"):
        rss = int(line.rsplit(": ", 1)[1].strip())
print(json.dumps({"elapsedMs": elapsed, "maxRssKb": rss}))
''')

# summarize.py: fold the per-run records into measurement.json + verdict.
# Correctness is judged on run 1: dark sampling + text extraction are
# recorded once per doc/candidate (runs 2-3 record null/0 placeholders and
# exist to prove per-page byte determinism).
with open(os.path.join(tools, "summarize.py"), "w", encoding="utf-8") as f:
    f.write('''import glob, json, os, sys
run_dir, out = sys.argv[1], sys.argv[2]
expected = {}
for line in open(sys.argv[3], encoding="utf-8"):
    name, count = line.rstrip("\\n").split("\\t")
    expected[name] = int(count)
docs = []
all_ok = True
for name in sorted(expected):
    stem = name.rsplit(".", 1)[0]  # measure tree dirs use the file stem
    doc = {"file": name, "expectedPages": expected[name], "candidates": {}}
    for cand in ("poppler", "pdfium"):
        runs = [json.load(open(p, encoding="utf-8"))
                for p in sorted(glob.glob(os.path.join(run_dir, "measure", stem, cand, "run*", "run.json")))]
        ids = {r["identitySha256"] for r in runs}
        pages = {r["pages"] for r in runs}
        determinism = len(runs) == 3 and len(ids) == 1 and pages == {expected[name]}
        fidelity = pages == {expected[name]}
        first = runs[0] if runs else {}
        correctness = bool(first.get("darkFractions")
                           and min(first["darkFractions"]) > 0.0
                           and first.get("textChars", 0) > 0)
        # The protocol promises whole-document wall latency AND peak RSS. A run
        # that recorded neither did not measure them. Fail closed rather than
        # pass a receipt that silently drops a declared dimension.
        counters = bool(runs) and all(
            r.get("elapsedMs") is not None and r.get("maxRssKb") is not None
            for r in runs)
        ok = bool(runs and determinism and fidelity and correctness and counters)
        all_ok = all_ok and ok
        doc["candidates"][cand] = {
            "runs": runs,
            "determinism": bool(determinism),
            "pageCountFidelity": bool(fidelity),
            "correctness": correctness,
            "latencyAndRssRecorded": counters,
            "verdict": "PASS" if ok else "FAIL",
        }
    docs.append(doc)
result = {
    "schemaVersion": "setjoin.meet.renderer-qualification-measurement/1",
    "kind": "renderer-requalification-measurement",
    "platform": "linux/amd64",
    "protocol": "3 runs x every frozen corpus PDF @150 dpi; per-page sha256 determinism; "
                "page-count fidelity vs the frozen manifest; non-blank sampling "
                "(1/mid/last, 1/4 pixel grid) + text-char correctness; whole-document "
                "wall latency (timed child inside the sandbox, symmetric across "
                "candidates); peak RSS",
    "networkIsolation": "bwrap --unshare-net (canary-proven before any measurement)",
    "docs": docs,
    "verdict": "PASS" if all_ok else "FAIL",
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(result, f, indent=2, sort_keys=True)
    f.write("\\n")
print("measurement verdict: %s" % result["verdict"])
''')
PY
printf %s "$MANIFEST_JSON" | python3 -c '
import json, sys
m = json.load(sys.stdin)
for name, count in zip(m["pdfFiles"], m["pdfCounts"]):
    print("%s\t%s" % (name, count))' >"$RUN_DIR/tools/pdf_docs.tsv"
status "C measurement: input list written ($(wc -l <"$RUN_DIR/tools/pdf_docs.tsv") frozen pdf rows)"

MEASURE="$RUN_DIR/measure"
RENDER_DPI=150
CORPUS_ROOT="$CORPUS_DIR"
while IFS=$'\t' read -r DOCFILE EXPECTED; do
  [ -n "$DOCFILE" ] || continue
  STEM="${DOCFILE%.*}"
  DOC_PDF="$CORPUS_ROOT/$DOCFILE"
  [ -f "$DOC_PDF" ] || die "C: frozen corpus pdf missing: $DOC_PDF"
  status "C measurement: $STEM (expected pages: $EXPECTED)"

  for RUN_N in 1 2 3; do
    # --- poppler run ------------------------------------------------------
    OUT="$MEASURE/$STEM/poppler/run$RUN_N"
    mkdir -p "$OUT"
    "${BWRAP[@]}" /usr/bin/time -v -o "$OUT/time.txt" \
      pdftoppm -r "$RENDER_DPI" "$DOC_PDF" "$OUT/page" \
      2>>"$CANARY" || die "C: pdftoppm failed ($STEM poppler run$RUN_N)"
    python3 "$RUN_DIR/tools/page_digests.py" "$OUT" >"$OUT/digests.json"
    PAGES=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pages"])' "$OUT/digests.json")
    [ "$PAGES" -eq "$EXPECTED" ] || status "C measurement: NOTE poppler run$RUN_N rendered $PAGES pages (expected $EXPECTED)"
    if [ "$RUN_N" -eq 1 ]; then
      DARKS="["
      SEP=""
      for PG in 1 $(((PAGES + 1) / 2)) "$PAGES"; do
        F=""
        for PF in "$OUT"/page-*.ppm; do
          N=$(basename "$PF" .ppm)
          N="${N#page-}"
          if [ "$N" -eq "$PG" ] 2>/dev/null; then
            F=$(python3 "$RUN_DIR/tools/dark_fraction.py" "$PF")
            break
          fi
        done
        [ -n "$F" ] || die "C: sampled page $PG missing ($STEM poppler)"
        DARKS="$DARKS$SEP$F"
        SEP=", "
      done
      DARKS="$DARKS]"
      TEXT_CHARS=$({ "${BWRAP[@]}" pdftotext "$DOC_PDF" - 2>>"$CANARY" || true; } | wc -c)
    else
      DARKS="null"
      TEXT_CHARS=0
    fi
    python3 "$RUN_DIR/tools/time_parse.py" "$OUT/time.txt" >"$OUT/time.json"
    python3 - "$OUT/run.json" "$OUT/digests.json" "$OUT/time.json" "$PAGES" "$DARKS" "$TEXT_CHARS" <<'PY'
import json, sys
out, digests, t, pages, darks, chars = sys.argv[1:8]
d = json.load(open(digests)); tv = json.load(open(t))
try:
    darks = json.loads(darks)
except Exception:
    darks = None
doc = {"run": None, "pages": int(pages), "identitySha256": d["identitySha256"],
       "elapsedMs": tv["elapsedMs"], "maxRssKb": tv["maxRssKb"],
       "darkFractions": darks, "textChars": int(chars)}
import os
doc["run"] = int(os.path.basename(os.path.dirname(out)).replace("run", ""))
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
    # Pages are discardable: only digests + counters are retained per run.
    rm -f "$OUT"/page-*.ppm

    # --- pdfium run ---------------------------------------------------------
    OUT="$MEASURE/$STEM/pdfium/run$RUN_N"
    mkdir -p "$OUT"
    "${BWRAP[@]}" /usr/bin/time -v -o "$OUT/time.txt" \
      "$RUN_DIR/tools/pdfium_harness" "$DOC_PDF" "$OUT" "$RENDER_DPI" \
      >"$OUT/harness.txt" 2>>"$CANARY" || die "C: pdfium harness failed ($STEM run$RUN_N)"
    python3 "$RUN_DIR/tools/page_digests.py" "$OUT" >"$OUT/digests.json"
    PAGES_P=$(sed -n 's/^PAGES //p' "$OUT/harness.txt")
    CHARS_P=$(sed -n 's/^CHARS //p' "$OUT/harness.txt")
    RSS_P=$(sed -n 's/^RSS_KB //p' "$OUT/harness.txt")
    [ "$PAGES_P" -eq "$EXPECTED" ] || status "C measurement: NOTE pdfium run$RUN_N rendered $PAGES_P pages (expected $EXPECTED)"
    if [ "$RUN_N" -eq 1 ]; then
      DARKS="["
      SEP=""
      for PG in 1 $(((PAGES_P + 1) / 2)) "$PAGES_P"; do
        F=""
        for PF in "$OUT"/page-*.ppm; do
          N=$(basename "$PF" .ppm)
          N="${N#page-}"
          if [ "$N" -eq "$PG" ] 2>/dev/null; then
            F=$(python3 "$RUN_DIR/tools/dark_fraction.py" "$PF")
            break
          fi
        done
        [ -n "$F" ] || die "C: sampled page $PG missing ($STEM pdfium)"
        DARKS="$DARKS$SEP$F"
        SEP=", "
      done
      DARKS="$DARKS]"
      TEXT_CHARS="$CHARS_P"
    else
      DARKS="null"
      TEXT_CHARS=0
    fi
    python3 "$RUN_DIR/tools/time_parse.py" "$OUT/time.txt" >"$OUT/time.json"
    python3 - "$OUT/run.json" "$OUT/digests.json" "$OUT/time.json" "$PAGES_P" "$DARKS" "$TEXT_CHARS" "$RSS_P" <<'PY'
import json, os, sys
out, digests, t, pages, darks, chars, rss = sys.argv[1:9]
d = json.load(open(digests)); tv = json.load(open(t))
try:
    darks = json.loads(darks)
except Exception:
    darks = None
doc = {"run": int(os.path.basename(os.path.dirname(out)).replace("run", "")),
       "pages": int(pages), "identitySha256": d["identitySha256"],
       "elapsedMs": tv["elapsedMs"], "maxRssKb": tv["maxRssKb"] or int(rss),
       "darkFractions": darks, "textChars": int(chars)}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
    rm -f "$OUT"/page-*.ppm
  done
done <"$RUN_DIR/tools/pdf_docs.tsv"

python3 "$RUN_DIR/tools/summarize.py" "$RUN_DIR" "$RECEIPT/measurement.json" "$RUN_DIR/tools/pdf_docs.tsv" ||
  die "C: measurement summarization failed"
MEASUREMENT_VERDICT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["verdict"])' "$RECEIPT/measurement.json")
status "C measurement: verdict $MEASUREMENT_VERDICT"

# --- R: run receipt ----------------------------------------------------------
python3 - "$RECEIPT/run.json" "$RUN_DIR" "$ENGINE_OBSERVED" "$MANIFEST_REVISION" "$MEASUREMENT_VERDICT" <<'PY'
import json, os, sys
out, run_dir, engine_observed, manifest_rev, verdict = sys.argv[1:7]
rec = os.path.join(run_dir, "receipt")
engine = json.load(open(os.path.join(rec, "engine.json"), encoding="utf-8"))
pdfium = json.load(open(os.path.join(rec, "pdfium.json"), encoding="utf-8"))
meas = json.load(open(os.path.join(rec, "measurement.json"), encoding="utf-8"))
canary = open(os.path.join(rec, "canary.txt"), encoding="utf-8").read()
canary_proven = ("SMOKE PASS" in canary and "DENIED-CANARY PASS" in canary
                 and "DENIED-CURL PASS" in canary and "CONTROL PASS" in canary)
doc = {
    "schemaVersion": "setjoin.meet.renderer-qualification-run/1",
    "kind": "renderer-requalification-run-receipt",
    "platform": "linux/amd64",
    "scope": "run-scoped receipt only — never a manifest re-pin, never a commit; "
             "the rev-3 platform-marked row re-pin belongs to the owning authority",
    "consumesDecisions": [
        "docs/verification/2026-09-20-meet-renderer-qualification.md §11/§11.1 "
        "(linux-ci-host re-qualification; platform-marked receipt rows)",
        "retired-docs:verification/2026-09-22-portfolio-execution.md wave-1 module B: frozen "
        "rev-2 corpus stays renderer input everywhere; Linux capture lands in "
        "platform-marked rows at manifest rev 3",
    ],
    "manifestRevisionConsumed": int(manifest_rev),
    "engine": engine,
    "pdfium": pdfium,
    "producerCaptureFragment": "producer-capture-fragment.json",
    "networkDenial": {
        "mechanism": "bwrap --unshare-net",
        "canaryProven": canary_proven,
        "canaryEvidence": "canary.txt",
    },
    "measurement": {"verdict": meas["verdict"], "detail": "measurement.json"},
    "verdict": "PASS" if (verdict == "PASS" and canary_proven) else "FAIL",
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
PY
status "R receipts complete: $RECEIPT (run.json verdict: $(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["verdict"])' "$RECEIPT/run.json"))"

[ "$MEASUREMENT_VERDICT" = "PASS" ] || die "measurement verdict FAIL — receipts retained under $RECEIPT for inspection"
status "lane complete: PASS"
