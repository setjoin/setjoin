#!/usr/bin/env bash
# MEET M6 slice 1 — Word/text pagination + spreadsheet static print pages:
# the committed, deterministic CONVERSION RECIPES for the pinned LibreOffice
# headless producer (MEET plan retired-docs:superpowers/plans/2026-08-25-meet-
# document-presentation-semantic-recording.md, M6 "Add Word/text pagination
# and spreadsheet static print pages under the same manifest; retain explicit
# fidelity warnings and fallback"; owner decision D3 one-suite constraint in
# retired-docs:verification/2026-09-19-owner-consolidated-decisions.md).
#
# This script MIRRORS the pipeline contract in
# mailserver/internal/meet/presentation/docmode.go
# (ProducerConversionRecipe / ConversionRecipeFor) — the argv below is the
# executable form of the same committed recipe; the two must agree.
#
# Modes:
#   scripts/meet-m6-convert-doc-modes.sh recipe
#       Print the committed recipes as JSON (no engine needed).
#   scripts/meet-m6-convert-doc-modes.sh convert <srcdir> <outdir>
#       Run the pinned producer over every admitted source found in <srcdir>
#       (docx odt txt xlsx ods), writing the paged PDF inputs + a producer
#       receipt into <outdir>. FAILS CLOSED when soffice is absent or cannot
#       be versioned: the fidelity state is rendition_unavailable — never a
#       silent substitute. <outdir> must NOT be the M0 corpus directory (the
#       corpus dir must exactly equal the frozen manifest).
#   scripts/meet-m6-convert-doc-modes.sh verify <outdir>
#       Re-derive the page count of every converted PDF (the page-tree
#       "/Type /Page" token method corpus_manifest.go uses for corpus PDFs,
#       extended here to LibreOffice's unspaced "/Type/Page" spelling) and
#       check the producer receipt exists. This is a recipe-aid counter —
#       the M1-pinned paging primitive remains the production counter.
#
# Environment:
#   SOFFICE_BIN                      engine binary (default "soffice")
#   MEET_M6_CONVERT_TIMEOUT_SECONDS  per-file wall-clock bound (default 300;
#                                    a first-ever run can sit minutes in
#                                    font-cache rebuilds — a hung producer
#                                    fails the file, never waits forever)
#
# Properties:
#   - Print-layout conversion only: word/text paginates by the producer's
#     OWN pagination (frozen default theme for txt, UTF-8 import pinned);
#     spreadsheets render the STATIC PRINT LAYOUT (print area/scale exactly
#     as the producer resolves them) — never an interactive grid, and no
#     single-page-sheet override of the print layout.
#   - Deterministic argv: isolated user profile per run, --norestore, an
#     explicit export filter per mode family, no network.
#   - NOT a behavior flip: this is a recipe/qualification aid. The rendition
#     pipeline admits work only behind the existing OFF feature flags, and
#     outputs converted here are producer-side evidence, never pinned corpus
#     bytes (docs/verification/meet-m0-corpus.json is owned by the
#     qualification lane and is not touched by this script).

source "$(dirname "$0")/_base.sh"

# The D3 one-suite producer identity (docmode.go DocModeProducerEngineID).
ENGINE_ID="libreoffice-headless-soffice"
ENGINE_BIN="${SOFFICE_BIN:-soffice}"

# The mode gate table (docmode.go documentModeProfiles), mirrored:
#   word_text_paginated — docx odt txt: producer's own pagination,
#     fidelity class producer_pagination, fallback
#     office_editor_or_screen_share.
#   spreadsheet_print_static — xlsx ods: producer print area/scale,
#     fidelity class static_print_layout, fallback
#     screen_share_or_office_editor.
ADMITTED_FORMATS="docx odt txt xlsx ods"
CORPUS_DIR="$ROOT/mailserver/internal/meet/presentation/testdata/corpus"

die() {
  echo "meet-m6-convert-doc-modes: $1" >&2
  exit "${2:-1}"
}

mode_for_format() {
  case "$1" in
    docx | odt | txt) echo "word_text_paginated" ;;
    xlsx | ods) echo "spreadsheet_print_static" ;;
    *) return 1 ;;
  esac
}

export_filter_for_format() {
  case "$1" in
    docx | odt | txt) echo "pdf:writer_pdf_Export" ;;
    xlsx | ods) echo "pdf:calc_pdf_Export" ;;
  esac
}

print_layout_for_format() {
  case "$1" in
    docx | odt | txt) echo "producer_print_pagination" ;;
    xlsx | ods) echo "producer_print_area_scale" ;;
  esac
}

fidelity_for_format() {
  case "$1" in
    docx | odt | txt) echo "producer_pagination" ;;
    xlsx | ods) echo "static_print_layout" ;;
  esac
}

fallback_for_format() {
  case "$1" in
    docx | odt | txt) echo "office_editor_or_screen_share" ;;
    xlsx | ods) echo "screen_share_or_office_editor" ;;
  esac
}

# bounded_run <seconds> <logfile> <cmd...> — run one command under a
# wall-clock bound, portably (no GNU timeout dependency): the engine runs in
# the background and is killed when the bound expires (exit 124). A hung
# producer fails the conversion; it never wedges the pipeline. The engine's
# stdio is detached (stdin from /dev/null, output to <logfile>): LibreOffice's
# macOS launcher wedges in a background job that still holds the terminal's
# stdin.
bounded_run() {
  bound="$1"
  log="$2"
  shift 2
  : >"$log"
  "$@" </dev/null >"$log" 2>&1 &
  pid=$!
  waited=0
  while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$bound" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    echo "meet-m6-convert-doc-modes: producer exceeded the ${bound}s bound; conversion failed" >&2
    return 124
  fi
  wait "$pid"
}

# engine_args_for_format mirrors ConversionRecipeFor's argv AFTER the engine
# binary, one argument per line, with the literal operand placeholders the Go
# contract carries ("<profile>", "<outdir>", "<source>").
engine_args_for_format() {
  format="$1"
  printf '%s\n' --headless --norestore "-env:UserInstallation=file://<profile>"
  if [ "$format" = "txt" ]; then
    printf '%s\n' "--infilter=Text (encoded):UTF8"
  fi
  printf '%s\n' --convert-to "$(export_filter_for_format "$format")"
  printf '%s\n' --outdir '<outdir>' '<source>'
}

recipe_json() {
  ENGINE_ID="$ENGINE_ID" FORMAT="$1" EXPORT_FILTER="$(export_filter_for_format "$1")" \
  PRINT_LAYOUT="$(print_layout_for_format "$1")" FIDELITY="$(fidelity_for_format "$1")" \
  FALLBACK="$(fallback_for_format "$1")" python3 <<'PY'
import json
import os

fmt = os.environ["FORMAT"]
mode = "word_text_paginated" if fmt in ("docx", "odt", "txt") else "spreadsheet_print_static"
args = ["--headless", "--norestore", "-env:UserInstallation=file://<profile>"]
if fmt == "txt":
    args.append("--infilter=Text (encoded):UTF8")
args += ["--convert-to", os.environ["EXPORT_FILTER"], "--outdir", "<outdir>", "<source>"]
print(json.dumps({
    "mode": mode,
    "sourceFormat": fmt,
    "engineId": os.environ["ENGINE_ID"],
    "engineArgs": args,
    "printLayout": os.environ["PRINT_LAYOUT"],
    "fidelityClass": os.environ["FIDELITY"],
    "fallback": os.environ["FALLBACK"],
}, indent=2))
PY
}

cmd_recipe() {
  for f in $ADMITTED_FORMATS; do
    recipe_json "$f"
  done
}

cmd_convert() {
  srcdir="$1"
  outdir="$2"
  [ -d "$srcdir" ] || die "source dir $srcdir is not a directory" 2
  [ -d "$outdir" ] || die "output dir $outdir is not a directory" 2

  # The M0 corpus dir must exactly equal the frozen manifest — converted
  # output may never land there (VerifyM0CorpusDir refuses extras).
  corpus_abs="$(cd "$CORPUS_DIR" && pwd)"
  outdir_abs="$(cd "$outdir" && pwd)"
  case "$outdir_abs" in
    "$corpus_abs" | "$corpus_abs"/*)
      die "output dir must not be the M0 corpus directory ($CORPUS_DIR)" 2
      ;;
  esac

  # Fail closed when the pinned producer is absent or cannot be versioned:
  # rendition_unavailable is an EXPLICIT fidelity state, never a silent
  # substitute (a raw dump, a skipped document, a different engine's best
  # effort).
  command -v "$ENGINE_BIN" >/dev/null 2>&1 ||
    die "producer absent: $ENGINE_BIN not found — fidelity state rendition_unavailable (never a silent substitute)" 3
  engine_version="$("$ENGINE_BIN" --version 2>/dev/null | head -1)"
  [ -n "$engine_version" ] ||
    die "producer version unavailable: '$ENGINE_BIN --version' produced nothing — fidelity state rendition_unavailable" 3

  profile="$(mktemp -d "${TMPDIR:-/tmp}/meet-m6-profile.XXXXXX")"
  # The recipe arg already carries the file:// prefix (file://<profile>);
  # the substitution supplies the absolute directory path only.
  profile_path="$(cd "$profile" && pwd)"
  # Owned-resource cleanup: the isolated profile is removed on success,
  # failure AND cancellation.
  trap 'rm -rf "$profile" 2>/dev/null' EXIT
  bound="${MEET_M6_CONVERT_TIMEOUT_SECONDS:-300}"

  conv_log="$outdir_abs/convert.log"
  for src in "$srcdir"/*; do
    [ -f "$src" ] || continue
    format="${src##*.}"
    format="$(printf '%s' "$format" | tr '[:upper:]' '[:lower:]')"
    mode_for_format "$format" >/dev/null || continue
    echo "converting $(basename "$src") [$(mode_for_format "$format"), $(fidelity_for_format "$format")]"
    # Substitute the recipe's literal placeholders; the argv stays
    # element-for-element the committed recipe (the space-bearing txt
    # infilter survives as ONE argument).
    set --
    while IFS= read -r arg; do
      arg="${arg//<profile>/$profile_path}"
      arg="${arg//<outdir>/$outdir_abs}"
      arg="${arg//<source>/$src}"
      set -- "$@" "$arg"
    done <<<"$(engine_args_for_format "$format")"
    if ! bounded_run "$bound" "$conv_log" "$ENGINE_BIN" "$@"; then
      cat "$conv_log" >&2 || true
      die "conversion failed or timed out for $(basename "$src") — fidelity state rendition_unavailable for this run (never a partial substitute)" 3
    fi
    grep -h "^convert " "$conv_log" || true
    pdf="$outdir_abs/$(basename "${src%.*}").pdf"
    [ -f "$pdf" ] || die "conversion produced no PDF for $(basename "$src")" 1
    echo "  -> $(basename "$pdf")"
  done
  rm -rf "$profile"

  ENGINE_ID="$ENGINE_ID" ENGINE_VERSION="$engine_version" OUTDIR="$outdir_abs" python3 <<'PY'
import datetime
import json
import os

receipt = {
    "engineId": os.environ["ENGINE_ID"],
    # Captured verbatim from `soffice --version` — never invented.
    "engineVersion": os.environ["ENGINE_VERSION"],
    "convertedAt": datetime.datetime.now(datetime.timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "evidence": (
        "Dev-side conversion receipt only; qualification evidence for the "
        "pinned producer comes from the linux-ci-host run (owner decision D3). "
        "Not corpus-pinned bytes: regenerated output re-pins digests with a "
        "dated receipt."
    ),
    "fidelityNote": (
        "word/text pages by the producer's own pagination "
        "(producer_pagination); spreadsheets are the static print layout "
        "(static_print_layout) — never an interactive grid."
    ),
}
path = os.path.join(os.environ["OUTDIR"], "producer.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump(receipt, f, indent=2)
    f.write("\n")
print("producer receipt written to %s" % path)
PY
}

cmd_verify() {
  outdir="$1"
  [ -d "$outdir" ] || die "output dir $outdir is not a directory" 2
  [ -f "$outdir/producer.json" ] ||
    die "missing producer receipt ($outdir/producer.json); unattributed PDFs are not evidence" 1
  OUTDIR="$(cd "$outdir" && pwd)" python3 <<'PY'
import json
import os
import sys

outdir = os.environ["OUTDIR"]
with open(os.path.join(outdir, "producer.json"), encoding="utf-8") as f:
    receipt = json.load(f)
failures = 0
for name in sorted(os.listdir(outdir)):
    if not name.endswith(".pdf"):
        continue
    with open(os.path.join(outdir, name), "rb") as f:
        data = f.read()
    # Page-tree token count: the spaced spelling corpus_manifest.go pins for
    # corpus PDFs plus LibreOffice's unspaced spelling; "/Pages" (the tree
    # itself) is subtracted in each spelling.
    pages = (
        data.count(b"/Type /Page")
        - data.count(b"/Type /Pages")
        + data.count(b"/Type/Page")
        - data.count(b"/Type/Pages")
    )
    print("%s: %d pages" % (name, pages))
    if pages <= 0:
        failures += 1
        print("  FAIL: zero-page artifact refused")
print("producer:", receipt["engineId"], receipt["engineVersion"])
sys.exit(1 if failures else 0)
PY
}

case "${1:-}" in
  recipe)
    cmd_recipe
    ;;
  convert)
    [ $# -eq 3 ] || die "usage: $0 convert <srcdir> <outdir>" 2
    cmd_convert "$2" "$3"
    ;;
  verify)
    [ $# -eq 2 ] || die "usage: $0 verify <outdir>" 2
    cmd_verify "$2"
    ;;
  "")
    die "usage: $0 [recipe|convert <srcdir> <outdir>|verify <outdir>]" 2
    ;;
  *)
    die "unknown mode $1" 2
    ;;
esac
