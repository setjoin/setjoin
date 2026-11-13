#!/usr/bin/env bash
# Apply all reducer SQL files to the local PostgreSQL instance via FIXED-POINT
# iteration: load every file (deterministic path order); anything that fails
# is retried in the next iteration (a forward reference resolves once its
# target has loaded); repeat until an iteration adds ZERO new successes. What
# remains at that fixed point is fatal — a genuine SQL error or a real
# dependency cycle (the two are indistinguishable by exit code and don't need
# to be: both are "still broken after every legitimate retry", named and
# reported the same way).
# Usage: bash scripts/reload-reducers.sh
#        bash scripts/reload-reducers.sh --preflight-only   # ARCH-007 input
#            validation only: refuses archived SQL before ANY psql invocation
#            (used by check-archive-exclusion-selftest.sh; never touches a DB).
#
# REDUCERS_ROOT (test-only): relocates both reducer-tree inputs (preflight AND
# load) to a synthetic scratch root; unset means the repo ROOT.
#
# FAIL-LOUD CONTRACT (do not weaken):
# the apply loops classify each `psql` by exit code and NEVER silently drop a
# reducer. A file that never loads clean after fixed point is reached is
# recorded and the script exits NON-ZERO naming the file. A transient
# connection blip (psql exit 2 — "too many clients" / "connection refused"
# under parallel builds) is retried inline with backoff, PER ATTEMPT — this is
# orthogonal to the fixed-point retry (a same-file backoff, not a cross-file
# convergence loop). Any unclassified non-zero (e.g. exit 1: cannot open -f
# file) is still eligible for fixed-point retry — harmless, since a genuine
# non-forward-ref failure just keeps failing every iteration and is reported
# as a survivor once nothing more resolves it. ON_ERROR_STOP=1 (PG_OPTS) is a
# PRECONDITION — without it a SQL error never raises exit 3 and the
# classification breaks.
#
# There is no separate "sort" step and no `-- deps:` header vocabulary to
# maintain: file order no longer matters for correctness (fixed-point
# convergence tolerates ANY dependency depth), only for determinism, which a
# plain `LC_ALL=C sort` on the path gives for free. This is what killed the
# self-cycle bug class: a malformed/prose-leaking header can no longer affect
# the load, because nothing reads header comments anymore.
#
# This single invocation is a complete, self-contained fixed-point build —
# the caller (load-test-schema.sh) needs exactly ONE call, not a manual
# two-pass wrapper: this script's own first iteration tolerates forward refs
# exactly like the old "pass 1"; its own final (converged) iteration is the
# gate exactly like the old "pass 2".
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Test-only input-root override (check-archive-exclusion-selftest.sh case C):
# relocates the reducer-tree enumeration to a synthetic scratch root. Unset →
# exactly the historical $ROOT behavior.
REDUCERS_ROOT="${REDUCERS_ROOT:-$ROOT}"

DB="${DB_NAME:-mailserver}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"

# ON_ERROR_STOP=1 is load-bearing: it makes a SQL error in a -f file exit 3 (vs a
# silent 0), which the classification below depends on. Do not remove it.
PG_OPTS="-h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB -v ON_ERROR_STOP=1"

# Retry tuning for the connection-blip (exit 2) path under parallel-build contention.
RETRY_MAX="${REDUCER_RETRY_MAX:-3}"        # attempts beyond the first for a conn blip
RETRY_BASE_MS="${REDUCER_RETRY_BASE_MS:-200}"  # linear backoff: attempt * base

# Accumulators (loud summary at end).
FAILED_FILES=()     # files that never loaded clean even at the fixed point
RETRIED_NOTES=()    # "<file>: retried N time(s)" — chronic contention is visible, not absorbed

# Set by apply_reducer on failure — the caller (load_reducer_set) snapshots
# these per file so the FINAL fixed-point survivor report can name each
# file's own last-seen reason, not just the last file attempted overall.
LAST_WHY=""
LAST_OUTPUT=""

# ── Apply ONE reducer with exit-code classification + bounded retry ─────
# Args: <absolute-path> <display-label>
# Returns 0 on a clean load. Returns 1 on failure and sets LAST_WHY/LAST_OUTPUT
# (does NOT append to FAILED_FILES — that only happens once the caller's
# fixed-point loop confirms the file never converges).
# Classification (psql exit under ON_ERROR_STOP=1):
#   0       → loaded clean.
#   2       → connection blip → retry up to RETRY_MAX with linear backoff,
#             SAME attempt, before giving up on this call.
#   3       → SQL/parse error — commonly an unresolved forward reference this
#             early in fixed-point convergence; may resolve once its target
#             loads in a later iteration, may be a genuine error/cycle if it
#             never does. Either way: recorded, no per-call retry (that's the
#             caller's job).
#   other   → unclassified (e.g. 1: cannot open -f file) → recorded, no
#             per-call retry.
apply_reducer() {
    local path="$1" label="$2"
    local attempt=0 rc out
    while :; do
        out="$(psql $PG_OPTS -f "$path" -q 2>&1)"
        rc=$?
        if [ "$rc" -eq 0 ]; then
            [ -n "$out" ] && printf '%s\n' "$out"
            [ "$attempt" -gt 0 ] && RETRIED_NOTES+=("$label: retried $attempt time(s) (connection blip)")
            return 0
        fi
        if [ "$rc" -eq 2 ] && [ "$attempt" -lt "$RETRY_MAX" ]; then
            attempt=$((attempt + 1))
            local sleep_ms=$((RETRY_BASE_MS * attempt))
            echo "    ! $label: connection blip (psql exit 2), retry $attempt/$RETRY_MAX after ${sleep_ms}ms" >&2
            # bash printf supports fractional sleep on macOS/Linux coreutils
            sleep "$(awk "BEGIN{print $sleep_ms/1000}")"
            continue
        fi
        case "$rc" in
            2) LAST_WHY="connection failure after $RETRY_MAX retries (psql exit 2)";;
            3) LAST_WHY="SQL/parse error (psql exit 3 under ON_ERROR_STOP=1)";;
            *) LAST_WHY="unclassified psql exit $rc (e.g. cannot open file)";;
        esac
        LAST_OUTPUT="$out"
        return 1
    done
}

# ── Load a set of reducer files to a fixed point ────────────────────────
# Args: <dir> <label-prefix> (label-prefix is prepended to each filename in
# progress output / the final failure report, e.g. "authserver/").
#
# Loads every *.sql in `dir`, deterministic LC_ALL=C path order. Anything
# that fails is retried next iteration; the loop stops the instant an
# iteration adds zero new successes (a fixed point — nothing left pending can
# ever resolve, since resolving would require a file not-yet-loaded that
# itself isn't stuck, and there is none). Whatever is still pending at that
# point is fatal: appended to FAILED_FILES with its own last-seen reason.
load_reducer_set() {
    local dir="$1" prefix="$2"
    local -A why_by_file=()
    local -A out_by_file=()
    local -a pending=()
    while IFS= read -r f; do
        [ -n "$f" ] && pending+=("$f")
    done < <(cd "$dir" 2>/dev/null && LC_ALL=C ls *.sql 2>/dev/null | LC_ALL=C sort)

    local total=${#pending[@]}
    local loaded=0 iteration=0

    if [ "$total" -eq 0 ]; then
        # Zero files is never a valid reducer tree — a wrong dir or a broken
        # glob must not read as a clean load (fail-loud posture).
        echo "    ✗ no *.sql files found in $dir — refusing a silent empty load" >&2
        FAILED_FILES+=("${prefix}(none) — no *.sql files found in $dir")
        return
    fi

    while [ "${#pending[@]}" -gt 0 ]; do
        iteration=$((iteration + 1))
        local -a next_pending=()
        local progressed=0
        for f in "${pending[@]}"; do
            echo "    $f"
            if apply_reducer "$dir/$f" "${prefix}${f}"; then
                loaded=$((loaded + 1))
                progressed=1
            else
                why_by_file["$f"]="$LAST_WHY"
                out_by_file["$f"]="$LAST_OUTPUT"
                next_pending+=("$f")
            fi
        done
        if [ "$progressed" -eq 0 ]; then
            # Fixed point: this iteration resolved nothing new. Whatever is
            # still in next_pending is a permanent failure.
            break
        fi
        pending=("${next_pending[@]}")
    done

    if [ "${#pending[@]}" -gt 0 ]; then
        echo "    ==> fixed point reached after $iteration iteration(s) — ${#pending[@]} reducer(s) never loaded clean:" >&2
        for f in "${pending[@]}"; do
            echo "    ✗ ${prefix}${f}: ${why_by_file[$f]}" >&2
            if [ -n "${out_by_file[$f]:-}" ]; then
                printf '%s\n' "${out_by_file[$f]}" | sed 's/^/        /' >&2
            fi
            FAILED_FILES+=("${prefix}${f} — ${why_by_file[$f]}")
        done
    fi

    echo "    Done: $loaded / $total files applied clean ($iteration iteration(s))."
}

# ── ARCHIVE PREFLIGHT (ARCH-007) — pure input validation, zero DB contact ──
# The fixed-point load below feeds every *.sql in both reducer trees to psql.
# This preflight enumerates that EXACT selection first and refuses — loudly,
# naming the offending file — BEFORE the first psql invocation, so an
# accidentally-redirected loader can never execute archived provenance SQL.
# Both the literal enumerated path and its symlink-resolved realpath must be
# free of /_archive/ (docs/adr/ARCH-007-schema-baseline-collapse.md).
archive_guard_refuse() {
    echo "✗ refusing to execute archived SQL — non-executed provenance: $1" >&2
    echo "  archived trees under */sql/_archive/ are provenance only; every loader" >&2
    echo "  rejects them (ARCH-007: docs/adr/ARCH-007-schema-baseline-collapse.md)." >&2
    exit 1
}

archive_guard_check_one() {
    local rp
    rp="$(realpath "$1" 2>/dev/null)" || rp=""
    [ -n "$rp" ] || rp="$1"
    case "$1" in */_archive/*) archive_guard_refuse "$1" ;; esac
    case "$rp" in */_archive/*) archive_guard_refuse "$rp" ;; esac
}

archive_preflight() {
    local dir f
    for dir in \
        "$REDUCERS_ROOT/mailserver/sql/reducers" \
        "$REDUCERS_ROOT/authserver/sql/reducers"; do
        # Same enumeration idiom as load_reducer_set below.
        # shellcheck disable=SC2012,SC2035
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            archive_guard_check_one "$dir/$f"
        done < <(cd "$dir" 2>/dev/null && LC_ALL=C ls *.sql 2>/dev/null | LC_ALL=C sort)
    done
}

# Self-test entry: run ONLY the preflight (pure; no psql is ever invoked) and exit.
if [ "${1:-}" = "--preflight-only" ]; then
    archive_preflight
    echo "==> archive preflight clean (no database contact made)."
    exit 0
fi

# ── Apply both reducer trees ─────────────────────────────────────────────

archive_preflight   # ARCH-007: refuse archived SQL before any psql runs (see above)

echo "==> Reloading mailserver reducers (fixed-point order)..."
load_reducer_set "$REDUCERS_ROOT/mailserver/sql/reducers" ""

if [ -d "$REDUCERS_ROOT/authserver/sql/reducers" ]; then
    echo "==> Reloading authserver reducers (fixed-point order)..."
    load_reducer_set "$REDUCERS_ROOT/authserver/sql/reducers" "authserver/"
fi

# ── Loud, propagated verdict ───────────────────────────────────────────
if [ ${#RETRIED_NOTES[@]} -gt 0 ]; then
    echo "==> NOTE: reducers needed connection-blip retries (suspect parallel-build contention / max_connections):" >&2
    for n in "${RETRIED_NOTES[@]}"; do echo "      - $n" >&2; done
fi

if [ ${#FAILED_FILES[@]} -gt 0 ]; then
    echo "==> REDUCER LOAD FAILED — ${#FAILED_FILES[@]} file(s) never loaded clean (fixed point reached):" >&2
    for ff in "${FAILED_FILES[@]}"; do echo "      - $ff" >&2; done
    echo "    (a survivor at fixed point is either a genuine SQL error or a real" >&2
    echo "     dependency cycle — fix the reducer. A connection failure past retries" >&2
    echo "     is infrastructure — re-run or raise max_connections.)" >&2
    exit 1
fi

echo "==> All reducers reloaded."
