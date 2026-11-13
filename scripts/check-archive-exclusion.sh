#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-archive-exclusion.sh — machine-checkable non-executability assertion
# for the archived SQL trees (ARCH-007 baseline collapse).
#
# {authserver,mailserver}/sql/_archive/ are NON-EXECUTED provenance. Their
# exclusion from every loader path is asserted here three ways:
#   1. SENTINEL: every *.sql under */sql/_archive/ carries the
#      SETJOIN-ARCHIVE-NONEXECUTED header within its first 5 lines — a
#      per-file, greppable marker (not just README prose).
#   2. LOADER-PATH SCAN: no file under scripts/ (any file type) and no *.go
#      file may reference an `_archive` path in an execution context (psql,
#      `-f `, go:embed, embed.FS). Allowlisted: comment lines (except //go:
#      directives, which the compiler acts on), the `-prune` find-exclusion
#      lines (check-reducererr-contract.sh / check-toggle-registry.sh), and
#      this guard + its self-test. The sanctioned revival pattern (re-apply a
#      archived file via a new reviewed V-migration, e.g. V074) references the
#      archive only from mailserver/sql/dbschema/V*.sql files, which are
#      outside the scanned loader sets by construction.
#   3. INPUT-ENUMERATION CONTRACT: the exact file inputs the loaders execute
#      must still exist where this guard expects them (V001__baseline.sql,
#      provision-roles.sql, _fixtures.sql, a non-empty V[0-9]*__*.sql glob,
#      non-empty *.sql reducer globs), and dbschema.go must still carry the
#      dir-local `//go:embed *.sql` + `^V(\d+)__.+\.sql$` contract — so a
#      loader-selection change cannot silently escape this guard's coverage.
#
# Runtime enforcement lives in the loaders themselves (archive_preflight in
# reload-reducers.sh / load-test-schema.sh, placed BEFORE the first psql call
# / the destructive recreate block). check-archive-exclusion-selftest.sh
# proves both the guard and the preflights FIRE on planted archive inputs.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# Self-test override: guard a synthetic scratch root instead of the real repo.
SCAN_ROOT="${ARCHIVE_GUARD_ROOT:-$ROOT}"

violations=()

# ── 1. Sentinel presence on every archive SQL file ────────────────────────
archive_dirs="$(find "$SCAN_ROOT" -maxdepth 3 -type d -path '*/sql/_archive' 2>/dev/null || true)"
if [ -z "$archive_dirs" ]; then
  violations+=("no */sql/_archive tree found under $SCAN_ROOT — the archive moved; update this guard's contract")
fi
while IFS= read -r d; do
  [ -n "$d" ] || continue
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if ! head -n 5 "$f" 2>/dev/null | grep -q 'SETJOIN-ARCHIVE-NONEXECUTED'; then
      violations+=("archive SQL file missing SETJOIN-ARCHIVE-NONEXECUTED sentinel: $f")
    fi
  done < <(find "$d" -type f -name '*.sql' 2>/dev/null | LC_ALL=C sort)
done <<<"$archive_dirs"

# ── 2. Loader-path scan (scripts/* + **/*.go) ─────────────────────────────
# A line is a violation when it references a path-like `_archive` token (i.e.
# `_archive` NOT followed by an identifier character — `is_archived` and
# `archived` don't match) AND an execution indicator (psql / `-f ` / go:embed /
# embed.FS) survives the allowlist below.
scan_file() {
  local file="$1" base line lineno content
  base="$(basename "$file")"
  case "$base" in
    check-archive-exclusion.sh | check-archive-exclusion-selftest.sh) return 0 ;;
  esac
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    lineno="${line%%:*}"
    content="${line#*:}"
    case "$content" in
      *-prune*) continue ;; # documented find-exclusion lines
      '#'*) continue ;;     # shell comment
      '//'*)                # Go comment — but //go: directives are CODE
        case "$content" in '//go:'*) ;; *) continue ;; esac
        ;;
    esac
    if printf '%s\n' "$content" | grep -Eq 'psql|-f |go:embed|embed\.FS'; then
      violations+=("loader-path scan: $file:$lineno references an _archive path in an execution context: $content")
    fi
  done < <(grep -nE '_archive([^[:alnum:]_]|$)' "$file" 2>/dev/null || true)
}

for f in "$SCAN_ROOT"/scripts/*; do
  [ -f "$f" ] || continue
  scan_file "$f"
done
while IFS= read -r g; do
  [ -n "$g" ] || continue
  scan_file "$g"
done < <(find "$SCAN_ROOT" \
  \( -name node_modules -o -name .git -o -name worktrees -o -name build -o -name vendor \) -prune \
  -o -type f -name '*.go' -print 2>/dev/null | LC_ALL=C sort)

# ── 3. Loader input-enumeration contract ───────────────────────────────────
require_input() {
  local desc="$1" path="$2"
  [ -f "$path" ] || violations+=("loader input contract: $desc missing: $path")
}
require_input "baseline (load-test-schema.sh direct -f)" \
  "$SCAN_ROOT/mailserver/sql/dbschema/V001__baseline.sql"
require_input "provision-roles.sql (load-test-schema.sh pre+post pass)" \
  "$SCAN_ROOT/scripts/provision-roles.sql"
require_input "_fixtures.sql (load-test-schema.sh pgTAP step)" \
  "$SCAN_ROOT/mailserver/sql/tests/_fixtures.sql"

migs="$(LC_ALL=C ls "$SCAN_ROOT"/mailserver/sql/dbschema/V[0-9]*__*.sql 2>/dev/null || true)"
[ -n "$migs" ] || violations+=("loader input contract: no V[0-9]*__*.sql migrations under $SCAN_ROOT/mailserver/sql/dbschema")
for rd in "$SCAN_ROOT/mailserver/sql/reducers" "$SCAN_ROOT/authserver/sql/reducers"; do
  rs="$(LC_ALL=C ls "$rd"/*.sql 2>/dev/null || true)"
  [ -n "$rs" ] || violations+=("loader input contract: no *.sql reducers under $rd")
done

dbschema_go="$SCAN_ROOT/mailserver/sql/dbschema/dbschema.go"
if [ -f "$dbschema_go" ]; then
  grep -q '^//go:embed \*\.sql$' "$dbschema_go" ||
    violations+=("go embed contract: '//go:embed *.sql' missing from $dbschema_go — the dir-local embed glob is the archive-exclusion backstop")
  grep -qF '^V(\d+)__.+\.sql$' "$dbschema_go" ||
    violations+=("go embed contract: V<NNN>__*.sql filename regex missing from $dbschema_go")
else
  violations+=("go embed contract: $dbschema_go missing")
fi

# ── Verdict ────────────────────────────────────────────────────────────────
if [ "${#violations[@]}" -gt 0 ]; then
  echo "check-archive-exclusion: ${#violations[@]} violation(s):" >&2
  for v in "${violations[@]}"; do echo "  - $v" >&2; done
  exit 1
fi
echo "check-archive-exclusion: OK — archive sentinels present, no loader executes toward an _archive path, loader input contract intact."
