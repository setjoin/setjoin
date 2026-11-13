#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-coverage.sh — the native-RLS COVERAGE GUARD (W7 / plan
# 2026-06-18-native-rls-backstop.md). Machine-checked replacement for the
# manual sweep that MISSED ~17 raw `FROM messages` Go files (W6's flip-safety
# verify, the ⚠️ at the top of the plan).
#
# WHY THIS EXISTS. The W6 FORCE flip (V004) ENABLE+FORCEs RLS on `messages` +
# `message_tags`. It is LATENT — a no-op until the prod DSN switches to the
# non-owner `setjoin_app` role. The moment it goes live, EVERY app-pool query
# that reads/writes `messages`/`message_tags` WITHOUT a transaction-scoped
# `app.current_mailbox_id` GUC fails-closed (tenant reads → empty / 404; tenant
# writes → 42501; cross-tenant admin → blind/orphan). The W3 sweep that claimed
# "zero raw sites" was (a) scoped to the jmap package and (b) matched only
# reducer-CALL sites (`SELECT fn(`), so it never saw raw `FROM messages`
# queries in blob/user/admin/smtp/spam. A manual sweep is not a coverage proof.
#
# WHAT IT DOES. Enumerates EVERY backtick / double-quoted SQL string literal in
# the non-test gateway Go tree (`mailserver/internal`) that TOUCHES any table in
# the runtime-derived FORCE'd set (see the D-1 block below) AS A TABLE (FROM /
# JOIN / INTO / UPDATE / DELETE FROM — word-boundary; a bare `message_id` column
# in another table does NOT count; `message_tags` counts;
# `message_trace`/`message_attachments`/`message_recalls` do NOT — those are
# different tables). Each such literal MUST be CLASSIFIED in
# scripts/rls-coverage-allowlist.txt as one of:
#   · WRAPPED        — the call runs inside a tx that set app.current_mailbox_id
#                      (CallScoped / withScope / a hand-rolled inline scoped tx).
#   · BYPASS         — the handler is constructed on workerPool (BYPASSRLS); name
#                      the main.go construction line in the reason.
#   · AUDITED-XTENANT— intentionally cross-tenant on the bypass pool (admin
#                      eDiscovery / monitor / drain / spam), one-line reason.
# A FORCE'd-table literal that is NOT classified FAILS the guard.
#
# WHY THE ALLOWLIST IS HUMAN-MAINTAINED (not auto-inferred). Routing-to-bypass
# happens at CONSTRUCTION (main.go passes `workerPool`); the handler still calls
# `h.pool` internally, so the call SITE is indistinguishable from a tenant one.
# And a `tx.` receiver is NOT a reliable WRAPPED signal: admin_mailboxes.go /
# admin_users.go open a PLAIN `pool.Begin()` tx (no set_config) for their delete
# fan-out — auto-exempting `tx.` would be a silent false-negative on exactly the
# cross-tenant admin deletes that orphan under FORCE. So the guard does NOT
# parse receivers; it forces every messages-touching raw site to be EXPLICITLY
# classified by a human who read the call site. The guard's job is to make
# "added a raw messages query without thinking about RLS" un-mergeable, and to
# fail LOUDLY when a classified site's SQL drifts out from under its entry.
#
# RELATIONSHIP TO THE OTHER GUARDS. check-gateway-ownership.sh asks "does this
# raw user-data query carry an OWNERSHIP predicate?" (app-layer R4). This guard
# asks the orthogonal "is this messages/message_tags site COVERED by the RLS tx
# wrapper or routed to the bypass pool?" (so the FORCE flip can't break/leak it).
# A site can pass one and fail the other; both run in test.sh, selftest-first.
#
# Usage: scripts/check-rls-coverage.sh   (exit 0 = clean, 1 = uncovered site).
# Wired into scripts/test.sh + scripts/lint.sh (selftest-first).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

export LC_ALL=C  # byte-stable sort/match; no locale surprises (robustness).

# GATEWAY_DIR / ALLOWLIST_FILE may be overridden (the guard's own self-test uses
# this to point at a synthetic tree + allowlist). Default to the real tree.
GATEWAY="${GATEWAY_DIR:-$ROOT/mailserver/internal}"
ALLOWLIST_FILE="${RLS_ALLOWLIST_FILE:-$(dirname "$0")/rls-coverage-allowlist.txt}"

# ── FORCE'd-table set: derived from the migrations, NOT hand-listed (D-1,
# plan 2026-09-18-debt-consolidation.md). The W7 hand list drifted the moment
# V114/V140/V158/V181/V199/V201/V217/V246/V254/V259… joined — a FORCE'd table
# missing from a hand list means its app-pool sites are unguarded and
# fail-closed-blind at the flip. So the set is now extracted at guard runtime
# from `mailserver/sql/dbschema/V*.sql`. The extraction is performed ONCE per
# invocation and cached in FORCE_TABLES below — never across invocations, so a
# migration edit is picked up by the next run with no invalidation step.
#
# Covered statement forms (anything else FAILS LOUDLY — an unrecognized form
# must break the guard, not silently shrink the FORCE'd set):
#   · direct, whitespace-flexible + schema-qualified:
#       ALTER TABLE public.messages FORCE  ROW LEVEL SECURITY;   (V004, 2 spaces)
#       ALTER TABLE public.mdm_device_state FORCE ROW LEVEL SECURITY; (V254)
#   · NO FORCE: never ADDS a table; a later NO FORCE REMOVES an earlier FORCE
#     (final migration state wins — V140's dedup window: NO FORCE → FORCE).
#     A bare ENABLE is a NO-OP for the FORCE set (D-1 r2): ENABLE flips only
#     relrowsecurity and never unsets relforcerowsecurity, so ENABLE after
#     FORCE leaves the table FORCE'd.
#   · dynamic FOREACH-over-a-literal-ARRAY + EXECUTE format('…%I…FORCE…', var):
#       V199 (mailbox lifecycle), V201 (mail work), V217 (exchange assessment),
#       V114 (drive; also `FORCE  ROW` inside the format string). A block
#       carrying BOTH forms replays its operations IN STATEMENT ORDER (D-1 r2:
#       NO FORCE → FORCE must end FORCE'd, not let NO FORCE win unconditionally).
#   · comments (`--` …, nested `/* … */` block comments, quote/dollar-quote
#     aware) never contribute tables — INCLUDING comments inside inline
#     `DO $$ … $$` bodies (D-1 r3): the body is plpgsql source, so its
#     comments are not statements and a block-commented NO FORCE inside a DO
#     body must not un-force a table.
#   · consumed-prefix validation (D-1 r2): any unrecognized ALTER TABLE … ROW
#     LEVEL SECURITY text BEFORE a recognized statement (e.g. a quoted
#     `public."omega"` identifier) fails the guard loudly instead of being
#     silently discarded — the old final-suffix net only saw the tail.
#   · loop-body validation (D-1 r3): every UNCONSUMED statement in a FOREACH
#     block body is validated before the body is discarded — the direct-form
#     check excludes quoted identifiers, so `ALTER TABLE public."omega" FORCE
#     ROW LEVEL SECURITY;` inside the loop used to vanish with the body and
#     exit 0 without omega. Same loud-failure posture as the prefix net.
# Extracted names are lowercase, `public.`-stripped identifiers. The emit regex
# below stays word-bounded, so look-alikes (message_trace, a message_id column,
# mailboxes vs mailbox_delegates, device_id vs device_events) still do NOT match.
# RLS_PRINT_TABLE_SET=1 prints the derived set (one name per line, sorted) and
# exits — the self-test asserts it against independently maintained fixtures.
SCHEMA_DIR="${RLS_SCHEMA_DIR:-$ROOT/mailserver/sql/dbschema}"

# Migrations in VERSION order (numeric — C string sort would put V100 < V99),
# because a later NO FORCE/FORCE must override an earlier FORCE/NO FORCE.
MIG_LIST="$(find "$SCHEMA_DIR" -maxdepth 1 -name 'V*.sql' -type f 2>/dev/null \
  | awk '{ s=$0; base=s; sub(/.*\//,"",base); v=base; sub(/^V/,  "", v); sub(/^0+/, "", v); sub(/[^0-9].*$/, "", v); if (v=="") v=0; printf "%010d %s\n", v, s }' \
  | LC_ALL=C sort \
  | cut -d' ' -f2-)"
if [ -z "$MIG_LIST" ]; then
  echo "  [RLS] FORCE extraction failed: no V*.sql migrations found under $SCHEMA_DIR" >&2
  exit 1
fi

# sq = a single straight quote (the awk program itself is single-quoted shell
# text, so literal quotes are passed in as a variable, never spelled inline).
# shellcheck disable=SC2086
FORCE_TABLES="$(awk -v sq="'" '
  FNR == 1 {
    if (stream != "") stream = stream "\n"   # file separator: statements never span files
    nf++
    fstart[nf] = length(stream) + 1
    fname[nf] = FILENAME
    inblk = 0; prevopen = 0; incomment = 0
  }
  {
    # Cheap raw-line prefilter FIRST: the per-char comment/quote machine below
    # must never run on 100KB seed-INSERT lines (substr-per-char is quadratic
    # and would hang the guard). A line is processed only when it can
    # participate in an RLS statement:
    #   · it carries an RLS marker (statement / block / array keywords), or
    #   · it OPENS a block comment (the opener line itself may carry no RLS
    #     marker while a LATER line inside the comment does — the opener must
    #     arm incomment or the comment content would leak through), or
    #   · a FOREACH block is open (its array literals continue bare), or
    #   · a block comment is open (its `*/` terminator must be tracked), or
    #   · the previous processed line ended with an open statement (no ";"),
    #     i.e. a direct statement wrapped across lines.
    line = tolower($0)
    if (!inblk && !prevopen && incomment == 0 && line !~ /row level security|alter table|foreach|array\[|\/\*/) next
    # Per-line quote/dollar state (single line of DDL never leaves a literal
    # open; cross-line tracking would force scanning every seed line). Block
    # comments DO span lines, so incomment (a nesting DEPTH) persists across
    # lines until the matching `*/` (D-1 r2).
    dollar = ""; insq = 0
    out = ""; i = 1; n = length(line)
    while (i <= n) {
      c = substr(line, i, 1)
      if (incomment > 0) {
        # Inside a block comment: track nesting, emit nothing.
        if (substr(line, i, 2) == "*/") { incomment--; i += 2; continue }
        if (substr(line, i, 2) == "/*") { incomment++; i += 2; continue }
        i++; continue
      }
      if (dollar != "") {
        # D-1 r3 (Astra): a dollar-quoted DO body is plpgsql SOURCE — its
        # comments are not statements, so strip them exactly like top-level
        # comments instead of copying them into the stream verbatim (a
        # block-commented `NO FORCE` inside `DO $$ … $$` used to un-force the
        # table). incomment is a nesting DEPTH and persists across lines; insq
        # guards `/*`/`--` inside plpgsql string literals (format strings).
        if (incomment > 0) {
          if (substr(line, i, 2) == "*/") { incomment--; i += 2; continue }
          if (substr(line, i, 2) == "/*") { incomment++; i += 2; continue }
          i++; continue
        }
        if (insq) {
          if (c == sq) {
            if (substr(line, i, 2) == sq sq) { out = out sq sq; i += 2; continue }
            insq = 0
          }
          out = out c; i++; continue
        }
        if (c == sq) { insq = 1; out = out c; i++; continue }
        if (c == "-" && substr(line, i, 2) == "--") break   # body line comment: drop to EOL
        if (c == "/" && substr(line, i, 2) == "/*") { incomment++; i += 2; continue }
        if (substr(line, i, length(dollar)) == dollar) { out = out dollar; i += length(dollar); dollar = ""; continue }
        out = out c; i++; continue
      }
      if (insq) {
        if (c == sq) {
          if (substr(line, i, 2) == sq sq) { out = out sq sq; i += 2; continue }
          insq = 0
        }
        out = out c; i++; continue
      }
      if (c == sq) { insq = 1; out = out c; i++; continue }
      if (c == "$" && match(substr(line, i), /^\$[a-z_]*\$/)) {
        dollar = substr(line, i, RLENGTH); out = out dollar; i += RLENGTH; continue
      }
      if (c == "-" && substr(line, i, 2) == "--") break   # line comment: drop to EOL
      if (c == "/" && substr(line, i, 2) == "/*") { incomment++; i += 2; continue }   # block comment: drop to */ (nested)
      out = out c; i++
    }
    gsub(/[ \t\r]+/, " ", out)
    if (out != "") stream = stream out " "
    if (out ~ /foreach/ && out !~ /end loop/) inblk = 1
    if (out ~ /end loop/) inblk = 0
    prevopen = (out != "" && out !~ /;/)
  }
  function die(msg, off) {
    printf "  [RLS] FORCE extraction UNSUPPORTED form in %s: %s\n", file_of(off), msg > "/dev/stderr"
    printf "        → extend the extractor in scripts/check-rls-coverage.sh (a silent miss would unguard a FORCE%s table).\n", sq "d" > "/dev/stderr"
    exit 3
  }
  function file_of(off,   i) {
    for (i = nf; i >= 1; i--) if (off >= fstart[i]) return fname[i]
    return "?"
  }
  # Consumed-prefix net (D-1 r2): every extraction branch below DISCARDS the
  # text that precedes what it consumes. If a discarded prefix carries an
  # ALTER TABLE … ROW LEVEL SECURITY fragment, that statement was NOT
  # recognizable by the extraction (e.g. a quoted `public."omega"` identifier)
  # and would vanish silently — the final-suffix net never sees it. Break
  # loudly instead. (Anything matchable in a prefix would have been consumed
  # earlier: match() always finds the FIRST recognizable form, so a hit here
  # is by construction an unsupported shape.) off is the absolute stream
  # offset of the first byte of prefix.
  function check_prefix(prefix, off) {
    if (match(prefix, /alter table [^;]*row +level +security/))
      die("unrecognized ALTER TABLE … ROW LEVEL SECURITY text in a consumed prefix — a statement would silently vanish", off + RSTART - 1)
  }
  END {
    if (nf == 0) die("no migration content extracted", 0)
    rest = stream; rlen0 = 0
    while (length(rest) > 0) {
      dpos = match(rest, /alter table (public\.)?[a-z_][a-z0-9_]* +(no +force|force|enable) +row +level +security/)
      dlen = RLENGTH   # capture immediately: the next match clobbers RSTART/RLENGTH
      fpos = match(rest, /foreach +[a-z_][a-z0-9_]* +in array +array\[[^]]*\] +loop/)
      flen = RLENGTH
      if (!dpos && !fpos) break
      if (dpos && (!fpos || dpos < fpos)) {
        check_prefix(substr(rest, 1, dpos - 1), rlen0)
        stmt = substr(rest, dpos, dlen)
        core = stmt
        sub(/^alter table /, "", core)
        sub(/ +(no +force|force|enable) +row +level +security$/, "", core)
        sub(/^public\./, "", core)
        # FORCE adds; NO FORCE removes. A bare ENABLE is a NO-OP for the FORCE
        # set (D-1 r2): ENABLE flips relrowsecurity only and never unsets
        # relforcerowsecurity, so ENABLE after FORCE keeps the table forced.
        if (stmt ~ / no +force /) delete FORCE[core]
        else if (stmt !~ / enable /) FORCE[core] = 1
        rest = substr(rest, dpos + dlen)
        rlen0 = rlen0 + dpos + dlen - 1
        continue
      }
      # ── dynamic block: FOREACH var IN ARRAY ARRAY[...] LOOP … END LOOP ──
      check_prefix(substr(rest, 1, fpos - 1), rlen0)
      absoff = rlen0 + fpos - 1
      blkhdr = substr(rest, fpos, flen)
      after  = substr(rest, fpos + flen)
      var = blkhdr; sub(/^foreach +/, "", var); sub(/ +in array.*/, "", var)
      arr = blkhdr; match(arr, /\[[^]]*\]/); arr = substr(arr, RSTART + 1, RLENGTH - 2)
      epos = index(after, "end loop")
      if (epos == 0) die("FOREACH block without END LOOP", absoff)
      body = substr(after, 1, epos - 1)
      rest = substr(after, epos + 8)
      rlen0 = rlen0 + fpos + flen + epos + 8 - 1
      # A real direct statement inside the block body (name followed by a space)
      # is unsupported; format strings carry public.%i (no space) and pass.
      if (match(body, /alter table (public\.)?[a-z_][a-z0-9_]* +[a-z]/))
        die("direct ALTER TABLE inside a FOREACH block — unsupported", absoff)
      ops = ""; bogus = ""   # ops: ordered "d"(elete)/"f"(orce) replay list
      # resid accumulates every byte of the body NOT consumed by a recognized
      # EXECUTE format call, so it can be validated before the body is
      # discarded (D-1 r3: unconsumed loop-body statements must not vanish).
      resid = ""
      qre = sq "[^" sq "]*" sq   # a single-quoted literal
      b = body
      while (match(b, /execute +format\(/)) {
        resid = resid substr(b, 1, RSTART - 1)
        b = substr(b, RSTART + RLENGTH)
        if (!match(b, qre)) { bogus = "EXECUTE format without a literal format string"; break }
        fmt = substr(b, RSTART + 1, RLENGTH - 2)
        b = substr(b, RSTART + RLENGTH)   # consume the literal itself
        if (fmt !~ /row +level +security/) { resid = resid " "; continue }   # non-RLS format call
        if (fmt !~ /^alter table public\.%i (no +force|force|enable) +row +level +security$/) {
          bogus = "unrecognized dynamic RLS format: \"" fmt "\""; break
        }
        if (fmt ~ /^alter table public\.%i enable/) { resid = resid " "; continue } # ENABLE: neither FORCE nor un-FORCE
        p = index(b, ")")
        if (p == 0) { bogus = "EXECUTE format call without closing paren"; break }
        arg = substr(b, 1, p - 1)
        resid = resid " " substr(b, 1, p)   # consume the argument list through ")"
        b = substr(b, p + 1)
        gsub(/^[ ,]+/, "", arg)   # drop the leading comma + whitespace
        gsub(/ +$/, "", arg)
        if (arg != var) { bogus = "format argument \"" arg "\" is not the FOREACH variable \"" var "\""; break }
        # Record the operation IN ORDER: replay order decides the final state
        # (D-1 r2 — NO FORCE followed by FORCE must end forced).
        ops = ops (fmt ~ / no +force / ? "d" : "f")
      }
      if (bogus != "") die(bogus, absoff)
      resid = resid b   # the tail after the last recognized call is unconsumed too
      # D-1 r3 loop-body net: whatever the consumption above did NOT recognize
      # is validated BEFORE the body is discarded. The direct-form check above
      # excludes quoted identifiers (`public."omega"`), so a quoted-identifier
      # direct statement inside the loop used to vanish with the body and exit
      # 0 without omega. Same loud-failure posture as the consumed-prefix net.
      if (match(resid, /alter table [^;]*row +level +security/))
        die("unrecognized ALTER TABLE … ROW LEVEL SECURITY text inside a FOREACH block body — a statement would silently vanish", absoff)
      if (ops != "") {                # non-RLS FOREACH blocks (e.g. ALTER FUNCTION
                                      # loops) must not even validate their arrays
        a = arr
        while (match(a, sq "[^" sq "]+" sq)) {
          t = substr(a, RSTART + 1, RLENGTH - 2)
          if (t !~ /^[a-z_][a-z0-9_]*$/) die("non-identifier table literal in ARRAY: " t, absoff)
          # Replay the operations IN STATEMENT ORDER, per array element
          # (every format call applies to every element).
          seq = ops
          while (seq != "") {
            if (substr(seq, 1, 1) == "d") delete FORCE[t]; else FORCE[t] = 1
            seq = substr(seq, 2)
          }
          a = substr(a, RSTART + RLENGTH)
        }
      }
    }
    # Loud-failure net: any ALTER TABLE … ROW LEVEL SECURITY shape that survived
    # the main loop unrecognized (quoted identifiers, %s table names, unknown
    # actions, statement fragments) must break the guard, not slip through.
    if (match(rest, /alter table (public\.)?[^;]*row +level +security/))
      die("unrecognized ALTER TABLE … ROW LEVEL SECURITY statement survived extraction", rlen0 + RSTART - 1)
    nforce = 0
    for (t in FORCE) nforce++
    if (nforce == 0) {
      printf "  [RLS] FORCE extraction derived ZERO FORCE%sd tables from the migrations — extraction is broken.\n", sq > "/dev/stderr"
      exit 3
    }
    for (t in FORCE) print t
  }
' $MIG_LIST)" && awk_status=0 || awk_status=$?
if [ "$awk_status" -ne 0 ]; then
  # Preserve the extractor's distinct loud-failure status (3): callers and the
  # selftest discriminate it from the guard's own generic exit 1.
  echo "  [RLS] FORCE extraction failed (status $awk_status) — refusing to run the guard on a broken table set." >&2
  exit "$awk_status"
fi
if [ -z "$FORCE_TABLES" ]; then
  echo "  [RLS] FORCE extraction produced an empty table set — refusing to run." >&2
  exit 1
fi

SORTED_TABLES="$(printf '%s\n' "$FORCE_TABLES" | LC_ALL=C sort -u)"
TBL_COUNT="$(printf '%s\n' "$SORTED_TABLES" | wc -l | tr -d ' ')"

if [ "${RLS_PRINT_TABLE_SET:-0}" = "1" ]; then
  printf '%s\n' "$SORTED_TABLES"
  exit 0
fi

# The regex is word-bounded (see the emit() regex in the scan below) so
# `message_tags` matches but `message_trace` / `message_attachments` /
# `message_recalls` / a `message_id` column / `mailboxes` do NOT. Passed into
# awk via -v (single source of truth).
RLS_TBL="($(printf '%s\n' "$SORTED_TABLES" | paste -sd '|' -))"

echo "==> native-RLS coverage guard (W7 + D-1): ${TBL_COUNT} FORCE'd table(s) derived from migrations; app-pool sites must be classified"

if [ ! -f "$ALLOWLIST_FILE" ]; then
  echo "  [RLS] allowlist file not found: $ALLOWLIST_FILE" >&2
  exit 1
fi

fail=0
report() { echo "  $1"; fail=1; }

# ── is_classified <basename> <lowercased-stripped-sql>
# The allowlist is `<basename>\t<CLASS>\t<unique lowercase substring>\t<reason>`.
# Blank lines and `#`-comment lines are ignored. An entry matches only in its
# named file AND only when its substring appears (lowercased) in the literal.
# Returns 0 (classified) / 1 (not). Loads the file fresh each call is wasteful;
# we read it once into ALLOW_LINES below.
ALLOW_LINES="$(grep -vE '^[[:space:]]*(#|$)' "$ALLOWLIST_FILE" || true)"

is_classified() {
  local base="$1" sql="$2" line akey asub
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    akey="${line%%	*}"                          # field 1: basename
    asub="${line#*	}"; asub="${asub#*	}"        # drop f1, f2(CLASS)
    asub="${asub%%	*}"                           # field 3: substring
    [ "$akey" = "$base" ] || continue
    case "$sql" in *"$asub"*) return 0 ;; esac
  done <<< "$ALLOW_LINES"
  return 1
}

TMP_HITS="$(mktemp)"
trap 'rm -f "$TMP_HITS"' EXIT

# ── FAST PATH. One awk invocation over the whole non-test Go tree:
#   extract every literal → lowercase it → keep ONLY the ones that touch a
#   FORCE'd table ($RLS_TBL) AS A TABLE → emit "FILE:LINE<TAB>lowsql<TAB>origsql".
# Doing the lowercase + table-touch filter inside awk (no per-literal subshell)
# keeps the guard fast: the bash loop below then runs over only the ~dozens of
# matching literals, not the hundreds of total literals. The table-touch match is
# word-bounded so message_trace / message_attachments / message_recalls, a bare
# message_id column, and `mailboxes` do NOT match.
# The sorted expansion deliberately supplies one awk input argument per source file.
# shellcheck disable=SC2046
awk -v rls_tbl="$RLS_TBL" '
  BEGIN { mode=0; buf=""; startline=0 }
  FNR==1 { fname=FILENAME; mode=0; buf="" }   # reset literal state per file
  {
    line=$0; i=1; n=length(line)
    while (i<=n) {
      c=substr(line,i,1)
      if (mode==1) { if (c=="`") { mode=0; emit() } else { buf=buf c } ; i++ }
      else if (mode==2) {
        if (c=="\\") { buf=buf c substr(line,i+1,1); i+=2; continue }
        if (c=="\"") { mode=0; emit() } else { buf=buf c }
        i++
      } else {
        if (c=="/" && substr(line,i+1,1)=="/") break
        if (c=="`") { mode=1; buf=""; startline=FNR; i++ }
        else if (c=="\"") { mode=2; buf=""; startline=FNR; i++ }
        else i++
      }
    }
    if (mode==1) buf=buf " "
    else if (mode==2) { mode=0; buf="" }
  }
  function emit(   s, l) {
    s=buf; gsub(/[ \t\r\n]+/," ",s); sub(/^ /,"",s)
    if (s=="") return
    l=tolower(s)
    # table-touch on the FORCE-flip table set (RLS_TBL), word-bounded both sides.
    if (l ~ ("(^|[^a-z_])(from|join|into|update|delete +from) +" rls_tbl "([^a-z0-9_]|$)"))
      print fname ":" startline "\t" l "\t" s
  }
' $(find "$GATEWAY" -name '*.go' ! -name '*_test.go' -type f 2>/dev/null | LC_ALL=C sort) > "$TMP_HITS"

# Walk only the FORCE'd-table hits; flag any not classified.
while IFS=$'\t' read -r loc low sql; do
  [ -z "$low" ] && continue
  base="${loc##*/}"; base="${base%%:*}"
  if is_classified "$base" "$low"; then
    continue
  fi
  report "[RLS] ${loc}  FORCE'd-table app-pool site NOT classified for RLS coverage (set derived from mailserver/sql/dbschema V*.sql):"
  report "      $(printf '%s' "$sql" | cut -c1-150)"
  report "      → classify it in scripts/rls-coverage-allowlist.txt as WRAPPED (inside a CallScoped/withScope/inline scoped tx),"
  report "        BYPASS (handler constructed on workerPool — name the main.go line), or AUDITED-XTENANT (cross-tenant on bypass, with a reason)."
done < "$TMP_HITS"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "native-RLS coverage guard FAILED — uncovered FORCE'd-table app-pool site(s) above."
  echo "Each must be WRAPPED, BYPASS, or AUDITED-XTENANT before the prod DSN can switch to setjoin_app."
  echo "See retired-docs:superpowers/plans/archive/2026-06-18-native-rls-backstop.md (W7) and docs/standards/DATABASE_SECURITY.md (Deploy gate)."
  exit 1
fi

echo "    native-RLS coverage guard: clean (every FORCE'd-table app-pool site classified)."
