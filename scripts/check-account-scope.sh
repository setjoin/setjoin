#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-account-scope.sh — self-enforcing guard for the account-scope currency
# (ADR-003, docs/adr/ARCH-003-account-scope-currency.md) AND the seam-adoption +
# notify-channel contracts (the load-bearing seams: notify_state_change,
# transition_message_location, resolve_identity; ADR-004 address-aware identity).
#
# The account-slot argument every reducer receives is ALWAYS a mailbox_id
# (`parseAccountID` resolves a JMAP accountId to the caller's PRIMARY mailbox
# id). `users.id` and `mailboxes.id` are independent BIGSERIAL sequences and
# `mailboxes.user_id` is nullable, so confusing the two matches the WRONG row
# (or zero rows) and fails SILENTLY in production. Likewise, a push keyed by a
# user id (instead of a mailbox id) silently reaches NO subscriber, and a calendar
# person-lookup by `users.email` only silently misses anyone addressed by an alias
# or UPN. This guard makes those bug classes un-writable and un-maskable. It fails on:
#
#   A. Ownership-predicate confusion — a LIVE (non-comment) reducer line with a
#      `user_id = p_mailbox_id` / `user_id = p_account_id` predicate (scoping the
#      authenticated person by a mailbox id). Allowlisted: `p_viewer_id` /
#      `p_user_id` (genuinely user-keyed inputs — a different concept, ADR-003 §2).
#
#   B. A NEW `p_account_id` reducer PARAMETER — the retired legacy name. The only
#      two survivors are `calendar_free_busy` / `calendar_free_busy_multi`, pinned
#      by frozen migration V061 (documented ADR-003 exception, allowlisted here).
#
#   C. Mailbox-id against the USERS table — a `WHERE id = p_mailbox_id` /
#      `WHERE id = p_account_id` whose statement targets `users` (matching a
#      mailbox id against the users PK). This is the exact bug just found
#      (jmap_calendar_event_set_update:546). `WHERE id = p_mailbox_id` against
#      `mailboxes` is CORRECT and is not flagged.
#
#   D. Coincident pgTAP fixtures — `INSERT INTO mailboxes (id, user_id, …)` whose
#      first two VALUES are equal (mailbox.id == user_id). Coincident ids make a
#      buggy `user_id = p_mailbox_id` predicate pass by accident; divergent ids
#      are the regression guard. Tests must use mk_account() or disjoint literals.
#
#   E. Open-coded state-bump + push (seam bypass) — a reducer file (other than the
#      seam owners notify_state_change.sql / notify_calendar_state.sql /
#      notify_contact_state.sql, the reminder/mailbox self-bumpers, and the two
#      primitive-definers utils.sql / utils_tags.sql) that BOTH inline-`UPDATE
#      <table> SET jmap_<anything>_state` AND `pg_notify(` (case-insensitive). The
#      state-table match covers mailboxes | calendars | addressbooks |
#      contact_groups | tasks (not just mailboxes — calendar/contact bumps were
#      previously invisible); the state-column match is ANY jmap_*_state column
#      (email/tag/mailbox/thread/reminder/…). That re-implements the "thing changed
#      → bump JMAP state → push" side-effect the seam family owns; callers must
#      route through the matching seam.
#
#   F. Push channel keyed by a USER id — a `pg_notify('tag:'|…|'calendar:'|…|
#      'contact:' || <expr>` (case-insensitive on the pg_notify keyword) whose
#      <expr> is a user-id token (`user_id`, `p_user_id`, `p_viewer_id`,
#      `p_actor_id`, `*_user_id`). The channel id must be a MAILBOX id (subscribers
#      listen on `tag:{mailbox_id}`); a user-keyed channel reaches NO subscriber in
#      production. PLUS a Go-side assertion that the ws push-channel topology
#      (ws/topology.go's sessionChannels(), shared by WS + SSE — arch review
#      #A2) subscribes by the resolved mailbox id, never claims.UserID.
#
#   H. POSITIVE reducer-scope (param-is-used) — a reducer whose signature
#      DECLARES the account slot (`p_mailbox_id`/`p_account_id`) but never
#      REFERENCES it in the body. The negative checks above catch a WRONG
#      predicate; H catches the accept-but-IGNORE bug (DATABASE_SECURITY.md "rule
#      of thumb"): an unused account slot scopes nothing, so the reducer
#      returns/mutates rows for EVERY mailbox (R1). This is the positive half that
#      makes the steady state fail-closed under the deferred-RLS posture
#      (ARCH-006). HONEST BOUND: it is "param-is-USED", not
#      "every-user-data-statement-is-scoped" — a finer per-statement check is too
#      false-positive-prone given reducers resolve p_mailbox_id into derived
#      locals (account_scope → v_domain_id), bind it via EXECUTE … USING, and
#      thread it through CTEs. The finer gap stays on A/C + review (ARCH-006 §residual).
#
#   G. Calendar person-lookup by a single address — a `<alias>.email = …` for ANY
#      alias bound to the `users` table (`u`, `usr`, `mu`, … — discovered from
#      FROM/JOIN `users <alias>`), or `users.email = …`, or a bare `WHERE email = …`
#      against `users`, in a CALENDAR reducer. A person must be resolved
#      address-aware (primary ∪ alias ∪ UPN) via resolve_identity() (ADR-004 §3),
#      never by users.email alone (which misses alias/UPN-addressed people). A
#      `mailboxes.email = …` ownership check is CORRECT and not flagged.
#
# Exact and low-false-positive by construction: checks operate on
# comment-stripped SQL; A/C/G resolve the target table of the actual statement
# (not a line-local guess); B matches only real parameter declarations; E/F are
# file- and channel-scoped with explicit allowlists.
#
# KNOWN LIMIT (documented, not over-engineered): a reducer can stage a user id in
# a local variable (e.g. `v_uid := claims_user; … pg_notify('tag:' || v_uid, …)`)
# and the channel/predicate then references the local, not a p_user_id-shaped
# token — F/A cannot see through that variable indirection lexically. Catching it
# would require dataflow analysis. Mitigations that DO hold the line: the
# convention that the account slot is `p_mailbox_id` (so the correct value is in
# scope without an intermediate), the DB-gated push_channel_test.go (asserts the
# mailbox-keyed channel receives and the user-keyed channel is silent), and code
# review. New reducers staging a user id into a local before a pg_notify channel
# should be treated as suspect in review.
#
# Usage: scripts/check-account-scope.sh   (exit 0 = clean, 1 = violation found)
# Wired into scripts/test.sh.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# REDUCERS_DIR / TESTS_DIR may be overridden (used by the guard's own negative-case
# self-test); they default to the repo's reducer + pgTAP trees.
REDUCERS="${REDUCERS_DIR:-$ROOT/mailserver/sql/reducers}"
TESTS="${TESTS_DIR:-$ROOT/mailserver/sql/tests}"
# WS_HANDLER may be overridden by the self-test; defaults to the ws push-channel
# topology (arch review #A2: WS Upgrade + SSE EventSource single-home their
# session NOTIFY-channel construction in ws/topology.go's sessionChannels(),
# so that — not ws/handler.go — is the one place "tag:%d"/mailboxID now
# literally appears).
WS_HANDLER="${WS_HANDLER:-$ROOT/mailserver/internal/ws/topology.go}"

# Files allowed to keep the legacy `p_account_id` param (frozen V061; ADR-003 §B).
ACCOUNT_ID_ALLOWLIST="calendar_freebusy.sql calendar_freebusy_multi.sql"

# Files allowed to BOTH bump a jmap_*_state column inline AND pg_notify (Check E).
# notify_state_change.sql is the single owner of the EMAIL/TAG/THREAD push domain;
# notify_calendar_state.sql / notify_contact_state.sql are the calendar / contact
# secondary seams (the bump+push every calendar/contact reducer routes through);
# notify_task_state.sql is the task secondary seam (PUSH-ONLY: the per-row
# tasks.jmap_state bump stays in jmap_task.sql; the seam owns only the task: push);
# utils.sql / utils_tags.sql DEFINE the bump primitives (and never pg_notify
# themselves). The remaining two own DISTINCT state domains that the seams do NOT
# cover, so they legitimately bump+push themselves:
#   - jmap_mailbox.sql       — Mailbox/set self-bumps jmap_mailbox_state, pushes on
#                              tag:{mailbox_id} (folder rename/reparent/subscribe).
#   - reminders_actions.sql  — bump_reminder_state bumps jmap_reminder_state (the
#                              reminder ledger, A6, the reminder seam), pushes on
#                              tag:{mailbox_id}.
# scheduled_action_remind.sql is NO LONGER allowlisted — it now routes its
# jmap_reminder_state bump+push through bump_reminder_state (Decision C), so it
# inline-bumps nothing. All push on the CORRECT mailbox-keyed channel (Check F still
# guards that). New files that inline a jmap_*_state bump on mailboxes / calendars /
# addressbooks / contact_groups / tasks + pg_notify are still caught.
# append_change.sql (the jmap_changes_journal writer, offline #3) is NOT in this
# list — it only INSERTs into jmap_changes_journal; it never bumps a jmap_*_state
# column or calls pg_notify. Check E does not flag it. check-changes-journal-coverage.sh
# is the dedicated guard for the journal-coverage contract (every jmap_email_state bump
# must pair with append_email_change or route through notify_state_change).
STATE_NOTIFY_ALLOWLIST="notify_state_change.sql notify_calendar_state.sql notify_contact_state.sql notify_task_state.sql utils.sql utils_tags.sql jmap_mailbox.sql reminders_actions.sql"

# Calendar reducer files Check G inspects for single-address person lookups.
CALENDAR_GLOB_RE='^(calendar_|jmap_calendar)'

fail=0
report() { echo "  $1"; fail=1; }

is_allowlisted_account_file() {
  local base; base="$(basename "$1")"
  for a in $ACCOUNT_ID_ALLOWLIST; do [ "$base" = "$a" ] && return 0; done
  return 1
}

is_state_notify_allowlisted() {
  local base; base="$(basename "$1")"
  for a in $STATE_NOTIFY_ALLOWLIST; do [ "$base" = "$a" ] && return 0; done
  return 1
}

echo "==> ADR-003 account-scope + seam-adoption + notify-channel guard"

# ── Check A + C: predicate confusion in LIVE reducer SQL ─────────────────────
# A single awk pass per file. It strips `-- …` line comments, tracks the most
# recent table token from FROM/JOIN/UPDATE/INTO (the statement the WHERE belongs
# to), and inspects each `= p_mailbox_id` / `= p_account_id` comparison.
for f in "$REDUCERS"/*.sql; do
  out=$(awk '
    # Strip a trailing line comment (-- …). Good enough: reducers never embed
    # a literal "--" inside a string on the lines we inspect.
    { line = $0; sub(/--.*/, "", line) }

    # Track the nearest preceding table token of the current statement.
    {
      tmp = line
      while (match(tmp, /[Ff][Rr][Oo][Mm][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        tok = substr(tmp, RSTART, RLENGTH); sub(/^[Ff][Rr][Oo][Mm][ \t]+/, "", tok)
        last_table = tolower(tok); tmp = substr(tmp, RSTART + RLENGTH)
      }
      tmp = line
      while (match(tmp, /[Jj][Oo][Ii][Nn][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        tok = substr(tmp, RSTART, RLENGTH); sub(/^[Jj][Oo][Ii][Nn][ \t]+/, "", tok)
        last_table = tolower(tok); tmp = substr(tmp, RSTART + RLENGTH)
      }
      if (match(line, /[Uu][Pp][Dd][Aa][Tt][Ee][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        tok = substr(line, RSTART, RLENGTH); sub(/^[Uu][Pp][Dd][Aa][Tt][Ee][ \t]+/, "", tok)
        last_table = tolower(tok)
      }
      if (match(line, /[Ii][Nn][Tt][Oo][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        # INTO targets a table only for INSERT INTO; plpgsql SELECT … INTO var is
        # not a table. Only treat as table when preceded by INSERT on this line.
        if (line ~ /[Ii][Nn][Ss][Ee][Rr][Tt][ \t]+[Ii][Nn][Tt][Oo]/) {
          tok = substr(line, RSTART, RLENGTH); sub(/^[Ii][Nn][Tt][Oo][ \t]+/, "", tok)
          last_table = tolower(tok)
        }
      }
    }

    # Check A: user_id = p_mailbox_id / p_account_id (ownership predicate).
    # Word boundaries written as explicit char classes (portable BSD+GNU awk).
    line ~ /[Uu][Ss][Ee][Rr]_[Ii][Dd][ \t]*=[ \t]*p_(mailbox_id|account_id)([^A-Za-z0-9_]|$)/ {
      print "A\t" NR "\t" $0
    }

    # Check C: WHERE id = p_mailbox_id / p_account_id where the statement targets
    # the users table (a mailbox id matched against users.id — the bug class).
    line ~ /(^|[^A-Za-z0-9_])id[ \t]*=[ \t]*p_(mailbox_id|account_id)([^A-Za-z0-9_]|$)/ {
      if (last_table == "users") print "C\t" NR "\t" $0
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r kind lineno text; do
    [ -z "$kind" ] && continue
    if [ "$kind" = "A" ]; then
      report "[A] $(basename "$f"):$lineno  ownership predicate scopes a user by a mailbox id:"
      report "      ${text#"${text%%[![:space:]]*}"}"
      report "      → the account slot is a mailbox id; scope by 'mailbox_id = p_mailbox_id', or use p_user_id/p_viewer_id for genuinely user-keyed inputs."
    else
      report "[C] $(basename "$f"):$lineno  mailbox id matched against the USERS table (matches zero rows in prod):"
      report "      ${text#"${text%%[![:space:]]*}"}"
      report "      → resolve the user behind a mailbox via account_scope(p_mailbox_id), not 'users WHERE id = p_mailbox_id'."
    fi
  done <<< "$out"
done

# ── Check B: any NEW `p_account_id` parameter declaration ────────────────────
# A param declaration is `p_account_id <TYPE>` (not a comment, not a call site).
for f in "$REDUCERS"/*.sql; do
  is_allowlisted_account_file "$f" && continue
  out=$(awk '
    { line = $0; sub(/--.*/, "", line) }
    line ~ /(^|[^A-Za-z0-9_])p_account_id[ \t]+(BIGINT|INT|INTEGER|SMALLINT|TEXT|BOOLEAN|BOOL|JSONB|JSON|TIMESTAMPTZ|TIMESTAMP|DATE|UUID|NUMERIC|BIGINT[ \t]*\[\])/ {
      print NR "\t" $0
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r lineno text; do
    [ -z "$lineno" ] && continue
    report "[B] $(basename "$f"):$lineno  new 'p_account_id' parameter (retired name — use 'p_mailbox_id'):"
    report "      ${text#"${text%%[![:space:]]*}"}"
    report "      → rename the parameter to p_mailbox_id (ADR-003). Only calendar_free_busy[_multi] keep the legacy name (frozen V061)."
  done <<< "$out"
done

# ── Check D: coincident-id pgTAP fixtures (mailbox.id == user_id) ─────────────
# Flags INSERT INTO mailboxes (id, user_id, …) VALUES (A, B, …) where A == B.
# The VALUES tuple often lands on a line AFTER the INSERT … (id, user_id, …)
# column list, so we stay "armed" from the column list until a value tuple is
# inspected, and handle multi-row VALUES on one line. Case classes (not the
# gawk-only IGNORECASE) keep this portable across BSD + GNU awk.
for f in "$TESTS"/*.pg "$TESTS"/*.sql; do
  [ -e "$f" ] || continue
  out=$(awk '
    # Arm when we see INSERT INTO mailboxes (id, user_id, … — record the line.
    /[Ii][Nn][Ss][Ee][Rr][Tt][ \t]+[Ii][Nn][Tt][Oo][ \t]+mailboxes[ \t]*\([ \t]*id[ \t]*,[ \t]*user_id([ \t]*,| )/ {
      armed = 1; arm_line = NR; arm_text = $0
    }
    armed {
      rest = $0
      while (match(rest, /\([ \t]*[0-9]+[ \t]*,[ \t]*[0-9]+/)) {
        tuple = substr(rest, RSTART, RLENGTH)
        a = tuple; sub(/^\([ \t]*/, "", a); sub(/[ \t]*,.*/, "", a)
        b = tuple; sub(/^\([ \t]*[0-9]+[ \t]*,[ \t]*/, "", b)
        if (a == b) { print arm_line "\t" arm_text }
        armed = 0   # one INSERT statement = one verdict (first value tuple wins)
        rest = substr(rest, RSTART + RLENGTH)
      }
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r lineno text; do
    [ -z "$lineno" ] && continue
    report "[D] $(basename "$f"):$lineno  coincident fixture (mailbox.id == user_id) masks the bug class:"
    report "      ${text#"${text%%[![:space:]]*}"}"
    report "      → use mk_account()/mk_shared_mailbox() or give the mailbox an id != its user_id (divergent by construction)."
  done <<< "$out"
done

# ── Check E: open-coded state-bump + push (seam bypass) ──────────────────────
# A reducer file (not a seam owner / not a primitive-definer) that BOTH
# inline-bumps a `jmap_*_state` column inside an `UPDATE <state-table> … ;`
# statement AND `pg_notify(` re-implements the "thing changed → bump JMAP state →
# push" side-effect the seam family owns. Comment-stripped.
#
# PRECISION (Wave 3 fix): the state-bump detection must find an
# `UPDATE <state-table> SET …` whose statement (spanning newlines, up to its
# terminating `;`) contains a `jmap_*_state =` assignment ANYWHERE — NOT only when
# jmap_state is the FIRST column after SET on a SINGLE line. Two real bypasses hid
# behind the old line-local form: (a) `UPDATE calendars SET is_shared=…,
# jmap_state=jmap_state+1` (jmap_state not first) and (b) a multi-line UPDATE whose
# column list spans lines before the `jmap_state = …` line. The awk below
# accumulates each `UPDATE <state-table> … ;` statement across lines and matches a
# `jmap_*_state =` assignment within that accumulated range.
#
# The state-table set is mailboxes | calendars | addressbooks | contact_groups |
# tasks; the state-column match is ANY jmap_*_state column
# (email/tag/mailbox/thread/reminder/…). pg_notify is matched case-insensitively
# (PG_NOTIFY( is the same call and must not defeat the check).
for f in "$REDUCERS"/*.sql; do
  is_state_notify_allowlisted "$f" && continue
  has_state=$(awk '
    { line = $0; sub(/--.*/, "", line) }
    # Not currently inside a tracked UPDATE statement: look for the start of an
    # UPDATE on a state-bearing table. (Case classes keep this portable BSD+GNU.)
    !instmt {
      if (line ~ /[Uu][Pp][Dd][Aa][Tt][Ee][ \t]+(mailboxes|calendars|addressbooks|contact_groups|tasks)([ \t]|$)/) {
        instmt = 1; stmt_line = NR; acc = line
        # The terminating ; may already be on this same line (single-line UPDATE).
        if (acc ~ /;/) {
          if (acc ~ /jmap_[A-Za-z_]*state[ \t]*=/) { print stmt_line; exit }
          instmt = 0; acc = ""
        }
        next
      }
      next
    }
    # Inside the UPDATE statement: accumulate lines until the terminating ;.
    instmt {
      acc = acc " " line
      if (acc ~ /;/) {
        # Statement complete — does it assign a jmap_*_state column anywhere?
        if (acc ~ /jmap_[A-Za-z_]*state[ \t]*=/) { print stmt_line; exit }
        instmt = 0; acc = ""
      }
    }
  ' "$f")
  [ -z "$has_state" ] && continue
  has_notify=$(awk '{ line=tolower($0); sub(/--.*/,"",line);
    if (line ~ /pg_notify[ \t]*\(/) { print NR; exit } }' "$f")
  [ -z "$has_notify" ] && continue
  report "[E] $(basename "$f"):$has_state  open-codes a JMAP state bump + pg_notify (line $has_notify) outside notify_state_change:"
  report "      → route the bump+push through notify_state_change(p_mailbox_id, p_tag_id); do not inline UPDATE …jmap_*_state + pg_notify."
done

# ── Check F: a push channel keyed by a USER id (not a mailbox id) ─────────────
# pg_notify('tag:'|'calendar:'|'contact:' || <expr>) where <expr> is a user-id
# token. Subscribers listen on tag:{mailbox_id}; a user-keyed channel reaches no
# one. The channel literal and the key expr may span the call's first two lines,
# so inspect each pg_notify with its following line joined.
for f in "$REDUCERS"/*.sql; do
  out=$(awk '
    { raw[NR] = $0 }
    END {
      for (i = 1; i <= NR; i++) {
        # Lowercase the working copy so PG_NOTIFY( / Pg_Notify( (same call) are
        # caught too. Channel prefixes (tag/calendar/contact) and user-id tokens
        # are lowercase by convention, so matching on the lowercased copy is exact.
        line = tolower(raw[i]); sub(/--.*/, "", line)
        if (line !~ /pg_notify[ \t]*\(/) continue
        # Join this line + the next (channel arg often wraps to the next line).
        joined = line
        if (i < NR) { nxt = tolower(raw[i+1]); sub(/--.*/, "", nxt); joined = joined " " nxt }
        # Isolate the channel argument: text between pg_notify( and the first comma.
        chan = joined
        sub(/.*pg_notify[ \t]*\(/, "", chan)
        sub(/,.*/, "", chan)
        # Flag only the mailbox-keyed channel families, keyed by a user-id token.
        if (chan ~ /['"'"'](tag|calendar|contact):['"'"'][ \t]*\|\|/ &&
            chan ~ /(^|[^A-Za-z0-9_])(p_user_id|p_viewer_id|p_actor_id|user_id|[A-Za-z_]*_user_id)([^A-Za-z0-9_]|$)/) {
          gsub(/^[ \t]+/, "", chan)
          print i "\t" chan
        }
      }
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r lineno chan; do
    [ -z "$lineno" ] && continue
    report "[F] $(basename "$f"):$lineno  push channel keyed by a user id (reaches NO subscriber in prod):"
    report "      channel: ${chan}"
    report "      → key the channel on the MAILBOX id (e.g. 'tag:' || p_mailbox_id), the value subscribers listen on."
  done <<< "$out"
done

# ── Check F (Go side): ws/handler.go must subscribe by a mailbox id ───────────
# The push producer emits on tag:{mailbox_id}; the consumer must subscribe there,
# never on claims.UserID (the historic bug — silently matched zero notifications).
if [ -f "$WS_HANDLER" ]; then
  if ! grep -qE 'fmt\.Sprintf\("tag:%d", *mailboxID\)' "$WS_HANDLER"; then
    report "[F] $(basename "$WS_HANDLER")  WS handler does not subscribe to tag:{mailboxID}:"
    report "      → it must subscribe on the resolved primary mailbox id (fmt.Sprintf(\"tag:%d\", mailboxID))."
  fi
  if grep -qE 'fmt\.Sprintf\("(tag|calendar):%d", *claims\.UserID\)' "$WS_HANDLER"; then
    report "[F] $(basename "$WS_HANDLER")  WS handler subscribes by claims.UserID (the user id), not a mailbox id:"
    report "      → resolve the primary mailbox id (GetAccountID) and subscribe on tag:{mailboxID}."
  fi
fi

# ── Check G: calendar person-lookup by a single address (use resolve_identity) ─
# A `<alias>.email = …` for ANY alias bound to the users table (or a bare
# `WHERE email = …` against users) in a CALENDAR reducer resolves a person by
# their primary address only — missing aliases + ad_upn (ADR-004). It must go
# through resolve_identity(). A `mailboxes.email = …` ownership check is correct
# and is NOT flagged. The aliases are discovered dynamically from FROM/JOIN
# `users <alias>` so non-`u` aliases (usr, mu, …) can't slip a person-lookup past.
for f in "$REDUCERS"/*.sql; do
  base="$(basename "$f")"
  [[ "$base" =~ $CALENDAR_GLOB_RE ]] || continue
  out=$(awk '
    { line = $0; sub(/--.*/, "", line)
      # Record every alias bound to the users table: FROM users <alias> /
      # JOIN users <alias> (the alias is optional — bare "FROM users" sets the
      # statement table). The optional AS keyword is handled. File-scoped: an
      # alias bound anywhere in the file is treated as a users alias everywhere
      # (reducers do not rebind a short alias to two different tables).
      tmp = line
      while (match(tmp, /[Ff][Rr][Oo][Mm][ \t]+users([ \t]+([Aa][Ss][ \t]+)?[A-Za-z_][A-Za-z0-9_]*)?/)) {
        seg = substr(tmp, RSTART, RLENGTH); last_table = "users"
        a = seg; sub(/^[Ff][Rr][Oo][Mm][ \t]+users[ \t]*/, "", a); sub(/^[Aa][Ss][ \t]+/, "", a)
        if (a ~ /^[A-Za-z_][A-Za-z0-9_]*$/) users_alias[tolower(a)] = 1
        tmp = substr(tmp, RSTART + RLENGTH)
      }
      tmp = line
      while (match(tmp, /[Jj][Oo][Ii][Nn][ \t]+users([ \t]+([Aa][Ss][ \t]+)?[A-Za-z_][A-Za-z0-9_]*)?/)) {
        seg = substr(tmp, RSTART, RLENGTH); last_table = "users"
        a = seg; sub(/^[Jj][Oo][Ii][Nn][ \t]+users[ \t]*/, "", a); sub(/^[Aa][Ss][ \t]+/, "", a)
        if (a ~ /^[A-Za-z_][A-Za-z0-9_]*$/) users_alias[tolower(a)] = 1
        tmp = substr(tmp, RSTART + RLENGTH)
      }
      # Track the nearest preceding statement table (for the bare-email case and a
      # non-users FROM/JOIN that resets last_table).
      tmp = line
      while (match(tmp, /[Ff][Rr][Oo][Mm][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        tok = substr(tmp, RSTART, RLENGTH); sub(/^[Ff][Rr][Oo][Mm][ \t]+/, "", tok)
        last_table = tolower(tok); tmp = substr(tmp, RSTART + RLENGTH)
      }
      tmp = line
      while (match(tmp, /[Jj][Oo][Ii][Nn][ \t]+[A-Za-z_][A-Za-z0-9_]*/)) {
        tok = substr(tmp, RSTART, RLENGTH); sub(/^[Jj][Oo][Ii][Nn][ \t]+/, "", tok)
        last_table = tolower(tok); tmp = substr(tmp, RSTART + RLENGTH)
      }
    }
    # Qualified person match: users.email = (always a person lookup).
    line ~ /(^|[^A-Za-z0-9_])users\.email[ \t]*=/ { print NR "\t" $0; next }
    # Qualified person match against ANY alias bound to users (u, usr, mu, …).
    {
      probe = line
      while (match(probe, /(^|[^A-Za-z0-9_])[A-Za-z_][A-Za-z0-9_]*\.email[ \t]*=/)) {
        m = substr(probe, RSTART, RLENGTH)
        al = m; sub(/^[^A-Za-z0-9_]*/, "", al); sub(/\.email.*/, "", al)
        if (tolower(al) in users_alias) { print NR "\t" $0; probe = ""; next }
        probe = substr(probe, RSTART + RLENGTH)
      }
    }
    # Bare `email = …` only when the current statement targets the users table.
    line ~ /(^|[^A-Za-z0-9_.])email[ \t]*=/ {
      if (last_table == "users") print NR "\t" $0
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r lineno text; do
    [ -z "$lineno" ] && continue
    report "[G] $base:$lineno  calendar person-lookup by a single address (misses aliases + UPN):"
    report "      ${text#"${text%%[![:space:]]*}"}"
    report "      → resolve the person address-aware via resolve_identity(address) (ADR-004 §3), not users.email =."
  done <<< "$out"
done

# ── Check H: POSITIVE reducer-scope — a declared account slot must be USED ────
# The checks above are NEGATIVE (they catch a reducer that writes the WRONG
# predicate). H is the POSITIVE half that makes the steady state fail-closed
# under the deferred-RLS posture (ARCH-006): a reducer whose signature DECLARES
# the account slot (`p_mailbox_id`/`p_account_id`) must REFERENCE that parameter
# in its body — at least once beyond the declaration. This catches the
# accept-but-ignore R1 bug (DATABASE_SECURITY.md "rule of thumb": a function that
# receives the account slot but never uses it scopes NOTHING — it returns/mutates
# rows for EVERY mailbox). A parameter declaration is `p_<name> <TYPE>` inside the
# argument list; a use is any other occurrence of the token (a WHERE predicate, a
# `USING p_mailbox_id` dynamic-SQL bind, an `account_scope(p_mailbox_id)` resolve
# into a local/CTE, …).
#
# HONEST BOUND (recorded in ARCH-006's residual): this is "param-is-USED", NOT
# "every-user-data-statement-is-scoped". A reducer that uses p_mailbox_id in ONE
# statement but forgets it in a SECOND user-data statement is NOT caught here — a
# per-statement positive check is too false-positive-prone given reducers
# legitimately resolve p_mailbox_id into derived locals (`v_domain_id` via
# account_scope), bind it through `EXECUTE … USING p_mailbox_id`, and thread it
# through CTEs (retention.sql scopes every statement by a v_domain_id derived from
# account_scope(p_mailbox_id) — a per-statement check would false-fire on all of
# them). The finer per-statement gap stays on the NEGATIVE checks A/C + review.
for f in "$REDUCERS"/*.sql; do
  is_allowlisted_account_file "$f" && continue   # frozen calendar_free_busy[_multi]
  out=$(awk '
    { line = $0; sub(/--.*/, "", line) }
    # A declaration: p_mailbox_id / p_account_id immediately followed by a TYPE
    # (inside the CREATE FUNCTION arg list). Record that the slot is declared and
    # on which line; also count NON-declaration uses of the same token.
    {
      for (slot = 1; slot <= 2; slot++) {
        name = (slot == 1) ? "p_mailbox_id" : "p_account_id"
        # declaration form: <name> <TYPE>
        decl_re = "(^|[^A-Za-z0-9_])" name "[ \t]+(BIGINT|INT|INTEGER|SMALLINT|TEXT|BOOLEAN|BOOL|JSONB|JSON|TIMESTAMPTZ|TIMESTAMP|DATE|UUID|NUMERIC)"
        if (line ~ decl_re) { declared[name] = 1; if (!(name in declline)) declline[name] = NR }
        # any occurrence of the bare token (declaration or use)
        probe = line
        while (match(probe, "(^|[^A-Za-z0-9_])" name "([^A-Za-z0-9_]|$)")) {
          occ[name]++
          probe = substr(probe, RSTART + RLENGTH)
        }
      }
    }
    END {
      for (slot = 1; slot <= 2; slot++) {
        name = (slot == 1) ? "p_mailbox_id" : "p_account_id"
        # Declared but referenced ONLY in the declaration line(s) → never used.
        # A used param has occ > number-of-declarations. We approximate
        # "number of declarations" as 1 (a reducer declares the slot once); a
        # second occurrence anywhere is a genuine use.
        if (declared[name] && occ[name] <= 1) {
          print name "\t" declline[name]
        }
      }
    }
  ' "$f")
  [ -z "$out" ] && continue
  while IFS=$'\t' read -r slot lineno; do
    [ -z "$slot" ] && continue
    report "[H] $(basename "$f"):$lineno  reducer DECLARES the account slot '$slot' but never USES it (scopes nothing):"
    report "      → reference '$slot' in the body — scope user-data statements by 'mailbox_id = $slot' (or resolve the user/domain via account_scope($slot)). An unused account slot returns/mutates rows for EVERY mailbox (R1)."
  done <<< "$out"
done

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "account-scope / seam-adoption / notify-channel guard FAILED."
  echo "See docs/adr/ARCH-003-account-scope-currency.md and ARCH-004-directory-org-scope.md."
  exit 1
fi

echo "    account-scope + seam-adoption + notify-channel guard: clean."
