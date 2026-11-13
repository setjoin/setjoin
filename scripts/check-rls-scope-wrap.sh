#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-rls-scope-wrap.sh — W4 native-RLS Go-leg guard (the flip blocker's
# other half: mailserver/sql/dbschema/V134__meet_chat_write_policies.sql
# proved the write policies as setjoin_app in pgTAP, but internal/chat and
# internal/meet never SET the app.current_user_id GUC — so under the
# flipped runtime (setjoin_app, NOBYPASSRLS) every chat/meet route would
# fail-closed even with correct policies. retired-docs:superpowers/plans/
# 2026-06-18-native-rls-backstop.md, TODOS.md "Meet B1" ledger item 1.
#
# THE INVARIANT: every user-request-path DB call in internal/chat and
# internal/meet must run inside dbscope.RunUserScoped (the drive.go
# reference pattern — Begin, set_config('app.current_user_id', userID,
# true), fn, Commit, all transaction-local so it's PgBouncer-transaction-
# -mode-safe) — never a bare *pgxpool.Pool method call on the Handler's own
# `pool` field. After that refactor, the ONLY way `h.pool` can legally
# appear in either package is as a plain argument to
# dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {...}) —
# never as `h.pool.Query(`/`.QueryRow(`/`.Exec(`/`.Begin(`. That is the
# exact, mechanical thing this script checks: any DIRECT h.pool.<method>(
# call site outside the small, reasoned allowlist below is a W4 regression
# — a route that will fail-closed (or worse, silently run unscoped) the
# moment the runtime DSN flips to the constrained setjoin_app role.
#
# w.pool (a Worker's pgxutil.WorkerPool field, BYPASSRLS by construction —
# meet's worker.go/worker_breakouts.go/worker_captions.go/
# worker_recordings.go, chat/unfurl.go's own Worker type) is OUT OF SCOPE by
# construction: the receiver variable is `w`, never `h`, so it can never
# match the `h\.pool\.` pattern below — no allowlist entry needed, but
# named here for the reader who wonders why those files never show up.
#
# ALLOWLIST (file:Type.Func -> reason; every entry hand-verified against the
# reducer it calls, not just "looked unauthenticated"):
#   mailserver/internal/chat/unfurl.go:Handler.processUnfurl
#   mailserver/internal/chat/unfurl.go:Handler.applyUnfurl
#   mailserver/internal/chat/unfurl.go:Handler.fetchAndStoreImage
#   mailserver/internal/chat/unfurl.go:Handler.unfurlImage
#     -> every reducer called here (chat_link_preview_lookup/claim/
#        cache_write, chat_message_unfurl_apply, chat_link_preview_image_
#        owner) is ALREADY SECURITY DEFINER and self-scopes by url_hash/
#        sha256, never by caller identity (chat_link_previews is deny-all
#        to the app role, V122 §E) — there is no p_user_id to bind a GUC
#        to, and triggerUnfurl's detached goroutine (ctx.WithoutCancel)
#        never threads a caller id through in the first place.
#   mailserver/internal/meet/webhook.go:Handler.handleWebhook
#   mailserver/internal/meet/webhook.go:Handler.handleEgressEvent
#     -> the LiveKit webhook receiver: runs on the APP pool with NO caller
#        GUC (a webhook has no user) — V134 converted
#        meeting_participant_event/meeting_recording_event to SECURITY
#        DEFINER specifically so this call site can succeed with no GUC set.
#   mailserver/internal/meet/lobby.go:PublicHandler.handleCreate
#   mailserver/internal/meet/lobby.go:PublicHandler.handlePoll
#     -> the ONE unauthenticated Meet surface: meeting_join_request_create/
#        _poll are ALREADY SECURITY DEFINER (the pre-existing precedent
#        V134's own header cites for its two new conversions) and
#        self-scope by slug/secret — PublicHandler never resolves a caller
#        identity at all (locked interface, lobby.go's own header comment).
#
# Everything else — every route on chat.Handler / meet.Handler (including
# meet's PUBLIC-looking-but-actually-authed knock/decideJoinRequest, both on
# *Handler not *PublicHandler) — must route through dbscope.RunUserScoped,
# either directly or via the execChat/queryChatJSON/execMeet/queryMeetJSON
# choke points (which themselves call dbscope.RunUserScoped exactly once).
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

ALLOW=(
  "mailserver/internal/chat/unfurl.go:Handler.processUnfurl"
  "mailserver/internal/chat/unfurl.go:Handler.applyUnfurl"
  "mailserver/internal/chat/unfurl.go:Handler.fetchAndStoreImage"
  "mailserver/internal/chat/unfurl.go:Handler.unfurlImage"
  "mailserver/internal/meet/webhook.go:Handler.handleWebhook"
  "mailserver/internal/meet/webhook.go:Handler.handleEgressEvent"
  "mailserver/internal/meet/lobby.go:PublicHandler.handleCreate"
  "mailserver/internal/meet/lobby.go:PublicHandler.handlePoll"
)

is_allowed() {
  local key="$1" a
  for a in "${ALLOW[@]}"; do
    [ "$a" = "$key" ] && return 0
  done
  return 1
}

# funcKey <file> <line> -> "Type.Func" (or just "Func" for a free function)
# for the nearest `^func ` signature at or before <line> — the enclosing
# function/method of the matched call site.
funcKey() {
  local file="$1" line="$2" sig
  sig="$(awk -v target="$line" '/^func / && NR<=target { sig=$0 } END { print sig }' "$file")"
  local recv fn
  recv="$(printf '%s' "$sig" | sed -nE 's/^func \([a-zA-Z_][a-zA-Z0-9_]* \*([A-Za-z0-9_]+)\).*/\1/p')"
  if [ -n "$recv" ]; then
    fn="$(printf '%s' "$sig" | sed -nE 's/^func \([a-zA-Z_][a-zA-Z0-9_]* \*[A-Za-z0-9_]+\) ([A-Za-z0-9_]+)\(.*/\1/p')"
    printf '%s.%s' "$recv" "$fn"
  else
    fn="$(printf '%s' "$sig" | sed -nE 's/^func ([A-Za-z0-9_]+)[\(\[].*/\1/p')"
    printf '%s' "$fn"
  fi
}

# scan <dir> [allow-relative-to] -> prints "relpath:line" for every
# unwrapped h.pool.<method>( call site not covered by ALLOW. When
# allow-relative-to is empty (the real repo run), keys are checked against
# ALLOW verbatim; the self-test passes its own tmp root so ALLOW simply
# never matches (proving the flag path) without needing throwaway entries.
scan() {
  local dir="$1" reporoot="$2" f line key relpath
  while IFS=: read -r f line _; do
    [ -z "$f" ] && continue
    relpath="${f#"$reporoot"/}"
    key="$relpath:$(funcKey "$f" "$line")"
    if ! is_allowed "$key"; then
      echo "$relpath:$line"
    fi
  done < <(grep -rnE '\bh\.pool\.(Query|QueryRow|Exec|Begin)\(' --include='*.go' "$dir" 2>/dev/null | grep -v '_test\.go')
}

# ── self-test: a fixture with a wrapped (dbscope.RunUserScoped) call and a
# bare unwrapped one; the scan must flag exactly the unwrapped one. ────────
selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  # Deliberately NOT "wrapped.go"/"unwrapped.go" — one is a substring of the
  # other, the exact footgun check-scope-containment.sh's own selftest
  # comment warns about; distinct stems side-step it entirely.
  cat > "$tmp/clean.go" <<'EOF'
package x

func (h *Handler) ok(ctx context.Context, userID int64) error {
	return dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT 1`).Scan(&x)
	})
}
EOF
  cat > "$tmp/violation.go" <<'EOF'
package x

func (h *Handler) bad(ctx context.Context) error {
	return h.pool.QueryRow(ctx, `SELECT 1`).Scan(&x)
}
EOF
  local out; out="$(scan "$tmp" "$tmp")"
  if echo "$out" | grep -q 'clean\.go'; then
    echo "SELFTEST FAIL: flagged the dbscope.RunUserScoped-wrapped site" >&2; return 1
  fi
  if ! echo "$out" | grep -q 'violation\.go'; then
    echo "SELFTEST FAIL: missed the bare h.pool call" >&2; return 1
  fi
}

selftest

viol="$(
  { scan "$ROOT/mailserver/internal/chat" "$ROOT"
    scan "$ROOT/mailserver/internal/meet" "$ROOT"
  } 2>/dev/null
)"
if [ -n "$viol" ]; then
  echo "check-rls-scope-wrap: FAIL — direct h.pool call(s) outside dbscope.RunUserScoped and outside the allowlist:" >&2
  echo "$viol" | sed 's/^/  /' >&2
  echo "  Fix: wrap the call in dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error { ... })" >&2
  echo "  (see internal/drive for the reference pattern), or — if the reducer is genuinely" >&2
  echo "  SECURITY DEFINER and self-scoped with no caller identity — add a reasoned entry to" >&2
  echo "  this script's ALLOW list." >&2
  exit 1
fi
echo "check-rls-scope-wrap: OK — every chat/meet user-path DB call is GUC-scoped via dbscope.RunUserScoped"
