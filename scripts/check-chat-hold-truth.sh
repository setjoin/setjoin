#!/usr/bin/env bash
# check-chat-hold-truth.sh — chat_hold_active(id) is the ONLY hold-truth
# source (A4b spec §2.3). The raw chat_channels.legal_hold BOOLEAN is arm 1
# of the predicate; reading it directly for list/tile/preview/enforcement
# went blind the day case holds landed (V127). This guard fails any read of
# the bare `legal_hold` token in the scanned trees outside the enumerated
# writer/definition sites. legal_hold_reason (a display label, not a truth
# source) is exempt.
set -euo pipefail
cd "$(dirname "$0")/.."

# Legitimately-remaining raw-boolean sites (the arm's own plumbing), plus the
# MAIL/WORM-storage legal-hold namespace that merely shares the token
# (verified at plan time: admin_config.go `worm_legal_hold_enabled`,
# admin_ediscovery.go `legal_hold_objects` — mailbox/object-lock holds, not
# chat_channels.legal_hold):
#   chat_channel_set_hold.sql    — the boolean arm's set/release writer
#   V126__chat_compliance.sql    — arm-1 column DDL + the original predicate
#   V127__chat_oversight.sql     — the two-arm predicate definition (historical
#                                   first-CREATE, untouched — arch #A6)
#   chat_scope_helper.sql        — the LIVE chat_hold_active definition post
#                                   arch #A6 (reducer reload CREATE OR REPLACEs
#                                   over V127's copy; body is byte-identical)
allow='chat_channel_set_hold\.sql|V126__chat_compliance\.sql|V127__chat_oversight\.sql|chat_scope_helper\.sql|admin_config\.go|admin_ediscovery\.go'

# Match RAW-COLUMN reads only (qualified reference, WHERE predicate,
# assignment, or an unqualified SELECT-list read) — NOT the bare token: the
# repointed projection itself is `chat_hold_active(c.id) AS legal_hold`
# (wire-key alias, review F1), and an alias must never trip the guard that
# mandates it. legal_hold_reason is stripped first (display label, not a
# truth source).
#
# review F8: the original alternation missed an UNQUALIFIED list read —
# `SELECT id, legal_hold FROM chat_channels` has no `c.`/table-prefix, no
# WHERE/SET keyword, and no `=` on the same line, so it slipped through every
# existing arm. The added SELECT-list arm catches `legal_hold` immediately
# preceded by a comma/open-paren/SELECT-keyword-plus-space (i.e. it is a
# projected column, not a right-hand-side alias target). The line-start arm
# catches the multi-line variant (a continuation line of a wrapped SELECT list
# beginning with the bare column) — safe against the sanctioned alias, which
# always appears as `AS legal_hold` mid-line, never at line start.
hits=$(grep -rn --include='*.go' --include='*.sql' 'legal_hold' \
         mailserver/internal/admin mailserver/internal/chat mailserver/sql/reducers \
         mailserver/cmd mailctl 2>/dev/null \
       | grep -v '_test\.go' \
       | sed 's/legal_hold_reason//g' \
       | grep -E '(c\.legal_hold\b|chat_channels\.legal_hold\b|WHERE[[:space:]]+legal_hold\b|SET[[:space:]]+legal_hold\b|legal_hold[[:space:]]*=|SELECT[^;]*[,(][[:space:]]*legal_hold\b|SELECT[[:space:]]+legal_hold\b|^[^:]*:[0-9]+:[[:space:]]*`?legal_hold\b)' \
       | grep -Ev "$allow" || true)

if [ -n "$hits" ]; then
  echo "check-chat-hold-truth: raw legal_hold read outside the allowlist —"
  echo "route hold truth through chat_hold_active(channel_id) instead:"
  echo "$hits"
  exit 1
fi
echo "check-chat-hold-truth: OK"
