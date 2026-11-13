#!/usr/bin/env bash
# Prove the Guest G2 history-reader manifest guard is non-vacuous. Each
# mutation removes one reader's explicit floor marker from an otherwise clean
# scratch copy; the guard must fail and name that reducer. A clean copy must
# still pass.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD_SRC="$ROOT/scripts/check-guest-history-readers.sh"

if [ ! -f "$GUARD_SRC" ]; then
  echo "SELFTEST FAIL: missing check-guest-history-readers.sh"
  exit 1
fi

manifest='chat_messages_list mailserver/sql/reducers/chat_message.sql
chat_messages_since mailserver/sql/reducers/chat_message.sql
chat_thread_list mailserver/sql/reducers/chat_message.sql
chat_search mailserver/sql/reducers/chat_search.sql
chat_conversation_list mailserver/sql/reducers/chat_read.sql
chat_pins_list mailserver/sql/reducers/chat_pin.sql
chat_saves_list mailserver/sql/reducers/chat_save.sql
chat_my_threads mailserver/sql/reducers/chat_threads.sql
chat_channel_readers mailserver/sql/reducers/chat_readers.sql
chat_message_send mailserver/sql/reducers/chat_message.sql
chat_message_edit mailserver/sql/reducers/chat_message.sql
chat_message_delete mailserver/sql/reducers/chat_message.sql
chat_reaction_toggle mailserver/sql/reducers/chat_reaction.sql
chat_pin_toggle mailserver/sql/reducers/chat_pin.sql
chat_save_toggle mailserver/sql/reducers/chat_save.sql
chat_poll_vote mailserver/sql/reducers/chat_poll.sql
chat_poll_close mailserver/sql/reducers/chat_poll.sql
chat_poll_results mailserver/sql/reducers/chat_poll.sql
drive_attachment_content mailserver/internal/drive/memberscope.go
drive_attachment_metadata mailserver/internal/drive/memberscope.go
drive_chunk_head mailserver/internal/drive/chunks.go'

mk_clean() {
  local d="$1" path
  mkdir -p "$d/scripts"
  cp "$GUARD_SRC" "$d/scripts/"
  while read -r _ path; do
    mkdir -p "$d/$(dirname "$path")"
    cp "$ROOT/$path" "$d/$path"
  done <<< "$manifest"
}

fail=0
while read -r reducer path; do
  d="$(mktemp -d)"
  mk_clean "$d"
  sed "/GUEST_HISTORY_FLOOR: $reducer/d" "$ROOT/$path" > "$d/$path"
  if out="$(GUEST_HISTORY_ROOT="$d" bash "$d/scripts/check-guest-history-readers.sh" 2>&1)"; then
    echo "SELFTEST FAIL [$reducer]: guard did not fire after its marker was removed"
    fail=1
  elif ! grep -q "$reducer" <<< "$out"; then
    echo "SELFTEST FAIL [$reducer]: guard fired but did not name the reducer"
    echo "$out" | sed 's/^/    /'
    fail=1
  else
    echo "  [$reducer] missing marker caught: OK"
  fi
  rm -rf "$d"
done <<< "$manifest"

d="$(mktemp -d)"
mk_clean "$d"
if out="$(GUEST_HISTORY_ROOT="$d" bash "$d/scripts/check-guest-history-readers.sh" 2>&1)"; then
  echo "  [clean scratch copy] passes: OK"
else
  echo "SELFTEST FAIL [clean scratch copy]:"
  echo "$out" | sed 's/^/    /'
  fail=1
fi
rm -rf "$d"

if [ "$fail" -ne 0 ]; then
  echo "check-guest-history-readers selftest: FAILED"
  exit 1
fi
echo "check-guest-history-readers selftest OK (21/21 mutations caught + clean copy passes)"
