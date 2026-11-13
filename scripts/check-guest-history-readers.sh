#!/usr/bin/env bash
# Guest G2 history-wall manifest. These are the complete member-visible chat
# readers, remembered-ID mutations, and exact Drive attachment reads that can
# disclose or mutate message history. Every entry must keep an explicit,
# reviewable GUEST_HISTORY_FLOOR marker in its owning file. This is deliberately
# a fixed manifest, not a best-effort SQL/Go parser.
set -euo pipefail

ROOT="${GUEST_HISTORY_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
fail=0
count=0

while read -r reducer path; do
  count=$((count + 1))
  file="$ROOT/$path"
  if [ ! -f "$file" ]; then
    echo "GUEST-HISTORY: $reducer owner file is missing: $path"
    fail=1
    continue
  fi
  if ! grep -qE "^CREATE OR REPLACE FUNCTION ${reducer}\\(" "$file"; then
    echo "GUEST-HISTORY: $reducer is absent from its manifested owner $path"
    fail=1
  fi
  if ! grep -q "GUEST_HISTORY_FLOOR: $reducer" "$file"; then
    echo "GUEST-HISTORY: $reducer lost its history-floor marker in $path"
    fail=1
  fi
done <<'MANIFEST'
chat_messages_list mailserver/sql/reducers/chat_message.sql
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
MANIFEST

while read -r marker gofunc path; do
  count=$((count + 1))
  file="$ROOT/$path"
  if [ ! -f "$file" ]; then
    echo "GUEST-HISTORY: $marker owner file is missing: $path"
    fail=1
    continue
  fi
  if ! grep -qE "^func (\\([^)]*\\) )?${gofunc}\\(" "$file"; then
    echo "GUEST-HISTORY: $gofunc is absent from its manifested owner $path"
    fail=1
  fi
  if ! grep -q "GUEST_HISTORY_FLOOR: $marker" "$file"; then
    echo "GUEST-HISTORY: $marker lost its history-floor marker in $path"
    fail=1
  fi
done <<'GO_MANIFEST'
drive_attachment_content chatAttachmentLiveSQL mailserver/internal/drive/memberscope.go
drive_attachment_metadata chatAttachmentNodeVisibleSQL mailserver/internal/drive/memberscope.go
drive_chunk_head headChunk mailserver/internal/drive/chunks.go
GO_MANIFEST

if [ "$count" -ne 21 ]; then
  echo "GUEST-HISTORY: manifest cardinality drifted (got $count, want 21)"
  fail=1
fi

exit "$fail"
