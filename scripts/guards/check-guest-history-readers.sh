#!/usr/bin/env bash
# Guest G2 history-wall manifest. These are the complete member-visible chat
# readers, remembered-ID mutations, and exact Drive attachment reads that can
# disclose or mutate message history. Every entry must keep an explicit,
# reviewable GUEST_HISTORY_FLOOR marker in its owning file. This is deliberately
# a fixed manifest, not a best-effort SQL/Go parser.
set -euo pipefail

ROOT="${GUEST_HISTORY_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
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
chat_messages_list sql/reducers/chat_message.sql
chat_messages_since sql/reducers/chat_message.sql
chat_thread_list sql/reducers/chat_message.sql
chat_search sql/reducers/chat_search.sql
chat_conversation_list sql/reducers/chat_read.sql
chat_pins_list sql/reducers/chat_pin.sql
chat_saves_list sql/reducers/chat_save.sql
chat_my_threads sql/reducers/chat_threads.sql
chat_channel_readers sql/reducers/chat_readers.sql
chat_message_send sql/reducers/chat_message.sql
chat_message_edit sql/reducers/chat_message.sql
chat_message_delete sql/reducers/chat_message.sql
chat_reaction_toggle sql/reducers/chat_reaction.sql
chat_pin_toggle sql/reducers/chat_pin.sql
chat_save_toggle sql/reducers/chat_save.sql
chat_poll_vote sql/reducers/chat_poll.sql
chat_poll_close sql/reducers/chat_poll.sql
chat_poll_results sql/reducers/chat_poll.sql
MANIFEST

if [ "$count" -ne 18 ]; then
  echo "GUEST-HISTORY: manifest cardinality drifted (got $count, want 18)"
  fail=1
fi

exit "$fail"
