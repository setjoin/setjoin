# RFC 9051 — IMAP4rev2 Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc9051

## §7.1.1 CAPABILITY
- Server MUST advertise `IMAP4rev2` in CAPABILITY string
- Server MUST NOT advertise capabilities it cannot fulfill

## §6.2.1 STARTTLS Command
- MUST be implemented
- Upgrades connection to TLS

## §6.2.2 AUTHENTICATE Command
- MUST be implemented  
- SASL authentication

## §6.4.8 MOVE Command (REQUIRED)
- Moves message(s) to another mailbox
- MUST return COPYUID response code

## §6.4.2 Mailbox Deselection
- CLOSE: permanently removes \Deleted messages, closes mailbox
- UNSELECT: closes mailbox without expunging
- Both MUST emit `[CLOSED]` response code
- RECENT response MUST NOT be emitted (deprecated)

## §6.4.4 SEARCH Command
- SEARCH response format is ESEARCH (extended search)
- Old SEARCH format is deprecated
- Returns message sequence numbers, not UIDs

## §4.1 UIDVALIDITY + UIDNEXT
- UIDVALIDITY MUST be a persistent value per mailbox (from database column)
- UIDNEXT MUST be the predicted next UID, not total+1

## Required Commands (27 total per RFC 9051)
CAPABILITY, NOOP, LOGOUT, ENABLE, STARTTLS, AUTHENTICATE, LOGIN, SELECT, EXAMINE, CREATE, DELETE, RENAME, SUBSCRIBE, UNSUBSCRIBE, LIST, STATUS, APPEND, CLOSE, UNSELECT, EXPUNGE, SEARCH, FETCH, STORE, COPY, MOVE, UID, NAMESPACE
