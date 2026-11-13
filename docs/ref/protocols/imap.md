## IMAP4rev2 Protocol Requirements
> **RFC 9051** (IMAP4rev2), **RFC 7162** (CONDSTORE)

### MANDATORY — Capability
- MUST advertise `IMAP4rev2`, NOT `IMAP4rev1` (§7.1.1)
- MUST NOT advertise capabilities the server cannot fulfill (e.g., LITERAL+, IDLE if broken)
- Current valid capabilities after TLS: `IMAP4rev2 LOGIN-REFERRALS ID ENABLE`
- Before TLS, a configured listener also advertises `STARTTLS LOGINDISABLED`; `LOGIN` and `AUTHENTICATE` return `PRIVACYREQUIRED` until the upgrade succeeds
- A non-loopback `IMAP_ADDR` is invalid unless both `TLS_CERT` and `TLS_KEY` are configured; loopback-only plaintext is reserved for explicit local development

### MANDATORY — SELECT/EXAMINE
- When `feature.imap_membership_uid` is OFF, the legacy UID rail remains active.
  When it is ON for a connection, the selected tag's `imap_folder_entries`
  rows are the sole message-sequence/UID authority for that connection.
- UIDVALIDITY MUST use the selected tag's `imap_uid_validity`, never a mailbox
  or tag internal ID (§4.1).
- UIDNEXT MUST be the selected tag's monotonic `imap_uid_next`, strictly greater
  than every live membership UID; deletions never reuse UIDs (§4.1).
- SELECT MUST emit required LIST response (§6.3.2)
- MUST emit [CLOSED] response code on mailbox deselection
- MUST NOT emit deprecated RECENT response

### MANDATORY — Required Commands (13 missing, all must be implemented)
- MOVE (§6.4.8), CLOSE (§6.4.2), UNSELECT (§6.4.2)
- COPY (§6.4.7), NAMESPACE (§6.3.8)
- CREATE, DELETE, RENAME (§6.3.3-6.3.5)
- STARTTLS (§6.2.1), AUTHENTICATE (§6.2.2)
- ENABLE (§6.3.1)

### MANDATORY — Existing Command Fixes (all done)
- ✅ SEARCH MUST use `ESEARCH` response format, not deprecated SEARCH (§6.4.4)
- ✅ SEARCH MUST return message sequence numbers, not UIDs (UID SEARCH returns UIDs via ESEARCH tag)
- ✅ FETCH MUST honor sequence set argument (currently fetches ALL messages)
- ✅ FETCH envelope structure MUST match RFC 9051 §7.4.2 format
- ✅ STORE MUST support range (e.g., `1:5`), not just single seq numbers (§6.4.6)
- ✅ EXPUNGE response sequence numbers MUST be correct (§7.5.1)
- ✅ IDLE MUST send actual unsolicited responses (§7.5.1)

### DO NOT
- Do NOT advertise `IMAP4rev1` — use `IMAP4rev2`
- Do NOT advertise `LITERAL+` unless non-synchronizing literals are fully supported
- Do NOT advertise `IDLE` unless server sends unsolicited responses
- Do NOT use mailbox internal ID for UIDVALIDITY
- Do NOT change UID interpretation mid-connection. The feature mode is pinned
  when the authenticated session begins; an operator drains/reconnects clients
  after changing the read mode.
- Do NOT report mailbox/tag IDs in COPYUID or MOVE response codes. The first
  value is the destination tag's UIDVALIDITY and the source/destination UID sets
  are paired in command order.

### Membership UID repair and cutover

`imap_membership_uid_backfill_batch` is bounded and restart-safe. Run batches
until `imap_membership_uid_readiness` reports no missing entries, duplicate live
UIDs, invalid UID ranges, or UIDNEXT mismatch. Progressless batches fail the
cutover rather than looping. Keep the feature OFF on any mismatch. A rollback
changes only the read mode; membership evidence is retained for diagnosis.

### Verification
```bash
go test ./internal/imap/... -v
pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test \
  mailserver/sql/tests/imap_membership_uid.pg
```
