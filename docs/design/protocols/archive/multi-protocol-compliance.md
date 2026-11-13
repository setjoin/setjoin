# Multi-Protocol Compliance — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Fix 44 protocol compliance findings spanning IMAP (29), SMTP (23), JMAP (3), CalDAV (3), LDAP (1), DKIM (1), DMARC (1), and DANE (1). Found via full-codebase quality audit + RFC compliance check against 39 RFCs. Each finding references the exact RFC section.

## IMAP4rev2 Compliance (RFC 9051)

### Critical (3)

| # | Line | Finding | RFC | Fix |
|---|------|---------|-----|-----|
| C1 | 388 | EXAMINE readOnly never enforced — write handlers don't check `c.readOnly` | 9051 §6.3.2 | Add `checkNotReadOnly()` guard at entry to STORE(812), EXPUNGE(962), MOVE(1233), COPY(1288), APPEND(1492). Returns `NO [READ-ONLY]` if true. |
| C2 | 317 | App password LOGIN success path sets `c.authed=true` but returns without sending tagged OK — client hangs | 9051 §6.2.2 | Add `c.reply(tag, "OK [CAPABILITY ...] LOGIN completed")` after line 318 |
| C3 | 1433 | Same bug in AUTHENTICATE app password path — sets authed, no OK response | 9051 §6.2.2 | Add `c.reply(tag, "OK AUTHENTICATE completed")` after line 1435 |

### High (3)

| # | Line | Finding | RFC | Fix |
|---|------|---------|-----|-----|
| H1 | 262 | No inactivity timeout — connections stay open indefinitely | 9051 §7.1.4 | 30-min idle timer. Send `* BYE Idle timeout` before close. Reset timer on any command. |
| H2 | 721 | Capability doesn't reflect post-STARTTLS state | 9051 §6.2.1 | Recompute capability string after STARTTLS completes |
| H3 | 324 | smtp_sessions INSERT error silently ignored in IMAP → SMTP bridge | — | Log error, return tagged NO to client |

### Medium (9)

| # | Line | Finding | RFC | Fix |
|---|------|---------|-----|-----|
| M1 | 576 | FETCH missing BODY[] and BODYSTRUCTURE fetch items | 9051 §6.4.5 | Implement BODY[] (header/body parts by section), BODYSTRUCTURE (MIME tree) |
| M2 | 441 | LIST missing CHILDREN capability — clients can't show expand/collapse | 9052 §4.3 | Add CHILDREN to capability. Return `\HasChildren` or `\HasNoChildren` in LIST response |
| M3 | 547 | STATUS always returns all data items, ignoring client request | 9051 §6.3.11 | Only include data items the client explicitly requested in the STATUS command |
| M4 | 1492 | APPEND EXISTS response sends 0 instead of actual count | 9051 §6.3.12 | Query actual EXISTS after append, use that count |
| M5 | 1233 | MOVE/COPY COPYUID emits message sequence numbers instead of UIDs | 9051 §6.3.9 | Fix COPYUID response to use actual UIDs from uid_mapping |
| M6 | 1607 | IDLE doesn't verify mailbox is selected | 9051 §6.3.14 | If no mailbox selected, reject IDLE with tagged BAD |
| M7 | 223 | UID handler missing UID EXPUNGE support | 9051 §6.4.8 | Add UID EXPUNGE command handler |
| M8 | 576 | FETCH data model uses "tags" internally but IMAP spec uses "folders" — inconsistency | 9051 §1 | Rename internal references to use "folders" consistently |
| M9 | 530 | RCPT TO accepted from any state — should only be valid after MAIL FROM, before DATA | 9051 §6.2 | Enforce strict state machine in RCPT TO handler |

### Low (5)

| # | Line | Finding | RFC | Fix |
|---|------|---------|-----|-----|
| L1 | 275 | Missing SPECIAL-USE capability — no \Sent, \Drafts, \Trash, \Junk, \Archive | 9051 §6.3.8 | Add SPECIAL-USE to capability. Flag mailboxes with role-based attributes in LIST |
| L2 | 275 | Missing REFERRAL in responses despite LOGIN-REFERRALS capability | 9051 §6.2.2 | Remove LOGIN-REFERRALS from capability (no referral support planned) OR implement REFERRAL |
| L3 | 812 | STORE missing .SILENT modifier — client can't suppress untagged FETCH | 9051 §6.4.6 | Accept `.SILENT` suffix, suppress untagged FETCH responses when present |
| L4 | 1420 | AUTHENTICATE missing SASL-IR support — extra round-trip | 9051 §6.2.2 | Add SASL-IR to capability, accept initial response in AUTHENTICATE command |
| L5 | — | Missing per-user connection limit | 9051 §7.1.4 | Add `max_imap_connections_per_user` config (default 10). Track in connection registry |

## SMTP Compliance (RFC 5321, 6409, 6531, 3030)

### Critical (4)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| C1 | 367 | inbound.go | RSET sets state to phaseGreeting; handleMail requires phaseEhlo — forced re-EHLO | 5321 §4.1.1.5 | `reset()` sets state to `phaseEhlo`, not `phaseGreeting` |
| C2 | 275 | inbound.go | Missing SMTPUTF8 advertisement — international email unsupported | 6531 §3 | Add SMTPUTF8 to EHLO. Parse SMTPUTF8= parameter in MAIL FROM. Accept UTF-8 in local parts |
| C3 | 262 | inbound.go | No read/write deadlines — trivial connection-exhaustion DoS | 5321 §4.5.3.2.6 | Set 5-min `SetReadDeadline` before each `ReadLine`. Reset on each command. |
| C4 | 250 | submission.go | AUTH PLAIN ignores authzid — attacker can authenticate as different user | 4616 §2 | Parse authzid from parts[0]. Verify authzid empty OR matches authcid OR authcid authorized as authzid. |

### High (5)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| H1 | 180 | submission.go | STARTTLS not enforced before AUTH on port 587 | 6409 §3.2 | Reject AUTH with `530 5.7.0 Must issue STARTTLS first` if TLS not active |
| H2 | 430 | inbound.go | No RCPT TO count limit | 5321 §4.5.3.1.10 | Max 100 recipients per message. Return `452 4.5.3 Too many recipients` if exceeded. |
| H3 | 620 | outbound.go | Outbound STARTTLS cert verification not configured | 5321 §5.1 | Verify outbound TLS certificates. Add DANE/TLSA lookup. Log verification failures. |
| H4 | 689 | inbound.go | DMARC reject reply is racy under parallel delivery to same mailbox | — | Serialize DMARC reject writing under per-mailbox mutex |
| H5 | 460 | outbound.go | SMTP command injection via null sender `MAIL FROM:<>` not sanitized | 5321 §4.1.1.2 | Validate outbound MAIL FROM path. Sanitize angle brackets in null sender. |

### Medium (5)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| M1 | 375 | inbound.go | MAIL FROM SIZE parameter not parsed | 5321 §4.1.1.2 | Parse `SIZE=` from MAIL FROM params. Enforce against `message_size_limit`. |
| M2 | 375 | inbound.go | Missing BODY=8BITMIME parameter parsing | 1652 §3 | Parse `BODY=` parameter. Handle 8BITMIME content conversion. |
| M3 | — | inbound.go | Missing BDAT/CHUNKING support for large messages | 3030 §2 | Add BDAT command. Chunk large messages to avoid in-memory buffering. |
| M4 | 444 | outbound.go | Outbound doesn't validate EHLO SIZE from remote server | 5321 §4.1.1.2 | Check remote SIZE in EHLO response. Reject oversized messages before attempting delivery. |
| M5 | 210 | submission.go | No recipient count limit for submission | 6409 §3.3 | Max 100 recipients per submission message |

### Low (1)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| L1 | — | inbound.go | Missing DSN extension (NOTIFY/RET/ENVID) | 3461 §4 | Add DSN to EHLO. Parse NOTIFY, RET, ENVID parameters in MAIL FROM and RCPT TO. |

## Implementation Approach

All fixes are mechanical and self-contained. Each follows the same pattern:

1. Read the current code at the cited line
2. Read the relevant RFC section from `docs/ref/rfcs/`  
3. Write the fix (<10 lines for most)
4. Add a test case verifying the fix
5. Commit with RFC reference in message

No shared infrastructure. No cross-cutting changes. Both protocol files can be worked on independently.

---

## JMAP Compliance (RFC 8620, 8621, 8887)

### Medium (3)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| J1 | — | handler.go | Error responses use custom JSON format instead of RFC 8620 §7 `problem+json`. Methods return `{"error":"..."}` but RFC 8620 requires `{"type":"urn:ietf:params:jmap:error:...","status":...,"detail":"..."}` | 8620 §7 | Adopt Spec B RFC 7807 format. Map JMAP error types to URNs: `urn:ietf:params:jmap:error:invalidArguments`, `serverError`, `accountNotFound`, etc. |
| J2 | — | push.go | WebSocket push state tokens don't match RFC 8887 §3.2 format. State change events should include `changed` map with `{accountId: {type: state}}` structure | 8887 §3.2 | Update push notification payload to match RFC 8887 event format |
| J3 | — | handler.go | SearchSnippet response for Email/query doesn't include preview text of matching content as required by RFC 8621 §5.4 | 8621 §5.4 | Generate search snippets from message body text matching the query, include in SearchSnippet response |

## CalDAV Compliance (RFC 4791, 5545)

### Medium (3)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| D1 | — | ical.go | Recurrence rule expansion incomplete — EXDATE (exception dates) not handled. Recurring events with excluded dates show all occurrences | 5545 §3.8.5.1 | Parse EXDATE property, exclude matching dates from recurrence expansion |
| D2 | — | caldav.go | Free/busy query doesn't exclude TRANSP:TRANSPARENT events from busy time calculation | 4791 §7.9 | Filter out TRANSPARENT events when computing free/busy response |
| D3 | — | — | iTIP/iMIP scheduling not implemented — no automatic sending of VEVENT updates when calendar events are created/modified | 5546 §2 | Add iTIP message generation on calendar event changes. Send via SMTP for iMIP transport |

## LDAP Compliance (RFC 4511, 4513)

### Low (1)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| L1 | — | server.go | Only SIMPLE bind supported. SASL DIGEST-MD5 and EXTERNAL (TLS client cert) not implemented | 4513 §3-4 | Add SASL EXTERNAL bind for TLS client certificate auth. DIGEST-MD5 low priority (read-only GAL) |

## DKIM Compliance (RFC 6376, 8301)

### Medium (1)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| K1 | — | pipeline_modify_dkim.go | Header canonicalization doesn't correctly handle `l=` (body length count) tag — the signed body byte count includes trailing CRLF after the last line | 6376 §3.5 | Update `l=` calculation to exclude trailing CRLF from signed byte count |

## DMARC Compliance (RFC 7489)

### Low (1)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| M1 | — | dmarc.go | Aggregate reporting (rua) not implemented — no daily XML reports sent to domain owners | 7489 §7.2 | Generate and send DMARC aggregate reports (daily XML via SMTP to rua addresses). Configurable per domain |

## DANE Compliance (RFC 6698, 7672)

### Medium (1)

| # | Line | File | Finding | RFC | Fix |
|---|------|------|---------|-----|-----|
| N1 | — | dane.go | TLSA record validation doesn't check certificate usage field correctly — all records treated as CA constraint (usage=0) even when usage=2 (service cert constraint) or usage=3 (trust anchor assertion) | 6698 §2.1.1, 7672 §3.1 | Parse TLSA cert usage field. Validate per: 0=CA constraint, 1=service cert constraint, 2=trust anchor, 3=domain-issued cert |

## Updated References

- `docs/ref/rfcs/rfc9051-imap4rev2.txt` — IMAP4rev2 (2021)
- `docs/ref/rfcs/rfc5258-imap-list-extensions.txt` — IMAP LIST Command Extensions (2008)
- `docs/ref/rfcs/rfc9052-cose-structures.txt` — COSE: Structures and Process (2022)
- `docs/ref/rfcs/rfc5321-smtp.txt` — SMTP (2008)
- `docs/ref/rfcs/rfc6409-smtp-submission.txt` — Message Submission
- `docs/ref/rfcs/rfc6531-smtputf8.txt` — SMTPUTF8
- `docs/ref/rfcs/rfc3030-bdat-chunking.txt` — BDAT/CHUNKING
- `docs/ref/rfcs/rfc3461-dsn.txt` — Delivery Status Notifications
- `docs/ref/rfcs/rfc4616-sasl-plain.txt` — SASL PLAIN
- `docs/ref/protocols/imap.md` — Internal IMAP protocol guidelines
- `docs/ref/protocols/smtp.md` — Internal SMTP protocol guidelines
