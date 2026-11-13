## SMTP Protocol Requirements
> **RFC 5321** (SMTP), **RFC 6409** (Submission), **RFC 3207** (STARTTLS), **RFC 8314** (TLS)

### MANDATORY — EHLO Extensions
- Port 587 submission MUST advertise `250-STARTTLS` before `250-AUTH` (RFC 6409 §7, RFC 8314 §3)
- Port 25 inbound SHOULD advertise `250-STARTTLS` for opportunistic encryption (RFC 3207 §4)
- Both MUST advertise `250-ENHANCEDSTATUSCODES` (RFC 6409 §7)
- Port 587 MUST require TLS before accepting AUTH credentials (RFC 8314 §3)

### MANDATORY — Delivery Headers
- Final delivery MUST prepend `Received:` trace header with from/by/for/date (RFC 5321 §4.4)
- Final delivery MUST add `Return-Path:` header with envelope sender (RFC 5321 §4.4)
- Submission MUST add `Date:` header if missing (RFC 5322 §3.6.1)
- Submission MUST add `Sender:` header when From differs from authenticated identity (RFC 5322 §3.6.2)

### MANDATORY — Message Integrity
- Line length MUST be validated: max 998 characters + CRLF (RFC 5322 §2.1.1)
- `dotStuff()` MUST preserve CRLF line endings in output (RFC 5321 §4.5.2)
- Outbound MUST fetch actual blob content from MinIO — do NOT send MinIO path strings as body

### MANDATORY — Command Sequence
- MUST enforce SMTP state machine: greeting → EHLO → MAIL → RCPT → DATA (RFC 5321 §4.1.4)
- Out-of-order commands MUST return 503 "Bad sequence of commands"

### MANDATORY — Outbound Delivery
- MUST try all MX records in preference order until delivery succeeds (RFC 5321 §5.1)
- Outbound STARTTLS `tls.Config` MUST set `MinVersion: tls.VersionTLS12` (RFC 8996 §4-5)
- Message-ID MUST use valid FQDN domain, not bare "mailserver" (RFC 5322 §3.6.4)

### DO NOT
- Do NOT accept MAIL before EHLO/HELO
- Do NOT send MinIO blob path strings as SMTP message body
- Do NOT split on `\n` and join with `\n` in dotStuff — use `\r\n`
- Do NOT try only the first MX record — iterate all records

### Verification
```bash
go test ./internal/smtp/... -run TestSMTP -v
```
