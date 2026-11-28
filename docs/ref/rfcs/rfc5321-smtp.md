# RFC 5321 — SMTP Critical Sections
> Source: https://www.rfc-editor.org/rfc/rfc5321

## §4.1.4 Order of Commands
The sequential order of a session:
```
GREETING → EHLO/HELO → MAIL → (RCPT)* → DATA → (more transactions or QUIT)
```

## §4.4 Trace Information
- Each MTA MUST prepend a `Received:` header at the top of the message
- Final delivery MTA MUST add `Return-Path:` header with envelope MAIL FROM

### Received: Header Format
```
Received: from HELO_NAME (reverse.dns.name [IP.ADDRESS])
    by RECEIVING_HOST with ESMTP id MESSAGE_ID
    for <FINAL_RECIPIENT>; TIMESTAMP;
```

### Return-Path: Header Format
```
Return-Path: <envelope-sender@example.com>
```

## §5.1 MX Fallback
- MUST try MX records in preference order (lowest preference value first)
- MUST fall back to next MX if current one fails or is unreachable
- net.LookupMX() returns records sorted by preference

## §4.5.2 Transparency (dot-stuffing)
- Lines starting with `.` MUST be prefixed with additional `.`
- `\r\n.\r\n` is the end-of-data marker
- dotStuff() MUST preserve CRLF line endings
