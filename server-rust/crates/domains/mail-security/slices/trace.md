## Slice `trace`

- Admin list and timeline need `requireMailPerm`, the CSV `requireMailExport`; none is org-wide
  only. Everything is a read on the worker credential (`message_trace` and `outbound_queue` are
  global; `delivery_attempts` is forced RLS and Go reads it on the worker pool). Errors are bare
  `WriteError` ("database error"); an invalid UTF-8 filter or path id is Go's PostgreSQL error (500).
  List filters: `ILIKE %v%` for from/to/subject, `=` for event/status (`details->>'status'`),
  `dateFrom/dateTo` only when `time.Parse(RFC3339)` accepts them (`go_rfc3339`); `limit` 1..200 else 50.
  `details` is a `json.RawMessage` (compacted, HTML-escaped; absent when NULL, `null` for JSON null);
  `remoteHost` is omitted only for NULL. The CSV is Go's writer (header unescaped, cells formula
  escaped, `details` as PostgreSQL's jsonb text, seconds-precision UTC), 10,000 rows, no `no-store`.
- Timeline: latest `outbound_queue` row per `message_id` by `queued_at`; with a `message_pk` it adds
  the cross-mailbox recipients (problems first). `recipients` is `omitempty`, so the retention-skew
  case answers only `detailExpired:true`.
- User trace (`GET /messages/{emailId}/trace`, token only): the message must sit in one of the
  user's mailboxes (`mb.user_id`; else 404). A `Sent` system tag means the per-recipient outbound view
  (queue row by `message_pk`+mailbox, attempts by mailbox); otherwise Go fetches the header block from
  the loopback `http://127.0.0.1/jmap/download/<mailbox>/<raw_ref>/<subject>.eml` with the request's
  Authorization and Cookie (1 MiB cap, any failure degrades to the empty inbound trace) and Rust does
  the same (`mail_security_trace.rs`, reqwest, redirects followed). `src/received.rs` ports
  `textproto.ReadMIMEHeader`, `mail.ParseDate` over `time.Parse` (48 layouts, `Local` read as UTC),
  the five RE2 patterns and Go's JSON, checked by `tests/received_vectors.json` (265 inputs recorded
  from Go 1.26.6). Identity names come from `HOSTNAME`/`INTERNAL_DOMAINS`; with `SETJOIN_CONFIG` set
  the user route stays with Go (Rust cannot read the file). A timestamp outside years 0..9999 is a
  marshal error: 200 with an empty body.
- Oracle: `tests/mailsec_oracle/trace.rs` stashes the two global tables; the inbound cases start a
  stand-in on 127.0.0.1:80 (Go's hard-coded base), so run them as root and never in parallel.
