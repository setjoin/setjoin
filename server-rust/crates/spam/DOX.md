# Shared spam scoring (#526)

`model` is the existing F06 Rust keyed FTRL implementation moved verbatim from
`domains/mail-security/src/spam_model*`; F06 re-exports its original public path.
Its immutable Go blob/tokenizer tests stay in F06, and the trainer uses that
same implementation. This foundation crate permits SMTP to consume it without
a protocol-to-family dependency.

`Store` reads `user_spam_model` on the SMTP worker credential with the recipient-
resolved user predicate. No row or empty placeholder is cold; disabled, corrupt,
wrong-user and invalid numeric models skip scoring. A `Batch` belongs to one
connection, serializes recipient fanout, holds models for 50 scored deliveries,
and releases on drop, including listener cancellation. Per-call mode does not
update batch gauges. Go's process gauge defects remain: cache hits are never
reported to the store, and dropping several models decrements the model gauge
only once (bytes release completely). `process_stats` is shared by the gateway
composition root between its two inbound listeners and the HTTP spam dashboard;
tests can supply independent stats with `Store::with_stats`.

SMTP's frozen-Go socket/model/batch corpus is
`protocols/smtp/oracle/security-ftrl-go.json`; replay through `tests/session.rs`.
Models are seeded from the compressed Go-generated sealed bytes in that corpus,
not retrained by Rust. The F06 model tests still byte-compare all 15 recorded
training/tokenizer cases through the compatibility re-export.
