# Shared MIME byte parser (#348)

`setjoin-mime` is the existing F05 port of frozen Go `internal/mimeutil`, moved
verbatim into the foundation when SMTP needed it. It owns Go-compatible byte
strings, header unfolding/decoding, address parsing, body/charset extraction,
MIME traversal and date parsing. It performs no database, network or crypto I/O.
`ImportFields` stores the parsed email address in `from_addr` and display name in
`from_name` (fixed in `#221`, retiring Go's historical swap); SMTP uses the individual
functions directly.

F05 re-exports this crate as `setjoin_mailboxes::mimeutil`, preserving existing
callers. New shared consumers depend on `setjoin-mime` directly. The independent
Go-recorded corpus remains at [F05 vectors](../domains/mailboxes/tests/vectors/); verify with
`cargo test --locked -p setjoin-mailboxes --test mimeutil_vectors`.
SMTP's socket/storage oracle also compares the parsed fields and raw hash.

`rewrite_parts` (#350) applies optional leaf-body replacements only after the
same strict traversal succeeds. Headers, preamble, epilogue, nested boundaries
and each framing newline remain byte-identical; errors return no partially
rewritten result. It adds no I/O or cryptography. The highest-seam qualification
is the gateway's recorded outbound SMTP preparation corpus, including nested
multipart and untouched calendar/attachment leaves; existing F05 MIME vectors
remain regression coverage for the shared reader.
