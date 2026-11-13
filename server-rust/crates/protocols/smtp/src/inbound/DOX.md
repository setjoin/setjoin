# Enabled inbound security pipeline (#526)

Parent: [SMTP](../../DOX.md). The listener owns SMTP intake; inbound delivery runs
cross-tenant on `WorkerDatabase`, with every recipient/user resolved server-side.
No sender-supplied mailbox/user identifier grants authority. Go runtime is frozen;
only tagged recording adapters change.

`security-*-requests.json` drives the frozen Go listener. Its immutable `*-go.json`
records socket replies, raw stored blobs, normal delivery effects and the additional
`security-observe.sql` columns. Native replay is in `tests/session.rs`, with Go absent.
Feature settings use the listener's live `Flags`; the baseline SMTP1 corpora keep
their disabled-feature fixture. Each new stage has a first failing replay followed
by the minimal implementation. `scripts/test-smtp-inbound-mutants.py` proves a
passing baseline rejects each deliberately missing stage in a test-only build.

Qualified so far: external-domain warning, exact internal display-name flag,
RBL DNS lookups and heuristic spam scoring, deterministic ML detectors (sender mismatch, forged
recipients, mixed scripts, hidden HTML), and recipient-owned safe/blocked sender
adjustments. ML checks add their ordered symbols before per-user score clamps.
Queries for global sender-domain/name policy intentionally use the SMTP worker;
per-user sender decisions constrain the recipient-resolved user. Go's sender lists
only apply through aliases; the safe list clamps to at most one and blocked list
raises to at least ten while preserving prior symbols. The ALL_CAPS rule never
fires because Go lowercases the subject before counting uppercase ASCII.

Activation remains staged until every required adapter is qualified. This document
will track the remaining pipeline, runtime composition and default-ON rehearsal.

RBL recording uses an owned UDP DNS server behind `net.DefaultResolver`; production
Go still calls `net.LookupHost`. Rust uses the injected hickory-backed mail-auth
resolver. All three providers preserve their score/symbol order; RBL alone does
not score without `feature.spam_scoring`, matching Go.

FTRL uses [setjoin-spam](../../../../spam/DOX.md), the exact shared model used by
F06's trainer. Each connection owns its batch and releases on cancellation; the
socket oracle compares live/released store gauges and FTRL's junk placement.

Anti-phish uses the configured internal/protected domains, enabled user-name cache
(default five minutes), pg_trgm fuzzy threshold, Go's confusables and bounded edit
distance. Detectors fail open on lookup errors. Strict mode upgrades warnings;
policy rejection prevents every recipient write. Security fix #544 (owner-approved
2026-11-05): a lone anti-phish rejection replies 550 (frozen Go acknowledged it
with 250 and silently dropped the mail); the recorded cases are pinned
divergences. Go's LF warning
fallback inserts a new header block before the original message and adds no body
banner; raw bytes and unchanged delivery body are separately checked. The contact-
graph detector receives no resolved mailbox ID from Go and is therefore a no-op.

ClamAV owns a serialized cached TCP/Unix connection with Go's 30-second dial,
exchange deadline and cache lifetime. Commands are `nPING` / 4096-byte big-endian
`nINSTREAM` frames. Health failures do not disable scans; scan/protocol failures
condemn as `ClamAV:unavailable`. Daemon-closed cached connections preserve Go's
first-message unavailable/reconnect behavior. The corpus compares every command
and scan digest through an independent fake daemon.

CAPE uses reqwest with native TLS roots, multipart file `attachment.bin`, the
configured token and a deadline covering submission plus three-second polls.
Startup health checks do not disable it. Only an empty ClamAV verdict, a risky raw
Content-Type and the recipient domain's enabled sandbox admit analysis. Suspicious
and malicious verdicts condemn; domain action `reject` returns Go's generic 451.
Analyzer errors follow configured fail-open/closed behavior. Parity: Go ignores a
view response's HTTP status when its JSON is valid. Independent HTTP/multipart
peers check method, path, credentials, filename and uploaded message digest.

Condemnation is applied by worker-only `rust_smtp_inbound_security` in the same
transaction as delivery; a quarantine fault rolls every row/state/notify back.
The wrapper's ACL survives role reprovisioning. [SQL contract](../../../../../../mailserver/sql/DOX.md#rust-smtp-inbound-security-transaction-526).

Group moderation consults the live recipient group's settings before expansion:
closed groups reject external senders, moderated groups hold the verbatim reducer
payload for approval, and condemned holds defer. Group deliveries return no single
message ID; every copy inserted by that transaction is quarantined before commit.
The socket corpus observes holds, approval status, all member copies, notifications
and raw blobs. SQL fault tests prove failed member quarantine rolls back all copies
and both tenant states. No iMIP or received callback runs for a held/group-null result.

S/MIME verifies the pristine detached multipart/signed content before body mutations.
The unmodified OpenSSL crate verifies CMS signature/digest and X.509 chains; the
shared certificates foundation supplies Go's strict parse profile and PEM/cache
semantics. Trust is the exact bundled Mozilla roots plus fingerprint-authorized
deployment/recipient-domain anchors. EKU, validity, From binding and the admin
blocklist grade valid/untrusted/invalid; extraction failure leaves NULL metadata.
Only valid mail skips body mutations; rejection policy still applies. #544: a
multipart/signed message with anything outside the signed pair (text or a part after
the closing boundary, an extra part, a second signature) is not fully signed:
`extract` yields no verdict, so it is unsigned mail (no badge, warnings, rewriting).
The boundary comes from the one Content-Type exactly as the body walkers read it (shared
`extract_header`: first, any case, unfolded); a second Content-Type or non-blank
preamble also yields no verdict (parser-differential bypass). Harvest is
valid-only, best effort, outside the delivery transaction and derives the receiving
owner through Go's alias-only lookup. It files under the validated From, while
badge metadata retains the first SAN. Go wires no CRL fetch/store for this path.
The 34 socket cases check raw bytes, all badge fields, exact harvested certificates,
the bundle fingerprint fence, repeated upserts and best-effort DB failures. The
mutation corpus uses a recorded warning to prove signed-body exemption. Mutants
cover missing verification/harvest, integrity/trust/From/revocation bypasses and
mutation of a valid signed body. Gateway composition additionally proves actual
SMTP badges follow the shared listener's cache invalidation.
Parity: Go's CMS BER conversion and OpenSSL both consume a valid prefix, accepting
trailing signature octets; indefinite BER verifies and truncated CMS is invalid.

Link protection signs with the already-derived key (`LinkConfig.key` = Go `tokenKeyN`; the gateway reads
`SMTP_LINK_PROTECT_KEY`, never `JWT_SECRET`; `derive_link_key` is the test/golden helper). It walks strict MIME parts, decodes target text/plain and text/html
bodies, rewrites external HTTP(S)/protocol-relative destinations and re-encodes
the original transfer encoding. Calendar and binary leaves remain untouched;
ambiguous MIME/undecodable target bodies condemn as `MIME:unparseable`, below a
ClamAV/sandbox detection's audit priority. HTML uses the existing audited parser
and Go-compatible serializer; URL attributes, srcset and CSS are rewritten while
visible HTML text remains original. Internal exemption uses the shared Go URL
authority parser. Ring derives the versioned HMAC key and signs Go-ordered,
HTML-escaped JSON claims; previous keys never mint. Mailbox binding retains Go's
alias-only lookup. Only a positive rewrite rebuilds the trace/body view; cached
header fields stay pristine, and FTRL/blob hashing follow the resulting bytes.
The recording helper recovers its oracle clock from real minted tokens in decoded
blobs, never by changing Go time or normalizing token signatures. Production uses
the system clock and receives only trusted deployment key configuration.
Quoted-printable admission mirrors Go's physical-line, soft-break and raw-control
rules; an admission/normalization step shields raw high bytes before the existing
library decoder, which otherwise silently drops them. The library still owns
hex decoding and re-encoding. Forty-two recorded link sessions cover encoding
and framing edges, signatures/warnings, AV precedence and exact token bytes.
Parity: Go's stored body fields retain transfer encoding; only the rewrite/clock
observer decodes it. Expected stored rows are never normalized to hide that bug.


iMIP runs best-effort after a committed non-NULL message ID, even for a condemned
copy; held/group NULL results skip it. REQUEST (#544) accepts only a body attendee
who owns the mailbox this delivery's envelope recipient resolves to (alias, mailbox
address or catch-all, as `deliver` resolves it; the gate takes `p_recipient`), then charges the per-user budget before primary-mailbox/dedup/import checks,
and imports Go's limited tentative object (no organizer/attendees). Worker-only
`rust_smtp_imip_*` reducers own resolution, rate charging, dedup and occurrences;
apply re-proves the primary mailbox/user relation and occurrence CANCEL locks the
organizer-bound copy. REPLY and series CANCEL call the original calendar reducers.
Full-address SPF/aligned DKIM roles and S/MIME's tri-state anchor scope gate mutations;
DNS and tenant trust are OR evidence per affected owner domain. Existing #493's
mail-auth strict verification rejects positive DKIM l= signatures entirely; partial
body signatures can never authenticate iMIP. This port preserves that secure verifier.
The 8-bit signed-calendar regression verifies original bytes before replacement-rune
text parsing; the cryptographic scope is never a lossy Unicode reconstruction.
Signed calendars require valid CMS even with badge verification OFF, use the first
resolvable recipient-domain pool and only the verified content; no unsigned fallback.
#544: iMIP passes the revocation option, so a revoked or blocklisted signer is
untrusted and iMIP stops (frozen Go omitted it). Divergences: `oracle/divergences.json`
`go_replay: "pinned"` entries (reviewed, owner-approved reason, sha256 of the frozen-Go
corpus file, expectation under `oracle/security/`); `SECFIX12_WRITE_SECURITY=1`
regenerates them for diff review, `oracle/derive-secfix12.py` derives the secure-only
cases, `scripts/test-secfix12-mutants.py` restores each bug.
Forty-six recorded socket sessions cover requests, roles, recurrence, S/MIME and
full-body DKIM. Notifications are real LISTEN; generated IDs map to UID+mailbox+
occurrence. The frozen general observer orders journal by mailbox/state, whose
independent datatype counters tie: iMIP compares all journal rows as a multiset,
retaining every value; other observations and raw bytes are exact.

iMIP `extract` finds offsets with `to_ascii_lowercase` (byte-identical offsets, as Go slices bytes); Unicode lowercasing
(Kelvin sign, U+0130) shifted them and panicked after COMMIT, so never slice the original by offsets from `to_lowercase`.
