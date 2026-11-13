---
title: Email protocol security — 2026 update
fetched: 2026-06-10
source_urls:
  - https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/
  - https://www.postfix.org/smtp-smuggling.html
  - https://smtpsmuggling.com/
  - https://seclists.org/oss-sec/2023/q4/348
  - https://pkg.go.dev/net/textproto
  - https://go.dev/src/net/textproto/reader.go
  - https://www.kb.cert.org/vuls/id/555316
  - https://nostarttls.secvuln.info/
  - https://github.com/advisories/GHSA-9j88-vvj5-vhgr
  - https://github.com/jstedfast/MimeKit/security/advisories/GHSA-g7hc-96xr-gvvx
  - https://symfony.com/blog/cve-2026-45067-email-header-smtp-command-injection-via-crlf-in-symfony-component-mime-address
  - https://github.com/netty/netty/security/advisories/GHSA-jq43-27x9-3v86
  - https://hackerone.com/reports/3387499
  - https://www.ietf.org/archive/id/draft-crocker-dkim-replay-00.html
  - https://halon.io/blog/the-dkim-replay-attack-and-how-to-mitigate
  - https://www.valimail.com/resources/guides/email-security-best-practices/mta-sts/
  - https://www.captaindns.com/en/blog/mta-sts-vs-dane
---

# Email protocol security — 2026 update

Current guidance (as of 2026-06-10) on the email-transport threat classes that
matter for a Go mail server, plus a "verify in SetJoin" checklist tied to the
actual code in `mailserver/internal/smtp`.

> Sources are linked inline. Where a claim could not be fetched from an
> authoritative page it is marked. All URLs are in the frontmatter.

---

## 1. SMTP smuggling (SEC Consult 2023 + follow-on CVEs)

**The attack.** SEC Consult disclosed SMTP smuggling on 2023-12-18. A sender and
a receiver disagree on what terminates the DATA block. RFC 5321 mandates exactly
`<CR><LF>.<CR><LF>`. Lenient receivers also accept non-standard variants such as
`<LF>.<LF>` or `<LF>.<CR><LF>`. An attacker who controls an *outbound* relay that
emits a bare-LF sequence can hide a second `.<CRLF>` + fresh `MAIL FROM/DATA`
inside one message; a lenient receiver splits it into two messages, the second
spoofed and inheriting the first's passing SPF/DKIM/DMARC.
- Advisory: SEC Consult — https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/
- Tracker: https://smtpsmuggling.com/

**CVEs.** CVE-2023-51764 (Postfix), CVE-2023-51765 (Sendmail), CVE-2023-51766
(Exim). Cisco Secure Email and Microsoft/GMX were also affected on the inbound
side.

**Recommended fix — strict `CRLF.CRLF`-only termination.** On the *receiving*
(inbound MX) side, treat only `<CR><LF>.<CR><LF>` as end-of-data. Bare `<LF>`
inside DATA must be either rejected or normalized to `<CR><LF>` *before*
end-of-data scanning — never accepted as a line terminator that can form a `.`
end-of-data marker. Postfix shipped `smtpd_forbid_bare_newline` (3.8.5+):
`reject` (strict) or `normalize` (default 3.9+, rewrites bare LF to CRLF, with
`smtpd_forbid_bare_newline_exclusions = $mynetworks`).
- Postfix guidance: https://www.postfix.org/smtp-smuggling.html

**Go-specific hazard.** `net/textproto` `DotReader` documents `\r\n` input
(https://pkg.go.dev/net/textproto), but the *implementation*
(https://go.dev/src/net/textproto/reader.go) is lenient: it accepts a bare `\n`
as a line terminator and a bare `\n.\n` as end-of-data, and `ReadLine` elides
"the final \n or \r\n". A Go MTA built naively on `DotReader` therefore inherits
the smuggling-receiver behavior. The fix is to scan the raw DATA bytes for bare
`\n` / bare `\r` not part of a `\r\n` pair and reject (or normalize) before
trusting the dot framing.

---

## 2. DKIM replay + ARC adoption

**DKIM replay.** A valid DKIM-signed message from a reputable domain is captured
and re-sent en masse to new recipients. The original `d=` signature still
verifies, so receivers see `dkim=pass` and inbox it. The April 2025 Google
OAuth/DKIM-replay spoof made this mainstream.
- Problem statement (IETF draft): https://www.ietf.org/archive/id/draft-crocker-dkim-replay-00.html

**Sender mitigations (2024–2026 consensus).**
- Tight DKIM key rotation (3–6 months for high-risk domains).
- **Over-sign** the headers attackers would mutate: `From`, `To`, `Cc`,
  `Subject`, `Date`, `Reply-To`, `Content-Type` (list each header an extra time
  in `h=` so adding a second copy breaks the signature).
- Set a short signature expiry `x=` to shrink the replay window.
- Anchor on DMARC `From`-domain alignment + outbound rate-limiting / anomaly
  detection on send volume.
- Halon mitigation guide: https://halon.io/blog/the-dkim-replay-attack-and-how-to-mitigate

**Receiver side.** DKIM `pass` alone is not a deliverability/trust signal —
require DMARC alignment, and weigh per-IP reputation. Replayed mail typically
arrives from an IP unrelated to the signing domain's normal egress.

**ARC (RFC 8617) adoption.** ARC preserves auth results across forwarders/lists
by chaining `ARC-Seal` / `ARC-Message-Signature` / `ARC-Authentication-Results`.
It is widely *generated* by Google/Microsoft but **enforcement by receivers is
still inconsistent**; treat a valid ARC chain as evidence the *previous hop*
authenticated the message, not as a substitute for DMARC. Sealing inbound mail
lets *your* downstream (forwarders, your own mailing lists) trust your verdict.

---

## 3. MTA-STS vs DANE — current best practice

| | MTA-STS (RFC 8461) | DANE for SMTP (RFC 7672) |
|---|---|---|
| Trust anchor | Web PKI / public CAs over HTTPS | DNSSEC + TLSA records |
| Prereq | None (just HTTPS policy host) | DNSSEC on sender *and* receiver |
| MITM resistance | Weaker on first contact (no DNSSEC; active attacker can strip before policy is cached) | Stronger (DNSSEC-signed, no first-contact gap) |
| Adoption | Broad — Gmail/M365 enforce | Lower, but growing in EU/gov |

**Best practice 2026: publish both.** Deploy MTA-STS first (broad compatibility,
no DNSSEC dependency), start in `testing` mode, watch TLS-RPT, then move to
`enforce`. Add DANE/TLSA where you control DNSSEC for stronger, CA-independent
guarantees. Senders should honor whichever the recipient publishes.
- Valimail 2026 guide: https://www.valimail.com/resources/guides/email-security-best-practices/mta-sts/
- Comparison: https://www.captaindns.com/en/blog/mta-sts-vs-dane

**TLS-RPT (RFC 8460).** The mandatory companion to both. Publish `_smtp._tls`
TXT with a `rua=` mailto/https endpoint; you receive daily JSON aggregate
reports of TLS-negotiation successes/failures toward your domain — the only way
to see silent STARTTLS-stripping or policy mismatches before they cause loss.

---

## 4. STARTTLS / IMAP / SMTP CVE classes (Go-relevant)

**STARTTLS plaintext command/response injection (the "nostarttls" class).**
Original: CVE-2011-0411 (Postfix). Root cause: the plaintext→TLS switch happens
*below* the application's I/O buffering, so commands the attacker injected (in
the same TCP segment as `STARTTLS`) sit in the read buffer and get executed
*inside* the TLS session. Fix per CERT VU#555316: **purge the application I/O
buffer immediately after the TLS handshake** — never carry pre-TLS buffered
bytes into the encrypted phase.
- CERT VU#555316: https://www.kb.cert.org/vuls/id/555316
- Research: https://nostarttls.secvuln.info/
- Related: CVE-2021-38542 (Apache James IMAP/POP3), CVE-2021-32066 (Net::IMAP strip).

**CVE-2026-41319 — MailKit STARTTLS response injection / SASL downgrade.** Newest
instance (client-side, but same boundary bug). On STARTTLS upgrade MailKit
replaced the stream with `SslStream` but **did not clear the internal read
buffer**; `ReadResponse()` saw `inputIndex != inputEnd` and processed pre-TLS
attacker bytes as a trusted post-TLS response, letting a MITM inject a fake
capability line and force a SASL downgrade (e.g. SCRAM-SHA-256 → PLAIN).
Fixed in 4.16.0 by resetting `inputIndex = inputEnd`.
- https://github.com/advisories/GHSA-9j88-vvj5-vhgr

**CRLF / SMTP command injection via envelope addresses (2024–2026 wave).** Bare
`\r` / `\n` in a `MAIL FROM` / `RCPT TO` address (often via an RFC-5322 quoted
local-part or an RFC-3461 DSN suffix) is emitted verbatim into the protocol
line, splitting one command into two → spoofed mail from a trusted IP that
passes SPF/DKIM.
- CVE-2026-45067 (Symfony Mime, quoted local-part): https://symfony.com/blog/cve-2026-45067-email-header-smtp-command-injection-via-crlf-in-symfony-component-mime-address
- MimeKit GHSA-g7hc-96xr-gvvx (4.15.0): https://github.com/jstedfast/MimeKit/security/advisories/GHSA-g7hc-96xr-gvvx
- Netty SMTP codec: https://github.com/netty/netty/security/advisories/GHSA-jq43-27x9-3v86
- libcurl 8.16.0 DSN suffix: https://hackerone.com/reports/3387499
- Lesson: reject any address/parameter containing `\r` or `\n` before it reaches
  a `Cmd`/`Fprintf` that writes an SMTP line.

**Go `net/textproto` advisories to track (patch Go toolchain).**
- CVE-2025-61724 — quadratic CPU in `ReadResponse` (DoS via pathological input).
- CVE-2026-42507 — unescaped attacker input in `net/textproto` errors → log
  injection into `net/http` / `net/smtp` error strings.
  (Per WebSearch result; confirm exact text against the Go security tracker.)

---

## Verify in SetJoin

Tied to `mailserver/internal/smtp`. File:line references current as of fetch.

### A. Inbound DATA — strict end-of-data / bare-LF (SMTP smuggling)
- [ ] `inbound.go:498` uses `c.tp.DotReader()`. Go's `DotReader` accepts bare
  `\n` and `\n.\n` end-of-data — **this is the smuggling vector.** Add an
  explicit pre-check: scan the raw DATA stream for any `\n` not preceded by `\r`
  (and any lone `\r`) and **reject** (`550 5.6.0`) or normalize to CRLF before
  delivery. Do not rely on `DotReader` framing alone.
- [ ] `validateLineLengths` (`helpers.go:125`) splits on `\n` and tolerates a
  missing `\r` — it is a length check, **not** a bare-LF guard. It does not
  close the smuggling hole; add the bare-LF check above as a separate gate.
- [ ] The `354` prompt (`inbound.go:495`) correctly states `<CRLF>.<CRLF>`; make
  the parser *enforce* what the prompt promises.
- [ ] Add a regression test feeding `<LF>.<LF>` and `<LF>.<CR><LF>` mid-DATA and
  assert the injected second message is rejected, not delivered (cassette in
  `internal/protocoltest` or an `inbound_*_test.go`).

### B. STARTTLS buffer discard (plaintext→TLS boundary)
- [ ] `inbound.go:320-329`: after `tlsConn.Handshake()` the code builds a **new**
  `textproto.NewConn(tlsConn)` and calls `c.reset()`. Creating a fresh
  textproto reader over the raw `tlsConn` **discards** the old plaintext read
  buffer — this is the correct nostarttls/VU#555316 mitigation. **Verify** no
  code path reads from `c.tp` between sending `220` and the handshake, and that
  no bytes from the old `*bufio.Reader` are reused. Keep it this way.
- [ ] Confirm the IMAP bridge (`internal/imap`) does the identical reset on its
  STARTTLS upgrade — the MailKit CVE-2026-41319 and Apache James CVE-2021-38542
  show IMAP/POP3 are equally exposed. (Out of `smtp` scope; check separately.)
- [ ] Add a test: pipeline `STARTTLS\r\nNOOP-INJECTED\r\n` in one write, then
  assert `NOOP-INJECTED` is **not** executed after the handshake.

### C. ARC in the inbound pipeline
- [ ] `inbound.go:647` calls `c.sealARC(fromDomain, dkimResult, dkimDomain)`
  (`sealARC` at `inbound.go:860`) and rebuilds the trace/`Received` headers from
  the **sealed** bytes — confirm `ARC-Seal` is computed over the final message
  including the just-added `Received`/`Authentication-Results`, in correct
  instance order (`i=`), and that an existing inbound ARC chain (`cv=`) is
  evaluated, not blindly overwritten (RFC 8617 §5).
- [ ] Confirm ARC sealing runs **after** SPF/DKIM/DMARC produce results
  (so `ARC-Authentication-Results` reflects this hop) and **before** trace
  header injection feeds delivery.
- [ ] Treat a valid inbound ARC chain as supporting evidence only — DMARC
  alignment still governs the accept/quarantine/reject decision (see §2).

### D. Outbound CRLF / command injection
- [ ] `outbound.go:482` / `:489`: `tp.Cmd("MAIL FROM:<%s>", from)` and
  `tp.Cmd("RCPT TO:<%s>", rcpt)`. **Reject `from`/`rcpt` containing `\r` or `\n`
  before this call** (the Symfony/MimeKit/Netty/libcurl class). Add a guard in
  `extractAddr`/envelope build that returns an error on any control char.
- [ ] Add a unit test asserting an address with an embedded `\r\nDATA` is
  rejected and never written to the wire.

### E. Transport policy (MTA-STS / DANE / TLS-RPT)
- [ ] `mtasts.go`, `dane.go`, `tlsrpt.go`, `tls_policy.go` exist — confirm the
  outbound policy resolver prefers DANE (when DNSSEC-validated TLSA present) and
  falls back to MTA-STS, and that TLS-RPT reports are emitted for both
  enforced-policy failures and STARTTLS-strip detections.
- [ ] Confirm MTA-STS policy fetch validates the policy host cert and caches
  per RFC 8461 (no re-fetch on every message; honor `max_age`).
