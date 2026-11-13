# ADR: DES-005 — SMTP Outbound Sender Authorization

**Status:** Accepted  
**Date:** 2026-05-15  
**Source:** `auditbyminimax.md` (MS-014)

## Context

The audit identified that mail submitted via SMTP submission (port 587) is not re-verified for SPF/DKIM alignment. The concern was that if a user's mailbox credentials are stolen, an attacker could send forged mail with an arbitrary `From` address.

Two audit documents proposed re-verifying SPF on outbound mail. This ADR documents why we reject that approach and what we do instead.

## Decision

We rely on a three-layer outbound sender authorization strategy:

1. **DKIM Signing** — Every outbound message is cryptographically signed with the sending domain's private key. Receiving servers verify the signature against the domain's DNS-published public key. This proves the mail server is authorized to send on behalf of the domain.

2. **Envelope Sender Authorization** — The SMTP submission handler (`handleMail`) verifies the envelope `MAIL FROM` address belongs to the authenticated user by checking `mailboxes.email` and `aliases.email` against the user's `user_id`. Unauthorized addresses are rejected with `553`.

3. **DMARC Policy** — Domain owners configure `dmarc_policy` (`none`, `quarantine`, `reject`) on their domain. DMARC requires alignment between the `From` header domain and either the DKIM `d=` domain or the SPF envelope domain. A `p=reject` policy instructs receiving servers to reject any misaligned mail.

## Rationale

### Why We Reject SPF Re-Verification on Outbound

SPF is defined in RFC 7208 as a **receiver-side** mechanism. It validates the envelope `MAIL FROM` against the sending server's IP address — an inbound check at SMTP reception time. Attempting to re-verify SPF on outbound submission makes no semantic sense:

- The submitting user is authenticated. The submission server IS the "authorized SPF sender" for its domains.
- SPF checks source IP against DNS records. The submission server's own IP would always pass its own SPF record.
- A stolen credential lets the attacker send FROM any address the victim is authorized to use — SPF adds no protection here because the submission server IP IS authorized to send for the domain.

### Why DKIM Is Sufficient

Unlike SPF, DKIM is a **content-level** signature that survives forwarding, mailing lists, and relays. It proves:

1. The mail originated from a server holding the domain's private key
2. The message content (headers + body) has not been modified in transit

Combined with DMARC alignment, DKIM effectively prevents From-header spoofing by authenticated senders: an attacker who steals credentials can only DKIM-sign mail with the victim's domain, which DMARC receivers would consider aligned (pass). But the envelope sender check (layer 2) already prevents the attacker from sending from unauthorized addresses.

### Why the Envelope Sender Check Is Necessary

DKIM signs whatever domain has a published key. If an attacker uses credentials for `alice@company.com` to send mail with `MAIL FROM: ceo@bank.com`, DKIM would sign with `company.com` (the credential domain), but the message would be misaligned from a DMARC perspective on `bank.com`. The envelope check catches this before the mail enters the queue:

```go
// submission.go:289-303
var allowed bool
pool.QueryRow(ctx,
    `SELECT EXISTS(
        SELECT 1 FROM mailboxes mb
        LEFT JOIN aliases a ON a.mailbox_id = mb.id AND lower(a.email) = lower($1)
        WHERE mb.user_id = $2 AND (lower(mb.email) = lower($1) OR a.id IS NOT NULL)
    )`,
    envelopeFrom, userID,
).Scan(&allowed)
if !allowed {
    return "553 Envelope-from address not authorized for this user"
}
```

## Implementation

| Layer | File | Lines |
|-------|------|-------|
| DKIM signing | `gateway/internal/smtp/outbound.go:549-583` | Loads `domain_signing_keys.private_key`, calls `SignDKIM()`, prepends `DKIM-Signature` header |
| Envelope check | `gateway/internal/smtp/submission.go:289-303` | Verifies `MAIL FROM` against `mailboxes` + `aliases` for authenticated user |
| DMARC policy | `sql/schema/001_domains.sql:12-16` | `dmarc_policy` column with `none`/`quarantine`/`reject` |
| DMARC reports | `gateway/internal/smtp/dmarc_report.go` | Aggregate report generation per RFC 7489 |

## DMARC Policy Hardening Guidance

Domain administrators should follow this hardening path:

1. **Start with `p=none`** — Monitor aggregate reports (`rua`) for 2-4 weeks. Identify all legitimate mail sources.
2. **Move to `p=quarantine`** — After confirming all legitimate sources DKIM-sign, instruct receiving servers to quarantine (spam folder) misaligned mail.
3. **Move to `p=reject`** — After another monitoring period, instruct receiving servers to reject misaligned mail. This fully prevents spoofing.
4. **DKIM key rotation** — Rotate DKIM private keys every 90 days. Publish new selectors in DNS before rotating. Keep old selectors published for 7 days to allow in-flight mail to verify.

## Consequences

| Aspect | Impact |
|--------|--------|
| Positive | All outbound mail is cryptographically signed (if domain has DKIM configured) |
| Positive | Envelope sender impersonation is blocked at SMTP submission |
| Positive | No false positives — legitimate users can use any of their authorized From: addresses |
| Negative | Domains without DKIM keys send unsigned mail (no signing, no error) |
| Negative | DMARC enforcement is opt-in per domain — no system-wide `p=reject` |
| Neutral | SPF is not re-verified on outbound — this is correct per RFC 7208 |

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|-------------|
| Re-verify SPF on outbound | SPF is receiver-side only (RFC 7208). Makes no semantic sense on submission |
| Force DKIM signing for all domains | Would break relay/forwarding scenarios where the MX domain differs from the From domain |
| Validate From: domain against user's domains | User may legitimately send from any domain they have `send_as` permission for (including external) |
