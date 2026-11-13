# Owner-approved security fixes (2026-11-05)

Frozen Go is being deleted, so its security bugs are not mirrored here. Each fix below
is an **owner-approved security fix 2026-11-05** (ARCH-029 exception). The recorded Go
corpora stay immutable; the cases that locked a bug in are listed in
`oracle/divergences.json` (`go_replay:"skipped"`, reason, issue, secure test, mutant)
and the secure behaviour is asserted in `tests/secfix_inbound.rs` and
`tests/transport.rs`. `session.rs` checks every record names a real recorded case.

Mutants: build with `--features oracle-mutants` and `SETJOIN_SMTP_MUTANT=<id>`;
`scripts/test-smtp-secfix-mutants.py` (REQUIRE_DB=1 and the disposable DSNs) requires
each to be rejected by its secure test, then runs the same tests on the ordinary build.

| Issue | Fix | Mutant id |
|---|---|---|
| #492 | ARC sealing uses the RECEIVING (recipient's hosted) domain's key, never the attacker-controlled From domain; no key for it means no seal | `arc-seal-with-from-domain` |
| #492 | ARC sealing verifies the incoming chain through mail-auth; `cv=pass` only for a verified chain, `cv=fail` for a forged one, no seal on a chain that already failed or cannot be parsed | `arc-trust-presence` |
| #492 | DKIM `x=` expiry is enforced (mail-auth); an expired signature is `fail` | `dkim-ignore-expiry` |
| #492 | DMARC organizational domain uses the public-suffix list (`psl` crate, as mail-auth) | `dmarc-org-last-two-labels` |
| #493 | Outbound DKIM signs only messages the signing domain originated: never a rule-forward (`forward_unwrap_links`, sent as `noreply-forward@<primary>` with the original From), and only when the From header's domain equals the signing domain, so a spoofed inbound From cannot leave with an aligned signature | `dkim-sign-forwards`, `dkim-sign-foreign-from` |
| #493 | Outbound DKIM signs from the active `domain_signing_keys` columns (`active`, `private_key_pem`, selector/algorithm from the row) and prepends a complete `DKIM-Signature:` field (RSA or Ed25519, mail-auth) | `dkim-sign-legacy-columns`, `dkim-sign-bare-header` |
| #493 | DKIM verification, ARC parsing/sealing (instance from the parsed chain, no wrap) are mail-auth's; DMARC alignment accepts any verifying signature | none (verifier replaced; round trip rejects a broken one) |
| #493 | SPF: DNS failures are `temperror`, term/void budget exhaustion and unknown or malformed mechanisms are `permerror`; `ip4` never takes an IPv6 operand/client, bare `ip6` matches, `a/24` and `mx//64` work, `include` of a policy-less domain and `redirect` of one are `permerror`, `redirect=` applies after all mechanisms | `spf-errors-are-non-matches`, `spf-unknown-mechanism-ignored`, `spf-ip4-accepts-ipv6` |
| #493 | DMARC: omitted `adkim`/`aspf` relaxed, `sp=` governs subdomains, several records at a name end discovery (not concatenated), ARC records the real DMARC result | `dmarc-default-strict`, `dmarc-ignore-subdomain-policy`, `dmarc-concatenate-records` |
| #500 | A TLS session is DANE-validated only after a TLSA record matched its chain; a pooled session is reused for a DANE destination only if it matched and the current records still match it | `dane-pool-trusts-label` |
| #500 | DANE-TA/PKIX-TA require the matching CA to be in the verified chain (leaf verifies with it as sole anchor; PKIX-TA also passes PKIX); DANE-EE skips PKIX, name and validity; decided inside the handshake (`outbound/dane.rs`) from one TLSA answer | `dane-ca-without-linkage`, `dane-ee-requires-pkix` |
| #488 | A refused connection is answered beside the accept loop (64 concurrent, 5 s each), so a stalled implicit-TLS client cannot freeze accepts | `smtp-inline-refusal` |
| #488 | DATA with no accepted recipient is `554 5.5.1`; DATA cut before its terminator is `451`; a recipient lookup outage is `451 4.3.0`, never `550` | `smtp-data-without-recipients`, `smtp-accept-short-eof`, `smtp-lookup-failure-permanent` |
| #465 | S/MIME trust pools (mail-security `TrustCache`, gateway `smime_trust.rs`): no cached pool while the LISTEN connection is down, cache cleared when it is back, an invalidation racing a read wins | `SETJOIN_MAILSEC_MUTANT`: `smime-no-reconnect-reload`, `smime-cache-while-deaf` |

Not fixed here (still frozen-Go behaviour, stated so nobody assumes otherwise):
#488 item 4 (recipient commits survive another recipient's DATA failure; the reply is
never 250 but a retry duplicates) and item 6 (ported in #526: an anti-phish-only rejection silently drops mail with SMTP250,
mirroring Go pending its dedicated security fix); DANE-EE
cannot use a self-signed leaf that sets `CA:TRUE` (webpki refuses a CA as end entity).
Functional items of #493/#500 (MTA-STS, TLS-RPT) are untouched.

DNS plumbing: `mail_auth/bridge.rs` fetches every DKIM/ARC key through the injectable
`Dns` trait into a total `ResolverCache`, so mail-auth never uses its own resolver.

Maintenance: the `psl` public-suffix list is compiled into the crate (a caret range
`2.1` in `Cargo.toml`, the exact version locked in `Cargo.lock`). It goes stale as the
list changes, so bump it periodically (`cargo update -p psl`; dependabot proposes it).
