## Slice `smime`

- HTTP side: `bins/gateway/src/mail_security_smime.rs` (its own `action()` consulted first by the
  shared table). List needs `requireMailPerm`; import and delete need `mail.security`
  (`MAIL_SECURITY`, audited denial, not org-wide-only so a domain-scoped admin is served);
  `GET /user/cert-status` needs only a verified token. The caller's domain scope comes from the
  live governed grants (0 is deployment-wide); `smime_trust_anchors` is global (no RLS) and the
  scope is in each statement's WHERE.
- List is `{"anchors":[...]}` newest first (`created_at DESC`, id as the tie-break Go leaves
  undefined); a row with NULL validity bounds fails Go's `time.Time` scan and pgx closes the result set, so that row and every older one are dropped (no error); bare
  500 "database error". Import mirrors `ParseMultipartForm(1 MiB)` (query values precede body
  values in `r.Form`, so `?label=` wins; a bad query escape or `;` is "failed to parse form"
  after the body parsed), `FormValue("label")` trimmed (default "imported"), `FormFile("cert")`
  (a part without a filename is a value: "missing cert file"), then `smime.ParseAnchorChain`:
  a port of Go's `pem.Decode` plus `certificate.rs`'s audited Go parsing profile; every block must parse and only whitespace may
  follow, else "not a valid PEM certificate"; v3 extension OIDs must be unique (Go rejects duplicates, including unknown extensions); only the FIRST certificate's expiry is checked
  ("certificate is already expired"). One row per certificate (`rust_mailsec_smime_anchor_import`,
  conflict on (fingerprint, domain) renames the label) plus the `smime_trust_changed`
  notification in one transaction; the answer is `{"fingerprint":<first>,"ok":true}`.
- Delete parses the id like `strconv.ParseInt` (400 "invalid id"), calls
  `rust_mailsec_smime_anchor_delete` (scope in the DELETE's WHERE; the notification only when a row
  went) and answers `{"ok":true}` or 404 "trust anchor not found".
- `GET /user/cert-status` reports the first certificate from the request's own TLS handshake.
  No peer (including plain HTTP) is `{"status":"none"}`; certificate headers are ignored.
  It returns `valid`, `expired`, or `expiring` when the truncated remaining day count is
  at most 30 (including 0). Only expiring adds `expires_in_days`; all peer responses include
  `expires_at` (UTC) and the last subject CN. As in Go, this hint does not check NotBefore
  or look up a user S/MIME row. Go-recorded lifecycle cases live in `mail-security/divfix/`.
- `smime::trust::TrustCache` is Go's per-domain pool cache (`smimeRootsForDomain`: deployment-wide plus
  the domain's rows, only certificates whose DER fingerprint equals the row's) and
  `SmimeTrustListener` (gateway) clears it on `smime_trust_changed`; see the gateway DOX.
- Oracle: `tests/mailsec_oracle/smime.rs` stashes and restores the global table; fixed certificates live
  in `tests/conformance/mail-security/smime-certs/` and their validity dates are masked by name. A
  `scoped-<variant>` label is a domain-scoped persona. Family faults `no-smime-notify` and
  `no-delete-scope` (R3: delete ignoring the caller's scope) run in `mailsec_smime.rs` outside the
  catalog (the family-mutant names are one per family).
