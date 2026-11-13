## Slice `dlp`

- HTTP side: `bins/gateway/src/mail_security_dlp.rs` (five admin routes through the shared adapter) and
  `bins/gateway/src/link_protect.rs` (+ `link_protect_pages.rs`, Go's two interstitials verbatim) for the
  unauthenticated `GET /link-protect`, its own `Intercept` mounted at the root. Gates: patterns GET and
  anti-phish GET `requireMailPerm`, patterns PUT `mail.security`, anti-phish PUT `security.write`, audit list
  `audit.read` (org-wide only: a domain-scoped admin gets the audited 403). `dlp_policies`, `system_config`
  and `link_protect_audit` carry no tenant column.
- Patterns: GET lists `is_pattern` rows by `priority,id` (a scoped admin sees global rows and its domain's;
  severity maps `block/quarantine/notify_admin/warn` to `critical/high/medium/low`). PUT refuses a scoped admin
  (403) before decoding, decodes `[]{id,name,regex,severity,enabled}` with Go's folding and null rules (1 MiB),
  and calls `rust_mailsec_dlp_patterns_replace` (delete then insert in one transaction, priority = position;
  Go's two 500 details are kept by re-raising `dlp_clear_failed` / `dlp_save_failed`). A foreign-key violation
  from `dlp_violations` is `failed to clear patterns`. Success is a bare 200 with no body or content type.
- Anti-phish: GET reads `antiphish_%` rows (value trimmed of `"`, `true`/`True` are true, a list that does not
  decode is `[]`, a stored `null` list renders `null`); PUT is one upsert statement (Go's six upserts are one
  batch transaction) and a missing list marshals as `null`.
- Audit list: `since` is Go's `time.Parse(RFC3339)` (a zero time adds no filter), `limit` 1..100 else 50, items
  render `created_at` in the process's local zone; a NULL `message_id` or `client_ip` makes Go's scan fail and
  end the list at that row, so Rust ends it there too; the document keys are `count` then `items` (a map).
- Click: the token is `base64(payload).base64(HMAC)` under a key derived per version
  (`JWT_SECRET`, `JWT_LINK_PROTECT_TOKEN_VERSION`, `JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET`, all from the
  environment; with `SETJOIN_CONFIG` set and `JWT_SECRET` or `SAFEBROWSING_API_KEY` unset the route forwards to
  Go). Scanners: Safe Browsing when `SAFEBROWSING_API_KEY` is set, then the Spamhaus DBL over DNS
  (`<host>.dbl.spamhaus.org`, NXDOMAIN or an empty answer is clean, `127.0.1.*` is listed, any other failure is a
  scanner error; the host is Go's `url.Parse` authority, never the userinfo). The reducer
  `link_protect_check_and_audit` decides and audits in one receipted transaction scoped to the signed mailbox;
  a failure fails closed to the warn page. Strict mode is `feature_toggles` (default ON when the row is absent);
  with only the DBL it can never change a verdict, because the base verdict is unknown only after a scanner error.
- Oracle: `tests/mailsec_oracle/dlp.rs` (admin routes, global tables moved aside and restored) and the stand-alone
  `tests/mailsec_linkprotect.rs` (fake DBL on 127.0.0.66:53, run as root; Go's container mounts a `resolv.conf`
  naming it; the Go request pool is the owner pool, as for `POST /report`).

Owner review (#468, 2026-11-03): the Safe Browsing scanner is accepted as implemented.
Frozen Go calls Google directly and cannot be recorded without a live API key; the
request and verdict mapping remain tested against a local HTTP peer. The fake-DBL
Go recordings remain authoritative for the rest of the link-protection path.
