# Claude Opus 5 review — connectivity-aware sync E3

Date: 2026-08-12

Claude Opus 5 at xhigh reviewed E3 read-only. Its initial score was 6.5/10
because the tree changed while it was reading, mode-OFF status codes drifted from
the plan, handler tests were thin, Rust wording overstated clean reopen/interleave
as crash/concurrency, and safe restart discarded retry-budget context. It also
recorded MinIO's HEAD-per-Range cost and non-blocking bearer/account observations.

Accepted and corrected:

- feature/winning-mode OFF now hides mint and download as 404; other generation
  drift remains 409;
- request tests cover feature-OFF, guest/scoped/derived/missing-device rejection,
  path/claim mismatch, mode hiding, and real-DB origin JTI/family/all revocation
  semantics when `DB_DSN` is available;
- safe restart retains deadline/attempt metadata outside the purged checkpoint;
- evidence now says clean-close reopen and sequential interleave, deferring hard
  process/thread/platform isolation to E4;
- MinIO cost, unbound-bearer rationale, and the actual TypeScript filename are
  documented.

Accepted during review: the signer moved to an HKDF-domain-separated,
independently rotatable master with current/previous verification. Mixed pods
accept old/new attachment tokens without widening normal authentication.

Not E3 blockers: `attachmentPrefetch` remains an automatic-work ceiling rather
than a deliberate foreground-download prohibition; signed mailbox/account fields
are defense-in-depth beside live ownership; download shaping and object-store load
evidence remain E6 gates while behavior is OFF. Claude's first score is not reused
as final go/no-go because it explicitly required a frozen correction recheck.
