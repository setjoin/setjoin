# IDLOGIN4 closing census (#494) — 2026-11-08

All 25 assigned mailserver registrations are native/ON: zero assigned gaps. The
historical #333 closing audit remains unchanged.

| Method | Registration | State |
| --- | --- | --- |
| GET | `/auth/me/app-passwords` | ON |
| POST | `/auth/me/app-passwords` | ON |
| DELETE | `/auth/me/app-passwords/{id}` | ON |
| POST | `/auth/me/dlp-check` | ON |
| GET | `/auth/me/mailtips` | ON |
| DELETE | `/auth/me/migration` | ON |
| GET | `/auth/me/migration` | ON |
| POST | `/auth/me/migration` | ON |
| POST | `/auth/me/migration/cancel` | ON |
| POST | `/auth/me/migration/pause` | ON |
| POST | `/auth/me/migration/resume` | ON |
| POST | `/auth/me/migration/test-imap` | ON |
| POST | `/auth/me/migration/upload` | ON |
| GET | `/auth/me/org-chart` | ON |
| POST | `/auth/me/read-receipt` | ON |
| GET | `/auth/me/smime/certs` | ON |
| POST | `/auth/me/smime/certs` | ON |
| DELETE | `/auth/me/smime/certs/{id}` | ON |
| POST | `/auth/me/smime/certs/{id}/default` | ON |
| GET | `/auth/me/smime/recipient-certs` | ON |
| POST | `/auth/me/smime/recipient-certs` | ON |
| DELETE | `/auth/me/smime/recipient-certs/{id}` | ON |
| GET | `/auth/me/webhooks` | ON |
| POST | `/auth/me/webhooks` | ON |
| DELETE | `/auth/me/webhooks/{id}` | ON |

Each registration has immutable covered-Go success/cross-tenant/invalid-input
floors, native HTTP/effect replay with zero F21 Go hops and a status mutant.
Mutators include repeated calls and committed row/object companions. Go ignores
unused bodies and identity fields on advisory surfaces; those successful floors
preserve token ownership. M365 self-service start remains refused as Go does.

The five resumed routes reuse the SAME orchestrator as F05. Cancellation at an
ICS object read now settles exactly as Go; F05 cancel/pause and 11 uploaded-phase
regressions pass. Pause202 still lets ICS complete (Go parity). Upload64 MiB,
first/second storage failures and partial persistence are recorded; Go200 sizes
remain mirrored. IMAP uses the existing all-answer SSRF dialer and 30-second bound;
private-policy, private-address, authentication, JSON merge and no-mailbox cases
pass. The mixed public/private DNS test proves refusal before any TCP attempt.

All eight migration registrations preserve Go mailbox-less user behavior through
the existing non-guest/live-revocation proof. Ten such HTTP cases include native
revoked denial. No mailbox identity is invented and other surfaces stay strict.

Final verification passed: all 273 serial `identity_self_service` tests, zero
failures/ignored/skips, REQUIRE_DB=1, Go variables unset, and no recording bridge.
The updated workspace build and all four default guards pass; five connector tests, F05
13 regressions, initial 79 mail-security tests and SMTP five S/MIME tests also pass.

Reproduce: source the assigned IDLOGIN4 env.sh, then
`cargo test --locked --manifest-path server-rust/Cargo.toml -p setjoin-gateway
--test identity_self_service -- --test-threads=1 --nocapture`. The final receipt
is retained in IDLOGIN4-evidence/final-full-native.log. Four required default
guards cover adequacy, family isolation, inventory and context budgets. The full
server-Rust lane and adequacy execution/coverage are deferred to the orchestrator.

The global F21 inventory has seven OFF registrations outside this ticket: four
guest aliases (#406), two device routes (#405/#420), and `/auth/admin/` (#333).
They are named external owners, not gaps in #494; no global zero-gap claim is made.

New Go captures fence startup recovery with a paused sentinel, wait for failure,
then delete it before active seeds. Existing captures are immutable, including
the historical startup-recovery projections. The owned IMAP bridge and all Go
recorders are removed before final native replay. Root AGENTS index is intentionally
unchanged per the merge-hygiene instruction. A prior bounded Graphify update timed
out without an index; direct source/contracts remain authoritative.
