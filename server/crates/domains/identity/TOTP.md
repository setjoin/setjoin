# TOTP (#334)

HTTP lives in `bins/auth/src/totp.rs`; the domain takes only signature-verified
Session principals, never request user/mailbox identifiers. Authentication uses
authserver's session cache and DPoP admission; pending challenges use their own
signed token type. Unported threat/device/CA shapes retain their named owners.

`rust_identity_totp_remove` reproduces frozen Go's single serialized removal
transaction: person fence, owned session-bound unexpired step-up, users lock,
factor/recovery wipe, one generation advance, checked success audit. Refusals
preserve the step-up; best-effort refusal audit remains a separate statement.
There is no state bump or notification in Go. Lost COMMIT never returns success.

The front-door HTTP oracle is `setjoin-auth --test mfa_oracle`, with the assigned
disposable DB and REQUIRE_DB=1, one test thread. Record only new cases with the
covered frozen-Go auth process via GOFREE_RECORD_UPSTREAM; native replay leaves
both Go upstreams unset and checks zero Go proxy hops. Existing goldens are
immutable. The fixture owns the shared identity advisory lock for its lifetime.

The shared TOTP cycle holds `FOR NO KEY UPDATE` across Rust's audited HMAC and
constant-time three-window comparison. One reducer owns replay claim, counter
increment or reset, and lock timestamp. The fifth bad code is still `invalid`
in Go; the following request is `locked`. Missing enabled secret is bookkeeping
failure with no counter. The Go replay rule is elapsed30s since acceptance, not
an accepted time-step index.

Removal begin preserves Go's independent transactions: initial state/password
reads, committed shared cycle, recovery bcrypt fallback (without consuming a
code), prior step-up DELETE, new hashed step-up INSERT, best-effort audit. A
later failure does not roll back earlier committed parts. Only SHA-256 of the
random32-byte token persists, bound to the verified user's session for300s.

Session setup uses the canonical person/users fences, durable token revocation
recheck and the full possession tuple (user/JTI/operation/scope/family/generation).
First bind stages a15-minute encrypted pending secret and binds the grant in one
transaction; resume returns that same row and secret. A dead bound target returns
Go's409; a live tuple mismatch burns the owned proof before the403. First-bind
success and refusal audits retain their separate best-effort Go transactions.

Session confirmation validates the staged code under the retained person/users
fences, then consumes the full grant tuple, checks the proving factor, promotes
and audits in one reducer transaction. Wrong codes leave the proof/target intact;
dead target mismatches burn and audit together before refusal.

Bootstrap setup/confirmation use the signed normalized-identity and local
credential-version fence, durable revocation, current mandatory-enrollment state,
and the mfa_pending grant tuple. Password hash digests use pgcrypto as an opaque
credential-version comparison (as login compares its proved stored hash); TOTP
MAC and code comparisons remain ring/subtle. Bootstrap confirmation owns grant
consumption, activation, generation, audit and refresh anchor in one transaction.
The independent auth/sign-in/session tail runs before COMMIT, as frozen Go does;
its results survive a lost commit while credentials never escape on Unknown.

Ordinary TOTP verify preserves Go's separate committed cycle before completion:
wrong/replayed codes count; a missing enabled secret is bookkeeping failure; an
enabled completion principal is reloaded, live scope/admission derived, then the
signed refresh anchor is stored under its original identity/credential fence.
The legacy AMR fallback, sorted distinct factors, exact expiries and session
cookie match Go. Owner-approved security fix 2026-11-05: completion rechecks
durable pending-token revocation inside the fenced mint transaction; refusal
returns no credentials or login tail while leaving the accepted cycle spent. The complete HTTP/effect oracle
checks signatures and persisted token links before masking random values.

Password login now handles the TOTP challenge and mandatory-enrollment branches.
The pending token carries pwd AMR, a random JTI,300s expiry and the digest of the
exact password hash already verified by PasswordProof. C2/C3 bootstrap issuance
commits its token-bound pending grant under the same current credential/person
fence before returning403. C1 UV-capable accounts receive no password grant and
use the native TOTP possession issuer; WebAuthn possession uses #336’s native management ceremony.
Push selection/fallback uses #336's native challenge helper.

The verify edge oracle pins Go's legacy secret normalization (outer whitespace,
case and base32 padding), elapsed-time replay rule, revoked pending challenge
behavior, malformed claims and counter/reset/anchor statement failures. Threat-
wrapped public completion endpoints retain the interceptor's 1MiB413 JSON reply.
Trailing JSON remains accepted; both recorded/replayed request observations use
the same TOTP-code placeholder even when extra invalid bytes follow the object.

Every TOTP user transaction attaches an actor-bound foundation commit receipt.
`lookup_operation` accepts a newly verified Session, the returned opaque ID and
a code-owned operation category; it rechecks enabled identity, credential fence,
durable revocation and transition admission under the same operation lock.
Another user's valid credential cannot recover the result. The receipt reveals
only whether the transaction committed; recovery never returns bearer tokens or
repeats an uncertain write. `mfa_faults` cuts the actual PG wire before/after
removal COMMIT and observes fresh `/auth/me`, one generation/audit, proof
consumption, lookup and foreign/disabled authority. Go-independent audit tails
retain their earlier semantics and do not acquire these receipts.

The threat-wrapped setup/confirmation/login-completion registrations bound the
whole body before session, CSRF or possession checks. Frozen Go rejects an
oversized ignored setup body before it can stage a factor; four oversized wire
recordings pin413 and no effects. The body is retained exactly for any later
named-owner forward. Legacy base32 format vectors also pin Go's padding and
unused-bit rules, implemented with the maintained codec rather than new crypto.

Public password recovery (#336) reuses the package-private `cycle_for` seam
through its sealed credential lookup principal, rather than constructing a fake
Session. The public signed-session cycle remains unchanged; both consumers
serialize on the same user row, replay timestamp and failure/lock state.

The hash-pinned `identity-mfa/divergences.json` records this owner-approved
security fix 2026-11-05. `mutant_pending_revocation_gap_restores_go_bug` removes
only the reducer guard, restores the positive Go capture, and proves the secure
HTTP/effect expectation rejects the vulnerability. Original captures are immutable.
