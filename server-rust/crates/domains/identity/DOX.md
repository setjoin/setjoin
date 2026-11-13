# Identity login, session and token (F21)

Shared domain for the login/session/token slices: login (#331), sessions
and refresh (#332), token/internal/device/guest endpoints and chain listener
(#333). MFA, directory connectors and federation remain separate transfer units.
No dependency on another route-family crate. HTTP is in `bins/auth`, except
mailserver-local self-service (#494), whose adapter lives in the gateway.

`login::verify` alone mints `PasswordProof`: enabled user identity and exact
stored hash are read by the credential address, then checked with the shared
bcrypt/SM3 verifier on a blocking task. Request uid/mailbox fields never enter
that proof. Subsequent reads/writes bind its user, including live admin scope.
Go does not resolve a mailbox for login; neither does Rust.

`rust_identity_login_mint` calls Go's local identity-person fence and inserts
one refresh anchor only under that same enabled user and password hash. This is
the entire Go transaction; it has no audit, state bump or notify. The user-scoped transport transaction must receive an explicit COMMIT
acknowledgement before tokens are returned. A lost result returns a family
operation UUID, never success; `lookup_mint` requires a freshly verified password
and constrains the anchor to that current authority. The family UUID is correlation,
never authority. No blind retry.

Auth-event log, `rust_identity_signin_record`, and sessions insertion remain
separate best-effort statements/transactions exactly as Go's HTTP tail. Known
sign-ins set a transaction-local user GUC; failed attempts derive known identity
from the enabled credential lookup, or store NULL for an unresolved principal.
No hashing upgrade occurs in Go's password-login verifier. Guest/CA
completion retains named owner handoffs; native TOTP, backup and push completion
are described in `bins/auth/DOX.md`.

Checks: auth HTTP oracle; `mailserver/sql/tests/rust_identity_login.pg`.

## F21 slice census (#331)

The inventory guard's `identity_slice` is the checked ownership map, including
both front-door aliases and real auth registrations. `login` (#331) owns login,
password policy, first-party JWKS, health and ready. `sessions-refresh` (#332)
owns refresh/logout/me/session-token and forgot-password. #337 assigns the
existing password-change registration to `connectors-a` below.
`token-issuance` (#333) owns the remaining first-party public/internal/device/
guest/terms endpoints and the chain listener. MFA uses the three slices below; OIDC/SAML,
identity-links and the OIDC discovery wrapper use the three federation slices below (#339–#341).
The census includes mailserver `/auth/me/*` aliases; their original Go provenance
is retained for #333's closing audit rather than silently removed or enabled.

Go resolves guest CA context even with CA policies disabled, before force-
password/MFA token issuance. Its lookup failure is 503. The later mint admission
checks transition first, then guest type (separate 500 projections); a blocked
transition stops before the second lookup. Native tests inject both lookup
failures separately. Guest completion itself stays with #406.

## Token issuance slice (#333)

`issuance` owns frozen authserver discovery/version projections. Ordered struct
fields differ from sorted Go maps; HTML escaping and transport newline remain
byte significant. Public reads use no user identity. Version publication queries
the existing `client_versions` table; its absence/error is Go's `up_to_date`
fallback. The oracle creates and removes a legacy-table fixture for published
versions without changing the canonical schema.

`issuance::ClientProof` seals internal-key or verified OAuth-client authority.
Introspection reads only after this proof and possession of the token string;
the SHA-256 hash is the capability lookup. User-owned identity fields never
select the principal. This is the service-authority exception, not user-token
access. Ordered RFC7662 projection preserves omitted fields and inactive errors.

RFC7009 revocation repeats the authenticated client/null-client constraint and
presented hash in its UPDATE, along with the token row's resolved user. It is
Go's one-statement transaction: no audit, notify or family-wide revocation is
added. User scope and explicit COMMIT use the existing auth command executor.
Unknown returns 503 plus an operation UUID, never success or a retry. Fresh
client-authenticated RFC7662 introspection recovers the token's visible state.

Terms reads and acceptance use SessionProof's verified user, never body/query
identity or a mailbox. Pending reads set transaction-local user scope and join
acceptance by that user and current document version. Acceptance calls existing
`record_tou_acceptance` through the explicit-COMMIT auth command executor;
its BZ102 hints remain 409 and all other DB errors stay generic. The Go reducer
has no audit/state/notify, and repeats upsert the same owned row.

SCIM disable requires internal-only ClientProof (OAuth clients and user JWTs
have no such authority). The service selects an org target by numeric ID first,
otherwise exact scim_external_id; external lookup failures mirror Go's benign
not-found result. One existing `revoke_user_sessions` call owns all session,
OAuth/OP token, pending elevation, possession/ceremony, audit and notify writes.
The caller performs no check-then-mutate ownership authorization outside that
verified service capability. Unknown COMMIT never reports success.

`impersonation` accepts only sealed SessionProof and resolves the live governed
users.impersonate grant, then derives the current actor/target tiers. The
minted 15-minute access credential carries act and never admin/family authority.
The direct Go mount ignores the grant's domain scope; the recorded scoped-grant
foreign-target case pins that security bug under ARCH-029. Audit writes remain
Go's separate best-effort single statements; no extra transaction is invented.

`bootstrap::Proof` mirrors device.RequireUserAuth's explicit access-Bearer
signature seam. It supplies the device owner and cannot be constructed from a
request identity field. Go does not run its full revocation/DPoP funnel at this
bootstrap seam. Registration calls `rust_identity_device_register` with the
transaction-local verified user. The existing secret codec seals the random
32-byte trust root under the startup JWT master; repeats preserve its envelope
and return no plaintext. A checked event INSERT shares the transaction.

WebPush registration is one user-owned INSERT of pgcrypto-encrypted delivery
subscription, with Go's ON CONFLICT DO NOTHING. Native approval-device possession
and factor-generation transactions use #336’s atomic native registration. The
executor supplies deployment crypto GUCs transaction-locally; neither body nor
claims choose the owner or encryption key. Unknown COMMIT never returns 204.

## Native Drive mirror (#333 scope amendment)

`drive_token::Issuer` is the frozen gateway's narrow HS256 signing exception,
using ring HMAC and the dedicated mailserver-drive-native-1 kid. Its input is a
sealed shared proof; uid/email/account, JTI and family are inherited. Output is
access + scp=drive, capped at twelve hours and source expiry. Device-bound
sources are refused. No sub/nbf/admin/act/cnf/device/policy claims or fresh JTI
are added. The mint writes no database row, rotates no key and creates no new
session. Gateway transport is in bins/gateway/src/drive_native.rs.

#333's [closing audit](../../../tests/conformance/identity-token/CLOSING-AUDIT.md)
records the exact unfinished prerequisite shapes and 25 mailserver-local
self-service registrations now assigned to IDLOGIN4 by the orchestrator. #332
sessions and credential writes are included by the integration merge; MFA and
federation retain their named owners.
## Established sessions (#332)

`session::Session` is sealed by shared ES256/HS256/SM2 verification; request
identity fields cannot construct it. `/auth/me` uses its principal for profile,
primary-mailbox aliases and direct send-as delegates, deriving admin/guest state
from PostgreSQL. `/auth/session/token` reveals the presented string without mint
or rotation. Bound access-token admission stays with DPoP owner #405.

Logout calls the existing `revoke_user_sessions` boundary, including audit,
critical-event notify, OAuth/runtime/possession cleanup. Unknown COMMIT returns
503 and `X-Operation-ID`, never success. No cookie is cleared by frozen logout.

Refresh uses `rust_identity_refresh` for the person/row fences, admission,
linear grace-window rotation, integrity containment and reuse/disable revocation.
Its first call produces a proposal. Rust signs only that proposal; the publishing
call derives it again under the same locks and compares the complete principal,
email/admin/guest, parent hash and family before any write. A changed proposal
retries without publishing. The transport waits for explicit COMMIT before
returning credentials. Go's independent best-effort auth-event log remains
independent; refresh adds neither a browser cookie nor a sessions row.

The refresh publishing reducer records only opaque `rust_operation_receipts`
metadata from the infrastructure's transaction-local operation ID. Unknown
returns Go's 401 problem bytes plus `X-Operation-ID`. A fresh signed refresh
proof and the same operation lock can look up the marker; disabled/revoked
authority cannot turn into a false absence. The independent auth event is
written before COMMIT, on another pool lease, as frozen Go does.

## Credential writes (#332)

`password::change` validates Go's policy/common-password/email/history checks,
then builds a credential-version/history proposal outside SQL. The reducer takes
the local identity fence, rechecks both under row lock, updates credential and
history, and calls the existing all-session revocation reducer atomically.
History failures preserve Go's revocation-failed projection; the exception
subtransaction rolls back every credential and revocation effect.

`password::reset` accepts only the sealed password-reset JWT principal. Its
single-use marker is a separate committed statement BEFORE user/policy/fence
checks, exactly as Go. The credential+revocation transaction deliberately leaves
must_change_password and history unchanged. Policy/admin reads are server-side;
request user/mailbox fields never supply authority. The authenticated change
uses the verified JWT email as frozen Go does; reset uses its verified uid.
Both writes store opaque Rust outcome metadata in the publishing transaction.

Token SessionProof is constructed only from #332's verified Session after the
auth transport's shared revocation-cache gate. Both route groups observe the
same startup/30-second snapshot; there is no token-specific durable revocation
read. Terms, impersonation and WebPush retain their own downstream authority.

## MFA slice ownership (#334–#336)

The checked `identity_slice` inventory map divides MFA into `mfa-totp` (#334,
seven auth registrations plus the front-door subtree), `mfa-webauthn` (#335),
and `mfa-push-possession` (#336, including recovery codes and all possession
issuers, including their WebAuthn proof arms). TOTP consumes the existing
possession-grant format; its issuers remain with #336. Detailed TOTP contract:
[TOTP.md](TOTP.md). Qualified shapes have no return-to-Go switch.

## TOTP transaction qualification (#334)

The seven TOTP auth registrations and the gateway subtree default ON after the
frozen-Go HTTP/effect corpus. Authenticated factor work consumes a session-bound
proof; login/bootstrap work consumes a signed pending principal. Request identity
fields never select an owner. Multi-statement transitions remain reducers under
person/users fences through audited Rust code verification. Independent Go tails
stay independent, including the bootstrap tail before COMMIT. No new workers.
Actor-bound commit receipts permit fresh-authority outcome lookup and never
recover credentials or authorize replay. Default-inventory, route-status mutant,
proof/lockout/replay, statement-fault and wire-COMMIT cases cover this slice;
[transaction details and parity caveats](TOTP.md) supplement this contract.

## Push and possession (#336)

`push` derives the startup VAPID public key with unmodified RustCrypto P-256.
The public HTTP discovery ignores caller credentials and malformed unused input,
as frozen Go does. It changes no session, signing key or identity state. HTTP and
recording details: [push oracle](../../../tests/conformance/identity-push/README.md).

Password grant issuance takes the sealed access-session principal. Person and
user fences, durable revocation, cohort and lock checks precede password proof;
the proof callback retains that transaction until budget/reset, target ownership
and replacement of the complete grant tuple. Only a SHA-256 hash persists.
Refusal/success audits stay independent as in Go. Unknown COMMIT releases no grant.

TOTP possession issuance retains the canonical fences across the existing
`totp::validate` and shared cycle reducer. Accepted proof and the full session
grant commit together; wrong/replayed codes commit their failure counter.
Foreign target ownership or any later statement error rolls back the cycle.
No audit, generation increment or notification is invented at issuance.

Recovery-code regeneration consumes the complete session proof under canonical
fences before generating ten random four-byte hex codes and bcrypt 2a/10 hashes.
Hashing runs on a blocking task while the bounded transaction retains its locks.
Only hashes reach PostgreSQL; replacement, the separate generation update and
checked audit commit with proof consumption. Mismatch burns and dead-factor
rollback match Go. Any generation/write failure rolls the proof back; Unknown
returns no plaintext codes. No notification or mailbox state change is added.

Go's recovery consumer passes no target constraint (`TargetBound=false`); the
unused-target oracle preserves that detail. Issuers still forbid supplying a
target for recovery. Nil target means unconstrained at consumption, not an
additional NULL-target predicate invented by Rust.

Backup-code login completion reads the owned bcrypt hashes, verifies only the
bcrypt credential format, and commits one array_remove CAS with both the user
and exact matched hash in its WHERE. Concurrent claims cannot reuse or resurrect
codes. This consumption is independent of the existing fenced MFA mint: later
identity, credential, admission or mint failure leaves the code spent, as in Go.
The signed pending principal supplies ownership; request identity fields do not.

Native push-device registration takes the existing sealed SessionProof from the
shared auth admission. The controller validates provider and uncompressed P-256
key before impersonation/proof work, as Go does. One reducer consumes the full
applicable session grant tuple, encrypts the delivery token with deployment-only
PGP context, inserts the owned device, advances generation and checks audit.
Refusal audit is independent; any later write failure restores the proof.
Unknown COMMIT returns an actor-bound operation ID without reporting204.

Push status reads approval under the signed pending principal, then commits one
owned, live, exact-token harvest CAS independently before MFA minting. A locked
but unapproved challenge never authorizes a session; repeat, expired, foreign-user
and foreign-session polls are uniform false. Push completion retains pending AMR
and appends swk/user, with Go's legacy pwd fallback and unchanged signing key.

Native approval is preauthenticated by its signed device assertion, not by a
browser bearer. The nonce/device capability lookup supplies only a candidate
owner. The reducer repeats that owner join and locks both live rows before Rust
verifies the full Go canonical envelope with ring ECDSA-P256-SHA256. Only the
verified signature allows approval or wrong-code accounting; an already spent
three-strike challenge is burnt without pretending approval. Strict HTTP fields
prevent caller-supplied owner/session values. An uncertain commit returns no204.

Challenge creation retains Go's separate per-user count and owned INSERT, its
three-per-five-minute limit, and a process-local ten-per-IP budget charged before
the DB limit. Audited rand samples the two-digit code and nonce; only the nonce
is returned. The complete pending token is the harvest binding.

`push_delivery` sends only native APNs/FCM/HMS MFA payloads. It owns request-
independent jobs until the auth runtime drops, plus the shared transport's OAuth
cache. Owned/live/key-bearing devices are read first; each encrypted delivery
token is decrypted independently in deployment crypto context. One unreadable
or invalid-key device cannot suppress another. ring supplies every ECDH, HKDF
and AES-GCM primitive in PUSH_ECIES_CONTRACT; each device gets a new ephemeral
key and nonce. The injectable NativeDelivery seam controls external provider I/O
only. It supplies no user, challenge, signing-key or database authority.

Password-login push generation accepts the sealed PasswordProof, never a body
identity. Its token retains the exact credential fence and pwd AMR; the challenge
stores that exact token as its harvest binding. Push-first selection, fresh TOTP
fallback on definite creation failure and push-only unavailability mirror Go.
WebAuthn transfer (#335): [profile and transaction contract](WEBAUTHN.md).

## Public recovery budget (#336)

`recovery::Principal` seals the enabled credential lookup by email; request user
IDs cannot select budget or challenge ownership. Begin prefers TOTP over push,
returns the same delayed decoy for missing/no-MFA/budget-refused principals, and
binds native push challenges to `forgot-password`. The separate worker executor
calls `rust_identity_recovery_budget` under the shared account row lock: begin
and verify share thirty attempts per fixed fifteen-minute window. Refusal does
not extend the window; only its first occurrence writes the independent audit.
The request pool never acquires worker-only accessor privileges. These are
request effects, with no new background worker or GO_WORKERS_OFF entry.

`recovery::ResetProof` is constructed only after committed factor acceptance;
its claims retain the request's credential email and the existing five-minute
password-reset JWT profile. TOTP uses the same owned `totp::cycle_for` transaction
as signed-session verification; only the sealed recovery principal may call
that package-private seam. Factor consumption commits before reset signing,
so signing failure never makes a consumed code reusable.

Push recovery retains the worker account/challenge locks through subtle's
constant-time answer comparison. The five-failure account lock dominates even a
correct answer, counts refused attempts without extending its horizon, and is
separate from the three-wrong-answer challenge burn. Only `forgot-password`
challenges are eligible. Account/challenge writes commit together before a sealed
ResetProof exists; infrastructure failures remain Go's uniform refusal.

## WebAuthn possession (#336)

`possession` owns management assertions and reuses the existing WebAuthn profile.
Begin takes the canonical person/users/durable-revocation fence, C1 cohort,
WebAuthn budget and owned target checks, then replaces the user's same-kind
ceremony. The returned random challenge is stored only as its SHA-256 binding;
operation, target, token scope, JTI and family come from verified admission and
validated operation. Begin consumes no grant, stages no factor, and adds no
audit, generation or notification. Options require user verification; they list
only live UV-capable credentials. Actor-bound receipts withhold output on Unknown.

Finish peeks only the verified user's live scope/JTI ceremony, checks the exact
operation/target, then retains the canonical fence through the shared RP's
assertion framing, challenge-hash, origin/RP, UV, handle, live-key and signature
checks. Malformed assertions preserve ceremony and budget; evaluated failures
commit only the WebAuthn counter. Success resets that budget, consumes the
ceremony and replaces the complete owned grant together. Session scope returns
one random secret; pending scope binds the original token hash and returns only
granted:true. Issuance adds no factor generation, credential update, audit or
notify. Later statement errors restore the ceremony and prior grant.

Owner-approved security fix 2026-11-05: pending MFA mint rechecks durable
revocation under the identity fence. Login assertion completion atomically
claims a hash-only WebAuthn challenge and checks the live owned key/counter;
see WEBAUTHN.md and the immutable, hash-pinned security divergence expectations.
Passkey-first push is native #336 through sealed LoginProof, retaining hwk AMR
and frozen Go's empty challenge session binding and independent counter commit.

All #336 publishing commands use the existing actor-bound commit receipt seam.
The code-owned `totp::Operation` categories also enumerate password/TOTP grants,
backup generation/consumption, native registration, push approval/send/harvest
management begin/finish and recovery budget/push. Fresh Session lookup repeats current enabled,
credential/transition and durable revocation checks and cannot recover secrets.
`push_oracle commit_*` cuts both sides of actual PostgreSQL COMMIT for these
commands and proves atomic effects, no output, and actor-only recovery.

## Directory connector census (#337, #338)

Frozen authserver has no connector CRUD, test, health or password-verification
HTTP registrations. Its only reachable connector call site is the best-effort
tail of `PUT /auth/password` (`authserver/internal/handlers/auth.go:1245`).
The inventory assigns that registration to `connectors-a`; its existing local
password reducer, session admission and recorded #332 transaction cuts remain
the authority. Login/reset retain their original slices: neither calls a
connector. Directory administration and sync belong to F01/F02, not F21.

| Slice | Ticket | Reachable routes and behavior |
| --- | --- | --- |
| `connectors-a` | #337 | `PUT /auth/password`: local credential/history/revocation transaction, including users marked `sync_source=ad` with an AD GUID. |
| `connectors-b` | #338 | No additional HTTP registration. AD factory/LDAPS methods and manager API are dormant library surfaces in authserver. |

`main.go:822–826` registers AD and local factories but creates only local; no
production authserver caller creates AD. Therefore `CachedGet("ad")` is empty
and the post-commit AD tail performs no I/O. Preserve that functional Go defect;
do not instantiate AD from configuration or request fields during the rewrite.
The local connector's own verify/rehash/change methods likewise have no runtime
caller; porting them speculatively would add behavior. #338 owns the remaining
AD library audit and closing census, not a new live endpoint or worker.

The #337 HTTP/effect recordings extend `identity-login` with
`password-connector-*`. Cross-tenant input cannot select a target; ownership
comes from the verified session. SSRF on connector endpoints is inapplicable
because no such endpoints exist; endpoint-looking JSON fields are ignored.
No signing material, sessions, worker ownership or transaction shape changes.
See the [recording contract](../../../tests/conformance/identity-login/README.md#directory-connector-slice-a-337).

Directory connectors closeout (#338): [complete AD/local reachability audit,
criterion applicability and verification](CONNECTORS.md). Slice B adds no live
route, worker, database write or outbound-I/O contract; slice A's sole route is ON.

## Owner-approved security fixes (SECFIX3, #509, 2026-11-05)

Dummy-hash login in the profile's own algorithm (`login::dummy_hash`, #487), uid-keyed password change (#490), domain-scoped impersonation and
`act` on the derived Drive token (#495), android-safetynet attestation is refused outright (#504; its x5c leaf
was never anchored and Google shut the API down; the frozen verifier survives only behind the
`oracle-mutants` feature). Synthetic SafetyNet fixtures: `tests/fixtures/safetynet`. Mutants:
`scripts/test-secfix3-mutants.py`.

## Federation slice map (#339–#341)

The inventory's `federation-op` (#339) owns OP discovery/metadata, keys,
namespace mounts `/authorize`, `/oauth/`, callback, completion, userinfo,
revocation and end-session, including their front-door aliases.
`federation-rp` (#340) owns OIDC login/callback/link and the mixed front-door
`/auth/oidc/` subtree; a more specific completion registration selects the OP.
`federation-saml` (#341) owns SAML metadata/login/ACS/link and the shared
identity-link list/delete at its closing audit. Unported shapes retain these
named owners. `scripts/test-identity-federation-slices.py` verifies the complete
public inventory; the inventory guard checks the source-derived assignments.

OIDC OP profile and key custody (#339): [OIDC.md](OIDC.md).

OIDC relying-party configuration, transport and custody (#340): [RP.md](RP.md).

SAML SP profile, encrypted registry and frozen middleware boundaries (#341): [SAML.md](SAML.md).
Verified SAML ACS, the one non-parity feature here (#546, owner decision on #534): [ACS.md](ACS.md).

## Mailserver self-service (#494)

`self_service` owns the verified-user database boundary for mailserver-only F21
registrations. The HTTP adapter is `bins/gateway/src/identity_self_service.rs`;
its routes must not be mistaken for authserver aliases. Recorded qualification
controls ON state, per registration, in the route inventory and catalog.
[Transaction map and parity details](SELF_SERVICE.md);
[HTTP/effect recording and replay](../../../tests/conformance/identity-self-service/README.md).
