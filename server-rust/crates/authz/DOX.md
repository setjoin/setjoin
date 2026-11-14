# Shared request admission

`push::authenticate` (#318) is the separate WS/SSE out-of-band first-party access-token
seam. It returns a sealed `PushIdentity`, checks access type/scope/iat and the
live guest satellite, and does not add HTTP CSRF or mailbox-lifecycle gates to
Go's push handshake. `push::revoked` reads only that identity's durable all/JTI/
family revocations. The transport resolves its primary mailbox separately and
enforces the outer guest program gate. Live socket goldens cover this boundary.
`authenticate_detailed` distinguishes invalid credentials, inactive guests and
unavailable guest lookup for Go's outer problem responses. `command_authorization`
resolves the verified user's primary mailbox, pre-batch state and live admin roles
for the same command executor used by HTTP. Guest presence uses user scope and
requires no primary mailbox. HTTP security shapes still requiring #420 retain
whole-request forwarding before any work.

`authorize` retains the caller's Go feature-toggle requirement. New
`authorize_request` is for inventory-gated routes that have no Go feature
flag, including `/blobs/{sha256}`. Both run the same
configured signature, current guest/session, primary-mailbox and lifecycle checks; both
resolve active governed roles for signed admins. Only the feature-toggle
requirement differs. An unresolved check still requires forwarding the
untouched request to Go, and the sealed context remains the only source of
actor and mailbox IDs.

The staged blob HTTP download tests exercise the unflagged path. Existing
authorization and JMAP tests protect the flagged path. Neither function
supplies permission for a target resource; family queries retain their own
authenticated ownership predicates.

`authorize_attachment` verifies only the dedicated Go HS256 attachment kid,
with HKDF-SHA256 domain separation and current/retiring gateway secrets. It
returns a sealed identity plus signed binding after the same guest, revocation,
primary-mailbox and lifecycle checks. It cannot authorize ordinary routes.
The F16 adapter must repeat origin-session, device, policy-generation and
blob-ownership checks; signature verification alone grants no object access.

`Arc<K: KeySource>` shares the same JWKS cache between JMAP, F12 and F16. The narrow
attachment verifier still accepts only its dedicated kid/scope, including the
retiring attachment secret; that support does not widen normal session auth.

`AuthContext::email()` carries verified-token display metadata for Go-compatible
console audit and denial envelopes (#266/#269). It grants no permission and supplies no database
ownership key. Normal and narrow attachment verification retain the claim only
after signature/type checks. Authority still comes from the sealed user/mailbox
and each family's live grants and target predicates.

## ES256 verification on ring (#388)

`es256::VerifyingKey` verifies ES256 with `ring` (`ECDSA_P256_SHA256_FIXED`);
p256 0.13 was removed. `jwks::parse` validates each JWK point once with
ring's public-point check (on the curve, coordinates below the field prime),
run through an ephemeral ECDH agreement because ring exposes the check no
other way. Invalid keys are skipped as before. `token::signed_claims` rejects
a signature that is not 64 bytes before the key lookup. `ring` rejects `r`
or `s` outside `[1, n-1]` after the lookup, which is also when golang-jwt runs
its keyfunc. High-S signatures verify, as in Go's `crypto/ecdsa`. Tests pin this:
the Go `jwtutil` vectors (`go_recorded_jwtutil_vectors_…`), high-S, malformed
signatures and off-curve JWKS points. Test signers use p256 0.14 (RustCrypto
signs, ring verifies).

Advisory analysis, RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, secret-dependent
branches in subtraction, zero counting, division and Montgomery
multiplication): this crate only verified signatures. ECDSA verification has
no secret input (public key, signature, signing input), so a timing leak
could reveal nothing secret. `UintRef` and `BoxedMontyForm` do not exist in
0.5.x. The use was not exploitable. It was removed anyway, so
`cargo deny check advisories` passes with no ignore. The ES256 verification seam never signs or holds a private EC key; first-party
key custody is described below. Known divergence (pre-existing, kept): go-jose
fails the whole JWKS document on an off-curve key, while Rust skips only that key.

## Shared authorize chain (moved verbatim from server-rust/AGENTS.md, #385)

Shared `authorize` chain: ES256/JWKS or configured legacy keys,
guest belt, denylist and primary-mailbox/
lifecycle checks. `None` requires forwarding the untouched request to Go.
Sealed `AuthContext` takes user from the verified token, mailbox from that
user's primary lookup; `Authorized` exposes the verified token's issue time,
JTI and family for the worker denylist. `roles()` reads active, unexpired
governed role-group IDs per request for signed admins (Go's predicate);
read failure/timeout defers (bound `precheck_timeout()`: 1 s, or
`SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS` 1..=60000; the DB-backed conformance harness
sets 15 s so a starved host cannot forward an oracle request, #421). Signed scope/admin/permissions are claims,
never live grants. Mailbox is the mailstore isolation unit; domains are not
tenants. Per-target domain/OU/set guards remain with each family. JMAP
state keeps its DB round trip. `AuthContext::auth_time()` is the signed `auth_time`
claim (Go's `SessionAuthTime`, #292), `None` when unsigned. `Authorized::device_id()` is the signed
`device.id` fingerprint (Go's `Claims.Device.ID`, #307), empty without a device claim.

## Stored password formats (#342)

`password::verify` dispatches frozen Go's stored bcrypt and `$sm3$` formats.
Bcrypt uses the maintained bcrypt crate; SM3 uses RustCrypto `pbkdf2`/`sm3`
and `subtle` comparison. Empty/invalid salt, digest and zero rounds fail closed.
The helper has no protocol, database or threat-policy authority. LDAP's recorded
socket corpus exercises it with real stored Go hashes. Protocol admission still
requires the shared interceptor from #420.

`standard_upgrade` reproduces the default standard-profile legacy-hash upgrade:
bcrypt cost 10, Go's `$2a$` version, and the 72-byte generation limit. It runs
only after verification; nonstandard profile selection belongs to production
shared protocol admission. The LDAP corpus compares repeated login and committed
upgrade effects. `tests/password_formats.rs` also replays frozen format vectors.

## Shared protocol password check (#355-0)

`basic::verify` ports `pwhash.CheckAppPassword` and `auth.CheckPassword` once
for every protocol. Each caller passes an explicit `Policy`: accepted kinds
(`Accept`), guest app passwords, and TOTP account passwords. IMAP uses
app-then-account; DAV Basic (#355a) will use `AppPassword` only. By owner
ruling (2026-11-14) both refuse a TOTP user's account password, a recorded
divergence from frozen Go; the flag is read by the per-call account SELECT
before the cache. The account lookup, the enabled filter and the fail-closed
`is_guest_account` refusal run on every call. `PasswordCache` keeps Go's 60 s
verification cache, bounded (4096), swept on insert, keyed by a random
per-instance HMAC over user id, email, stored hash and secret; app passwords
are never cached. `tests/basic_password.rs` covers each rule against the
assigned DB.

## First-party key custody and legacy JWTs (#331)

`legacy_jwt::LegacyKeys` verifies configured HS256 kids with ring and the fixed
`authserver-sm2-1` SM2 kid with RustCrypto `sm2`'s prehash API. Frozen Go signs
SM3(JWS input) directly, without ZA; its SM2 signature is ASN.1 DER. SEC1 and
PKCS#8 PEMs are accepted. `Jwks::with_legacy_keys` adds these deployment-owned
keys to the existing signature seam; the gateway wires `JWT_SECRET` and optional
`SM2_PRIVATE_KEY_FILE`. ES256 still resolves exclusively by JWKS kid, and every
existing claim, session, ownership and guest gate remains at admission. Guest
credential verification/admission completion is owned by #406.

`signing_keys::KeySet::load` reads active/retiring `signing_keys` rows, opens the
existing EK01 column envelope using the raw JWT secret, and loads PKCS#8 P-256
keys. Retired keys never verify or appear in JWKS. An empty active set generates
and seals one key with ring, inserts with `ON CONFLICT DO NOTHING`, and re-reads
the winner. No cutover rotation. Public SPKI hashing derives Go's `es256-` kid.
Snapshots are startup-loaded like Go. `sign` emits fixed-width JWS r||s, and the
legacy signing helpers use audited primitives only. No secret implements Debug.

Verification: `tests/legacy_jwt.rs` replays frozen shared vectors and recorded
SM2 PEMs; `tests/signing_keys.rs` uses the assigned disposable DB and the Go
recording in `tests/conformance/identity-login/keys.json`. It can emit Rust tokens
for the Go overlay's `TestVerifyIDLoginRust` (see the corpus README). These are
synthetic fixture keys, never production material.

`clientip` (#331) is the gateway's trusted-proxy resolver moved verbatim into
this foundation. `bins/gateway::forwarded` re-exports it, preserving its API and
rightmost-hop semantics/tests. setjoin-auth uses the same parser, with Go's
TRUSTED_PROXY_IP exact socket-peer trust for auth-event/sign-in IPs; request
headers cannot supply a peer. Its cookie forwarding trust remains Go's separate
AUTH_TRUST_PROXY / AUTH_TRUSTED_PROXY_CIDRS + loopback rule. Deferred requests
replace X-Forwarded-For with the resolved address before the additional Go hop.

## Authserver first-party verification (#333)

`token::validate_first_party` exposes the configured signature, existing claim
shape and registered-claim checks without gateway mailbox/guest/scope admission.
It alone grants no endpoint authority: identity's sealed SessionProof applies
access type and the #405 DPoP boundary after the auth process's shared
positive revocation-cache admission (#332). Auth
loads existing ES256 plus deployment HS256/SM2 keys once, without rotation.

## Shared URL admission (#333)

`go_url` is the existing gateway link-protect net/url authority parser moved
verbatim into the shared foundation; the gateway re-exports its public API.
`ssrf::blocked` likewise holds the existing literal-IP policy, re-exported by
gateway ssrf without changing its URL parser. Authserver WebPush registration
uses the Go parser plus this policy; DNS/dial-time enforcement stays with the
sender. Go's cheap ValidateURL accepts both http and https and treats nonstandard
numeric hosts as hostnames; registration must preserve that behavior.

## Drive-scoped credentials (#333)

`push::authenticate_drive` accepts unscoped or drive-scoped first-party access
proofs with the existing guest belt and no mailbox requirement. It is used only
by the native Drive issuer. Ordinary push and ordinary HTTP proof paths retain
scope rejection. `authorize_drive_request` additionally checks the actual
Drive path before allowing a mirror; admin/sharing paths use ordinary admission.
Concrete Drive handlers supply their actual path. Intercept's member check is
bucket-only and does not grant endpoint authority. `token::presented` is Go's
first-header/first-cookie final selection moved verbatim from auth ingress;
the conservative staging extractor remains available for other adapters.
Arc<KeySource> delegates both ES256 lookup and configured legacy keys; wrapping a
source must not erase HS256/SM2 support. The #333 Drive usage wire case covers the
legacy-key path through the actual concrete adapter, not just a direct verifier.
The Drive-only source proof accepts absent iat as Go does (the mirror receives a
fresh iat); the ordinary push proof still requires it. Runtime revocation uses
Go's distinct middleware map projection, rather than the credential-error body.

## Chain configuration listener (#333)

`auth_chain::Chain` publishes Basic admission generations from `auth_methods`
and `feature.disable_basic_auth`. Missing toggle/read failure disables password
admission; signed-token verification remains installed independently. Success
publishes atomically. A dedicated `DB_DIRECT_DSN` listener subscribes before each
refresh and refreshes after reconnect to repair missed changes. Socket loss
retains the last snapshot as Go does; a failed query removes password authority.
The gateway starts this process-local task by default with request/direct DSNs,
joins it on shutdown, and keeps Go's copy running until Go deletion. No DB writes,
singleton or GO_WORKERS_OFF handover applies. Native Drive consumes the cache:
disabled Basic denies locally; enabled Basic proof stays with #420, Kerberos
with #339. Certificate/password strategy implementations are not duplicated by
this cache. `chain_worker` replays actual frozen Chain admission through durable
notifications, missing config, connection termination/reconnect and read failure.
Password writes (#332): `password::hash` reproduces Go's 72-byte boundary,
bcrypt 2a/cost10 and SMx/hybrid PBKDF2-HMAC-SM3/100000/salt16/key32 envelope.
All RNG, KDF and hash operations use existing audited dependencies. The auth
HTTP credential oracles verify writes through subsequent login, alongside the
shared frozen-Go stored-format vectors; no crypto implementation is handwritten.

Identity address matching (#332): `address::canonical` returns a sealed
CanonicalAddress after trim, ASCII fold and a single parsed RFC5322 address
(display name stripped). It never adds Unicode normalization or IDNA. The
separate `lower`/`equal_fold` helpers use ICU simple mappings for the Go callers
that explicitly use strings.ToLower/EqualFold. They must not replace the ASCII
canonicalizer. Legacy signed-email and Kelvin-sign reset HTTP goldens pin both
contracts. mailparse was already in the workspace; ICU casemap is aligned with
the existing ICU2.4 dependency set and must pass the ordinary licence guard.

#332 preserves net.SplitHostPort's unbracketed IPv6 result for explicit ports;
portless IPv6 keeps brackets. Frozen Go therefore rejects mixed port forms
although their effective origins match. The HTTP csrf-ipv6 recording pins this
residual denial alongside the direct-TLS/forwarded-host login carry-over.

## Runtime gates (#405)

The gateway installs the central [runtime chain](../../bins/gateway/runtime-access.DOX.md)
before concrete authenticated adapters. `gates` no longer defers these toggle shapes.
`runtime::Proof` seals configured-key member access claims; malformed nested device/risk/cnf
claims fail verification. Terminal guest admission is the #406 hook alongside runtime gates; unported protocol
admission retains #420 ownership.

`device::DeviceResolver` uses the request credential and existing device reducers: encrypted
EK01 or best-effort legacy migration, SHA-256 body binding, RustCrypto HMAC verification,
fresh timestamp, deployment-wide nonce consumption, then verified-user attribution. Preserve
Go's inner URI after `/api` stripping and its consumed nonce on a foreign-device refusal.
`dpop` uses ring ES256, RFC7638 thumbprints and a bounded 300 s replay cache. Runtime mirrors
Go's non-`ath` verifier. No cryptographic primitive is handwritten.

`geoip::CountryDb` validates a MaxMind MMDB and optional SHA-256 pin. Default download-cache
files require the pin; operator files may omit it. This reader never downloads or replaces
operator files; bootstrap/threat-interceptor lifecycle remains #420. Invalid/unavailable files
leave country resolution unarmed, as Go's open failure does. Frozen-Go-validated fixture and
WebCrypto DPoP proof live in [the corpus](../../tests/conformance/authzgates/README.md).
Tests: `runtime_gates`, `device_credential`; gateway HTTP corpus covers live gates/effects.

Runtime attachment proofs (#405) reuse the dedicated `token::attachment` verifier and
retain its signed device/JTI/family claims. `Proof::attachment` grants no endpoint
or mailbox authority; the gateway restricts it to attachment GET/HEAD paths. Ordinary
proof verification continues to reject attachment scope.

## Mailbox-less HTTP guest proof (#406)

`authorize_user_request` uses the existing configured first-party verifier and
live guest satellite; ordinary members retain the original mailbox/lifecycle
chain. An active guest returns sealed user authority with no mailbox (the legacy
`mailbox_id()` accessor is zero). Never construct a MailboxId from that absence.
The HTTP front door must apply the unconditional guest program/route belt; proof
verification alone grants no endpoint or target membership. The dedicated JMAP
discovery branch returns Go's minimal guest capabilities before mailbox lookup.

`AuthContext::is_guest` is derived from the live satellite, including stripped or
member-claiming tokens. `database_scope` preserves a member's real mailbox and
returns user-only scope for a mailbox-less proof. Chat, Meet, Drive and RTC use
`authorize_user_request` / `authorize_drive_user_request`; Drive retains its exact
scoped-token path containment. These helpers grant no target membership. The
front-door belt runs before route budgets; an installed shared admission hook
replaces the old JWT-bearing-request deferral rule.

`AuthContext::has_permission` (#406) resolves current active governed grants for
signed admins; non-admin signed permissions retain frozen Go's claim behavior.
Full-spec routes use it instead of deferring every admin or domain-scoped token.
Per-target family policy remains outside this helper.

`authorize_console_request` checks the same identity/session/mailbox gates but
leaves live console permission resolution to its caller, avoiding an unused
role-ID read. Frozen Go `auth/chain.go:482` retains signed permission claims when
ResolveAuthority errors, despite its deny-by-default comment. Full-spec routes
preserve this security defect on error/timeout (`authority-error.json`); a
successful empty live grant set still replaces stale signed permissions.

HTTP CSRF belongs to the gateway before dispatch, after its core budget and
before route budgets. It also runs for injected local adapters without a limiter;
the recorder's empty proxy-only table remains a transparent transport.
Authorization proof builders do not recheck Origin without an HTTP method;
GET/HEAD/OPTIONS retain Go's bypass. The shared net/url parser admits Go's
userinfo URL forms while retaining the recorded mixed-port IPv6 refusal.


Trusted proxy prefixes (#414): mapped IPv6 addresses normalize both address
and width (`::ffff:127.0.0.1/128` → `127.0.0.1/32`); shorter-than-mapping
prefixes remain IPv6. This preserves Go IPNet membership and prevents an IPv4
mask-width underflow. Gateway configuration's recorded HTTP rate-budget cases
exercise mapped CIDRs plus strict per-member database-list parsing.

## Shared policy evaluator (#420)

`policy` is the existing F03 model, simulator, store and runtime Engine promoted
verbatim into the foundation so password protocols and auth runtime can share it
without a family dependency. F03 re-exports its original public namespace.
No new SQL or policy decisions accompany this move. Existing F03 evaluation,
evaluation_vectors and policy_store targets remain the verification lane.

Auth runtime uses `Engine::invalidate_auth` for its Go-specific reload failure
contract (clear stale break-glass exclusions). Gateway `invalidate` retains its
existing last-successful exclusion behavior; the shared metadata/scope caches
and evaluator semantics are otherwise unchanged.


## Mailbox mail-read grants (#419)

`mailbox::can_read` accepts a verified `MailboxAuthContext` and a target mailbox
selector. The primary account passes directly; other accounts require a live
read/send_as/send_on_behalf/full_access grant. manage_calendar alone denies mail.
Its one SELECT carries authenticated user ownership and uses `read_user_scoped`
for FORCE-RLS `mailbox_delegates`, with no pooled role change or cached grant.
F16 narrow attachments and JMAP HTTP account admission share this gate. Their
object reads still constrain rows to the authenticated actor or the freshly
admitted exact delegated mailbox. An unrelated account selector does not remove
Go's own-attachments fallback. No write, audit, state bump or notification occurs.
The F16 HTTP oracle records all grant levels, cross-user/selector denial,
revocation between reads, range and 304, using the app request credential.

## Device-only HTTP authority (#417)

`DeviceResolver::verify_request` mirrors `shared/device.VerifyDeviceRequest` for
public telemetry: the body claim becomes a `VerifiedDevice` only after body hash,
freshness, HMAC and the committed nonce claim succeed. No JWT or X-Device-ID is
required for this seam. Its private constructor prevents ingest from trusting a
raw body ID. It grants only device attribution, never a user/session grant.
`resolve` retains the additional verified-user attribution check for runtime
policy; its existing foreign-device nonce consumption is unchanged.

## Owner-approved security fixes (SECFIX3, #509, 2026-11-05)

`dpop::verify` now takes the access token and requires `ath` (#499; the replay cache keeps entries for the full proof window and refuses new proofs when full rather than evicting; the frozen WebCrypto vector
without it is refused). The policy engine clears `loaded` on invalidation so a failed reload fails
closed, classifies legacy `step_up` as enforcing, and sends a geo-tier read error down the checked
failure path (`store::resolve_geo` returns a Result). The device resolver checks ownership before
the single-use nonce is consumed. `PushIdentity::act()` carries impersonation provenance. Mutants:
`scripts/test-secfix3-mutants.py`.

## Mailserver identity without a mailbox (#494)

`authorize_mailserver_identity_request` retains the same token verification,
security admission, guest exclusion, durable revocations and live admin roles.
Its sole additional case is an existing non-guest user with zero owned mailboxes:
it supplies user-only scope (mailbox id 0) for the exact native migration
registrations. Start retains Go400 without a mailbox; status/history/control,
upload and connection tests require user authority only. A suspended/detached or
non-primary owned mailbox cannot use this case. Other authorization APIs are
unchanged.
The F21 route's no-mailbox oracle and native revoked/no-mailbox denial protect it.
