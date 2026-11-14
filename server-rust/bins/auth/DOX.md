# Standalone setjoin-auth (#331)

Thin HTTP process over the F21 `setjoin-identity` crate and shared authz key
custody. `Config::from_env` reads SETJOIN_CONFIG YAML then environment overrides.
DB_DSN is the request pool; no worker/direct credentials are substituted.
DB_WORKER_DSN (YAML db.worker_dsn), defaulting to DB_DSN, is used only for
cross-tenant revocation reconciliation. Startup
checks the embedded schema version and loads the existing encrypted signing key
snapshot. JWT_SIGNING_ALG selects ES256 or Go's HS256/SM2 profile behavior. No key
rotation. JWT issuer/audience and access/refresh lifetimes remain compatible.

Native routes: POST /auth/login, GET /auth/password-policy (HEAD returns 405),
GET/HEAD /.well-known/jwks.json, /.well-known/setjoin, /api/v1/version, /health and /ready; GET/HEAD /auth/me and
/auth/session/token, POST /auth/logout and /auth/refresh, PUT /auth/password,
and POST /auth/forgot-password/reset. TLS_CERT/TLS_KEY support
HTTP/1.1 and HTTP/2; plaintext is loopback-only. LISTEN_ADDR then explicit YAML
listen.addr then AUTHSERVER_URL then 127.0.0.1:8443 determine the listener.
SIGINT/SIGTERM drain owned connections with Go's 30-second bound.

The front door selects `rust-auth` for qualified entries using
GATEWAY_RUST_AUTH_UPSTREAM. AUTHSERVER_GO_UPSTREAM is only for shapes not yet
ported: stateful threat interception and device proof/trust (#420), conditional
access/DPoP controls (#405), guest identity
completion (#406), or federation (#339–#341).
Forwarding happens before any effect and preserves the whole request/body. An
unset upstream fails closed. Completed shapes have no return-to-Go flag.

Go login accepts unknown fields, folded field names, null scalar values and one
JSON value followed by trailing bytes; typed mismatches fail. Credential proof
alone supplies identity. Force-password-change returns a five-minute restricted
JWT and no session. Ordinary login commits the refresh family first, then Go's
independent best-effort logs/session row, cookie and response. Password-policy
and JWKS endpoints are public; their cross-tenant corpus cases prove that caller
identity does not alter public data. Problem bodies use the shared gateway
encoder; CSRF uses its distinct frozen middleware map projection.

Tests: `cargo test -p setjoin-auth --test http_recorded --test startup`, strict
DB env and one test thread. Key format/interchangeability tests live in authz.
The F21 frozen-Go HTTP corpus and recorder are in `tests/conformance/identity-login`.
Direct-auth login recordings/replays use only auth-listener inventory rows (#516),
so the gateway's outer CSRF layer cannot preempt authserver's route middleware.
The gateway-only change-password alias remains covered by bundled-inventory cases.
Client IP attribution uses Go's separate TRUSTED_PROXY_IP exact peer setting,
through the shared authz clientip parser. Cookie Secure trust is unchanged;
these two Go trust settings must not be conflated.
The five X-Device proof headers select #420 before buffering/decoding. Ordinary
login still resolves guest CA context before force-password/MFA, mirroring Go's
fail-closed 503 even when conditional-access policies are disabled.
The DB test common fixture installs the recorded synthetic Go key under the
family advisory lock before listeners load, including fresh-schema runs. It
never changes runtime key custody or the immutable recorded public key.
Duplicate JSON map fields merge as in Go (null resets); an empty later
DPoP map cannot erase an earlier key before the #405 handoff.

#333 token-slice wire recordings start in `tests/conformance/identity-token`;
`token_oracle` replays the real front door with Go upstreams unset and checks
zero Go-hop counters. Public discovery preserves the request Host, map key
order, HTML escaping and no-store headers. Its planted status mutant is
served on the HTTP wire before comparison.

`POST /auth/introspect` (#333) is native for JSON/internal-key and RFC7662
form calls. INTERNAL_API_KEY reads `internal.api_key` from YAML with env override.
OAuth clients use Basic before client_secret_post, enabled-client lookup and
bcrypt with Go's dummy comparison for unknown clients. JSON accepts only the
internal gate. The endpoint reads the presented token's hash without validating
it as a JWT (including app passwords), and Go deliberately permits one
authenticated OAuth client to introspect another client's presented token.
Errors/unknown/revoked/expired/disabled tokens collapse to inactive.

`POST /auth/revoke` (#333) is native RFC7009. Internal callers can revoke only
NULL-client tokens; OAuth clients can revoke their own or NULL-client tokens.
Unknown/mismatched/already revoked tokens are empty 200 no-ops. JSON carries
no form token here and is not the introspection legacy contract. COMMIT wire
loss returns 503 with x-operation-id; `token_faults` proves before/after outcomes.

`GET/HEAD /terms/pending` and `POST /terms/accept` (#333) are native. They use
Go authserver's signature/access/revocation guard, without gateway mailbox or
guest gates; non-empty cnf.jkt still forwards whole to #405 before effects.
Mutations retain CSRF and authenticated source IP. Pending JSON preserves struct
order and no added cache policy; HEAD preserves representation length. Terms
acceptance ignores request identity, maps stale/missing/disabled documents to
Go's reducer hint, and never reports success after an unknown COMMIT.

`POST /auth/scim/disable` (#333) is internal-key-only. It never accepts an
ordinary user JWT or OAuth client as service authority. User ID precedence,
external lookup misses, malformed values and reducer errors mirror Go. The
complete store/audit/notify oracle also injects an OAuth write failure and
suppresses app_notify as a live planted mutant, restoring fixtures before
reporting any comparison error.

`POST /admin/reload` and SIGHUP share atomic publication of the live internal
API key. All four gates observe that generation. Signing keys, pools, threat
settings and SSO options remain startup-bound; the HTTP report names them as
restart-required. `reload_process` starts the actual binary, rotates the key
with SIGHUP and proves existing signing material is unchanged. The wire corpus
rotates an operator YAML file and checks old/new authority on all four gates.
Authserver session extraction takes Go's first Bearer header or first valid
access_token cookie, including quoted cookies. The conservative gateway
extractor remains separate. Cookie precedence is recorded through pending terms.

Token-oracle operator-key restoration failures remain errors after server,
environment and fixture teardown (#516). The wire status-mutant regression
`reload_restoration_failure_does_not_poison_next_case` forces restoration failure
then runs a normal reload replay, guarding against duplicate-client cascades.

`POST /auth/admin/users/{id}/impersonate` (#333) preserves full session + CSRF,
live permission and strict descending tier checks. Cookie Secure uses login's
transport/proxy trust. The oracle validates signature, random JTI, uid/sub/act,
15-minute lifetime and absent admin before masking randomness, then byte-checks
the response/cookie and complete owned audit rows. Setup/cleanup uses an owner
connection; append-only audit and last-super-admin triggers are disabled only
inside cleanup transactions for exact fixture rows. Runtime guards stay active.

`POST /device/register` (#333) is the authenticated device bootstrap. It keeps
Go's explicit Bearer guard (no cookie), CSRF, exact one-JSON-value 1MiB limit,
required fields and fingerprint byte bounds. An invoker reducer commits the
owned device upsert and event together; unknown COMMIT returns 503/operation ID.
Only first creation returns the secret. The oracle opens complete row envelopes
and checks them against the returned secret before masking random ciphertext.

WebPush-only `POST /auth/device/register` (#333) keeps outer 64KiB buffering,
full session/CSRF, provider/subscription bounds and shared Go URL admission.
Stateful threat, rate and device proof shapes remain #420; native push providers
use #336’s possession-gated transaction below. DB_ENCRYPTION_KEY and AUDIT_HMAC_KEY are startup-bound
pool configuration and use the executor's protected transaction-local context.
Configured DB encryption keys keep Go's profile-specific strength floor before
serving; `startup::weak_database_encryption_key_is_rejected_before_listening`
exercises the actual binary. Empty keys remain legal and WebPush fails closed.

Reload (#333) retains the prior key when validation fails and preserves Go's
specific JWT expiry errors. SCIM/reload mounts are fixed at boot: an empty boot
internal key omits them permanently, even after SIGHUP rearms other gates.
`reload_process` checks frozen-Go before/after wire observations in addition to
real SIGHUP rearming and unchanged signing keys.

CSRF expected-scheme uses a sanitized single http/https forwarded token (trimmed,
case-insensitive), then direct connection TLS. A malformed or >255-byte forwarded
host falls back to Host, matching frozen shared middleware. The `csrf` HTTP test
replays the real Go direct-TLS/malformed-host login decoder recordings in
`identity-login/security/csrf.json`; its recorder refuses overwrites.

Established-session admission mirrors Go's positive-match revocation cache: a
startup worker-credential snapshot, then independent 30-second reconciliation.
A failed reconcile retains the prior snapshot. The owned task is aborted when
the server drops. It has no shared effects and runs in both processes during
transfer; it is not switched off through GO_WORKERS_OFF. Go does not subscribe
this auth-process mirror to NOTIFY, so immediate repeated logout remains 204
until reconciliation; the recorded repeat pins that behavior.

Forgot-password reset mounting snapshots feature.forgot_password at startup, as
in Go. It uses bounded JSON, CSRF and the named threat interception boundary.
Go's JSON error/message responses retain no-store; password change uses Go's
problem projections and unbounded authenticated decoder. Reset-token signature,
type and email checks precede its single-use consumption; that consumption is
committed even when later policy validation fails.

Established-session credentials use Go's nonempty, case-sensitive Bearer prefix
first, then the first valid access_token cookie (an empty first cookie blocks
later duplicates). The maintained cookie parser supplies field/quote parsing;
the adapter applies Go's cookie-value byte policy and bare-name extension.
Recorded quoted/whitespace, empty-duplicate, unmatched-quote and bearer-priority
cases protect this seam. Session-token recovery never mints a replacement.

The #332 bundled inventory enables established me/token/logout/refresh, local
password change and reset; the obsolete gateway change-password alias returns
Go's 404. Recovery begin/verify and the MFA routes below are native #336.
Actual bundled-inventory
replays pin default dispatch without a completed-shape rollback switch.
Password/reset wire-COMMIT cases compare real Go error bytes plus credential,
revocation, audit and reset-proof consumption; native unknown outcomes expose
only X-Operation-ID. Reset proof consumption precedes its separate write txn.
Successful credential-login CSRF supplements live in security/csrf-success.json;
the csrf target records them only with GOFREE_RECORD_CSRF_SUCCESS=1 and the two
explicit loopback Go HTTP/TLS recorders. Ordinary runs verify both issued token
signatures and their fixture principal/family without Go.

Merge compatibility (#333/#332): string-only login/session decodes retain
`ingress::fields`; token route structs with integer fields use `typed_fields`.
User-command execution retains both opaque operation receipts and deployment
crypto context before the reducer; neither is request-controlled. Token-route
cookie selection uses the established-session parser from #332, including the
first empty/bare cookie and whitespace handling.

Token-route admission (#333/#332) shares the established-session signature proof
and process-local revocation snapshot. It does not query revocations per request.
`token_recorded::token_and_session_routes_share_the_process_revocation_snapshot`
proves both routes retain admission before reconciliation and reject after a
fresh startup snapshot, matching Go's shared bearerAuth registration. The sealed
identity SessionProof retains access-type, positive-user and DPoP checks.

TOTP MFA slice (#334): [domain contract](../../crates/domains/identity/TOTP.md).
The native removal adapter uses the same verified Session and process revocation
snapshot as existing session routes, then CSRF and the unconditional impersonation
refusal. Its bounded JSON decoder retains Go field folding/null/trailing semantics.


All seven TOTP registrations (#334) are native: GET/HEAD setup; POST confirm,
verify, enroll/setup, enroll/confirm, remove/begin and remove. Pending endpoints
validate the signed mfa_pending type directly; authenticated management shares
the existing revocation snapshot, CSRF and impersonation rejection. Go's verify
endpoint has its distinct admission, preserved by the oracle. Completion bodies
retain Go duplicate-map merging and null reset for dpop_jwk. Only unported
threat/device, CA/DPoP and guest shapes forward to their
named owners before effects. The MFA corpus checks the real front door with
Go unset, raw JSON/cookie bytes, audited factor state and signed anchor links.

Password-login MFA branches are native for push preference, TOTP fallback and
mandatory enrollment. A bootstrap token and its C2/C3 password grant publish
atomically under the original password proof. C1 UV holders use the native TOTP
possession issuer; WebAuthn possession uses the native #336 management ceremony. Completed push shapes have
no forwarding switch; the obsolete push handoff test has been removed.

TOTP namespace dispatch (#334) retains Go mux404/405 bytes and Allow headers.
The seven registrations and subtree are ON, alongside the native #335
WebAuthn and #336 push, possession and recovery registrations.
Factor-management fault recordings cover proof tuple, binding/staging/audit
rollback and bootstrap credential/identity fences. Operation recovery uses the
actor-bound foundation receipt with fresh authority, never a blind retry.

Push discovery (#336): GET /auth/push/vapid-key exposes the public half of
startup VAPID_PRIVATE_KEY (`vapid.private_key` in YAML); absence returns Go's
404. Key derivation stays in the identity domain. The frozen-Go front-door
corpus is [identity-push](../../tests/conformance/identity-push/README.md).

POST /auth/mfa/reauth (#336) keeps outer threat/body bounds, verified session,
CSRF and strict JSON media type before the password possession proof. The domain
holds fences through password verification and the grant reducer; HTTP publishes
only after acknowledged COMMIT. A body user_id never selects the owner.

POST /auth/mfa/possession/totp (#336) uses the same session/CSRF/media-type
admission and the existing TOTP cycle, atomically with its owned grant. C2/C3
accounts are directed to password reauthentication; replay counts as a failure.

POST /auth/backup-codes/generate (#336) shares threat/body bounds, session, CSRF
and impersonation refusal. X-MFA-Reauth takes priority over the exact JSON body
member. The complete proof gates generation; plaintext codes publish only after
COMMIT. A missing/mismatched proof keeps Go's typed reauth remediation and audit.

POST /auth/backup-codes/verify (#336) accepts a signed mfa_pending proof and code,
then uses the shared TOTP completion/mint transport in `src/totp.rs`. A claimed
code stays spent if later token minting fails. Access/refresh signatures, store
hashes, family links, claims and cookie bytes are checked by the push oracle.

Native apns/fcm/hms shapes of POST /auth/device/register (#336) now reuse its
existing64KiB bound, shared session proof, CSRF and typed decoder. Public-key
validation precedes impersonation/proof refusal. X-MFA-Reauth wins over the body.
The native reducer commits device, proof, generation and audit before204; WebPush
keeps its existing ungated delivery-subscription transaction.

POST /auth/push/verify (#336) preserves C10: after bounded JSON and signed
mfa_pending validation it always returns410, including a correct in-band answer.
It never reads/consumes a challenge or issues credentials. Approval is exclusively
out of band. The oracle compares the entire challenge row before/after refusal.

`/auth/push/status` uses the pending signature and exact stored token binding,
not a client-supplied identity. Harvest commits before the shared MFA mint tail;
a later fence/mint failure leaves it consumed. Its false poll replies preserve
Go's no-store header; token success retains the existing session cookie bytes.

`/auth/mfa/approve` retains Go's closed assertion body and threat ingress. Device
signature authority covers the locked database user/session; there is no browser
answer bypass. Stale/bad signatures do not increment counters; correctly signed
wrong codes do, burning at three. Only approved_at authorizes the separate poll.

Push send returns only a nonce/TTL bound to the exact verified pending token.
The local IP budget runs in both runtimes during migration; it has no shared
worker effect. Only committed creation queues native delivery. Native providers
are built from the same shared environment only when VAPID enables Go's provider;
invalid public VAPID derivation does not disable native MFA. Auth runtime drop
aborts owned delivery jobs. `with_native_push` is the embedding boundary for a
native provider transport, without transferring authentication authority.

Password login (#336) tries push before TOTP when the provider is configured,
using a pending credential tied to the exact proved password version. Ordinary
creation failure or rate refusal falls back to a fresh TOTP pending token; a
push-only account without an available method gets Go's500. Unknown COMMIT
returns an operation ID and never retries through the fallback. No sign-in or
session tail runs until the second factor completes.
WebAuthn (#335) lives in `src/webauthn.rs` and the Identity domain's
[profile contract](../../crates/domains/identity/WEBAUTHN.md). Listing and naming
share established-session signature/revocation admission and naming retains
CSRF. The single naming UPDATE repeats verified user ownership; missing,
foreign and revoked targets remain Go's empty200 no-op. Unknown COMMIT returns
an operation ID and never success. Detailed HTTP/effect oracle: `webauthn_oracle`.

The seven WebAuthn registrations and gateway subtree are ON by default after
recorded HTTP/effect replay. Public login reads a MAC-authenticated Go cookie
principal and verifies the owned stored credential before counter/token writes;
registration and revocation consume the complete possession tuple under the
person/users fence. Unknown commits return an actor-bound opaque operation ID.
Owner-approved security fix 2026-11-05 rejects counter regression and repeated
login challenges through the atomic live-key claim reducer (including zero counters).
Immutable Go captures and reviewed security expectations retain the divergence trail.
Pending threat admission (#420), guest completion (#406) and
DPoP/CA completion (#405) shapes retain their named upstream owner before writes.

Public recovery begin (#336) snapshots the same startup feature mount as reset.
Its process-local enumeration budget is separate from push-send's budget;
account attempts use only DB_WORKER_DSN (DB_DSN fallback), never SET ROLE or the
request pool. Generic decoys and real TOTP replies share the 100ms floor. The
HTTP/effect corpus checks budget, factor, token and audit isolation.

Recovery verification (#336) shares begin's enumeration/account budget. Its TOTP
branch reuses the committed replay/lockout cycle and issues the existing
five-minute password_reset profile from a sealed successful factor proof. It
creates no login session or refresh anchor. Refused proofs use Go's uniform
JSON/delay; bookkeeping errors issue no token. Unknown COMMIT exposes an opaque
operation ID and no reset credential.

WebAuthn possession (#336) uses `src/possession.rs`: threat ingress, CSRF, strict
JSON media type, then bearer/cookie/pending admission. Invalid earlier session
modes fall through to the next; valid access admission wins over the JSON pending
member. Pending scope authorizes only bootstrap.totp.enroll. The management
begin response has no ceremony cookie; its server row is authority. These paths
reuse the integrated #335 relying party rather than forwarding ordinary proofs.

Management finish retains Go's distinct check order: strict whole-body decode,
dual-token admission, live ceremony, operation/target equality, impersonation,
then fenced proof verification. Parse errors are 400 without a counter; evaluated
proof failures are 403 with durable accounting; a locked budget is 429 before
proof evaluation. Session grants retain the existing reauth_token/300s wire
profile; pending grants return granted:true without a new secret. COMMIT loss
returns an operation ID and no grant.

Push and backup namespaces (#336) are native, including Go's method405/Allow,
unknown404, and HEAD representation lengths. VAPID HEAD shares GET's public
representation without a body; absent configuration uses Go's typed not-found
problem. Public foreign/invalid bearer input does not select any principal or
change these mux/discovery replies. Both gateway namespace mounts are ON.

WebAuthn first-factor push now completes natively through the sealed assertion
proof, preserving hwk AMR, push-first selection, TOTP fallback and push-only
failure. The frozen Go challenge has an empty session binding; the oracle pins
this functional bug. Unknown creation publishes no pending token or nonce.

#336's commit qualification covers twelve publishing commands, including public
recovery's separate worker pool. Actual before/after PG COMMIT cuts withhold all
secrets and success; fresh actor-bound lookup observes the receipt while foreign,
disabled and revoked authority is refused. Recovery's earlier fixed-window budget
remains independently committed. The corpus also pins pending bootstrap grants,
access-over-body precedence, cookie/CSRF/media checks, malformed/evaluated UV
failures, lock horizon, target revocation and statement rollback.
#420 factors the existing process-local denylist snapshot into `setjoin-threat`;
the auth wrapper retains its boot seed/30-second timer and shutdown ownership.
The shared task oracle verifies positive matches, foreign principals, failed
refresh retention and authoritative removal with frozen Go.

## Auth background process ownership (#420)

Main initializes the shared threat/GeoIP/configuration runtime after schema
verification and binding the original auth address. This excludes authserverd
from that listener during the #331 whole-binary process swap. Shared effects
require `RUST_WORKERS_ON=auth-runtime` plus `GO_WORKERS_OFF=auth-runtime`, the
explicit retirement attestation for the entire Go auth process (Go has no
per-task auth launcher switch). Missing attestation refuses startup. Library
`AuthServer::load` never starts feed or retention, so HTTP fixture servers do not
make network calls or compete for global tasks.

The task runs feed at boot/30 minutes and independent rotated/OIDC GC at one
minute. Process-local feature/CA listeners and 30-second session cache run on
both sides until Go is deleted. Request, worker and direct credentials remain
separate; GeoIP opens only the auth process's explicitly configured MMDB.
SIGHUP is armed before DB startup, retains the previous key on failed validation,
and reports rearmed versus restart-required settings. Signing material stays
unchanged. Every owned task is aborted on process shutdown/error.

Operational stop: remove auth-runtime from RUST_WORKERS_ON and restart the native
process to suspend shared feed/retention. Go remains retired. Recovery reinstalls
the previous complete release; there is no route-level return-to-Go path.
Verification: shared `setjoin-threat --test tasks`, auth `startup`, `config`,
`reload_process` and established-session/token targets, all with strict DB DSNs.

Directory connector slice A (#337) removes the premature AD-source password
handoff. Frozen authserver never warms its registered AD connector, so local
password changes for AD-marked users commit normally and perform no directory
I/O. `PUT /auth/password` is ON as `connectors-a`; admission, CSRF, the existing
password reducer and Unknown-COMMIT handling are shared with #332. Slice B
#338 has no additional reachable HTTP registration; see the Identity
[census](../../crates/domains/identity/DOX.md#directory-connector-census-337-338).
Completed shapes have no return-to-Go switch (owner decision 2026-11-04).

## Owner-approved security fixes (SECFIX3, #509, 2026-11-05)

Fixed in Rust, not in frozen Go: unknown-email login hashes a dummy bcrypt (#487); the refresh
rotation grace refuses a revoked/expired parent and the password change keys on the signed uid
(#490, SQL in `rust_identity_refresh`/`rust_identity_password_write`); the revocation list refuses
every token until its first successful load, JSON bodies cap at 1 MiB (#491); impersonation is
limited to the granting assignments' domains, `/device/register` refuses a revoked token and
requires a DPoP proof (ath, htm, htu) for a cnf-bound one (#495). Tests: `tests/secfix3.rs`;
reviewed expectations under `tests/conformance/identity-{login,token,webauthn}/security` (the
`SECFIX3_WRITE_SECURITY=1` switch writes an expectation for review, never in CI). Mutants:
`scripts/test-secfix3-mutants.py` (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`).

OIDC Provider startup and profile (#339): [domain contract](../../crates/domains/identity/OIDC.md).
`OIDC_PROVIDER_ENABLED`, `HOSTNAME`, `OIDC_PROVIDER_PRIVATE_KEY_FILE` and
`OIDC_PROVIDER_PUBLIC_KEY_FILE` have matching YAML settings under `oidc_provider`
(except `hostname`). Existing OP keys are loaded before serving; malformed keys
refuse startup. The OP's optional mount is separate from route transfer.

Native OP handoff (#339) owns authorization, authenticated completion and callback
transport; the detailed [profile](../../crates/domains/identity/OIDC.md) defines
its sealed capabilities, one-shot digest binding and commit publication. These
qualified mounts have no completed-shape return-to-Go switch. Shared HTTP threat
and DPoP shapes retain their existing named #420/#405 handoffs before effects.

OIDC RP startup (#340): `OIDC_ENABLED` (YAML `oidc.enabled`, default false)
is independent of the OP switch. Login, callback, authenticated link and the
mixed gateway namespace are ON in the bundled inventory. GET/HEAD gateway link
aliases retain Go's 405 because auth registers POST only. Completed RP shapes
have no return-to-Go switch. Login-time CA/device and bound-session prerequisites
retain their existing #405/#420 owners before token exchange or any write.
The [RP contract](../../crates/domains/identity/RP.md) owns the guarded HTTPS,
sealed assertion, profile/JIT/mapping, normalized fence and link semantics.

RP callback account/JIT/group settlement and `oidc_rp` task are native (#340).
The [RP contract](../../crates/domains/identity/RP.md) owns the sealed assertion,
normalized fence and explicit link transaction details. Library embeddings start
the listener explicitly; main requires both named transfer attestations. The
listener uses DB_DIRECT_DSN, while normalized reducers use DB_WORKER_DSN.

RP secret migration failure warns and retains the healthy sealed-provider subset;
it does not stop the process, matching frozen authserver main.go:693. Provider
loading still refuses plaintext/corrupt envelopes. The actual disabled-RP process
availability test lives beside the immutable reseal transaction oracle in `rp_secrets`.

SAML startup and login bindings (#341): `SAML_ENABLED` / `saml.enabled` (false),
`SAML_CERT_FILE` / `saml.cert_file` and `SAML_KEY_FILE` / `saml.key_file` select
existing SP material. Invalid material warns and disables the registry, as Go;
invalid registrations fail closed independently. `DB_ENCRYPTION_KEY` is bound
as a pgcrypto parameter for this deployment-configuration read; an unscoped
read cannot rely on a transaction-local GUC. The external IdP transport passed
to `load_with_rp_http` also supplies SAML metadata HTTPS I/O. Signed Redirect and
POST login use the [SAML profile](../../crates/domains/identity/SAML.md) and
[immutable HTTP corpus](../../tests/conformance/identity-saml/README.md).

`GET/HEAD /auth/identity-links` and `POST /auth/saml/{idp}/link` (#341) are
native. List ownership comes from the verified session; query/body user IDs are
ignored. Linking retains full-session + CSRF admission and fresh AAL2, then
commits the exact live-session elevation and opaque receipt before returning
the encrypted flow and signed request. List no-store, link cookie order,
90-second tracking and 600-second elevation/flow expiry match frozen Go. The
HTTP corpus validates ciphertext contents against the committed row before
normalizing randomness. `rust_identity_saml.pg` covers the SQL transaction.

Shared unlink and SAML worker (#341): `DELETE /auth/identity-links/{id}` uses
fresh token-owned authority and the canonical reducer/receipt transaction;
COMMIT ambiguity publishes no success. `start_saml_listener` and process startup
require both named transfer attestations; the retained task uses DB_DIRECT_DSN.
Detailed contracts and oracle evidence are in the identity SAML profile above.

Verified ACS (#546, owner-approved feature 2026-11-08, decision on #534):
`POST /auth/saml/{idp}/acs` verifies a SAMLResponse against the registration's pinned
certificate and answers `303` (login, with the `access_token` cookie) or the link result;
any refusal is a generic 401/400/413/503 problem, an audit row `saml.acs.<class>`, and a
cleared single-use tracking cookie. A link-purpose answer is held and completed by the same-site
`GET /auth/saml/{idp}/link/complete` (never a login). Contract, checks, replay cache and limits:
[ACS.md](../../crates/domains/identity/ACS.md). Tests: `saml_acs` (HTTP/database),
`saml_interop` (real IdP container), mutants `scripts/test-samlacs-mutants.py`.

OIDC RP follow-ups (#547, owner-approved security fixes 2026-11-05): the per-login address
update is gone (`rust_identity_rp_settle` never rewrites `users.email`); with
`feature.identity_model_v2` on, a JIT user is created with its link through `identity_auth_jit`
even in shadow/legacy read mode (no orphan; only a serving source keeps the mint fence); its soft
address collision is a 409 `explicit account linking is required`, in the OIDC callback and the
SAML ACS. `POST /auth/oidc/link` sets the flow cookies and `identity_link_flow` `SameSite=Lax`
so the IdP's cross-site redirect carries them; a link callback without the Strict
`access_token` cookie holds the verified assertion (`rust_identity_rp_link_hold`, 2 minutes, one
per flow) and answers a `200` refresh page to `GET /auth/oidc/link/complete?provider=..&token=..`,
the same-site request that proves the live session and releases the assertion once
(`rust_identity_rp_link_take`) into `rust_identity_rp_link_finish` (same pattern as the SAML ACS).
A callback that does carry the session still completes directly. Tests `rp_secfix13`; mutants
`scripts/test-secfix13-mutants.py`.

OIDC login flow cookies (#548, owner-approved functional fix 2026-11-09): `GET /auth/oidc/login`
sets `oidc_state/nonce/provider/verifier` `SameSite=Lax` (Go: Strict, so the IdP's cross-site redirect
never carried them) and the callback's flow-cookie clears are Lax too; the session `access_token`
cookie stays Strict. Detail: [RP.md](../../crates/domains/identity/RP.md). Test `rp_oidclax`
(callback with Lax-eligible cookies only); mutants `scripts/test-oidclax-mutants.py`.


## Guest invitation acceptance (#342)

`src/guest_invite.rs` mirrors frozen Go GET/HEAD/POST `/auth/guest-invite/accept`.
The gateway alias adds its global CSRF gate and authLimit; the handler has no CSRF
(the single-use token authorizes). Both methods share recovery's enumeration
budget. POST: login's shared pending boundary (`src/http_threat.rs`, #420/#405,
resolved by DELETE #142 together with login), Go's outer 1 MiB cap, native
always-on `ip_rules` (Go's 403 bytes), strict closed JSON, and the `auth_attempts`
postAuth tail with GeoIP country. Terminal rejects sleep Go's fixed 100 ms after
the transaction settled (additive; per-class timing differs as in Go). Own
two-connection worker pool; startup logs a degraded posture (no BYPASSRLS,
missing reducers). Residuals: CAPTCHA header and username lockout (#346).
