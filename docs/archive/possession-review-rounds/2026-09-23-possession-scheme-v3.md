# First-factor possession scheme v3 (2026-09-23) — implementation-grade specification

Owner decision stands: option (a) — every factor-set mutation requires a fresh
possession proof of an already-enrolled factor; bearer identity alone never
extends a factor set (`2026-09-23-owner-decisions-possession-pwhash.md:5-31`).
v2 was conceptually approved; Astra r1 + r2 (`-astra-r1.md`, `-astra-r2.md`)
found spec-level gaps. This v3 resolves every r2 finding and follows r2's fix
plan as its outline: §1 state model, §2 database authority, §3 endpoint/client
map, §4 executable acceptance, §5 open questions. Where the code contradicts an
input, the code wins and the contradiction is noted inline and in Self-check.

Zero-possession-factor accounts fall back to the landed V271 password step-up
(`authserver/internal/handlers/mfa_reauth.go`). Existing session machinery is
not loosened: `BearerAuthenticator.Authenticate` keeps enforcing revocation and
DPoP (`authserver/internal/token/authenticator.go:119-169`).

---

## 1. State model

### 1.1 Proof-grant record (the tuple)

One grant row in the existing V271 transport table `mfa_reauth_step_ups`
(`mailserver/sql/dbschema/V271__mfa_reauth_step_ups.sql:48-57`; issuance/consumption
in `mfa_reauth.go:138-212`), extended by a forward migration (§2.1) with:

| Column | Meaning |
|---|---|
| `operation` | operation kind being authorized (§1.3) — consumption re-checks it against the endpoint |
| `target_ref` | nullable target binding: pending-enrollment ID (TOTP), WebAuthn ceremony challenge hash (registration), raw credential ID (`passkey_credentials.id`, base64url text), `NULL` for target-less operations |
| `proof_method` | `password` \| `totp` \| `webauthn_uv` — how this grant was earned |
| `proving_factor_id` | nullable identity of the factor that proved (credential ID bytes for `webauthn_uv`; `NULL` for `password`) |
| `proving_factor_version` | for `totp`: the `users.last_totp_used_at`-generation marker plus enabled state re-checked at consumption; for `webauthn_uv`: the credential's `sign_count` + `revoked_at IS NULL` at issuance |
| `token_scope` | `session` (default; `session_jti` is an access-token JTI) \| `mfa_pending` (`session_jti` is the MFA-pending token's JTI) |
| `refresh_family_id` | the presented access token's family (`claims.RefreshFamilyID()`, read at `authenticator.go:151`); `NULL` for `mfa_pending` scope |

Unchanged columns keep V271 semantics: hash-only storage, single live row per
user (issuance deletes prior rows, `mfa_reauth.go:146-149`), `expires_at` guard,
`DELETE ... RETURNING` single-use consumption (`mfa_reauth.go:199-204`, the
V250 pattern at `authserver/internal/authn/totp_removal.go:204-216`). TTL stays
5 minutes (`MFAReauthStepUpTTL`, `mfa_reauth.go:87`).

**Consumption re-validates the FULL tuple**: live session (request
authenticated through `BearerAuthenticator`), `token_scope` matches the
presented token type, `session_jti == claims.JTI`, `refresh_family_id` matches
when set, `operation` matches the endpoint, `target_ref` matches the request's
factor/pending-enrollment/ceremony, TTL live, proving factor still enabled at
its recorded version (re-checked under the row fence, §2.2). Any mismatch is a
refusal; nothing partial commits.

### 1.2 Cohort classification fields

Classification is **derived at issuance from schema state, never stored on the
account and never influenced by attempt outcomes** (r2 finding 5: a cancelled or
failed UV assertion must not reclassify the account):

- New column `passkey_credentials.uv_capable boolean NOT NULL DEFAULT false`
  (forward migration; **all pre-existing rows set to false** — the current
  schema records no UV capability, `V001__baseline.sql:4721-4731`, and
  registration does not request or record UV,
  `authserver/internal/authn/webauthn.go:55-67`). New registrations persist the
  attestation's user-verified flag in
  `PasskeyProvider.persistCredential` (`webauthn.go:279-305`). Pre-GA unknowns
  classify as non-UV (owner clean-cut rationale,
  owner-decisions doc:34-45).
- Cohort is a pure function, evaluated inside the issuance transaction:
  - **C1 possession-capable** — `users.totp_enabled` OR EXISTS non-revoked
    `uv_capable = true` credential → possession proof required (`totp` or
    `webauthn_uv`), user's choice among enrolled C1 methods.
  - **C2 factor-holder without UV proof** — `hasVerifiedMFAFactor` true
    (`mfa_reauth.go:113-128`: enabled TOTP, `push_mfa_enabled`, legacy
    `users.webauthn_credentials <> '[]'::jsonb`, any non-revoked normalized
    credential) but not C1 → **password step-up grant**, plus a product upgrade
    prompt. Documented cohort, not a silent pass (v2 §3b).
  - **C3 zero-factor** — `hasVerifiedMFAFactor` false → password step-up
    (bootstrap; the landed V271 contract, `mfa_reauth.go:3-41`).

### 1.3 Operation kinds

`totp.enroll` (C3 first enrollment), `totp.replace` (C1+ setup over existing
enabled TOTP), `webauthn.register` (normalized `passkey_credentials`; the legacy
jsonb table has no registration endpoint in the tree — code note, Self-check),
`webauthn.revoke`, `recovery.regenerate`, `device.register.native`,
`bootstrap.totp.enroll` (`mfa_pending` scope). TOTP removal is NOT an operation
here — the V250 decision table remains its authority (§3, exception row).

### 1.4 Dedicated WebAuthn challenge lifecycle

Existing login (`BeginLogin`, `authserver/internal/authn/webauthn.go:97-132`;
`WebAuthnLoginFinish`, `handlers/webauthn.go:121-272`) and registration cookie
state (`wa_reg_sess` encrypted cookie, `MaxAge` 300,
`handlers/webauthn.go:42-45,60-69`) do NOT satisfy the management-proof
requirements (r1 finding 5, r2 finding 4). Ordinary login semantics are
unchanged. The scheme adds a **server-side ceremony store** — new table
`webauthn_ceremonies` (forward migration, §2.1):

```
challenge_hash text PK          -- SHA-256 of the issued challenge
user_id      bigint NOT NULL    -- FK users ON DELETE CASCADE
kind         text NOT NULL      -- 'registration' | 'management_assertion'
operation    text NOT NULL      -- §1.3 operation this ceremony may authorize
session_jti  text NOT NULL      -- access JTI (empty for mfa_pending scope, recorded in scope col)
token_scope  text NOT NULL DEFAULT 'session'
created_at   timestamptz NOT NULL
expires_at   timestamptz NOT NULL   -- 5 minutes, same bound as grants
```

- **Registration begin** (`WebAuthnRegisterBegin`) inserts a `registration`
  row in the same transaction that produces the go-webauthn creation options;
  the response cookie stays as transport but the row is the authority.
- **Registration finish** consumes the row (`DELETE ... RETURNING`, single-use)
  inside the promotion transaction (§2.2), so one replayed ceremony can never
  produce two credentials/grants.
- **Management-assertion ceremony** (the possession proof for C1): begin mints
  assertion options with `userVerification: 'required'` server-side (existing
  `BeginLogin` supplies no UV requirement, `webauthn.go:125`; the webmail client
  requests `'preferred'`, `mailserver/webmail/src/lib/stores/auth.ts:483` — the
  management ceremony is a separate begin/finish pair, not login), stores a
  `management_assertion` row bound to {user, operation, session JTI}; finish
  verifies the assertion with UV required, consumes the row, and issues the
  grant **in one transaction**. Origin/RP binding is enforced by the existing
  go-webauthn config (`RPID`/`RPOrigins`, `webauthn.go:36-41`) plus
  challenge/session-data equality; user-handle cross-account checks are the
  library's existing ones plus V271's user/JTI predicates (r1 finding 5 keeps
  them).
- Expired rows are dead by the `expires_at` guard; issuance of a new ceremony
  deletes the user's prior rows of the same kind (V250 cleanup convention,
  `totp_removal.go:164-167`).

### 1.5 Bootstrap token binding (`mfa_pending` scope)

Mandatory enrollment runs pre-session on `mfa_pending` tokens
(`handlers/totp.go:104-121`; minted 5-minute TTL with a random JTI,
`authserver/internal/token/jwt.go:281-300`). Grants for `bootstrap.totp.enroll`:

- `token_scope = 'mfa_pending'`; `session_jti` = the MFA-pending token's `jti`
  (validated by `h.jwt.Validate` + `Type == TypeMFAPending`, `totp.go:117-119`).
- Enrollment authorization keeps the **existing identity/credential fences**:
  `applyAuthenticationMintFence` + `verifyCredentialFence` run in the enrollment
  transaction (`totp.go:124-153`, `totp.go:306-334`); the grant adds the proof
  requirement, it does not replace fences.
- **Passkey-holder bootstrap (r2 finding 3)**: `mfa_status` deliberately returns
  `enrollment_required` for passkey-only password logins because the password
  challenge predicate considers only TOTP/push
  (`mailserver/sql/reducers/auth_policy.sql:99-117`). Option (a) decides the
  security contract: a passkey holder is NOT a zero-possession account, so
  `bootstrap.totp.enroll` for it requires a possession proof — the C1
  `webauthn_uv` ceremony with `token_scope = 'mfa_pending'` (challenge bound to
  the MFA-pending JTI instead of a session), or refusal. Password-only bootstrap
  is reserved for C3. The UX/policy question is §5.1.

### 1.6 Begin-vs-finish transitions per flow

| Flow | Begin arm | Finish arm |
|---|---|---|
| TOTP enroll/replace (session) | `GET /auth/totp/setup` — **peeks** the grant, writes pending secret only | `POST /auth/totp/confirm` — **consumes** grant before activation (V271 peek/consume semantics, `totp.go:84,426`) |
| TOTP bootstrap (`mfa_pending`) | `POST /auth/totp/enroll/setup` — peeks the `mfa_pending` grant | `POST /auth/totp/enroll/confirm` — consumes grant in the promotion tx |
| WebAuthn registration | `GET /auth/webauthn/register/begin` — peeks grant + creates ceremony row | `POST /auth/webauthn/register/finish` — consumes ceremony row AND grant, then mutation |
| WebAuthn revoke / recovery regenerate / native device register | single-call — **consumes** grant before the mutation | — |
| Management possession proof (C1) | dedicated assertion begin — creates challenge row | assertion finish — consumes row, issues grant |

### 1.7 State machine

States: `NONE` → `CEREMONY_LIVE` (WebAuthn ceremonies only) → `GRANT_LIVE` →
terminal: `CONSUMED`, `DEAD` (expired | invalidated | refused).

| State | Event | Guard | Action | Next state |
|---|---|---|---|---|
| NONE | proof begin (C1) | not impersonated; budget not locked (§2.4); cohort C1 | insert ceremony row; return assertion options | CEREMONY_LIVE |
| NONE | password reauth (C2/C3) | not impersonated; budget not locked; password verifies via `VerifyTOTPRemovalPassword` (`totp_removal.go:115-126`) | insert grant (`proof_method='password'`, cohort operation) | GRANT_LIVE |
| NONE | TOTP proof (C1) | not impersonated; budget not locked; enabled secret verifies + replay claim wins under row fence (§2.2) | insert grant (`proof_method='totp'`) | GRANT_LIVE |
| CEREMONY_LIVE | assertion/attestation finish | challenge row live; UV required; origin/RP ok; budget not locked | consume ceremony row; (assertion: insert grant; registration: proceed to promotion, §2.2) | GRANT_LIVE / CONSUMED |
| GRANT_LIVE | gated-arm call | full tuple re-validates (§1.1) under row fence | consume row; mutate; success audit; commit | CONSUMED |
| GRANT_LIVE | gated-arm call | tuple mismatch (wrong purpose/target/pending ID, replay, expired, wrong session) | typed 403 `reauth_required`, audit refusal | DEAD (row deleted) |
| GRANT_LIVE | TTL elapsed | `expires_at <= now()` | row inert | DEAD |
| GRANT_LIVE | proving factor revoked/replaced | consumption-time re-check fails under fence | refusal | DEAD |
| GRANT_LIVE | logout / account switch / family or all revocation | `revoke_user_sessions` fires | reducer deletes grants (§2.5) | DEAD |
| GRANT_LIVE (`password`, C3) | account gains first possession factor | first C1/C2 factor exists | delete unconsumed password grants (v2 §1) | DEAD |
| GRANT_LIVE | refresh rotation | rotation mints a NEW access JTI (`refresh.go:285,369`); grant keeps original JTI binding | no action — refreshed client's JTI differs, grant unusable from the new token; old pair bounded by the 5-minute TTL (§2.5) | GRANT_LIVE |
| any | impersonated bearer (`claims.AdminActorID != nil`, `jwt.go:413-436`; `mustUser` passes claims through, `handlers/auth.go:3351-3358`) | — | refuse unconditionally at issuance AND every consumption, incl. the V250 removal flow (r2 disposition) | NONE |

---

## 2. Database authority

### 2.1 Forward migration (one version, named objects)

1. `ALTER TABLE mfa_reauth_step_ups ADD COLUMN operation text NOT NULL,
   target_ref text, proof_method text NOT NULL, proving_factor_id bytea,
   proving_factor_version bigint, token_scope text NOT NULL DEFAULT 'session',
   refresh_family_id text` — existing unconsumed password-only rows are
   **DELETED** at migration time (owner clean cut, v2 §7; pre-GA).
2. `CREATE TABLE totp_pending_enrollments (user_id bigint PRIMARY KEY REFERENCES
   users(id) ON DELETE CASCADE, secret_enc bytea NOT NULL, created_at
   timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL)` —
   pending TOTP secrets move OUT of `users.totp_secret_enc` so an active
   credential is never overwritten by an unconfirmed one (r1 finding 2, r2
   finding 1; today `GenerateTOTPSecret` overwrites
   `authserver/internal/authn/totp.go:164-180`).
3. `ALTER TABLE passkey_credentials ADD COLUMN uv_capable boolean NOT NULL
   DEFAULT false` (§1.2).
4. `CREATE TABLE webauthn_ceremonies (...)` per §1.4.
5. `ALTER TABLE users ADD COLUMN possession_failed_attempts integer NOT NULL
   DEFAULT 0, ADD COLUMN possession_locked_until timestamptz` (§2.4).
6. Reducer/mount wiring for §2.5.

### 2.2 Canonical lock ordering

Every transaction that issues, consumes, or mutates factor state acquires, in
order, holding to commit (no lock is ever acquired out of sequence):

1. **`users` row fence** — `SELECT ... FOR NO KEY UPDATE` (the mode
   `ConfirmTOTP`/`ConfirmTOTPEnrollmentTx` already use,
   `authn/totp.go:258-266,333-347`; `FOR UPDATE` as used by the V250 removal,
   `totp_removal.go:218-222`, conflicts with it, so both serialize).
2. **factor rows** — `passkey_credentials` / `push_devices` rows for the target
   credential/device.
3. **proof-artifact rows** — grant consumption (`DELETE ... RETURNING`) and
   ceremony consumption, last.

Consequences, named against today's code:

- **Consumption + promotion + audit in ONE transaction** (r2 fix plan 2),
  wrapped in the existing **caller-owned-transaction pattern**
  (`ConfirmTOTPEnrollmentTx`, `authn/totp.go:324-410`, which "never commits"
  and lets the fenced completion own the commit via `MintTx` +
  `commitDeferredTokenResponse`, `handlers/totp.go:379-393`; single-tx shape
  precedent: `DisableTOTPWithStepUp`, `totp_removal.go:191-258`). The
  transaction = lock users → re-validate tuple + proving factor → mutate factor
  (TOTP enable, passkey insert/revoke, recovery rotate, device insert) → audit
  insert → commit. TOTP promotion specifically: verify code against
  `totp_pending_enrollments`, then in-tx delete the pending row + set
  `users.totp_secret_enc` + `totp_enabled = TRUE` + consume grant + audit.
- **Issuance verification serializes against factor changes** (r1 finding 2):
  TOTP proof verification for grant issuance runs its secret read + replay
  claim on the SAME transaction holding the users fence — the seam already
  exists (`totpVerifyStore`, `authn/totp.go:75-90`); this closes the
  read-secret-then-claim window r1 identified in `verifyTOTPCore` callers.
- **Passkey revocation gains the fence**: `RevokeCredential` is today a bare
  `UPDATE passkey_credentials` (`webauthn.go:198-204`); under v3 it runs
  inside the users-fence transaction with grant re-validation, closing the
  consume-vs-revoke race r2 finding 1 named.
- Cancellation/abandonment: deleting the `totp_pending_enrollments` row (or
  letting `expires_at` lapse) leaves the active factor untouched — repair of
  today's behavior where replacement setup overwrites the live secret
  (`authn/totp.go:170`), whose confirm can then never re-enable an enabled row
  (`totp.go:283-284` guard matches zero rows). Code-vs-v2 note: v2 §2 implied
  replacement confirm works; in current code the overwrite makes the active
  factor require codes from the unconfirmed secret immediately and the confirm
  fails closed. The pending-table split fixes both; no compatibility shims.

### 2.3 Failure budgets — serialized, with thresholds

- **TOTP proofs keep the existing shared policy**: 5 consecutive failures →
  15-minute lock (`totpMaxFailures`/`totpLockDuration`,
  `authn/totp.go:418-424`; pure decision `NextTOTPLockout`,
  `totp.go:431-438`) across login, recovery and management, still funneled
  through `VerifyTOTPWithLockout` (`totp.go:498-528`).
- **Password and WebAuthn-assertion proofs get the same shape on new counters**
  (`users.possession_failed_attempts` / `possession_locked_until`, §2.1):
  threshold 5, lock 15 minutes. `proof_method` failure classes are recorded on
  their own counters; a lock on either counter refuses issuance.
- **Serialized increments**: the counter update is a single
  `UPDATE users SET possession_failed_attempts = possession_failed_attempts + 1,
  possession_locked_until = CASE ... END WHERE id = $1 AND
  (possession_locked_until IS NULL OR possession_locked_until <= now())`
  executed under the users fence inside the issuance transaction — repairing
  the read-then-write lost update in `RecordTOTPFailure`
  (`authn/totp.go:467-473`, writes a previously-read count) and the fail-open
  lock-state read in `VerifyTOTPWithLockout` (`totp.go:511`).
- **Fail-closed rules**: a locked budget refuses issuance (429, matching
  `ErrTOTPLocked` handling, `handlers/totp_removal.go:59-61`); a lock-state
  read error refuses issuance with 500 — issuance never proceeds on unknown
  state. (Verification-side bookkeeping errors still fail the proof closed.)
- Budget check + increment happen inside the issuance transaction (§2.2 lock
  order), so concurrent failures cannot lose increments and budgets are exact.

### 2.4 Atomic success audit

The success audit row (`admin_audit_log`, the established convention —
transactional in `DisableTOTPWithStepUp` `totp_removal.go:249-255` and
`ConfirmTOTPEnrollmentTx` `authn/totp.go:402-408`) commits in the SAME
transaction as grant consumption + mutation. Refusal audits stay best-effort
off-transaction (`mfa_reauth.go:287-292`) — an audit-insert failure after a
definitive refusal must not fabricate a mutation outcome.

### 2.5 Session-invalidation triggers (durable, consumption-time fenced)

- **Logout / account switch / credential change / admin revocation**: the
  `revoke_user_sessions` reducer is the single boundary for session death
  (`mailserver/sql/reducers/revoke_user_sessions.sql:1-7`). v3 extends it:
  scope `all` deletes ALL the user's `mfa_reauth_step_ups` rows and
  `webauthn_ceremonies` rows; scope `family` deletes rows whose
  `refresh_family_id` matches; scope `jti` deletes rows whose `session_jti`
  matches. Same transaction, per the reducer's boundary contract. Defense in
  depth: the denylist already refuses revoked (user, jti, family) bearers at
  request authentication (`authenticator.go:146-155`), so a dead session
  cannot even reach consumption.
- **Refresh** (r2 finding 6 + named acceptance case): rotation replaces the
  refresh row (`refresh.go:285`) and mints a new access token — a NEW JTI,
  same family (`refresh.go:319-392`). The grant keeps its ORIGINAL JTI, so the
  refreshed client must re-prove (v2 §6 "grants are NOT refreshed" holds; JTI
  binding is not loosened). The retained old-access-token + grant pair is
  real (the old access token is not revoked by rotation) and is bounded by the
  5-minute grant TTL and the access token's own lifetime; it grants no power
  beyond the session that already held both. §4 names the test that pins this
  behavior.
- **Proving-factor revocation/replacement**: consumption re-validates
  `proving_factor_*` under the users fence (§1.1); revocation paths additionally
  best-effort-delete outstanding grants issued on that factor.
- **First possession factor gained**: unconsumed password-cohort (C3) grants
  are deleted (v2 §1 invalidation rule).

---

## 3. Endpoint/client map

Every gated endpoint → owning handler (file:line) → operation kind → client
surface → accepted proof methods. "Webmail" = the SPA
(`mailserver/webmail`); "native" = platform clients. Mounts are in
`authserver/cmd/authserverd/main.go` (line refs below).

| Endpoint (mount) | Owning handler | Operation kind | Client surface | Proofs accepted |
|---|---|---|---|---|
| `POST /auth/mfa/reauth` (main.go:1053) | `MFAReauthBegin`, `handlers/mfa_reauth.go:228` | issuance only (not a mutation) | webmail `auth.ts:684` (`beginMFAReauth`); native | `password` (C2/C3); C1 accounts get a method-aware refusal naming possession options |
| `GET /auth/totp/setup` (main.go:1035) | `TOTPSetup`, `handlers/totp.go:31` | `totp.enroll` (peek) / `totp.replace` (C1+ current-code arm) | webmail both settings pages (`auth.ts:733`; `settings/+page.svelte:427`) | `password` \| `totp` \| `webauthn_uv` per cohort; replacement arm additionally keeps its `current_totp_code` lockout check (`totp.go:63-74`) |
| `POST /auth/totp/confirm` (main.go:1037) | `TOTPConfirm`, `handlers/totp.go:407` | `totp.enroll`/`totp.replace` (consume + promote) | same | same, consumed here |
| `POST /auth/totp/enroll/setup` (main.go:1024) | `TOTPEnrollmentSetup`, `handlers/totp.go:110` | `bootstrap.totp.enroll` (peek, `mfa_pending` scope) | webmail login/enrollment flow (`auth.ts:772`) | C3: `password` bootstrap (the password step already proved at login); passkey-holder: `webauthn_uv` ceremony bound to the MFA-pending JTI (§1.5); refusal otherwise |
| `POST /auth/totp/enroll/confirm` (main.go:1025) | `TOTPEnrollmentConfirm`, `handlers/totp.go:239` | `bootstrap.totp.enroll` (consume + promote) | same (`auth.ts:784`) | same, consumed in the promotion tx |
| `GET /auth/webauthn/register/begin` (main.go:1011) | `WebAuthnRegisterBegin`, `handlers/webauthn.go:22` | `webauthn.register` (peek + ceremony create) | webmail `settings/+page.svelte:366`; native | per cohort; **bearer-only registration refused** (owner decision) |
| `POST /auth/webauthn/register/finish` (main.go:1013) | `WebAuthnRegisterFinish`, `handlers/webauthn.go:51` | `webauthn.register` (consume ceremony + grant, persist) | same | same, consumed |
| `DELETE /auth/webauthn/credential/{id}` (main.go:1020) | `WebAuthnRevokeCredential`, `handlers/webauthn.go:329` | `webauthn.revoke` (consume) | webmail; native | per cohort, `target_ref` = credential ID (`decodeCredentialID`, `webauthn.go:319-326`) |
| `POST /auth/backup-codes/generate` (main.go:1093) | `GenerateBackupCodes`, `handlers/mfa.go:31` | `recovery.regenerate` (consume) | webmail `auth.ts:702`, security page; native | per cohort, EVERY account (V271 posture kept) |
| `POST /auth/device/register` (main.go:1075) | `DeviceRegister`, `handlers/device.go:95` | `device.register.native` (consume) — **native providers `apns`/`fcm`/`hms` only** | native clients | per cohort. **Distinction (r2 fix plan 3):** native registrations are authentication devices — they carry `device_public_key`, receive ECIES number-match challenges and are the only devices `dispatchToNativeDevices` selects (`authn/push.go:445-448`) and `/auth/mfa/approve` accepts (`device.go:19-25`). `provider = 'webpush'` rows are WebPush notification **subscriptions** — delivery keys that never answer approvals (`authn/push.go:415-423`) — and are NOT gated |
| `POST /auth/totp/remove/begin` (main.go:1044) + `POST /auth/totp/remove` (main.go:1045) | `TOTPRemovalBegin`/`Confirm`, `handlers/totp_removal.go:28,93`; decision table `authn/totp_removal.go:45-110`; removal tx `totp_removal.go:191-258` | **EXPLICIT EXCEPTION** — V250 decision table remains authority (password+current TOTP; authenticator-lost → password+non-consuming recovery-code check `totp_removal.go:133-147`; no codes → self-service refusal to admin/support) | webmail `auth.ts:810,827`, security page | not re-gated by this scheme; recovery codes are break-glass, not possession proofs (v2 §4). Impersonation rejection (§1.7 last row) IS applied here per the r2 disposition |
| `PUT /auth/webauthn/credential/{id}/name` (main.go:1019) | `WebAuthnNameCredential`, `handlers/webauthn.go:275` | out of scope — metadata rename, no factor-set change | webmail | not gated |
| `GET /auth/webauthn/credentials` (main.go:1018) | `WebAuthnListCredentials`, `handlers/webauthn.go:355` | read-only | webmail | not gated |

Not gated (login/second-factor completion, no factor-set change):
`POST /auth/totp/verify` (`handlers/totp.go:183`),
`POST /auth/backup-codes/verify` (`main.go:1095`),
`POST /auth/push/verify` / `POST /auth/mfa/push/send` / `POST /auth/push/status`
(main.go:1057-1064), `POST /auth/mfa/approve` (main.go:1079),
`/auth/webauthn/login/*` (main.go:1016-1017), forgot-password arms
(main.go:1098-1102).

**Code-vs-input note (push MFA registration)**: v2 §2 lists "push MFA
registration" as a covered mutation, but no production endpoint sets
`users.push_mfa_enabled` — it is read (`authn/push.go:219-228`,
`mfa_reauth.go:117`, `auth_policy.sql:75`) and written only by tests. The
real enrollable push surface is `POST /auth/device/register` (native), which
this map gates. If a `push_mfa_enabled` enrollment endpoint is added later it
is gated by construction under operation kind `device.register.native` (§4
pins the inventory test).

### 3.1 Webmail surfaces contract

- `/settings/security`
  (`mailserver/webmail/src/routes/settings/security/+page.svelte:123-196`):
  the existing password-only reauth handoff (`submitReauth` →
  `beginMFAReauth`, lines 170-196) becomes method-aware — C1 accounts are
  offered the WebAuthn-UV assertion or TOTP proof; password appears only for
  C2/C3. Held-proof discipline already present (`openReauth` clears
  `heldReauthToken`, lines 141-149) is kept.
- `/settings` general page:
  `beginPasskeyEnrollment` currently raw-fetches
  `/auth/webauthn/register/begin|finish` (`settings/+page.svelte:363-425`) and
  `handleSetupTOTP`/`handleConfirmTOTP` call setup/confirm with **no token**
  (lines 427-453; the r2 finding 7 gap). Both are rerouted through the shared
  method-aware reauth store functions (`auth.ts:733-770`), so every gated call
  carries the grant and the 403 contract drives the handoff.
- **Auth-generation fencing**: the client drops pending ceremony/grant state
  whenever `checkAuth` (`auth.ts:244`) observes a changed account identity,
  and discards late responses before assigning secrets or recovery codes.
  This is a UX fence only — server-side tuple binding (§1.1) is the
  enforcement; a response already in flight to a browser that then switches
  accounts is refused by the JTI/user binding on any replay, and returned
  secrets are never valid for another account.

---

## 4. Executable acceptance

Named cases per layer. "DB/bookkeeping" (corrected per r2) failures are
injected at the named statement. Existing tests that expect ungated
factor-holder enrollment or password-only regeneration are deliberately
revised (r1 fix plan 5); ordinary login compatibility tests are retained.

### 4.1 DB race/fault tests (exercise the named concurrency)

| Test | Concurrency/fault exercised |
|---|---|
| `TestGrantConsumeExactlyOnceConcurrent` | two transactions racing the `DELETE ... RETURNING` consumption + mutation → exactly one commits, second refuses with factor intact (V250 pattern, `totp_removal.go:204-216`) |
| `TestRevokeVsConsumeRace` | passkey revocation vs grant consumption interleaved before-verify / during-verify / before-commit — users-fence ordering (§2.2) makes every interleaving converge refused-or-consistent; pins the closure of the `webauthn.go:198-204` fence-less update |
| `TestTOTPReplaceStagedAndCancellable` | replacement setup writes only `totp_pending_enrollments`; cancellation/abandonment preserves the ACTIVE secret and codes; promotion swaps atomically (r2-named case: cancellation preserving active TOTP) |
| `TestAssertionReplaySingleGrant` | one replayed assertion replayed against assertion-finish: ceremony row single-use → at most one grant ever (r2-named case; r2 finding 4) |
| `TestProofBudgetSerializedUnderLoad` | N concurrent failed password/WebAuthn proofs → counter exactly N, lock trips at 5 for 15 min — pins the §2.3 single-statement increment vs today's lost update (`authn/totp.go:467-473`) |
| `TestBudgetReadFailureRefusesIssuance` | fault at the budget read → issuance 500, never proof issuance (fail-closed; contrasts `VerifyTOTPWithLockout`'s fail-open load, `totp.go:511`) |
| `TestGrantAuditFaultRollsBackAll` | DB/bookkeeping fault at the audit insert (§2.4) → mutation, grant consumption AND audit all roll back; nothing partial commits |
| `TestTOTPProofVsFactorChangeRace` | issuance-time TOTP verify on the fenced tx vs concurrent disable/replace — no accepted proof against a revoked/replaced secret (r1 finding 2 closed) |

### 4.2 Handler/mux tests

| Test | Asserts |
|---|---|
| `TestBearerOnlyWebAuthnRegisterRefused` | begin/finish without a live grant → typed 403 `reauth_required` (`mfa_reauth.go:96-105` shape) — the owner decision's negative case |
| `TestPasswordOnlyRefusedWhenPossessionRequired` | C1 account + password grant → refused at every §3 endpoint |
| `TestWrongPurposeTargetPendingRefused` | grant bound to operation/target A presented at B (incl. wrong pending-enrollment ID and wrong `target_ref` credential) → refusal |
| `TestCrossAccountCeremonyRefused` | ceremony/grant of user A on user B's session → refusal (user/JTI predicates, §1.4) |
| `TestStaleExpiredCeremonyRefused` / `TestProofAndCeremonyExpiryIndependent` | ceremony row dead but grant live, and vice versa → both refuse; TTLs independent |
| `TestMissingUVRefused` | management assertion without UV → refusal (server-side requirement, §1.4) |
| `TestWrongChallengeOriginRPRefused` | assertion against wrong challenge/origin/RP → refusal (go-webauthn config, `webauthn.go:36-41`) |
| `TestImpersonationRefusedIssuanceAndConsumption` | `AdminActorID` bearer (`jwt.go:413-436`) refused at `/auth/mfa/reauth`, every gated arm, and the V250 removal begin/confirm, even with valid evidence |
| `TestNormalizedNonUVCredentialCohort` | non-UV normalized credential + no TOTP → C2 password step-up; UV assertion against it not usable as proof; failed/cancelled UV never reclassifies (r2-named case) |
| `TestRefreshRetainsOldPairBounded` / `TestRefreshNewJTIRefused` | after rotation: old access token + its grant consumable only within the 5-minute TTL (documented, §2.5); NEW access token + old grant refused on JTI mismatch (r2-named retained-pair case) |
| `TestSessionReplacementAndLogoutInvalidate` | family revocation via `revoke_user_sessions` deletes grants; replaced session cannot consume |
| `TestFirstFactorPasswordGrantInvalidAfterPossessionEnrolls` | C3 password grant dies when the account gains its first possession factor |
| `TestBootstrapPasskeyHolderRequiresUVProof` | passkey-only account in mandatory enrollment (`auth_policy.sql:99-117` routing) cannot enroll TOTP on the `mfa_pending` token alone; UV ceremony satisfies; C3 zero-factor password bootstrap still works end-to-end (r2-named bootstrap-with-passkeys case) |
| `TestNativeDeviceRegisterGatedWebpushNotGated` | `apns`/`fcm`/`hms` registration needs a grant; `webpush` subscription registration does not, and never answers `/auth/mfa/approve` |
| `TestMutationInventoryComplete` | every §3 row refuses without the correct grant — guards against future ungated additions (incl. any future `push_mfa_enabled` setter, §3 note) |
| `TestExistingFlowsUnregressed` | TOTP/passkey/push/recovery login, conditional-access and DPoP completion guarantees behave exactly as today (`webauthn.go:200-272` CA leg, `completionMetadataForDPoP`) |

### 4.3 Browser lifecycle tests (per webmail surface)

- `/settings/security`: method-aware handoff — C1 offers WebAuthn-UV/TOTP,
  password only for C2/C3; retry-after-proof loops honestly
  (`+page.svelte:186-195`); expiry requires a NEW proof (no grant refresh).
- `/settings` (general): passkey registration (`:363`) and TOTP
  setup/confirm (`:427,439`) route through the shared handoff; returned
  secrets/recovery codes render only if the account identity is unchanged at
  response time (§3.1).
- Both surfaces: session replacement during a ceremony, refresh mid-ceremony,
  logout/account switch → pending enrollment UI drops, late responses
  discarded, next gated call re-runs the handoff.

---

## 5. Open questions for the owner

1. **`mfa_status` routing for passkey-only password logins**
   (`mailserver/sql/reducers/auth_policy.sql:99-117`): the security contract is
   fixed by option (a) (§1.5 — passkey holders must prove UV or are refused),
   but whether the policy should keep forcing them into TOTP enrollment at all
   (vs. routing them to passkey login, or letting the UV ceremony satisfy the
   login's MFA step directly) is a product/policy-reducer change outside this
   scheme's authority. Owner to pick the UX; implementation of §1.5 is
   fail-closed under either answer.
2. **Native `device.register.native` proof cohort**: registering a native
   device from a C2 (e.g. legacy-jsonb-only) account with a password grant is
   permitted under §3. If native devices should be treated as
   possession-grade upgrades (i.e. require C1 proofs because they mint
   approval capability), say so — the gate itself is identical; only the
   accepted-proof set changes.

---

## Self-check

One omission/conflict pass over inputs vs code:

1. **Code-vs-v2 conflict (noted §3):** no production endpoint sets
   `users.push_mfa_enabled`; "push MFA registration" resolves to native
   `POST /auth/device/register` gating. v2 §2's row is otherwise unmatched in
   code.
2. **Code-vs-v2 conflict (noted §1.3, §2.2):** v2 §2 says WebAuthn
   registration covers "both normalized and legacy tables"; code registers
   only normalized `passkey_credentials` (`authn/webauthn.go:279-305`); the
   legacy `users.webauthn_credentials` jsonb has no registration endpoint —
   it only affects cohort classification.
3. **Code-vs-v2 conflict (noted §2.2):** v2 implied TOTP replacement confirm
   works; current code overwrites the active secret at setup
   (`authn/totp.go:170`) and confirm's guarded enable can never match an
   enabled row (`totp.go:283-284`). v3 specifies the pending-table split as
   the fix; the pre-existing broken-replacement window is not preserved.
4. **Unresolved by me (deliberately):** §5.1 policy-routing preference and
   §5.2 native-device proof cohort — genuinely owner decisions; not invented.
5. **UV flag source:** §1.2 specifies persisting the attestation's
   user-verified flag; `go-webauthn`'s `Credential.Flags.UserVerified` carries
   it, but I did not run code to confirm the exact field path version in
   `go.mod` — implementer should confirm at implementation time.
6. **Impersonation guard placement:** r2 requires rejection at issuance and
   every mutation including the removal flow; §1.7/§4.2 specify it, but the
   exact shared-helper name (`rejectImpersonated`) is illustrative, not
   prescribed.
7. **`hms` provider support** exists in handler + V074 constraint
   (`device.go:125`, `V074__restore_push_devices_native.sql:19`) — no
   conflict, recorded so the §3 native set is not "corrected" back to the
   V001 three-provider list.
8. No builds/tests were run; this is a specification document. All file:line
   citations were read from the current worktree.
