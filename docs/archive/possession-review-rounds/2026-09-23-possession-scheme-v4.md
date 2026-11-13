# First-factor possession scheme v4 (2026-09-23) — implementation-grade specification

Owner decision stands: option (a) — every factor-set mutation requires a fresh
possession proof of an already-enrolled factor; bearer identity alone never
extends a factor set (`2026-09-23-owner-decisions-possession-pwhash.md:5-31`).
v2 was conceptually approved; Astra r1 + r2 + r3 (`-astra-r1.md`, `-astra-r2.md`,
`-astra-r3.md`) found spec-level gaps. v3 resolved every r2 finding; r3 confirmed
r2 findings 4–5 closed and the endpoint map correct, and held on five residuals.
This v4 is v3 carried forward with the partial sections REPLACED:

- **Factor generations + target lifecycle (was PARTIAL)** → new §1.8 (per-user
  mutation-only generation counter, justified from code), §1.1 (grant binds it),
  §1.6 (distinct pending-enrollment IDs + one-time atomic begin binding + staged
  provenance).
- **Failure budgets (was PARTIAL)** → §2.3 rewritten: named storage, single
  atomic increment with `RETURNING`, per-method counters, fail-closed
  bookkeeping, and a test oracle derived from that storage spec alone.
- **Bootstrap issuance (was PARTIAL)** → §1.5.1: the exact minting point
  (`auth.go:734-747`), why no transaction exists there today
  (`jwt.go:262-302` is pure signing), and the precise seam change that puts the
  bootstrap grant row in the same commit as the scope token.
- **Six additional acceptance cases** → §4.4, each with setup/steps/expected.

Sections not listed above carry forward from v3 unchanged in contract (line
citations re-verified against the current worktree). Where the code contradicts
an input, the code wins and the contradiction is noted inline and in
Self-check. r3 confirms the two owner-open questions (§5) do NOT block these
engineering contracts; they are carried, not escalated.

Zero-possession-factor accounts fall back to the landed V271 password step-up
(`authserver/internal/handlers/mfa_reauth.go`). Existing session machinery is
not loosened: `BearerAuthenticator.Authenticate` keeps enforcing revocation and
DPoP (`authserver/internal/token/authenticator.go:119-169`; the type check that
rejects `mfa_pending` bearers is `authenticator.go:142`).

---

## 1. State model

### 1.1 Proof-grant record (the tuple)

One grant row in the existing V271 transport table `mfa_reauth_step_ups`
(`mailserver/sql/dbschema/V271__mfa_reauth_step_ups.sql:48-57`; issuance/consumption
in `mfa_reauth.go:138-212`), extended by a forward migration (§2.1) with:

| Column | Meaning |
|---|---|
| `operation` | operation kind being authorized (§1.3) — consumption re-checks it against the endpoint |
| `target_ref` | nullable target binding: pending-enrollment UUID (TOTP), WebAuthn ceremony challenge hash (registration), raw credential ID (`passkey_credentials.id`, base64url text), `NULL` for target-less operations and for every grant before its begin-arm binding transition (§1.6) |
| `proof_method` | `password` \| `totp` \| `webauthn_uv` — how this grant was earned |
| `proving_factor_id` | nullable identity of the factor that proved (credential ID bytes for `webauthn_uv`; `NULL` for `password`) |
| `bound_factor_generation` | the `users.factor_generation` value observed at issuance (§1.8); consumption requires the current value to still equal it |
| `token_scope` | `session` (default; `session_jti` is an access-token JTI) \| `mfa_pending` (`session_jti` is the MFA-pending token's JTI) |
| `refresh_family_id` | the presented access token's family (`claims.RefreshFamilyID()`, read at `authenticator.go:151`); `NULL` for `mfa_pending` scope |

(v4: `proving_factor_version` from v3 is REPLACED by `bound_factor_generation`.
v3 keyed TOTP grants to `users.last_totp_used_at` and WebAuthn grants to
`sign_count`; r3 finding 1 showed both move on ordinary USE — issuance's own
replay claim updates `last_totp_used_at` (`authn/totp.go:127-135`) and login
updates `sign_count` (`authn/webauthn.go:188-192`) — so a grant could be
invalidated by its own issuance or by unrelated logins. A mutation-only counter
(§1.8) has the correct dynamics for both factor families.)

Unchanged columns keep V271 semantics: hash-only storage, single live row per
user (issuance deletes prior rows, `mfa_reauth.go:146-149`), `expires_at` guard,
`DELETE ... RETURNING` single-use consumption (`mfa_reauth.go:199-204`, the
V250 pattern at `authserver/internal/authn/totp_removal.go:204-216`). TTL stays
5 minutes (`MFAReauthStepUpTTL`, `mfa_reauth.go:87`).

**Consumption re-validates the FULL tuple**: live session (request
authenticated through `BearerAuthenticator`), `token_scope` matches the
presented token type, `session_jti == claims.JTI`, `refresh_family_id` matches
when set, `operation` matches the endpoint, `target_ref` matches the request's
pending-enrollment ID / ceremony / credential, TTL live,
`bound_factor_generation == users.factor_generation` (read under the row fence,
§2.2), proving factor still enabled/not-revoked (`totp_enabled` for `totp`;
`revoked_at IS NULL` for `webauthn_uv`). Any mismatch is a refusal; nothing
partial commits.

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
session_jti  text NOT NULL      -- the REAL JTI of the presenting token
                                -- (access JTI, or the mfa-pending JTI for
                                -- mfa_pending scope; never empty — v4 fixes
                                -- v3's "empty for mfa_pending" contradiction)
token_scope  text NOT NULL DEFAULT 'session'
refresh_family_id text          -- the access token's family at ceremony
                                -- creation; NULL for mfa_pending scope.
                                -- (v4: supplies the family binding r3
                                -- finding 4 found missing from v3.)
created_at   timestamptz NOT NULL
expires_at   timestamptz NOT NULL   -- 5 minutes, same bound as grants
```

- **Registration begin** (`WebAuthnRegisterBegin`) inserts a `registration`
  row in the same transaction that produces the go-webauthn creation options
  AND performs the grant's one-time target binding (`target_ref =
  challenge_hash`, §1.6); the response cookie stays as transport but the row is
  the authority.
- **Registration finish** consumes the row (`DELETE ... RETURNING`, single-use)
  inside the promotion transaction (§2.2), so one replayed ceremony can never
  produce two credentials/grants.
- **Management-assertion ceremony** (the possession proof for C1): begin mints
  assertion options with `userVerification: 'required'` server-side (existing
  `BeginLogin` supplies no UV requirement, `webauthn.go:125`; the webmail client
  requests `'preferred'`, `mailserver/webmail/src/lib/stores/auth.ts:483` — the
  management ceremony is a separate begin/finish pair, not login), stores a
  `management_assertion` row bound to {user, operation, session JTI, family};
  finish verifies the assertion with UV required, consumes the row, and issues
  the grant **in one transaction**. Origin/RP binding is enforced by the existing
  go-webauthn config (`RPID`/`RPOrigins`, `webauthn.go:36-41`) plus
  challenge/session-data equality; user-handle cross-account checks are the
  library's existing ones plus V271's user/JTI predicates (r1 finding 5 keeps
  them).
- Expired rows are dead by the `expires_at` guard; issuance of a new ceremony
  (only possible under a NEW grant, since begin binding is one-time per grant,
  §1.6) deletes the user's prior rows of the same kind (V250 cleanup convention,
  `totp_removal.go:164-167`).

### 1.5 Bootstrap token binding (`mfa_pending` scope)

Mandatory enrollment runs pre-session on `mfa_pending` tokens
(`handlers/totp.go:104-121`; minted 5-minute TTL with a random JTI,
`authserver/internal/token/jwt.go:281-289,298`). Grants for
`bootstrap.totp.enroll`:

- `token_scope = 'mfa_pending'`; `session_jti` = the MFA-pending token's `jti`
  (validated by `h.jwt.Validate` + `Type == TypeMFAPending`, `totp.go:117-121`).
- Enrollment authorization keeps the **existing identity/credential fences**:
  `applyAuthenticationMintFence` + `verifyCredentialFence` run in the enrollment
  transaction (`totp.go:124-153`, `totp.go:306-334`; the seams are
  `auth.go:430-441` and `auth.go:448-469`); the grant adds the proof
  requirement, it does not replace fences.
- **Grant issuance itself is specified in §1.5.1 (new in v4)** — r3 finding 3:
  v3 said password verification "creates the grant" but never identified the
  issuer. It is the login flow's `enrollment_required` branch, in the same
  commit as the scope token.
- **Passkey-holder bootstrap (r2 finding 3)**: `mfa_status` deliberately returns
  `enrollment_required` for passkey-only password logins because the password
  challenge predicate considers only TOTP/push
  (`mailserver/sql/reducers/auth_policy.sql:99-117`). Option (a) decides the
  security contract: a passkey holder is NOT a zero-possession account, so
  `bootstrap.totp.enroll` for it requires a possession proof — the C1
  `webauthn_uv` ceremony with `token_scope = 'mfa_pending'` (challenge bound to
  the MFA-pending JTI instead of a session; ceremony `session_jti` is the real
  pending JTI, `refresh_family_id` NULL), or refusal. Password-only bootstrap
  is reserved for C3/C2 (§1.5.1 issuance split). The UX/policy question is
  §5.1.

#### 1.5.1 Bootstrap grant issuance — the concrete path (v4)

**Where the `mfa_pending` scope is minted today.** The only bootstrap minting
point is the password login's mandatory-enrollment branch:
`readMFAStatus` (`auth.go:725`) returns `enrollment_required` and the branch at
`authserver/internal/handlers/auth.go:734-747` calls `h.issueMFAPending`
(`auth.go:471-481`), which delegates to
`jwt.IssueMFAPendingWithFences` (`jwt.go:262-302`; random JTI minted at
`jwt.go:281-284`, `Type = TypeMFAPending` at `:288`, 5-minute expiry at
`:298`). The other `issueMFAPending` call sites are NOT bootstrap — they are
second-factor completions for already-enrolled accounts (TOTP login
`auth.go:806-821`, CA step-up `auth.go:894-909`, WebAuthn-login second factor
`handlers/webauthn.go:220,245`) and never authorize enrollment. A passkey-only
account reaches the bootstrap point only by logging in with its PASSWORD:
`WebAuthnLoginFinish` issues a full session with no enrollment routing when no
challengeable MFA is enrolled (`webauthn.go:197-199,262-271`), while the
password path routes via `auth_policy.sql:99-117`.

**Why no transaction exists there today.** `IssueMFAPendingWithFences` is pure
in-memory JWT signing — there is no DB write, hence no transaction, at the mint
point (`jwt.go:262-302`). "Same transaction as the scope token" therefore
requires a precise seam change, specified here:

1. **JWT seam** (authserver/internal/token/jwt.go): extract the JTI generation
   at `jwt.go:276-284` so the JTI is generated FIRST and the signer accepts it:
   new exported `IssueMFAPendingWithFencesJTI(userID, email string,
   identityFence *jwtutil.IdentityFenceClaim, credentialFence string, jti
   string, amr ...string) (token string, jti string, err error)` — signs with
   the supplied JTI and returns it. Existing `IssueMFAPending*` wrappers keep
   byte-identical behavior by generating a random JTI and delegating (the
   16-byte random hex discipline of `jwt.go:281-284` is preserved everywhere).
2. **Handler seam** (authserver/internal/handlers/auth.go): new
   `issueMFAPendingBootstrap(ctx, userID, email, completion) (string, error)`
   replacing the bare `h.issueMFAPending` call at `auth.go:735`, and it runs:
   1. `BEGIN` on the pool.
   2. `applyAuthenticationMintFence` + `verifyCredentialFence` in that tx
      (the identical fences the enrollment setup/confirm arms run,
      `totp.go:124-153`/`306-334` — a concurrent password change or identity
      transition between the login's password read and this commit fails the
      login closed; r3's "preserve the existing credential and identity
      fences").
   3. Cohort evaluation inside the tx (§1.2): SELECT `totp_enabled` OR EXISTS
      non-revoked `uv_capable` credential.
   4. Sign the token with a pre-generated JTI via
      `IssueMFAPendingWithFencesJTI` (signing is pure CPU; the token string
      exists before any DB write).
   5. **C2/C3 only**: INSERT the bootstrap grant into `mfa_reauth_step_ups` in
      the SAME tx: `{token_hash = SHA-256(mfa_token), user_id,
      session_jti = jti, operation = 'bootstrap.totp.enroll', proof_method =
      'password', proving_factor_id = NULL, bound_factor_generation =
      users.factor_generation, token_scope = 'mfa_pending',
      refresh_family_id = NULL, target_ref = NULL, expires_at = now() + 5
      min}` (delete any prior grant rows for the user first, the
      `mfa_reauth.go:146-149` convention). The grant's presentation secret IS
      the mfa_token itself — hash-only storage is preserved (V271 posture,
      `V271__mfa_reauth_step_ups.sql:37-41`), no second opaque secret is added
      to the wire, and the response shape at `auth.go:743-748` is unchanged.
      **C1 (UV-capable passkey holder)**: NO password grant is inserted; the
      response still carries `mfa_token` (the ceremony begin needs its JTI),
      and the grant is minted later by the `webauthn_uv` management-ceremony
      finish (§1.4) with `token_scope='mfa_pending'`, `session_jti` = the
      pending JTI, `proof_method='webauthn_uv'`, `proving_factor_id` = the
      proving credential ID — that finish transaction is the C1 bootstrap
      issuance point.
   6. `COMMIT`. Only after commit does the handler write the response. Any
      failure (fence, insert, commit) → 500, token never returned: a client
      never holds an `mfa_token` whose bootstrap grant did not commit. This is
      the "same transaction as the scope token" contract, adapted to a
      stateless JWT: the grant row and the token's return are atomic, and the
      row binds {JTI, user, operation='bootstrap', no target} from birth.
3. **Consumption** (`/auth/totp/enroll/setup|confirm`, §1.6) peeks/consumes by
   `{token_hash = SHA-256(presented mfa_token), user_id, session_jti =
   claims.JTI, operation, token_scope}` — the exact tuple predicates
   `peekMFAReauth`/`consumeMFAReauth` already apply (`mfa_reauth.go:169-188`,
   `194-212`), plus the new columns.

The request/response contract is otherwise today's: the unauthenticated
`POST /auth/totp/enroll/setup` body `{"mfa_token":"..."}` (`totp.go:110-121`)
gains an `enrollment_id` response member and `POST /auth/totp/enroll/confirm`
(`totp.go:239-252`) gains a required `enrollment_id` request member (§1.6).
`BearerAuthenticator` never sees these tokens (`authenticator.go:142` rejects
non-access types), and no bearer-mount change is needed — resolving r3's
observation that the mapped `/auth/mfa/reauth` issuer cannot serve bootstrap
(`cmd/authserverd/main.go:1053` + `authenticator.go:142`): bootstrap issuance
moves to the login flow where the proof already happened.

### 1.6 Begin-vs-finish transitions per flow (v4: distinct enrollment IDs, one-time binding, staged provenance)

r3 finding 2: v3's `totp_pending_enrollments` had only `user_id` as identity
and no transition assigning a target to a grant. v4 fixes both:

**Pending-enrollment table (§2.1 migration 2)** — each enrollment is a row with
its own UUID:

```
id             uuid PRIMARY KEY DEFAULT gen_random_uuid()
user_id        bigint NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
secret_enc     bytea NOT NULL
staged_by_jti  text NOT NULL      -- JTI of the token that ran setup (access
                                  -- JTI or mfa-pending JTI): staged provenance
staged_via     text NOT NULL DEFAULT 'unknown'  -- advisory audit-only surface tag
created_at     timestamptz NOT NULL DEFAULT now()
expires_at     timestamptz NOT NULL  -- 15 minutes; abandonment expiry
```

`user_id` UNIQUE keeps one live pending enrollment per user (today's
"latest secret wins" replay shape, `authn/totp.go:186-188`, is preserved at the
storage layer), but **each setup mints a NEW id**: repeated setup is
`INSERT ... ON CONFLICT (user_id) DO UPDATE SET id = gen_random_uuid(),
secret_excluded..., staged_by_jti = excluded..., created_at = now(),
expires_at = ... RETURNING id` — the previous enrollment ID stops resolving the
moment a newer setup commits.

**One-time atomic grant binding at the begin arm.** The begin arm (setup /
register-begin) runs, in one transaction that also creates the pending
enrollment / ceremony row (and applies the fences for `mfa_pending` scope):

```sql
UPDATE mfa_reauth_step_ups
   SET target_ref = $enrollment_or_ceremony_id
 WHERE token_hash = $1 AND user_id = $2 AND session_jti = $3
   AND expires_at > now() AND target_ref IS NULL
RETURNING token_hash
```

The `target_ref IS NULL` guard under the row lock makes the binding one-time
and atomic: exactly one begin can bind a given grant. Outcomes:

- **First begin**: row returned → binding committed; the enrollment/ceremony
  row is created with `staged_by_jti` = the presenting token's JTI; the
  response returns `enrollment_id` (TOTP) or the creation options (WebAuthn).
- **Repeated begin on the SAME grant (resume)**: if `target_ref` is already
  bound AND the bound enrollment row is live AND its `staged_by_jti` equals the
  presenting token's JTI, the begin arm is a **resume**: TOTP re-derives the
  provisioning URI from the SAME pending secret (retry-after-network-loss
  works; no second secret is minted, no re-binding occurs); WebAuthn
  registration answers 200 with the live ceremony's `challenge_hash` binding
  status and the client reuses its already-issued creation options and
  `wa_reg_sess` cookie — no second ceremony is minted for a bound grant.
- **Repeated begin that would re-bind (setup B after setup A on one grant)**:
  the UPDATE matches zero rows with `target_ref IS NOT NULL` and no resumable
  live enrollment → typed 409 problem (`proof_already_bound`); the client must
  re-prove (new grant) to stage a different enrollment. This is deliberate
  fail-closed strictness under option (a): one proof authorizes exactly one
  staged target.
- **Grant dead (expired/consumed/replaced)**: zero rows → the existing typed
  403 `reauth_required` (`mfa_reauth.go:96-105`).

**Confirm/promotion references the binding.** The confirm/promotion arm
requires the client to present the `enrollment_id` it received from setup and
validates, inside the promotion transaction (§2.2): grant row live with
`target_ref = presented enrollment_id`; pending row `id = presented
enrollment_id AND user_id = $user AND staged_by_jti = claims.JTI`; then it
verifies the code against THAT row's secret, deletes it, promotes, and consumes
the grant. Every stale combination refuses by construction:

- (new grant, old ID) — `target_ref` mismatch (bound to the new ID).
- (old grant, old ID) — pending row `id` no longer exists (replaced by the new
  setup's row).
- (any grant, ID staged by a different session) — `staged_by_jti` mismatch.

This gives r3's "wrong pending-enrollment ID" case a concrete, exerciseable
identifier: the UUID returned by setup.

| Flow | Begin arm | Finish arm |
|---|---|---|
| TOTP enroll/replace (session) | `GET /auth/totp/setup` — **peeks** the grant, performs one-time binding, writes pending row, returns `enrollment_id` | `POST /auth/totp/confirm` — validates binding + `enrollment_id`, **consumes** grant before activation (V271 peek/consume semantics, `totp.go:84,426`) |
| TOTP bootstrap (`mfa_pending`) | `POST /auth/totp/enroll/setup` — peeks the `mfa_pending` grant, binding + pending row under the enrollment fences | `POST /auth/totp/enroll/confirm` — consumes grant in the promotion tx |
| WebAuthn registration | `GET /auth/webauthn/register/begin` — peeks grant + one-time binding (`target_ref = challenge_hash`) + ceremony row | `POST /auth/webauthn/register/finish` — consumes ceremony row AND grant, then mutation |
| WebAuthn revoke / recovery regenerate / native device register | single-call — **consumes** grant before the mutation. `webauthn.revoke` has its target from the request, so `target_ref` = the credential ID is set AT ISSUANCE and consumption re-checks it against the presented `{id}`; `recovery.regenerate` and `device.register.native` carry `target_ref = NULL` | — |
| Management possession proof (C1) | dedicated assertion begin — creates challenge row | assertion finish — consumes row, issues grant |

### 1.7 State machine

States: `NONE` → `CEREMONY_LIVE` (WebAuthn ceremonies only) → `GRANT_LIVE` →
`TARGET_BOUND` (grant sub-state after §1.6 binding, where required) → terminal:
`CONSUMED`, `DEAD` (expired | invalidated | refused).

| State | Event | Guard | Action | Next state |
|---|---|---|---|---|
| NONE | proof begin (C1) | not impersonated; budget not locked (§2.3); cohort C1 | insert ceremony row; return assertion options | CEREMONY_LIVE |
| NONE | password reauth (C2/C3) | not impersonated; budget not locked; password verifies via `VerifyTOTPRemovalPassword` (`totp_removal.go:115-126`) | insert grant (`proof_method='password'`, cohort operation, generation bound, §1.8) | GRANT_LIVE |
| NONE | TOTP proof (C1) | not impersonated; budget not locked; enabled secret verifies + replay claim wins under row fence (§2.2) | insert grant (`proof_method='totp'`) | GRANT_LIVE |
| CEREMONY_LIVE | assertion/attestation finish | challenge row live; UV required; origin/RP ok; budget not locked | consume ceremony row; (assertion: insert grant; registration: proceed to promotion, §2.2) | GRANT_LIVE / CONSUMED |
| GRANT_LIVE | begin arm (gated flows) | full tuple + `target_ref IS NULL` | one-time binding + pending/ceremony row (§1.6) | TARGET_BOUND |
| TARGET_BOUND | begin arm, same grant + same JTI + live target | §1.6 resume rule | return same enrollment/options, no new rows | TARGET_BOUND |
| TARGET_BOUND / target-less GRANT_LIVE | gated-arm call | full tuple re-validates (§1.1) under row fence | consume row; mutate; bump `factor_generation`; success audit; commit | CONSUMED |
| GRANT_LIVE | gated-arm call | tuple mismatch (wrong purpose/target/pending ID, replay, expired, wrong session, generation advanced) | typed 403 `reauth_required`, audit refusal | DEAD (row deleted) |
| GRANT_LIVE | TTL elapsed | `expires_at <= now()` | row inert | DEAD |
| GRANT_LIVE | ANY factor mutation commits (enroll/replace confirm, registration, revoke, recovery regen, removal) | `users.factor_generation` advanced past `bound_factor_generation` (§1.8) | consumption-time re-check fails under fence | DEAD |
| GRANT_LIVE | logout / account switch / family or all revocation | `revoke_user_sessions` fires | reducer deletes grants AND ceremonies (§2.5) | DEAD |
| GRANT_LIVE | durable revocation row matches in the issuance/consumption tx | §2.2 step 0 recheck | refusal | DEAD |
| GRANT_LIVE (`password`, C3) | account gains first possession factor | first C1/C2 factor exists | delete unconsumed password grants (v2 §1) | DEAD |
| GRANT_LIVE | refresh rotation | rotation mints a NEW access JTI (`refresh.go:285,369`); grant keeps original JTI binding | no action — refreshed client's JTI differs, grant unusable from the new token; old pair bounded by the 5-minute TTL (§2.5) | GRANT_LIVE |
| any | impersonated bearer (`claims.AdminActorID != nil`, `jwt.go:413-436`; `mustUser` passes claims through, `handlers/auth.go:3351-3358`) | — | refuse unconditionally at issuance AND every consumption, incl. the V250 removal flow (r2 disposition) | NONE |

### 1.8 Factor generations and target lifecycle (v4 — full spec; replaces v3's version markers)

**Model: ONE per-user counter, `users.factor_generation bigint NOT NULL
DEFAULT 0`** (forward migration, §2.1). Chosen over per-factor generation
columns; justification from the code:

1. **TOTP has no per-factor identity to hang a generation on.** It is a
   single per-user factor living directly on the `users` row
   (`totp_enabled`/`totp_secret_enc`; enabled by `ConfirmTOTP`'s guarded
   enable, `authn/totp.go:278-292`; wiped by `DisableTOTPWithStepUp`,
   `totp_removal.go:230-247`). A per-TOTP generation would be another users
   column — i.e. the per-user counter anyway.
2. **The grant store is already single-live-row-per-user** (issuance deletes
   all prior rows, `mfa_reauth.go:146-149`). Per-factor granularity could only
   benefit a grant that survived an unrelated factor mutation; at most one
   grant per user exists, so there is no beneficiary. Collateral damage of a
   global bump is bounded: the single outstanding grant dies and the user
   re-proves once.
3. **Every issuance/consumption/mutation transaction already serializes on the
   `users` row** (§2.2 lock order) — reading and incrementing a users-column
   generation rides the existing lock chain with zero new locking. Per-factor
   generations on `passkey_credentials` would force factor-row reads into
   TOTP-proof issuance transactions.
4. **Only a mutation-only marker has the right dynamics** (r3 finding 1):
   `last_totp_used_at` moves on use — including the replay claim inside
   issuance itself (`authn/totp.go:127-135`) — and `sign_count` moves on
   ordinary login (`authn/webauthn.go:188-192`); both invalidated v3's grants
   spuriously. The generation counter NEVER moves on use.

**Increment rule — transactionally, in the SAME UPDATE as the mutation, inside
the promotion/mutation transaction (§2.2), on EVERY factor mutation:**

- TOTP first-enrollment confirm and replace confirm (`bootstrap.totp.enroll`,
  `totp.enroll`, `totp.replace` promotion tx, §2.2);
- WebAuthn registration finish — including same-ID re-registration, whose
  `ON CONFLICT (id) DO UPDATE` swaps the public key in place
  (`authn/webauthn.go:287-294`);
- WebAuthn revoke (`RevokeCredential`'s new fenced tx, §2.2);
- recovery-code regeneration (`GenerateBackupCodes`,
  `handlers/mfa.go:31,39`);
- the V250 removal wipe (`DisableTOTPWithStepUp`,
  `totp_removal.go:230-247`) — removal mutates the factor set even though it
  is not re-gated by this scheme (§3 exception row);
- native device registration (`device.register.native` mutation) — devices are
  approval capability, not proving factors, but the gate consumes a grant in
  the same tx and the bump is free and uniform.

Mechanically the promotion statement appends
`factor_generation = users.factor_generation + 1` to the factor-mutating UPDATE
(e.g. `ConfirmTOTP`'s guarded enable gains the column; zero-rows guard
unchanged). WebAuthn replaces bump via a dedicated
`UPDATE users SET factor_generation = factor_generation + 1 WHERE id = $1`
inside the persist tx.

**Bind and check rule:**

- Every grant binds `bound_factor_generation = users.factor_generation` read
  inside its issuance transaction (§2.2), under the same fence.
- Every peek and consumption re-reads `users.factor_generation` under the same
  fence and requires equality with `bound_factor_generation` (§1.1). Because
  both reads happen inside transactions holding the users fence, the compare
  is race-free: a mutation either commits before the check (mismatch →
  refusal) or after it (the mutation's own serial ordering decides).

**Consequences (named):**

- A `totp.replace` grant survives its own issuance and the setup arm: issuance's
  replay claim advances `last_totp_used_at` but not the generation; ordinary
  logins advance neither. The grant dies only when the replacement promotion
  (which consumes it) or any OTHER mutation commits.
- Same-ID key replacement (r3-named) invalidates every outstanding grant,
  including any proven by the replaced credential's OLD public key, even though
  the credential ID is unchanged.
- Revoking passkey A also kills an outstanding grant proven by passkey B —
  accepted deliberately per justification 2 (single live grant; one re-proof).
- Replacement no longer invalidates its own grant, and the setup arm's extra
  proof is reconciled: **the grant subsumes the `current_totp_code` check.**
  v3 kept the replacement arm's second TOTP verification
  (`handlers/totp.go:63-74`); r3 finding 1 flagged the resulting conflict. v4
  deletes that arm for gated accounts: a valid `totp.replace` grant was earned
  by verifying a current code against the ACTIVE secret inside the fenced
  issuance tx (§2.2) — a strictly stronger check than the old pool-level
  `VerifyTOTPWithLockout` read (`totp.go:63`), and the only callers of the old
  arm (TOTP-enabled accounts) are all C1-gated under v4. C2/C3 accounts have no
  enabled TOTP by cohort definition (§1.2), so no ungated gap is created. The
  5-failure lockout funnel stays on the issuance path (§2.3), where replacement
  codes are actually verified.

---

## 2. Database authority

### 2.1 Forward migration (one version, named objects)

1. `ALTER TABLE mfa_reauth_step_ups ADD COLUMN operation text NOT NULL,
   target_ref text, proof_method text NOT NULL, proving_factor_id bytea,
   bound_factor_generation bigint NOT NULL, token_scope text NOT NULL DEFAULT
   'session', refresh_family_id text` — existing unconsumed password-only rows
   are **DELETED** at migration time (owner clean cut, v2 §7; pre-GA).
2. `CREATE TABLE totp_pending_enrollments (...)` per §1.6 (UUID PK, `user_id`
   UNIQUE, staged provenance columns, expiry).
3. `ALTER TABLE passkey_credentials ADD COLUMN uv_capable boolean NOT NULL
   DEFAULT false` (§1.2).
4. `CREATE TABLE webauthn_ceremonies (...)` per §1.4 (including
   `refresh_family_id` and the real-JTI `session_jti`).
5. `ALTER TABLE users
   ADD COLUMN factor_generation bigint NOT NULL DEFAULT 0,                      -- §1.8
   ADD COLUMN possession_password_failed_attempts integer NOT NULL DEFAULT 0,   -- §2.3
   ADD COLUMN possession_password_locked_until timestamptz,                     -- §2.3
   ADD COLUMN possession_webauthn_failed_attempts integer NOT NULL DEFAULT 0,   -- §2.3
   ADD COLUMN possession_webauthn_locked_until timestamptz`                     -- §2.3
   (the existing `users.totp_failed_attempts`/`totp_locked_until` pair,
   `V001__baseline.sql:5877-5878`, remains the TOTP proof-method counter).
6. Reducer/mount wiring for §2.5 (updated `revoke_user_sessions` in its own
   migration).

### 2.2 Canonical lock ordering (v4: person fence unified, durable revocation recheck added)

Every transaction that issues, consumes, or mutates factor state acquires, in
order, holding to commit (no lock is ever acquired out of sequence):

0. **`identity_auth_person_fence(user)`** — the per-user advisory transaction
   lock the session-revocation boundary already takes
   (`mailserver/sql/reducers/revoke_user_sessions.sql:39`; primitive at
   `mailserver/sql/reducers/identity_auth_local_mint_fence.sql:6-24`). v3 named
   the users row lock "canonical" but `revoke_user_sessions` never takes it —
   r3 finding 4 called this a split fence. v4 unifies: revocation and
   factor-state work serialize on the SAME advisory lock first, so a committed
   revocation is always visible to a later issuance/consumption and an
   in-flight issuance/consumption always finishes before a revocation proceeds.
1. **`users` row fence** — `SELECT ... FOR NO KEY UPDATE` (the mode
   `ConfirmTOTP`/`ConfirmTOTPEnrollmentTx` already use,
   `authn/totp.go:258-266,333-347`; `FOR UPDATE` as used by the V250 removal,
   `totp_removal.go:218-222`, conflicts with it, so both serialize).
2. **factor rows** — `passkey_credentials` / `push_devices` rows for the target
   credential/device.
3. **proof-artifact rows** — grant consumption (`DELETE ... RETURNING`) and
   ceremony consumption, last.

Plus, inside every issuance and consumption transaction, after the fence and
before any state change, a **durable revocation recheck** (r3 finding 4: the
request-time denylist at `authenticator.go:146-155` is an earlier in-memory
check, not a durable one inside the tx):

```sql
SELECT EXISTS (SELECT 1 FROM session_revocations
                WHERE user_id = $1
                  AND (scope = 'all'
                       OR (scope = 'family' AND family_id = $2)
                       OR (scope = 'jti'    AND jti = $3))
                  AND (expires_at IS NULL OR expires_at > now()))
```
against `session_revocations` (`V055__cae_runtime_core.sql:9-24`), `$2` being
the presented token's family (NULL-safe) and `$3` its JTI. A matching row
refuses; nothing partial commits. Deleting artifacts during revocation (§2.5)
removes the row itself; this recheck additionally refuses any artifact-creating
request that was already admitted when revocation committed.

Consequences, named against today's code:

- **Consumption + promotion + audit in ONE transaction** (r2 fix plan 2),
  wrapped in the existing **caller-owned-transaction pattern**
  (`ConfirmTOTPEnrollmentTx`, `authn/totp.go:324-410`, which "never commits"
  and lets the fenced completion own the commit via `MintTx` +
  `commitDeferredTokenResponse`, `handlers/totp.go:379-393`; single-tx shape
  precedent: `DisableTOTPWithStepUp`, `totp_removal.go:191-258`). The
  transaction = person fence → users fence → re-validate tuple + generation +
  proving factor + durable revocation → mutate factor (TOTP enable +
  generation bump, passkey insert/revoke, recovery rotate, device insert) →
  audit insert → commit. TOTP promotion specifically: verify code against the
  bound `totp_pending_enrollments` row (§1.6), then in-tx delete the pending
  row + set `users.totp_secret_enc` + `totp_enabled = TRUE` +
  `factor_generation = factor_generation + 1` + consume grant + audit.
- **Issuance verification serializes against factor changes** (r1 finding 2):
  TOTP proof verification for grant issuance runs its secret read + replay
  claim on the SAME transaction holding the users fence — the seam already
  exists (`totpVerifyStore`, `authn/totp.go:75-90`); this closes the
  read-secret-then-claim window r1 identified in `verifyTOTPCore` callers.
- **Passkey revocation gains the fence**: `RevokeCredential` is today a bare
  `UPDATE passkey_credentials` (`webauthn.go:198-204`); under v4 it runs
  inside the person+users-fence transaction with grant re-validation and a
  generation bump, closing the consume-vs-revoke race r2 finding 1 named.
- Cancellation/abandonment: deleting the `totp_pending_enrollments` row (or
  letting `expires_at` lapse) leaves the active factor untouched — repair of
  today's behavior where replacement setup overwrites the live secret
  (`authn/totp.go:170-175`), whose confirm can then never re-enable an enabled
  row (`totp.go:283-284` guard matches zero rows). The pending-table split
  fixes both; no compatibility shims.

### 2.3 Failure budgets — storage, transaction behavior, oracle (v4 — full spec; replaces v3 §2.3)

**Counter model (chosen): one counter pair per proof method.** The proof
methods are exactly `password | totp | webauthn_uv` (§1.1). TOTP already owns a
per-method pair on `users` (`totp_failed_attempts`/`totp_locked_until`,
`V001__baseline.sql:5877-5878`; policy at `authn/totp.go:418-424`), so v4 adds
the two missing pairs rather than sharing one:

| Method | Counter columns | Threshold / lock |
|---|---|---|
| `password` | `users.possession_password_failed_attempts` / `possession_password_locked_until` | 5 / 15 min |
| `webauthn_uv` | `users.possession_webauthn_failed_attempts` / `possession_webauthn_locked_until` | 5 / 15 min |
| `totp` | `users.totp_failed_attempts` / `totp_locked_until` (existing) | 5 / 15 min (existing, `totp.go:418-424`) |

This resolves v3's contradiction (one shared pair in the migration vs
per-method policy, r3 finding 5). Independent lockouts also keep a password
failure storm from locking out WebAuthn recovery and vice versa. Thresholds and
durations reuse the existing constants' values (`totpMaxFailures = 5`,
`totpLockDuration = 15 * time.Minute`, `totp.go:418-424`); the pure decision
shape stays `NextTOTPLockout` (`totp.go:431-438`).

**Transaction behavior.** Budget check, proof verification, and counter
write all live INSIDE the issuance transaction (§2.2 lock order: person fence →
users fence). The increment is a SINGLE atomic statement — this is the
specified form for every counter, and it is also the repair of
`RecordTOTPFailure`'s read-then-write lost update
(`authn/totp.go:467-473` writes a previously-read absolute count):

```sql
UPDATE users
   SET possession_password_failed_attempts = possession_password_failed_attempts + 1,
       possession_password_locked_until =
         CASE WHEN possession_password_failed_attempts + 1 >= 5
              THEN now() + interval '15 minutes'
              ELSE possession_password_locked_until END
 WHERE id = $1
   AND (possession_password_locked_until IS NULL
        OR possession_password_locked_until <= now())
RETURNING possession_password_failed_attempts, possession_password_locked_until
```

(`password` / `webauthn` column names swap per method; the TOTP counter is
migrated to the same single-statement form — r3 explicitly noted that writing
the NEW counters does not by itself repair the existing shared TOTP writers.
`VerifyTOTPWithLockout`'s failure write (`totp.go:518`) and
`ConfirmTOTPEnrollmentTx`'s (`totp.go:368-374`, serialized by its fence at
`:345` but aligned anyway) both switch to the atomic form.)

Semantics pinned by the statement:

- **Evaluated failures** (a proof actually verified against a secret and
  rejected) increment. **Locked refusals do not**: once
  `possession_*_locked_until > now()`, the WHERE guard matches zero rows, the
  attempt is refused as locked, and the counter does not move — refused
  bookkeeping is committed as a refusal, never as a failure increment.
- **Success resets** are part of the same issuance transaction
  (`possession_*_failed_attempts = 0, possession_*_locked_until = NULL`, the
  `ResetTOTPLockout` shape, `totp.go:476-481`) — there is no "accepted
  alongside a reset error" state (r3's contrast with `totp.go:524`): a reset
  failure rolls the whole issuance back.
- **Fail-closed bookkeeping**: any DB error at the lock-state read, the
  increment, or the reset aborts the issuance transaction → 500, NO grant,
  counters unchanged (rolled back). This repairs `VerifyTOTPWithLockout`'s
  fail-open load (`totp.go:511` discards the load error) for the management
  path structurally (the path no longer uses the pool-level seam; §2.2
  in-tx verification), and the login-path seam is repaired to map bookkeeping
  errors to a distinct refusal outcome rather than proceeding or returning
  acceptance-with-error.
- A locked budget refuses issuance with 429 (matching `ErrTOTPLocked`
  handling, `handlers/totp_removal.go:59-61`); a lock-state read error refuses
  with 500 — issuance never proceeds on unknown state.

**Oracle rule: the acceptance tests' expected outcomes are defined from THIS
storage spec alone.** For N ≥ 5 concurrent failed proofs of one method, all
arriving before any lock exists: the fence serializes them; the first 5 are
evaluated failures (counter passes 1..5, lock timestamp set by the 5th), and
every later request is a locked refusal that leaves the counter at exactly 5.
Expected assertions: `possession_*_failed_attempts = 5`, lock timestamp set,
exactly `N - 5` locked refusals, zero grants issued. For N < 5: counter = N,
no lock. A bookkeeping fault test asserts refusal + preserved state (counter
and lock exactly as before the attempt, no grant row).

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
  (`mailserver/sql/reducers/revoke_user_sessions.sql:1-7`; it already takes
  `identity_auth_person_fence` at `:39`, which §2.2 makes the shared fence).
  v4 extends it (same transaction, per the reducer's boundary contract):
  scope `all` deletes ALL the user's `mfa_reauth_step_ups` rows and
  `webauthn_ceremonies` rows; scope `family` deletes rows whose
  `refresh_family_id` matches (grants AND ceremonies — v3 named the ceremony
  deletion but gave the ceremony schema no family column; v4 supplies the
  binding, §1.4); scope `jti` deletes rows whose `session_jti` matches.
  Defense in depth: the denylist refuses revoked (user, jti, family) bearers
  at request authentication (`authenticator.go:146-155`), and §2.2's durable
  in-tx recheck refuses anything already admitted.
- **Refresh** (r2 finding 6 + named acceptance case): rotation replaces the
  refresh row (`refresh.go:285`) and mints a new access token — a NEW JTI,
  same family (`refresh.go:307-392`, new access at `:369`, successor INSERT at
  `:385`). The grant keeps its ORIGINAL JTI, so the refreshed client must
  re-prove (v2 §6 "grants are NOT refreshed" holds; JTI binding is not
  loosened). The retained old-access-token + grant pair is real (the old
  access token is not revoked by rotation) and is bounded by the 5-minute
  grant TTL and the access token's own lifetime; it grants no power beyond the
  session that already held both. §4 names the test that pins this behavior.
- **Proving-factor revocation/replacement**: consumption re-validates
  `proving_factor_id` + `bound_factor_generation` under the fences (§1.1,
  §1.8); every mutation's generation bump deterministically kills outstanding
  grants, and revocation paths additionally best-effort-delete outstanding
  grants as immediate cleanup.
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
| `POST /auth/mfa/reauth` (main.go:1053) | `MFAReauthBegin`, `handlers/mfa_reauth.go:228` | issuance only (not a mutation) — session-scope grants (C2/C3 password, and the C3 `totp.enroll` grant) | webmail `auth.ts:684` (`beginMFAReauth`); native | `password` (C2/C3); C1 accounts get a method-aware refusal naming possession options. **Bootstrap issuance does NOT live here** (bearer mount rejects `mfa_pending`, `authenticator.go:142`); it lives in the login flow (§1.5.1) |
| `GET /auth/totp/setup` (main.go:1035) | `TOTPSetup`, `handlers/totp.go:31` | `totp.enroll` (peek) / `totp.replace` (peek) | webmail both settings pages (`auth.ts:733`; `settings/+page.svelte:427`) | `password` \| `totp` \| `webauthn_uv` per cohort. **v4: the separate `current_totp_code` verification is removed** — the grant subsumes it (§1.8 last bullet); the arm performs only the peek + one-time binding (§1.6) |
| `POST /auth/totp/confirm` (main.go:1037) | `TOTPConfirm`, `handlers/totp.go:407` | `totp.enroll`/`totp.replace` (consume + promote) | same | same, consumed here; requires the setup-issued `enrollment_id` (§1.6) |
| `POST /auth/totp/enroll/setup` (main.go:1024) | `TOTPEnrollmentSetup`, `handlers/totp.go:110` | `bootstrap.totp.enroll` (peek, `mfa_pending` scope) | webmail login/enrollment flow (`auth.ts:772`) | C3/C2: `password` bootstrap grant minted at login (§1.5.1); passkey-holder (C1): `webauthn_uv` ceremony bound to the MFA-pending JTI (§1.5); refusal otherwise |
| `POST /auth/totp/enroll/confirm` (main.go:1025) | `TOTPEnrollmentConfirm`, `handlers/totp.go:239` | `bootstrap.totp.enroll` (consume + promote) | same (`auth.ts:784`) | same, consumed in the promotion tx; requires `enrollment_id` (§1.6) |
| `GET /auth/webauthn/register/begin` (main.go:1011) | `WebAuthnRegisterBegin`, `handlers/webauthn.go:22` | `webauthn.register` (peek + one-time binding + ceremony create) | webmail `settings/+page.svelte:366`; native | per cohort; **bearer-only registration refused** (owner decision) |
| `POST /auth/webauthn/register/finish` (main.go:1013) | `WebAuthnRegisterFinish`, `handlers/webauthn.go:51` | `webauthn.register` (consume ceremony + grant, persist) | same | same, consumed |
| `DELETE /auth/webauthn/credential/{id}` (main.go:1020) | `WebAuthnRevokeCredential`, `handlers/webauthn.go:329` | `webauthn.revoke` (consume) | webmail; native | per cohort, `target_ref` = credential ID (`decodeCredentialID`, `webauthn.go:319-326`) |
| `POST /auth/backup-codes/generate` (main.go:1093) | `GenerateBackupCodes`, `handlers/mfa.go:31` | `recovery.regenerate` (consume) | webmail `auth.ts:702`, security page; native | per cohort, EVERY account (V271 posture kept) |
| `POST /auth/device/register` (main.go:1075) | `DeviceRegister`, `handlers/device.go:95` | `device.register.native` (consume) — **native providers `apns`/`fcm`/`hms` only** | native clients | per cohort. **Distinction (r2 fix plan 3):** native registrations are authentication devices — they carry `device_public_key`, receive ECIES number-match challenges and are the only devices `dispatchToNativeDevices` selects (`authn/push.go:445-448`) and `/auth/mfa/approve` accepts (`device.go:19-25`). `provider = 'webpush'` rows are WebPush notification **subscriptions** — delivery keys that never answer approvals (`authn/push.go:415-423`) — and are NOT gated |
| `POST /auth/totp/remove/begin` (main.go:1044) + `POST /auth/totp/remove` (main.go:1045) | `TOTPRemovalBegin`/`Confirm`, `handlers/totp_removal.go:28,93`; decision table `authn/totp_removal.go:45-110`; removal tx `totp_removal.go:191-258` | **EXPLICIT EXCEPTION** — V250 decision table remains authority (password+current TOTP; authenticator-lost → password+non-consuming recovery-code check `totp_removal.go:133-147`; no codes → self-service refusal to admin/support) | webmail `auth.ts:810,827`, security page | not re-gated by this scheme; recovery codes are break-glass, not possession proofs (v2 §4). Impersonation rejection (§1.7 last row) IS applied here per the r2 disposition; the removal tx bumps `factor_generation` (§1.8) |
| `PUT /auth/webauthn/credential/{id}/name` (main.go:1019) | `WebAuthnNameCredential`, `handlers/webauthn.go:275` | out of scope — metadata rename, no factor-set change | webmail | not gated |
| `GET /auth/webauthn/credentials` (main.go:1018) | `WebAuthnListCredentials`, `handlers/webauthn.go:355` | read-only | webmail | not gated |

Not gated (login/second-factor completion, no factor-set change):
`POST /auth/totp/verify` (`handlers/totp.go:183`),
`POST /auth/backup-codes/verify` (`main.go:1095`),
`POST /auth/push/verify` / `POST /auth/push/send` / `POST /auth/push/status`
(main.go:1057-1064), `POST /auth/mfa/approve` (main.go:1079),
`/auth/webauthn/login/*` (main.go:1016-1017), forgot-password arms
(main.go:1099-1101).

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
  method-aware reauth store functions (`auth.ts:733-770`), and confirm calls
  carry the setup-issued `enrollment_id` (§1.6), so every gated call
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

Named cases per layer. "DB/bookkeeping" failures are injected at the named
statement. Existing tests that expect ungated factor-holder enrollment or
password-only regeneration are deliberately revised (r1 fix plan 5); ordinary
login compatibility tests are retained.

### 4.1 DB race/fault tests (exercise the named concurrency)

| Test | Concurrency/fault exercised |
|---|---|
| `TestGrantConsumeExactlyOnceConcurrent` | two transactions racing the `DELETE ... RETURNING` consumption + mutation → exactly one commits, second refuses with factor intact (V250 pattern, `totp_removal.go:204-216`) |
| `TestRevokeVsConsumeRace` | passkey revocation vs grant consumption interleaved before-verify / during-verify / before-commit — §2.2 ordering (person fence → users fence → artifacts) makes every interleaving converge refused-or-consistent; pins the closure of the `webauthn.go:198-204` fence-less update |
| `TestTOTPReplaceStagedAndCancellable` | replacement setup writes only `totp_pending_enrollments`; cancellation/abandonment preserves the ACTIVE secret and codes; promotion swaps atomically (r2-named case: cancellation preserving active TOTP) |
| `TestAssertionReplaySingleGrant` | one replayed assertion replayed against assertion-finish: ceremony row single-use → at most one grant ever (r2-named case; r2 finding 4) |
| `TestProofBudgetSerializedUnderLoad` | **v4 oracle (from §2.3 storage alone):** N = 8 concurrent failed password proofs → counter EXACTLY 5, lock timestamp set by the 5th, exactly 3 locked refusals that do NOT increment, zero grants issued. (Corrects v3's "exactly N", r3 finding 5.) Same assertions for the `webauthn_uv` counter; TOTP counter pinned by the migrated single-statement writer vs today's lost update (`authn/totp.go:467-473`) |
| `TestBudgetBookkeepingFaultRefusesAndPreserves` | fault injected at the budget state read (and, in variants, at the increment / reset) inside the issuance tx → 500, NO grant row, counter and lock state EXACTLY as before the attempt (fail-closed + preserved state; contrasts `VerifyTOTPWithLockout`'s fail-open load, `totp.go:511`, and accepted-alongside-reset-error, `totp.go:524`) |
| `TestBudgetLockedRefusalDoesNotIncrement` | while `possession_*_locked_until > now()`: refused attempts leave the counter and lock untouched (§2.3 WHERE guard) — distinguishes evaluated failures from locked refusals in the oracle |
| `TestGrantAuditFaultRollsBackAll` | DB/bookkeeping fault at the audit insert (§2.4) → mutation, grant consumption, generation bump AND audit all roll back; nothing partial commits |
| `TestTOTPProofVsFactorChangeRace` | issuance-time TOTP verify on the fenced tx vs concurrent disable/replace — no accepted proof against a revoked/replaced secret (r1 finding 2 closed) |
| `TestGenerationBumpKillsOutstandingGrant` | grant live at generation G; any §1.8 mutation commits G+1 in a parallel tx; consumption of the G-grant refuses under the fence (§1.8 check rule) |

### 4.2 Handler/mux tests

| Test | Asserts |
|---|---|
| `TestBearerOnlyWebAuthnRegisterRefused` | begin/finish without a live grant → typed 403 `reauth_required` (`mfa_reauth.go:96-105` shape) — the owner decision's negative case |
| `TestPasswordOnlyRefusedWhenPossessionRequired` | C1 account + password grant → refused at every §3 endpoint |
| `TestWrongPurposeTargetPendingRefused` | grant bound to operation/target A presented at B → refusal. Now concrete (§1.6): wrong pending-enrollment UUID (present setup A's ID to grant bound to B, and the dead-ID combinations), wrong `target_ref` credential, wrong ceremony |
| `TestCrossAccountCeremonyRefused` | ceremony/grant of user A on user B's session → refusal (user/JTI predicates, §1.4) |
| `TestStaleExpiredCeremonyRefused` / `TestProofAndCeremonyExpiryIndependent` | ceremony row dead but grant live, and vice versa → both refuse; TTLs independent |
| `TestMissingUVRefused` | management assertion without UV → refusal (server-side requirement, §1.4) |
| `TestWrongChallengeOriginRPRefused` | assertion against wrong challenge/origin/RP → refusal (go-webauthn config, `webauthn.go:36-41`) |
| `TestImpersonationRefusedIssuanceAndConsumption` | `AdminActorID` bearer (`jwt.go:413-436`) refused at `/auth/mfa/reauth`, every gated arm, and the V250 removal begin/confirm, even with valid evidence |
| `TestNormalizedNonUVCredentialCohort` | non-UV normalized credential + no TOTP → C2 password step-up; UV assertion against it not usable as proof; failed/cancelled UV never reclassifies (r2-named case) |
| `TestRefreshRetainsOldPairBounded` / `TestRefreshNewJTIRefused` | after rotation: old access token + its grant consumable only within the 5-minute TTL (documented, §2.5); NEW access token + old grant refused on JTI mismatch (r2-named retained-pair case) |
| `TestSessionReplacementAndLogoutInvalidate` | family revocation via `revoke_user_sessions` deletes grants (and ceremonies, §2.5); replaced session cannot consume |
| `TestFirstFactorPasswordGrantInvalidAfterPossessionEnrolls` | C3 password grant dies when the account gains its first possession factor |
| `TestBootstrapGrantIssuedAtomicallyWithScopeToken` | C3 login → `enrollment_required` response carries `mfa_token` ONLY if the bootstrap grant row committed in the same tx (§1.5.1): fault the grant INSERT → 500, no `mfa_token` in any response, no row; committed case → row holds {SHA-256(mfa_token), pending JTI, operation `bootstrap.totp.enroll`, scope `mfa_pending`, NULL target, current generation} |
| `TestBootstrapPasskeyHolderRequiresUVProof` | passkey-only (UV-capable) account in mandatory enrollment (`auth_policy.sql:99-117` routing) gets NO password bootstrap grant at login (§1.5.1 step 5); `enroll/setup` with the bare `mfa_token` refuses; the UV ceremony mints the `webauthn_uv` `mfa_pending` grant; C3 zero-factor password bootstrap still works end-to-end (r2-named bootstrap-with-passkeys case) |
| `TestNativeDeviceRegisterGatedWebpushNotGated` | `apns`/`fcm`/`hms` registration needs a grant; `webpush` subscription registration does not, and never answers `/auth/mfa/approve` |
| `TestMutationInventoryComplete` | every §3 row refuses without the correct grant — guards against future ungated additions (incl. any future `push_mfa_enabled` setter, §3 note) |
| `TestExistingFlowsUnregressed` | TOTP/passkey/push/recovery login, conditional-access and DPoP completion guarantees behave exactly as today (`webauthn.go:200-272` CA leg, `completionMetadataForDPoP`) |

### 4.3 Browser lifecycle tests (per webmail surface)

- `/settings/security`: method-aware handoff — C1 offers WebAuthn-UV/TOTP,
  password only for C2/C3; retry-after-proof loops honestly
  (`+page.svelte:186-195`); expiry requires a NEW proof (no grant refresh).
- `/settings` (general): passkey registration (`:363`) and TOTP
  setup/confirm (`:427,439`) route through the shared handoff; confirm calls
  carry the setup-issued `enrollment_id`; returned secrets/recovery codes
  render only if the account identity is unchanged at response time (§3.1).
- Both surfaces: session replacement during a ceremony, refresh mid-ceremony,
  logout/account switch → pending enrollment UI drops, late responses
  discarded, next gated call re-runs the handoff.

### 4.4 r3-named additional acceptance cases (v4 — six, each executable as written)

**1. `TestTOTPReplaceEndToEndWithGrant` — successful TOTP-authorized
replacement end-to-end.**
*Setup:* C1 account with active TOTP (secret S1) and a second C1 method not
required; user session F/JTI₁.
*Steps:* (a) present a current S1 code at the C1 proof arm → issuance tx
verifies against ACTIVE secret under the fence, mints grant
{operation `totp.replace`, proof_method `totp`, bound_factor_generation G,
target NULL}; (b) `GET /auth/totp/setup` peeks grant, binds target_ref = E1,
inserts pending row (secret S2, staged_by_jti JTI₁), returns `enrollment_id`
E1 — assert `users.totp_secret_enc` STILL decrypts to S1 and `totp_enabled`
still TRUE; (c) `POST /auth/totp/confirm` with {code from S2, enrollment_id
E1} → promotion tx: pending row deleted, `totp_secret_enc` = S2,
`totp_enabled` TRUE, `factor_generation` = G+1, grant consumed, audit row —
all one commit.
*Expected:* replacement completes; between (a) and (c) the active factor was
never S2 (today's bug: setup overwrites immediately, `authn/totp.go:170-175`,
and confirm can then never match, `totp.go:283-284`); no `current_totp_code`
was required at (b) — the grant subsumed it (§1.8); old codes from S1 stop
verifying only after (c); any OTHER outstanding grant died at (c) via the
generation bump.

**2. `TestRepeatedSetupDistinctEnrollmentIDs` — old pending refused after a
new one is created.**
*Setup:* C1 account, two valid proofs available.
*Steps:* (a) proof 1 → grant G1; setup → E1 (secret S1'); (b) abandon. Proof
2 → grant G2 (issuance deletes G1's row, `mfa_reauth.go:146-149`); setup on
G2 → E2 (the `ON CONFLICT (user_id) DO UPDATE` mints a NEW uuid and replaces
the pending row, §1.6); (c) attempt confirm with {E1 + G2} → refused
(`target_ref` = E2 ≠ E1). Attempt confirm with {E1 + a re-minted G1-shaped
grant or the deleted row} → refused (grant row gone / pending id E1
unresolvable). Attempt setup again on G2 targeting a new enrollment → typed
409 `proof_already_bound` (§1.6). Retry setup on G2 with the SAME JTI while
E2 is live → resume, returns E2's URI unchanged.
*Expected:* exactly one live pending enrollment per user; every stale
(grant, enrollment) combination refuses with the factor untouched; only
{G2, E2} confirms.

**3. `TestOrdinaryFactorUseKeepsGrant` — ordinary factor USE during a grant's
lifetime.**
*Setup:* C1 account with active TOTP; unconsumed grant (e.g.
`recovery.regenerate`, proof `totp`) bound {JTI₁, generation G} on session
JTI₁.
*Steps:* (a) log in from a fresh browser context with password + a current
TOTP code — login verification runs `verifyTOTPCore` (replay claim updates
`last_totp_used_at`, `authn/totp.go:127-135`) and success resets the TOTP
lockout (`totp.go:476-481`); (b) also perform a passkey login for the
WebAuthn variant (sign_count update, `authn/webauthn.go:188-192`); (c) from
the ORIGINAL session JTI₁, consume the grant at `/auth/backup-codes/generate`.
*Expected:* (a) and (b) succeed with full tokens — ordinary use is never
blocked by an outstanding grant; the grant row is UNCHANGED (unconsumed, same
JTI binding, `bound_factor_generation` still G — use-writes touch
`last_totp_used_at`/`sign_count`/lockout columns only, never
`factor_generation`, §1.8); (c) succeeds within TTL. Conversely the NEW
login's tokens (new JTI) cannot consume the grant (§1.1 JTI binding) — that
negative is asserted in the same test.

**4. `TestSameIDKeyReplacementInvalidatesGrant` — WebAuthn credential
re-registration over the SAME credential ID.**
*Setup:* C1 account with UV credential C (id K, public key P1, uv_capable
TRUE); outstanding grant proven by C (bound {proving_factor_id K, generation
G}); attacker/user obtains a new attestation for id K with public key P2.
*Steps:* (a) second proof → `webauthn.register` grant; begin binds
target_ref = ceremony hash; (b) finish with the P2 attestation → persist tx:
`persistCredential`'s `ON CONFLICT (id) DO UPDATE` swaps public_key P1 → P2
scoped to the owner (`authn/webauthn.go:287-294`), ceremony + grant consumed,
`uv_capable` re-persisted from the new attestation, `factor_generation`
bumped to G+1 — one commit.
*Expected:* registration succeeds with the SAME credential ID; the
P1-era grant (bound at G) now refuses consumption (generation mismatch,
§1.1); an assertion signed with P1 (the old key) fails verification against
the swapped row; `uv_capable` reflects the NEW attestation's UV flag (a
non-UV re-registration reclassifies the credential to FALSE, cohort follows
§1.2 — and a non-UV same-ID replacement can never be used as a
`webauthn_uv` proof thereafter).

**5. `TestRevokeRacesIssuanceAndConsumption` — revocation racing issuance /
consumption.**
*Setup:* session on refresh family F, access JTI₁; C1 account. A
revocation tx = `revoke_user_sessions(scope='family', family=F)` or a
passkey revoke; an issuance tx = the C1 proof → grant tx; a consumption =
gated-arm consume.
*Steps / interleavings (drive each by holding the person fence from the test):*
(i) revocation COMMITS before the issuance tx takes the fence → the §2.2
durable recheck sees the `session_revocations` row → issuance refuses, no
grant; (ii) issuance tx holds the fence and has verified the proof when the
revocation commits behind it → issuance completes, then the revocation's
artifact deletes (§2.5) remove the just-issued grant → consumption refuses
(row gone; denylist also refuses the bearer at `authenticator.go:146-155`);
(iii) revocation commits between issuance and consumption → same as (ii)'s
consumption half; (iv) consumption tx holds the fence when revocation
commits behind it → consumption completes exactly once, revocation proceeds
after and deletes nothing (row already consumed) — state consistent.
*Expected:* every interleaving converges refused-or-consistent; no
interleaving yields a consumable grant that outlives a committed revocation,
and no double consumption. Pins the §2.2 person-fence unification
(`revoke_user_sessions.sql:39`) and the in-tx durable recheck (r3 finding 4).

**6. `TestFamilyRevocationInvalidatesCeremonies` — family revocation of
ceremonies.**
*Setup:* session on family F (JTI₁); user begins a `webauthn.register`
ceremony (row bound {JTI₁, refresh_family_id F, target_ref = ceremony hash on
the grant}) AND holds an unconsumed grant with `refresh_family_id` F; a
second session on family F₂ of the same user also holds a live ceremony +
grant.
*Steps:* (a) trigger `revoke_user_sessions(scope='family', family=F)`
(`revoke_user_sessions.sql:71-90` — extended per §2.5 to delete grants and
ceremonies by family); (b) attempt ceremony finish + grant consumption from
family F; (c) attempt ceremony finish + consumption from family F₂.
*Expected:* (b) refuses twice over — the ceremony and grant rows were deleted
by the reducer in the revocation tx, and the §2.2 durable recheck refuses the
revoked family's bearer regardless; (c) is UNAFFECTED — narrow family
revocation does not widen (`revoke_user_sessions.sql:44-46` comment), F₂'s
ceremony finishes and its grant consumes normally; the family-scope deletion
matched ONLY `refresh_family_id = F` rows (the §1.4 column supplies the
binding v3 lacked).

---

## 5. Open questions for the owner

(r3 confirms these do NOT block the engineering contracts above; carried, not
escalated.)

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

One omission/conflict pass over inputs (v3 + r3) vs code:

1. **r3 finding 1 (generation + target lifecycle)** — resolved: §1.8 defines
   the per-user mutation-only `users.factor_generation` (choice justified from
   code: single-row TOTP factor `authn/totp.go:278-292`; single-live-grant
   store `mfa_reauth.go:146-149`; users-fence serialization §2.2; use-markers
   `totp.go:127-135`/`webauthn.go:188-192` move on use); §1.6 defines distinct
   enrollment UUIDs, the one-time atomic begin binding with named
   repeated-begin semantics, and `staged_by_jti` provenance checked at
   confirm. The replacement-proof conflict is reconciled by deleting the
   setup-arm `current_totp_code` check (`handlers/totp.go:49-74`) — the grant
   subsumes it; v3 said "keeps" it, which is the conflict r3 named, and v4
   supersedes v3 here.
2. **r3 finding 2 residual** — resolved by the same §1.6 machinery; the
   "wrong pending-enrollment ID" case now has a concrete identifier (the setup
   response's `enrollment_id`) and `TestWrongPurposeTargetPendingRefused`
   names the combinations.
3. **r3 finding 3 (bootstrap issuance)** — resolved in §1.5.1: minting point
   `auth.go:734-747` via `issueMFAPending` (`auth.go:471-481`) →
   `jwt.IssueMFAPendingWithFences` (`jwt.go:262-302`); no transaction exists
   there today (pure signing), so the JWT JTI seam and
   `issueMFAPendingBootstrap` handler seam are specified precisely, the grant
   row is inserted in the fence-and-commit tx that gates the token's return,
   C1 vs C2/C3 issuance is split (C1's grant comes from the UV-ceremony
   finish), and the v3 self-contradiction ("ceremony `session_jti` empty for
   `mfa_pending`" vs bootstrap needing the real pending JTI, r3's schema
   contradiction) is fixed: `session_jti` is ALWAYS the real presenting
   token's JTI (§1.4). The `/auth/mfa/reauth`-as-bootstrap-issuer mapping r3
   rejected (mount requires access auth, `main.go:1053`;
   `authenticator.go:142`) is dropped.
4. **r3 finding 4 residuals** — resolved: §2.2 step 0 unifies on
   `identity_auth_person_fence` (`revoke_user_sessions.sql:39`,
   `identity_auth_local_mint_fence.sql:20-22`) taken BEFORE the users row
   lock; the durable in-tx revocation recheck queries `session_revocations`
   (`V055__cae_runtime_core.sql:9-24`) inside every issuance/consumption;
   `webauthn_ceremonies.refresh_family_id` supplies the family binding §2.5's
   family deletion needed.
5. **r3 finding 5 (failure budgets)** — resolved in §2.3: per-method counter
   pairs (schema matches policy; TOTP pair pre-exists,
   `V001__baseline.sql:5877-5878`), single atomic `UPDATE ... +1 ... RETURNING`
   under the fence repairing `RecordTOTPFailure`
   (`authn/totp.go:467-473`) AND the TOTP writers, locked refusals do not
   increment, bookkeeping errors roll back (fail-closed, preserved state —
   repairing `totp.go:511`/`totp.go:524`), and the corrected oracle
   (`TestProofBudgetSerializedUnderLoad`: exactly 5 evaluated, N−5 locked
   refusals without increment).
6. **Six r3-named acceptance cases** — written executable in §4.4 with
   setup/steps/expected; bootstrap e2e became implementable via §1.5.1
   (additionally pinned by `TestBootstrapGrantIssuedAtomicallyWithScopeToken`,
   §4.2).
7. **Code-vs-input conflicts carried from v3** (re-verified): no production
   endpoint sets `push_mfa_enabled` (§3 note); registration covers only
   normalized `passkey_credentials` (`authn/webauthn.go:279-305`), the legacy
   jsonb affects cohort only; replacement setup/confirm is broken in current
   code (`authn/totp.go:170-175`, `handlers/totp.go` confirm → `totp.go:283-284`
   zero-rows) and the pending-table split is the fix.
8. **v3 contradictions superseded (diff aids for reviewers):** §1.1
   `proving_factor_version` → `bound_factor_generation`; §1.4 ceremony
   `session_jti` "empty" → always real JTI; §2.2 "users row fence is
   canonical" → person fence first; §2.3 one shared counter pair → per-method
   pairs; §3 setup row "keeps current_totp_code check" → removed; §4.1
   `TestProofBudgetSerializedUnderLoad` oracle corrected;
   `TestBudgetReadFailureRefusesIssuance` renamed/broadened to
   `TestBudgetBookkeepingFaultRefusesAndPreserves` with the preserved-state
   oracle; new §4.1 `TestBudgetLockedRefusalDoesNotIncrement` and
   `TestGenerationBumpKillsOutstandingGrant`.
9. **Deliberately unchanged:** §5 owner questions (r3: not blocking);
   impersonation guard placement illustrative (`rejectImpersonated`); `hms`
   provider support (`device.go:125`, `V074__restore_push_devices_native.sql:19`)
   recorded so §3 is not "corrected" back to three providers.
10. **Not verified by execution:** the exact `go-webauthn` field path for the
    attestation UV flag (`Credential.Flags.UserVerified` per r3's library
    check at go-webauthn@v0.17.4) — implementer confirms at implementation
    time. `push.go:445-448`/`415-423` and `device.go:19-25,125` citations are
    carried from v3's Astra-validated endpoint map.
11. No builds/tests were run; this is a specification document. All new
    file:line citations were read from the current worktree (auth.go, jwt.go,
    authenticator.go, refresh.go, handlers/{totp,webauthn,mfa_reauth,mfa}.go,
    authn/{totp,totp_removal,webauthn}.go, main.go mounts, V250/V271/V055/V001,
    revoke_user_sessions.sql, identity_auth_local_mint_fence.sql,
    auth_policy.sql, webmail auth.ts + settings pages).
