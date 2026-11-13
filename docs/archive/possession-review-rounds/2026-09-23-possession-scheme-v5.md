# First-factor possession scheme v5 (2026-09-23) — implementation-grade specification

Owner decision stands: option (a) — every factor-set mutation requires a fresh
possession proof of an already-enrolled factor; bearer identity alone never
extends a factor set (`2026-09-23-owner-decisions-possession-pwhash.md:5-31`).
v2 was conceptually approved; Astra r1–r3 found spec-level gaps; v4 resolved
them and r4 (`-astra-r4.md`) held on four findings. This v5 is **v4 carried
forward with FOUR targeted corrections** (structure and numbering preserved so
reviewers can diff against v4):

- **[r4 finding 1, P1] Revocation watermark (fixes v4 §2.2's new predicate)** —
  v4's durable recheck treated every unexpired `scope='all'` row as revoking
  every token for the user. Actual semantics compare the token's issuance time
  against `not_before` (`shared/threat/denylist.go:85`, tested at
  `shared/threat/denylist_test.go:15`); the reducer retains rows for 31 days
  (`mailserver/sql/reducers/revoke_user_sessions.sql:21`), so v4 literally
  followed would have blocked factor management — and bootstrap issuance —
  even after a legitimate fresh login. §2.2 now preserves the EXISTING
  issuance-time watermark semantics under the person fence, including
  missing-`iat` handling. Acceptance: §4.1 `TestDurableRevocationRecheckWatermark`,
  §4.4 case 8.
- **[r4 finding 2, P1] Shared TOTP budget serialization** — §2.3 now specifies
  ONE transaction-aware verification cycle for EVERY shared TOTP caller (login,
  forgot-password, removal; full caller inventory with file:line), with
  explicit per-caller refusal behavior on bookkeeping failures, and new
  mixed-entry-point concurrency tests. The per-method counter columns,
  management-only counter oracle and rollback rules are kept unchanged.
- **[r4 finding 3, P1] C1 bootstrap contract** — the "no grant before
  finish" condition is scoped SPECIFICALLY TO REGISTRATION ceremonies;
  authentication/assertion ceremonies follow the NONE → ceremony transition
  (§1.4, §1.7). The endpoint map is completed: the C1 TOTP issuer and the
  management-assertion begin/finish endpoints are specified explicitly with
  token admission (presented `mfa_token`), request/response bodies and grant
  hash binding — bootstrap consumption always hashes the PRESENTED
  `mfa_token` (`handlers/mfa_reauth.go:163-212`), and that hash assignment is
  now explicit for C1 issuance too (§1.5.1 step 5). Acceptance: §4.4 case 7.
- **[r4 finding 4, P2] Acceptance fixtures** — the three v4 cases whose
  fixtures contradicted the state model (family isolation, same-ID
  replacement, repeated setup) are corrected with bounded database fixtures
  (§4.4 cases 2, 4, 6).

Sections not listed above carry forward from v4 unchanged in contract (line
citations re-verified against the current worktree). Where the code
contradicts an input, the code wins and the contradiction is noted inline and
in Self-check. r3/r4 confirm the two owner-open questions (§5) do NOT block
these engineering contracts; they are carried, not escalated.

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

(v4 replaced v3's `proving_factor_version` with `bound_factor_generation`.
v3 keyed TOTP grants to `users.last_totp_used_at` and WebAuthn grants to
`sign_count`; r3 finding 1 showed both move on ordinary USE — issuance's own
replay claim updates `last_totp_used_at` (`authn/totp.go:127-135`) and login
updates `sign_count` (`authn/webauthn.go:188-192`) — so a grant could be
invalidated by its own issuance or by unrelated logins. A mutation-only counter
(§1.8) has the correct dynamics for both factor families.)

Unchanged columns keep V271 semantics: hash-only storage, single live row per
user (issuance deletes prior rows, `mfa_reauth.go:146-149`), `expires_at` guard,
`DELETE ... RETURNING` single-use consumption (`mfa_reauth.go:190-212`, the
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
                                -- mfa_pending scope; never empty)
token_scope  text NOT NULL DEFAULT 'session'
refresh_family_id text          -- the access token's family at ceremony
                                -- creation; NULL for mfa_pending scope.
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
  **Endpoints (v5 — completes the r4 finding 3 map):** the pair is
  `POST /auth/mfa/possession/webauthn/begin` and
  `POST /auth/mfa/possession/webauthn/finish` (full contracts in §3). Begin is
  admitted by TOKEN, never by a grant: a valid access bearer → `session`
  scope; otherwise a presented `mfa_token` with `Type == TypeMFAPending` →
  `mfa_pending` scope (the pending-token proof contract r4 found missing —
  no existing route supplies it: the `/auth/mfa/reauth` handler's body accepts
  only `password`, `handlers/mfa_reauth.go:231-262`, and its mount requires
  access authentication, `cmd/authserverd/main.go:1053`, which
  `authenticator.go:142` makes unusable for `mfa_pending` bearers).
- **Ceremony kinds and the grant precondition (v5 — resolves the r4 finding 3
  contradiction between v4:164, v4:256 and v4:379):** the "new ceremony only
  under a NEW grant" rule applies SPECIFICALLY TO **REGISTRATION** ceremonies —
  they are the only kind whose begin performs the grant's one-time target
  binding (§1.6), so they are reachable only under a live unbound grant.
  **Management-assertion ceremonies are AUTHENTICATION ceremonies issued
  WITHOUT any grant**: they follow the NONE → CEREMONY_LIVE transition (§1.7),
  guarded by {cohort C1, budget not locked (§2.3), an admitted token as above}.
  This is what makes C1 bootstrap reachable at all: the bootstrap user has NO
  grant until the assertion finish mints one (§1.5.1 step 5). A new assertion
  begin deletes the user's prior `management_assertion` rows (one live ceremony
  per user+kind; V250 cleanup convention, `totp_removal.go:164-167`).
- Expired rows are dead by the `expires_at` guard; issuance of a new
  **registration** ceremony deletes the user's prior `registration` rows
  (V250 cleanup convention, `totp_removal.go:164-167`).

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
- **Grant issuance itself is specified in §1.5.1 (v4)** — r3 finding 3:
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
  pending JTI, `refresh_family_id` NULL), or refusal. The ceremony is served by
  the §3 possession endpoints with the presented `mfa_token` as admission
  (§1.4). Password-only bootstrap is reserved for C3/C2 (§1.5.1 issuance
  split). The UX/policy question is §5.1.

#### 1.5.1 Bootstrap grant issuance — the concrete path (v4; v5 completes the C1 half)

**Where the `mfa_pending` scope is minted today.** The only bootstrap minting
point is the password login's mandatory-enrollment branch:
`readMFAStatus` (`auth.go:725`) returns `enrollment_required` and the branch at
`authserver/internal/handlers/auth.go:734-756` calls `h.issueMFAPending`
(`auth.go:471-481`), which delegates to
`jwt.IssueMFAPendingWithFences` (`jwt.go:262-302`; random JTI minted at
`jwt.go:281-284`, `Type = TypeMFAPending` at `:288`, 5-minute expiry with
`IssuedAt` set at `jwt.go:295-298`). The other `issueMFAPending` call sites are
NOT bootstrap — they are second-factor completions for already-enrolled
accounts (TOTP login `auth.go:806-821`, CA step-up `auth.go:894-909`,
WebAuthn-login second factor `handlers/webauthn.go:220,245`) and never
authorize enrollment. A passkey-only account reaches the bootstrap point only
by logging in with its PASSWORD: `WebAuthnLoginFinish` issues a full session
with no enrollment routing when no challengeable MFA is enrolled
(`webauthn.go:197-199,262-271`), while the password path routes via
`auth_policy.sql:99-117`.

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
      to the wire, and the response shape at `auth.go:742-756` is unchanged.
      **C1 (UV-capable passkey holder) — v5 completes this half (r4 finding
      3):** NO password grant is inserted; the response still carries
      `mfa_token`. The grant is minted later by the `webauthn_uv`
      management-assertion FINISH —
      `POST /auth/mfa/possession/webauthn/finish` (§1.4, §3) — which is an
      AUTHENTICATION ceremony (NONE → CEREMONY_LIVE, §1.7): the "ceremony only
      under a new grant" rule does NOT apply to it (that rule is
      registration-only, §1.4), so the C1 bootstrap user can begin the
      ceremony with NO grant in existence. The finish transaction is the C1
      bootstrap issuance point, and its grant INSERT is fully specified:
      `{token_hash = SHA-256(**presented mfa_token**), user_id,
      session_jti = the pending token's JTI (read from the validated
      `mfa_token` claims), operation = 'bootstrap.totp.enroll',
      proof_method = 'webauthn_uv', proving_factor_id = the proving
      credential ID, bound_factor_generation = users.factor_generation,
      token_scope = 'mfa_pending', refresh_family_id = NULL, target_ref =
      NULL, expires_at = now() + 5 min}`. **Grant hash binding (explicit for
      C1):** bootstrap consumption always hashes the PRESENTED `mfa_token`
      (`reauthTokenHash`, `handlers/mfa_reauth.go:163-166`, applied by
      `peekMFAReauth`/`consumeMFAReauth`, `mfa_reauth.go:168-212`; v4 stated
      this at the consumption side only) — C1 issuance therefore stores
      `SHA-256` of the SAME bytes the login returned and the client presents:
      issuance and consumption agree by construction, no second secret is
      minted, and the finish response body is `{"granted": true}` (the client
      keeps using the same `mfa_token` for enroll setup/confirm). For
      contrast, C2/C3 issuance hashes the `mfa_token` it just minted (step 5
      above), and session-scope C1 issuance hashes the opaque `reauth_token`
      it just minted (§3 possession rows) — every issuance now names its hash
      assignment.
   6. `COMMIT`. Only after commit does the handler write the response. Any
      failure (fence, insert, commit) → 500, token never returned: a client
      never holds an `mfa_token` whose bootstrap grant did not commit. (For
      C1 the grant commit happens at the ceremony finish, not at login; the
      login commits only the token — the finish's own atomicity is §1.4's
      "consume row + issue grant in one transaction".) This is the "same
      transaction as the scope token" contract, adapted to a stateless JWT:
      for C2/C3 the grant row and the token's return are atomic, and the row
      binds {JTI, user, operation='bootstrap', no target} from birth.
3. **Consumption** (`/auth/totp/enroll/setup|confirm`, §1.6) peeks/consumes by
   `{token_hash = SHA-256(presented mfa_token), user_id, session_jti =
   claims.JTI, operation, token_scope}` — the exact tuple predicates
   `peekMFAReauth`/`consumeMFAReauth` already apply (`mfa_reauth.go:168-212`),
   plus the new columns.

The request/response contract is otherwise today's: the unauthenticated
`POST /auth/totp/enroll/setup` body `{"mfa_token":"..."}` (`totp.go:110-121`)
gains an `enrollment_id` response member and `POST /auth/totp/enroll/confirm`
(`totp.go:239-252`) gains a required `enrollment_id` request member (§1.6).
`BearerAuthenticator` never sees these tokens (`authenticator.go:142` rejects
non-access types), and no bearer-mount change is needed for the bootstrap
arms — bootstrap issuance lives in the login flow where the password proof
already happened, and the C1 bootstrap proof lives on the §3 possession
endpoints where the `mfa_token` itself is the admission.

### 1.6 Begin-vs-finish transitions per flow (v4: distinct enrollment IDs, one-time binding, staged provenance)

r3 finding 2: v3's `totp_pending_enrollments` had only `user_id` as identity
and no transition assigning a target to a grant. v4 fixed both; v5 carries it
forward unchanged:

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
| Management possession proof (C1, authentication ceremony — NO grant at begin) | `POST /auth/mfa/possession/webauthn/begin` — token admission (bearer or presented `mfa_token`, §3); deletes prior same-kind ceremony rows; creates the `management_assertion` row | `POST /auth/mfa/possession/webauthn/finish` — consumes row, issues grant in one tx (§1.5.1 step 5: C1 hash binding); session scope returns `reauth_token`, `mfa_pending` scope binds `SHA-256(presented mfa_token)` |

### 1.7 State machine

States: `NONE` → `CEREMONY_LIVE` (WebAuthn ceremonies only) → `GRANT_LIVE` →
`TARGET_BOUND` (grant sub-state after §1.6 binding, where required) → terminal:
`CONSUMED`, `DEAD` (expired | invalidated | refused).

| State | Event | Guard | Action | Next state |
|---|---|---|---|---|
| NONE | assertion begin (C1, `POST /auth/mfa/possession/webauthn/begin`) | not impersonated; budget not locked (§2.3); cohort C1; **token admitted (access bearer → session scope, or presented `mfa_token` → `mfa_pending` scope, §3) — NO grant exists or is required: authentication ceremony; the grant-under-begin rule is registration-only (§1.4)** | delete prior `management_assertion` rows; insert ceremony row; return assertion options | CEREMONY_LIVE |
| NONE | password reauth (C2/C3, `POST /auth/mfa/reauth`) | not impersonated; budget not locked; password verifies via `VerifyTOTPRemovalPassword` (`totp_removal.go:115-126`) | insert grant (`proof_method='password'`, operation declared by the request (§1.1 consumption re-check), generation bound, §1.8) | GRANT_LIVE |
| NONE | TOTP proof (C1, `POST /auth/mfa/possession/totp`) | not impersonated; budget not locked; enabled secret verifies + replay claim wins — via the §2.3 ONE-cycle INSIDE the §2.2 issuance tx | insert grant (`proof_method='totp'`) | GRANT_LIVE |
| CEREMONY_LIVE | assertion/attestation finish | challenge row live; UV required; origin/RP ok; budget not locked | consume ceremony row; (assertion: insert grant — §1.5.1 step 5 for `mfa_pending`; registration: proceed to promotion, §2.2) | GRANT_LIVE / CONSUMED |
| GRANT_LIVE | begin arm (gated flows) | full tuple + `target_ref IS NULL` | one-time binding + pending/ceremony row (§1.6) | TARGET_BOUND |
| TARGET_BOUND | begin arm, same grant + same JTI + live target | §1.6 resume rule | return same enrollment/options, no new rows | TARGET_BOUND |
| TARGET_BOUND / target-less GRANT_LIVE | gated-arm call | full tuple re-validates (§1.1) under row fence | consume row; mutate; bump `factor_generation`; success audit; commit | CONSUMED |
| GRANT_LIVE | gated-arm call | tuple mismatch (wrong purpose/target/pending ID, replay, expired, wrong session, generation advanced) | typed 403 `reauth_required`, audit refusal | DEAD (row deleted) |
| GRANT_LIVE | TTL elapsed | `expires_at <= now()` | row inert | DEAD |
| GRANT_LIVE | ANY factor mutation commits (enroll/replace confirm, registration, revoke, recovery regen, removal) | `users.factor_generation` advanced past `bound_factor_generation` (§1.8) | consumption-time re-check fails under fence | DEAD |
| GRANT_LIVE | logout / account switch / family or all revocation | `revoke_user_sessions` fires | reducer deletes grants AND ceremonies (§2.5) | DEAD |
| GRANT_LIVE | durable revocation row matches in the issuance/consumption tx | §2.2 step 0b recheck (issuance-time watermark semantics, v5) | refusal | DEAD |
| GRANT_LIVE (`password`, C3) | account gains first possession factor | first C1/C2 factor exists | delete unconsumed password grants (v2 §1) | DEAD |
| GRANT_LIVE | refresh rotation | rotation mints a NEW access JTI (`refresh.go:285,369`); grant keeps original JTI binding | no action — refreshed client's JTI differs, grant unusable from the new token; old pair bounded by the 5-minute TTL (§2.5) | GRANT_LIVE |
| any | impersonated bearer (`claims.AdminActorID != nil`, `jwt.go:413-436`; `mustUser` passes claims through, `handlers/auth.go:3351-3358`) | — | refuse unconditionally at issuance AND every consumption, incl. the V250 removal flow (r2 disposition) | NONE |

### 1.8 Factor generations and target lifecycle (v4 — carried forward unchanged)

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
  deleted that arm for gated accounts: a valid `totp.replace` grant was earned
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

### 2.2 Canonical lock ordering (v4 person fence unified; v5 fixes the durable recheck's watermark predicate)

Every transaction that issues, consumes, or mutates factor state acquires, in
order, holding to commit (no lock is ever acquired out of sequence):

0. **`identity_auth_person_fence(user)`** — the per-user advisory transaction
   lock the session-revocation boundary already takes
   (`mailserver/sql/reducers/revoke_user_sessions.sql:39`; primitive at
   `mailserver/sql/reducers/identity_auth_local_mint_fence.sql:6-24`). v3 named
   the users row lock "canonical" but `revoke_user_sessions` never takes it —
   r3 finding 4 called this a split fence. v4 unified: revocation and
   factor-state work serialize on the SAME advisory lock first, so a committed
   revocation is always visible to a later issuance/consumption and an
   in-flight issuance/consumption always finishes before a revocation proceeds.
   (r4 confirms this structure and the §1.4 family column are correct.)
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
check, not a durable one inside the tx). **v5 replaces v4's predicate**, which
treated every unexpired `scope='all'` row as revoking every token for the user
and would have refused factor management for the full 31-day row retention
(`revoke_user_sessions.sql:21`) even after a legitimate fresh login (r4
finding 1). The recheck mirrors the EXISTING enforcement semantics of
`SessionDenylist.IsRevoked` (`shared/threat/denylist.go:82-99`):

```sql
SELECT EXISTS (
  SELECT 1 FROM session_revocations
   WHERE user_id = $1
     AND (expires_at IS NULL OR expires_at > now())
     AND (
       (scope = 'jti'       AND jti = $3)
       OR (scope = 'family' AND family_id = $2)
       OR (scope = 'all'
           AND ($4::timestamptz IS NULL OR $4 <= not_before))
     )
)
```

against `session_revocations` (`V055__cae_runtime_core.sql:9-24`), with `$1`
the authenticated user, `$2` the presented token's refresh family (NULL-safe;
NULL for `mfa_pending`), `$3` its JTI, and **`$4` the presented token's
issuance time (`claims.IssuedAt`), bound as NULL when the claim is absent**
(never a zero timestamp). Semantics pinned to the existing implementation —
the SQL is a faithful mirror, not a new policy:

- **`scope='all'` is an ISSUANCE-TIME WATERMARK, not a blanket.** The row
  denies every token whose `iat <= not_before` and denies nothing issued
  strictly after: `IsRevoked` denies iff `!iat.After(watermark)`
  (`denylist.go:85`) — boundary INCLUSIVE — explicitly tested at
  `denylist_test.go:15-21` (before/after) and `denylist_test.go:130,135-137`
  (exact boundary denied; post-watermark survives).
- **Missing `iat` fails CLOSED.** The authenticator maps a nil `IssuedAt`
  claim to the zero time (`authenticator.go:147-150`); the zero time is never
  after the watermark, so such a token is denied (`denylist.go:85`). The SQL
  mirror denies via `$4 IS NULL`. All tokens this scheme issues carry `iat`
  (`jwt.go:295-298` sets it on `mfa_pending`; access tokens likewise), so this
  is an edge policy, preserved not invented.
- **`jti`/`family` rows are exact matches and `iat`-independent**
  (`denylist.go:88-97`) — unchanged from v4.
- **Row-shape facts the EXISTS relies on:** durable rows carry
  `not_before TIMESTAMPTZ NOT NULL DEFAULT now()` (`V055__cae_runtime_core.sql:19`)
  and the reducer stamps `expires_at = statement_timestamp() + 31 days`
  (`revoke_user_sessions.sql:21`, INSERT at `:106-119`); at most one `scope='all'`
  row per user exists (the reducer deletes prior `'all'` rows in the same
  transaction, `revoke_user_sessions.sql:69-70`), and per-row EXISTS
  comparison is equivalent to the max-watermark compaction the in-memory
  mirror performs (`denylist.go:184-187`).

**Named consequence (the point of the correction):** a legitimate fresh login
AFTER an all-session revocation issues tokens with `iat > not_before`; those
tokens pass this recheck, so proof issuance, grant consumption and bootstrap
issuance all work immediately — for as long as the old row is retained
(31 days). Old tokens (issued at-or-before the watermark) are refused both at
request authentication (`authenticator.go:151`) and by this in-tx recheck,
closing the admitted-request race r3 finding 4 named. Deleting artifacts
during revocation (§2.5) removes the rows themselves; this recheck
additionally refuses any artifact-creating request that was already admitted
when revocation committed.

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
  `UPDATE passkey_credentials` (`webauthn.go:198-204`); under the scheme it
  runs inside the person+users-fence transaction with grant re-validation and
  a generation bump, closing the consume-vs-revoke race r2 finding 1 named.
- Cancellation/abandonment: deleting the `totp_pending_enrollments` row (or
  letting `expires_at` lapse) leaves the active factor untouched — repair of
  today's behavior where replacement setup overwrites the live secret
  (`authn/totp.go:170-175`), whose confirm can then never re-enable an enabled
  row (`totp.go:283-284` guard matches zero rows). The pending-table split
  fixes both; no compatibility shims.

### 2.3 Failure budgets — storage, transaction behavior, oracle (v4 counter model kept; v5 adds the shared TOTP cycle)

**Counter model (kept from v4): one counter pair per proof method.** The proof
methods are exactly `password | totp | webauthn_uv` (§1.1). TOTP already owns a
per-method pair on `users` (`totp_failed_attempts`/`totp_locked_until`,
`V001__baseline.sql:5877-5878`; policy at `authn/totp.go:418-424`), so the
scheme adds the two missing pairs rather than sharing one:

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

**Transaction behavior — management proofs (kept from v4).** Budget check,
proof verification, and counter write all live INSIDE the issuance transaction
(§2.2 lock order: person fence → users fence). The increment is a SINGLE
atomic statement — this is the specified form for every counter, and it is
also the repair of `RecordTOTPFailure`'s read-then-write lost update
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

Semantics pinned by the statement (kept):

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
  counters unchanged (rolled back).
- A locked budget refuses issuance with 429 (matching `ErrTOTPLocked`
  handling, `handlers/totp_removal.go:59-61`); a lock-state read error refuses
  with 500 — issuance never proceeds on unknown state.

**Oracle rule (kept, management-only):** the acceptance tests' expected
outcomes are defined from THIS storage spec alone. For N ≥ 5 concurrent failed
proofs of one method, all arriving before any lock exists: the fence
serializes them; the first 5 are evaluated failures (counter passes 1..5, lock
timestamp set by the 5th), and every later request is a locked refusal that
leaves the counter at exactly 5. Expected assertions:
`possession_*_failed_attempts = 5`, lock timestamp set, exactly `N - 5` locked
refusals, zero grants issued. For N < 5: counter = N, no lock. A bookkeeping
fault test asserts refusal + preserved state (counter and lock exactly as
before the attempt, no grant row).

**v5 — ONE transaction-aware verification cycle for EVERY shared TOTP caller
(r4 finding 2).** v4 fixed the management proof's cycle but left the EXISTING
shared seam (`VerifyTOTPWithLockout`, `authn/totp.go:510`) as separate pool
operations: a fail-open lock-state load (`totp.go:511` discards the load
error), then verify, then an unconditional counter write. A login can pass its
initial lock check, pause, then resume and clear a lock established by
concurrent management or removal failures (`ResetTOTPLockout` clears
unconditionally, `totp.go:476-481`); atomic increments alone do not prevent
this. The specification: **every caller below runs the WHOLE
load→check-locked→verify→record/reset cycle inside ONE transaction holding the
`users` row fence** (`FOR NO KEY UPDATE`, first statement of the cycle), with
bookkeeping failures as a distinct refusal outcome.

Caller inventory (every current caller of `VerifyTOTPWithLockout` /
shared-budget TOTP verification, file:line, before this scheme's deletions):

1. **Login second factor** — `TOTPVerify`, `POST /auth/totp/verify`
   (mount `main.go:1023`): `authserver/internal/handlers/totp.go:203`.
2. **TOTP replace arm (deleted by this scheme)** — `TOTPSetup`'s
   `current_totp_code` check, `GET /auth/totp/setup` (mount `main.go:1035`):
   `handlers/totp.go:63`. §1.8 removes this arm (the grant subsumes it); it is
   listed so it cannot survive as an unconverted pool-level caller.
3. **Forgot-password** — `ForgotPasswordVerify` TOTP branch,
   `POST /auth/forgot-password/verify` (mount `main.go:1100`, behind
   `FeatureForgotPassword`): `handlers/forgot_password.go:528`.
4. **TOTP removal begin** — `BeginTOTPRemoval` decision-table case 1,
   `POST /auth/totp/remove/begin` (mount `main.go:1044`):
   `authn/totp_removal.go:85`. (The removal tx itself,
   `DisableTOTPWithStepUp`, verifies no TOTP code — it consumes the step-up
   token — and is not a budget caller; its begin arm is item 4.)
5. **Enrollment confirm (budget writer, not a `VerifyTOTPWithLockout`
   caller)** — `ConfirmTOTPEnrollmentTx` failure write
   `authn/totp.go:368-374` and success reset folded into the enable UPDATE
   `authn/totp.go:383-395`; already serialized by its users-fence read
   (`FOR NO KEY UPDATE`, `authn/totp.go:333-347`); migrates to the
   single-statement increment form per the kept v4 rule above.

(Adjacent, not TOTP: the push branch has its own budget on `auth_lockouts`
whose verdict is ALREADY one transaction — `VerifyChallengeWithLockout`,
`authn/push_lockout.go:243-260` — cited as the in-tree shape precedent, not
part of this budget.)

The cycle (new seam `VerifyTOTPWithLockoutTx(ctx, q, userID, code)
(TOTPVerifyOutcome, error)`, `q` = tx or pool via the existing
`totpVerifyStore` shape, `authn/totp.go:79-90`; the pool-level
`VerifyTOTPWithLockout` becomes a thin BEGIN/COMMIT wrapper or is deleted once
all callers are converted):

1. **Lock + read**: `SELECT totp_locked_until, COALESCE(totp_failed_attempts, 0)
   FROM users WHERE id = $1 FOR NO KEY UPDATE` — replaces the fail-open
   pool-level `LoadTOTPLockState` (`authn/totp.go:454-461`, error discarded at
   `:511`). A missing row (deleted user) → invalid, no writes.
2. **Locked** → `TOTPLocked`, rollback (no writes; locked refusals do not
   increment — the kept semantics above).
3. **Verify** on the SAME `q`: secret read + constant-time compare + atomic
   replay claim — the existing `verifyTOTPCore` statements (`totp.go:104-145`).
4. **Record/reset**: failure → the §2.3 single-statement atomic increment,
   TOTP-column form; success → reset in the same transaction; COMMIT.

The whole-cycle-in-one-transaction property closes the r4-named hole BY
CONSTRUCTION: the lock check and the reset share the fence, so a lock
committed by a concurrent cycle is either visible to step 1 (the pauser had
not yet read state) or the pauser holds the fence and the concurrent failure
cannot commit until after the reset — there is no interleaving in which a
stale "unlocked" observation clears a lock that exists at write time.

**Explicit caller handling of bookkeeping failures (v5).** A new outcome
`TOTPBookkeepingError` (distinct from `Invalid`/`Locked`/`Accepted`) is
returned when ANY statement of the cycle errors; the cycle is rolled back and
counters are exactly as before. No caller proceeds, and no caller reports
acceptance, on this outcome. Per caller:

| Caller | `TOTPBookkeepingError` behavior | Invalid / Locked (unchanged) |
|---|---|---|
| `TOTPVerify` (login, `handlers/totp.go:196-215`) | 500 `internal error`; no tokens; no session state change. (Supersedes today's accepted-with-error: `totp.go:524-526` returns `TOTPAccepted` with a logged reset error, and the handler logs-and-continues at `totp.go:205-207`.) | 401 / 429 |
| `ForgotPasswordVerify` (`forgot_password.go:528-537`) | 500 with NO enumeration signal (no constant-time delay theater on an infrastructure failure); no `reset_token` | 401 after `enumConstantDelay` / 429 after delay |
| `BeginTOTPRemoval` (`totp_removal.go:85-107`) | wrapped error → handler default branch → 500 (`handlers/totp_removal.go:63-66`); the recovery-code fallback (`totp_removal.go:97-105`) must NOT run — today's code already returns before it on `logErr`; this pins it | 401 `invalid code` / 429 (`totp_removal.go:59-61`) |
| C1 TOTP management proof (`POST /auth/mfa/possession/totp`, §3) | runs INSIDE the §2.2 issuance tx (person fence → users fence → this cycle); a bookkeeping error aborts the whole issuance → 500, NO grant (the kept fail-closed rule) | 403 / 429 |
| `ConfirmTOTPEnrollmentTx` (`totp.go:333-410`) | error at its counter write already aborts its caller-owned tx (`totp.go:374-376`); unchanged behavior, atomic-form write | existing outcomes |

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
  The scheme extends it (same transaction, per the reducer's boundary contract):
  scope `all` deletes ALL the user's `mfa_reauth_step_ups` rows and
  `webauthn_ceremonies` rows; scope `family` deletes rows whose
  `refresh_family_id` matches (grants AND ceremonies — the ceremony schema's
  §1.4 column supplies the binding); scope `jti` deletes rows whose
  `session_jti` matches. Defense in depth: the denylist refuses revoked
  (user, jti, family) bearers at request authentication
  (`authenticator.go:146-155`), and §2.2's durable in-tx recheck — with the
  v5 watermark semantics — refuses anything already admitted. Note the
  watermark's direction here too: after a scope `all` revocation, artifact
  deletion (this bullet) is what kills pre-revocation grants outright; the
  recheck is the belt-and-braces for in-flight requests presenting
  pre-watermark tokens.
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
`authserver/cmd/authserverd/main.go` (line refs below). **v5 adds three
endpoints (the C1 possession-proof family, r4 finding 3) and completes the
`/auth/mfa/reauth` row; all other rows carry forward from v4.**

| Endpoint (mount) | Owning handler | Operation kind | Client surface | Proofs accepted |
|---|---|---|---|---|
| `POST /auth/mfa/reauth` (main.go:1053) | `MFAReauthBegin`, `handlers/mfa_reauth.go:228` | issuance only (not a mutation) — session-scope password grants (C2/C3) | webmail `auth.ts:684` (`beginMFAReauth`); native | `password` only — the handler's body accepts ONLY `{"password"}` today (`mfa_reauth.go:231-262`) and v5 does NOT change that contract; the mount requires access authentication (`main.go:1053`). **v5 additions:** (i) the request gains a required `operation` member declaring the §1.3 operation the grant will carry — §1.1's consumption re-check forces issuance-time binding, which v4 left implicit (Self-check); (ii) C1 accounts receive the method-aware 403 refusal NAMING the possession endpoints below. **Bootstrap issuance does NOT live here** (bearer mount rejects `mfa_pending`, `authenticator.go:142`); it lives in the login flow (§1.5.1) and, for C1, on the possession endpoints |
| `POST /auth/mfa/possession/totp` (**NEW**; mount adjacent to main.go:1053: `threatInterceptor` + `requireAuth` + CSRF, same posture as `/auth/mfa/reauth`) | new handler in the `handlers/mfa_reauth.go` possession family | grant issuance only — session-scope `proof_method='totp'` grants (C1) | webmail method-aware handoff (§3.1); native | **C1 only**; **session scope only** — a `mfa_pending` holder never has TOTP enabled (C1-with-TOTP completes login as a second factor, `auth.go:806-821`, and never reaches `enrollment_required`; `auth_policy.sql:99-117` routes only TOTP/push-less accounts to enrollment), so no bootstrap TOTP surface exists. Request: `{"operation":"<§1.3 kind>","code":"..."}`. The enabled secret is verified through the §2.3 ONE cycle INSIDE the §2.2 issuance tx (person fence → users fence). Response: `{"reauth_token":"...","expires_in":300}` (V271 shape, `mfa_reauth.go:262-269`); grant `token_hash = SHA-256(presented reauth_token)` (`reauthTokenHash`, `mfa_reauth.go:163-166`). C2/C3 → 403 naming `password` |
| `POST /auth/mfa/possession/webauthn/begin` (**NEW**; mount: `threatInterceptor` only — bootstrap callers are pre-session, and begin creates only a single-use JTI-bound ceremony row that authorizes nothing by itself) | new handler (ceremony store, §1.4) | management-assertion ceremony create (authentication ceremony — NO grant) | webmail method-aware handoff (§3.1); native | **Token admission (v5, the r4 finding 3 pending-token contract):** valid access bearer → `session` scope ({user, JTI, family} from claims); ELSE presented body member `{"mfa_token":"..."}` validated as `Type == TypeMFAPending` (the `totp.go:117-121` pattern) → `mfa_pending` scope; else 401. Cohort C1 required; budget not locked (§2.3); impersonation refused (§1.7). Response: PKC assertion options with `userVerification:'required'` server-side (§1.4) |
| `POST /auth/mfa/possession/webauthn/finish` (**NEW**; mount: `threatInterceptor` + CSRF — session-scope callers ride the ambient cookie; native/token-bearing callers pass per the fetch-metadata passthrough discipline of `main.go:1011-1015`) | new handler (ceremony store, §1.4) | management-assertion finish → grant issuance (authentication ceremony) | same | Same dual admission; body = the assertion plus `{"operation":"<§1.3 kind>"}` and, for `mfa_pending` admission, the same `mfa_token`. One tx (§2.2): consume ceremony row (single-use), UV required, issue grant. **Session scope:** response `{"reauth_token":"...","expires_in":300}`; grant `token_hash = SHA-256(minted reauth_token)`, `session_jti` = access JTI, `refresh_family_id` = presented family. **`mfa_pending` scope:** response `{"granted":true}` — NO new secret; grant `token_hash = SHA-256(**presented mfa_token**)`, `session_jti` = pending JTI, `refresh_family_id` NULL (§1.5.1 step 5 — the explicit C1 hash assignment) |
| `GET /auth/totp/setup` (main.go:1035) | `TOTPSetup`, `handlers/totp.go:31` | `totp.enroll` (peek) / `totp.replace` (peek) | webmail both settings pages (`auth.ts:733`; `settings/+page.svelte:427`) | `password` \| `totp` \| `webauthn_uv` per cohort. The separate `current_totp_code` verification is removed (v4; §1.8 last bullet) — the grant subsumes it; the arm performs only the peek + one-time binding (§1.6), deleting the `handlers/totp.go:63` budget caller (§2.3 inventory item 2) |
| `POST /auth/totp/confirm` (main.go:1037) | `TOTPConfirm`, `handlers/totp.go:407` | `totp.enroll`/`totp.replace` (consume + promote) | same | same, consumed here; requires the setup-issued `enrollment_id` (§1.6) |
| `POST /auth/totp/enroll/setup` (main.go:1024) | `TOTPEnrollmentSetup`, `handlers/totp.go:110` | `bootstrap.totp.enroll` (peek, `mfa_pending` scope) | webmail login/enrollment flow (`auth.ts:772`) | C3/C2: `password` bootstrap grant minted at login (§1.5.1); passkey-holder (C1): `webauthn_uv` ceremony via the possession endpoints, bound to the MFA-pending JTI (§1.5, §3); refusal otherwise |
| `POST /auth/totp/enroll/confirm` (main.go:1025) | `TOTPEnrollmentConfirm`, `handlers/totp.go:239` | `bootstrap.totp.enroll` (consume + promote) | same (`auth.ts:784`) | same, consumed in the promotion tx; requires `enrollment_id` (§1.6) |
| `GET /auth/webauthn/register/begin` (main.go:1011) | `WebAuthnRegisterBegin`, `handlers/webauthn.go:22` | `webauthn.register` (peek + one-time binding + ceremony create) | webmail `settings/+page.svelte:366`; native | per cohort; **bearer-only registration refused** (owner decision) |
| `POST /auth/webauthn/register/finish` (main.go:1013) | `WebAuthnRegisterFinish`, `handlers/webauthn.go:51` | `webauthn.register` (consume ceremony + grant, persist) | same | same, consumed |
| `DELETE /auth/webauthn/credential/{id}` (main.go:1020) | `WebAuthnRevokeCredential`, `handlers/webauthn.go:329` | `webauthn.revoke` (consume) | webmail; native | per cohort, `target_ref` = credential ID (`decodeCredentialID`, `webauthn.go:319-326`) |
| `POST /auth/backup-codes/generate` (main.go:1093) | `GenerateBackupCodes`, `handlers/mfa.go:31` | `recovery.regenerate` (consume) | webmail `auth.ts:702`, security page; native | per cohort, EVERY account (V271 posture kept) |
| `POST /auth/device/register` (main.go:1075) | `DeviceRegister`, `handlers/device.go:95` | `device.register.native` (consume) — **native providers `apns`/`fcm`/`hms` only** | native clients | per cohort. **Distinction (r2 fix plan 3):** native registrations are authentication devices — they carry `device_public_key`, receive ECIES number-match challenges and are the only devices `dispatchToNativeDevices` selects (`authn/push.go:445-448`) and `/auth/mfa/approve` accepts (`device.go:19-25`). `provider = 'webpush'` rows are WebPush notification **subscriptions** — delivery keys that never answer approvals (`authn/push.go:415-423`) — and are NOT gated |
| `POST /auth/totp/remove/begin` (main.go:1044) + `POST /auth/totp/remove` (main.go:1045) | `TOTPRemovalBegin`/`Confirm`, `handlers/totp_removal.go:28,93`; decision table `authn/totp_removal.go:45-110`; removal tx `totp_removal.go:191-258` | **EXPLICIT EXCEPTION** — V250 decision table remains authority (password+current TOTP; authenticator-lost → password+non-consuming recovery-code check `totp_removal.go:133-147`; no codes → self-service refusal to admin/support) | webmail `auth.ts:810,827`, security page | not re-gated by this scheme; recovery codes are break-glass, not possession proofs (v2 §4). Impersonation rejection (§1.7 last row) IS applied here per the r2 disposition; the removal tx bumps `factor_generation` (§1.8). The begin arm's TOTP verification is a §2.3 shared-cycle caller (inventory item 4) |
| `PUT /auth/webauthn/credential/{id}/name` (main.go:1019) | `WebAuthnNameCredential`, `handlers/webauthn.go:275` | out of scope — metadata rename, no factor-set change | webmail | not gated |
| `GET /auth/webauthn/credentials` (main.go:1018) | `WebAuthnListCredentials`, `handlers/webauthn.go:355` | read-only | webmail | not gated |

Not gated (login/second-factor completion, no factor-set change):
`POST /auth/totp/verify` (`handlers/totp.go:183`; its verification is a §2.3
shared-cycle caller, inventory item 1),
`POST /auth/backup-codes/verify` (`main.go:1095`),
`POST /auth/push/verify` / `POST /auth/push/send` / `POST /auth/push/status`
(main.go:1057-1064), `POST /auth/mfa/approve` (main.go:1079),
`/auth/webauthn/login/*` (main.go:1016-1017), forgot-password arms
(main.go:1099-1101; the verify arm's TOTP branch is inventory item 3).

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
  offered the WebAuthn-UV assertion (§3 possession endpoints) or TOTP proof
  (`POST /auth/mfa/possession/totp`); password appears only for C2/C3.
  Held-proof discipline already present (`openReauth` clears
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
| `TestDurableRevocationRecheckWatermark` (**v5**, r4 finding 1) | the §2.2 recheck predicate against `session_revocations`: with a live `scope='all'` row, presented tokens with `iat < not_before` are denied, `iat == not_before` denied (boundary inclusive), `iat > not_before` PASS, `iat` NULL denied (fail-closed); `scope='jti'`/`'family'` rows stay `iat`-independent exact matches; two `'all'` rows (fixture) deny per the greatest watermark. Mirrors `denylist.go:82-99` (`denylist_test.go:11-25,130,135-137`) — explicitly the correction of v4's blanket EXISTS |
| `TestProofBudgetSerializedUnderLoad` | **management-oracle (from §2.3 storage alone, kept):** N = 8 concurrent failed password proofs → counter EXACTLY 5, lock timestamp set by the 5th, exactly 3 locked refusals that do NOT increment, zero grants issued. Same assertions for the `webauthn_uv` counter; TOTP counter pinned by the migrated single-statement writer vs today's lost update (`authn/totp.go:467-473`) |
| `TestTOTPBudgetMixedEntryPointsSerialize` (**v5**, r4 finding 2) | login (`POST /auth/totp/verify`), forgot-password (`ForgotPasswordVerify`) and removal (`BeginTOTPRemoval`) failures racing ONE users-row budget through the §2.3 ONE-cycle: failures serialize under the users fence, counter = evaluated failures capped at 5 with the lock set by the 5th regardless of which entry point delivered it, later entrants from EVERY entry point refused locked without increment, no lost update (contrast `RecordTOTPFailure`'s read-then-write, `totp.go:467-473`) |
| `TestPausedLoginCannotClearConcurrentLock` (**v5**, r4 finding 2) | the named hole (`totp.go:511-527` separate pool ops): (i) login cycle passes its lock read then pauses (test holds the users fence); concurrent removal-begin failures block; login resumes, verifies a VALID code, commits its reset; the failures then commit — final state LOCKED at the 5th evaluated failure (the stale-unlocked reset never erased it); (ii) failures commit first, the login cycle then reads the lock in step 1 → `TOTPLocked` without verify (a reset never runs against a lock established before its read) |
| `TestBudgetBookkeepingFaultRefusesAndPreserves` | fault injected at the budget state read (and, in variants, at the increment / reset) inside the issuance tx → 500, NO grant row, counter and lock state EXACTLY as before the attempt (fail-closed + preserved state; contrasts `VerifyTOTPWithLockout`'s fail-open load, `totp.go:511`, and accepted-alongside-reset-error, `totp.go:524`). v5 variant: the same fault through EACH shared caller (login, forgot-password, removal begin) yields that caller's §2.3 refusal behavior (`TOTPBookkeepingError` mapping table) |
| `TestBudgetLockedRefusalDoesNotIncrement` | while `possession_*_locked_until > now()`: refused attempts leave the counter and lock untouched (§2.3 WHERE guard) — distinguishes evaluated failures from locked refusals in the oracle; same assertion for the TOTP columns through the shared cycle |
| `TestGrantAuditFaultRollsBackAll` | DB/bookkeeping fault at the audit insert (§2.4) → mutation, grant consumption, generation bump AND audit all roll back; nothing partial commits |
| `TestTOTPProofVsFactorChangeRace` | issuance-time TOTP verify on the fenced tx vs concurrent disable/replace — no accepted proof against a revoked/replaced secret (r1 finding 2 closed) |
| `TestGenerationBumpKillsOutstandingGrant` | grant live at generation G; any §1.8 mutation commits G+1 in a parallel tx; consumption of the G-grant refuses under the fence (§1.8 check rule) |

### 4.2 Handler/mux tests

| Test | Asserts |
|---|---|
| `TestBearerOnlyWebAuthnRegisterRefused` | begin/finish without a live grant → typed 403 `reauth_required` (`mfa_reauth.go:96-105` shape) — the owner decision's negative case |
| `TestPasswordOnlyRefusedWhenPossessionRequired` | C1 account + password grant → refused at every §3 endpoint |
| `TestWrongPurposeTargetPendingRefused` | grant bound to operation/target A presented at B → refusal. Concrete (§1.6): wrong pending-enrollment UUID (present setup A's ID to grant bound to B, and the dead-ID combinations), wrong `target_ref` credential, wrong ceremony |
| `TestCrossAccountCeremonyRefused` | ceremony/grant of user A on user B's session → refusal (user/JTI predicates, §1.4) |
| `TestStaleExpiredCeremonyRefused` / `TestProofAndCeremonyExpiryIndependent` | ceremony row dead but grant live, and vice versa → both refuse; TTLs independent |
| `TestMissingUVRefused` | management assertion without UV → refusal (server-side requirement, §1.4) |
| `TestWrongChallengeOriginRPRefused` | assertion against wrong challenge/origin/RP → refusal (go-webauthn config, `webauthn.go:36-41`) |
| `TestImpersonationRefusedIssuanceAndConsumption` | `AdminActorID` bearer (`jwt.go:413-436`) refused at `/auth/mfa/reauth`, the possession endpoints, every gated arm, and the V250 removal begin/confirm, even with valid evidence |
| `TestNormalizedNonUVCredentialCohort` | non-UV normalized credential + no TOTP → C2 password step-up; UV assertion against it not usable as proof; failed/cancelled UV never reclassifies (r2-named case) |
| `TestRefreshRetainsOldPairBounded` / `TestRefreshNewJTIRefused` | after rotation: old access token + its grant consumable only within the 5-minute TTL (documented, §2.5); NEW access token + old grant refused on JTI mismatch (r2-named retained-pair case) |
| `TestSessionReplacementAndLogoutInvalidate` | family revocation via `revoke_user_sessions` deletes grants (and ceremonies, §2.5); replaced session cannot consume |
| `TestFirstFactorPasswordGrantInvalidAfterPossessionEnrolls` | C3 password grant dies when the account gains its first possession factor |
| `TestAllSessionRevocationThenFreshLoginManagesFactors` (**v5**, r4 finding 1) | handler-level watermark end-to-end (with §4.4 case 8): after `revoke_user_sessions(scope='all')`, the OLD bearer is refused (`ErrRevoked`, `authenticator.go:151`) while a FRESH login's C1 proof issuance → grant → consumption ALL succeed — and a C3 fresh login's bootstrap enrollment completes — even though the durable row is still retained (31 days, `revoke_user_sessions.sql:21`); a missing-`iat` token is refused throughout |
| `TestBootstrapGrantIssuedAtomicallyWithScopeToken` | C3 login → `enrollment_required` response carries `mfa_token` ONLY if the bootstrap grant row committed in the same tx (§1.5.1): fault the grant INSERT → 500, no `mfa_token` in any response, no row; committed case → row holds {SHA-256(mfa_token), pending JTI, operation `bootstrap.totp.enroll`, scope `mfa_pending`, NULL target, current generation} |
| `TestBootstrapPasskeyHolderRequiresUVProof` | passkey-only (UV-capable) account in mandatory enrollment (`auth_policy.sql:99-117` routing) gets NO password bootstrap grant at login (§1.5.1 step 5); `enroll/setup` with the bare `mfa_token` refuses; the UV ceremony on the §3 possession endpoints mints the `webauthn_uv` `mfa_pending` grant with `token_hash = SHA-256(presented mfa_token)`; C3 zero-factor password bootstrap still works end-to-end (r2-named bootstrap-with-passkeys case) |
| `TestPossessionEndpointsAdmission` (**v5**) | the new §3 rows' admission contract: no token and no bearer → 401; `mfa_pending`-typed token → `mfa_pending`-scope ceremony/grant; access bearer → session scope; access-typed token in the `mfa_token` member → 401 (type parity, `authenticator.go:142` discipline); `POST /auth/mfa/possession/totp` for a C2/C3 account → 403 naming `password`; non-C1 cohort at the webauthn begin → 403 |
| `TestNativeDeviceRegisterGatedWebpushNotGated` | `apns`/`fcm`/`hms` registration needs a grant; `webpush` subscription registration does not, and never answers `/auth/mfa/approve` |
| `TestMutationInventoryComplete` | every §3 row refuses without the correct grant — guards against future ungated additions (incl. any future `push_mfa_enabled` setter, §3 note) |
| `TestExistingFlowsUnregressed` | TOTP/passkey/push/recovery login, conditional-access and DPoP completion guarantees behave exactly as today (`webauthn.go:200-272` CA leg, `completionMetadataForDPoP`); includes the converted shared TOTP cycle: a valid login second-factor code still completes (`POST /auth/totp/verify` through the §2.3 one-cycle) |

### 4.3 Browser lifecycle tests (per webmail surface)

- `/settings/security`: method-aware handoff — C1 offers WebAuthn-UV/TOTP
  (the §3 possession endpoints), password only for C2/C3; retry-after-proof
  loops honestly (`+page.svelte:186-195`); expiry requires a NEW proof (no
  grant refresh).
- `/settings` (general): passkey registration (`:363`) and TOTP
  setup/confirm (`:427,439`) route through the shared handoff; confirm calls
  carry the setup-issued `enrollment_id`; returned secrets/recovery codes
  render only if the account identity is unchanged at response time (§3.1).
- Both surfaces: session replacement during a ceremony, refresh mid-ceremony,
  logout/account switch → pending enrollment UI drops, late responses
  discarded, next gated call re-runs the handoff.

### 4.4 r3/r4-named additional acceptance cases (v5 — eight; cases 2, 4, 6 fixtures corrected per r4 finding 4; cases 7-8 new per corrections 3 and 1)

**1. `TestTOTPReplaceEndToEndWithGrant` — successful TOTP-authorized
replacement end-to-end.** (Carried from v4 unchanged.)
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
new one is created (v5: refusal, resume and 409 semantics are exercised on
SEPARATELY-fixture'd grants; r4 finding 4).**
Consistent refusal semantics, fixed first: a confirm-arm tuple mismatch
DELETES the grant (§1.7: GRANT_LIVE gated-arm mismatch → DEAD, row deleted).
No sub-case may reuse a grant after such a death, so each sub-scenario mints
its own grant.
*Setup:* C1 account with active TOTP; each sub-scenario starts from a fresh
proof → fresh grant.
*Steps:*
(a) *Stale-ID refusals (grants G2 → G3).* Proof → G2; setup on G2 → E1
(secret S1′); abandon. Proof → G3 (issuance deletes G2's row,
`mfa_reauth.go:146-149`); setup on G3 → E2 (the `ON CONFLICT (user_id) DO
UPDATE` mints a NEW uuid and replaces the pending row, §1.6). Attempt confirm
{E1 + G3} → refused: `target_ref` = E2 ≠ E1, and the refusal DELETES G3
(§1.7) — assert G3's row gone, active factor untouched, E2 still live. Then,
via a bounded fixture that re-inserts a G2-shaped row directly (bypassing
issuance's delete convention), attempt confirm {E1 + re-inserted row} →
refused: pending id E1 no longer resolves (replaced by E2's row) — factor
untouched. Sub-scenario ends here BY THE STATE MACHINE'S OWN SEMANTICS.
(b) *Same-JTI resume (fresh grant G4).* Proof → G4; setup → E3; retry setup
on G4 with the SAME JTI while E3 is live → resume: returns E3's provisioning
URI unchanged, no new rows, binding untouched.
(c) *Bound grant with dead target (fresh grant G5).* Proof → G5; setup → E4;
fixture: force E4's `expires_at` into the past; setup again on G5 → target
bound, target dead, not resumable → typed 409 `proof_already_bound` (§1.6).
*Expected:* exactly one live pending enrollment per user at all times; every
stale (grant, enrollment) combination refuses with the factor untouched;
only {G3, E2} could have confirmed — and (a) terminates at the first
tuple-mismatch refusal instead of continuing on a dead grant (the v4 fixture
contradiction); resume (b) and the 409 (c) are observed on grants that have
not died a tuple-mismatch death.

**3. `TestOrdinaryFactorUseKeepsGrant` — ordinary factor USE during a grant's
lifetime.** (Carried from v4 unchanged.)
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
re-registration over the SAME credential ID (v5: a bounded database fixture
isolates the generation predicate; r4 finding 4).**
*Setup:* C1 account with UV credential C (id K, public key P1, uv_capable
TRUE) at `factor_generation` G.
*Steps:* (a) user takes a proof → `webauthn.register` grant (fresh, bound at
the CURRENT generation G); begin binds `target_ref` = ceremony hash; (b)
**bounded fixture:** INSERT a replica of the OLD-era grant row directly —
{`proving_factor_id` = K, `bound_factor_generation` = G, operation
`recovery.regenerate`, `token_scope='session'`, the test session's JTI/family,
live TTL} — bypassing issuance so the one-live-grant delete
(`mfa_reauth.go:146-149`) cannot remove it; assert BOTH rows live (the
fixture grant and the registration grant); (c) finish with the P2
attestation → persist tx: `persistCredential`'s `ON CONFLICT (id) DO UPDATE`
swaps public_key P1 → P2 scoped to the owner (`authn/webauthn.go:287-294`),
ceremony + the PRESENTED registration grant consumed, `uv_capable`
re-persisted from the new attestation, `factor_generation` bumped to G+1 —
one commit; (d) attempt consumption of the FIXTURE grant at
`/auth/backup-codes/generate` presenting its own token → REFUSED; (e) an
assertion signed with P1 (the old key) fails verification against the
swapped row; (f) `uv_capable` reflects the NEW attestation's UV flag.
*Expected:* registration succeeds with the SAME credential ID; the refusal
at (d) is attributable to the GENERATION predicate, not to a missing row —
the fixture row was asserted present after (b) and the finish tx deletes
only the presented ceremony + grant, so the deciding mismatch is
`bound_factor_generation G ≠ current G+1` (§1.1/§1.8). This is exactly the
isolation r4 demanded: v4's fixture obtained a second grant, whose ISSUANCE
deleted the old grant before replacement, making the later refusal
unattributable. A non-UV same-ID replacement reclassifies the credential to
FALSE (cohort follows §1.2) and can never be used as a `webauthn_uv` proof
thereafter.

**5. `TestRevokeRacesIssuanceAndConsumption` — revocation racing issuance /
consumption.** (Carried from v4 unchanged.)
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
ceremonies (v5: the second family's artifacts are a bounded DB fixture; r4
finding 4).**
*Setup:* session S1 on family F (JTI₁). Through PUBLIC FLOWS only: the user
proves → live grant G_A (`refresh_family_id` F), and `webauthn.register`
begin binds G_A's target and creates ceremony row C_A {kind `registration`,
JTI₁, F}. The second session's artifacts CANNOT arise through public flows —
one live grant per user (`mfa_reauth.go:146-149`) and a new registration
ceremony deletes prior same-kind rows (§1.4) — so they are a **bounded
fixture:** INSERT grant G_B {`refresh_family_id` F₂, `session_jti` JTI₂,
operation `recovery.regenerate`, live TTL} and ceremony row C_B {kind
`registration`, `session_jti` JTI₂, `refresh_family_id` F₂, live TTL}
directly, alongside a test-held family-F₂ bearer (JTI₂).
*Steps:* (a) assert all four rows live; trigger
`revoke_user_sessions(scope='family', family=F)`
(`revoke_user_sessions.sql:71-90` — extended per §2.5 to delete grants and
ceremonies by family); (b) attempt ceremony finish + grant consumption from
family F (S1's G_A/C_A); (c) attempt to finish C_B and consume G_B
presenting the family-F₂ bearer.
*Expected:* (b) refuses twice over — G_A and C_A were deleted by the reducer
in the revocation tx, and the §2.2 durable recheck refuses the revoked
family's bearer regardless; (c) is UNAFFECTED — narrow family revocation does
not widen (`revoke_user_sessions.sql:44-46` comment): G_B and C_B survive
(SELECT counts before/after pin that the family-scope deletion matched ONLY
`refresh_family_id = F` rows), C_B finishes and G_B consumes normally. The
fixture's asserted presence at step (a) makes the non-widening attributable
to the narrow predicate rather than to absent rows — the exact defect r4
named in v4's fixture, which required two simultaneous public-flow grants.

**7. `TestC1BootstrapUVEndToEnd` — C1 login → UV proof → setup → confirm
(v5 NEW; r4 finding 3).**
*Setup:* passkey-only account: one UV-capable credential, `totp_enabled`
FALSE, `hasVerifiedMFAFactor` TRUE (§1.2) → C1; password login routes to
mandatory enrollment (`auth_policy.sql:99-117`).
*Steps:* (a) password login → `enrollment_required` response carries
`mfa_token` T (§1.5.1); assert NO `mfa_reauth_step_ups` row exists for the
user (C1 gets no password grant); (b) `POST
/auth/mfa/possession/webauthn/begin` body `{"mfa_token": T}` → 200 assertion
options with `userVerification:'required'`; ceremony row {kind
`management_assertion`, `session_jti` = T's JTI, `refresh_family_id` NULL};
(c) `POST /auth/mfa/possession/webauthn/finish` body {`mfa_token`: T,
assertion with UV, `operation`: `bootstrap.totp.enroll`} → in ONE tx the
ceremony row is consumed and the grant INSERTed:
{`token_hash = SHA-256(T)`, `session_jti` = T's JTI, operation
`bootstrap.totp.enroll`, `proof_method='webauthn_uv'`,
`proving_factor_id` = credential ID, `token_scope='mfa_pending'`,
`refresh_family_id` NULL, `target_ref` NULL, `bound_factor_generation` =
current}; response `{"granted": true}`; (d) `POST
/auth/totp/enroll/setup` body `{"mfa_token": T}` → peek matches on
`token_hash = SHA-256(presented T)` (§1.5.1 step 3), one-time binding +
pending row, returns `enrollment_id` E1; (e) `POST
/auth/totp/enroll/confirm` body {`mfa_token`: T, code from the pending
secret, `enrollment_id`: E1} → promotion tx consumes the grant, enables
TOTP, bumps `factor_generation`, writes the success audit — one commit.
*Expected:* full bootstrap completes for a C1 account with ZERO
password-grant issuance; T is the only secret on the wire end-to-end
(hash-only storage, V271 posture; issuance and consumption hash the SAME
presented bytes, §1.5.1 step 5); presenting any OTHER token at (d) →
SHA-256 mismatch → typed 403 `reauth_required`; replaying (c) → ceremony row
single-use → at most one grant ever; the identity/credential fences ran in
the setup/confirm transactions (`totp.go:124-153,306-334`).

**8. `TestAllSessionRevocationWatermark` — old tokens fail; tokens issued
after an all-session revocation succeed (v5 NEW; r4 finding 1).**
*Setup:* C1 account with TOTP enabled; live session S1 (family F, access
JTI₁, `iat` T₀ < T₁) holding an unconsumed grant. Second fixture account:
C3, no factors.
*Steps:* (a) `revoke_user_sessions(scope='all', …)` commits → row
{`not_before` ≈ T₁, `expires_at` = T₁ + 31 days}
(`revoke_user_sessions.sql:21,106-119`); (b) replay S1's access token at a
gated endpoint → refused at request authentication (`ErrRevoked`,
`authenticator.go:151`); the §4.1
`TestDurableRevocationRecheckWatermark` pins the same predicate in-tx;
(c) fresh password+TOTP login AFTER the revocation → new tokens with
`iat > not_before` authenticate; C1 proof issuance
(`POST /auth/mfa/possession/totp`) SUCCEEDS; grant consumption succeeds;
(d) the C3 account: revoke all, fresh login → `enrollment_required` +
`mfa_token`; `enroll/setup` + `confirm` complete (bootstrap issuance is NOT
blocked by the retained row); (e) boundary variant: a token with
`iat == not_before` is denied; a token with NO `iat` claim is denied
(fail-closed mirror of `authenticator.go:147-150` + `denylist.go:85`).
*Expected:* factor management and bootstrap issuance are refused only for
tokens issued at-or-before the watermark (and missing-`iat` tokens), never
for post-revocation logins — for the full 31-day retention of the row;
this is the EXISTING `IsRevoked` semantics (`denylist.go:85`) preserved
under the person fence, not a new policy.

---

## 5. Open questions for the owner

(r3/r4 confirm these do NOT block the engineering contracts above; carried,
not escalated.)

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

One omission/conflict pass over inputs (v4 + r4) vs code, then the v4→v5
supersession map.

### Omission/conflict pass

1. **r4 finding 1 (revocation watermark)** — resolved: §2.2's durable recheck
   now mirrors `SessionDenylist.IsRevoked` exactly (`denylist.go:82-99`):
   `scope='all'` denies iff `iat <= not_before` (boundary inclusive,
   `denylist_test.go:130`), `iat > not_before` survives, missing `iat` fails
   closed (`authenticator.go:147-150` zero-time → `denylist.go:85` deny;
   SQL `$4 IS NULL` → deny); `jti`/`family` stay `iat`-independent exact
   matches; row shape (31-day retention `revoke_user_sessions.sql:21`,
   single-`'all'-row` discipline `:69-70`, `not_before DEFAULT now()`
   `V055__cae_runtime_core.sql:19`) read and cited. No stricter semantics
   invented. Acceptance: §4.1 `TestDurableRevocationRecheckWatermark` (predicate),
   §4.2 `TestAllSessionRevocationThenFreshLoginManagesFactors` and §4.4 case 8
   (old fail / post-revocation succeed, both cohort shapes, boundary + missing-iat).
2. **r4 finding 2 (shared TOTP budget)** — resolved: §2.3 names ONE
   transaction-aware cycle (fence-first lock+read → check → verify → record/
   reset, `VerifyTOTPWithLockoutTx`) and inventories EVERY current caller:
   `handlers/totp.go:203` (login), `handlers/totp.go:63` (replace arm — deleted
   by §1.8, listed so it cannot survive unconverted),
   `forgot_password.go:528` (forgot-password), `totp_removal.go:85` (removal
   begin), plus the budget writer `ConfirmTOTPEnrollmentTx`
   (`totp.go:368-374/383-395`). Each caller's `TOTPBookkeepingError` refusal
   behavior is stated (login 500; forgot-password 500 without enumeration
   signal; removal 500 with the recovery-code fallback pinned not to run;
   management proof aborts issuance). Mixed-entry-point concurrency tests:
   §4.1 `TestTOTPBudgetMixedEntryPointsSerialize` +
   `TestPausedLoginCannotClearConcurrentLock` (the r4-named
   pass-check-pause-clear hole, closed by construction and tested in both
   interleaves). Kept unchanged: per-method counter columns, the
   management-only oracle (`TestProofBudgetSerializedUnderLoad`), locked
   refusals do not increment, rollback/preserved-state rules.
3. **r4 finding 3 (C1 contract)** — resolved: §1.4 scopes "new ceremony only
   under a NEW grant" to REGISTRATION ceremonies and states management-
   assertion ceremonies are authentication ceremonies following NONE →
   CEREMONY_LIVE with no grant precondition — reconciling v4:256 with v4:164
   and v4:379 (r4's contradiction). §3 completes the map: the C1 TOTP issuer
   (`POST /auth/mfa/possession/totp`, session-scope only, with the documented
   reason no bootstrap TOTP surface is reachable) and the management-assertion
   pair (`POST /auth/mfa/possession/webauthn/begin|finish`) with dual token
   admission (access bearer | presented `mfa_token`, `Type == TypeMFAPending` —
   the pending-token proof contract no existing route supplies:
   `mfa_reauth.go:231-262` accepts only password, `main.go:1053` requires
   access auth, `authenticator.go:142` rejects pending bearers), explicit
   request/response bodies, mounts, and grant hash binding for all three
   issuance shapes (C2/C3 minted-`mfa_token`; C1 session minted-
   `reauth_token`; C1 bootstrap PRESENTED `mfa_token` — matching
   consumption's `reauthTokenHash`, `mfa_reauth.go:163-212`). Acceptance:
   §4.4 case 7 (login → UV proof → setup → confirm) and §4.2
   `TestPossessionEndpointsAdmission`.
4. **r4 finding 4 (acceptance fixtures)** — resolved: case 2 split into three
   sub-scenarios on separately-minted grants with the state machine's
   delete-on-mismatch semantics fixed FIRST (a refusal kills the grant; no
   post-refusal reuse); case 4 uses a bounded database fixture (re-inserted
   old-generation grant, asserted present) so the post-replacement refusal is
   attributable to the generation predicate instead of the issuance-delete
   artifact; case 6 inserts the second family's grant + ceremony as a bounded
   fixture (public flows cannot produce two live grants per user) with
   before/after row counts pinning narrow-family non-widening.
5. **Prior rounds carried intact** — r1–r3 closures (generations §1.8,
   one-time binding §1.6, bootstrap issuance §1.5.1, person-fence unification
   §2.2 step 0, ceremony family column §1.4, per-method budgets §2.3, six
   r3-named cases §4.4 1–6) are re-asserted unchanged where r4 confirmed them
   ("the shared fence and ceremony family column themselves correctly address
   r3"; "per-method columns, management-only counter oracle and rollback rules
   are otherwise coherent"; C2/C3 bootstrap resolved).
6. **Code-vs-input conflicts carried from v4** (re-verified where re-cited):
   no production endpoint sets `push_mfa_enabled` (§3 note); registration
   covers only normalized `passkey_credentials` (`authn/webauthn.go:279-305`);
   replacement setup/confirm is broken in current code
   (`authn/totp.go:170-175`, `totp.go:283-284`) and the pending-table split is
   the fix; push's budget is separate (`auth_lockouts`,
   `push_lockout.go`) and already one-transaction — cited as shape precedent.
7. **New tension made explicit (not a redesign):** §1.1 requires
   consumption-time `operation` matching, which forces issuance-time
   operation binding; v4 left the issuance-side request member implicit. v5
   adds the required `operation` member to the NEW possession endpoints' bodies
   and notes it for `/auth/mfa/reauth` (§3). Flagged here for the reviewer.
8. **Deliberately unchanged:** §5 owner questions (non-blocking); the two
   v4-introduced test names kept where their contracts survive;
   `hms` provider support (`device.go:125`,
   `V074__restore_push_devices_native.sql:19`) recorded so §3 is not
   "corrected" back to three providers; impersonation guard placement
   illustrative (`rejectImpersonated`).
9. **Not verified by execution:** the exact `go-webauthn` field path for the
   attestation UV flag (`Credential.Flags.UserVerified` per r3's library
   check at go-webauthn@v0.17.4) — implementer confirms at implementation
   time. The new endpoints' handler files do not exist yet (specified into
   the `handlers/mfa_reauth.go` possession family); their mount postures cite
   the existing adjacent mounts they mirror. `push.go:445-448`/`415-423` and
   `device.go:19-25,125` citations are carried from v3/v4's validated map.
10. No builds/tests were run; this is a specification document. All new
    file:line citations were read from the current worktree:
    `shared/threat/{denylist,denylist_test}.go`,
    `authserver/internal/token/{authenticator,jwt,refresh}.go`,
    `authserver/internal/authn/{totp,totp_removal,webauthn,push_lockout}.go`,
    `authserver/internal/handlers/{totp,totp_removal,mfa_reauth,mfa,webauthn,
    auth,forgot_password}.go`, `authserver/cmd/authserverd/main.go`,
    `V250`-pattern `totp_removal.go`, `V055/V074/V271/V001` schemas,
    `revoke_user_sessions.sql`, `identity_auth_local_mint_fence.sql`,
    `auth_policy.sql`, webmail `auth.ts` + settings pages.

### v4 → v5 supersession map (diff aids for reviewers)

| v4 location | v5 location | Change |
|---|---|---|
| Header (v4:1-34) | Header | v5 preamble: four r4 corrections enumerated; r1-r3 history compressed; carry-forward rule restated |
| §1.4 management-assertion bullet (v4:152-163) | §1.4 | Adds endpoints (`/auth/mfa/possession/webauthn/begin|finish`), dual token admission, and the note that no existing route supplies the pending-token proof contract (`mfa_reauth.go:231-262`, `main.go:1053`, `authenticator.go:142`) |
| §1.4 ceremony-lifecycle bullet (v4:164-167) | §1.4 final two bullets | "Only possible under a NEW grant" SCOPED TO REGISTRATION ceremonies; assertion ceremonies explicitly grant-free (NONE → CEREMONY_LIVE); one-live-ceremony-per-user+kind stated for both kinds — resolves the r4 finding 3 contradiction |
| §1.5 passkey-holder bullet (v4:187-197) | §1.5 | Names the possession endpoints as the C1 bootstrap ceremony surface (contract unchanged) |
| §1.5.1 step 5 C1 bullet (v4:256-262) | §1.5.1 step 5 | C1 bootstrap issuance fully specified: finish endpoint named, no-grant precondition removed (authentication ceremony), grant INSERT columns written out, and the hash assignment made EXPLICIT (`token_hash = SHA-256(presented mfa_token)`), matching consumption (`mfa_reauth.go:163-212`); response body `{"granted": true}`; step 6 C1 atomicity note adjusted (grant commits at finish, not login) |
| §1.5.1 jwt.go citations | §1.5.1 | `IssuedAt` set at `jwt.go:295-298` (supports the watermark's `$4` for `mfa_pending`); `auth.go:734-747` → `:734-756` (branch re-pinned) |
| §1.6 flow table last row (v4:369) | §1.6 | Row names the real endpoints and the NO-grant-at-begin property |
| §1.7 NONE rows (v4:379-381) | §1.7 | Assertion-begin row: token admission named, NO grant required (registration-only rule); TOTP-proof row names `POST /auth/mfa/possession/totp` and the §2.3 one-cycle; password row notes the `operation` request member; durable-revocation row renamed "step 0b (issuance-time watermark semantics, v5)" |
| §2.2 durable recheck (v4:538-551) | §2.2 | Predicate REPLACED: watermark semantics (`$4` iat; `$4 IS NULL` fail-closed; boundary inclusive; jti/family iat-independent) with the code mirror citations (`denylist.go:82-99`, `denylist_test.go:15,130`, `authenticator.go:147-150`, `V055:19`, `revoke_user_sessions.sql:21,69-70,106-119`) and the fresh-login consequence named — corrects v4's blanket EXISTS (r4 finding 1) |
| §2.3 (v4:584-664) | §2.3 | Counter model, single-statement increment, kept semantics and management oracle unchanged; ADDED the shared-cycle subsection: caller inventory (5 items, file:line), `VerifyTOTPWithLockoutTx` cycle, construction-level closure of the pause-and-clear hole, `TOTPBookkeepingError` per-caller refusal table |
| §2.5 logout bullet (v4:677-689) | §2.5 | Adds the watermark-direction note (artifact deletion kills pre-revocation grants; the recheck covers in-flight pre-watermark tokens) |
| §3 reauth row (v4:718) | §3 | Password-only contract stated (`mfa_reauth.go:231-262`); `operation` request member added; C1 refusal names the possession endpoints |
| §3 (v4:716-731) | §3 | THREE NEW ROWS: `POST /auth/mfa/possession/totp`, `POST /auth/mfa/possession/webauthn/begin`, `POST /auth/mfa/possession/webauthn/finish` (admission, bodies, responses, mounts, hash bindings); setup row notes the deleted `handlers/totp.go:63` caller; not-gated list annotates the shared-cycle callers |
| §3.1 (v4:749-772) | §3.1 | Method-aware handoff names the concrete C1 endpoints; otherwise unchanged |
| §4.1 (v4:785-797) | §4.1 | NEW rows: `TestDurableRevocationRecheckWatermark`, `TestTOTPBudgetMixedEntryPointsSerialize`, `TestPausedLoginCannotClearConcurrentLock`; `TestBudgetBookkeepingFaultRefusesAndPreserves` gains the per-shared-caller variant; all other rows carried |
| §4.2 (v4:800-818) | §4.2 | NEW rows: `TestAllSessionRevocationThenFreshLoginManagesFactors`, `TestPossessionEndpointsAdmission`; `TestBootstrapPasskeyHolderRequiresUVProof` names the possession endpoints and the C1 hash binding; `TestImpersonationRefusedIssuanceAndConsumption` and `TestExistingFlowsUnregressed` cover the new endpoints/converted cycle |
| §4.4 case 2 (v4:856-870) | §4.4 case 2 | Fixture corrected: three sub-scenarios on fresh grants; delete-on-mismatch semantics fixed first; no post-refusal grant reuse (r4 finding 4) |
| §4.4 case 4 (v4:891-908) | §4.4 case 4 | Fixture corrected: bounded DB fixture isolates the generation predicate; refusal attributable to G vs G+1, not issuance deletion (r4 finding 4) |
| §4.4 case 6 (v4:932-949) | §4.4 case 6 | Fixture corrected: second family's grant + ceremony inserted as a bounded fixture with asserted presence and before/after row counts (r4 finding 4) |
| — | §4.4 case 7 | NEW: `TestC1BootstrapUVEndToEnd` (login → UV proof → setup → confirm; r4 finding 3) |
| — | §4.4 case 8 | NEW: `TestAllSessionRevocationWatermark` (old tokens fail; post-revocation logins succeed; boundary + missing-iat; r4 finding 1) |
| §5 (v4:953-971) | §5 | Carried verbatim (non-blocking) |
| Self-check (v4:975-1057) | Self-check | Rewritten: omission/conflict pass keyed to r4 findings 1-4, then this supersession map |
