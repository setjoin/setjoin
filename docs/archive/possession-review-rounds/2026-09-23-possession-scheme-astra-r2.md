V2 improves the scheme, but several r1 findings remain unresolved. This is a design-readiness review against current source; no files changed or tests executed.

1. **[P1] Proof provenance and the shared revocation fence remain incomplete.**  
   The grant tuple (retired-docs:verification/2026-09-23-possession-scheme-v2.md:10) omits proof method and proving-factor identity; the migration (retired-docs:verification/2026-09-23-possession-scheme-v2.md:90) adds only proving-factor **version**. The mutation target cannot also identify the credential authorizing it—for example, TOTP authorizing revocation of a passkey.

   Atomic consumption is correctly specified, but the scheme must also define serialization against factor changes. [V250](/authserver/internal/authn/totp_removal.go:218) locks the user row; [passkey revocation](/authserver/internal/authn/webauthn.go:198) independently updates a credential row. Merely placing validation and consumption in one transaction does not close that race.

   Likewise, excluding pending replacements from proofs does not specify their storage lifecycle. [TOTP setup](/authserver/internal/authn/totp.go:170) overwrites the active secret, while [confirmation](/authserver/internal/authn/totp.go:278) accepts only disabled TOTP. V2 needs explicit separate staging, preservation of the active factor, and atomic promotion/version change.

2. **[P1] The referenced failure budget does not exist.**  
   V2:31 (retired-docs:verification/2026-09-23-possession-scheme-v2.md:31) says issuance shares “V271’s lockout budgeting.” Actual [reauth issuance](/authserver/internal/handlers/mfa_reauth.go:255) invokes a [password verifier without counters](/authserver/internal/authn/totp_removal.go:115). Existing TOTP verification still [ignores lock-state read errors](/authserver/internal/authn/totp.go:510), [writes a previously calculated failure count](/authserver/internal/authn/totp.go:467), and can return acceptance alongside a bookkeeping error.

   R1 required the authoritative account budget, serialized updates, explicit password/WebAuthn limits, shared TOTP five-failure/15-minute policy, and fail-closed issuance. V2 specifies none of those mechanics or limits.

3. **[P1] Mandatory bootstrap is listed, but its authorization path is undefined.**  
   V2:38 (retired-docs:verification/2026-09-23-possession-scheme-v2.md:38) points bootstrap to §4, which only describes removal. [Enrollment setup](/authserver/internal/handlers/totp.go:104) accepts an `mfa_pending` token before any access session exists; [reauth issuance](/authserver/internal/handlers/mfa_reauth.go:225) requires an access token.

   This needs a concrete pre-session grant/ceremony contract, including token-type binding and issuance eligibility. It must distinguish zero-factor bootstrap from passkey-holder enrollment: [current policy](/mailserver/sql/reducers/auth_policy.sql:99) deliberately sends passkey-only password logins into mandatory enrollment. “NOT exempt” alone leaves implementers choosing between blocking legitimate bootstrap and retaining password-only enrollment for existing passkey holders.

4. **[P1] Single-use grants do not establish single-use WebAuthn proofs.**  
   V2:44 (retired-docs:verification/2026-09-23-possession-scheme-v2.md:44) requires UV, but does not define the dedicated assertion ceremony’s server-side challenge record, account/session/operation binding, expiry, or atomic consumption when issuing a grant. Those requirements appear largely as acceptance-test names.

   Existing [BeginLogin](/authserver/internal/authn/webauthn.go:125) supplies ordinary login options; [login completion](/authserver/internal/handlers/webauthn.go:120) completes authentication. Existing registration stores [ceremony state in an encrypted cookie](/authserver/internal/handlers/webauthn.go:36). None supplies the missing management-proof lifecycle. Consuming each resulting grant once does not prevent one replayed assertion from producing successive grants.

5. **[P1] Normalized credentials are not necessarily UV-capable.**  
   V2’s cohort rule (retired-docs:verification/2026-09-23-possession-scheme-v2.md:48) associates normalized WebAuthn credentials with UV capability. Current [registration](/authserver/internal/authn/webauthn.go:60) does not explicitly require UV, and the [normalized schema](/mailserver/sql/dbschema/V001__baseline.sql:4721) contains no UV-capability classification.

   A normalized credential that cannot perform UV, with no TOTP, has no specified cohort. Define authoritative treatment of existing/unknown/non-UV credentials and mixed cohorts. A cancelled or failed UV assertion must not itself qualify the account for password fallback.

6. **[P1] JTI binding alone does not implement the promised session invalidation.**  
   V2:22 (retired-docs:verification/2026-09-23-possession-scheme-v2.md:22) claims replacement/logout/account-switch invalidation “via JTI.” JTI equality prevents using a grant with a different token; it does not invalidate a retained matching old-token/grant pair.

   [Refresh](/authserver/internal/token/refresh.go:285) rotates the refresh-token record and [mints another access token](/authserver/internal/token/refresh.go:369). [Access authentication](/authserver/internal/token/authenticator.go:138) checks validity and revocation, rather than requiring the newest access JTI. Specify the durable grant/session-generation invalidation mechanism and its consumption-time fence. “Grants are not refreshed” does not supply that mechanism.

7. **[P2] The general Settings TOTP handoff remains omitted.**  
   V2’s webmail section (retired-docs:verification/2026-09-23-possession-scheme-v2.md:78) explicitly updates `/settings/security` and `/settings` passkey registration. But `/settings` also directly calls [TOTP setup and confirmation without grants](/mailserver/webmail/src/routes/settings/+page.svelte:427).

   Explicitly cover those handlers and discard stale responses before assigning secrets or recovery codes. Server-side tuple checks cannot retract a successful response already travelling to a browser that subsequently changes accounts.

The r1 disposition is:

| R1 finding | Re-review result |
|---|---|
| 1. Grant lifecycle/atomicity | Partial: TTL, operation binding and atomic mutation/audit are specified; provenance and ceremony transitions remain incomplete. |
| 2. Revocation/replacement | Partial: invalidation intent is stated; shared serialization and staged replacement remain undefined. |
| 3. Mutation inventory | Native registration is explicitly included; bootstrap authorization remains unresolved. |
| 4. Failure counters | Unresolved; references nonexistent V271 budgeting. |
| 5. WebAuthn ceremony | UV requirement added; dedicated ceremony lifecycle remains unresolved. |
| 6. Impersonation | Resolved **at scheme level** by unconditional issuance and consumption refusal, including the removal flow. |
| 7. Compatibility/webmail | Recovery-removal exception resolved; cohort classification and general Settings coverage remain incomplete. |

The forward migration and clean-cut legacy-grant invalidation are concrete improvements. The expanded acceptance list is useful, but cannot substitute for the missing contracts.

One prioritized fix plan:

1. **Complete the scheme’s state model:** proof method plus proving-factor ID/version, operation/enrollment identity, begin-versus-finish transitions, dedicated WebAuthn challenge lifecycle, bootstrap token binding, cohort classification, and session invalidation.
2. **Specify database authority:** shared lock ordering across issuance, factor changes and consumption; separate pending TOTP storage; atomic promotion, grant consumption and success audit; serialized failure budgets with explicit thresholds and failure handling.
3. **Map every endpoint and client:** identify owning handlers, distinguish native authentication devices from WebPush subscriptions, retain the removal decision table, and cover both Settings TOTP flows plus passkey registration.
4. **Make acceptance executable:** require database race/fault tests, handler/mux coverage and browser lifecycle tests. Include assertion replay producing multiple grants, normalized non-UV credentials, retained old-token/grant pairs after refresh, bootstrap with existing passkeys, and cancellation preserving active TOTP. Correct “DB/booking” to “DB/bookkeeping.”

ASTRA REVIEW: HOLD — bootstrap authorization, failure budgets, proof lifecycle, revocation fencing and cohort handling remain insufficiently specified.
