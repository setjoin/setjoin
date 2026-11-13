**V5 closes the watermark and shared-TOTP serialization findings, but is not yet implementation-ready.** Three blocking issues remain. Read-only review; no files changed or tests run.

1. **[P1] The issuance request contracts still cannot supply all required bindings.**

   V5 requires `webauthn.revoke` grants to bind the credential ID **at issuance** (v5:432 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:432)), but none of the specified password, TOTP or WebAuthn issuance bodies carries that target (v5:911 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:911)). The existing code obtains the credential ID only at the later DELETE endpoint ([webauthn.go:338](/authserver/internal/handlers/webauthn.go:338)); the password issuer currently accepts only `password` ([mfa_reauth.go:233](/authserver/internal/handlers/mfa_reauth.go:233)).

   Similarly, assertion ceremonies require an operation when created (v5:148 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:148)), but the new WebAuthn contract specifies `operation` only at **finish**, not begin (v5:913 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:913)). Session-scope begin cannot derive whether the assertion authorizes registration, revocation or recovery regeneration.

   **Correction:** specify operation at assertion begin, enforce equality at finish, and supply the revoke target to each applicable issuer. Pin its encoding and ownership validation. Add successful targeted-revocation tests plus changed-operation/changed-target refusals. The C1 bootstrap lifecycle and presented-token hash binding themselves are corrected.

2. **[P2, new] The assertion-begin mount omits CSRF despite mutating cookie-authenticated state.**

   V5:913 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:913) explicitly mounts begin with only the threat interceptor because it “authorizes nothing by itself.” However, begin **deletes the user’s existing management assertions** (v5:198 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:198)).

   Actual access authentication accepts the ambient cookie ([authenticator.go:125](/authserver/internal/token/authenticator.go:125)). A same-site, cross-origin browser request can therefore replace an outstanding ceremony without proving possession. `SameSite=Strict` does not establish same-origin protection; the existing CSRF middleware explicitly checks scheme, host and port ([csrf.go:57](/shared/middleware/csrf.go:57)). The usual auth decoder also accepts non-JSON content types ([json_ingress.go:17](/authserver/internal/handlers/json_ingress.go:17)).

   **Correction:** apply CSRF to begin’s cookie-authenticated path, preserving the documented native/pending-token behavior. Add a mux test showing a foreign-origin request cannot delete an existing ceremony.

3. **[P2, residual r4] Family-isolation case 6 remains internally impossible.**

   Its second-family fixture creates **G_B for `recovery.regenerate`** alongside **C_B of kind `registration`** (v5:1175 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:1175)), then expects C_B to finish and G_B to consume normally (v5:1190 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:1190)).

   Registration finish requires a `webauthn.register` grant bound to that ceremony and consumes both together (v5:431 (retired-docs:verification/2026-09-23-possession-scheme-v5.md:431)). The recovery grant cannot authorize it. Adding a separate registration grant would also make successful registration advance the generation and invalidate G_B.

   **Correction:** fixture G_B as a correctly bound `webauthn.register` grant and assert one successful registration consuming G_B/C_B. Test surviving recovery grants separately.

The r4 disposition is:

| Finding | Round-5 disposition |
|---|---|
| Revocation watermark | **Closed at specification level.** The SQL matches inclusive `iat <= not_before` and missing-`iat` refusal in [denylist.go:82](/shared/threat/denylist.go:82). |
| Shared TOTP serialization | **Closed at specification level.** The complete fenced cycle, caller inventory and refusal mappings address the separate operations in [totp.go:510](/authserver/internal/authn/totp.go:510). |
| C1 bootstrap | Lifecycle, admission and hash binding corrected; the broader issuance transport contract remains incomplete as above. |
| Acceptance fixtures | Cases 2 and 4 corrected; case 6 still contradicts the required operation/binding semantics. |

ASTRA REVIEW: HOLD — complete issuance bindings, protect assertion begin against CSRF, and correct the family-isolation fixture.
