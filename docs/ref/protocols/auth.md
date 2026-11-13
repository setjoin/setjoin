## Authentication Protocol Requirements
> **OIDC Core 1.0**, **SAML 2.0** (OASIS), **RFC 6238** (TOTP), **RFC 4226** (HOTP), **RFC 4120** (Kerberos), **FIDO2/WebAuthn**, **RFC 7519** (JWT)

### OIDC — Core 1.0
- Nonce MUST be generated in login, stored in cookie, validated in callback (§3.1.2.1, §15.5.2)
- NEEDS FIX: `OIDCLogin` generates state but not nonce; `OIDCCallback` validates state but not nonce
- `c_hash` (code hash) MUST be validated: SHA-256 of authorization code, first 128 bits (§3.1.3.7, §16.11)
- `at_hash` (access token hash) MUST be validated via `idToken.VerifyAccessToken()` (§3.1.3.7)
- `redirect_uri` MUST be validated in callback handler (§3.1.2.7)
- `email_verified` claim SHOULD be checked; UserInfo endpoint SHOULD be queried

### TOTP — RFC 6238
- Replay protection: reject if same code within 30s window (§5.2). Track `last_totp_used_at`
- Per-account lockout: increment `totp_failed_attempts`, lock after 5 failures (§7.2-7.3)
- Kerberos SSO MUST NOT bypass TOTP: if user has `totp_enabled=TRUE`, issue `TypeMFAPending`

### Kerberos — RFC 4120
- SPN/Realm MUST be enforced: validate `creds.Realm()` against configured `KerberosRealm`
- Enctype restrictions SHOULD be set — gokrb5/v8 does not support per-enctype filtering
- `MaxClockSkew(5*time.Minute)` MUST be set on service settings
- `RequireHostAddr(true)` MUST be set on service settings

### SAML — SAML Core 2.0
- SP-initiated SSO MUST have route registered: `/auth/saml/login` 
- Signing method MUST be RSA-SHA256, NOT RSA-SHA1:
  `middleware.ServiceProvider.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"`
- `SignRequest: true` MUST be set in `samlsp.Options`
- Assertion replay detection: check `used_saml_assertions` table for assertion IDs

### WebAuthn — FIDO2 / Level 2
- User handle MUST be opaque random bytes (≥32), NOT deterministic integer:
  `webauthn_user_handle BYTEA` column populated with `crypto/rand.Read()`

### JWT — RFC 7519
- All tokens MUST include `kid` header: `"mailserver-hmac-1"`
- Validation MUST check `kid` before accepting a token

### DO NOT
- Do NOT skip nonce validation — go-oidc docs state "Verify does NOT do nonce validation"
- Do NOT use RSA-SHA1 for SAML signing — SHA-1 deprecated since 2013
- Do NOT use `fmt.Sprintf("%d", u.id)` for WebAuthn user handle — must be random
- Do NOT issue `TypeAccess` from Kerberos when user has TOTP enabled

### Verification
```bash
go test ./internal/auth/... -v
```
