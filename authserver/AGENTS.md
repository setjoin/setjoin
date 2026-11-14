# authserver — DOX child AGENTS.md

Owns authentication/signing/MFA/directory and threat contracts. Auth and mail share the combined schema; never execute authserver/sql/_archive. Schema mismatch refuses startup. Preserve request/worker/listener separation, subscribe-before-reload and fail-closed snapshots. shared/jwtutil owns claims/verification; preserve kid/algorithm, issuer/audience binding, encrypted custody and separate OIDC keys. Credential-accepting anonymous endpoints require threat interception; authenticated mutations require CSRF. Config changes update struct/defaults/loader/env contract; token changes include every accept/reject consumer. Read startup/signing and affected feature sections, DATABASE_SECURITY for queries and corresponding auth/protocol standards.

## DOX sections

- [1. Purpose](DOX.md#1-purpose)
- [2. Ownership](DOX.md#2-ownership)
- [3. Local Contracts](DOX.md#3-local-contracts)
  - [Shared PostgreSQL cluster](DOX.md#shared-postgresql-cluster)
  - [Three DB connections](DOX.md#three-db-connections)
  - [Startup order (mandatory)](DOX.md#startup-order-mandatory)
  - [Token signing](DOX.md#token-signing)
  - [Auth priority chain (gateway-side, not this server)](DOX.md#auth-priority-chain-gateway-side-not-this-server)
  - [Key files](DOX.md#key-files)
  - [Environment variables](DOX.md#environment-variables)
- [4. Features / Capabilities](DOX.md#4-features--capabilities)
  - [Password authentication](DOX.md#password-authentication)
  - [JWT lifecycle](DOX.md#jwt-lifecycle)
  - [OAuth2 token introspection (RFC 7662)](DOX.md#oauth2-token-introspection-rfc-7662)
  - [OAuth2 token revocation (RFC 7009)](DOX.md#oauth2-token-revocation-rfc-7009)
  - [OAuth2 Authorization Server Metadata (RFC 8414)](DOX.md#oauth2-authorization-server-metadata-rfc-8414)
  - [XOAUTH2 / app passwords (IMAP/SMTP SASL)](DOX.md#xoauth2--app-passwords-imapsmtp-sasl)
  - [TOTP (RFC 6238)](DOX.md#totp-rfc-6238)
  - [WebAuthn / passkeys (FIDO2)](DOX.md#webauthn--passkeys-fido2)
  - [Push MFA (number matching)](DOX.md#push-mfa-number-matching)
  - [Backup codes](DOX.md#backup-codes)
  - [MFA first-factor possession gate (possession scheme v7; supersedes nightly-16 step-up)](DOX.md#mfa-first-factor-possession-gate-possession-scheme-v7-supersedes-nightly-16-step-up)
  - [Forgot password (self-service reset via MFA)](DOX.md#forgot-password-self-service-reset-via-mfa)
  - [SAML 2.0 SP](DOX.md#saml-20-sp)
  - [OIDC Relying Party (RP)](DOX.md#oidc-relying-party-rp)
  - [OIDC Identity Provider (OP / IdP mode)](DOX.md#oidc-identity-provider-op--idp-mode)
  - [Identity resolution — resolve_identity seam (ADR-004 Half A)](DOX.md#identity-resolution--resolve_identity-seam-adr-004-half-a)
  - [JIT (Just-In-Time) user provisioning](DOX.md#jit-just-in-time-user-provisioning)
  - [Kerberos / SPNEGO](DOX.md#kerberos--spnego)
  - [AD / LDAP identity sync](DOX.md#ad--ldap-identity-sync)
  - [8-step pre-auth threat pipeline](DOX.md#8-step-pre-auth-threat-pipeline)
  - [Conditional access](DOX.md#conditional-access)
  - [Device trust](DOX.md#device-trust)
  - [Admin impersonation](DOX.md#admin-impersonation)
  - [SCIM session revocation](DOX.md#scim-session-revocation)
  - [Login events](DOX.md#login-events)
  - [Config hot reload](DOX.md#config-hot-reload)
  - [Well-known / version](DOX.md#well-known--version)
  - [API endpoint index](DOX.md#api-endpoint-index)
- [5. Work Guidance](DOX.md#5-work-guidance)
- [6. Verification](DOX.md#6-verification)
- [7. Child DOX Index](DOX.md#7-child-dox-index)

Auth background task recording: [runtime oracle](DOX.md#auth-runtime-recording-202).

OIDC RP task transfer: [named listener gate](DOX.md#oidc-rp-listener-transfer-340).

SAML SP task transfer: [named listener gate](DOX.md#saml-sp-listener-transfer-341).
