# OIDC Provider (IdP) Mode — zitadel/oidc Migration

## Problem

The authserver can authenticate users AGAINST external OIDC providers (RP mode via coreos/go-oidc), but cannot act AS an OIDC identity provider for other applications. Applications like Grafana, GitLab, or custom internal tools need their own SSO solution instead of using our authserver.

Additionally, using two separate libraries (coreos/go-oidc for RP + whatever we'd add for OP) adds complexity. Migrating both RP and OP to [zitadel/oidc](https://github.com/zitadel/oidc) — an OpenID Foundation certified library — simplifies the codebase and gives us both directions with one dependency.

## Design

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    authserver                            │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │         zitadel/oidc (single library)             │   │
│  │                                                   │   │
│  │  pkg/client/rp  ←── RP mode (unchanged behavior)  │   │
│  │  pkg/op         ←── OP mode (NEW)                 │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  OIDC RP (existing):         OIDC OP (new):             │
│  /auth/oidc/login             /.well-known/...           │
│  /auth/oidc/callback          /authorize                 │
│                               /token                     │
│                               /userinfo                  │
│                               /jwks                      │
└──────────────────────────────────────────────────────────┘
```

### RP Migration: coreos/go-oidc → zitadel/oidc RP

**Replacements:**

| Old | New |
|-----|-----|
| `gooidc.NewProvider(ctx, url)` | `rp.NewRelyingPartyOIDC(ctx, issuer, clientID, secret, redirectURI, scopes)` |
| Manual `oauth2.Config` + `gooidc.Verifier` | Single `rp.RelyingParty` handles everything |
| Manual `at_hash` / `c_hash` validation | Automatic via library |
| Manual `idToken.Claims(&claims)` | `*oidc.IDTokenClaims` with typed fields |
| Custom `GroupsFromIDToken(...)` | `claims.Claims` map for custom claims like `groups` |

**Simplifies:** ~80 lines of manual OIDC protocol wiring → ~30 lines of library calls. State, nonce, PKCE, and token verification handled automatically.

### OP Implementation: Storage Interface

The zitadel/oidc OP package requires a `Storage` interface. We implement it backed by PostgreSQL (same pattern as our existing PL/pgSQL reducers — business logic in PG, thin Go wrapper).

```go
// PGStorage implements op.Storage backed by PostgreSQL.
type PGStorage struct {
    pool   *pgxpool.Pool
    issuer string
}

// Required methods:
func (s *PGStorage) CreateAuthRequest(ctx, authReq, userID) (op.AuthRequest, error)
func (s *PGStorage) AuthRequestByID(ctx, id) (op.AuthRequest, error)
func (s *PGStorage) AuthRequestByCode(ctx, code) (op.AuthRequest, error)
func (s *PGStorage) CreateAccessToken(ctx, request) (id string, expiration time.Time, err error)
func (s *PGStorage) CreateAccessAndRefreshTokens(ctx, request, currentRefreshToken string) (...)
func (s *PGStorage) TokenRequestByRefreshToken(ctx, refreshToken) (op.TokenRequest, error)
func (s *PGStorage) GetClientByClientID(ctx, clientID) (op.Client, error)
func (s *PGStorage) AuthorizeClientIDSecret(ctx, clientID, clientSecret) error
func (s *PGStorage) GetKeyByIDAndClientID(ctx, keyID, clientID) (*jose.JSONWebKey, error)
func (s *PGStorage) SetUserinfoFromToken(ctx, userinfo, tokenID, subject, origin) error
func (s *PGStorage) SetUserinfoFromScopes(ctx, userinfo, userID, scopes) error
func (s *PGStorage) GetPrivateClaimsFromScopes(ctx, userID, scopes) (map[string]interface{}, error)
func (s *PGStorage) SignatureAlgorithms(ctx) ([]jose.SignatureAlgorithm, error)
func (s *PGStorage) KeySet(ctx) ([]jose.SigningKey, error)
func (s *PGStorage) GetRefreshTokenInfo(ctx, refreshToken) (userID, tokenID string, err error)
```

**Simplified approach:** We implement the storage methods that the authorization code flow needs (the ones above). Unused flows (device auth, JWT profile, etc.) return `ErrNotImplemented`.

### Schema

```sql
-- OIDC clients registered with our IdP
CREATE TABLE oidc_clients (
    id              TEXT PRIMARY KEY,        -- client_id
    name            TEXT NOT NULL,
    secret          TEXT NOT NULL,           -- bcrypt-hashed client secret
    redirect_uris   TEXT[] NOT NULL,         -- allowed redirect URIs
    grant_types     TEXT[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    scopes          TEXT[] NOT NULL DEFAULT '{openid,profile,email}',
    enabled         BOOL NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Active authorization requests (short-lived, cleaned by cron)
CREATE UNLOGGED TABLE oidc_auth_requests (
    id              TEXT PRIMARY KEY,        -- request ID
    client_id       TEXT NOT NULL REFERENCES oidc_clients(id),
    redirect_uri    TEXT NOT NULL,
    state           TEXT NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT,
    code_challenge_method TEXT,
    scopes          TEXT[] NOT NULL,
    user_id         BIGINT,                  -- set after authentication
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT now() + INTERVAL '10 minutes'
);

-- Issued tokens (for refresh + introspection)
CREATE TABLE oidc_tokens (
    id              TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES oidc_clients(id),
    user_id         BIGINT NOT NULL REFERENCES users(id),
    refresh_token_hash TEXT,                 -- SHA-256 of refresh token
    scopes          TEXT[] NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cron: prune expired auth requests every 5 min
-- Cron: prune revoked/expired tokens daily
```

### Security Design

| Concern | Implementation |
|---------|---------------|
| **Token signing** | RSA 2048-bit keypair (generated on first boot, stored encrypted). `RS256` algorithm. Public key exposed via JWKS endpoint. |
| **Client auth** | `client_secret_post` (primary) + `client_secret_basic`. Secrets bcrypt-hashed in `oidc_clients`. |
| **PKCE** | Required for all clients. `S256` only — `plain` rejected. |
| **Redirect URIs** | Exact match only. No wildcards, no partial matches. |
| **State** | Cryptographically random, validated on callback. |
| **Access tokens** | 5-minute TTL. Signed JWT with `sub`, `iss`, `aud`, `exp`, `iat`, `jti`. |
| **Refresh tokens** | 30-day TTL. Rotation with theft detection (same pattern as existing refresh token rotation). SHA-256 stored. |
| **Authorization codes** | Single-use, 10-minute TTL. Deleted after exchange. |
| **Cookies** | `HttpOnly`, `Secure`, `SameSite=Strict` for login session. |
| **Rate limiting** | Existing threat interceptor wraps `/authorize` endpoint. |

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | No | OIDC Discovery |
| `GET` | `/jwks` | No | Public key set (RS256) |
| `GET` | `/authorize` | Session | Authorization endpoint — login page redirect |
| `POST` | `/token` | Client | Token endpoint — code exchange, refresh |
| `GET` | `/userinfo` | Bearer | User claims (sub, email, name) |

### Login Flow

```
1. App redirects user to GET /authorize?client_id=grafana&redirect_uri=...&state=...
2. If user not logged in → show login page (reuse existing login UI)
3. After login (password/WebAuthn/TOTP/passkey) → redirect back with code
4. App POST /token with code + client_secret → receives access_token + refresh_token
5. App GET /userinfo with Bearer access_token → receives user profile
```

### Data Flow

```
/authorize
  → Validate client_id, redirect_uri
  → Store auth request in oidc_auth_requests
  → Show login page (reuse existing login handler)
  → After auth: set user_id on auth request
  → Redirect to app with ?code=...&state=...

/token (POST, client_secret_post)
  → Validate client_id + client_secret
  → Lookup auth request by code
  → Delete auth request (single-use)
  → Generate access token (JWT, 5min TTL)
  → Generate refresh token (opaque, SHA-256 stored)
  → Return {access_token, refresh_token, id_token, expires_in}

/userinfo (GET, Bearer token)
  → Validate access token JWT
  → Lookup user
  → Return {sub, email, name, email_verified}
```

### Scope

| Layer | What | Lines |
|-------|------|-------|
| Schema | `oidc_clients` + `oidc_auth_requests` + `oidc_tokens` tables | ~50 |
| Key management | RSA keypair gen, JWKS endpoint | ~40 |
| OP Storage | PG-backed implementation of op.Storage | ~150 |
| OP endpoints | SetupServer wiring, route registration | ~40 |
| RP migration | Replace coreos/go-oidc with zitadel/oidc RP | ~60 net (simplification) |
| Admin API | Client CRUD | ~40 |
| Admin UI | Client management page | ~50 |
| **Total** | | **~430 lines** |

### Dependencies

- Add: `github.com/zitadel/oidc/v3` (replaces `github.com/coreos/go-oidc/v3`)
- Add: `github.com/go-jose/go-jose/v4` (JWT signing, comes with zitadel/oidc)
- Remove: `github.com/coreos/go-oidc/v3`
