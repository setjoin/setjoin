# ADR: ARCH-002 — Shared Database Architecture

**Status:** Accepted  
**Date:** 2026-05-15  
**Source:** `auditbykimi_comprehensive.md` (ARCH-002), `auditbyminimax.md`

## Context

The gateway and authserver share a PostgreSQL database and the same `JWT_SECRET`. Both audit documents flagged this as tight coupling — a schema change in one service affects the other. Alternatives proposed: event-driven (NATS/RabbitMQ) or gRPC API layer.

## Decision

We accept shared database coupling as the correct architecture for SMB scale (< 1000 users). The project's core philosophy — "database IS the application server" — makes this coupling intentional and necessary. We mitigate the risks through three lightweight practices rather than through infrastructure changes.

## Mitigations

### 1. PL/pgSQL Functions as API Contract

Both services call the same stored procedures for shared logic — no raw table queries cross service boundaries. This is the database equivalent of a service API:

| Function | Called By | Purpose |
|----------|-----------|---------|
| `validate_password()` | Gateway + Authserver | Password complexity enforcement |
| `mfa_status()` | Gateway + Authserver | MFA policy checks |
| `authenticate()` | Gateway | User verification |
| `check_quota()` | Gateway | Storage quota enforcement |

If the `users` table schema changes, only the PL/pgSQL function needs to be updated — both Go services continue to work unchanged as long as the function signature is stable.

### 2. Shared Kernel Library

The `shared/` module provides Go types and functions used by both services:

| Package | What It Provides |
|---------|-----------------|
| `shared/pwhash` | `User` struct, `CheckPassword()`, `HashPassword()`, `LookupByEmail()` |
| `shared/cryptokey` | `DeriveCookieKey()` via HKDF-SHA256 |
| `shared/envutil` | `Getenv()`, `ParseBool()`, `RandomID()` |

Both services import `shared` with `replace` directives in their `go.mod` files. A schema change that affects the User struct is caught by the Go compiler when the shared module is updated.

### 3. JWT Secret via Environment Variable

Both services read `JWT_SECRET` from the same environment variable. At SMB scale, both are deployed together from the monorepo, so configuration drift is impossible.

**JWT Secret Rotation Procedure:**

1. Generate a new 32+ character secret
2. Set both `JWT_SECRET=new_key` and `JWT_SECRET_PREV=old_key` on both services
3. For a 5-minute overlap window, accept tokens signed with either key
4. After 5 minutes (max access token TTL), remove `JWT_SECRET_PREV`
5. Single-command deploy: `systemctl restart both-services`

### 4. Config Validation at Startup

Both services now validate configuration on startup and return errors gracefully instead of crashing with `panic()`. A misconfigured `JWT_SECRET` produces a clear error before the server accepts connections.

## Revisit Triggers

We will reassess this architecture when any of these occur:

| Trigger | Why Revisit |
|---------|------------|
| **10,000+ users** | DB may become the bottleneck; read replicas needed |
| **Third service added** | Coordination cost rises with each new DB client |
| **Separate team ownership** | Two independent teams modifying the same schema creates conflict |
| **Independent deploy cycles** | If authserver needs weekly patches but gateway is monthly, coupling becomes painful |
| **DB read replica load** | One noisy service causes replica lag that affects the other |

At that point, the gRPC option becomes the logical next step — replacing direct DB queries with a well-defined API. Event-driven (NATS/RabbitMQ) is only justified for asynchronous, eventually-consistent workflows.

## Consequences

| Aspect | Impact |
|--------|--------|
| Positive | Zero network latency for auth decisions (IMAP LOGIN runs in one DB round-trip) |
| Positive | Single schema migration file — no coordination between separate DBs |
| Positive | PL/pgSQL functions provide compile-time interface between services |
| Negative | Schema changes require coordinated deploys (both services briefly) |
| Negative | A bad migration can affect both services simultaneously |
| Neutral | JWT is signed/verified locally on each service — no remote token validation |
