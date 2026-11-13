# SCIM Provisioning — Design Spec

> **Roadmap item:** Stage 2.5 — "Regulated-Industry Ready" identity automation
> **Date:** 2026-05-31 | **Effort:** ~3 weeks | **Filed under:** `mailserver/gateway/internal/scim/`, `authserver/internal/handlers/scim.go`

## Goal

Provide a SCIM 2.0 server endpoint (RFC 7644) so identity providers — Entra ID, Okta, OneLogin, PingFederate — can push users and groups into the mailserver. Create, update, disable, and delete user lifecycle flows with full attribute mapping. Group push drives distribution group membership. Incremental sync via `syncToken` keeps the IdP in sync without full re-import. This is table-stakes for enterprise procurement: RFPs from organizations with >500 users universally ask for SCIM.

## Architecture

A new `scim` package in the gateway exposes `/scim/v2/Users` and `/scim/v2/Groups` endpoints behind Bearer token auth (a provisioned SCIM API key, separate from the gateway's internal API key). The gateway validates the Bearer token against a new `scim_tokens` table, then proxies user CRUD and group membership operations to PostgreSQL reducers. The authserver is informed only for token revocation events (user disable → revoke all sessions). All SCIM operations are idempotent: externalId (the IdP's stable identifier) is stored on `users.scim_external_id` and `distribution_groups.scim_external_id`, making repeated PATCH requests safe.

```
IdP (Entra ID / Okta)
    │  POST/PATCH/GET/DELETE  /scim/v2/{Users,Groups}
    │  Authorization: Bearer <scim_token>
    ▼
┌─────────────────────────────────────────────┐
│  gateway/internal/scim/                      │
│  ├── server.go       HTTP handler, auth,     │
│  │                    JSON serialization      │
│  ├── user.go         User resource CRUD      │
│  ├── group.go        Group resource CRUD     │
│  ├── patch.go        PATCH op interpreter    │
│  ├── filter.go       SCIM filter parser      │
│  └── schemas.go      Core/Enterprise schemas │
├─────────────────────────────────────────────┤
│  PostgreSQL reducers (shared)                │
│  ├── scim_upsert_user(p_external_id, ...)    │
│  ├── scim_disable_user(p_external_id)        │
│  ├── scim_delete_user(p_external_id)         │
│  ├── scim_upsert_group(p_external_id, ...)   │
│  └── scim_apply_group_members(p_group_id,    │
│          p_member_external_ids[])             │
├─────────────────────────────────────────────┤
│  authserver/internal/handlers/scim.go         │
│  └── PostSCIMDisable → revoke all sessions   │
│      for the disabled user via NOTIFY        │
└─────────────────────────────────────────────┘
```

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `mailserver/gateway/internal/scim/server.go` | **Create** | Mux registration, Bearer auth check, JSON `application/scim+json` content-type handling |
| `mailserver/gateway/internal/scim/user.go` | **Create** | `GET/POST/PUT/PATCH/DELETE /Users` — map SCIM user resource to `users` table columns |
| `mailserver/gateway/internal/scim/group.go` | **Create** | `GET/POST/PATCH/DELETE /Groups` — map SCIM group resource to `distribution_groups` + members |
| `mailserver/gateway/internal/scim/patch.go` | **Create** | RFC 7644 PATCH interpreter: `add`, `replace`, `remove` operations on user/group attributes |
| `mailserver/gateway/internal/scim/filter.go` | **Create** | SCIM filter parser (attribute+operator+value) for `GET /Users?filter=userName eq "..."` — `eq`, `co`, `sw` operators |
| `mailserver/gateway/internal/scim/schemas.go` | **Create** | SCIM core schema (`urn:ietf:params:scim:schemas:core:2.0:User`, `:Group`) + enterprise extension (`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User`) structs |
| `mailserver/gateway/internal/scim/scim_test.go` | **Create** | httptest unit tests covering CRUD, PATCH, filter, error responses |
| `mailserver/sql/migrations/V0NN__scim_schema.sql` | **Create** | `scim_tokens` table, `users.scim_external_id`, `distribution_groups.scim_external_id`, indexes, SCIM reducers |
| `mailserver/sql/tests/scim.pg` | **Create** | pgTAP tests for SCIM reducers |
| `authserver/internal/handlers/scim.go` | **Create** | `POST /auth/scim/disable` — revoke sessions for SCIM-disabled users (called by gateway via internal API) |
| `mailserver/gateway/internal/handlers/auth_proxy.go` | **Modify** | Route `/scim/*` to scim package, `/auth/scim/*` to authserver |
| `mailserver/gateway/internal/config/config.go` | **Modify** | Add `SCIM_ENABLED` feature toggle |

## Key Design Decisions

1. **Gateway-led, not authserver-led.** SCIM is primarily a user-provisioning and group-membership operation — it touches the `users`, `distribution_groups`, and `distribution_group_members` tables, all of which live in the mailserver database. The authserver is only involved for session revocation on disable/delete. Routing SCIM through the gateway avoids duplicating user CRUD logic across two servers. The gateway's scim package talks directly to PostgreSQL reducers; the gateway calls the authserver's `/auth/scim/disable` endpoint (with the internal API key) only when a user is deprovisioned.

2. **Separate SCIM API key, not JWT reuse.** SCIM clients (Entra ID provisioning agent, Okta SCIM app) expect a static Bearer token configured in their provisioning UI. A `scim_tokens` table stores named tokens with optional expiry. Tokens are hashed with bcrypt at rest. The admin console (Phase 13) provides UI for provisioning and rotating SCIM tokens.

3. **Attribute mapping is configurable, not hardcoded.** Different IdPs send different attribute shapes. We provide a `scim_attribute_mapping` JSONB column on each SCIM token that maps SCIM paths (e.g., `name.givenName` → `users.display_name`, `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` → `users.department_id`). Sensible defaults cover Entra ID and Okta out of the box.

4. **Disable, don't delete (by default).** SCIM deprovisioning sets `users.active = FALSE` and revokes all sessions. Hard-delete is configurable per token (`deletion_policy`: `soft` or `hard`). Most enterprises want audit trails; soft-disable is the safer default.

5. **Incremental sync via syncToken.** `GET /Users?startIndex=1&count=100` with `syncToken` returns only users changed since the token's timestamp. The syncToken is an opaque base64-encoded cursor containing the last-seen `users.updated_at` value. Groups use the same pattern against `distribution_groups.updated_at`. This avoids full re-import on every sync cycle.

## Dependencies

- **Phase 16 (SSO Group Provisioning)** — the `distribution_group_members.source` column (`manual` / `sso`) already exists from the group mapping system. SCIM-assigned memberships set `source = 'scim'`, sharing the same auto-removal logic on re-sync.
- **Phase 13 (Admin Console)** — SCIM token management UI is deferred to the admin shell; initial token provisioning is via SQL or CLI (`mailctl scim create-token`).
- **`shared/pwhash` package** — bcrypt hashing for SCIM tokens at rest.
- **Competitive context (per roadmap line 111):** "Both EXO and Gmail support SCIM (EXO natively, Gmail via third-party bridges)." We match EXO by offering native SCIM — the IdP provisioning agent talks directly to our server, no bridge required.

## Non-Goals

- SCIM bulk operations (`POST /Bulk`) — rarely used by enterprise IdPs for email provisioning; can be added later.
- SCIM ServiceProviderConfig / ResourceTypes / Schemas discovery endpoints — static JSON responses are trivial; implement if an IdP (Okta) requires them for initial connection validation.
- SCIM-as-client (outbound). We are only implementing the SCIM server role. Outbound SCIM (pushing our users to another system) is out of scope.

## Effort Estimate

| Component | Effort |
|-----------|--------|
| Schema + SCIM token table + reducers + pgTAP tests | 3 days |
| `scim/` package: server, user, group, schemas | 5 days |
| `patch.go` — RFC 7644 PATCH interpreter | 2 days |
| `filter.go` — SCIM filter parser | 1.5 days |
| `authserver/internal/handlers/scim.go` — session revoke on disable | 0.5 days |
| Integration test with Entra ID SCIM provisioning agent + Okta SCIM app | 2 days |
| Documentation + `mailctl scim` subcommand | 1 day |
| **Total** | **~3 weeks** |
