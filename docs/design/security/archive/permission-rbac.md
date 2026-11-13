# SetJoin Permission-Based RBAC — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Replace the binary `IsAdmin` flag with a permission-based RBAC system. Add predefined role groups (Super Admin, User Admin, Help Desk, Audit Reader, Security Admin, Domain Admin), domain scoping for cross-domain isolation, and a hot-upgrade path for future permissions.

## Architecture

### Current: Binary admin

```
Claims: IsAdmin bool, AdminRole string
Middleware: RequireAdmin → super_admin OR user_admin = everything
Problem: user_admin == super_admin in practice, no granular delegation
```

### New: Permission-based

```
Claims: Permissions []string (Phase 1: resolved from AdminRole via lookup)
Middleware: RequirePerm(perm string) — single permission check
Roles: Named groups of permissions assigned to users
Domain scope: Optional domain_id filter on all admin queries
```

### Hot-upgrade path

Adding a new permission requires: 1 const + 1 middleware call + 1 entry in AllPermissions. Zero middleware changes. Admin UI auto-discovers. No data migration.

## Data Model

### admin_permissions (reference table, migration-seeded)

| Column | Type | Purpose |
|--------|------|---------|
| permission_key | TEXT PK | e.g. "users.write" |
| category | TEXT | e.g. "Users & Domains" |
| description | TEXT | Human-readable |
| is_sensitive | BOOLEAN DEFAULT false | Requires confirmation when assigning |

### admin_role_groups

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| name | TEXT UNIQUE | e.g. "Help Desk" |
| description | TEXT | |
| permissions | TEXT[] | e.g. {users.read,users.password_reset} |
| domain_scope | BIGINT FK domains.id | NULL = global |
| is_builtin | BOOLEAN DEFAULT false | Cannot delete builtin roles |

### admin_role_assignments

| Column | Type | Purpose |
|--------|------|---------|
| id | BIGSERIAL PK | |
| user_id | BIGINT FK users.id | |
| role_group_id | BIGINT FK admin_role_groups.id | |
| domain_override | BIGINT FK domains.id | Narrower than role scope (optional) |
| granted_by | BIGINT FK users.id | |
| expires_at | TIMESTAMPTZ | NULL = permanent |

## Permission Catalog (19 permissions)

| Category | Permission | Sensitive |
|----------|-----------|:---:|
| Users | users.read | |
| | users.write | |
| | users.delete | Yes |
| | users.password_reset | |
| | users.impersonate | Yes |
| Domains | domains.read | |
| | domains.write | Yes |
| Audit | audit.read | |
| MAM | mam.read | |
| | mam.write | Yes |
| Queue | queue.read | |
| | queue.write | |
| Reports | reports.read | |
| Security | security.write | Yes |
| Roles | roles.manage | Yes |
| Compliance | compliance.read | |
| | compliance.write | Yes |
| Backup | backup.read | |
| | backup.write | Yes |
| System | system.config | Yes |
| | system.upgrade | Yes |

## Predefined Role Groups

| Role | Permissions | Domain Scope |
|------|------------|:---:|
| Super Admin | All 19 | Global |
| User Admin | users.read, users.write, users.password_reset, domains.read, audit.read | Configurable |
| Help Desk | users.read, users.password_reset, queue.read, queue.write | Configurable |
| Audit Reader | audit.read, reports.read | Global |
| Security Admin | mam.read, mam.write, security.write, audit.read, users.read | Global |
| Domain Admin | users.read, users.write, users.password_reset, domains.read, audit.read, reports.read | Required |

## Middleware

```go
func RequirePerm(perm string) func(http.Handler) http.Handler
```

Single middleware. Checks `claims.HasPermission(perm)`. If claims have domain scope set, attaches to request context. Handlers filter by domain scope transparently.

## Admin UI

- `/admin/roles` — Role group list with builtin/custom indicators, click to edit
- `/admin/roles/{id}` — Edit permissions (checkbox grid by category), manage members, set domain scope
- `/admin/users` — Existing page, "Is Admin" checkbox replaced with role group multi-select dropdown

## CLI

```bash
mailctl role list|show|create|delete|edit
mailctl role members|assign|unassign
```

## Migration from current model

Phase 1: `AdminRole` string in JWT maps to permission set at auth time via lookup. Existing `super_admin` and `user_admin` roles become role groups with the correct permission sets. No breaking change.

## References

- Exchange Online RBAC: Role groups + management scopes
- Google Workspace: Predefined + custom roles, OU scoping
- DingTalk: Sub-admins with module + department scope
- Lark: Admin roles with per-feature permission toggles
- `shared/jwtutil/types.go:15` — Current Claims struct
- `mailserver/internal/middleware/auth.go:76` — Current RequireRole
