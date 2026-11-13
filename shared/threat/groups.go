package threat

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ResolveUserGroups returns the directory group IDs a user belongs to — the
// source for CA group-scope conditions. Shared by the HTTP login path and the
// IMAP/SMTP post-auth pass so the two paths can never drift.
//
// DEPRECATED for new call sites: this wrapper DROPS the query error, so a
// transient DB blip is indistinguishable from "no groups" and group/role-scoped
// CA policies silently skip. Prefer ResolveUserGroupsChecked (or the
// pgxPolicyStore scope cache, which surfaces the error) so the caller can route
// the failure through the engine fail-mode posture (PolicyEngine failMode /
// failModeDecision) instead of evaluating with empty membership.
// Query is R1-compliant: scoped to the supplied userID.
func ResolveUserGroups(ctx context.Context, pool *pgxpool.Pool, userID int64) []int64 {
	ids, _ := ResolveUserGroupsChecked(ctx, pool, userID)
	return ids
}

// ResolveUserGroupsChecked is ResolveUserGroups with the query error surfaced:
// a transient single-query blip returns (nil, err) instead of silently reading
// as "no group memberships". The error is the fail-signal for CA scope
// resolution (CA-SCOPE-RESOLUTION-FAIL-OPEN-CACHED) — callers must not discard
// it. Engines built on NewPolicyStore repair error-dropping callers
// automatically: PolicyEngine.Evaluate resolves scope through the
// ScopeResolver seam and routes failures into failModeDecision, so the
// production CA path never evaluates on silent empty membership even when the
// caller used the deprecated wrappers. Query is R1-compliant: scoped to the
// supplied userID.
func ResolveUserGroupsChecked(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]int64, error) {
	rows, err := pool.Query(ctx,
		`SELECT group_id FROM user_group_members WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve user groups: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan user group membership: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate user group memberships: %w", err)
	}
	return ids, nil
}

// ResolveRoleGroups returns the admin role-group IDs from the user's UNEXPIRED
// governed admin_role_assignments — the source for CA directory-role scope.
// Shared by the HTTP login path and the IMAP/SMTP post-auth pass.
//
// DEPRECATED for new call sites: drops the query error exactly as
// ResolveUserGroups does. Prefer ResolveRoleGroupsChecked so a transient blip
// can be routed through the engine fail-mode posture instead of silently
// reading as "no admin roles".
// Query is R1-compliant: scoped to the supplied userID.
func ResolveRoleGroups(ctx context.Context, pool *pgxpool.Pool, userID int64) []int64 {
	ids, _ := ResolveRoleGroupsChecked(ctx, pool, userID)
	return ids
}

// ResolveRoleGroupsChecked is ResolveRoleGroups with the query error surfaced:
// a transient single-query blip returns (nil, err) instead of silently reading
// as "no role memberships". Query is R1-compliant: scoped to the supplied
// userID.
func ResolveRoleGroupsChecked(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]int64, error) {
	rows, err := pool.Query(ctx,
		`SELECT role_group_id FROM admin_role_assignments
		  WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now())`, userID)
	if err != nil {
		return nil, fmt.Errorf("resolve role groups: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan admin role assignment: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin role assignments: %w", err)
	}
	return ids, nil
}
