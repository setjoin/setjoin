package permissions

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is the minimal subset of pgx needed to run the issuance-time scope
// MINT. It is satisfied by *pgxpool.Pool, *pgxpool.Conn, and pgx.Tx, so callers
// can pass a pool for a one-shot read or a transaction to mint inside an
// in-flight txn. Mirrors shared/identity.Querier (the house style for these
// single-sourced lookups).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Authority is the live request-time projection of governed admin grants.
// GlobalPermissions contains only permissions carried by active assignments
// that are both domain-unscoped and OU/set-unscoped. It is intentionally
// separate from Permissions: a scoped identity.write grant may manage reachable
// people, but it must never become authority over organization-global identity
// configuration or inventory.
type Authority struct {
	Permissions       []string
	GlobalPermissions []string
	DomainScope       *int64
}

// MintDomainScope is the single home of authserver's issuance-time domain-scope
// query: the MIN of the effective scope (domain_override ?? domain_scope) across
// a user's admin role assignments where that effective scope is non-NULL AND the
// assignment is not expired. This is the scope authserver STAMPS into the JWT.
//
// It is the INVERSE projection of Resolve over the same rows: Resolve returns the
// narrowest non-NULL scope by scanning per-row and taking the smallest in Go;
// MintDomainScope asks the database for the same MIN directly. Because both now
// run from one definition (this function and Resolve in the same file), the
// scope-agreement test can no longer compare Resolve against a hand-copied
// FICTION of the mint rule — it executes this exact code path. In particular the
// expires_at filter is load-bearing: without it an expired narrowing
// domain_override would win the MIN here while Resolve (which honors expires_at)
// drops it, so the gateway would re-derive + enforce a BROADER scope than this
// token mints (scope-broadening). Mint and enforce MUST apply the same expiry
// rule; this is why it lives here, single-sourced, rather than as a twin.
//
// Returns a nil *int64 when the user has no non-NULL scoped assignment (an
// unscoped/global admin). The error MUST be propagated by callers as fail-closed:
// returning (nil, nil) on a query error would silently mint an unscoped global
// token (see auth.go issueTokensWithFactors' HTTP 500).
func MintDomainScope(ctx context.Context, q Querier, userID int64) (*int64, error) {
	var scope *int64
	err := q.QueryRow(ctx,
		`SELECT MIN(COALESCE(ra.domain_override, rg.domain_scope))
		 FROM admin_role_assignments ra
		 JOIN admin_role_groups rg ON rg.id = ra.role_group_id
		 WHERE ra.user_id = $1
		   AND COALESCE(ra.domain_override, rg.domain_scope) IS NOT NULL
		   AND (ra.expires_at IS NULL OR ra.expires_at > now())
		   AND admin_assignment_active(ra.eligible, ra.activated_until)`,
		userID,
	).Scan(&scope)
	if err != nil {
		return nil, err
	}
	return scope, nil
}

// Resolve loads the effective permission set and enforced domain scope for a
// user from their admin role assignments.
//
//   - Multi-role union: a user with several role assignments gets the union of
//     every role group's permissions (deduplicated).
//   - Honors expires_at: assignments whose expires_at has passed are excluded;
//     a NULL expires_at is a permanent assignment.
//   - Narrowest scope wins: the effective scope per assignment is the
//     per-assignment domain_override if set, else the role group's domain_scope
//     (domain_override ?? domain_scope). Across assignments, the narrowest
//     non-NULL scope (smallest domain id) is returned.
//   - NULL scope is GLOBAL: a NULL domain_scope/domain_override means unscoped.
//     This function returns a nil *int64 for that case; downstream,
//     DomainScopeFromContext maps "no scope" to 0, so scope==0 ⇒ unscoped/global.
//
// This is the single source of truth for permission/scope resolution. It is
// the same user-id / multi-role / domain_override / expires_at rule authserver
// uses to MINT the JWT's domain scope — and the mint query is no longer a
// hand-copied twin: authserver calls MintDomainScope (below), the inverse-
// projection sibling of this function over the same rows, so mailserver's
// ENFORCED scope agrees with the minted one by sharing code, not by lockstep.
func Resolve(ctx context.Context, pool *pgxpool.Pool, userID int64) ([]string, *int64, error) {
	authority, err := ResolveAuthority(ctx, pool, userID)
	if err != nil {
		return nil, nil, err
	}
	return authority.Permissions, authority.DomainScope, nil
}

// ResolveAuthority resolves effective permissions plus the explicit
// organization-global subset from the same live assignment rows.
func ResolveAuthority(ctx context.Context, pool *pgxpool.Pool, userID int64) (Authority, error) {
	if pool == nil {
		return Authority{}, nil
	}

	rows, err := pool.Query(ctx,
		`SELECT rg.permissions,
		        COALESCE(ra.domain_override, rg.domain_scope) AS effective_scope,
		        ra.scope_type
		 FROM admin_role_assignments ra
		 JOIN admin_role_groups rg ON rg.id = ra.role_group_id
		 WHERE ra.user_id = $1
		   AND (ra.expires_at IS NULL OR ra.expires_at > now())
		   AND admin_assignment_active(ra.eligible, ra.activated_until)`,
		userID,
	)
	if err != nil {
		return Authority{}, err
	}
	defer rows.Close()

	var allPerms [][]string
	var globalPerms [][]string
	var narrowestScope *int64

	for rows.Next() {
		var perms []string
		var scope *int64
		var scopeType *string
		if err := rows.Scan(&perms, &scope, &scopeType); err != nil {
			return Authority{}, err
		}
		allPerms = append(allPerms, perms)
		if scope == nil && scopeType == nil {
			globalPerms = append(globalPerms, perms)
		}
		// Narrowest domain scope wins (non-nil with smallest ID).
		// NULL scope ⇒ global; it never narrows the result.
		if scope != nil {
			if narrowestScope == nil || *scope < *narrowestScope {
				narrowestScope = scope
			}
		}
	}
	if err := rows.Err(); err != nil {
		return Authority{}, err
	}

	return Authority{
		Permissions:       MergePermissions(allPerms...),
		GlobalPermissions: MergePermissions(globalPerms...),
		DomainScope:       narrowestScope,
	}, nil
}
