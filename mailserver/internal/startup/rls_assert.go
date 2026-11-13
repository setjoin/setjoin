package startup

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// rls_assert.go — the BOOT-TIME native-RLS role/ownership self-check (native-rls
// W7 / plan 2026-06-18, "AUTOPLAN GAUNTLET REVIEW" F3/F5/F6). The check-rls-
// coverage.sh guard and the rls_role_model.pg pgTAP run in CI — they NEVER run on
// a customer's own Postgres cluster. So a per-install misconfiguration of the
// three-role split (setjoin_app must be NOBYPASSRLS + own no FORCE'd table;
// setjoin_owner owns the tables and runs DDL) is invisible until it silently
// leaks. This runs the load-bearing role/ownership invariants at gateway startup
// on the ACTUAL runtime connection and REFUSES TO BOOT on violation — fail-closed
// downtime beats silently-disabled tenant isolation. The probe also covers RLS
// enablement itself: a table carrying policies with relrowsecurity = false has
// every policy predicate dead, a misconfiguration class the CI-only guard would
// otherwise never see on customer clusters.
//
// Only meaningful once the operator has flipped (DB_DSN → the non-owner
// setjoin_app role). On the dev/test/owner superuser identity the flip is inert
// (a superuser bypasses RLS even under FORCE), so the check self-skips.

// rlsRoleState is the probed state of the runtime DB role — the pure input to the
// invariant check, so the decision logic is unit-testable without a live cluster.
type rlsRoleState struct {
	currentUser string
	isSuper     bool
	bypassRLS   bool
	ownedForced []string // FORCE'd user-data tables/partitions owned by currentUser
	rlsDisabled []string // tables that carry RLS policies but have relrowsecurity = false
}

// checkRLSInvariants is the PURE decision: given the runtime role's state, is the
// native-RLS posture safe? Returns a fatal-worthy error on a silent-isolation-loss
// misconfiguration, nil when safe (or inert on a superuser runtime).
func checkRLSInvariants(s rlsRoleState) error {
	if s.isSuper {
		// Superuser bypasses RLS even under FORCE — the flip is inert. This is the
		// dev/test/owner identity; nothing to enforce. (Caller logs the inert note.)
		return nil
	}
	if s.bypassRLS {
		return fmt.Errorf("native-RLS boot check: runtime role %q has BYPASSRLS — tenant RLS is SILENTLY bypassed; "+
			"the gateway's DB_DSN must be a NOBYPASSRLS role (setjoin_app), not the worker/owner credential", s.currentUser)
	}
	if len(s.ownedForced) > 0 {
		return fmt.Errorf("native-RLS boot check: runtime role %q OWNS FORCE'd table(s) %v — a table's owner bypasses RLS "+
			"even under FORCE, so tenant isolation is SILENTLY disabled on them; they must be owned by setjoin_owner "+
			"(run partition/DDL as the owner, not the app role)", s.currentUser, s.ownedForced)
	}
	if len(s.rlsDisabled) > 0 {
		// Policies written but row security switched off: every policy predicate
		// is dead and tenant isolation is silently absent on these tables — the
		// exact class the CI-only coverage guard exists for (no in-repo list of
		// user-data tables is consulted: policies attached but disabled is
		// unconditionally wrong, catalog-derived, so it cannot drift).
		return fmt.Errorf("native-RLS boot check: table(s) %v carry RLS policies but ROW LEVEL SECURITY is DISABLED — "+
			"every policy predicate is dead and tenant isolation is silently off; "+
			"re-enable with ALTER TABLE ... ENABLE ROW LEVEL SECURITY", s.rlsDisabled)
	}
	return nil
}

// probeRLSRoleState reads the runtime role's attributes + any FORCE'd table it
// owns, in a single round trip each (both catalog reads, no user data).
func probeRLSRoleState(ctx context.Context, db *pgxpool.Pool) (rlsRoleState, error) {
	var s rlsRoleState
	if err := db.QueryRow(ctx,
		`SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&s.currentUser, &s.isSuper, &s.bypassRLS); err != nil {
		return s, fmt.Errorf("probe runtime role attributes: %w", err)
	}
	// FORCE'd tables/partitions owned by the current (runtime) role. relkind r =
	// ordinary table, p = partitioned parent. relforcerowsecurity is the FORCE bit.
	rows, err := db.Query(ctx,
		`SELECT c.relname FROM pg_class c
		   JOIN pg_roles r ON r.oid = c.relowner
		  WHERE c.relforcerowsecurity AND c.relkind IN ('r','p') AND r.rolname = current_user
		  ORDER BY c.relname`)
	if err != nil {
		return s, fmt.Errorf("probe owned FORCE'd tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return s, err
		}
		s.ownedForced = append(s.ownedForced, name)
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	// Tables that carry RLS policies but have row security disabled. Policies
	// can only be created against a table explicitly, so "policies exist yet
	// relrowsecurity = false" is unconditionally a broken isolation posture —
	// this closes the boot-check coverage gap on RLS enablement (the CI
	// coverage guard never runs on a customer's cluster).
	rows, err = db.Query(ctx,
		`SELECT DISTINCT c.relname
		   FROM pg_policy pol
		   JOIN pg_class c ON c.oid = pol.polrelid
		  WHERE c.relkind IN ('r','p') AND NOT c.relrowsecurity
		  ORDER BY c.relname`)
	if err != nil {
		return s, fmt.Errorf("probe RLS-disabled policy tables: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return s, err
		}
		s.rlsDisabled = append(s.rlsDisabled, name)
	}
	if err := rows.Err(); err != nil {
		return s, err
	}
	return s, nil
}

// AssertRLSRoleInvariants probes the runtime role and enforces the native-RLS
// role/ownership invariants. Returns an error the caller treats as FATAL (refuse
// to boot). A nil error means safe-or-inert. A probe failure is returned too
// (the caller decides; the schema-version guard already proved the DB is
// reachable, so a probe error here is unexpected and worth failing on).
func AssertRLSRoleInvariants(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	s, err := probeRLSRoleState(ctx, db)
	if err != nil {
		return err
	}
	if s.isSuper {
		logger.Info("native-RLS boot check: runtime is a superuser identity — FORCE is inert (flip not live), skipping",
			"role", s.currentUser)
		return nil
	}
	if err := checkRLSInvariants(s); err != nil {
		return err
	}
	logger.Info("native-RLS boot check: passed",
		"role", s.currentUser, "bypassrls", s.bypassRLS, "owned_forced_tables", len(s.ownedForced),
		"rls_disabled_policy_tables", len(s.rlsDisabled))
	return nil
}
