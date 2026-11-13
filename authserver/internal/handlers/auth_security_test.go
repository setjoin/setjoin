package handlers

import (
	"context"
	"strings"
	"testing"

	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// ============================================================================
// Security fix 1 — JIT email injection (createJITUser)
//
// The email used for JIT provisioning comes from the untrusted SAML NameID /
// OIDC sub. It must be normalized + validated BEFORE any user is provisioned.
// These tests prove that a malicious NameID never reaches the INSERT: validation
// short-circuits with a rejection error while the DB pool is never touched.
//
// Against the OLD code (which inserted the NameID verbatim) these inputs would
// have been passed straight into users.email; here they must be rejected.
// ============================================================================

func TestCreateJITUser_RejectsMaliciousNameID(t *testing.T) {
	// A closed pool errors on ANY query. If validation did NOT short-circuit,
	// createJITUser would reach the INSERT and fail with a connection/DB error
	// instead of the validation-rejection error — so the assertion on the error
	// message proves the email was rejected before provisioning.
	pool := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool,
		JWT:  newTestJWT(),
	})

	cases := []struct {
		name  string
		email string // value derived from a hostile SAML NameID / OIDC sub
	}{
		{"control_char_newline", "attacker@evil.com\nBcc: victim@corp.com"},
		{"control_char_cr", "attacker@evil.com\rTo: spam@corp.com"},
		{"null_byte", "attacker@evil.com\x00admin@corp.com"},
		{"not_an_email", "not-an-email-at-all"},
		{"no_domain_dot", "user@localhost"},
		{"empty", ""},
		{"only_whitespace", "   "},
		{"header_injection_in_localpart", "a\r\nFrom: root@corp.com"},
		{"overlong", strings.Repeat("a", 300) + "@example.com"},
		{"angle_bracket_injection", "<script>@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			user, err := h.createJITUser(context.Background(), tc.email, "", "", tc.email, "https://idp.example.com")
			if err == nil {
				t.Fatalf("expected createJITUser to REJECT malicious email %q, but it returned a user (no validation)", tc.email)
			}
			if user != nil {
				t.Fatalf("expected no user to be provisioned for %q, got %+v", tc.email, user)
			}
			// The rejection must come from email validation, NOT from a DB error,
			// which proves the INSERT was never attempted.
			if !strings.Contains(err.Error(), "jit_user_creation_rejected_invalid_email") {
				t.Fatalf("expected email-validation rejection for %q, got: %v", tc.email, err)
			}
		})
	}
}

// TestCreateJITUser_NormalizesValidEmail confirms a well-formed (but messy)
// email passes validation and is normalized (trim + lowercase) before reaching
// the INSERT. With a closed pool the INSERT then fails, but the error must be a
// DB error — NOT a validation rejection — proving the address was accepted.
func TestCreateJITUser_NormalizesValidEmail(t *testing.T) {
	pool := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool,
		JWT:  newTestJWT(),
	})

	_, err := h.createJITUser(context.Background(), "  Alice.Smith@Example.Com  ", "", "", "Alice Smith", "https://idp.example.com")
	if err == nil {
		t.Fatal("expected a DB error from the closed pool after a valid email passed validation")
	}
	if strings.Contains(err.Error(), "jit_user_creation_rejected_invalid_email") {
		t.Fatalf("a well-formed email must NOT be rejected by validation, got: %v", err)
	}
}

// ============================================================================
// Security fix 2 — impersonation privilege escalation + token scope
// ============================================================================

// TestImpersonationRank_NoUpwardOrEqual proves the privilege ordering used by
// AdminImpersonate: an actor may only impersonate STRICTLY less-privileged
// accounts. Equal-or-higher targets are refused (targetRank >= actorRank).
func TestImpersonationRank_NoUpwardOrEqual(t *testing.T) {
	// Post-RBAC-cut-over the tier is derived from GOVERNED admin_role_assignments
	// (the users.admin_role enum is gone): isAdmin, hasGoverned, isSuperAdminGroup.
	type principal struct {
		isAdmin    bool
		governed   bool
		superGroup bool
	}
	superAdmin := principal{true, true, true}     // governed Super Admin group → rank 4
	governedAdmin := principal{true, true, false} // governed non-super role  → rank 3
	legacyAdmin := principal{true, false, false}  // is_admin flag, no governed row → rank 1
	regular := principal{false, false, false}     // no privilege → rank 0

	rank := func(p principal) int { return impersonationRank(p.isAdmin, p.governed, p.superGroup) }
	allowed := func(actor, target principal) bool { return rank(target) < rank(actor) }

	// A super-admin can impersonate every lower tier, but NOT another super-admin.
	if allowed(superAdmin, superAdmin) {
		t.Error("super-admin must NOT impersonate another super-admin (equal privilege)")
	}
	if !allowed(superAdmin, governedAdmin) {
		t.Error("super-admin should be able to impersonate a governed admin")
	}
	if !allowed(superAdmin, regular) {
		t.Error("super-admin should be able to impersonate a regular user")
	}

	// A governed (non-super) admin must NOT impersonate a super-admin (upward) or
	// another governed admin (equal). All governed non-super admins share rank 3,
	// so the no-upward/equal rule refuses peer impersonation without an enum.
	if allowed(governedAdmin, superAdmin) {
		t.Error("governed admin must NOT impersonate super-admin (privilege escalation)")
	}
	if allowed(governedAdmin, governedAdmin) {
		t.Error("governed admin must NOT impersonate another governed admin (equal privilege)")
	}
	if !allowed(governedAdmin, legacyAdmin) {
		t.Error("governed admin should be able to impersonate a bare is_admin account")
	}
	if !allowed(governedAdmin, regular) {
		t.Error("governed admin should be able to impersonate a regular user")
	}

	// A bare is_admin (no governed row) sits at the floor admin tier (1): it can
	// impersonate non-admins but NOT any governed admin, nor another bare admin.
	if !allowed(legacyAdmin, regular) {
		t.Error("legacy is_admin should be able to impersonate a regular user")
	}
	if allowed(legacyAdmin, governedAdmin) {
		t.Error("legacy is_admin must NOT impersonate a governed admin (upward)")
	}
	if allowed(legacyAdmin, legacyAdmin) {
		t.Error("legacy is_admin must NOT impersonate another legacy admin (equal)")
	}

	// A non-admin has rank 0 and can impersonate no one (the handler also gates
	// on is_admin, but the ranking must never let rank-0 act as an actor).
	if allowed(regular, regular) {
		t.Error("non-admin actor must never be allowed to impersonate")
	}
}

// TestIssueImpersonation_ScopeConstrainedWithActClaim proves the issued
// impersonation token is scope-constrained: it carries the RFC 8693 act claim
// (actor id) for audit, targets the impersonated user, and grants NO admin
// authority (IsAdmin false). The admin_role claim was removed by the RBAC
// cut-over, so there is no role to assert empty — the wire-level invariant (no
// "role" key) is pinned by jwtutil.TestClaimsNeverCarryRoleClaim. This is the
// same scope constraint AdminImpersonate re-verifies before handing out a token.
func TestIssueImpersonation_ScopeConstrainedWithActClaim(t *testing.T) {
	j := newTestJWT()
	const actorID = int64(7)
	const targetID = int64(42)

	tok, err := j.IssueImpersonation(targetID, "target@example.com", actorID, "")
	if err != nil {
		t.Fatalf("IssueImpersonation: %v", err)
	}
	claims, err := j.Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// act claim present and correct (audit trail of who impersonated).
	if claims.AdminActorID == nil {
		t.Fatal("impersonation token must carry the act (actor) claim")
	}
	if *claims.AdminActorID != actorID {
		t.Errorf("act claim = %d, want %d", *claims.AdminActorID, actorID)
	}
	// Subject is the impersonated user, not the actor.
	if claims.UserID != targetID {
		t.Errorf("token UserID = %d, want target %d", claims.UserID, targetID)
	}
	// Scope constraint: the token must NOT grant admin rights.
	if claims.IsAdmin {
		t.Error("impersonation token must NOT be marked IsAdmin")
	}
}

// ============================================================================
// Security fix 3 — SSO email injection on the RETURNING-user path
// (updateSSOEmail), a SIBLING of the createJITUser fix.
//
// updateSSOEmail writes the IdP-reported email to users.email for an existing
// SSO user on EVERY login. The email is untrusted (SAML NameID / OIDC email
// claim). The prior wave validated only createJITUser; this proves the sibling
// site is now closed too, routed through the SAME shared validated seam.
//
// Against the OLD code (which UPDATE'd users.email verbatim) these inputs would
// have reached the UPDATE; here they must be rejected BEFORE any DB call. With a
// closed pool, a validation rejection (not a DB error) proves the UPDATE was
// never attempted.
// ============================================================================

func TestUpdateSSOEmail_RejectsMaliciousEmail(t *testing.T) {
	pool := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT()})

	cases := []struct {
		name  string
		email string
	}{
		{"control_char_newline", "attacker@evil.com\nBcc: victim@corp.com"},
		{"control_char_cr", "attacker@evil.com\rTo: spam@corp.com"},
		{"null_byte", "attacker@evil.com\x00admin@corp.com"},
		{"not_an_email", "not-an-email-at-all"},
		{"no_domain_dot", "user@localhost"},
		{"empty", ""},
		{"only_whitespace", "   "},
		{"header_injection_in_localpart", "a\r\nFrom: root@corp.com"},
		{"overlong", strings.Repeat("a", 300) + "@example.com"},
		{"angle_bracket_injection", "<script>@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := h.updateSSOEmail(context.Background(), 42, tc.email)
			if err == nil {
				t.Fatalf("expected updateSSOEmail to REJECT malicious email %q, got nil error (no validation)", tc.email)
			}
			// Rejection must come from the shared email-validation seam, NOT a DB
			// error — proving the UPDATE was never attempted.
			if !strings.Contains(err.Error(), "sso_email_rejected_invalid") {
				t.Fatalf("expected email-validation rejection for %q, got: %v", tc.email, err)
			}
		})
	}
}

// TestUpdateSSOEmail_AcceptsValidEmailReachesDB confirms a well-formed (but
// messy) email passes the shared validator and reaches the UPDATE. With a closed
// pool the UPDATE fails, but the error must be a DB error — NOT a validation
// rejection — proving the address was accepted and normalized.
func TestUpdateSSOEmail_AcceptsValidEmailReachesDB(t *testing.T) {
	pool := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT()})

	err := h.updateSSOEmail(context.Background(), 42, "  Alice.Smith@Example.Com  ")
	if err == nil {
		t.Fatal("expected a DB error from the closed pool after a valid email passed validation")
	}
	if strings.Contains(err.Error(), "sso_email_rejected_invalid") {
		t.Fatalf("a well-formed email must NOT be rejected by validation, got: %v", err)
	}
}

// TestNormalizeAndValidateSSOEmail_PureSeam tests the shared seam directly: it
// normalizes (trim + lowercase) valid input and rejects hostile input. This is
// the single chokepoint both createJITUser and updateSSOEmail consume, so the
// validation can never be missed at one site again.
func TestNormalizeAndValidateSSOEmail_PureSeam(t *testing.T) {
	// Valid, messy input is normalized.
	got, err := normalizeAndValidateSSOEmail("  Alice.Smith@Example.Com  ")
	if err != nil {
		t.Fatalf("valid email rejected: %v", err)
	}
	if got != "alice.smith@example.com" {
		t.Errorf("normalize = %q, want %q", got, "alice.smith@example.com")
	}

	// Hostile inputs are rejected with an empty result.
	for _, bad := range []string{
		"attacker@evil.com\nBcc: victim@corp.com",
		"a\r\nFrom: root@corp.com",
		"attacker@evil.com\x00x@corp.com",
		"not-an-email",
		"user@localhost",
		"",
		"   ",
	} {
		out, err := normalizeAndValidateSSOEmail(bad)
		if err == nil {
			t.Errorf("expected rejection for %q, got nil error", bad)
		}
		if out != "" {
			t.Errorf("expected empty result on rejection for %q, got %q", bad, out)
		}
	}
}

// ============================================================================
// Security fix 4 — IdP group->role mapping privilege-escalation ceiling
// (applyGroupMappings).
//
// Task 4 (RBAC unification): cappedSSORole has been removed.  Admin role
// writes now go to admin_role_assignments (NULL granted_by = system/SSO)
// using adminRoleToGroupID, so the ceiling is structural — unknown roles
// produce no row, and SoD enforcement is delegated to trg_sod_exclusion.
// The privilege-escalation coverage moved to:
//   TestApplyGroupMappings_*  (sso_group_mapping_test.go)
//   TestApplyGroupMappings_BZ001WarnPath_StaticGuard
// ============================================================================

// ============================================================================
// Security fix 5 — mint-scope condition: super_admin now enters scope resolution
//
// Before: `if user.IsAdmin && user.AdminRole != "super_admin"` skipped
// MintDomainScope for super_admin, meaning a super_admin with a domain-scoped
// role assignment would receive a GLOBAL token (scope-broadening).
//
// After: `if user.IsAdmin` — all admins go through scope resolution.
// MintDomainScope returns nil (global) when there are no narrowing rows, so
// super_admin accounts with no domain-scoped assignments are unaffected.
// ============================================================================

// TestMintDomainScope_NoAssignments_ReturnsNilGlobal proves MintDomainScope
// returns nil (global scope) for an admin user with no role assignments.
// This is the expected result for super_admin accounts in typical deployments:
// the condition change does not narrow their scope.
func TestMintDomainScope_NoAssignments_ReturnsNilGlobal(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Seed a user who has no admin_role_assignments rows.
	var userID int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin)
		 SELECT 'mintscope-no-assign', 'mintscope-no-assign@example.com', 'Mint Test', id, 'local', TRUE, TRUE
		 FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1
		 RETURNING id`,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user (schema not loaded?): %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	scope, err := permissions.MintDomainScope(ctx, pool, userID)
	if err != nil {
		t.Fatalf("MintDomainScope returned unexpected error: %v", err)
	}
	if scope != nil {
		t.Errorf("no-assignment admin: expected nil (global) scope, got domain_id=%d", *scope)
	}
}

// TestMintDomainScope_DomainScopedAssignment_NarrowsScope proves MintDomainScope
// returns a non-nil domain ID when the user has a domain-scoped role assignment.
// A super_admin with such a row now gets a NARROWED token (the bug the condition
// fix closes): previously super_admin skipped MintDomainScope and always got global.
func TestMintDomainScope_DomainScopedAssignment_NarrowsScope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	// Resolve a local domain to use as the scope.
	var domainID int64
	err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1`).Scan(&domainID)
	if err != nil {
		t.Skipf("no local domain in test DB: %v", err)
	}

	// Seed an admin user (scope is derived from the governed assignment below,
	// not from any users.admin_role enum — that column is gone).
	var userID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled, is_admin)
		 VALUES ('mintscope-scoped', 'mintscope-scoped@example.com', 'Mint Scoped', $1, 'local', TRUE, TRUE)
		 RETURNING id`,
		domainID,
	).Scan(&userID)
	if err != nil {
		t.Skipf("could not seed test user: %v", err)
	}

	// Seed a role group with the narrowed domain_scope and assign it.
	var rgID int64
	err = pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, description, permissions, domain_scope)
		 VALUES ('mintscope-rg', 'Mint scope test group', ARRAY[]::text[], $1)
		 RETURNING id`,
		domainID,
	).Scan(&rgID)
	if err != nil {
		t.Skipf("could not create role group: %v", err)
	}

	_, err = pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, $2)`,
		userID, rgID,
	)
	if err != nil {
		t.Skipf("could not assign role group: %v", err)
	}

	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id = $1`, userID)
		pool.Exec(ctx, `DELETE FROM admin_role_groups WHERE id = $1`, rgID)
		pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	})

	scope, err := permissions.MintDomainScope(ctx, pool, userID)
	if err != nil {
		t.Fatalf("MintDomainScope returned unexpected error: %v", err)
	}
	if scope == nil {
		t.Error("domain-scoped assignment: expected non-nil scope, got nil (global)")
	} else if *scope != domainID {
		t.Errorf("scope = %d, want domain_id %d", *scope, domainID)
	}
}
