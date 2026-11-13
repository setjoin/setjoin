package mdm

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// Compliance evaluation (passcode/encryption/OS/jailbreak rules + the semver
// compare) moved into the mdm_device_checkin reducer (single source of truth,
// ARCH: logic where the data is). Its behaviour is now covered by
// mailserver/sql/tests/mdm_device_checkin.pg, not by Go unit tests — the Go-side
// evaluator and version-compare helpers were deleted.

// ── Policy resolution integration tests (skip without DB_DSN) ──────────────
//
// These implement the formerly stubbed bodies (D-MAILSERVER-INTERNAL-MDM-009):
// user > group > global precedence with priority as the in-layer tie-break.

// policyRandSuffix mints 8 hex chars of per-run uniqueness for fixture names
// on the shared test DB.
func policyRandSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// seedResolvePolicyFixture creates one enabled mdm_policies row and returns
// its id. The name is unique per test run so cleanup cannot collide.
func seedResolvePolicyFixture(t *testing.T, pool *pgxpool.Pool, scopeType string, scopeID *int64, priority int, passcodeMinLength int) int64 {
	t.Helper()
	ctx := context.Background()
	var id int64
	var scopeAny any
	if scopeID != nil {
		scopeAny = *scopeID
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO mdm_policies (name, description, priority, scope_type, scope_id, enabled, passcode_min_length)
		VALUES ($1, 'chunk-08 resolution test', $2, $3, $4, TRUE, $5)
		RETURNING id`,
		"chunk08-"+fmt.Sprintf("%d", time.Now().UnixNano())+"-"+scopeType,
		priority, scopeType, scopeAny, passcodeMinLength,
	).Scan(&id); err != nil {
		t.Fatalf("seed mdm_policies row: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM mdm_policies WHERE id=$1`, id); err != nil {
			t.Errorf("cleanup mdm_policies row %d: %v", id, err)
		}
	})
	return id
}

// seedResolvePolicyUser creates a standalone user (and backing domain row
// scope) and returns its id, mirroring the guestlifecycle fixture pattern.
//
// label is kept for readability only: the actual username/email carry an
// additional random suffix because the former fixed u1-u5 suffixes collided
// on users_username_domain_id_key / users_email_lower_idx across overlapping
// runs on the shared test DB (guest.invalid is a shared V143 seed domain).
func seedResolvePolicyUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	ctx := context.Background()
	name := "chunk08-" + label + "-" + policyRandSuffix(t)
	var userID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users (username,domain_id,email,display_name,enabled)
		SELECT $1,id,$2,'chunk-08 policy user',TRUE FROM domains WHERE name='guest.invalid'
		RETURNING id`, name, name+"@external.example").Scan(&userID); err != nil {
		t.Fatalf("seed policy user: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID); err != nil {
			t.Errorf("cleanup policy user %d: %v", userID, err)
		}
	})
	return userID
}

// topGlobalPriority snapshots the highest priority among currently enabled
// global policies. ResolvePolicy selects the highest-priority global row when
// no user/group row matches, and the shared test database (CI runner and local
// mailserver_test alike) permanently carries foreign enabled global rows — at
// minimum the V001 baseline seed ('Default', priority 0) plus any other
// package's in-flight fixtures. A test asserting GLOBAL resolution must seed
// its own global row strictly above that snapshot so its row is the
// production-semantics winner among all rows present, without reading or
// touching the foreign rows.
func topGlobalPriority(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var maxPriority int
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(max(priority), 0) FROM mdm_policies WHERE enabled AND scope_type = 'global'`,
	).Scan(&maxPriority); err != nil {
		t.Fatalf("snapshot enabled global priority: %v", err)
	}
	return maxPriority
}

func TestResolvePolicy_UserScopedWinsOverGlobal(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedResolvePolicyUser(t, pool, "u1")
	globalID := seedResolvePolicyFixture(t, pool, "global", nil, 100, 4)
	userPolicyID := seedResolvePolicyFixture(t, pool, "user", &userID, 0, 12)

	p, err := ResolvePolicy(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != userPolicyID {
		t.Fatalf("user-scoped policy %d must beat global %d; got %d (min=%d)",
			userPolicyID, globalID, p.ID, p.PasscodeMinLength)
	}
	if p.PasscodeMinLength != 12 {
		t.Fatalf("expected the user policy's passcode floor, got %d", p.PasscodeMinLength)
	}
}

func TestResolvePolicy_GlobalFallback(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedResolvePolicyUser(t, pool, "u2")
	// Priority above the pre-existing global rows (baseline seed + foreign
	// fixtures on the shared DB): the fallback winner under production
	// ordering must be OUR row, never scan-order luck among equal priorities.
	globalID := seedResolvePolicyFixture(t, pool, "global", nil, topGlobalPriority(t, pool)+1, 8)

	p, err := ResolvePolicy(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != globalID {
		t.Fatalf("expected global fallback %d, got %d", globalID, p.ID)
	}
}

func TestResolvePolicy_PriorityTiebreak(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedResolvePolicyUser(t, pool, "u3")
	low := seedResolvePolicyFixture(t, pool, "user", &userID, 10, 6)
	high := seedResolvePolicyFixture(t, pool, "user", &userID, 20, 14)

	p, err := ResolvePolicy(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != high {
		t.Fatalf("priority 20 policy %d must beat priority 10 policy %d; got %d",
			high, low, p.ID)
	}
}

func TestResolvePolicy_GroupScopeMatchesDepartmentAndLayersBelowUser(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// Department + user in that department.
	var deptID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO departments (name, path, ldap_ou)
		VALUES ($1, $1, $1) RETURNING id`, "chunk08-dept-"+suffix).Scan(&deptID); err != nil {
		t.Fatalf("seed department: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM departments WHERE id=$1`, deptID)
	})
	userID := seedResolvePolicyUser(t, pool, "u4")
	if _, err := pool.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2`, deptID, userID); err != nil {
		t.Fatal(err)
	}
	// A second user WITHOUT a department: group rows must not reach it.
	bareUserID := seedResolvePolicyUser(t, pool, "u5")

	globalID := seedResolvePolicyFixture(t, pool, "global", nil, topGlobalPriority(t, pool)+1, 4)
	groupID := seedResolvePolicyFixture(t, pool, "group", &deptID, 0, 10)
	userPolicyID := seedResolvePolicyFixture(t, pool, "user", &userID, 0, 16)

	// Group beats global for a department member.
	p, err := ResolvePolicy(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != userPolicyID {
		t.Fatalf("user policy %d must beat group policy %d; got %d", userPolicyID, groupID, p.ID)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM mdm_policies WHERE id=$1`, userPolicyID); err != nil {
		t.Fatal(err)
	}
	p, err = ResolvePolicy(ctx, pool, userID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != groupID {
		t.Fatalf("group policy %d must beat global policy %d for a department member; got %d",
			groupID, globalID, p.ID)
	}

	// A department-less user never matches the group row.
	p, err = ResolvePolicy(ctx, pool, bareUserID)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != globalID {
		t.Fatalf("department-less user must fall back to global %d; got %d", globalID, p.ID)
	}
}
