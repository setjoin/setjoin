package ldaputil

// AD-001 writer-level key allowlist tests (L2-C3, r2-C3-2): ApplyUserUpdate
// separates ACCEPTED INPUT KEYS (the fixed SyncAttrs table, including
// krb5_principal — normal caller behavior, floor-suppressed with audit) from
// WRITABLE COLUMNS (same minus krb5_principal). Any genuinely forbidden or
// unknown key in attrs OR extraSets is caller drift reaching for a users
// column the sync contract never granted → hard error, ZERO rows updated —
// including when the key carries an empty value (the empty-value continue must
// not let it escape) and when no other change is present (the len(sets)==0
// early return that extraSets traversal used to sit behind must not let it
// escape either).

import (
	"context"
	"strings"
	"testing"

	"setjoin.com/shared/identity"
	"setjoin.com/shared/testsupport"
)

// seedAllowlistFixture is unused — each DB test seeds its own (domain, user)
// pair inline so cleanup ordering stays local and obvious.

// TestSyncAttrsKeySetIsWriterAllowlistSource pins the source-of-truth link:
// SyncAttrs' fixed table IS the writer's accepted-input key set (both
// directions), and the extraSets set is the fixed per-engine {ad_usn_changed}.
func TestSyncAttrsKeySetIsWriterAllowlistSource(t *testing.T) {
	attrs := SyncAttrs(identity.CanonicalizeAddress("u@corp.example"),
		"U", "F", "L", "T", "P", "u@CORP.EXAMPLE")
	accepted := AcceptedSyncAttrsKeys()

	for k := range attrs {
		if !accepted[k] {
			t.Errorf("SyncAttrs key %q is not in the writer's accepted input set", k)
		}
	}
	for k := range accepted {
		if _, ok := attrs[k]; !ok {
			t.Errorf("writer accepted input key %q missing from SyncAttrs — the sets must stay identical", k)
		}
	}

	extra := AcceptedExtraSetKeys()
	if len(extra) != 1 || !extra["ad_usn_changed"] {
		t.Errorf("AcceptedExtraSetKeys = %v, want exactly {ad_usn_changed}", extra)
	}
}

// TestApplyUserUpdateRejectsForbiddenIdentityKeys is the r2 negative matrix:
// identity-bearing users columns and unknown/typo keys hard-error with zero
// rows updated — with a live value (no partial write of the accompanying
// profile change either) and with an EMPTY value and no other changes (the
// empty-value continue must not pre-empt validation).
func TestApplyUserUpdateRejectsForbiddenIdentityKeys(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaputil-allow-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, lower($2), 'Allowlist Fixture', $3, '$2a$10$placeholder')
		 RETURNING id`,
		"allow-"+suffix, "allow-"+suffix+"@"+domain, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	forbiddenKeys := []string{
		"is_admin", "is_local_admin", "id", "ad_upn", "password_hash",
		"oidc_subject", "saml_name_id", "enabled", "mfa_exempt",
		"department", // realistic drift: a real AD attribute that is not a users column
	}

	for _, key := range forbiddenKeys {
		t.Run(key+"_withValue", func(t *testing.T) {
			var res SyncResult
			err := ApplyUserUpdate(ctx, pool, userID,
				map[string]string{key: "forged-value", "display_name": "Drifted Name"},
				nil, nil, nil, "ad", nil, &res, testsupport.TestLogger())
			if err == nil {
				t.Fatalf("forbidden key %q was accepted", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("err = %v, want it to name the forbidden key %q", err, key)
			}
			if res.Updated != 0 || res.Skipped != 0 {
				t.Errorf("result = %+v, want zero counters on the rejected call", res)
			}
			var displayName string
			if err := pool.QueryRow(ctx,
				`SELECT display_name FROM users WHERE id = $1`, userID,
			).Scan(&displayName); err != nil {
				t.Fatalf("read back user: %v", err)
			}
			if displayName != "Allowlist Fixture" {
				t.Errorf("display_name = %q — the forbidden key must reject the WHOLE update, not partially write it", displayName)
			}
		})

		t.Run(key+"_emptyValueNoOtherChanges", func(t *testing.T) {
			var res SyncResult
			// Empty value for the forbidden key and NOTHING else: the
			// empty-value continue must not skip validation.
			err := ApplyUserUpdate(ctx, pool, userID,
				map[string]string{key: ""},
				nil, nil, nil, "ad", nil, &res, testsupport.TestLogger())
			if err == nil {
				t.Fatalf("forbidden key %q escaped validation via the empty-value continue", key)
			}
			if !strings.Contains(err.Error(), key) {
				t.Errorf("err = %v, want it to name the forbidden key %q", err, key)
			}
			if res.Updated != 0 || res.Skipped != 0 {
				t.Errorf("result = %+v, want zero counters on the rejected call", res)
			}
		})
	}
}

// TestApplyUserUpdateRejectsForbiddenExtraSetsKey pins the ordering vs the
// len(sets)==0 early return: a forbidden extraSets key must be rejected even
// when there are no attrs (the pre-fix writer returned before ever touching
// extraSets on a no-op write).
func TestApplyUserUpdateRejectsForbiddenExtraSetsKey(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaputil-allow-x-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, lower($2), 'ExtraSet Fixture', $3, '$2a$10$placeholder')
		 RETURNING id`,
		"allowx-"+suffix, "allowx-"+suffix+"@"+domain, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	t.Run("noOtherChanges", func(t *testing.T) {
		var res SyncResult
		err := ApplyUserUpdate(ctx, pool, userID,
			map[string]string{}, nil, nil, nil, "ad",
			map[string]interface{}{"enabled": false}, &res, testsupport.TestLogger())
		if err == nil {
			t.Fatal("forbidden extraSets key escaped validation via the len(sets)==0 early return")
		}
		if !strings.Contains(err.Error(), "enabled") {
			t.Errorf("err = %v, want it to name the forbidden extra-set key", err)
		}
		if res.Updated != 0 || res.Skipped != 0 {
			t.Errorf("result = %+v, want zero counters on the rejected call", res)
		}
	})

	t.Run("withAttrs", func(t *testing.T) {
		var res SyncResult
		err := ApplyUserUpdate(ctx, pool, userID,
			map[string]string{"display_name": "Should Not Land"}, nil, nil, nil, "ad",
			map[string]interface{}{"enabled": false}, &res, testsupport.TestLogger())
		if err == nil {
			t.Fatal("forbidden extraSets key was accepted alongside attrs")
		}
		if !strings.Contains(err.Error(), "enabled") {
			t.Errorf("err = %v, want it to name the forbidden extra-set key", err)
		}
		var displayName string
		if err := pool.QueryRow(ctx,
			`SELECT display_name FROM users WHERE id = $1`, userID,
		).Scan(&displayName); err != nil {
			t.Fatalf("read back user: %v", err)
		}
		if displayName != "ExtraSet Fixture" {
			t.Errorf("display_name = %q — the forbidden extra-set key must reject the WHOLE update", displayName)
		}
	})
}

// TestApplyUserUpdatePositiveProfileAndExtraSetsArm is the positive control:
// profile fields (canonical email included), the deptID path and the
// ad_usn_changed extraSets path all still sync.
func TestApplyUserUpdatePositiveProfileAndExtraSetsArm(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaputil-allow-p-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, lower($2), 'Positive Fixture', $3, '$2a$10$placeholder')
		 RETURNING id`,
		"allowp-"+suffix, "allowp-"+suffix+"@"+domain, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	var departmentID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO departments (name, path, ldap_ou) VALUES ($1, $1, $1) RETURNING id`,
		"allowlist-dept-"+suffix,
	).Scan(&departmentID); err != nil {
		t.Fatalf("insert department: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM departments WHERE id = $1`, departmentID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var res SyncResult
	newEmail := identity.CanonicalizeAddress("\tSynced." + suffix + "@" + domain).String()
	err := ApplyUserUpdate(ctx, pool, userID,
		map[string]string{
			"email":          newEmail,
			"display_name":   "Synced Name",
			"first_name":     "Synced",
			"last_name":      "Name",
			"job_title":      "Engineer",
			"phone":          "555-0101",
			"krb5_principal": "", // empty → the empty-value continue (pre-existing shape)
		},
		nil, nil, &departmentID, "ad",
		map[string]interface{}{"ad_usn_changed": int64(4242)},
		&res, testsupport.TestLogger())
	if err != nil {
		t.Fatalf("ApplyUserUpdate: %v", err)
	}
	if res.Updated != 1 {
		t.Errorf("Updated = %d, want 1", res.Updated)
	}

	var gotEmail, gotName, gotFirst, gotLast, gotTitle, gotPhone string
	var gotDept int64
	var gotUSN int64
	if err := pool.QueryRow(ctx,
		`SELECT email, display_name, first_name, last_name, job_title, phone,
		        department_id, ad_usn_changed
		   FROM users WHERE id = $1`, userID,
	).Scan(&gotEmail, &gotName, &gotFirst, &gotLast, &gotTitle, &gotPhone, &gotDept, &gotUSN); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if gotEmail != newEmail {
		t.Errorf("email = %q, want canonical %q", gotEmail, newEmail)
	}
	if gotName != "Synced Name" || gotFirst != "Synced" || gotLast != "Name" ||
		gotTitle != "Engineer" || gotPhone != "555-0101" {
		t.Errorf("profile columns did not sync: name=%q first=%q last=%q title=%q phone=%q",
			gotName, gotFirst, gotLast, gotTitle, gotPhone)
	}
	if gotDept != departmentID {
		t.Errorf("department_id = %d, want %d (deptID path unchanged)", gotDept, departmentID)
	}
	if gotUSN != 4242 {
		t.Errorf("ad_usn_changed = %d, want 4242 (extraSets path unchanged)", gotUSN)
	}
}
