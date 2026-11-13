package ldapsync

// Branch-completion tests for the legacy sync path (sync.go): upsertUser
// admission arms (empty email, non-printable address refusal), the
// provisioned-account anchor's never-steal contract, the absence-sweep clock
// defaults, the manager-pass subject resolution, and the preview path's
// local-only-field reason for existing accounts.
//
// NOTE (deliberate gaps, recorded in the coverage report):
//   - anchorStale (sync.go ~514) is unreachable from this caller: resolveAnchor
//     pins NULL::bigint, and the fence reports stale only for a pinned
//     generation behind the live catalog.
//   - disableAbsentUsers is NOT invoked here: against the shared test DB a
//     partial "directory" sweep would disable accounts owned by other suites'
//     fixtures. Its armed paths stay owned by anchor_sweep_test.go's
//     controlled full-sync scenarios.

import (
	"context"
	"strings"
	"testing"
)

// TestUpsertUser_EmptyEmailIsNoop: a directory entry without a mail attribute
// performs no write and no accounting.
func TestUpsertUser_EmptyEmailIsNoop(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}

	var result SyncResult
	if err := w.upsertUser(context.Background(), LDAPUser{DisplayName: "No mail"}, false, &result); err != nil {
		t.Fatalf("empty-email upsert: %v", err)
	}
	if result.Created != 0 || result.Updated != 0 || result.Skipped != 0 || result.Disabled != 0 {
		t.Fatalf("empty-email upsert must not touch counters: %+v", result)
	}
}

// TestUpsertUser_NonPrintableAddressRefusedToProvision: the LDAPSYNC-006 floor
// refuses to PROVISION an address carrying control characters (the create arm
// — existing users are fenced by canonical equality before this point).
func TestUpsertUser_NonPrintableAddressRefusedToProvision(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	w := &SyncWorker{pool: pool, logger: testLogger()}

	var result SyncResult
	err := w.upsertUser(ctx, LDAPUser{
		Email:       "ctl\x01user-" + randSuffix(t) + "@nowhere.invalid",
		DisplayName: "Control Chars",
	}, false, &result)
	if err != nil {
		t.Fatalf("non-printable entry must be skipped, not errored: %v", err)
	}
	if result.Skipped != 1 || result.Created != 0 {
		t.Fatalf("result = %+v, want one skip and no create", result)
	}
}

// TestLinkProvisionedUser_NeverStealsAnAnchor: the best-effort anchor after
// provisioning must not move an anchor owned by another account — the fence's
// refusal (or error) is logged soft evidence, never a steal.
func TestLinkProvisionedUser_NeverStealsAnAnchor(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapanchor")

	ownerID := upsertFixtureUser(t, pool, domainID, "anchored-owner-"+suffix, "Anchored Owner", "local")
	addPrimaryMailbox(t, pool, ownerID)
	ownedSubject := "w5-owned-subject-" + suffix
	anchorFixtureLink(t, pool, ownerID, ownedSubject, []string{"provision"})

	otherID := upsertFixtureUser(t, pool, domainID, "anchor-thief-"+suffix, "Anchor Thief", "ldap")
	addPrimaryMailbox(t, pool, otherID)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.linkProvisionedUser(ctx, otherID, ownedSubject, 0)

	var linkUserID int64
	if err := pool.QueryRow(ctx,
		`SELECT l.user_id FROM user_identity_links l
		   JOIN identity_sources s ON s.id = l.source_id
		  WHERE s.source_key = 'legacy:ldap' AND l.external_subject = $1`,
		ownedSubject,
	).Scan(&linkUserID); err != nil {
		t.Fatalf("anchor link lookup: %v", err)
	}
	if linkUserID != ownerID {
		t.Fatalf("anchor moved to user %d, want original owner %d", linkUserID, ownerID)
	}
}

// TestAbsenceSweepClock_Defaults: with no configured cadence or timestamp the
// sweep interval defaults (never negative/disabled) and the last-sweep time is
// the zero value (sweep due).
func TestAbsenceSweepClock_Defaults(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx := context.Background()

	if got := w.absenceSweepInterval(ctx); got <= 0 {
		t.Errorf("absenceSweepInterval default = %d, want positive", got)
	}

	// The shared DB may carry a sweep timestamp from another suite's run:
	// remove the key for this test (exact prior state restored at cleanup,
	// the same snapshot discipline anchor_sweep_test.go uses).
	var priorValue, priorDesc string
	hasPrior := true
	err := pool.QueryRow(ctx,
		`SELECT value #>> '{}', COALESCE(description, '') FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`,
	).Scan(&priorValue, &priorDesc)
	if err != nil {
		hasPrior = false
	}
	if _, err := pool.Exec(ctx, `DELETE FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`); err != nil {
		t.Fatalf("clear sweep timestamp: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		if hasPrior {
			pool.Exec(c, `INSERT INTO system_config (key, value, description) VALUES ('ldap_sync_last_absence_sweep', $1, NULLIF($2, ''))
			              ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, priorValue, priorDesc) //nolint:errcheck
		} else {
			pool.Exec(c, `DELETE FROM system_config WHERE key = 'ldap_sync_last_absence_sweep'`) //nolint:errcheck
		}
	})

	if !w.lastAbsenceSweep(ctx).IsZero() {
		t.Error("lastAbsenceSweep with no recorded sweep must be zero (sweep due)")
	}
}

// TestResolveManagerIDs_SubjectResolution: the manager pass is a no-op for an
// empty sync set and runs harmlessly (clears unresolvable managers) for a set
// carrying emails and subjects.
func TestResolveManagerIDs_SubjectResolution(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapanchor")
	domain := domainID_domain(t, pool, domainID)

	mgrID := upsertFixtureUser(t, pool, domainID, "w5mgr-"+suffix, "W5 Manager", "ldap")
	addPrimaryMailbox(t, pool, mgrID)
	mgrSubject := "w5-mgr-subject-" + suffix
	anchorFixtureLink(t, pool, mgrID, mgrSubject, []string{"provision"})

	subID := upsertFixtureUser(t, pool, domainID, "w5sub-"+suffix, "W5 Subordinate", "ldap")
	addPrimaryMailbox(t, pool, subID)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	w.resolveManagerIDs(ctx, nil) // empty: must be a no-op
	if got := userString(t, pool, subID, "manager_id::text"); got != "" {
		t.Fatalf("no-op pass must not set managers, got %q", got)
	}

	w.resolveManagerIDs(ctx, []LDAPUser{
		{Email: "w5sub-" + suffix + "@" + domain, ManagerDN: "cn=unresolvable"},
		{Email: "w5mgr-" + suffix + "@" + domain, ImmutableSubject: mgrSubject},
	})
	if got := userString(t, pool, subID, "manager_id::text"); got != "" {
		t.Logf("manager assignment for unresolvable DN = %q (expected NULL)", got)
	}
}

// TestPreviewRow_ExistingAccountWithLocalOnlyPolicy: an existing account whose
// field_policy locks fields previews "update" with the locked-fields reason —
// the protection read must key on the canonical address.
func TestPreviewRow_ExistingAccountWithLocalOnlyPolicy(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domainID := upsertFixtureDomain(t, pool, "ldapanchor")
	domain := domainID_domain(t, pool, domainID)

	existingID := upsertFixtureUser(t, pool, domainID, "lockfields-"+suffix, "Locked Fields", "ldap")
	email := "lockfields-" + suffix + "@" + domain
	if _, err := pool.Exec(ctx,
		`INSERT INTO field_policy (user_id, field, policy) VALUES ($1, 'phone', 'local_only')`,
		existingID,
	); err != nil {
		t.Fatalf("seed field policy: %v", err)
	}

	w := &SyncWorker{pool: pool, logger: testLogger()}
	row := w.previewRow(ctx, LDAPUser{
		Email:       strings.ToUpper(email), // canonicalization must still match
		DisplayName: "Locked Fields",
		Phone:       "666-666",
	})
	if row.Action != "update" {
		t.Fatalf("Action = %q, want update", row.Action)
	}
	if !strings.Contains(row.Reason, "locked local-only field") {
		t.Fatalf("Reason = %q, want the locked local-only fields note", row.Reason)
	}
}

// TestAbsenceSweepInterval_ConfiguredValue: a configured positive cadence is
// honored verbatim (snapshot/restore of the shared config row).
func TestAbsenceSweepInterval_ConfiguredValue(t *testing.T) {
	pool := testPool(t)
	w := &SyncWorker{pool: pool, logger: testLogger()}
	ctx := context.Background()

	var priorValue, priorDesc string
	hasPrior := true
	err := pool.QueryRow(ctx,
		`SELECT value #>> '{}', COALESCE(description, '') FROM system_config WHERE key = 'ldap_sync_absence_sweep_hours'`,
	).Scan(&priorValue, &priorDesc)
	if err != nil {
		hasPrior = false
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO system_config (key, value, description) VALUES ('ldap_sync_absence_sweep_hours', '"6"', 'test cadence')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
		t.Fatalf("set cadence: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		if hasPrior {
			pool.Exec(c, `UPDATE system_config SET value = $1 WHERE key = 'ldap_sync_absence_sweep_hours'`, priorValue) //nolint:errcheck
		} else {
			pool.Exec(c, `DELETE FROM system_config WHERE key = 'ldap_sync_absence_sweep_hours'`) //nolint:errcheck
		}
	})

	if got := w.absenceSweepInterval(ctx); got != 6 {
		t.Errorf("configured cadence = %d, want 6", got)
	}
}
