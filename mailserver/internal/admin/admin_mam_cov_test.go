package admin

// Coverage suite for the changed MAM handler lines the scope/perm suites do
// not reach: ListPolicies projection, UnlockDevice's full outcome set
// (registry-only 404, success, checked insertion failure, checked notify
// failure, in-statement out-of-scope), ListDevices/GetDeviceEvents query
// failures, SetGlobalPolicy/SetPerDevicePolicy/SetGroupPolicy/UnsetPerDevice
// Policy/UnsetGroupPolicy error branches, and the nil-pool guard on the shared
// console-id resolver.
//
// Failure injection follows the established package patterns: shadow-schema
// pools (openMAMListFixturePool / openMAMNotifyFixturePool) plant missing
// tables, NOT NULL insert failures and a failing pg_notify — never production
// edits.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fmtInt renders an int64 fixture id as a path value.
func fmtInt(v int64) string { return fmt.Sprintf("%d", v) }

// mamGroupPolicyReq builds a group-policy request with type/id/key path values.
func mamCovGroupPolicyReq(method, groupType, groupID, key, body string) *http.Request {
	return mamGroupPolicyReq(method, "/admin/mam/policies/group/"+groupType+"/"+groupID+"/"+key, groupType, groupID, key, body)
}

// TestMAMListPolicies_GlobalAndGroups proves the console policy listing
// projects global device_policy rows and device_policy_groups rows into one
// JSON response under the actor GUC.
func TestMAMListPolicies_GlobalAndGroups(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())
	ctx := context.Background()
	suffix := strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")

	var globalID, groupID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO device_policy (device_id, policy_key, policy_value, updated_at)
		 VALUES (NULL, $1, 'true', now()) RETURNING id`, "cov_global_pin_"+suffix,
	).Scan(&globalID); err != nil {
		t.Fatalf("seed global policy: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO device_policy_groups (policy_key, policy_value, group_type, group_id, updated_at)
		 VALUES ($1, '6', 'department', 918001, now()) RETURNING id`, "cov_group_pin_"+suffix,
	).Scan(&groupID); err != nil {
		t.Fatalf("seed group policy: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM device_policy WHERE id = $1`, globalID)
		_, _ = pool.Exec(c, `DELETE FROM device_policy_groups WHERE id = $1`, groupID)
	})

	rec := httptest.NewRecorder()
	h.ListPolicies(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/policies", nil), 1, 0))
	if rec.Code != http.StatusOK {
		t.Fatalf("ListPolicies: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "cov_global_pin_"+suffix) {
		t.Errorf("global policy row missing from listing: %s", body)
	}
	if !strings.Contains(body, "cov_group_pin_"+suffix) {
		t.Errorf("group policy row missing from listing: %s", body)
	}
	if !strings.Contains(body, `"department"`) {
		t.Errorf("group_type not projected: %s", body)
	}
}

// TestMAMListPolicies_QueryFailure_5xx proves the listing's checked query
// branches: shadow policy tables with truncated column sets fail the global
// and the group SELECT, and each failure answers 5xx — never an empty 200.
func TestMAMListPolicies_QueryFailure_5xx(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
	}{
		{
			// The global table is a truncated stub: the FIRST statement in
			// the transaction fails.
			name: "global_query",
			sql: `
				CREATE TABLE __SCHEMA__.device_policy(id bigint);
				CREATE TABLE __SCHEMA__.device_policy_groups(
					id bigint, policy_key text, policy_value text, group_type text,
					group_id bigint, updated_at timestamptz);`,
		},
		{
			// The global table is intact (its query succeeds); the group
			// table is a truncated stub, so the SECOND statement fails.
			name: "group_query",
			sql: `
				CREATE TABLE __SCHEMA__.device_policy(
					id bigint, device_id bigint, policy_key text, policy_value text, updated_at timestamptz);
				INSERT INTO __SCHEMA__.device_policy VALUES (1, NULL, 'ok_pin', 'true', now());
				CREATE TABLE __SCHEMA__.device_policy_groups(id bigint);`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shadowPool := openMAMListFixturePool(t, tc.sql)
			h := NewMAMHandler(shadowPool, mailboxTestLogger())
			rec := httptest.NewRecorder()
			h.ListPolicies(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/policies", nil), 1, 0))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("list policies query failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestMAMListPolicies_ScanFailureSkipsRow proves the defensive scan arms and
// their fail-closed outcome: a row with a NULL key fails the Scan (the row is
// skipped), but pgx surfaces the scan error through rows.Err() — so the
// listing fails closed with 500 instead of serving a partial result set.
func TestMAMListPolicies_ScanFailureSkipsRow(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy VALUES (1, NULL, 'good_pin', 'true', now());
		CREATE TABLE __SCHEMA__.device_policy_groups(
			id bigint, policy_key text, policy_value text, group_type text,
			group_id bigint, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy_groups VALUES (3, NULL, 'broken', 'department', 1, now());
		INSERT INTO __SCHEMA__.device_policy_groups VALUES (4, 'group_pin', '6', 'department', 1, now());`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/policies", nil), 1, 0))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list policies with broken rows: want 500 (fail closed), got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); strings.Contains(body, "good_pin") || strings.Contains(body, "group_pin") || strings.Contains(body, "broken") {
		t.Errorf("a partial result set leaked over a scan failure: %s", body)
	}
}

// TestMAMListPolicies_GroupScanFailure_FailsClosed proves the group-scan
// arm's fail-closed outcome in isolation: the global listing is clean, one
// group row carries a NULL key, and the listing 500s rather than serving the
// partial set.
func TestMAMListPolicies_GroupScanFailure_FailsClosed(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy VALUES (1, NULL, 'good_pin', 'true', now());
		CREATE TABLE __SCHEMA__.device_policy_groups(
			id bigint, policy_key text, policy_value text, group_type text,
			group_id bigint, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy_groups VALUES (3, NULL, 'broken', 'department', 1, now());`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/policies", nil), 1, 0))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("group scan failure: want 500 (fail closed), got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMResolve_NilPool_500 proves the shared resolver's nil-pool guard: a
// valid console id with no database answers 500 (never a panic, never a 404
// that would masquerade as a closed lookup).
func TestMAMResolve_NilPool_500(t *testing.T) {
	h := NewMAMHandler(nil, nil)
	for _, tc := range []struct {
		name string
		call func(h *MAMHandler, rec *httptest.ResponseRecorder)
	}{
		{"lock", func(h *MAMHandler, rec *httptest.ResponseRecorder) {
			h.LockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/lock", "123", "", 0, ""))
		}},
		{"unlock", func(h *MAMHandler, rec *httptest.ResponseRecorder) {
			h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", "123", "", 0, ""))
		}},
		{"events", func(h *MAMHandler, rec *httptest.ResponseRecorder) {
			h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", "123", "", 0, ""))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.call(h, rec)
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("nil pool: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestMAMUnlock_RegistryOnlyDevice_404 proves UnlockDevice refuses the
// registry-only outcome closed: the device resolves but has no authoritative
// devices row to attach evidence to — 404, nothing written.
func TestMAMUnlock_RegistryOnlyDevice_404(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())
	domA := ensureScopeTestDomain(t, pool, "mam-unlock-ro.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mam-unlock-ro.scope.test")
	base := mamScopeIDBase()
	regA := base + 20
	seedMAMRegistryDevice(t, pool, userA, regA, "44444444-4444-4444-8444-aaaaaaaaaaaa")

	rec := httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", fmtInt(regA), "", 0, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("registry-only unlock: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMUnlock_Success proves the unlocked outcome: evidence lands on the
// RESOLVED authoritative devices row and the response is 200.
func TestMAMUnlock_Success(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMAMHandler(pool, mailboxTestLogger())
	domA := ensureScopeTestDomain(t, pool, "mam-unlock-ok.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mam-unlock-ok.scope.test")
	base := mamScopeIDBase()
	regA, devA := base+30, base+31
	fp := "55555555-5555-4555-8555-bbbbbbbbbbbb"
	seedMAMRegistryDevice(t, pool, userA, regA, fp)
	seedMAMAuthoritativeDevice(t, pool, userA, devA, fp)

	rec := httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", fmtInt(regA), "", 0, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("unlock: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDeviceEventCount(t, pool, devA, "device_unlocked"); got != 1 {
		t.Errorf("unlock evidence on resolved devices row %d = %d, want 1", devA, got)
	}
}

// TestMAMUnlock_InsertionFailure_5xx proves the checked event insertion for
// the unlock path: a failing device_events INSERT (planted NOT NULL column)
// answers 5xx — never a silent 200.
func TestMAMUnlock_InsertionFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_events(
			id bigint, device_id bigint, event_type text, severity text,
			details jsonb, occurred_at timestamptz,
			planted_insert_failure text NOT NULL);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7011, 555011, 'mam-unlock-insert-fail', '88888888-8888-4888-8888-888888888887', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8011, 555011, '88888888-8888-4888-8888-888888888887')`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", "7011", "", 0, ""))
	if rec.Code < 500 {
		t.Fatalf("unlock insertion failure: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMUnlock_NotifyFailure_5xx proves the checked-propagation contract on
// the unlock path: the evidence committed, but a failed policy-change push
// (planted failing pg_notify) must surface as an error response.
func TestMAMUnlock_NotifyFailure_5xx(t *testing.T) {
	shadowPool := openMAMNotifyFixturePool(t, mamNotifyFailTables+mamPlantedNotifyFailureSQL)
	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", "7020", "", 0, ""))
	if rec.Code < 500 {
		t.Fatalf("unlock notify failure: want 5xx, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// The durable effect survived the failed push: the evidence row is present.
	if got := mamDeviceEventCount(t, shadowPool, 8020, "device_unlocked"); got != 1 {
		t.Errorf("unlock mutation did not survive the failed notify: %d rows, want 1", got)
	}
}

// TestMAMUnlock_DomainChangeBetweenLookupAndOperation_Closed reuses the
// mid-flight shadow fixture for the unlock arm of the in-statement scope
// contract: the resolution authorizes, the owner's domain flips, the
// device_events INSERT re-derives the predicate and matches zero rows →
// closed 404 with nothing written.
func TestMAMUnlock_DomainChangeBetweenLookupAndOperation_Closed(t *testing.T) {
	const consoleID = "7030"
	const devicesID = int64(8030)
	pool := openMAMListFixturePool(t, mamMidFlightFixtureSQL+mamMidFlightFlipSQL)
	h := NewMAMHandler(pool, mailboxTestLogger())

	rec := httptest.NewRecorder()
	h.UnlockDevice(rec, mamDeviceReq(http.MethodPost, "/admin/mam/devices/x/unlock", consoleID, "", 1, ""))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("mid-flight unlock: want 404 closed, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if got := mamDeviceEventCount(t, pool, devicesID, "device_unlocked"); got != 0 {
		t.Errorf("mid-flight unlock wrote device_unlocked evidence: %d rows", got)
	}
}

// TestMAMListDevices_QueryFailure_5xx proves a list-query failure inside the
// GUC transaction is a 5xx (never an empty 200): the shadow schema has
// device_registry with a truncated column set, so the projection fails.
func TestMAMListDevices_QueryFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7040, 555040, 'mam-list-fail', '88888888-8888-4888-8888-888888888886');`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.ListDevices(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil), 1, 0))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list devices query failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMGetDeviceEvents_QueryFailure_5xx proves a failed events read after a
// successful resolution is a 5xx: device_events exists in the shadow schema
// but lacks the projected columns, so the SELECT fails.
func TestMAMGetDeviceEvents_QueryFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_events(id bigint, device_id bigint);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7041, 555041, 'mam-events-fail', '88888888-8888-4888-8888-888888888885', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8041, 555041, '88888888-8888-4888-8888-888888888885');`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.GetDeviceEvents(rec, mamDeviceReq(http.MethodGet, "/admin/mam/devices/x/events", "7041", "", 0, ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("events query failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMSetGlobalPolicy_ExecFailure_5xx proves the global-policy upsert is
// checked: a failing INSERT (planted NOT NULL column) rolls into the outer
// error branch and answers 5xx.
func TestMAMSetGlobalPolicy_ExecFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz, planted_insert_failure text NOT NULL);`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.SetGlobalPolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/policies", "", "", 0,
		`{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("set global policy exec failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// mamFlipSeqFixtureSQL models a domain flip that lands on the (threshold+1)-th
// distinct transaction: every transaction through the threshold reads the
// owner IN scope; later transactions read the flipped (out-of-scope) domain.
// __THRESHOLD__ is replaced per test.
const mamFlipSeqFixtureSQL = `
	CREATE TABLE __SCHEMA__.device_registry(
		id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
		last_seen timestamptz, first_seen timestamptz);
	CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
	CREATE TABLE __SCHEMA__.device_policy(
		id bigint, device_id bigint, policy_key text, policy_value text,
		updated_at timestamptz);
	CREATE UNIQUE INDEX device_policy_device_key
		ON __SCHEMA__.device_policy(device_id, policy_key);
	CREATE TABLE __SCHEMA__.device_events(
		id bigint, device_id bigint, event_type text, severity text,
		details jsonb, occurred_at timestamptz);
	CREATE TABLE __SCHEMA__.mam_users_base(id bigint);
	INSERT INTO __SCHEMA__.mam_users_base VALUES (555050);
	INSERT INTO __SCHEMA__.device_registry
	VALUES(7050, 555050, 'mam-flipseq', '88888888-8888-4888-8888-888888888884', now(), now());
	INSERT INTO __SCHEMA__.devices
	VALUES(8050, 555050, '88888888-8888-4888-8888-888888888884');
	CREATE TABLE __SCHEMA__.flipseq_state(
		display bigint, target bigint, threshold bigint, txs bigint, last_tx bigint);
	INSERT INTO __SCHEMA__.flipseq_state VALUES (1, 2, __THRESHOLD__, 0, 0);
	CREATE FUNCTION __SCHEMA__.flipseq_domain() RETURNS bigint
	LANGUAGE plpgsql VOLATILE AS $fn$
	DECLARE s record; t bigint;
	BEGIN
	  SELECT * INTO s FROM __SCHEMA__.flipseq_state;
	  t := txid_current();
	  IF s.last_tx = t THEN
	    RETURN s.display;
	  END IF;
	  IF s.txs = s.threshold THEN
	    UPDATE __SCHEMA__.flipseq_state SET display = s.target;
	  END IF;
	  UPDATE __SCHEMA__.flipseq_state SET txs = s.txs + 1, last_tx = t;
	  RETURN s.display;
	END $fn$;
	CREATE VIEW __SCHEMA__.users AS
	  SELECT id, __SCHEMA__.flipseq_domain() AS domain_id FROM __SCHEMA__.mam_users_base;`

// TestMAMSetPerDevicePolicy_EvidenceWriteOutOfScope_404 is the paired-
// transaction arm of the in-statement scope contract for SetPerDevicePolicy:
// the scoped lookup AND the policy upsert both see the owner in scope (the
// override commits), THEN the owner's domain flips, and the evidence
// device_events INSERT (paired transaction 2) re-derives the predicate,
// matches zero rows and closes 404 — the stale authorization never writes
// evidence. mamWriteOutOfScopeProblem handles the outcome.
func TestMAMSetPerDevicePolicy_EvidenceWriteOutOfScope_404(t *testing.T) {
	const consoleID = "7050"
	const devicesID = int64(8050)
	pool := openMAMListFixturePool(t, strings.ReplaceAll(mamFlipSeqFixtureSQL, "__THRESHOLD__", "1"))
	h := NewMAMHandler(pool, mailboxTestLogger())

	rec := httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", consoleID, "", 1,
		`{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("evidence out-of-scope: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	// The override committed before the evidence write was refused.
	if got := mamDevicePolicyCount(t, pool, devicesID, "require_pin"); got != 1 {
		t.Errorf("committed override rows = %d, want 1 (the upsert preceded the flipped evidence write)", got)
	}
	if got := mamDeviceEventCount(t, pool, devicesID, "policy_applied"); got != 0 {
		t.Errorf("out-of-scope evidence write landed: %d policy_applied rows, want 0", got)
	}
}

// TestMAMSetPerDevicePolicy_UpsertFailure_5xx proves the per-device upsert is
// checked: a failing INSERT (planted NOT NULL column) answers 5xx.
func TestMAMSetPerDevicePolicy_UpsertFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text,
			updated_at timestamptz, planted_insert_failure text NOT NULL);
		CREATE UNIQUE INDEX device_policy_cov_key2 ON __SCHEMA__.device_policy(device_id, policy_key);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7051, 555051, 'mam-upsert-fail', '88888888-8888-4888-8888-888888888883', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8051, 555051, '88888888-8888-4888-8888-888888888883');`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.SetPerDevicePolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/devices/x/policy", "7051", "", 0,
		`{"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("upsert failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMUnsetPerDevicePolicy_DeleteFailure_5xx proves the per-device policy
// DELETE is checked: a failing statement (shadow device_policy carries a
// wrong-typed key column, so the DELETE cannot bind) answers 5xx — never a
// silent 200 over the RowsAffected check.
func TestMAMUnsetPerDevicePolicy_DeleteFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_registry(
			id bigint, user_id bigint, device_hash text, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		CREATE TABLE __SCHEMA__.devices(id bigint, user_id bigint, fingerprint text);
		CREATE TABLE __SCHEMA__.device_policy(device_id bigint, policy_key int);
		INSERT INTO __SCHEMA__.device_registry
		VALUES(7052, 555052, 'mam-unset-fail', '88888888-8888-4888-8888-888888888882', now(), now());
		INSERT INTO __SCHEMA__.devices
		VALUES(8052, 555052, '88888888-8888-4888-8888-888888888882');`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.UnsetPerDevicePolicy(rec, mamDeviceReq(http.MethodDelete, "/admin/mam/devices/x/policy/require_pin", "7052", "require_pin", 0, ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unset policy delete failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMSetGroupPolicy_ExecFailure_5xx proves the group-policy upsert is
// checked: a failing INSERT (planted NOT NULL column) answers 5xx.
func TestMAMSetGroupPolicy_ExecFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy_groups(
			id bigint, policy_key text, policy_value text, group_type text,
			group_id bigint, updated_at timestamptz, planted_insert_failure text NOT NULL);
		CREATE UNIQUE INDEX device_policy_groups_cov_key
			ON __SCHEMA__.device_policy_groups(policy_key, group_type, group_id);`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.SetGroupPolicy(rec, mamDeviceReq(http.MethodPut, "/admin/mam/policies/group", "", "", 0,
		`{"group_type":"department","group_id":918002,"policies":{"require_pin":"true"}}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("set group policy exec failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMUnsetGroupPolicy_DeleteFailure_5xx proves the group-policy DELETE is
// checked: a failing statement (shadow table carries a wrong-typed key column)
// answers 5xx.
func TestMAMUnsetGroupPolicy_DeleteFailure_5xx(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy_groups(
			policy_key text, policy_value text, group_type int, group_id bigint, updated_at timestamptz);`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.UnsetGroupPolicy(rec, mamCovGroupPolicyReq(http.MethodDelete, "department", "918003", "require_pin", ""))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("unset group policy delete failure: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMAMListPolicies_GlobalScanFailure_FailsClosed proves the global-scan
// arm's fail-closed outcome in isolation: the global listing carries one NULL
// key row (Scan fails, row skipped, rows.Err() surfaces the scan error) and
// the listing 500s rather than serving the partial set.
func TestMAMListPolicies_GlobalScanFailure_FailsClosed(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, `
		CREATE TABLE __SCHEMA__.device_policy(
			id bigint, device_id bigint, policy_key text, policy_value text, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy VALUES (1, NULL, NULL, 'broken', now());
		INSERT INTO __SCHEMA__.device_policy VALUES (2, NULL, 'good_pin', 'true', now());
		CREATE TABLE __SCHEMA__.device_policy_groups(
			id bigint, policy_key text, policy_value text, group_type text,
			group_id bigint, updated_at timestamptz);
		INSERT INTO __SCHEMA__.device_policy_groups VALUES (3, 'group_pin', '6', 'department', 1, now());`)

	h := NewMAMHandler(shadowPool, mailboxTestLogger())
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/policies", nil), 1, 0))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("global scan failure: want 500 (fail closed), got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
