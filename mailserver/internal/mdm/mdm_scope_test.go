package mdm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/testsupport"
)

// ── mdm-cross-domain-admin scope + wipe state-matrix tests ─────────────────
//
// Three-part wipe contract under test (do not conflate):
//   (1) ADMIN AUTHORIZATION — domain scope from the request context narrows
//       list/get/arm to devices whose owning user is inside the admin's domain
//       (mdm_device_state.user_id → users.domain_id, the owner-derived
//       resolution admin_can_reach uses for members). The predicate lives in
//       the same SQL statement (R1/R3, no check-then-mutate window).
//   (2) DEVICE ATTESTATION — "executed" is the SECOND client wipe_ack, i.e. an
//       UNVERIFIED CLIENT REPORT. These tests pin that RequestWipe treats it as
//       terminal ("wipe already executed") without asserting verified
//       destruction — no such mechanism exists.
//   (3) VERIFIED DESTRUCTION — out of scope here; intentionally untested.
//
// DB-backed tests gate on TEST_DB_DSN (falling back to DB_DSN — both are
// exported by scripts/test.sh); without either they skip, per repo convention.

func mdmScopeTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN not set — skipping DB-backed scope test")
	}
	return dsn
}

func mdmScopeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), mdmScopeTestDSN(t))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedScopeDomain creates (or finds) a named test domain; domains are shared
// fixture rows and are intentionally NOT deleted on cleanup (same contract as
// the admin package's ensureScopeTestDomain).
func seedScopeDomain(t *testing.T, pool *pgxpool.Pool, name string) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, name,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedScopeDomain(%s): %v", name, err)
	}
	return id
}

// seedScopeUser inserts a user in the domain with a unique identity. Cleanup
// deletes the user; mdm_device_state.user_id is ON DELETE CASCADE, so seeded
// devices go with it.
func seedScopeUser(t *testing.T, pool *pgxpool.Pool, domainID int64) int64 {
	t.Helper()
	suffix := mdmScopeRandomSuffix(t)
	var userID int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		"mdmscope-"+suffix, "mdmscope-"+suffix+"@scope.test", "MDM Scope Test", "$2a$10$placeholder", domainID,
	).Scan(&userID)
	if err != nil {
		t.Fatalf("seedScopeUser: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

// seedScopeDevice inserts an mdm_device_state row for the user with the given
// wipe state and returns the device id. Cleanup relies on user cascade, with an
// explicit delete as belt-and-braces for ownerless cases.
func seedScopeDevice(t *testing.T, pool *pgxpool.Pool, userID int64, wipeState, wipeLevel string) uuid.UUID {
	t.Helper()
	deviceID := uuid.New()
	var level any
	if wipeLevel != "" {
		level = wipeLevel
	}
	_, err := pool.Exec(context.Background(),
		`INSERT INTO mdm_device_state (device_id, user_id, platform, device_name, os_version, app_version,
		                                compliance_status, wipe_requested, wipe_level)
		 VALUES ($1, $2, 'ios', 'Scope Test Device', '17.0', '1.0', 'compliant', $3, $4)`,
		deviceID, userID, wipeState, level,
	)
	if err != nil {
		t.Fatalf("seedScopeDevice: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mdm_device_state WHERE device_id = $1`, deviceID)
	})
	return deviceID
}

func mdmScopeWipeState(t *testing.T, pool *pgxpool.Pool, deviceID uuid.UUID) (string, string, *time.Time) {
	t.Helper()
	var state, level string
	var requestedAt *time.Time
	err := pool.QueryRow(context.Background(),
		`SELECT wipe_requested, COALESCE(wipe_level, ''), wipe_requested_at
		 FROM mdm_device_state WHERE device_id = $1`, deviceID,
	).Scan(&state, &level, &requestedAt)
	if err != nil {
		t.Fatalf("read wipe state: %v", err)
	}
	return state, level, requestedAt
}

func mdmScopeRandomSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return hex.EncodeToString(b)
}

func mdmScopeEngine(t *testing.T, pool *pgxpool.Pool) *Engine {
	t.Helper()
	return NewEngine(pool, testsupport.TestLogger())
}

// wipeArmTestActors are fixed, per-test audit actor ids for the durable
// evidence assertions. admin_audit_log is append-only (BZ017 on UPDATE/DELETE),
// so rows written by a test cannot be deleted; each test scopes its assertions
// and leftovers to its own unique actor id (the same convention
// admin_ad_principal_reducer_test.go uses for append-only audit rows).
const (
	wipeArmActorStateMatrix = int64(776401)
	wipeArmActorDomainScope = int64(776402)
)

// mdmScopeWipeAuditCount counts the durable wipe-arm audit rows written for a
// DEVICE (the uuid is unique per run, so the count is exact even though
// admin_audit_log is append-only across runs) — durable evidence, not slog.
func mdmScopeWipeAuditCount(t *testing.T, pool *pgxpool.Pool, deviceID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'mdm_device_wipe_arm' AND notes = $1`, deviceID.String(),
	).Scan(&n); err != nil {
		t.Fatalf("count mdm_device_wipe_arm audit rows: %v", err)
	}
	return n
}

// mdmScopeWipeEventCount counts the durable device_events wipe rows for a
// device (parity with MAM lock/unlock evidence).
func mdmScopeWipeEventCount(t *testing.T, pool *pgxpool.Pool, deviceID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_events
		  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
		deviceID.String(),
	).Scan(&n); err != nil {
		t.Fatalf("count wipe_requested device_events: %v", err)
	}
	return n
}

// cleanupWipeEvidence removes the cleanable durable evidence a test armed
// (device_events rows carry no FK cascade; mdm_device_state rides the user
// cascade; admin_audit_log is append-only and stays, scoped to the unique
// actor id above).
func cleanupWipeEvidence(t *testing.T, pool *pgxpool.Pool, deviceID uuid.UUID) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM device_events
			  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
			deviceID.String())
	})
}

// ── unit (no DB) ─────────────────────────────────────────────────────────────

func TestWipeCompletionClientAttested_Marker(t *testing.T) {
	// The attestation-honesty marker must be the explicit string console
	// consumers match on; it labels completion as a client report, not proof.
	if WipeCompletionClientAttested != "client-attested" {
		t.Fatalf("WipeCompletionClientAttested = %q, want client-attested", WipeCompletionClientAttested)
	}
}

func TestRequestWipe_InvalidLevel_NoDB(t *testing.T) {
	e := NewEngine(nil, testsupport.TestLogger())
	err := e.RequestWipe(context.Background(), uuid.New(), "nuclear", 0, 0, "")
	verr, ok := err.(*ValidationError)
	if !ok || verr.Field != "level" {
		t.Fatalf("want level ValidationError, got %v", err)
	}
}

// TestMapWipeArmError_ConcurrentFailsClosed pins the fail-closed mapping of
// the reducer's belt-and-braces concurrent guard (BZ054/concurrent): a wipe
// arm that lost a race answers "device state changed concurrently; retry",
// never a silent re-arm.
func TestMapWipeArmError_ConcurrentFailsClosed(t *testing.T) {
	mapped := mapWipeArmError(&pgconn.PgError{
		Code:    "BZ054",
		Message: "device state changed concurrently",
		Hint:    `{"type":"concurrent"}`,
	})
	verr, ok := mapped.(*ValidationError)
	if !ok {
		t.Fatalf("want *ValidationError, got %v", mapped)
	}
	if verr.Field != "device_id" || !strings.Contains(verr.Message, "concurrently") {
		t.Fatalf("validation = %+v, want device_id / concurrent-mutation fail-closed", verr)
	}
}

// ── state matrix (DB) ────────────────────────────────────────────────────────

// TestRequestWipe_StateMatrix pins the retry semantics per state:
// none→pending arms; a pending retry with the same level succeeds
// idempotently WITHOUT a second transition (timestamps untouched); an executed
// wipe is terminal with an explicit error; an unknown device fails closed.
func TestRequestWipe_StateMatrix(t *testing.T) {
	pool := mdmScopeTestPool(t)
	e := mdmScopeEngine(t, pool)
	ctx := context.Background()

	dom := seedScopeDomain(t, pool, "mdm-state-matrix.scope.test")
	user := seedScopeUser(t, pool, dom)
	device := seedScopeDevice(t, pool, user, WipeNone, "")
	cleanupWipeEvidence(t, pool, device)

	// none → pending: armed.
	if err := e.RequestWipe(ctx, device, WipeAccount, 0, wipeArmActorStateMatrix, ""); err != nil {
		t.Fatalf("arm from none: %v", err)
	}
	state, level, firstAt := mdmScopeWipeState(t, pool, device)
	if state != WipePending || level != WipeAccount || firstAt == nil {
		t.Fatalf("after arm: state=%s level=%s at=%v", state, level, firstAt)
	}

	// Durable evidence landed with the arm — audit row AND device_events row,
	// in the same transaction, not just a log line.
	if got := mdmScopeWipeAuditCount(t, pool, device); got != 1 {
		t.Errorf("durable audit rows after arm = %d, want 1", got)
	}
	var (
		auditTarget string
		auditLevel  string
		auditActor  int64
	)
	if err := pool.QueryRow(ctx,
		`SELECT target_type, after_state->>'wipe_level', user_id FROM admin_audit_log
		  WHERE action = 'mdm_device_wipe_arm' AND notes = $1
		  ORDER BY id DESC LIMIT 1`, device.String(),
	).Scan(&auditTarget, &auditLevel, &auditActor); err != nil {
		t.Fatalf("read wipe audit row: %v", err)
	}
	if auditTarget != "mdm_device" || auditLevel != WipeAccount || auditActor != wipeArmActorStateMatrix {
		t.Errorf("audit row = (target=%s level=%s actor=%d), want mdm_device/account/%d",
			auditTarget, auditLevel, auditActor, wipeArmActorStateMatrix)
	}
	if got := mdmScopeWipeEventCount(t, pool, device); got != 1 {
		t.Errorf("durable device_events rows after arm = %d, want 1", got)
	}
	var (
		evSeverity string
		evDeviceID any
		evLevel    string
	)
	if err := pool.QueryRow(ctx,
		`SELECT severity, device_id, details->>'wipe_level' FROM device_events
		  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
		device.String(),
	).Scan(&evSeverity, &evDeviceID, &evLevel); err != nil {
		t.Fatalf("read wipe device_events row: %v", err)
	}
	if evSeverity != "critical" || evDeviceID != nil || evLevel != WipeAccount {
		t.Errorf("device_events row = (severity=%s device_id=%v level=%s), want critical/NULL/account",
			evSeverity, evDeviceID, evLevel)
	}

	// pending retry, same level → idempotent success, no double transition,
	// NO duplicate durable evidence.
	time.Sleep(10 * time.Millisecond)
	if err := e.RequestWipe(ctx, device, WipeAccount, 0, wipeArmActorStateMatrix, ""); err != nil {
		t.Fatalf("idempotent pending retry: %v", err)
	}
	state, level, secondAt := mdmScopeWipeState(t, pool, device)
	if state != WipePending || level != WipeAccount {
		t.Fatalf("after retry: state=%s level=%s", state, level)
	}
	if !secondAt.Equal(*firstAt) {
		t.Errorf("pending retry rewrote wipe_requested_at: %v -> %v", *firstAt, *secondAt)
	}
	if got := mdmScopeWipeAuditCount(t, pool, device); got != 1 {
		t.Errorf("idempotent retry duplicated audit evidence: %d rows, want 1", got)
	}
	if got := mdmScopeWipeEventCount(t, pool, device); got != 1 {
		t.Errorf("idempotent retry duplicated device_events evidence: %d rows, want 1", got)
	}

	// pending, different level → explicit conflict; state untouched, no
	// partial evidence for the rejected arm.
	err := e.RequestWipe(ctx, device, WipeDevice, 0, wipeArmActorStateMatrix, "")
	verr, ok := err.(*ValidationError)
	if !ok || verr.Field != "wipe_level" {
		t.Fatalf("level-mismatch retry: want wipe_level ValidationError, got %v", err)
	}
	if state2, _, _ := mdmScopeWipeState(t, pool, device); state2 != WipePending {
		t.Errorf("level-mismatch retry mutated state: %s", state2)
	}
	if got := mdmScopeWipeAuditCount(t, pool, device); got != 1 {
		t.Errorf("rejected arm wrote audit evidence: %d rows, want 1", got)
	}
	if got := mdmScopeWipeEventCount(t, pool, device); got != 1 {
		t.Errorf("rejected arm wrote device_events evidence: %d rows, want 1", got)
	}

	// executed → terminal, explicit error.
	if _, err := pool.Exec(ctx,
		`UPDATE mdm_device_state SET wipe_requested = $1 WHERE device_id = $2`, WipeExecuted, device); err != nil {
		t.Fatalf("force executed: %v", err)
	}
	err = e.RequestWipe(ctx, device, WipeAccount, 0, wipeArmActorStateMatrix, "")
	verr, ok = err.(*ValidationError)
	if !ok || verr.Message != "wipe already executed" {
		t.Fatalf("executed re-request: want 'wipe already executed', got %v", err)
	}

	// acknowledged, same level → idempotent success (device is mid-wipe).
	if _, err := pool.Exec(ctx,
		`UPDATE mdm_device_state SET wipe_requested = $1, wipe_level = $2 WHERE device_id = $3`,
		WipeAcknowledged, WipeDevice, device); err != nil {
		t.Fatalf("force acknowledged: %v", err)
	}
	if err := e.RequestWipe(ctx, device, WipeDevice, 0, wipeArmActorStateMatrix, ""); err != nil {
		t.Fatalf("acknowledged same-level retry: %v", err)
	}

	// unknown device → fail-closed.
	err = e.RequestWipe(ctx, uuid.New(), WipeAccount, 0, wipeArmActorStateMatrix, "")
	verr, ok = err.(*ValidationError)
	if !ok || verr.Field != "device_id" || verr.Message != "device not found" {
		t.Fatalf("unknown device: want fail-closed device not found, got %v", err)
	}
}

// TestRequestWipe_DomainScope pins owner-derived scope on the arm UPDATE
// (R3): a scoped admin cannot arm (or even detect) an out-of-scope device,
// while a global admin's behavior is unchanged.
func TestRequestWipe_DomainScope(t *testing.T) {
	pool := mdmScopeTestPool(t)
	e := mdmScopeEngine(t, pool)
	ctx := context.Background()

	domA := seedScopeDomain(t, pool, "mdm-scope-a.scope.test")
	domB := seedScopeDomain(t, pool, "mdm-scope-b.scope.test")
	userA := seedScopeUser(t, pool, domA)
	userB := seedScopeUser(t, pool, domB)
	deviceA := seedScopeDevice(t, pool, userA, WipeNone, "")
	deviceB := seedScopeDevice(t, pool, userB, WipeNone, "")
	// Only deviceA is armed in this test; its durable evidence must be
	// cleaned with it (device_events has no FK cascade from the device row).
	cleanupWipeEvidence(t, pool, deviceA)

	// Domain-A admin → domain-B device: denied AND indistinguishable from
	// missing; the row must be byte-unchanged ('none', never armed).
	err := e.RequestWipe(ctx, deviceB, WipeDevice, domA, wipeArmActorDomainScope, "")
	verr, ok := err.(*ValidationError)
	if !ok || verr.Field != "device_id" || verr.Message != "device not found" {
		t.Fatalf("cross-domain arm: want fail-closed device not found, got %v", err)
	}
	if state, _, _ := mdmScopeWipeState(t, pool, deviceB); state != WipeNone {
		t.Errorf("cross-domain arm mutated out-of-scope device: %s", state)
	}

	// Domain-A admin → domain-A device: allowed.
	if err := e.RequestWipe(ctx, deviceA, WipeDevice, domA, wipeArmActorDomainScope, ""); err != nil {
		t.Fatalf("same-domain arm: %v", err)
	}
	if state, level, _ := mdmScopeWipeState(t, pool, deviceA); state != WipePending || level != WipeDevice {
		t.Errorf("same-domain arm: state=%s level=%s", state, level)
	}

	// Even an executed out-of-scope device stays invisible to a scoped admin
	// (scope hides the executed status too — no existence leak via errors).
	if _, err := pool.Exec(ctx,
		`UPDATE mdm_device_state SET wipe_requested = $1 WHERE device_id = $2`, WipeExecuted, deviceB); err != nil {
		t.Fatalf("force executed: %v", err)
	}
	err = e.RequestWipe(ctx, deviceB, WipeAccount, domA, wipeArmActorDomainScope, "")
	verr, ok = err.(*ValidationError)
	if !ok || verr.Message != "device not found" {
		t.Fatalf("cross-domain executed: want device not found (no status leak), got %v", err)
	}

	// Global admin: unchanged — can arm the out-of-scope-to-A device... which is
	// executed here, so the terminal contract applies globally too.
	err = e.RequestWipe(ctx, deviceB, WipeAccount, 0, wipeArmActorDomainScope, "")
	verr, ok = err.(*ValidationError)
	if !ok || verr.Message != "wipe already executed" {
		t.Fatalf("global executed: want 'wipe already executed', got %v", err)
	}
}

// TestListDevices_DomainScope pins the R1 list predicate: a scoped admin's
// listing is filtered in SQL to same-domain owners; global admin sees all;
// self-service (admin=false) stays owner-scoped and unchanged.
func TestListDevices_DomainScope(t *testing.T) {
	pool := mdmScopeTestPool(t)
	e := mdmScopeEngine(t, pool)
	ctx := context.Background()

	domA := seedScopeDomain(t, pool, "mdm-list-a.scope.test")
	domB := seedScopeDomain(t, pool, "mdm-list-b.scope.test")
	userA := seedScopeUser(t, pool, domA)
	userB := seedScopeUser(t, pool, domB)
	deviceA1 := seedScopeDevice(t, pool, userA, WipeNone, "")
	deviceA2 := seedScopeDevice(t, pool, userA, WipeNone, "")
	deviceB := seedScopeDevice(t, pool, userB, WipeNone, "")

	contains := func(list []DeviceState, id uuid.UUID) bool {
		for _, d := range list {
			if d.DeviceID == id {
				return true
			}
		}
		return false
	}

	// Scoped admin: only domain-A devices.
	list, err := e.ListDevices(ctx, 0, true, domA)
	if err != nil {
		t.Fatalf("scoped list: %v", err)
	}
	if len(list) != 2 || !contains(list, deviceA1) || !contains(list, deviceA2) {
		t.Fatalf("scoped admin list leaked or missing devices: got %d, want exactly the 2 domain-A devices", len(list))
	}
	if contains(list, deviceB) {
		t.Errorf("scoped admin list leaked a domain-B device (IDOR)")
	}

	// Global admin: unchanged — sees both domains.
	list, err = e.ListDevices(ctx, 0, true, 0)
	if err != nil {
		t.Fatalf("global list: %v", err)
	}
	if !contains(list, deviceA1) || !contains(list, deviceB) {
		t.Errorf("global admin list must include devices from every domain")
	}

	// Self-service: owner-scoped, unchanged by an unrelated scope value.
	list, err = e.ListDevices(ctx, userB, false, 0)
	if err != nil {
		t.Fatalf("self-service list: %v", err)
	}
	if len(list) != 1 || !contains(list, deviceB) {
		t.Fatalf("self-service list: got %d devices, want exactly the owner's 1", len(list))
	}
}
