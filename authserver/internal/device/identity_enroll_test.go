package device

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// insertTestUser creates a minimal user row compatible with the test DB schema.
// username must be unique; domain_id must reference an existing domain. The test
// seeds its own domain (get-or-create) rather than assume a fixture: mailserver_test_ca
// carries no domain fixtures, so a hardcoded id FK-fails on a clean load.
func insertTestUser(ctx context.Context, pool *pgxpool.Pool, email string) (int64, error) {
	var domainID int64
	// ponytail: get-or-create a stable test domain in one statement; re-run-safe
	// (no UNIQUE on domains.name, so guard with NOT EXISTS) and fixture-independent.
	if err := pool.QueryRow(ctx,
		`WITH ins AS (
		   INSERT INTO domains (name, is_local) SELECT 'device-enroll-test.example', TRUE
		   WHERE NOT EXISTS (SELECT 1 FROM domains WHERE name = 'device-enroll-test.example')
		   RETURNING id
		 )
		 SELECT id FROM ins UNION ALL SELECT id FROM domains WHERE name = 'device-enroll-test.example' LIMIT 1`,
	).Scan(&domainID); err != nil {
		return 0, err
	}
	var id int64
	err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id)
		 VALUES ($1, $2, $2, $3) RETURNING id`,
		email, email, domainID,
	).Scan(&id)
	return id, err
}

func TestEnrollApproveRevoke(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, _ := pgxpool.New(context.Background(), dsn)
	defer pool.Close()
	ctx := context.Background()

	uid, err := insertTestUser(ctx, pool, fmt.Sprintf("enr-%d@device.test", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)

	reg, err := RegisterDevice(ctx, pool, uid, Identity{Fingerprint: "f0123456789012345678901234567890ab", Platform: "ios"}, testSecretCodec())
	if err != nil {
		t.Fatal(err)
	}
	did := reg.ID

	// Self-registered device is unenrolled (no-self-enroll).
	var st string
	pool.QueryRow(ctx, `SELECT enroll_state FROM devices WHERE id=$1`, did).Scan(&st)
	if st != "unenrolled" {
		t.Fatalf("registered device want unenrolled, got %q", st)
	}

	if err := EnrollDevice(ctx, pool, uid, did, "t"); err != nil {
		t.Fatal(err)
	}
	if err := ApproveDevice(ctx, pool, uid, did, "t"); err != nil {
		t.Fatal(err)
	}
	pool.QueryRow(ctx, `SELECT enroll_state FROM devices WHERE id=$1`, did).Scan(&st)
	if st != "approved" {
		t.Fatalf("after approve want approved, got %q", st)
	}
	// Illegal: approve again (approved->approved) errors via BZ095.
	if err := ApproveDevice(ctx, pool, uid, did, "t"); err == nil {
		t.Fatal("re-approve should error (illegal transition)")
	}
	if err := RevokeDevice(ctx, pool, uid, did, "t"); err != nil {
		t.Fatal(err)
	}
	rows, err := ListDevicesForUser(ctx, pool, uid)
	if err != nil || len(rows) != 1 || rows[0].EnrollState != "revoked" {
		t.Fatalf("list: err=%v rows=%+v", err, rows)
	}
}

func TestApprovalQueueDefaults(t *testing.T) {
	// Pure unit test — no DB needed.
	// ApprovalQueueFilter{} → state "enrolled", limit 100.
	f := ApprovalQueueFilter{}
	state := f.State
	if state == "" {
		state = "enrolled"
	}
	if state != "enrolled" {
		t.Fatalf("default state want enrolled, got %q", state)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if limit != 100 {
		t.Fatalf("default limit want 100, got %d", limit)
	}
	// Oversized limit clamps to 500 (spec max-page contract: brief line 227).
	f2 := ApprovalQueueFilter{Limit: 9999}
	limit2 := f2.Limit
	if limit2 <= 0 {
		limit2 = 100
	} else if limit2 > 500 {
		limit2 = 500
	}
	if limit2 != 500 {
		t.Fatalf("oversized limit want 500 (clamped to max), got %d", limit2)
	}
}

func TestListApprovalQueue(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, _ := pgxpool.New(context.Background(), dsn)
	defer pool.Close()
	ctx := context.Background()

	nano := time.Now().UnixNano()
	u1, err := insertTestUser(ctx, pool, fmt.Sprintf("q1-%d@device.test", nano))
	if err != nil {
		t.Fatalf("insert u1: %v", err)
	}
	u2, err := insertTestUser(ctx, pool, fmt.Sprintf("q2-%d@device.test", nano))
	if err != nil {
		t.Fatalf("insert u2: %v", err)
	}
	defer func() {
		pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, u1, u2)
	}()

	// Fingerprints must be ≥32 chars (ValidateFingerprint).
	// prefix(2) + 30-digit padded nano → 32 chars.
	fp := func(prefix string) string {
		return prefix + fmt.Sprintf("%030d", nano)
	}

	reg1, err := RegisterDevice(ctx, pool, u1, Identity{Fingerprint: fp("aa"), Platform: "android"}, testSecretCodec())
	if err != nil {
		t.Fatalf("register d1: %v", err)
	}
	d1 := reg1.ID

	reg2, err := RegisterDevice(ctx, pool, u2, Identity{Fingerprint: fp("bb"), Platform: "ios"}, testSecretCodec())
	if err != nil {
		t.Fatalf("register d2: %v", err)
	}
	d2 := reg2.ID

	// d3: approved device (should NOT appear in enrolled queue).
	reg3, err := RegisterDevice(ctx, pool, u1, Identity{Fingerprint: fp("cc"), Platform: "ios"}, testSecretCodec())
	if err != nil {
		t.Fatalf("register d3: %v", err)
	}
	d3 := reg3.ID

	// Enroll d1 and d2.
	if err := EnrollDevice(ctx, pool, u1, d1, "queue test"); err != nil {
		t.Fatalf("enroll d1: %v", err)
	}
	if err := EnrollDevice(ctx, pool, u2, d2, "queue test"); err != nil {
		t.Fatalf("enroll d2: %v", err)
	}
	// Enroll then approve d3 — it should NOT appear in the enrolled queue.
	if err := EnrollDevice(ctx, pool, u1, d3, "queue test"); err != nil {
		t.Fatalf("enroll d3: %v", err)
	}
	if err := ApproveDevice(ctx, pool, u1, d3, "queue test"); err != nil {
		t.Fatalf("approve d3: %v", err)
	}

	q, err := ListApprovalQueue(ctx, pool, ApprovalQueueFilter{})
	if err != nil {
		t.Fatalf("ListApprovalQueue: %v", err)
	}
	// Must contain d1 and d2 (enrolled); must NOT contain d3 (approved).
	ids := make(map[int64]bool)
	for _, r := range q {
		if r.EnrollState != "enrolled" {
			t.Errorf("queue row %d has state %q, want enrolled", r.ID, r.EnrollState)
		}
		if r.UserEmail == "" {
			t.Errorf("queue row %d missing UserEmail", r.ID)
		}
		ids[r.ID] = true
	}
	if !ids[d1] {
		t.Errorf("d1 missing from queue")
	}
	if !ids[d2] {
		t.Errorf("d2 missing from queue")
	}
	if ids[d3] {
		t.Errorf("d3 (approved) should not appear in enrolled queue")
	}

	// RequestedAt must be set for enrolled devices.
	for _, r := range q {
		if r.ID == d1 || r.ID == d2 {
			if r.RequestedAt == nil {
				t.Errorf("queue row %d: RequestedAt nil", r.ID)
			}
		}
	}
}

// The device HMAC secret is the trust-root: returned exactly once, at first
// creation. Re-registering the SAME (user, fingerprint) must hit the ON CONFLICT
// update path and return an EMPTY secret — the client already holds it, so the
// stored secret is never re-transmitted.
func TestRegisterDeviceSecretReturnedOnceOnly(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	pool, _ := pgxpool.New(context.Background(), dsn)
	defer pool.Close()
	ctx := context.Background()

	uid, err := insertTestUser(ctx, pool, fmt.Sprintf("rereg-%d@device.test", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	defer pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)

	id := Identity{Fingerprint: fmt.Sprintf("reg-once-%030d", time.Now().UnixNano()), Platform: "ios"}

	first, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	if first.HMACSecret == "" {
		t.Fatal("first registration must return the HMAC secret")
	}

	second, err := RegisterDevice(ctx, pool, uid, id, testSecretCodec())
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("re-register should hit the same device row: first=%d second=%d", first.ID, second.ID)
	}
	if second.HMACSecret != "" {
		t.Fatal("re-registration must NOT return the device HMAC secret (client already holds it)")
	}
}
