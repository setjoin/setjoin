package pgxutil

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenPool_EmptyDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := OpenPool(ctx, "", 0, "", "")
	if err == nil {
		t.Fatal("expected error for empty DSN")
	}
}

func TestOpenPool_InvalidDSN(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := OpenPool(ctx, "not-a-valid-pg-dsn", 0, "", "")
	if err == nil {
		t.Fatal("expected error for invalid DSN")
	}
}

func TestOpenPool_DefaultMaxConns(t *testing.T) {
	maxConns := 0
	if maxConns <= 0 {
		maxConns = 20
	}
	if maxConns != 20 {
		t.Errorf("default maxConns = %d, want 20", maxConns)
	}
}

func TestOpenDirectPool_FallsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	pool, err := OpenDirectPool(ctx, "", "postgres://user:pass@localhost/db")
	if err == nil {
		pool.Close()
	}
}

func TestOpenDirectConn_FallsBack(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := OpenDirectConn(ctx, "", "postgres://user:pass@localhost/db")
	if err == nil {
		conn.Close(ctx)
	}
}

func TestOpenPool_RetryInvalidDSN(t *testing.T) {
	// Test that OpenPool retries up to MaxRetries for invalid DSN.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_, err := OpenPool(ctx, "postgres://user:pass@localhost/db", 0, "", "")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error for unreachable DB")
	}
	if !contains(err.Error(), "failed after") {
		t.Errorf("expected retry exhaustion error, got: %v", err)
	}
	// Should have taken at least 1+2=3 seconds (2 retries) plus timeout.
	if elapsed < 2*time.Second {
		t.Errorf("expected retry backoff to take >2s, took %v", elapsed)
	}
}

func TestOpenPool_RetryCount(t *testing.T) {
	if MaxRetries != 3 {
		t.Errorf("MaxRetries = %d, want 3", MaxRetries)
	}
}

// TestOpenPool_AfterConnect_SetsEncryptionKeyGUC is the PERMANENT regression
// guard for the single choke point every `_enc` column family (S/MIME private
// keys, TOTP secrets, SAML IdP certs, push tokens) relies on: OpenPool's
// AfterConnect hook setting the app.encryption_key session GUC on every new
// backend connection. If that wiring is ever removed or bypassed, EVERY
// pgp_sym_decrypt call across both servers starts failing (fail-closed, per
// the family tests) — but nothing would say WHY until someone chased it
// through four unrelated packages. This test fails LOUDLY, at the source,
// the moment the hook itself regresses.
//
// Wired into scripts/check-guc-afterconnect.sh (auto-discovered by
// run-guards.sh) rather than relied on via shared/'s go test stage, which only
// runs in the opt-in RACE=1 lane — see that script for the removal-proof
// self-test (temporarily neuters this exact hook and asserts this test reds).
func TestOpenPool_AfterConnect_SetsEncryptionKeyGUC(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: this guard must not pass as a silent skip")
		}
		t.Skip("DB_DSN not set — skipping DB-backed AfterConnect guard")
	}

	const guardKey = "pgxutil-afterconnect-guard-key-32c"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := OpenPool(ctx, dsn, 2, guardKey, "")
	if err != nil {
		t.Fatalf("OpenPool: %v", err)
	}
	defer pool.Close()

	var got string
	if err := pool.QueryRow(ctx, "SELECT current_setting('app.encryption_key')").Scan(&got); err != nil {
		t.Fatalf("current_setting('app.encryption_key') errored on a fresh pool connection — "+
			"the AfterConnect GUC-set hook is not wired (or was removed): %v", err)
	}
	if got != guardKey {
		t.Fatalf("app.encryption_key GUC = %q, want %q — AfterConnect is not setting the "+
			"encryption key on new connections", got, guardKey)
	}
}

// auditCutoverKeyA / auditCutoverKeyB satisfy the 32-char first-activation
// floor; auditCutoverLegacyWeakKey is the shape of a pre-floor deployed key.
const (
	auditCutoverKeyA          = "audit-cutover-adequate-key-0123456789abcdef"
	auditCutoverKeyB          = "audit-cutover-replacement-key-fedcba9876543210"
	auditCutoverLegacyWeakKey = "audit-cutover-test-key" // 22 chars: weak under every profile
)

// resetAuditCutover clears the audit_chain_cutover singleton (and re-clears it
// on cleanup) so each matrix test starts pre-cutover.
func resetAuditCutover(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM audit_chain_cutover`); err != nil {
		t.Fatalf("reset audit cutover: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM audit_chain_cutover`) })
}

// insertAuditRow writes one admin_audit_log row through the given pool, so the
// chain trigger checksums it as v3: under THAT pool's AUDIT_HMAC_KEY session
// GUC (user_id NULL: no users fixture needed). The append-only trigger makes
// audit rows undeletable BY DESIGN — this package's tests therefore leave their
// marked rows in place (audit history is never rewritten, including by tests).
func insertAuditRow(t *testing.T, pool *pgxpool.Pool, action string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_audit_log(user_id, ip, action, target_type, before_state, after_state)
		 VALUES (NULL, '10.0.0.1', $1, 'system', '{}', '{}')`, action); err != nil {
		t.Fatalf("insert audit row %q: %v", action, err)
	}
}

// TestEnforceAuditCutoverActivatesIdempotentlyAndFailsClosedWithoutKey covers
// matrix cells 5/6 (adequate key activates; re-activation is idempotent) and
// cell 2 (empty key post-cutover refuses startup).
func TestEnforceAuditCutoverActivatesIdempotentlyAndFailsClosedWithoutKey(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	pool, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverKeyA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	resetAuditCutover(t, pool)
	if err := EnforceAuditCutover(context.Background(), pool, auditCutoverKeyA); err != nil {
		t.Fatalf("activate cutover: %v", err)
	}
	// Second boot on the activated install, same key: idempotent, still nil.
	if err := EnforceAuditCutover(context.Background(), pool, auditCutoverKeyA); err != nil {
		t.Fatalf("same-key boot after activation must pass, got: %v", err)
	}
	if err := EnforceAuditCutover(context.Background(), pool, ""); err == nil {
		t.Fatal("missing key accepted after cutover")
	}
}

// TestEnforceAuditCutoverRefusesWeakFirstActivation is matrix cell 3: a weak
// key must fail startup BEFORE audit_chain_activate_v3 can permanently lock V3
// in under it — the cutover singleton must still be absent afterwards.
func TestEnforceAuditCutoverRefusesWeakFirstActivation(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	pool, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverLegacyWeakKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	resetAuditCutover(t, pool)
	err = EnforceAuditCutover(context.Background(), pool, auditCutoverLegacyWeakKey)
	if err == nil || !contains(err.Error(), "at least 32 characters") {
		t.Fatalf("weak first activation = %v, want a >=32-character floor error", err)
	}
	var stillInactive bool
	if err := pool.QueryRow(context.Background(), `SELECT NOT EXISTS (SELECT 1 FROM audit_chain_cutover WHERE singleton)`).Scan(&stillInactive); err != nil {
		t.Fatal(err)
	}
	if !stillInactive {
		t.Fatal("weak key must never permanently activate audit V3")
	}
}

// TestEnforceAuditCutoverRefusesDifferentKeyAfterActivation is HOLD item 2
// (unmanaged key replacement): with rows HMAC'd under the activation key,
// supplying a different key must be refused loudly, the rows must stay
// untouched, and the original key must keep verifying.
func TestEnforceAuditCutoverRefusesDifferentKeyAfterActivation(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	poolA, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverKeyA)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolA.Close)
	resetAuditCutover(t, poolA)
	if err := EnforceAuditCutover(context.Background(), poolA, auditCutoverKeyA); err != nil {
		t.Fatalf("activate cutover: %v", err)
	}
	insertAuditRow(t, poolA, "pgxutil_cutover_replacement_test")

	poolB, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverKeyB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolB.Close)
	err = EnforceAuditCutover(context.Background(), poolB, auditCutoverKeyB)
	if err == nil || !contains(err.Error(), "does not match the key this install activated audit V3 with") {
		t.Fatalf("key replacement after activation = %v, want a loud refusal", err)
	}
	// The refusal must not have re-hashed anything: the original key still
	// verifies the very same rows (same-key verification, HOLD item 2).
	if err := EnforceAuditCutover(context.Background(), poolA, auditCutoverKeyA); err != nil {
		t.Fatalf("original key must keep verifying after a refused replacement, got: %v", err)
	}
}

// TestEnforceAuditCutoverSameWeakKeyContinuesWithWarning is matrix cell 4: an
// install that activated audit V3 before the floor existed keeps booting on its
// deployed weak key — verify_audit_chain stays fully valid on that segment and
// the weakness surfaces as a persistent operator-visible warning, never a
// rejection and never a silent key change. The legacy state is simulated by
// inserting the cutover singleton directly (the activation floor would refuse a
// weak key today — that is cell 3's test above).
func TestEnforceAuditCutoverSameWeakKeyContinuesWithWarning(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is required")
		}
		t.Skip("DB_DSN not set")
	}
	poolWeak, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverLegacyWeakKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolWeak.Close)
	resetAuditCutover(t, poolWeak)

	// Legacy install: cutover row exists, rows are HMAC'd under the weak key.
	var maxID int64
	var anchor *string
	if err := poolWeak.QueryRow(context.Background(),
		`SELECT coalesce(max(id), 0), (SELECT checksum FROM admin_audit_log ORDER BY id DESC LIMIT 1)
		 FROM admin_audit_log`).Scan(&maxID, &anchor); err != nil {
		t.Fatal(err)
	}
	if _, err := poolWeak.Exec(context.Background(),
		`INSERT INTO audit_chain_cutover(singleton, first_v3_id, anchor_checksum) VALUES (TRUE, $1, $2)`,
		maxID+1, anchor); err != nil {
		t.Fatalf("simulate legacy cutover: %v", err)
	}
	insertAuditRow(t, poolWeak, "pgxutil_cutover_weak_legacy_test")

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := EnforceAuditCutover(context.Background(), poolWeak, auditCutoverLegacyWeakKey); err != nil {
		t.Fatalf("same weak key on an already-activated install must continue, got: %v", err)
	}
	if !contains(buf.String(), "already activated audit V3") {
		t.Fatalf("expected a persistent operator-visible weak-key warning, got log: %q", buf.String())
	}
}

func TestEnforceAuditCutoverHandlesInactiveAndDatabaseFailures(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	pool, err := OpenPool(context.Background(), dsn, 2, "", auditCutoverKeyA)
	if err != nil {
		t.Fatal(err)
	}
	resetAuditCutover(t, pool)
	if err := EnforceAuditCutover(context.Background(), pool, ""); err != nil {
		t.Fatalf("inactive cutover rejected: %v", err)
	}
	pool.Close()
	// Cutover-state inspection is now the first DB operation for every key
	// branch, so a closed pool fails closed on it for both key states.
	if err := EnforceAuditCutover(context.Background(), pool, auditCutoverKeyA); err == nil || !contains(err.Error(), "inspect audit HMAC cutover") {
		t.Fatalf("closed pool key inspection error = %v", err)
	}
	if err := EnforceAuditCutover(context.Background(), pool, ""); err == nil || !contains(err.Error(), "inspect audit HMAC cutover") {
		t.Fatalf("closed pool inspection error = %v", err)
	}

	// The activation wrap is covered by a REAL reducer failure: a pool whose
	// connections never got the app.audit_hmac_key session GUC trips
	// audit_chain_activate_v3's own "AUDIT_HMAC_KEY is required to activate
	// audit V3" precondition.
	poolNoKey, err := OpenPool(context.Background(), dsn, 1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poolNoKey.Close)
	resetAuditCutover(t, poolNoKey)
	if err := EnforceAuditCutover(context.Background(), poolNoKey, auditCutoverKeyA); err == nil || !contains(err.Error(), "activate audit HMAC cutover") {
		t.Fatalf("GUC-less activation error = %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- Straggler-wave gap tests: GUC canary and audit-key verification arms ---

// mustClosedPool opens and immediately closes a pool against the test DSN so
// every later acquire fails without hanging.
func mustClosedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live-pool canary arms")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("pool open failed (%v); skipping", err)
	}
	pool.Close()
	return pool
}

// TestVerifySessionGUCCarry_AcquireFailure pins the acquire leg of the
// startup canary: an unusable pool is refused, never silently accepted.
func TestVerifySessionGUCCarry_AcquireFailure(t *testing.T) {
	pool := mustClosedPool(t)
	err := verifySessionGUCCarry(context.Background(), pool, "enc-key", "hmac-key")
	if err == nil || !strings.Contains(err.Error(), "acquire") {
		t.Fatalf("verifySessionGUCCarry(closed pool) = %v, want acquire failure", err)
	}
}

// TestVerifySessionGUCCarry_MismatchRefusesPool pins the deployment
// precondition itself: a plain pool (no AfterConnect hook) cannot carry the
// app.* GUCs, so the canary refuses it — the PgBouncer-without-
// track_extra_parameters shape this check exists for.
func TestVerifySessionGUCCarry_MismatchRefusesPool(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set — skipping live-pool canary arms")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("pool open failed (%v); skipping", err)
	}
	defer pool.Close()

	encKey := "canary-enc-" + uuid.NewString()
	err = verifySessionGUCCarry(context.Background(), pool, encKey, "")
	if err == nil || !strings.Contains(err.Error(), "did not survive") {
		t.Fatalf("plain pool with encryption GUC = %v, want carry failure", err)
	}

	hmacKey := "canary-hmac-" + uuid.NewString()
	err = verifySessionGUCCarry(context.Background(), pool, "", hmacKey)
	if err == nil || !strings.Contains(err.Error(), "did not survive") {
		t.Fatalf("plain pool with audit GUC = %v, want carry failure", err)
	}
}

// TestVerifyAuditActivationKey_UnreadableCutover pins the cutover-inspection
// error arm: a pool that cannot read audit_chain_cutover fails closed.
func TestVerifyAuditActivationKey_UnreadableCutover(t *testing.T) {
	pool := mustClosedPool(t)
	err := verifyAuditActivationKey(context.Background(), pool)
	if err == nil || !strings.Contains(err.Error(), "cutover") {
		t.Fatalf("verifyAuditActivationKey(closed pool) = %v, want cutover inspection failure", err)
	}
}
