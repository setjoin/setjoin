package mdm

// D6 / DBSCHEMA-005 at-rest verification for the device_registry legacy
// secret backfill (Astra D6 impl-r2 finding 2): device_registry.device_secret
// has no live reader, so the V260 envelope columns get their migration path
// from BackfillRegistryDeviceSecrets — legacy plaintext is sealed into the
// family EK01 envelope and the plaintext NULLed, idempotently.
//
// DB-backed tests need DB_DSN (testsupport skips otherwise; REQUIRE_DB makes
// a missing DB fail instead of silently passing).

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/device"
	"setjoin.com/shared/testsupport"
)

// openOneConnTestPool returns a pool to TEST_DB_DSN/DB_DSN hard-capped at a
// single connection — the supported production floor (DB_MAX_CONNS=1) that the
// backfill's collect-then-update discipline must survive.
func openOneConnTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(mdmScopeTestDSN(t))
	if err != nil {
		t.Fatalf("parse DSN: %v", err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open one-connection pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// backfillIDBase keeps fixture ids far from sequence-assigned rows (the
// admin/MAM test convention).
func backfillIDBase() int64 {
	return int64(9_100_000_000) + time.Now().UnixNano()%1_000_000
}

func seedBackfillDomainAndUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	// domains_name_check requires dot-separated labels.
	domain := fmt.Sprintf("backfill-%d.test", time.Now().UnixNano())
	var domainID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name) VALUES ($1)
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})
	suffix := fmt.Sprintf("backfill-%d", time.Now().UnixNano())
	var userID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Backfill Test', '$2a$10$placeholder', $3) RETURNING id`,
		suffix, suffix+"@backfill.test", domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// The device_registry row cascades with the user (user_id FK ON DELETE
	// CASCADE); an explicit delete is belt-and-braces.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_registry WHERE user_id = $1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID
}

func seedBackfillRegistryRow(t *testing.T, pool *pgxpool.Pool, userID, id int64, deviceHash string, secret *string) {
	t.Helper()
	ctx := context.Background()
	var err error
	if secret != nil {
		_, err = pool.Exec(ctx,
			`INSERT INTO device_registry (id, user_id, device_hash, device_secret)
			 VALUES ($1, $2, $3, $4)`, id, userID, deviceHash, *secret)
	} else {
		_, err = pool.Exec(ctx,
			`INSERT INTO device_registry (id, user_id, device_hash)
			 VALUES ($1, $2, $3)`, id, userID, deviceHash)
	}
	if err != nil {
		t.Fatalf("seed device_registry row %d: %v", id, err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_registry WHERE id = $1`, id)
	})
}

func TestBackfillRegistryDeviceSecrets_SealsAndDrainsPlaintext(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := device.NewSecretCodec([]byte("registry-backfill-test-master"), cryptokey.ProfileStandard)
	userID := seedBackfillDomainAndUser(t, pool)

	const legacySecret = "archived-mam-checkin-hmac-key"
	id := backfillIDBase()
	secretCopy := legacySecret
	seedBackfillRegistryRow(t, pool, userID, id, fmt.Sprintf("backfill-seal-%d", id), &secretCopy)

	sealed, err := BackfillRegistryDeviceSecrets(ctx, pool, codec, testsupport.TestLogger())
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if sealed < 1 {
		t.Fatalf("backfill migrated %d rows, want at least the seeded legacy row", sealed)
	}

	// The row is now ciphertext-only: plaintext NULL, envelope + key id in.
	var plaintext *string
	var envelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT device_secret, device_secret_enc, device_secret_key_id
		   FROM device_registry WHERE id = $1`, id,
	).Scan(&plaintext, &envelope, &keyID); err != nil {
		t.Fatal(err)
	}
	if plaintext != nil {
		t.Fatal("backfilled row must not retain the plaintext device_secret")
	}
	if envelope == nil {
		t.Fatal("backfilled row must hold the sealed envelope")
	}
	if !strings.HasPrefix(string(envelope), "EK01") {
		t.Fatal("envelope must carry the family EK01 magic")
	}
	if keyID == nil || *keyID != device.SecretKeyIDV1 {
		t.Fatalf("backfilled row must be stamped with the active key id, got %v", keyID)
	}

	// The envelope opens to the exact legacy value (recoverable ciphertext).
	opened, err := codec.Open(envelope, *keyID)
	if err != nil {
		t.Fatalf("open backfilled envelope: %v", err)
	}
	if opened != legacySecret {
		t.Fatalf("backfilled envelope opened %q, want the legacy value", opened)
	}

	// Idempotent: a second run selects nothing and migrates nothing.
	again, err := BackfillRegistryDeviceSecrets(ctx, pool, codec, testsupport.TestLogger())
	if err != nil {
		t.Fatalf("second backfill run: %v", err)
	}
	if again != 0 {
		t.Fatalf("second backfill run migrated %d rows, want 0 (idempotent)", again)
	}
}

func TestBackfillRegistryDeviceSecrets_LeavesPlaintextOnlyRowsAndUntouchedRowsAlone(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := device.NewSecretCodec([]byte("registry-backfill-test-master"), cryptokey.ProfileStandard)
	userID := seedBackfillDomainAndUser(t, pool)

	// A registry row WITHOUT a device_secret (the shared/threat insert shape)
	// must be ignored entirely — no envelope stamped for a nonexistent secret.
	plainID := backfillIDBase() + 1
	seedBackfillRegistryRow(t, pool, userID, plainID, fmt.Sprintf("backfill-empty-%d", plainID), nil)

	if _, err := BackfillRegistryDeviceSecrets(ctx, pool, codec, testsupport.TestLogger()); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	var envelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT device_secret_enc, device_secret_key_id
		   FROM device_registry WHERE id = $1`, plainID,
	).Scan(&envelope, &keyID); err != nil {
		t.Fatal(err)
	}
	if envelope != nil || keyID != nil {
		t.Fatalf("row without a device_secret must stay untouched, got env=%v key=%v", envelope != nil, keyID != nil)
	}
}

func TestBackfillRegistryDeviceSecrets_NilCodecFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	if _, err := BackfillRegistryDeviceSecrets(context.Background(), pool, nil, testsupport.TestLogger()); err == nil {
		t.Fatal("a nil codec must fail closed — silently leaving plaintext would defeat the control")
	}
}

// TestBackfillRegistryDeviceSecrets_OneConnectionPool is THE connection-
// starvation regression (Astra D6 impl-r2 HOLD): the backfill used to hold
// the SELECT's pool connection while issuing pool.Exec inside the row loop,
// so on the supported DB_MAX_CONNS=1 floor the UPDATE waited for its own
// SELECT's connection until the drain timeout expired — no row migrated and
// every boot repeated the failure. The backfill must collect the bounded
// batch, close/check the rows (returning the connection), and only then
// update. Everything here — seeding, both backfill runs, and every
// verification read — shares that single connection.
func TestBackfillRegistryDeviceSecrets_OneConnectionPool(t *testing.T) {
	pool := openOneConnTestPool(t)
	ctx := context.Background()
	codec := device.NewSecretCodec([]byte("registry-backfill-test-master"), cryptokey.ProfileStandard)
	userID := seedBackfillDomainAndUser(t, pool)

	const legacySecret = "one-conn-archived-mam-checkin-hmac-key"
	id := backfillIDBase() + 2
	secretCopy := legacySecret
	seedBackfillRegistryRow(t, pool, userID, id, fmt.Sprintf("backfill-oneconn-%d", id), &secretCopy)

	sealed, err := BackfillRegistryDeviceSecrets(ctx, pool, codec, testsupport.TestLogger())
	if err != nil {
		t.Fatalf("backfill on a one-connection pool: %v", err)
	}
	if sealed < 1 {
		t.Fatalf("backfill migrated %d rows, want at least the seeded legacy row", sealed)
	}

	var plaintext *string
	var envelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT device_secret, device_secret_enc, device_secret_key_id
		   FROM device_registry WHERE id = $1`, id,
	).Scan(&plaintext, &envelope, &keyID); err != nil {
		t.Fatal(err)
	}
	if plaintext != nil {
		t.Fatal("one-connection backfill must NULL the plaintext device_secret")
	}
	if envelope == nil {
		t.Fatal("one-connection backfill must leave the sealed envelope")
	}
	if keyID == nil {
		t.Fatal("one-connection backfill must stamp the key id")
	}
	opened, err := codec.Open(envelope, *keyID)
	if err != nil {
		t.Fatalf("open one-connection backfill envelope: %v", err)
	}
	if opened != legacySecret {
		t.Fatalf("one-connection envelope opened %q, want the legacy value", opened)
	}

	// Idempotent on the same single connection: a second run migrates nothing.
	again, err := BackfillRegistryDeviceSecrets(ctx, pool, codec, testsupport.TestLogger())
	if err != nil {
		t.Fatalf("second one-connection backfill run: %v", err)
	}
	if again != 0 {
		t.Fatalf("second one-connection run migrated %d rows, want 0 (idempotent)", again)
	}
}
