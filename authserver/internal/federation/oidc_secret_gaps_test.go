package federation

// Gap coverage for the OIDC client-secret at-rest seam (oidc_secret.go):
// the fail-closed arms the happy-path migration tests do not reach — the
// function guards, the envelope base64 encodings, and the malformed-row
// aborts. Each abort must happen BEFORE any write (the transaction rolls
// back), so a malformed row can never corrupt a valid neighbor.

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
)

// TestOpenOIDCClientSecret_EnvelopeEncodings pins decodeOIDCSecretEnvelope's
// encoding contract: a value sealed with padded std encoding (as some
// operators/tools produce) decodes through the fallback and still opens; a
// value that is neither URL- nor std-base64 fails closed as unsealed.
func TestOpenOIDCClientSecret_EnvelopeEncodings(t *testing.T) {
	const secret = "encoding-round-trip-secret"
	sealed, err := SealOIDCClientSecret(secret, testMasterKey, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	envelope, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("sealed value is not raw base64: %v", err)
	}

	// Padded std encoding of the SAME envelope must open identically.
	padded := base64.StdEncoding.EncodeToString(envelope)
	if padded == sealed {
		t.Fatal("test setup: std encoding unexpectedly equals the raw form")
	}
	opened, err := OpenOIDCClientSecret(padded, testMasterKey)
	if err != nil {
		t.Fatalf("OpenOIDCClientSecret(std-padded envelope) = %v, want success", err)
	}
	if opened != secret {
		t.Fatalf("std-padded round trip = %q, want %q", opened, secret)
	}

	// Neither encoding applies: refused as unsealed ciphertext.
	for name, stored := range map[string]string{
		"invalid base64": "not*valid!b64~",
		"raw garbage":    "###",
	} {
		if _, err := OpenOIDCClientSecret(stored, testMasterKey); err == nil ||
			!strings.Contains(err.Error(), "not cryptokey-sealed ciphertext") {
			t.Fatalf("%s: OpenOIDCClientSecret = %v, want not-sealed refusal", name, err)
		}
	}
}

// TestResealOIDCProviderClientSecrets_Guards pins the pure function guards:
// a nil pool and missing master key are refused before any database work.
func TestResealOIDCProviderClientSecrets_Guards(t *testing.T) {
	if _, err := ResealOIDCProviderClientSecrets(context.Background(), nil, testMasterKey, cryptokey.ProfileStandard); err == nil ||
		!strings.Contains(err.Error(), "nil pool") {
		t.Fatalf("Reseal(nil pool) = %v, want nil-pool error", err)
	}
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("TEST_DB_DSN")
	}
	if dsn == "" {
		t.Skip("neither DB_DSN nor TEST_DB_DSN set — skipping live-pool guard cases")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("pool open failed (%v); skipping", err)
	}
	t.Cleanup(pool.Close)

	if _, err := ResealOIDCProviderClientSecrets(context.Background(), pool, nil, cryptokey.ProfileStandard); err == nil ||
		!strings.Contains(err.Error(), "requires a DB encryption master key") {
		t.Fatalf("Reseal(no master key) = %v, want master-key error", err)
	}
}

// TestResealOIDCProviderClientSecrets_ClosedPoolFailsBegin pins the
// transaction-begin error arm: with an unusable pool the migration fails
// before reading a single row.
func TestResealOIDCProviderClientSecrets_ClosedPoolFailsBegin(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("TEST_DB_DSN")
	}
	if dsn == "" {
		t.Skip("neither DB_DSN nor TEST_DB_DSN set — skipping closed-pool case")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Skipf("pool open failed (%v); skipping", err)
	}
	pool.Close()

	if _, err := ResealOIDCProviderClientSecrets(context.Background(), pool, testMasterKey, cryptokey.ProfileStandard); err == nil {
		t.Fatal("Reseal(closed pool) = nil error, want begin failure")
	}
}

// TestResealOIDCProviderClientSecrets_MalformedRowsAbort pins the two
// malformed-row aborts: a config that is not a JSON object, and a
// client_secret that is not a JSON string. Both must error (rolling back,
// writing nothing) instead of sealing garbage. Each shape runs in its own
// subtest so the deterministic ORDER BY key scan aborts on THAT shape.
func TestResealOIDCProviderClientSecrets_MalformedRowsAbort(t *testing.T) {
	pool := newOIDCSecretTestPool(t)

	t.Run("config is not a JSON object", func(t *testing.T) {
		arrayKey := "oidc_provider_malformed-array-" + uuid.NewString() + "_config"
		insertOIDCConfig(t, pool, arrayKey, `["not","an","object"]`, false)
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, arrayKey) })

		_, err := ResealOIDCProviderClientSecrets(context.Background(), pool, testMasterKey, cryptokey.ProfileStandard)
		if err == nil {
			t.Fatal("Reseal with non-object config = nil error, want abort")
		}
		if !strings.Contains(err.Error(), "re-seal \""+arrayKey+"\"") ||
			!strings.Contains(err.Error(), "not a JSON object") {
			t.Fatalf("abort error must name the offending key and shape: %v", err)
		}

		// Nothing was written: the row keeps its shape (JSONB normalizes
		// whitespace, so assert semantically — an aborted migration never
		// rewrites a row as a sealed object).
		raw, _ := fetchOIDCConfig(t, pool, arrayKey)
		if !strings.HasPrefix(string(raw), "[") {
			t.Fatalf("malformed-array row was mutated: %s", raw)
		}
	})

	t.Run("client_secret is not a string", func(t *testing.T) {
		numKey := "oidc_provider_malformed-secret-" + uuid.NewString() + "_config"
		insertOIDCConfig(t, pool, numKey, `{"name":"num","client_secret":42}`, false)
		t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, numKey) })

		_, err := ResealOIDCProviderClientSecrets(context.Background(), pool, testMasterKey, cryptokey.ProfileStandard)
		if err == nil {
			t.Fatal("Reseal with non-string client_secret = nil error, want abort")
		}
		if !strings.Contains(err.Error(), "re-seal \""+numKey+"\"") ||
			!strings.Contains(err.Error(), "client_secret is not a string") {
			t.Fatalf("abort error must name the offending key and shape: %v", err)
		}

		raw, _ := fetchOIDCConfig(t, pool, numKey)
		if !strings.Contains(string(raw), `"client_secret": 42`) {
			t.Fatalf("malformed-secret row was mutated: %s", raw)
		}
	})
}

// TestResealOIDCProviderClientSecrets_RowLockTimesOut pins the row-scan error
// arm: the reseal transaction's FOR UPDATE scan blocks behind another
// transaction's row lock and the cycle's deadline expires — the migration
// fails before sealing anything (no partial write).
func TestResealOIDCProviderClientSecrets_RowLockTimesOut(t *testing.T) {
	pool := newOIDCSecretTestPool(t)
	key := "oidc_provider_locked-" + uuid.NewString() + "_config"
	insertOIDCConfig(t, pool, key, `{"name":"locked","client_secret":"plain-secret"}`, false)
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key) })

	// Hold FOR UPDATE on the candidate row from a second connection.
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lock tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx,
		`SELECT value FROM system_config WHERE key = $1 FOR UPDATE`, key,
	); err != nil {
		t.Fatalf("lock candidate row: %v", err)
	}

	scanCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	_, err = ResealOIDCProviderClientSecrets(scanCtx, pool, testMasterKey, cryptokey.ProfileStandard)
	if err == nil {
		t.Fatal("reseal completed despite the locked candidate row, want scan failure")
	}
}
