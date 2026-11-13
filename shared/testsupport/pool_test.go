package testsupport

import (
	"context"
	"testing"
)

func TestOpenTestPoolsAndToggleGuardUseProductionSeams(t *testing.T) {
	pool := OpenTestPool(t)
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatalf("OpenTestPool ping: %v", err)
	}

	const encryptionKey = "testsupport-coverage-key-32-bytes-minimum"
	gucPool := OpenTestPoolWithGUC(t, encryptionKey)
	var gotKey string
	if err := gucPool.QueryRow(t.Context(),
		`SELECT current_setting('app.encryption_key')`).Scan(&gotKey); err != nil {
		t.Fatalf("read encryption GUC: %v", err)
	}
	if gotKey != encryptionKey {
		t.Fatalf("encryption GUC=%q, want %q", gotKey, encryptionKey)
	}

	const key = "feature.identity_normalized_reads"
	var before bool
	if err := pool.QueryRow(t.Context(),
		`SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&before); err != nil {
		t.Fatalf("read toggle before guard: %v", err)
	}
	SetFeatureToggleForTest(t, pool, key, !before)
	var during bool
	if err := pool.QueryRow(t.Context(),
		`SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&during); err != nil {
		t.Fatalf("read toggle during guard: %v", err)
	}
	if during == before {
		t.Fatalf("toggle guard did not apply requested value: before=%v during=%v", before, during)
	}

	if logger := TestLogger(); logger == nil {
		t.Fatal("TestLogger returned nil")
	}
}

func TestOpenTestPoolWithGUCAllowsExplicitMissingKey(t *testing.T) {
	pool := OpenTestPoolWithGUC(t, "")
	var present bool
	err := pool.QueryRow(context.Background(),
		`SELECT current_setting('app.encryption_key', TRUE) IS NOT NULL`).Scan(&present)
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("missing-key pool unexpectedly installed app.encryption_key")
	}
}
