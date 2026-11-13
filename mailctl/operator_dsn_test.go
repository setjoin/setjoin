package main

import "testing"

func clearOperatorDSNEnv(t *testing.T) {
	t.Helper()
	for _, key := range operatorDSNEnvKeys {
		t.Setenv(key, "")
	}
}

func TestResolveOperatorDSN(t *testing.T) {
	clearOperatorDSNEnv(t)

	t.Setenv("DB_DIRECT_OWNER_DSN", "direct-owner-dsn")
	t.Setenv("DB_OWNER_DSN", "owner-dsn")
	t.Setenv("DB_DIRECT_DSN", "direct-dsn")
	t.Setenv("DB_DSN", "app-dsn")

	if got := resolveOperatorDSN("explicit-dsn"); got != "explicit-dsn" {
		t.Fatalf("explicit flag must win: got %q", got)
	}

	want := []string{"direct-owner-dsn", "owner-dsn", "direct-dsn", "app-dsn"}
	for i, key := range operatorDSNEnvKeys {
		if got := resolveOperatorDSN(""); got != want[i] {
			t.Errorf("%s highest set: want %q, got %q", key, want[i], got)
		}
		t.Setenv(key, "")
	}

	if got := resolveOperatorDSN(""); got != "" {
		t.Errorf("no source set: want empty, got %q", got)
	}
}

func TestResolveOperatorDSNNativeRLSOwnerWins(t *testing.T) {
	clearOperatorDSNEnv(t)
	t.Setenv("DB_DSN", "postgres://setjoin_app@app-pool/mail")
	t.Setenv("DB_DIRECT_DSN", "postgres://setjoin_app@postgres/mail")
	t.Setenv("DB_OWNER_DSN", "postgres://setjoin_owner@postgres/mail")
	t.Setenv("DB_DIRECT_OWNER_DSN", "postgres://setjoin_owner@postgres-direct/mail")

	if got := resolveOperatorDSN(""); got != "postgres://setjoin_owner@postgres-direct/mail" {
		t.Fatalf("Native-RLS operator command selected %q, want direct owner credential", got)
	}
}
