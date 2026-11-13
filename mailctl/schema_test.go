package main

import (
	"os"
	"testing"
)

// TestResolveSchemaDSN covers the DSN-preference logic the schema command relies
// on. DDL must run as the schema OWNER (under the constrained native-RLS shape
// DB_DSN is setjoin_app, and applying migrations over it creates app-owned
// tables — runbook footgun #1), so the owner DSNs win over the legacy pair:
// DB_DIRECT_OWNER_DSN → DB_OWNER_DSN → DB_DIRECT_DSN → DB_DSN, error when none
// set. Same precedence as deploy/scripts/upgrade.sh. The apply/check paths need
// a live database (verified by the end-to-end shell run); this guards the pure
// resolution logic in CI without one.
func TestResolveSchemaDSN(t *testing.T) {
	keys := []string{"DB_DIRECT_OWNER_DSN", "DB_OWNER_DSN", "DB_DIRECT_DSN", "DB_DSN"}
	for _, k := range keys {
		v, had := os.LookupEnv(k)
		t.Cleanup(func() { restore(k, v, had) })
	}

	// Full precedence: unset the winner at each step, the next key takes over.
	os.Setenv("DB_DIRECT_OWNER_DSN", "direct-owner-dsn")
	os.Setenv("DB_OWNER_DSN", "owner-dsn")
	os.Setenv("DB_DIRECT_DSN", "direct-dsn")
	os.Setenv("DB_DSN", "pooled-dsn")
	want := []string{"direct-owner-dsn", "owner-dsn", "direct-dsn", "pooled-dsn"}
	for i, k := range keys {
		if got, err := resolveSchemaDSN(); err != nil || got != want[i] {
			t.Errorf("%s highest set: want %q, got %q (err %v)", k, want[i], got, err)
		}
		os.Unsetenv(k)
	}

	// Errors when none are set.
	if _, err := resolveSchemaDSN(); err == nil {
		t.Error("none set: want an error")
	}
}

func TestSchemaCmdUnknownAction(t *testing.T) {
	if err := runSchema(nil, "bogus", nil); err == nil {
		t.Error("unknown schema action should return an error, not dispatch")
	}
}

func restore(key, val string, had bool) {
	if had {
		os.Setenv(key, val)
	} else {
		os.Unsetenv(key)
	}
}
