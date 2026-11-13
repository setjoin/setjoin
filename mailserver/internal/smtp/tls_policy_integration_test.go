package smtp

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// skipWithoutDB skips the test if TEST_DB_DSN is not set, following project convention.
func skipWithoutDB(t *testing.T) {
	t.Helper()
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
}

// TestOutboundWorkerLoadsPolicyFromDB verifies that tlsPolicyState.load
// correctly reads the TLS policy configuration from the system_config table.
func TestOutboundWorkerLoadsPolicyFromDB(t *testing.T) {
	skipWithoutDB(t)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("failed to connect to test DB: %v", err)
	}
	defer pool.Close()

	// Insert test policy configuration. The load function queries
	//   SELECT key, value->>0 AS val FROM system_config
	// so values are stored as JSONB arrays wrapping the actual config.
	enforceJSON, err := json.Marshal([]string{"fda.gov", "bank.gov"})
	if err != nil {
		t.Fatalf("failed to marshal enforce list: %v", err)
	}
	skipJSON, err := json.Marshal([]string{"old-server.local"})
	if err != nil {
		t.Fatalf("failed to marshal skip list: %v", err)
	}

	// Wrap in arrays so value->>0 extracts the inner value correctly.
	enforceWrapped, err := json.Marshal([]json.RawMessage{json.RawMessage(enforceJSON)})
	if err != nil {
		t.Fatalf("failed to wrap enforce: %v", err)
	}
	skipWrapped, err := json.Marshal([]json.RawMessage{json.RawMessage(skipJSON)})
	if err != nil {
		t.Fatalf("failed to wrap skip: %v", err)
	}
	globalWrapped, err := json.Marshal([]string{"enforce"})
	if err != nil {
		t.Fatalf("failed to wrap global mode: %v", err)
	}

	// Upsert policy rows.
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_enforce_domains", string(enforceWrapped))
	if err != nil {
		t.Fatalf("failed to insert enforce_domains: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_skip_domains", string(skipWrapped))
	if err != nil {
		t.Fatalf("failed to insert skip_domains: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_global_mode", string(globalWrapped))
	if err != nil {
		t.Fatalf("failed to insert global_mode: %v", err)
	}

	// Load policy from DB.
	var state tlsPolicyState
	if err := state.load(ctx, pool); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	enforce, skip, global := state.get()

	// Verify enforce list.
	if len(enforce) != 2 {
		t.Errorf("expected 2 enforce domains, got %d: %v", len(enforce), enforce)
	}
	if len(enforce) >= 2 {
		if enforce[0] != "fda.gov" || enforce[1] != "bank.gov" {
			t.Errorf("enforce list mismatch: got %v", enforce)
		}
	}

	// Verify skip list.
	if len(skip) != 1 {
		t.Errorf("expected 1 skip domain, got %d: %v", len(skip), skip)
	}
	if len(skip) >= 1 && skip[0] != "old-server.local" {
		t.Errorf("skip list mismatch: got %v", skip)
	}

	// Verify global mode.
	if !global {
		t.Error("global_enforce should be true")
	}

	// Clean up.
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key LIKE 'outbound_tls_%'`)
}

// TestGlobalEnforceRequiresTLSForAllDomains verifies that when global_enforce=true
// and no domain-specific list matches, requireTLS is true for any domain.
func TestGlobalEnforceRequiresTLSForAllDomains(t *testing.T) {
	skipWithoutDB(t)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("failed to connect to test DB: %v", err)
	}
	defer pool.Close()

	// Set global enforce with empty domain lists.
	emptyArray := "[]"
	enforceWrapped, _ := json.Marshal([]json.RawMessage{json.RawMessage(emptyArray)})
	skipWrapped, _ := json.Marshal([]json.RawMessage{json.RawMessage(emptyArray)})
	globalWrapped, _ := json.Marshal([]string{"enforce"})

	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_enforce_domains", string(enforceWrapped))
	if err != nil {
		t.Fatalf("failed to insert enforce_domains: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_skip_domains", string(skipWrapped))
	if err != nil {
		t.Fatalf("failed to insert skip_domains: %v", err)
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_global_mode", string(globalWrapped))
	if err != nil {
		t.Fatalf("failed to insert global_mode: %v", err)
	}

	// Load policy.
	var state tlsPolicyState
	if err := state.load(ctx, pool); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	enforce, skip, global := state.get()

	if !global {
		t.Fatal("global_enforce should be true")
	}

	// Test that any domain not in enforce/skip lists requires TLS under global enforce.
	testDomains := []string{"example.com", "google.com", "random-domain.org", "partner.net"}
	for _, domain := range testDomains {
		requireTLS, skipTLS := resolveTLSPolicy(domain, enforce, skip, global)
		if !requireTLS {
			t.Errorf("global_enforce=true: domain %q should require TLS", domain)
		}
		if skipTLS {
			t.Errorf("global_enforce=true: domain %q should not be skipped", domain)
		}
	}

	// Verify that skip list still overrides global enforce.
	// Insert a skip domain and reload.
	skipWithDomain, _ := json.Marshal([]string{"broken-mta.example.com"})
	skipWithDomainWrapped, _ := json.Marshal([]json.RawMessage{json.RawMessage(skipWithDomain)})
	_, err = pool.Exec(ctx,
		`INSERT INTO system_config (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
		"outbound_tls_skip_domains", string(skipWithDomainWrapped))
	if err != nil {
		t.Fatalf("failed to update skip_domains: %v", err)
	}
	if err := state.load(ctx, pool); err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	enforce, skip, global = state.get()

	// "broken-mta.example.com" should be skipped even under global enforce.
	requireTLS, skipTLS := resolveTLSPolicy("broken-mta.example.com", enforce, skip, global)
	if requireTLS {
		t.Error("broken-mta.example.com in skip list should NOT require TLS even with global enforce")
	}
	if !skipTLS {
		t.Error("broken-mta.example.com in skip list should be skipped")
	}

	// Clean up.
	_, _ = pool.Exec(ctx, `DELETE FROM system_config WHERE key LIKE 'outbound_tls_%'`)
}
