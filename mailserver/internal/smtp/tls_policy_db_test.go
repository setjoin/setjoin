package smtp

import (
	"encoding/json"
	"testing"
)

func TestLoadTLSPolicyFromConfig(t *testing.T) {
	// Test the parsing from raw config strings (doesn't need DB)
	enforceJSON := `["fda.gov", "bank.gov"]`
	skipJSON := `["old-server.local"]`

	enforce, skip, global := parseTLSPolicyConfig(
		map[string]string{
			"outbound_tls_enforce_domains": enforceJSON,
			"outbound_tls_skip_domains":    skipJSON,
			"outbound_tls_global_mode":     "enforce",
		},
		nil,
	)

	if len(enforce) != 2 {
		t.Errorf("expected 2 enforce domains, got %d", len(enforce))
	}
	if len(skip) != 1 {
		t.Errorf("expected 1 skip domain, got %d", len(skip))
	}
	if !global {
		t.Error("global enforce should be true")
	}
}

func TestMarshalTLSPolicyConfig(t *testing.T) {
	// Verify round-trip: what the admin API writes, the policy reader parses
	enforce := []string{"fda.gov", "bank.gov"}
	skip := []string{"old-server.local"}

	enforceJSON, _ := json.Marshal(enforce)
	skipJSON, _ := json.Marshal(skip)

	configs := map[string]string{
		"outbound_tls_enforce_domains": string(enforceJSON),
		"outbound_tls_skip_domains":    string(skipJSON),
		"outbound_tls_global_mode":     "enforce",
	}

	parsedEnforce, parsedSkip, parsedGlobal := parseTLSPolicyConfig(configs, nil)
	if len(parsedEnforce) != 2 || parsedEnforce[0] != "fda.gov" {
		t.Error("round-trip: enforce list mismatch")
	}
	if len(parsedSkip) != 1 || parsedSkip[0] != "old-server.local" {
		t.Error("round-trip: skip list mismatch")
	}
	if !parsedGlobal {
		t.Error("round-trip: global mode mismatch")
	}
}
