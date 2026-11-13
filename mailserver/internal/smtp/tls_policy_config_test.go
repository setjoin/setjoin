package smtp

import (
	"encoding/json"
	"testing"
)

func TestParseTLSPolicyConfig_Empty(t *testing.T) {
	enforce, skip, global := parseTLSPolicyConfig(nil, nil)
	if len(enforce) != 0 {
		t.Error("empty config: enforce list should be empty")
	}
	if len(skip) != 0 {
		t.Error("empty config: skip list should be empty")
	}
	if global {
		t.Error("empty config: global should be false")
	}
}

func TestParseTLSPolicyConfig_EnforceOnly(t *testing.T) {
	enforceJSON, _ := json.Marshal([]string{"fda.gov", "bank.gov"})
	configs := map[string]string{
		"outbound_tls_enforce_domains": string(enforceJSON),
	}

	enforce, skip, _ := parseTLSPolicyConfig(configs, nil)
	if len(enforce) != 2 || enforce[0] != "fda.gov" || enforce[1] != "bank.gov" {
		t.Errorf("enforce list: got %v", enforce)
	}
	if len(skip) != 0 {
		t.Error("no skip config: skip list should be empty")
	}
}

func TestParseTLSPolicyConfig_SkipOnly(t *testing.T) {
	skipJSON, _ := json.Marshal([]string{"old-server.local"})
	configs := map[string]string{
		"outbound_tls_skip_domains": string(skipJSON),
	}

	enforce, skip, _ := parseTLSPolicyConfig(configs, nil)
	if len(enforce) != 0 {
		t.Error("no enforce config: enforce list should be empty")
	}
	if len(skip) != 1 || skip[0] != "old-server.local" {
		t.Errorf("skip list: got %v", skip)
	}
}

func TestParseTLSPolicyConfig_GlobalEnforce(t *testing.T) {
	configs := map[string]string{
		"outbound_tls_global_mode": "enforce",
	}

	_, _, global := parseTLSPolicyConfig(configs, nil)
	if !global {
		t.Error("global_mode=enforce: global should be true")
	}

	// Test opportunistic (default)
	configs2 := map[string]string{
		"outbound_tls_global_mode": "opportunistic",
	}
	_, _, global2 := parseTLSPolicyConfig(configs2, nil)
	if global2 {
		t.Error("global_mode=opportunistic: global should be false")
	}
}

func TestParseTLSPolicyConfig_Override(t *testing.T) {
	// Env overrides should take precedence over system_config
	enforceJSON, _ := json.Marshal([]string{"db-domain.gov"})
	configs := map[string]string{
		"outbound_tls_enforce_domains": string(enforceJSON),
	}
	overrides := map[string]string{
		"outbound_tls_enforce_domains": `["env-domain.gov"]`,
	}

	enforce, _, _ := parseTLSPolicyConfig(configs, overrides)
	if len(enforce) != 1 || enforce[0] != "env-domain.gov" {
		t.Errorf("override not applied: got %v", enforce)
	}
}

func TestParseTLSPolicyConfig_InvalidJSON(t *testing.T) {
	configs := map[string]string{
		"outbound_tls_enforce_domains": `not-json`,
	}

	enforce, skip, _ := parseTLSPolicyConfig(configs, nil)
	if len(enforce) != 0 {
		t.Error("invalid JSON: enforce list should be empty")
	}
	if len(skip) != 0 {
		t.Error("invalid JSON: skip list should be empty")
	}
}

func TestTLSPolicy_Integration(t *testing.T) {
	// Full integration test: parse config + resolve policy
	enforceJSON, _ := json.Marshal([]string{"fda.gov", "bank.gov"})
	skipJSON, _ := json.Marshal([]string{"old-server.local"})
	configs := map[string]string{
		"outbound_tls_enforce_domains": string(enforceJSON),
		"outbound_tls_skip_domains":    string(skipJSON),
		"outbound_tls_global_mode":     "opportunistic",
	}

	enforce, skip, global := parseTLSPolicyConfig(configs, nil)

	// fda.gov → enforce
	require, s := resolveTLSPolicy("fda.gov", enforce, skip, global)
	if !require || s {
		t.Error("fda.gov: should be enforced")
	}

	// old-server.local → skip
	require, s = resolveTLSPolicy("old-server.local", enforce, skip, global)
	if require || !s {
		t.Error("old-server.local: should be skipped")
	}

	// example.com → opportunistic
	require, s = resolveTLSPolicy("example.com", enforce, skip, global)
	if require || s {
		t.Error("example.com: should be opportunistic")
	}

	// global enforce
	_, _, global = parseTLSPolicyConfig(nil, map[string]string{"outbound_tls_global_mode": "enforce"})
	require, _ = resolveTLSPolicy("any.com", enforce, nil, global)
	if !require {
		t.Error("any.com with global enforce: should be enforced")
	}
}
