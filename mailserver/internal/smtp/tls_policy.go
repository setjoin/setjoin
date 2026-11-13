package smtp

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// resolveTLSPolicy determines the TLS enforcement behavior for a destination
// domain. Returns (requireTLS, skipTLS).
//
// Resolution priority (highest wins):
//  1. enforce list match → requireTLS=true, skipTLS=false
//  2. skip list match    → requireTLS=false, skipTLS=true
//  3. global enforce     → requireTLS=true, skipTLS=false
//  4. default            → requireTLS=false, skipTLS=false (opportunistic)
func resolveTLSPolicy(domain string, enforceDomains, skipDomains []string, globalEnforce bool) (requireTLS, skipTLS bool) {
	d := strings.ToLower(domain)

	for _, ed := range enforceDomains {
		if strings.ToLower(ed) == d {
			return true, false // enforce wins over everything
		}
	}

	for _, sd := range skipDomains {
		if strings.ToLower(sd) == d {
			return false, true // skip
		}
	}

	if globalEnforce {
		return true, false
	}

	return false, false // opportunistic
}

// tlsPolicyState holds the parsed outbound TLS policy configuration.
type tlsPolicyState struct {
	mu             sync.RWMutex
	enforceDomains []string
	skipDomains    []string
	globalEnforce  bool
	loadedAt       time.Time
}

// load reads the current policy from system_config.
func (s *tlsPolicyState) load(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx,
		`SELECT key, value->>0 AS val FROM system_config
		 WHERE key IN ('outbound_tls_enforce_domains', 'outbound_tls_skip_domains', 'outbound_tls_global_mode')`)
	if err != nil {
		return err
	}
	defer rows.Close()

	configs := make(map[string]string)
	for rows.Next() {
		var key, val string
		if err := rows.Scan(&key, &val); err == nil {
			configs[key] = val
		}
	}

	enforce, skip, global := parseTLSPolicyConfig(configs, nil)

	s.mu.Lock()
	s.enforceDomains = enforce
	s.skipDomains = skip
	s.globalEnforce = global
	s.loadedAt = time.Now()
	s.mu.Unlock()

	return nil
}

// get returns the current policy lists.
func (s *tlsPolicyState) get() (enforce, skip []string, global bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enforceDomains, s.skipDomains, s.globalEnforce
}

// parseTLSPolicyConfig parses policy configuration from key-value maps.
// overrides (typically from env vars) take precedence over configs (DB).
func parseTLSPolicyConfig(configs, overrides map[string]string) (enforceDomains, skipDomains []string, globalEnforce bool) {
	get := func(key string) string {
		if v, ok := overrides[key]; ok && v != "" {
			return v
		}
		if v, ok := configs[key]; ok {
			return v
		}
		return ""
	}

	if raw := get("outbound_tls_enforce_domains"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &enforceDomains)
	}
	if raw := get("outbound_tls_skip_domains"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &skipDomains)
	}
	globalEnforce = get("outbound_tls_global_mode") == "enforce"
	return
}
