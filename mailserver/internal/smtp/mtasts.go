package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/ssrf"
)

// MTASTSPolicy represents a parsed MTA-STS policy (RFC 8461).
type MTASTSPolicy struct {
	Version  string   // "STSv1"
	Mode     string   // "none", "testing", "enforce"
	MX       []string // allowed MX hostnames
	MaxAge   int64    // seconds
	CachedAt time.Time
}

// MTASTSPolicyCache caches fetched MTA-STS policies in memory with DB persistence.
// On startup, policies are loaded from the mta_sts_policies table — no cold-cache
// penalty after restart. Newly fetched policies are persisted to the table for
// crash-safe resumability.
type MTASTSPolicyCache struct {
	mu    sync.RWMutex
	cache map[string]*MTASTSPolicy
	pool  *pgxpool.Pool
}

var mtaSTSCache = &MTASTSPolicyCache{cache: make(map[string]*MTASTSPolicy)}

// InitMTASTSCache loads previously persisted policies from PostgreSQL on startup.
// Must be called once during service initialization. Passing nil disables persistence.
func InitMTASTSCache(pool *pgxpool.Pool) {
	mtaSTSCache.pool = pool
	if pool == nil {
		return
	}
	rows, err := pool.Query(context.Background(),
		`SELECT domain, policy_json, fetched_at FROM mta_sts_policies`)
	if err != nil {
		slog.Error("mta-sts: failed to load policies from DB", "error", err)
		return
	}
	defer rows.Close()
	mtaSTSCache.mu.Lock()
	defer mtaSTSCache.mu.Unlock()
	for rows.Next() {
		var domain string
		var policy MTASTSPolicy
		var raw json.RawMessage
		var fetchedAt time.Time
		if err := rows.Scan(&domain, &raw, &fetchedAt); err != nil {
			continue
		}
		if err := json.Unmarshal(raw, &policy); err != nil {
			continue
		}
		policy.CachedAt = fetchedAt
		if time.Since(fetchedAt) < time.Duration(policy.MaxAge)*time.Second {
			mtaSTSCache.cache[domain] = &policy
		}
	}
	slog.Info("mta-sts: loaded policies from DB", "count", len(mtaSTSCache.cache))
}

// LookupMTASTS fetches and caches an MTA-STS policy for a domain.
// Returns nil if no policy exists or the domain uses mode "none".
func LookupMTASTS(domain string) *MTASTSPolicy {
	// Check cache
	mtaSTSCache.mu.RLock()
	if cached, ok := mtaSTSCache.cache[domain]; ok {
		if time.Since(cached.CachedAt) < time.Duration(cached.MaxAge)*time.Second {
			mtaSTSCache.mu.RUnlock()
			return cached
		}
	}
	mtaSTSCache.mu.RUnlock()

	// Step 1: DNS TXT lookup for _mta-sts.{domain}
	txts, err := lookupTXT("_mta-sts." + domain)
	if err != nil || len(txts) == 0 {
		return nil // no MTA-STS enabled
	}

	// Parse TXT record: "v=STSv1; id=20260509T000000Z"
	var policyID string
	for _, txt := range txts {
		for _, part := range strings.Split(txt, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "id=") {
				policyID = strings.TrimSpace(strings.TrimPrefix(part, "id="))
			}
		}
	}
	if policyID == "" {
		return nil
	}

	// Step 2: HTTPS fetch of mta-sts.txt from policy host
	policyHost := "mta-sts." + domain
	url := "https://" + policyHost + "/.well-known/mta-sts.txt"
	body, err := httpsGet(url)
	if err != nil {
		return nil
	}

	// Step 3: Parse policy
	policy := parseMTASTS(string(body))
	if policy == nil || policy.Mode == "none" {
		return nil
	}

	policy.CachedAt = time.Now()
	mtaSTSCache.mu.Lock()
	mtaSTSCache.cache[domain] = policy
	mtaSTSCache.mu.Unlock()

	// Persist to DB for crash-safe resumability
	if mtaSTSCache.pool != nil {
		raw, _ := json.Marshal(policy)
		mtaSTSCache.pool.Exec(context.Background(),
			`INSERT INTO mta_sts_policies (domain, policy_json, fetched_at)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (domain) DO UPDATE SET policy_json = $2, fetched_at = $3`,
			domain, raw, policy.CachedAt)
	}
	return policy
}

func parseMTASTS(body string) *MTASTSPolicy {
	policy := &MTASTSPolicy{MaxAge: 86400} // default 24h
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])
		switch key {
		case "version":
			policy.Version = value
		case "mode":
			policy.Mode = value
		case "mx":
			policy.MX = append(policy.MX, value)
		case "max_age":
			fmt.Sscanf(value, "%d", &policy.MaxAge)
			if policy.MaxAge <= 0 {
				policy.MaxAge = 86400
			}
		}
	}
	// Validate required fields
	if policy.Version != "STSv1" || policy.Mode == "" {
		return nil
	}
	if len(policy.MX) == 0 {
		return nil
	}
	return policy
}

// MXMatches checks if the connecting MX host is in the policy's allowed list.
func (p *MTASTSPolicy) MXMatches(mxHost string) bool {
	mxHost = strings.TrimSuffix(mxHost, ".")
	for _, allowed := range p.MX {
		allowed = strings.TrimSuffix(allowed, ".")
		if strings.EqualFold(strings.TrimSuffix(mxHost, "."), strings.TrimSuffix(allowed, ".")) {
			return true
		}
	}
	return false
}

// httpsGet performs an HTTPS GET request with a 10-second timeout.
func httpsGet(url string) ([]byte, error) {
	// SSRF guard: the policy host derives from an arbitrary recipient domain
	// (mta-sts.{domain}), so dial through the post-DNS guard that rejects
	// internal/link-local targets and defeats DNS rebinding. See shared/ssrf.
	client := ssrf.SafeHTTPClient(10 * time.Second)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpsGet: %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536)) // max 64KB
	if err != nil {
		return nil, err
	}
	return body, nil
}
