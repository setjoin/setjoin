package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/ssrf"
)

// ServerConfig is returned by the discovery endpoint.
type ServerConfig struct {
	URL             string `json:"url"`
	LoginField      string `json:"login_field"`
	LoginDomainHint string `json:"login_domain_hint,omitempty"`
	DiscoveredVia   string `json:"discovered_via"` // "srv", "mx", or "manual"
}

type cacheEntry struct {
	config  *ServerConfig
	expires time.Time
}

const (
	// discoveryCacheTTL bounds how long a successful discovery result is
	// served from cache. Ops tunable: 5 minutes keeps client setup snappy
	// while limiting staleness after DNS changes (pre-existing behavior,
	// previously hardcoded at the write site).
	discoveryCacheTTL = 5 * time.Minute

	// maxDiscoveryCacheEntries caps resident cache entries. /api/discover is
	// unauthenticated and the caller controls the cache key, so wildcard DNS
	// backed by unique hostnames must not grow the map without bound
	// (CWE-770: unauthenticated endpoint resource bounding). Ops tunable:
	// 1024 comfortably exceeds the distinct legitimate domains of a
	// 300-10,000-user deployment; realistic entries are <1 KB, and the
	// per-entry worst case is fixed by the 64 KB .well-known read cap in
	// fetchWellKnown below.
	maxDiscoveryCacheEntries = 1024
)

var (
	// nowFunc is a test seam for TTL behavior; production always sees time.Now.
	nowFunc = time.Now

	cache   = make(map[string]*cacheEntry)
	cacheMu sync.RWMutex
)

// cacheGet returns the cached config for domain. A hit requires an unexpired
// entry — identical to the previous handler-inline check — and an expired
// entry is now also evicted on access instead of lingering forever. The
// config pointer is captured under the read lock; cache entries are immutable
// after construction, so the returned config is safe to use unlocked.
func cacheGet(domain string) (*ServerConfig, bool) {
	now := nowFunc()
	var (
		config     *ServerConfig
		hit, found bool
	)
	cacheMu.RLock()
	if entry, ok := cache[domain]; ok {
		found = true
		if now.Before(entry.expires) {
			config, hit = entry.config, true
		}
	}
	cacheMu.RUnlock()

	if hit {
		return config, true
	}
	if !found {
		return nil, false
	}

	// Present but expired: evict lazily so dead entries do not accumulate.
	// Re-check under the write lock in case of a concurrent refresh.
	cacheMu.Lock()
	if entry, ok := cache[domain]; ok && !now.Before(entry.expires) {
		delete(cache, domain)
	}
	cacheMu.Unlock()
	return nil, false
}

// cachePut stores a discovery result, bounding resident memory: when the map
// is at cap, expired entries are pruned first and then the earliest-expiring
// (oldest) entry is evicted to make room, so the map never exceeds
// maxDiscoveryCacheEntries even under distinct wildcard-host key floods.
// Existing keys are replaced with a fresh immutable entry rather than mutated.
func cachePut(domain string, config *ServerConfig) {
	now := nowFunc()
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if _, ok := cache[domain]; !ok && len(cache) >= maxDiscoveryCacheEntries {
		pruneExpiredLocked(now)
		if len(cache) >= maxDiscoveryCacheEntries {
			evictEarliestExpiryLocked()
		}
	}
	cache[domain] = &cacheEntry{config: config, expires: now.Add(discoveryCacheTTL)}
}

// pruneExpiredLocked deletes every expired entry. Caller holds cacheMu.
func pruneExpiredLocked(now time.Time) {
	for key, entry := range cache {
		if !now.Before(entry.expires) {
			delete(cache, key)
		}
	}
}

// evictEarliestExpiryLocked deletes the entry closest to expiry — the oldest
// resident entry under the fixed TTL — keeping the freshest, most likely
// reused entries cached. Caller holds cacheMu and the map is non-empty.
func evictEarliestExpiryLocked() {
	var victim string
	var earliest time.Time
	found := false
	for key, entry := range cache {
		if !found || entry.expires.Before(earliest) {
			victim, earliest, found = key, entry.expires, true
		}
	}
	if found {
		delete(cache, victim)
	}
}

// HandleDiscover serves GET /api/discover?domain=company.com
// Performs DNS SRV/MX lookup, queries .well-known/setjoin, returns server config.
func HandleDiscover() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			httputil.WriteProblemStatus(w, http.StatusBadRequest, "domain parameter required")
			return
		}

		// Check cache (hit requires an unexpired entry; expired entries are
		// evicted by cacheGet).
		if config, ok := cacheGet(domain); ok {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(config)
			return
		}

		config, err := discover(domain)
		if err != nil {
			httputil.WriteProblemStatus(w, http.StatusNotFound, err.Error())
			return
		}

		cachePut(domain, config)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(config)
	}
}

func discover(domain string) (*ServerConfig, error) {
	// 1. Try SRV record: _jmap._tcp.{domain}
	if config, err := trySRV(domain); err == nil && config != nil {
		config.DiscoveredVia = "srv"
		return config, nil
	}

	// 2. Try MX record
	if config, err := tryMX(domain); err == nil && config != nil {
		config.DiscoveredVia = "mx"
		return config, nil
	}

	return nil, fmt.Errorf("no server found for domain %s", domain)
}

func trySRV(domain string) (*ServerConfig, error) {
	_, addrs, err := net.LookupSRV("jmap", "tcp", domain)
	if err != nil || len(addrs) == 0 {
		return nil, err
	}

	for _, addr := range addrs {
		target := strings.TrimSuffix(addr.Target, ".")
		url := fmt.Sprintf("https://%s:%d", target, addr.Port)
		if config := fetchWellKnown(url); config != nil {
			return config, nil
		}
	}
	return nil, fmt.Errorf("SRV found but no server responded")
}

func tryMX(domain string) (*ServerConfig, error) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		return nil, err
	}

	for _, mx := range mxRecords {
		host := strings.TrimSuffix(mx.Host, ".")
		url := fmt.Sprintf("https://%s:443", host)
		if config := fetchWellKnown(url); config != nil {
			return config, nil
		}
	}
	return nil, fmt.Errorf("MX found but no server responded")
}

func fetchWellKnown(serverURL string) *ServerConfig {
	// /api/discover is UNAUTHENTICATED and serverURL's host is derived from the
	// caller-supplied domain via DNS SRV/MX, so dial through ssrf.SafeHTTPClient:
	// its Control hook rejects loopback/private/link-local (incl. 169.254.169.254
	// metadata) targets AFTER DNS resolution, defeating DNS rebinding too.
	client := ssrf.SafeHTTPClient(5 * time.Second)
	resp, err := client.Get(serverURL + "/.well-known/setjoin") //nolint:gosec // G704: dialed through ssrf.SafeHTTPClient (post-DNS dialer guard, rebind-safe)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var wellknown struct {
		LoginField      string   `json:"login_field"`
		LoginDomainHint string   `json:"login_domain_hint,omitempty"`
		Features        []string `json:"features"`
	}
	// Cap the response body to 64 KB — a legitimate .well-known doc is tiny;
	// an unbounded read allows OOM on a malicious or misconfigured server.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&wellknown); err != nil {
		return nil
	}

	// Verify this is a SetJoin server
	hasJMAP := false
	for _, f := range wellknown.Features {
		if f == "jmap" {
			hasJMAP = true
			break
		}
	}
	if !hasJMAP {
		return nil
	}

	return &ServerConfig{
		URL:             serverURL,
		LoginField:      wellknown.LoginField,
		LoginDomainHint: wellknown.LoginDomainHint,
	}
}
