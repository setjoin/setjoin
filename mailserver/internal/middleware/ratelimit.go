package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/httputil"
)

// rateLimitEntry tracks attempts for a single key.
type rateLimitEntry struct {
	count   int
	resetAt time.Time
	blocked bool
}

// RateLimiter is a simple in-memory per-IP rate limiter.
// In a multi-instance deployment this should be backed by Redis or PostgreSQL.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimitEntry
	limit   int
	window  time.Duration
}

// NewRateLimiter creates a limiter that allows `limit` requests per `window`.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		entries: make(map[string]*rateLimitEntry),
		limit:   limit,
		window:  window,
	}
}

type parsedProxy struct {
	exact net.IP
	cidr  *net.IPNet
}

// trustedProxiesParsed is the parsed form of the trusted proxy list.
// Protected by trustedProxiesMu. Updated atomically by SetTrustedProxies.
var trustedProxiesParsed = []parsedProxy{
	{exact: net.ParseIP("127.0.0.1")},
	{exact: net.ParseIP("::1")},
}
var trustedProxiesMu sync.RWMutex

// SetTrustedProxies replaces the trusted proxy list. Call before serving.
func SetTrustedProxies(proxies []string) {
	parsed := make([]parsedProxy, 0, len(proxies))
	for _, p := range proxies {
		if strings.Contains(p, "/") {
			_, cidr, err := net.ParseCIDR(p)
			if err != nil {
				continue
			}
			parsed = append(parsed, parsedProxy{cidr: cidr})
		} else {
			parsed = append(parsed, parsedProxy{exact: net.ParseIP(p)})
		}
	}
	trustedProxiesMu.Lock()
	trustedProxiesParsed = parsed
	trustedProxiesMu.Unlock()
}

// LoadTrustedProxies reads the trusted proxy list from system_config and applies it.
// Falls back to localhost defaults (127.0.0.1, ::1) if the DB is unavailable or
// the config key is absent. Call once during service initialization.
func LoadTrustedProxies(ctx context.Context, pool *pgxpool.Pool) {
	var raw json.RawMessage
	err := pool.QueryRow(ctx,
		`SELECT value FROM system_config WHERE key = 'trusted_proxy_ips'`,
	).Scan(&raw)
	if err != nil {
		return // keep defaults
	}
	var ips []string
	if err := json.Unmarshal(raw, &ips); err != nil || len(ips) == 0 {
		return // keep defaults
	}
	SetTrustedProxies(ips)
}

func isTrustedProxy(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	for _, p := range trustedProxiesParsed {
		if p.exact != nil && parsed.Equal(p.exact) {
			return true
		}
		if p.cidr != nil && p.cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// Allow reports whether the key is within its rate limit.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, ok := rl.entries[key]
	if !ok || now.After(entry.resetAt) {
		rl.entries[key] = &rateLimitEntry{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if entry.blocked {
		return false
	}

	entry.count++
	if entry.count > rl.limit {
		entry.blocked = true
		return false
	}
	return true
}

// Cleanup removes expired entries. Call periodically.
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for k, v := range rl.entries {
		if now.After(v.resetAt) {
			delete(rl.entries, k)
		}
	}
}

// Limiter is the interface both RateLimiter and HybridRateLimiter satisfy.
type Limiter interface {
	Allow(key string) bool
}

// windowCounter tracks hits in a single rate-limit window.
type windowCounter struct {
	startTime int64
	count     int64
}

// HybridRateLimiter provides in-memory rate limiting with PostgreSQL durability.
type HybridRateLimiter struct {
	mu        sync.Mutex
	local     map[string]*windowCounter
	dirtyKeys map[string]bool
	db        *pgxpool.Pool
	limit     int
	window    time.Duration
	syncEvery time.Duration
	stop      func()
}

func NewHybridRateLimiter(pool *pgxpool.Pool, limit int, window time.Duration) *HybridRateLimiter {
	rl := &HybridRateLimiter{
		db:        pool,
		local:     make(map[string]*windowCounter),
		dirtyKeys: make(map[string]bool),
		limit:     limit,
		window:    window,
		syncEvery: 5 * time.Second,
	}
	if err := rl.loadFromDB(context.Background()); err != nil {
		slog.Warn("rate limiter: warm-up from DB failed, starting cold", "error", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	rl.stop = cancel
	go rl.syncLoop(ctx)
	return rl
}

func (rl *HybridRateLimiter) Allow(key string) bool {
	now := time.Now().Unix()
	windowStart := now - (now % int64(rl.window.Seconds()))
	rl.mu.Lock()
	defer rl.mu.Unlock()
	wc, ok := rl.local[key]
	if !ok || wc.startTime != windowStart {
		wc = &windowCounter{startTime: windowStart}
		rl.local[key] = wc
		rl.dirtyKeys[key] = true
	}
	if wc.count >= int64(rl.limit) {
		return false
	}
	wc.count++
	rl.dirtyKeys[key] = true
	return true
}

func (rl *HybridRateLimiter) Shutdown() {
	rl.stop()
	rl.sync(context.Background())
}

func (rl *HybridRateLimiter) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(rl.syncEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.sync(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// pruneStale removes entries whose window is older than 2*window.
// Caller must hold rl.mu.
func (rl *HybridRateLimiter) pruneStale() {
	oldest := time.Now().Add(-rl.window * 2).Unix()
	for k, wc := range rl.local {
		if wc.startTime < oldest {
			delete(rl.local, k)
		}
	}
}

// windowSnapshot is a value-copy of a windowCounter, used by sync() to avoid
// holding the lock while building the DB batch.
type windowSnapshot struct {
	startTime int64
	count     int64
}

func (rl *HybridRateLimiter) sync(ctx context.Context) {
	rl.mu.Lock()
	// Snapshot VALUES (not pointers) while holding the lock so concurrent
	// Allow() mutations on the shared windowCounter are not a data race.
	snapshot := make(map[string]windowSnapshot, len(rl.dirtyKeys))
	for k := range rl.dirtyKeys {
		if wc := rl.local[k]; wc != nil {
			snapshot[k] = windowSnapshot{startTime: wc.startTime, count: wc.count}
		}
	}
	rl.dirtyKeys = make(map[string]bool)

	// Prune entries older than 2*window from local map to prevent unbounded growth.
	rl.pruneStale()
	rl.mu.Unlock()
	if len(snapshot) == 0 {
		return
	}
	batch := &pgx.Batch{}
	for key, snap := range snapshot {
		batch.Queue(
			`INSERT INTO rate_limit_counters (key, window_start, count)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (key)
			 DO UPDATE SET count = CASE
			   WHEN rate_limit_counters.window_start = $2
			     THEN rate_limit_counters.count + $3
			     ELSE $3
			 END,
			 window_start = $2`,
			key, time.Unix(snap.startTime, 0), snap.count,
		)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	br := rl.db.SendBatch(ctx, batch)
	defer func() { _ = br.Close() }()
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			slog.Error("rate limiter sync error", "error", err)
		}
	}
}

func (rl *HybridRateLimiter) loadFromDB(ctx context.Context) error {
	oldest := time.Now().Add(-rl.window * 2)
	rows, err := rl.db.Query(ctx,
		`SELECT key, window_start, count FROM rate_limit_counters
		 WHERE window_start >= $1`, oldest)
	if err != nil {
		return err
	}
	defer rows.Close()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for rows.Next() {
		var key string
		var start, count int64
		if err := rows.Scan(&key, &start, &count); err != nil {
			continue
		}
		if existing, ok := rl.local[key]; !ok || start > existing.startTime {
			rl.local[key] = &windowCounter{startTime: start, count: count}
		}
	}
	return nil
}

// clientIP extracts the client IP from a request.
// X-Forwarded-For is only trusted when the immediate peer (RemoteAddr) is
// in the trusted proxy list. Otherwise the header is ignored to prevent spoofing.
func clientIP(r *http.Request) string {
	return httputil.ClientIPWithTrust(r, isTrustedProxy)
}

// ClientIP is the exported form of clientIP, for callers outside this package
// that need the same trusted-proxy-aware extraction for an AUDIT field only
// (never for rate-limiting or AuthZ — RateLimit already calls the unexported
// clientIP itself). internal/booking's public handlers use it for the
// booking_requests.created_ip audit column.
func ClientIP(r *http.Request) string {
	return clientIP(r)
}

// RateLimit returns middleware that rejects requests over the limit with 429.
func RateLimit(rl Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.Allow(ip) {
				httputil.WriteProblemStatus(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
