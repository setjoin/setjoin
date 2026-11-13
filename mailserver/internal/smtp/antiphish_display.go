package smtp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DisplayNameDetector checks for display-name spoofing by comparing the
// From header's display name against the organization's user display-name
// list. Exact matches from external domains are rejected. Fuzzy matches
// above a configurable pg_trgm similarity threshold are warned.
type DisplayNameDetector struct {
	pool *pgxpool.Pool

	mu              sync.RWMutex
	userCache       map[string]bool // lower(display_name) → true
	cacheExpiresAt  time.Time
	cacheTTL        time.Duration
	threshold       float64
	internalDomains map[string]bool // lower(domain) → true

	// similarityFunc is set to pg_trgm similarity in production; overridden in tests.
	similarityFunc func(a, b string) float64
}

// DisplayNameDetectorConfig holds configuration for the display-name detector.
type DisplayNameDetectorConfig struct {
	Pool            *pgxpool.Pool
	Threshold       float64 // pg_trgm similarity threshold (default 0.85)
	CacheTTL        time.Duration
	InternalDomains []string
}

// NewDisplayNameDetector creates a new display-name spoofing detector.
func NewDisplayNameDetector(cfg DisplayNameDetectorConfig) *DisplayNameDetector {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 0.85
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}
	d := &DisplayNameDetector{
		pool:            cfg.Pool,
		userCache:       make(map[string]bool),
		threshold:       cfg.Threshold,
		cacheTTL:        cfg.CacheTTL,
		internalDomains: make(map[string]bool),
		similarityFunc:  nil, // nil means use pg_trgm
	}
	for _, domain := range cfg.InternalDomains {
		d.internalDomains[strings.ToLower(strings.TrimSpace(domain))] = true
	}
	return d
}

// Name returns the detector identifier.
func (d *DisplayNameDetector) Name() string {
	return "display_name"
}

// Check evaluates the message for display-name spoofing.
func (d *DisplayNameDetector) Check(ctx context.Context, msg *PhishInput) (*PhishResult, error) {
	fromName := strings.TrimSpace(msg.FromName)
	if fromName == "" {
		return nil, nil
	}

	// Skip if sender domain is internal
	if d.isInternalDomain(msg.FromAddr) {
		return nil, nil
	}

	// Ensure cache is fresh
	if err := d.refreshCache(ctx); err != nil {
		return nil, err
	}

	fromNameLower := strings.ToLower(fromName)

	// Check exact match first (most definitive)
	d.mu.RLock()
	exactMatch := d.userCache[fromNameLower]
	d.mu.RUnlock()

	if exactMatch {
		return &PhishResult{
			Verdict:  PhishReject,
			Detector: d.Name(),
			Evidence: []string{fmt.Sprintf("display_name_exact_match:%s", fromName)},
		}, nil
	}

	// Fuzzy match: use server-side pg_trgm when pool is available (single query),
	// fall back to in-memory trigram for tests without a DB connection.
	if d.pool != nil {
		return d.checkFuzzyDB(ctx, fromNameLower)
	}
	return d.checkFuzzyMemory(fromNameLower)
}

// isInternalDomain checks whether the sender's domain is internal.
func (d *DisplayNameDetector) isInternalDomain(fromAddr string) bool {
	domain := ""
	if idx := strings.LastIndex(fromAddr, "@"); idx >= 0 {
		domain = strings.ToLower(strings.TrimSpace(fromAddr[idx+1:]))
		// Strip angle brackets from addresses like <user@domain>
		domain = strings.TrimRight(domain, ">")
	}
	if domain == "" {
		return false
	}
	return d.internalDomains[domain]
}

// refreshCache reloads the user cache from the database if the cache TTL has expired.
func (d *DisplayNameDetector) refreshCache(ctx context.Context) error {
	d.mu.RLock()
	expired := time.Now().After(d.cacheExpiresAt)
	d.mu.RUnlock()

	if !expired {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Double-check after acquiring write lock
	if !time.Now().After(d.cacheExpiresAt) {
		return nil
	}

	// If no pool, skip DB refresh (tests use pre-populated cache)
	if d.pool == nil {
		d.cacheExpiresAt = time.Now().Add(d.cacheTTL)
		return nil
	}

	rows, err := d.pool.Query(ctx, `SELECT lower(display_name) FROM users WHERE enabled = TRUE AND display_name IS NOT NULL AND display_name != ''`)
	if err != nil {
		return fmt.Errorf("refresh display name cache: %w", err)
	}
	defer rows.Close()

	newCache := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("scan display name: %w", err)
		}
		newCache[name] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows display name: %w", err)
	}

	d.userCache = newCache
	d.cacheExpiresAt = time.Now().Add(d.cacheTTL)
	return nil
}

// checkFuzzyDB runs a single server-side query using pg_trgm similarity()
// to find display names that are similar to the sender's display name.
// This replaces the N+1 pattern of calling similarity() per cached name.
func (d *DisplayNameDetector) checkFuzzyDB(ctx context.Context, fromNameLower string) (*PhishResult, error) {
	type match struct {
		name  string
		score float64
	}

	rows, err := d.pool.Query(ctx,
		`SELECT display_name, similarity(display_name, $1) AS score
		 FROM users
		 WHERE enabled = TRUE
		   AND display_name IS NOT NULL
		   AND display_name != ''
		   AND similarity(display_name, $1) >= $2
		 ORDER BY score DESC
		 LIMIT 1`,
		fromNameLower, d.threshold,
	)
	if err != nil {
		return nil, fmt.Errorf("antiphish display_name fuzzy query: %w", err)
	}
	defer rows.Close()

	var best *match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.name, &m.score); err != nil {
			return nil, fmt.Errorf("antiphish display_name fuzzy scan: %w", err)
		}
		best = &m
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("antiphish display_name fuzzy rows: %w", err)
	}

	if best != nil {
		return &PhishResult{
			Verdict:  PhishWarn,
			Detector: d.Name(),
			Evidence: []string{fmt.Sprintf("display_name_fuzzy_match:%s:%.2f", strings.ToLower(best.name), best.score)},
		}, nil
	}

	return nil, nil
}

// checkFuzzyMemory runs an in-memory trigram comparison against cached names.
// Used in tests where no DB pool is available.
func (d *DisplayNameDetector) checkFuzzyMemory(fromNameLower string) (*PhishResult, error) {
	d.mu.RLock()
	cachedNames := make([]string, 0, len(d.userCache))
	for name := range d.userCache {
		cachedNames = append(cachedNames, name)
	}
	d.mu.RUnlock()

	bestScore := 0.0
	bestName := ""
	for _, cachedName := range cachedNames {
		score := d.similarityInMemory(fromNameLower, cachedName)
		if score > bestScore {
			bestScore = score
			bestName = cachedName
		}
	}

	if bestScore >= d.threshold {
		return &PhishResult{
			Verdict:  PhishWarn,
			Detector: d.Name(),
			Evidence: []string{fmt.Sprintf("display_name_fuzzy_match:%s:%.2f", bestName, bestScore)},
		}, nil
	}

	return nil, nil
}

// similarityInMemory computes string similarity using the custom function
// (set in tests) or falling back to trigram similarity.
func (d *DisplayNameDetector) similarityInMemory(a, b string) float64 {
	if d.similarityFunc != nil {
		return d.similarityFunc(a, b)
	}
	return trigramSimilarity(a, b)
}

// trigramSimilarity computes a character-level trigram similarity score.
// This is a simplified version of pg_trgm's similarity for use in tests
// and as a fallback when the database is unavailable.
func trigramSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	trigramsA := extractTrigrams(a)
	trigramsB := extractTrigrams(b)

	if len(trigramsA) == 0 && len(trigramsB) == 0 {
		return 1.0
	}
	if len(trigramsA) == 0 || len(trigramsB) == 0 {
		return 0.0
	}

	// Count matching trigrams
	set := make(map[string]int, len(trigramsA))
	for _, t := range trigramsA {
		set[t]++
	}

	matches := 0
	for _, t := range trigramsB {
		if count, ok := set[t]; ok && count > 0 {
			matches++
			set[t]--
		}
	}

	return float64(matches) / float64(len(trigramsA)+len(trigramsB)-matches)
}

// extractTrigrams extracts character trigrams from a string.
func extractTrigrams(s string) []string {
	// Pad with two spaces at the front and one at the back (matching pg_trgm behavior)
	padded := "  " + s + " "
	trigrams := make([]string, 0, len(padded)-2)
	for i := 0; i < len(padded)-2; i++ {
		trigrams = append(trigrams, padded[i:i+3])
	}
	return trigrams
}
