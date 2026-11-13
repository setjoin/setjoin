package threat

// Coverage suite for the changed interceptor lines the pipeline/policy suites
// do not reach: stepThreatFeed's failed-lookup arm (never score on a failed
// query), upsertDevice's full device-registry lifecycle (new device, repeat
// auth_count bump, country change, and the best-effort failure arm), and
// writeThreatResponse's defense-in-depth delay clamp.
//
// Failure injection uses a shadow-schema pool (search_path shadow-first),
// the same pattern the mailserver admin tests use — never production edits.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// threatCovLogger discards log output.
func threatCovLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// threatShadowPool opens a pool whose search_path resolves a freshly created
// shadow schema BEFORE pg_catalog/public, so missing/mismatched shadow tables
// produce deterministic statement failures while unqualified references to
// tables the shadow omits still fall through to public.
func threatShadowPool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	adminPool := testsupport.OpenTestPool(t)
	schema := fmt.Sprintf("threat_cov_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create shadow schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	if setupSQL != "" {
		if _, err := adminPool.Exec(t.Context(), strings.ReplaceAll(setupSQL, "__SCHEMA__", schema)); err != nil {
			t.Fatalf("shadow setup: %v", err)
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DB_DSN: %v", err)
	}
	cfg.MaxConns = 2
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,pg_catalog,public`)
		return err
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open shadow pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestStepThreatFeed_QueryFailureZeroesHits proves stepThreatFeed's
// failed-lookup arm: when the feed query fails (shadow schema has no
// threat_feed_blocks), the step logs, zeroes the hit count — never scoring on
// a failed lookup — and proceeds.
func TestStepThreatFeed_QueryFailureZeroesHits(t *testing.T) {
	// A shadow threat_feed_blocks with a text cidr makes the >>= inet lookup
	// itself fail — an absent table would silently fall through to public.
	shadowPool := threatShadowPool(t, `CREATE TABLE __SCHEMA__.threat_feed_blocks(cidr text);`)
	ti := &ThreatInterceptor{
		pool:    shadowPool,
		toggles: toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true}),
		logger:  threatCovLogger(),
	}
	meta := &ConnectionMeta{SourceIP: "10.99.0.1"}

	result, reason, delay := ti.stepThreatFeed(context.Background(), meta)
	if result != ActionProceed {
		t.Fatalf("failed feed lookup must proceed, got %v (%q, %v)", result, reason, delay)
	}
	if meta.FeedHits != 0 {
		t.Fatalf("FeedHits = %d after a failed lookup, want 0 (never score on a failed lookup)", meta.FeedHits)
	}
}

// TestStepThreatFeed_EnforceRejectsHits pins the final enforcement step: a
// request that survived the pipeline with a positive feed-hit count is
// rejected; zero hits proceed.
func TestStepThreatFeed_EnforceRejectsHits(t *testing.T) {
	ti := &ThreatInterceptor{
		toggles: toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true}),
		logger:  threatCovLogger(),
	}
	result, reason, _ := ti.stepThreatFeedEnforce(context.Background(), &ConnectionMeta{FeedHits: 2})
	if result != ActionReject || reason != "threat_blocked" {
		t.Fatalf("feed hits 2: got (%v, %q), want (reject, threat_blocked)", result, reason)
	}
	result, reason, _ = ti.stepThreatFeedEnforce(context.Background(), &ConnectionMeta{FeedHits: 0})
	if result != ActionProceed {
		t.Fatalf("feed hits 0 must proceed, got %v (%q)", result, reason)
	}
}

// TestUpsertDevice_Lifecycle covers upsertDevice's registry lifecycle against
// the real database: a first auth mints the device_new audit event, a repeat
// bumps auth_count without a new event, a country change mints
// device_country_changed with the from/to metadata, and a failing registry
// (shadow schema) degrades to the best-effort warn — never failing the
// already-successful auth outcome.
func TestUpsertDevice_Lifecycle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	domainID := int64(9_100_000_000) + time.Now().UnixNano()%1_000_000_000
	userID := domainID + 1
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed upsertDevice fixture: %v: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (id, name, is_local) VALUES ($1, $2, TRUE)
	      ON CONFLICT (id) DO NOTHING`, domainID, "threat-cov.test")
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled)
	      VALUES ($1, $2, $3, $4, 'T', TRUE)
	      ON CONFLICT (id) DO NOTHING`,
		userID, "threat_cov_"+suffix, domainID, "threat_cov@threat-cov.test")
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM audit_log WHERE user_id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM device_registry WHERE user_id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	ti := &ThreatInterceptor{pool: pool, logger: threatCovLogger()}
	meta := &ConnectionMeta{SourceIP: "203.0.113.77", UserAgent: "ThreatCov/1", Country: "US"}
	deviceHash := fmt.Sprintf("%x", sha256.Sum256([]byte("ua|203.0.113.0")))

	// 1) First auth: device_new.
	ti.upsertDevice(ctx, meta, "ua|203.0.113.0", userID)
	assertDeviceRegistry(t, pool, userID, deviceHash, 1, "US")
	if got := auditEventCount(t, pool, userID, "device_new"); got != 1 {
		t.Fatalf("device_new audit rows = %d, want 1", got)
	}

	// 2) Repeat auth: auth_count bumps, NO new audit event.
	ti.upsertDevice(ctx, meta, "ua|203.0.113.0", userID)
	assertDeviceRegistry(t, pool, userID, deviceHash, 2, "US")
	if got := auditEventCount(t, pool, userID, "device_new"); got != 1 {
		t.Fatalf("device_new audit rows after repeat = %d, want 1", got)
	}

	// 3) Country change: device_country_changed with from/to metadata.
	meta.Country = "CA"
	ti.upsertDevice(ctx, meta, "ua|203.0.113.0", userID)
	assertDeviceRegistry(t, pool, userID, deviceHash, 3, "CA")
	if got := auditEventCount(t, pool, userID, "device_country_changed"); got != 1 {
		t.Fatalf("device_country_changed audit rows = %d, want 1", got)
	}

	// 4) Failing registry: the warn arm — no panic, outcome unchanged.
	brokenPool := threatShadowPool(t, `
		CREATE TABLE __SCHEMA__.device_registry(user_id bigint, device_hash text);`)
	brokenTI := &ThreatInterceptor{pool: brokenPool, logger: threatCovLogger()}
	brokenTI.upsertDevice(ctx, meta, "ua|203.0.113.0", userID)
}

func assertDeviceRegistry(t *testing.T, pool *pgxpool.Pool, userID int64, deviceHash string, wantAuthCount int, wantCountry string) {
	t.Helper()
	var authCount int
	var country string
	if err := pool.QueryRow(context.Background(),
		`SELECT auth_count, country FROM device_registry WHERE user_id = $1 AND device_hash = $2`,
		userID, deviceHash).Scan(&authCount, &country); err != nil {
		t.Fatalf("device_registry row missing: %v", err)
	}
	if authCount != wantAuthCount {
		t.Errorf("auth_count = %d, want %d", authCount, wantAuthCount)
	}
	if country != wantCountry {
		t.Errorf("country = %q, want %q", country, wantCountry)
	}
}

func auditEventCount(t *testing.T, pool *pgxpool.Pool, userID int64, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE user_id = $1 AND event_type = $2`,
		userID, eventType).Scan(&n); err != nil {
		t.Fatalf("count %s audit rows: %v", eventType, err)
	}
	return n
}

// TestWriteThreatResponse_ClampsExcessDelay proves the defense-in-depth
// clamp: whatever delay a step computed, the response sleeps for — and
// advertises — at most maxThreatResponseDelay.
func TestWriteThreatResponse_ClampsExcessDelay(t *testing.T) {
	rec := httptest.NewRecorder()
	writeThreatResponse(rec, http.StatusTooManyRequests, "tarpit_applied", "Request throttled", "",
		maxThreatResponseDelay+time.Second)

	if got := rec.Header().Get("X-Threat-Delay"); got != "15s" {
		t.Fatalf("X-Threat-Delay = %q, want the 15s clamp", got)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["retry_after"] != float64(15) {
		t.Fatalf("retry_after = %v, want 15", body["retry_after"])
	}
}
