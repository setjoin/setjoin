package threat

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// allTogglesOff returns flags with every pre-auth control disabled. With these
// and a nil policyEngine, intercept() short-circuits to ActionProceed (no pre-auth
// DB queries), so the ONLY DB write the middleware makes is the post-auth
// auth_attempts INSERT in recordOutcome — exactly the row this test pins.
func allTogglesOff() *toggle.FeatureFlags {
	return toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  false,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: false,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   false,
	})
}

// ensureCurrentAuthAttemptsPartition creates the auth_attempts partition
// covering now() if it doesn't already exist. The collapsed test baseline
// seeds only one historical month; in production create_monthly_partitions()
// (boot + cron) creates the current month. Shared by every DB-backed test in
// this package that writes to auth_attempts directly via the middleware.
// ponytail: shared schema infra, NOT dropped in cleanup — production keeps it
// and dropping it could break a concurrent sibling mid-insert; only rows are
// cleaned up by each caller.
func ensureCurrentAuthAttemptsPartition(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
DO $$
DECLARE
  v_name  TEXT := 'auth_attempts_' || to_char(date_trunc('month', now()), 'YYYY_MM');
  v_start TEXT := to_char(date_trunc('month', now()), 'YYYY-MM-DD');
  v_end   TEXT := to_char(date_trunc('month', now()) + INTERVAL '1 month', 'YYYY-MM-DD');
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = v_name) THEN
    BEGIN
      EXECUTE format('CREATE TABLE %I PARTITION OF auth_attempts FOR VALUES FROM (%L) TO (%L)',
                     v_name, v_start, v_end);
    EXCEPTION WHEN OTHERS THEN
      -- A concurrent sibling test won the race; the partition now exists.
      NULL;
    END;
  END IF;
END $$;`); err != nil {
		t.Fatalf("ensure current auth_attempts partition: %v", err)
	}
}

// TestMiddleware_FailedLogin_WritesOneAuthAttemptsRow drives the real authserver
// failed-auth handler (the threat Middleware) against a live DB: a 401 from the
// wrapped login handler must write exactly one auth_attempts row with
// outcome='failure', and a 200 must write outcome='success'. Asserts the actual
// columns the recordOutcome INSERT populates.
func TestMiddleware_FailedLogin_WritesOneAuthAttemptsRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	ensureCurrentAuthAttemptsPartition(t, ctx, pool)

	// Namespaced fixtures (high host octet + test-specific prefix) so concurrent
	// sibling runs don't collide.
	const srcIP = "198.51.100.231" // TEST-NET-2
	const userFail = "authattempt-fail-980001@auth-attempts.test"
	const userOK = "authattempt-ok-980002@auth-attempts.test"
	const userAgent = "auth-attempts-test-agent/1.0"

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`DELETE FROM auth_attempts WHERE source_ip = $1::INET AND target_username IN ($2, $3)`,
			srcIP, userFail, userOK)
	})

	// The real handler: live pool, all controls off (fast-path proceed), nil lockout
	// and nil siPool so recordOutcome's ONLY write is the auth_attempts INSERT (no
	// login_events mirror, no device registry).
	ti := &ThreatInterceptor{
		pool:    pool,
		toggles: allTogglesOff(),
	}

	// post sends one login through the middleware; the wrapped handler returns
	// `status` (401 = failed login, 200 = success).
	post := func(username string, status int) {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
		})
		body := fmt.Sprintf(`{"email":%q,"password":"wrong"}`, username)
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
		req.RemoteAddr = srcIP + ":54321"
		req.Header.Set("User-Agent", userAgent)
		ti.Middleware(next).ServeHTTP(httptest.NewRecorder(), req)
	}

	wantFP := userAgent + "|" + MaskIP(srcIP) // "...|198.51.100.0"

	// ---- Failed login (401) -> exactly one row, outcome='failure'.
	post(userFail, http.StatusUnauthorized)

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM auth_attempts WHERE source_ip = $1::INET AND target_username = $2`,
		srcIP, userFail).Scan(&count); err != nil {
		t.Fatalf("count failed-login rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("failed login must write exactly one auth_attempts row, got %d", count)
	}

	var (
		outcome, protocol, devFP, srcStr, geo string
		failureReason                         *string
	)
	if err := pool.QueryRow(ctx,
		`SELECT outcome, protocol, device_fingerprint, host(source_ip), geo_country, failure_reason
		   FROM auth_attempts WHERE source_ip = $1::INET AND target_username = $2`,
		srcIP, userFail).Scan(&outcome, &protocol, &devFP, &srcStr, &geo, &failureReason); err != nil {
		t.Fatalf("read failed-login row: %v", err)
	}
	if outcome != "failure" {
		t.Errorf("outcome = %q, want \"failure\"", outcome)
	}
	if protocol != ProtocolHTTP {
		t.Errorf("protocol = %q, want %q", protocol, ProtocolHTTP)
	}
	if devFP != wantFP {
		t.Errorf("device_fingerprint = %q, want %q (UA|maskedIP)", devFP, wantFP)
	}
	if srcStr != srcIP {
		t.Errorf("source_ip = %q, want %q", srcStr, srcIP)
	}
	// geoip is unconfigured in the test, so the handler records an empty country.
	if geo != "" {
		t.Errorf("geo_country = %q, want \"\" (no geoip reader)", geo)
	}
	// recordOutcome never populates failure_reason — it lives only on the pre-auth
	// reject path's outcome column. The real failed-login row leaves it NULL.
	if failureReason != nil {
		t.Errorf("failure_reason = %q, want NULL (recordOutcome does not set it)", *failureReason)
	}

	// ---- Mutation/contrast: successful login (200) -> exactly one row, outcome='success'.
	post(userOK, http.StatusOK)

	var okCount int
	var okOutcome string
	if err := pool.QueryRow(ctx,
		`SELECT count(*), max(outcome) FROM auth_attempts WHERE source_ip = $1::INET AND target_username = $2`,
		srcIP, userOK).Scan(&okCount, &okOutcome); err != nil {
		t.Fatalf("read success row: %v", err)
	}
	if okCount != 1 {
		t.Fatalf("successful login must write exactly one auth_attempts row, got %d", okCount)
	}
	if okOutcome != "success" {
		t.Errorf("successful login outcome = %q, want \"success\"", okOutcome)
	}
}
