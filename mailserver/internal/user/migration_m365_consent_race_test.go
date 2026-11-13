package user

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
)

// The race test in this file pins the EXACTLY-ONE-WINNER property of the M365
// consent callback consumption (med-shard2-023 / D-MAILSERVER-INTERNAL-USER-F-002):
// two concurrent callbacks for the SAME live consent state — through the real
// handler, the real RunUserScoped seam, and the real m365_consent_state_consume
// reducer — must produce exactly one completed consent and one rejection. The
// guarded single-statement UPDATE in the reducer arbitrates: the winner commits
// consumed_at; the loser's predicate re-evaluates against the updated row,
// matches nothing, and gets the existing "invalid or expired state" rejection.

// raceM365Callback is postM365Callback without any testing.T use, so it is
// safe to call from non-test goroutines.
func raceM365Callback(h *MigrationHandler, claims *auth.Claims, state string) *httptest.ResponseRecorder {
	target := "/admin/migration/m365/callback?admin_consent=True&tenant=" + m365TestTenant + "&state=" + state
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.AddCookie(&http.Cookie{Name: "m365_oauth_state", Value: state})
	rec := httptest.NewRecorder()
	h.M365Callback(rec, req)
	return rec
}

// TestM365Callback_ConcurrentSameStateExactlyOneWinner drives two goroutines
// through a barrier into the same live consent state. Exactly one callback
// wins (302, tenant persisted, audit row written, one verification run); the
// loser is rejected 400 before any verification or persistence, and the
// single-use state is consumed exactly once.
func TestM365Callback_ConcurrentSameStateExactlyOneWinner(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)
	claims := consentTestClaims(adminID, true)

	var verifyCalls atomic.Int64
	h.verifyM365Tenant = func(ctx context.Context, cfg migration.MigrationM365Config) error {
		verifyCalls.Add(1)
		return nil
	}

	state := insertM365ConsentState(t, pool, adminID, "race-consent-state-0007", false, false)

	const racers = 2
	start := make(chan struct{}) // barrier: released once both goroutines are parked
	type outcome struct {
		code int
		body string
	}
	outcomes := make([]outcome, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec := raceM365Callback(h, claims, state)
			outcomes[i] = outcome{code: rec.Code, body: rec.Body.String()}
		}(i)
	}
	close(start)
	wg.Wait()

	// Exactly one winner with the existing success redirect; exactly one
	// loser with the existing rejection.
	winners, losers := 0, 0
	for _, o := range outcomes {
		switch o.code {
		case http.StatusFound:
			winners++
		case http.StatusBadRequest:
			losers++
		default:
			t.Fatalf("unexpected callback status %d (want only 302/400): %s", o.code, o.body)
		}
	}
	if winners != 1 || losers != 1 {
		t.Fatalf("concurrent same-state callbacks: %d winners / %d losers, want exactly 1/1 (outcomes: %+v)",
			winners, losers, outcomes)
	}

	// The winner alone reached verification — the loser was rejected server-side
	// before it, and neither re-verified nor double-wrote.
	if got := verifyCalls.Load(); got != 1 {
		t.Fatalf("tenant verification ran %d times across concurrent callbacks, want exactly 1", got)
	}

	// Single use: consumed exactly once (one row, consumed_at set).
	if !consentStateConsumed(t, pool, state) {
		t.Fatalf("concurrent callbacks did not consume the consent state")
	}
	if n := m365ConsentAuditCount(t, pool, adminID); n != 1 {
		t.Fatalf("completion audit rows after concurrent callbacks = %d, want exactly 1", n)
	}

	// The persisted binding comes from exactly one completion: tenant + the
	// minted cloud.
	cfg := storedM365Config(t, h, pool)
	if cfg.TenantID != m365TestTenant {
		t.Fatalf("persisted TenantID = %q, want %q", cfg.TenantID, m365TestTenant)
	}
	if cfg.Cloud != "global" {
		t.Fatalf("persisted Cloud = %q, want the consent row's cloud \"global\"", cfg.Cloud)
	}
}
