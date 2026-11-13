package threat

// med-shard3-023 (THREAT-LOCKOUT-UNCAPPED-SLEEP + THREAT-LOCKOUT-KEY-NORMALIZATION):
// the lockout response is bounded at the tarpit convention (15s), lockout keys
// are case-insensitive, and the SQL escalation growth is capped. This file owns
// the four package tests for those contracts:
//
//  1. TestLockoutStep_ClampsDelayToTarpitCap        — above-cap remainder clamps,
//     sub-cap remainder passes through.
//  2. TestLockout_CaseRotationSharesEscalation      — victim@x.com and
//     Victim@X.com share one escalation counter; case rotation cannot bypass.
//  3. TestLockoutEscalate_CapsAtMaxLevel            — escalation at the max
//     level stops growing and re-arms the capped 8h window.
//  4. TestLockout_RejectedRequestsReleaseWithinCappedWindow — unauthenticated
//     lockout-triggering requests cannot hold connections minutes-to-hours.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// maxLockoutWindowSecs mirrors lockout_escalate's v_max_level cap:
// 900s * 2^5 = 28800s (8h). The Go test asserts the SQL-side cap through the
// production pgxLockoutStore seam.
const maxLockoutWindowSecs = 28800

func lockoutBoundToggles() *toggle.FeatureFlags {
	// SprayDetect is the one enabled control (keeps the pipeline past the
	// all-disabled fast path); the spray step sits AFTER lockout, so a locked
	// identity short-circuits before it and no other DB seam is touched.
	return toggle.NewStatic(map[string]bool{
		toggle.FeatureThreatFeed:  false,
		toggle.FeatureGeoBlock:    false,
		toggle.FeatureSprayDetect: true,
		toggle.FeatureCaptcha:     false,
		toggle.FeatureTarpit:      false,
		toggle.FeatureRateLimit:   false,
	})
}

// TestLockoutStep_ClampsDelayToTarpitCap: a rejected request's advertised delay
// is the capped window. A multi-hour remainder (uncapped exponential
// locked_until) must clamp to maxThreatResponseDelay; a remainder below the cap
// passes through unchanged.
func TestLockoutStep_ClampsDelayToTarpitCap(t *testing.T) {
	ti := &ThreatInterceptor{
		toggles: lockoutBoundToggles(),
		lockout: NewLockoutManager(&fakeLockoutStore{lockedKeys: map[string]time.Duration{
			"user:victim@x.com": 2 * time.Hour, // what uncapped escalation grows into
		}}, nil),
	}

	result, reason, delay := ti.stepLockout(context.Background(),
		&ConnectionMeta{SourceIP: "192.0.2.10", Username: "victim@x.com"})
	if result != ActionReject || reason != "lockout" {
		t.Fatalf("locked identity must reject as lockout; got %v %q", result, reason)
	}
	if delay != maxThreatResponseDelay {
		t.Fatalf("2h remainder must clamp to the %s tarpit cap, got %s", maxThreatResponseDelay, delay)
	}

	// Below the cap the remainder passes through untouched.
	ti.lockout = NewLockoutManager(&fakeLockoutStore{lockedKeys: map[string]time.Duration{
		"user:short@x.com": 10 * time.Second,
	}}, nil)
	_, _, delay = ti.stepLockout(context.Background(),
		&ConnectionMeta{SourceIP: "192.0.2.10", Username: "short@x.com"})
	if delay != 10*time.Second {
		t.Fatalf("sub-cap remainder must pass through unchanged, got %s", delay)
	}
}

// TestLockout_CaseRotationSharesEscalation: the lockout keys are normalized
// case-insensitively (account lookup is lower(email)-based), so spelling
// rotation resolves to the SAME counter — an attacker rotating case across
// attempts cannot reset escalation or bypass an established lockout.
func TestLockout_CaseRotationSharesEscalation(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	const ip = "192.0.2.21"
	user := fmt.Sprintf("case-rotation-%d@test.local", time.Now().UnixNano())
	lower := "user:" + strings.ToLower(user)
	keys := []string{"ip:" + ip, lower, "ip_user:" + ip + ":" + strings.ToLower(user)}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_lockouts WHERE lockout_key = ANY($1)`, keys)
	})

	// Pre-establish the lockout on the NORMALIZED user key.
	if _, err := pool.Exec(ctx,
		`INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until, escalation_level)
		 VALUES ($1, 1, now() + interval '10 minutes', 1)`, lower); err != nil {
		t.Fatalf("seed normalized lockout row: %v", err)
	}

	lm := NewLockoutManager(&pgxLockoutStore{pool: pool}, nil)
	rotated := strings.ToUpper(user)

	// Case rotation cannot bypass the lockout...
	locked, rem := lm.Check(ctx, ConnectionMeta{SourceIP: ip, Username: rotated})
	if !locked || rem <= 0 {
		t.Fatalf("rotated-case spelling must resolve to the normalized lockout; got locked=%v rem=%v", locked, rem)
	}

	// ...and escalating through the rotated spelling bumps the SAME normalized
	// counter instead of opening a fresh per-spelling row.
	lm.Escalate(ctx, ConnectionMeta{SourceIP: ip, Username: rotated})

	var failedCount int
	if err := pool.QueryRow(ctx,
		`SELECT failed_count FROM auth_lockouts WHERE lockout_key = $1`, lower).Scan(&failedCount); err != nil {
		t.Fatalf("read shared normalized counter: %v", err)
	}
	if failedCount != 2 {
		t.Fatalf("rotated-case escalation must bump the shared normalized counter to 2, got %d", failedCount)
	}

	var stray bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM auth_lockouts WHERE lockout_key = $1)`,
		"user:"+rotated).Scan(&stray); err != nil {
		t.Fatalf("probe for stray rotated-case row: %v", err)
	}
	if stray {
		t.Fatal("rotated-case spelling created its own lockout row — key normalization leaked")
	}
}

// TestLockoutEscalate_CapsAtMaxLevel: at the maximum escalation level the level
// stops growing and every further escalation re-arms the capped window
// (900s * 2^5 = 8h) instead of compounding into days.
func TestLockoutEscalate_CapsAtMaxLevel(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	key := fmt.Sprintf("cap:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM auth_lockouts WHERE lockout_key = $1`, key)
	})

	// Seed a row already at the max escalation level with an expired window.
	if _, err := pool.Exec(ctx,
		`INSERT INTO auth_lockouts (lockout_key, failed_count, locked_until, escalation_level)
		 VALUES ($1, 5, now(), 5)`, key); err != nil {
		t.Fatalf("seed max-level lockout row: %v", err)
	}

	store := &pgxLockoutStore{pool: pool}
	for i := 0; i < 3; i++ {
		if err := store.Escalate(ctx, key); err != nil {
			t.Fatalf("escalation %d at max level: %v", i+1, err)
		}

		var level int
		var remainingSecs float64
		if err := pool.QueryRow(ctx,
			`SELECT escalation_level, EXTRACT(EPOCH FROM (locked_until - now()))
			 FROM auth_lockouts WHERE lockout_key = $1`, key).Scan(&level, &remainingSecs); err != nil {
			t.Fatalf("read escalated row: %v", err)
		}
		if level != 5 {
			t.Fatalf("escalation %d: level must stay capped at 5, got %d", i+1, level)
		}
		if remainingSecs <= 0 || remainingSecs > float64(maxLockoutWindowSecs)+5 {
			t.Fatalf("escalation %d: re-armed window must be within the 8h cap, got %.0fs", i+1, remainingSecs)
		}
	}
}

// TestLockout_RejectedRequestsReleaseWithinCappedWindow (availability):
// concurrent unauthenticated lockout-triggering requests, each advertised hours
// of lockout remainder, must all release within the capped window — never
// accumulating minutes-to-hours of held goroutine/connection/buffers per
// identity — and each response must advertise exactly the cap in X-Threat-Delay.
func TestLockout_RejectedRequestsReleaseWithinCappedWindow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	const identities = 6
	locked := &fakeLockoutStore{lockedKeys: map[string]time.Duration{}}
	for i := 0; i < identities; i++ {
		locked.lockedKeys[fmt.Sprintf("user:victim-%d@x.com", i)] = 2 * time.Hour
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM auth_attempts WHERE target_username LIKE 'victim-%@x.com'`)
	})

	ti := &ThreatInterceptor{
		pool:    pool, // the middleware reject path records the attempt via recordAttempt
		toggles: lockoutBoundToggles(),
		lockout: NewLockoutManager(locked, nil),
	}

	reached := false
	handler := ti.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))

	start := time.Now()
	recs := make([]*httptest.ResponseRecorder, identities)
	var wg sync.WaitGroup
	for i := 0; i < identities; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf(`{"email":"victim-%d@x.com","password":"definitely-wrong"}`, i)
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			recs[i] = rec
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	if reached {
		t.Fatal("a locked-out request reached the downstream handler")
	}
	for i, rec := range recs {
		if rec == nil {
			t.Fatalf("identity %d: no response recorded", i)
		}
		if rec.Code != http.StatusForbidden {
			t.Fatalf("identity %d: status = %d, want 403", i, rec.Code)
		}
		if got := rec.Header().Get("X-Threat-Reason"); got != "lockout" {
			t.Fatalf("identity %d: X-Threat-Reason = %q, want lockout", i, got)
		}
		if got := rec.Header().Get("X-Threat-Delay"); got != maxThreatResponseDelay.String() {
			t.Fatalf("identity %d: X-Threat-Delay = %q, want the capped %q", i, got, maxThreatResponseDelay.String())
		}
	}
	// Availability bound: every rejected request released within the cap plus
	// scheduler slop — not the advertised 2h remainder (old behaviour).
	if elapsed > maxThreatResponseDelay+5*time.Second {
		t.Fatalf("%d rejected requests held for %s; all must release within the %s cap (+slop)",
			identities, elapsed, maxThreatResponseDelay)
	}
}
