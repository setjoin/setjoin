package handlers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

func TestRiskClaimForReadsThroughUserScope(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	email := fmt.Sprintf("risk-claim-%d@go-tests.local", time.Now().UnixNano())

	var userID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO users (username, email, display_name, domain_id, sync_source, enabled)
		SELECT $1, $1, 'Risk Claim Test', id, 'local', TRUE
		FROM domains
		WHERE is_local = TRUE
		ORDER BY id
		LIMIT 1
		RETURNING id`, email).Scan(&userID)
	if err != nil {
		t.Fatalf("seed risk-claim user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID) })

	_, err = pool.Exec(ctx, `
		INSERT INTO user_risk (user_id, score, level, signals)
		VALUES ($1, 73, 'medium', '["impossible_travel","failed_auth_velocity"]'::jsonb)`, userID)
	if err != nil {
		t.Fatalf("seed user risk: %v", err)
	}

	h := &deps{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{toggle.FeatureUserRisk: true}),
	}
	claim := h.riskClaimFor(ctx, userID)
	if claim == nil {
		t.Fatal("riskClaimFor returned nil for an enabled elevated-risk user")
	}
	if claim.UserScore != 73 || claim.Level != "medium" || !claim.RequiresMFA {
		t.Fatalf("risk claim = %+v, want score=73 level=medium requiresMFA=true", claim)
	}
	if len(claim.Signals) != 2 || claim.Signals[0] != "impossible_travel" || claim.Signals[1] != "failed_auth_velocity" {
		t.Fatalf("risk signals = %v, want reducer order preserved", claim.Signals)
	}
}
