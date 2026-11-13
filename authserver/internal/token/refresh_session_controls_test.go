package token

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/jwtutil"
)

func TestRefreshPreservesDeviceAndSignInFrequencyFamilyContext(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set; skipping refresh session-control integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	var domainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains LIMIT 1`).Scan(&domainID); err != nil {
		t.Skipf("no domain in test DB: %v", err)
	}

	const (
		userID = int64(999_991)
		email  = "dbtest-refresh-controls@example.com"
	)
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id,username,domain_id,email,display_name,enabled)
		 VALUES ($1,'dbtest-refresh-controls',$2,$3,'DB Test Refresh Controls',TRUE)
		 ON CONFLICT (id) DO UPDATE SET enabled=TRUE`,
		userID, domainID, email,
	); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM oauth_tokens WHERE user_id=$1`, userID) //nolint:errcheck
		pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)             //nolint:errcheck
	})

	provider := newTestProvider(t)
	family := uuid.NewString()
	sif := int64(3600)
	authTime := time.Now().Add(-30 * time.Minute).Unix()
	device := &jwtutil.DeviceClaim{
		ID:               "managed-device-1",
		Platform:         "macos",
		TrustTier:        "quarantined",
		ComplianceStatus: "jailbroken",
		WipeRequested:    true,
	}
	refresh, err := provider.IssueRefreshWithFamilySession(
		userID, email, family, nil, device, &sif, &authTime,
	)
	if err != nil {
		t.Fatalf("issue refresh: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id)
		 VALUES ($1,$2,'refresh',now()+interval '30 days',$3::uuid)`,
		userID, tokenHash(refresh), family,
	); err != nil {
		t.Fatalf("seed refresh anchor: %v", err)
	}

	for hop := 1; hop <= 2; hop++ {
		result, err := RefreshTokens(ctx, pool, provider, nil, refresh)
		if err != nil {
			t.Fatalf("refresh hop %d: %v", hop, err)
		}
		accessClaims, err := provider.Validate(result.AccessToken)
		if err != nil {
			t.Fatalf("validate access hop %d: %v", hop, err)
		}
		assertSessionControls(t, hop, accessClaims, device, sif, authTime)

		refreshClaims, err := provider.Validate(result.RefreshToken)
		if err != nil {
			t.Fatalf("validate refresh hop %d: %v", hop, err)
		}
		assertSessionControls(t, hop, refreshClaims, device, sif, authTime)
		refresh = result.RefreshToken
	}
}

func assertSessionControls(
	t *testing.T,
	hop int,
	claims *Claims,
	wantDevice *jwtutil.DeviceClaim,
	wantSIF, wantAuthTime int64,
) {
	t.Helper()
	if claims.Device == nil ||
		claims.Device.ID != wantDevice.ID ||
		claims.Device.TrustTier != wantDevice.TrustTier ||
		claims.Device.ComplianceStatus != wantDevice.ComplianceStatus ||
		claims.Device.WipeRequested != wantDevice.WipeRequested {
		t.Fatalf("hop %d dropped or changed device security claim: %+v", hop, claims.Device)
	}
	if claims.SignInFreq == nil || *claims.SignInFreq != wantSIF {
		t.Fatalf("hop %d SIF=%v, want %d", hop, claims.SignInFreq, wantSIF)
	}
	if claims.SessionAuthTime == nil || *claims.SessionAuthTime != wantAuthTime {
		t.Fatalf("hop %d auth_time=%v, want immutable %d", hop, claims.SessionAuthTime, wantAuthTime)
	}
}
