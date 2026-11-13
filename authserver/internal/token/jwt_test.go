package token

import (
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
)

func TestIssuePasswordReset(t *testing.T) {
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	tokenStr, err := p.IssuePasswordReset(42, "user@example.com")
	if err != nil {
		t.Fatalf("IssuePasswordReset failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token string")
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if claims.Type != TypePasswordReset {
		t.Errorf("expected token type %q, got %q", TypePasswordReset, claims.Type)
	}
	if claims.UserID != 42 {
		t.Errorf("expected UserID 42, got %d", claims.UserID)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected Email user@example.com, got %s", claims.Email)
	}
	if claims.JTI == "" {
		t.Error("expected non-empty JTI")
	}

	// Verify 5-minute expiry
	now := time.Now()
	exp := claims.ExpiresAt.Time
	if exp.Before(now) {
		t.Error("token already expired at issue time")
	}
	if exp.After(now.Add(6 * time.Minute)) {
		t.Errorf("expected expiry within 5 minutes, got %v from now", exp.Sub(now))
	}
}

func TestIssueAccessWithDevice(t *testing.T) {
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	device := &jwtutil.DeviceClaim{
		ID:               "d_781",
		Platform:         "iOS",
		TrustTier:        jwtutil.TrustTierTrusted,
		ComplianceStatus: jwtutil.ComplianceOK,
	}
	mam := &jwtutil.MAMClaim{
		PolicyVersion:       7,
		CopyPaste:           "block_external",
		Encryption:          "required",
		NotificationProfile: jwtutil.NotificationPush,
	}
	risk := &jwtutil.RiskClaim{
		UserScore: 5,
	}

	tokenStr, err := p.IssueAccessWithDevice(42, "user@example.com", false, device, mam, risk, nil)
	if err != nil {
		t.Fatalf("IssueAccessWithDevice failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if claims.Device == nil {
		t.Fatal("expected non-nil Device claim")
	}
	if claims.Device.ID != "d_781" {
		t.Errorf("Device.ID = %q, want d_781", claims.Device.ID)
	}
	if claims.Device.TrustTier != jwtutil.TrustTierTrusted {
		t.Errorf("Device.TrustTier = %q, want trusted", claims.Device.TrustTier)
	}
	if claims.MAM == nil {
		t.Fatal("expected non-nil MAM claim")
	}
	if claims.MAM.PolicyVersion != 7 {
		t.Errorf("MAM.PolicyVersion = %d, want 7", claims.MAM.PolicyVersion)
	}
	if claims.Risk == nil {
		t.Fatal("expected non-nil Risk claim")
	}
	if claims.Risk.UserScore != 5 {
		t.Errorf("Risk.UserScore = %d, want 5", claims.Risk.UserScore)
	}
}

func TestIssueAccessWithoutDevice_BackwardCompat(t *testing.T) {
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileStandard,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess failed: %v", err)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	if claims.Device != nil {
		t.Error("expected nil Device claim for legacy IssueAccess")
	}
	if claims.MAM != nil {
		t.Error("expected nil MAM claim for legacy IssueAccess")
	}
}
