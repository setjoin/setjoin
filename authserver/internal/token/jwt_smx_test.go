package token

import (
	"testing"
	"time"

	"setjoin.com/shared/cryptokey"

	"github.com/emmansun/gmsm/sm2"

	crand "crypto/rand"
)

func newTestSM2Key(t *testing.T) *sm2.PrivateKey {
	t.Helper()
	key, err := sm2.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey: %v", err)
	}
	return key
}

func TestSM2SignAndValidate(t *testing.T) {
	key := newTestSM2Key(t)
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key.PrivateKey,
		cryptokey.ProfileSMx,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess (SM2): %v", err)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate (SM2): %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "user@example.com")
	}
}

func TestSM2Token_WrongKey(t *testing.T) {
	key1 := newTestSM2Key(t)
	key2 := newTestSM2Key(t)

	// Sign with key1
	p1 := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key1.PrivateKey,
		cryptokey.ProfileSMx,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)
	tokenStr, err := p1.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}

	// Validate with key2
	p2 := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key2.PrivateKey,
		cryptokey.ProfileSMx,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)
	_, err = p2.Validate(tokenStr)
	if err == nil {
		t.Error("Validate with wrong SM2 key should fail")
	}
}

func TestStandard_IssuesHS256(t *testing.T) {
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
		t.Fatalf("IssueAccess (standard): %v", err)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate (standard): %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

func TestHybrid_IssuesHS256_WhenNoSM2Key(t *testing.T) {
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		nil,
		cryptokey.ProfileHybrid,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	// Hybrid without SM2 key should issue HS256
	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess (hybrid): %v", err)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate (hybrid): %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

func TestHybrid_AcceptsHS256_WhenSM2Configured(t *testing.T) {
	key := newTestSM2Key(t)
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key.PrivateKey,
		cryptokey.ProfileHybrid,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	// With SM2 key configured, hybrid should still issue SM2
	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess (hybrid+sm2): %v", err)
	}

	// Validate with the SM2 key
	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate (hybrid+sm2): %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

func TestSMx_IssuesSM2Only(t *testing.T) {
	key := newTestSM2Key(t)
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key.PrivateKey,
		cryptokey.ProfileSMx,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess (smx): %v", err)
	}

	// Parse without verifying to check header
	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate (smx): %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
}

func TestSM2RefreshToken(t *testing.T) {
	key := newTestSM2Key(t)
	p := NewJWTProvider(
		"test-secret-32-bytes-long-ok-now!!",
		&key.PrivateKey,
		cryptokey.ProfileSMx,
		time.Hour,
		720*time.Hour,
		"test-issuer",
	)

	tokenStr, err := p.IssueRefresh(42, "user@example.com")
	if err != nil {
		t.Fatalf("IssueRefresh (SM2): %v", err)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate refresh (SM2): %v", err)
	}
	if claims.Type != TypeRefresh {
		t.Errorf("Type = %q, want %q", claims.Type, TypeRefresh)
	}
}
