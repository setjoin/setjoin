package jwtutil

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyFreshAAL2AcceptanceAndCanonicalization(t *testing.T) {
	now := time.Date(2026, 8, 13, 3, 0, 0, 0, time.UTC)
	claims := &Claims{
		UserID: 42, JTI: "session", ACR: ACRAAL2,
		AMR:              []string{"future-extension", AMROTP, AMRPassword, AMROTP, "", AMRMultiFactor},
		RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(now.Add(-5 * time.Minute))},
	}
	evidence, err := VerifyFreshAAL2(claims, now, CurrentFreshAAL2Policy())
	if err != nil {
		t.Fatalf("VerifyFreshAAL2() error = %v", err)
	}
	want := []string{"future-extension", AMRMultiFactor, AMROTP, AMRPassword}
	if evidence.UserID != 42 || evidence.JTI != "session" || !evidence.IssuedAt.Equal(now.Add(-5*time.Minute)) ||
		len(evidence.AMR) != len(want) {
		t.Fatalf("evidence = %+v", evidence)
	}
	for i := range want {
		if evidence.AMR[i] != want[i] {
			t.Fatalf("AMR = %v, want %v", evidence.AMR, want)
		}
	}
}

func TestCurrentFreshAAL2Policy(t *testing.T) {
	policy := CurrentFreshAAL2Policy()
	if policy.MaxAge != 5*time.Minute || policy.MaxFutureSkew != 30*time.Second ||
		policy.MaxDistinctAMR != 16 {
		t.Fatalf("current policy = %+v", policy)
	}
	policy.MaxAge = 0
	if CurrentFreshAAL2Policy().MaxAge != 5*time.Minute {
		t.Fatal("caller mutation changed the shared current policy")
	}
}

func TestVerifyFreshAAL2RejectionMatrix(t *testing.T) {
	now := time.Date(2026, 8, 13, 3, 0, 0, 0, time.UTC)
	policy := FreshAAL2Policy{MaxAge: 5 * time.Minute, MaxFutureSkew: 30 * time.Second, MaxDistinctAMR: 4}
	valid := func() *Claims {
		return &Claims{UserID: 1, JTI: "jti", ACR: ACRAAL2,
			AMR:              []string{AMRPassword, AMROTP, AMRMultiFactor},
			RegisteredClaims: jwt.RegisteredClaims{IssuedAt: jwt.NewNumericDate(now)}}
	}
	tests := []struct {
		name   string
		mutate func(*Claims) (*Claims, FreshAAL2Policy)
		want   FreshAAL2Rejection
	}{
		{"invalid policy", func(c *Claims) (*Claims, FreshAAL2Policy) { return c, FreshAAL2Policy{} }, FreshAAL2InvalidPolicy},
		{"nil claims", func(*Claims) (*Claims, FreshAAL2Policy) { return nil, policy }, FreshAAL2Incomplete},
		{"missing subject", func(c *Claims) (*Claims, FreshAAL2Policy) { c.UserID = 0; return c, policy }, FreshAAL2Incomplete},
		{"missing jti", func(c *Claims) (*Claims, FreshAAL2Policy) { c.JTI = ""; return c, policy }, FreshAAL2Incomplete},
		{"wrong acr", func(c *Claims) (*Claims, FreshAAL2Policy) { c.ACR = ACRAAL1; return c, policy }, FreshAAL2WrongACR},
		{"future", func(c *Claims) (*Claims, FreshAAL2Policy) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(31 * time.Second))
			return c, policy
		}, FreshAAL2FromFuture},
		{"expired", func(c *Claims) (*Claims, FreshAAL2Policy) {
			c.IssuedAt = jwt.NewNumericDate(now.Add(-5*time.Minute - time.Second))
			return c, policy
		}, FreshAAL2Expired},
		{"too many unique", func(c *Claims) (*Claims, FreshAAL2Policy) { c.AMR = append(c.AMR, "x", "y"); return c, policy }, FreshAAL2TooManyAMR},
		{"missing marker", func(c *Claims) (*Claims, FreshAAL2Policy) { c.AMR = []string{AMRPassword, AMROTP}; return c, policy }, FreshAAL2MissingMFA},
		{"unknown does not count", func(c *Claims) (*Claims, FreshAAL2Policy) {
			c.AMR = []string{AMRPassword, "x", AMRMultiFactor}
			return c, policy
		}, FreshAAL2FewFactors},
	}
	for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
			claims, selectedPolicy := tt.mutate(valid())
			_, err := VerifyFreshAAL2(claims, now, selectedPolicy)
			if !IsFreshAAL2Rejection(err, tt.want) {
				t.Fatalf("error = %v, want reason %q", err, tt.want)
			}
			var typed *FreshAAL2Error
			if !errors.As(err, &typed) {
				t.Fatalf("error is not typed: %T", err)
			}
			if got, want := err.Error(), "fresh AAL2 rejected: "+string(tt.want); got != want {
				t.Fatalf("error text = %q, want %q", got, want)
			}
		})
	}
}
