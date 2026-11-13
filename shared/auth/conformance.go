package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// ConformanceFixtures supplies the per-implementation inputs the harness needs.
type ConformanceFixtures struct {
	ValidRequest   func() *http.Request // a request that should authenticate
	WantEmail      string               // expected Claims.Email for ValidRequest (REQUIRED — identity binding is part of the contract)
	InvalidRequest func() *http.Request // a request that should NOT authenticate

	// Optional deeper credential-verification fixtures (conformance-gap
	// hardening). When supplied, the harness asserts the corresponding leg of
	// the credential contract; nil legs are skipped (an implementation with no
	// such credential class has nothing to assert).
	WrongTypeRequest func() *http.Request // a credential of the WRONG token type (e.g. refresh presented as access) — must NOT authenticate
	ExpiredRequest   func() *http.Request // a credential past its lifetime — must NOT authenticate
	TamperedRequest  func() *http.Request // a credential whose signature does not cover its claims (tampered) — must NOT authenticate
}

// validateFixtures reports fixture-set problems before any subtest runs, so an
// incomplete fixture set fails loudly instead of silently skipping a contract
// leg (the old empty-WantEmail sentinel let implementations skip asserting WHO
// authenticated).
func validateFixtures(fx ConformanceFixtures) error {
	if fx.ValidRequest == nil || fx.InvalidRequest == nil {
		return errors.New("conformance fixtures must supply ValidRequest and InvalidRequest")
	}
	if fx.WantEmail == "" {
		return errors.New("conformance fixtures must pin WantEmail (identity binding)")
	}
	return nil
}

// AuthenticatorConformance asserts that any Authenticator honours the contract:
// valid creds -> (non-nil Claims, nil err) with the expected identity; invalid
// creds -> (nil/zero, non-nil err); and — when the deeper fixtures are
// supplied — wrong-type, expired, and tampered credentials are all rejected.
// Every service implementing Authenticator must pass this.
func AuthenticatorConformance(t *testing.T, factory func() Authenticator, fx ConformanceFixtures) {
	t.Helper()
	if err := validateFixtures(fx); err != nil {
		t.Fatal(err)
	}
	t.Run("valid request authenticates", func(t *testing.T) {
		a := factory()
		claims, err := a.Authenticate(context.Background(), fx.ValidRequest())
		if err != nil {
			t.Fatalf("valid request: unexpected error %v", err)
		}
		if claims == nil {
			t.Fatal("valid request: nil claims")
		}
		if claims.Email != fx.WantEmail {
			t.Fatalf("valid request: Email = %q, want %q", claims.Email, fx.WantEmail)
		}
	})
	t.Run("invalid request rejected", func(t *testing.T) {
		a := factory()
		claims, err := a.Authenticate(context.Background(), fx.InvalidRequest())
		if err == nil {
			t.Fatal("invalid request: expected error, got nil")
		}
		if claims != nil {
			t.Fatalf("invalid request: expected nil claims, got %+v", claims)
		}
	})
	rejects := func(name string, f func() *http.Request) {
		if f == nil {
			return
		}
		t.Run(name, func(t *testing.T) {
			a := factory()
			claims, err := a.Authenticate(context.Background(), f())
			if err == nil {
				t.Fatalf("%s: expected error, got nil", name)
			}
			if claims != nil {
				t.Fatalf("%s: expected nil claims, got %+v", name, claims)
			}
		})
	}
	rejects("wrong-type credential rejected", fx.WrongTypeRequest)
	rejects("expired credential rejected", fx.ExpiredRequest)
	rejects("tampered credential rejected", fx.TamperedRequest)
}
