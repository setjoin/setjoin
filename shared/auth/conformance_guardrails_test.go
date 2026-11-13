package auth

import (
	"context"
	"net/http"

	"setjoin.com/shared/jwtutil"
	"testing"
)

// Coverage for the conformance harness: a healthy authenticator passes all
// subtests, and nil optional fixtures are skipped without error (the
// harness's t.Fatal guard rails fire only for harness misuse, which is its
// documented behavior).

type conformanceAuthenticator struct{}

func (a *conformanceAuthenticator) Authenticate(_ context.Context, r *http.Request) (*jwtutil.Claims, error) {
	if stringsContainsInvalid(r.Header.Get("Authorization")) {
		return nil, context.Canceled
	}
	return &jwtutil.Claims{Email: "want@example.test"}, nil
}

func stringsContainsInvalid(v string) bool {
	for i := 0; i+7 <= len(v); i++ {
		if v[i:i+7] == "invalid" {
			return true
		}
	}
	return false
}

func headerReq(v string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", v)
	return r
}

// TestAuthenticatorConformancePassesHealthyAuthenticator runs the full
// conformance suite against a well-behaved authenticator. The optional
// deep fixtures (wrong-type/expired/tampered) are left nil, exercising the
// harness's nil-skip branch.
func TestAuthenticatorConformancePassesHealthyAuthenticator(t *testing.T) {
	fx := ConformanceFixtures{
		ValidRequest:   func() *http.Request { return headerReq("Bearer valid") },
		InvalidRequest: func() *http.Request { return headerReq("Bearer invalid") },
		WantEmail:      "want@example.test",
	}
	AuthenticatorConformance(t, func() Authenticator { return &conformanceAuthenticator{} }, fx)
}

// TestAuthenticatorConformanceValidateFixtures pins the fixture-validation
// contract directly: incomplete fixtures are an error before any
// authentication runs.
func TestAuthenticatorConformanceValidateFixtures(t *testing.T) {
	if err := validateFixtures(ConformanceFixtures{}); err == nil {
		t.Fatal("empty fixtures accepted")
	}
	if err := validateFixtures(ConformanceFixtures{
		ValidRequest:   func() *http.Request { return nil },
		InvalidRequest: func() *http.Request { return nil },
	}); err == nil {
		t.Fatal("fixtures without WantEmail accepted")
	}
	if err := validateFixtures(ConformanceFixtures{
		ValidRequest:   func() *http.Request { return nil },
		InvalidRequest: func() *http.Request { return nil },
		WantEmail:      "want@example.test",
	}); err != nil {
		t.Fatalf("complete fixtures rejected: %v", err)
	}
}
