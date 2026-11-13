package auth_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	sharedauth "setjoin.com/shared/auth"
	"setjoin.com/shared/jwtutil"
)

// happyFake authenticates iff the request carries header X-Test-User.
type happyFake struct{}

func (happyFake) Authenticate(_ context.Context, r *http.Request) (*jwtutil.Claims, error) {
	if u := r.Header.Get("X-Test-User"); u != "" {
		return &jwtutil.Claims{Email: u, Type: jwtutil.TypeAccess}, nil
	}
	return nil, errors.New("no credentials")
}

// scopedFake authenticates only requests classified "valid" via X-Test-Class;
// every other class is rejected. It lets the self-suite exercise the harness's
// deeper credential-verification legs (wrong-type / expired / tampered).
type scopedFake struct{}

func (scopedFake) Authenticate(_ context.Context, r *http.Request) (*jwtutil.Claims, error) {
	if r.Header.Get("X-Test-Class") == "valid" {
		return &jwtutil.Claims{Email: "alice@x", Type: jwtutil.TypeAccess}, nil
	}
	return nil, errors.New("rejected credential")
}

func classRequest(class string) func() *http.Request {
	return func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Test-Class", class)
		return r
	}
}

func TestConformanceHarness(t *testing.T) {
	sharedauth.AuthenticatorConformance(t, func() sharedauth.Authenticator { return happyFake{} },
		sharedauth.ConformanceFixtures{
			ValidRequest: func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("X-Test-User", "alice@x")
				return r
			},
			WantEmail:      "alice@x",
			InvalidRequest: func() *http.Request { r, _ := http.NewRequest(http.MethodGet, "/", nil); return r },
		})
}

// TestConformanceHarnessCredentialLegs exercises the full deep-fixture path:
// an implementation that rejects wrong-type, expired, and tampered credentials
// passes every supplied leg.
func TestConformanceHarnessCredentialLegs(t *testing.T) {
	sharedauth.AuthenticatorConformance(t, func() sharedauth.Authenticator { return scopedFake{} },
		sharedauth.ConformanceFixtures{
			ValidRequest:     classRequest("valid"),
			WantEmail:        "alice@x",
			InvalidRequest:   classRequest("invalid"),
			WrongTypeRequest: classRequest("wrong-type"),
			ExpiredRequest:   classRequest("expired"),
			TamperedRequest:  classRequest("tampered"),
		})
}
