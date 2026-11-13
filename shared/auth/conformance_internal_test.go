package auth

import (
	"net/http"
	"testing"
)

func reqFixture() func() *http.Request {
	return func() *http.Request { r, _ := http.NewRequest(http.MethodGet, "/", nil); return r }
}

// TestValidateFixturesRequiresIdentityBinding asserts the harness fails closed
// on an incomplete fixture set: identity binding (WantEmail) is mandatory, not
// an optional assertion an implementation can skip.
func TestValidateFixturesRequiresIdentityBinding(t *testing.T) {
	err := validateFixtures(ConformanceFixtures{
		ValidRequest:   reqFixture(),
		WantEmail:      "", // WHO authenticated unasserted — must be rejected
		InvalidRequest: reqFixture(),
	})
	if err == nil {
		t.Fatal("expected identity-binding validation error, got nil")
	}
}

// TestValidateFixturesRequiresRequestFixtures asserts both request fixtures are
// mandatory.
func TestValidateFixturesRequiresRequestFixtures(t *testing.T) {
	if err := validateFixtures(ConformanceFixtures{WantEmail: "a@x"}); err == nil {
		t.Fatal("expected missing-fixture validation error, got nil")
	}
	err := validateFixtures(ConformanceFixtures{
		ValidRequest: reqFixture(),
		WantEmail:    "a@x",
		// InvalidRequest nil
	})
	if err == nil {
		t.Fatal("expected nil InvalidRequest validation error, got nil")
	}
}

// TestValidateFixturesAcceptsCompleteSet asserts a complete fixture set passes.
func TestValidateFixturesAcceptsCompleteSet(t *testing.T) {
	if err := validateFixtures(ConformanceFixtures{
		ValidRequest:     reqFixture(),
		WantEmail:        "a@x",
		InvalidRequest:   reqFixture(),
		WrongTypeRequest: reqFixture(),
		ExpiredRequest:   reqFixture(),
		TamperedRequest:  reqFixture(),
	}); err != nil {
		t.Fatalf("complete fixtures rejected: %v", err)
	}
}
