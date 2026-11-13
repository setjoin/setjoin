package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"setjoin.com/shared/jwtutil"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRequireDeviceCompliance_AllowsTrusted(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return &jwtutil.Claims{
			UserID: 1, Email: "user@example.com", Type: jwtutil.TypeAccess,
			Device: &jwtutil.DeviceClaim{
				ID: "d_1", TrustTier: jwtutil.TrustTierTrusted, ComplianceStatus: jwtutil.ComplianceOK,
			},
		}
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireDeviceCompliance_AllowsCompliant(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return &jwtutil.Claims{
			UserID: 1, Email: "user@example.com", Type: jwtutil.TypeAccess,
			Device: &jwtutil.DeviceClaim{
				ID: "d_2", TrustTier: jwtutil.TrustTierCompliant,
			},
		}
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for compliant device, got %d", rec.Code)
	}
}

func TestRequireDeviceCompliance_BlocksQuarantined(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return &jwtutil.Claims{
			UserID: 1, Email: "user@example.com", Type: jwtutil.TypeAccess,
			Device: &jwtutil.DeviceClaim{
				ID: "d_3", TrustTier: jwtutil.TrustTierQuarantined,
			},
		}
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for quarantined device")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for quarantined device, got %d", rec.Code)
	}
}

func TestRequireDeviceCompliance_BlocksWipeRequested(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return &jwtutil.Claims{
			UserID: 1, Email: "user@example.com", Type: jwtutil.TypeAccess,
			Device: &jwtutil.DeviceClaim{
				ID: "d_4", TrustTier: jwtutil.TrustTierTrusted, WipeRequested: true,
			},
		}
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for wiped device")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wiped device, got %d", rec.Code)
	}
}

func TestRequireDeviceCompliance_BlocksNoDeviceClaim(t *testing.T) {
	// Fail-closed contract: a claim-less (nil Device) token carries no
	// verifiable wipe/quarantine state, so a wiped or quarantined device
	// riding such a token must be blocked, not waved through. With the bare
	// constructor (empty legacy policy) EVERY claim-less token is blocked
	// while enforcement is active.
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return &jwtutil.Claims{
			UserID: 1, Email: "user@example.com", Type: jwtutil.TypeAccess,
			// No Device field set — nil pointer
		}
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called for a claim-less token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 when no device claim present, got %d", rec.Code)
	}
}

// legacyPolicyClock is the fixed clock seam for cutoff simulation.
var legacyPolicyClock = time.Unix(1_800_000_000, 0)

// claimLessAccess returns claim-less access-token claims, optionally carrying
// refresh-rotation markers (fresh IssuedAt + refresh-family id).
func claimLessAccess(issuedAt *time.Time, familyID string) *jwtutil.Claims {
	c := &jwtutil.Claims{
		UserID: 7, Email: "legacy@example.com", Type: jwtutil.TypeAccess,
		FamilyID: familyID,
	}
	if issuedAt != nil {
		c.IssuedAt = jwtutil.NewNumericDate(*issuedAt)
	}
	return c
}

// TestRequireDeviceCompliance_NilClaims is the regression guard for the
// nil-claims 401 path: it must stay exactly as it was after the claim-less
// fail-closed change.
func TestRequireDeviceCompliance_NilClaims_Unchanged(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims {
		return nil
	}

	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called with nil claims")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nil claims, got %d", rec.Code)
	}
}

// TestRequireDeviceCompliance_PerClassCutoff simulates across each legacy
// token class's contracted deadline: a class passes strictly before its
// cutoff, is retired at and after it, and each class's deadline is evaluated
// independently. A token matching no class is blocked even mid-window.
func TestRequireDeviceCompliance_PerClassCutoff(t *testing.T) {
	cutoffA := legacyPolicyClock.Add(24 * time.Hour) // class A retires first
	cutoffB := legacyPolicyClock.Add(48 * time.Hour) // class B outlives it

	classes := []LegacyTokenClass{
		{
			Name:   "pre-enrollment-access",
			Match:  func(c *jwtutil.Claims) bool { return c.Type == jwtutil.TypeAccess },
			Cutoff: cutoffA,
		},
		{
			Name:   "legacy-issuer-signed",
			Match:  func(c *jwtutil.Claims) bool { return c.Type == jwtutil.TypeMFAPending },
			Cutoff: cutoffB,
		},
	}

	claimsFor := func(typ jwtutil.TokenType) *jwtutil.Claims {
		return &jwtutil.Claims{UserID: 7, Type: typ}
	}

	tests := []struct {
		name string
		now  time.Time
		typ  jwtutil.TokenType
		want int
	}{
		{"class A before its cutoff", legacyPolicyClock, jwtutil.TypeAccess, http.StatusOK},
		{"class A one nanosecond before cutoff", cutoffA.Add(-time.Nanosecond), jwtutil.TypeAccess, http.StatusOK},
		{"class A retired exactly at cutoff (inclusive)", cutoffA, jwtutil.TypeAccess, http.StatusForbidden},
		{"class A retired after cutoff", cutoffA.Add(time.Hour), jwtutil.TypeAccess, http.StatusForbidden},
		{"class B still in window after A retired", cutoffA.Add(time.Hour), jwtutil.TypeMFAPending, http.StatusOK},
		{"class B retired exactly at cutoff (inclusive)", cutoffB, jwtutil.TypeMFAPending, http.StatusForbidden},
		{"class B retired after cutoff", cutoffB.Add(time.Hour), jwtutil.TypeMFAPending, http.StatusForbidden},
		{"no matching class blocked mid-window", legacyPolicyClock, jwtutil.TypeRefresh, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &LegacyTokenPolicy{Classes: classes, Now: func() time.Time { return tc.now }}
			handler := RequireDeviceComplianceWithLegacyPolicy(
				func(r *http.Request) *jwtutil.Claims { return claimsFor(tc.typ) },
				p, testLogger(),
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != tc.want {
				t.Errorf("got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// TestRequireDeviceCompliance_LegacyClassZeroCutoffFailsClosed pins the
// misconfiguration posture: an inventoried class with no explicit deadline is
// never allowed.
func TestRequireDeviceCompliance_LegacyClassZeroCutoffFailsClosed(t *testing.T) {
	policy := &LegacyTokenPolicy{
		Classes: []LegacyTokenClass{
			{
				Name:  "deadline-less-class",
				Match: func(c *jwtutil.Claims) bool { return c.Type == jwtutil.TypeAccess },
				// Cutoff deliberately zero.
			},
		},
		Now: func() time.Time { return legacyPolicyClock },
	}

	handler := RequireDeviceComplianceWithLegacyPolicy(
		func(r *http.Request) *jwtutil.Claims { return claimLessAccess(nil, "") },
		policy, testLogger(),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler must not be called for a class without an explicit cutoff")
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for zero-cutoff legacy class, got %d", rec.Code)
	}
}

// TestRequireDeviceCompliance_RefreshRotationDoesNotRetireLegacyClass pins the
// contract that refresh rotation alone never removes a legacy class from
// enforcement: a freshly rotated claim-less token (new IssuedAt, refresh-family
// id) gets no exemption — it passes exactly when the un-rotated token passes,
// and both are blocked at the contracted cutoff regardless of rotation.
func TestRequireDeviceCompliance_RefreshRotationDoesNotRetireLegacyClass(t *testing.T) {
	cutoff := legacyPolicyClock.Add(24 * time.Hour)
	policyFor := func(now time.Time) *LegacyTokenPolicy {
		return &LegacyTokenPolicy{
			Classes: []LegacyTokenClass{
				{
					Name:   "pre-enrollment-access",
					Match:  func(c *jwtutil.Claims) bool { return c.Type == jwtutil.TypeAccess },
					Cutoff: cutoff,
				},
			},
			Now: func() time.Time { return now },
		}
	}

	oldIssued := legacyPolicyClock.Add(-720 * time.Hour) // legacy mint long ago
	rotatedIssued := legacyPolicyClock                   // refreshed just now
	preCutoff := []struct {
		name   string
		claims *jwtutil.Claims
	}{
		{"un-rotated legacy token", claimLessAccess(&oldIssued, "")},
		{"freshly rotated token", claimLessAccess(&rotatedIssued, "fam_1")},
	}
	for _, tc := range preCutoff {
		t.Run("in window passes: "+tc.name, func(t *testing.T) {
			handler := RequireDeviceComplianceWithLegacyPolicy(
				func(r *http.Request) *jwtutil.Claims { return tc.claims },
				policyFor(legacyPolicyClock), testLogger(),
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("got %d, want 200 — rotation must not narrow the contracted window", rec.Code)
			}
		})
	}

	rotatedAfterCutoff := cutoff.Add(time.Minute)
	postCutoff := []struct {
		name   string
		claims *jwtutil.Claims
	}{
		{"un-rotated legacy token", claimLessAccess(&oldIssued, "")},
		{"token rotated after the cutoff", claimLessAccess(&rotatedAfterCutoff, "fam_1")},
	}
	for _, tc := range postCutoff {
		t.Run("past cutoff blocked: "+tc.name, func(t *testing.T) {
			handler := RequireDeviceComplianceWithLegacyPolicy(
				func(r *http.Request) *jwtutil.Claims { return tc.claims },
				policyFor(cutoff.Add(time.Hour)), testLogger(),
			)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("handler must not be called past the contracted cutoff")
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("got %d, want 403 — refresh rotation alone must not retire the class or exempt the token", rec.Code)
			}
		})
	}
}

// TestDenyJSONIsRFC7807 asserts the shared deny path emits an RFC 7807
// problem+json body (Content-Type + non-empty type + correct status), not the
// prior hand-rolled application/json map.
func TestDenyJSONIsRFC7807(t *testing.T) {
	claimsFunc := func(r *http.Request) *jwtutil.Claims { return nil }
	handler := RequireDeviceCompliance(claimsFunc, testLogger())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["type"] == nil || body["type"] == "" {
		t.Errorf("missing problem type; body=%v", body)
	}
	if got, ok := body["status"].(float64); !ok || int(got) != http.StatusUnauthorized {
		t.Errorf("status = %v, want %d", body["status"], http.StatusUnauthorized)
	}
}

// TestCSRFRejectionIsRFC7807 asserts a rejected cross-origin request returns
// problem+json (was http.Error plain text).
func TestCSRFRejectionIsRFC7807(t *testing.T) {
	handler := CSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called on CSRF rejection")
	}))
	req := httptest.NewRequest(http.MethodPost, "http://good.example/x", nil)
	req.Host = "good.example"
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["type"] == nil || body["type"] == "" {
		t.Errorf("missing problem type; body=%v", body)
	}
}
