package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
)

func TestExchangeClaimsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims *auth.Claims
		want   int
	}{
		{"anonymous", nil, http.StatusUnauthorized},
		{"wrong permission", claimsWith(permissions.PermExchangeAssessmentRun), http.StatusForbidden},
		{"exact permission", claimsWith(permissions.PermExchangeAssessmentRead), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/admin/exchange-replacement/registry", nil)
			if tc.claims != nil {
				req = req.WithContext(auth.ContextWithUser(req.Context(), tc.claims))
			}
			rec := httptest.NewRecorder()
			claims, ok := exchangeClaims(rec, req, permissions.PermExchangeAssessmentRead)
			if tc.want == 0 {
				if !ok || claims == nil {
					t.Fatal("authorized claim rejected")
				}
				return
			}
			if ok || claims != nil || rec.Code != tc.want {
				t.Fatalf("ok=%v claims=%v status=%d want %d", ok, claims, rec.Code, tc.want)
			}
		})
	}
}

func TestExchangeIdempotencyRequiresCanonicalUUIDAndCanonicalizesPayload(t *testing.T) {
	key := "abcdefab-cdef-4abc-8def-abcdefabcdef"
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Idempotency-Key", key)
	rec := httptest.NewRecorder()
	got, digest, ok := exchangeIdempotency(rec, request, struct {
		Name string `json:"name"`
	}{Name: "项目"})
	if !ok || got.String() != key || len(digest) != 64 {
		t.Fatalf("key=%v digest=%q ok=%v", got, digest, ok)
	}
	request = httptest.NewRequest(http.MethodPost, "/", nil)
	request.Header.Set("Idempotency-Key", strings.ToUpper(key))
	rec = httptest.NewRecorder()
	if _, _, ok := exchangeIdempotency(rec, request, map[string]any{}); ok || rec.Code != 400 {
		t.Fatalf("noncanonical UUID accepted: %d", rec.Code)
	}
}

func TestDecodeExchangeRequestStrictAndSingleValue(t *testing.T) {
	type body struct {
		Name string `json:"name"`
	}
	for _, tc := range []struct {
		name, raw string
		wantErr   bool
	}{
		{"valid", `{"name":"estate"}`, false},
		{"unknown", `{"name":"estate","secret":"x"}`, true},
		{"trailing", `{"name":"estate"} {}`, true},
		{"malformed", `{"name":`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.raw))
			var got body
			err := decodeExchangeRequest(req, &got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestExchangeRequestLimitIsOneMiB(t *testing.T) {
	if maxExchangeAssessmentRequestBytes != 1<<20 {
		t.Fatalf("limit=%d", maxExchangeAssessmentRequestBytes)
	}
}

func TestExchangeSensitivePermissionRequiresFreshAAL2(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/exchange-replacement/projects", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claimsWith(permissions.PermExchangeAssessmentRun)))
	rec := httptest.NewRecorder()
	claims, ok := exchangeClaims(rec, req, permissions.PermExchangeAssessmentRun)
	if ok || claims != nil || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "fresh AAL2") {
		t.Fatalf("ok=%v status=%d body=%s", ok, rec.Code, rec.Body.String())
	}
}
