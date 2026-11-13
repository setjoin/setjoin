package httputil

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteProblemSetsContentType(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Type:   TypeNotFound,
		Title:  "Not Found",
		Status: http.StatusNotFound,
		Detail: "The resource was not found.",
	})
	resp := w.Result()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

func TestWriteProblemSetsInstance(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/users/42", nil)
	WriteProblem(w, r, &Problem{
		Type:   TypeNotFound,
		Title:  "Not Found",
		Status: http.StatusNotFound,
		Detail: "User not found.",
	})
	var decoded Problem
	json.NewDecoder(w.Body).Decode(&decoded)
	if decoded.Instance != "/api/users/42" {
		t.Errorf("Instance = %q, want /api/users/42", decoded.Instance)
	}
}

func TestWriteProblemDefaultsTypeToAboutBlank(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Status: http.StatusInternalServerError,
	})
	var decoded Problem
	json.NewDecoder(w.Body).Decode(&decoded)
	if decoded.Type != TypeAboutBlank {
		t.Errorf("Type = %q, want %q", decoded.Type, TypeAboutBlank)
	}
}

func TestWriteProblemDefaultsTitleToStatusText(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Status: http.StatusNotFound,
	})
	var decoded Problem
	json.NewDecoder(w.Body).Decode(&decoded)
	if decoded.Title != http.StatusText(http.StatusNotFound) {
		t.Errorf("Title = %q, want %q", decoded.Title, http.StatusText(http.StatusNotFound))
	}
}

func TestWriteProblemDoesNotOverrideExplicitType(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
	})
	var decoded Problem
	json.NewDecoder(w.Body).Decode(&decoded)
	if decoded.Type != TypeUnauthorized {
		t.Errorf("Type = %q, want %q", decoded.Type, TypeUnauthorized)
	}
}

func TestWriteProblemDoesNotOverrideExplicitTitle(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Type:   TypeForbidden,
		Title:  "Access Denied",
		Status: http.StatusForbidden,
	})
	var decoded Problem
	json.NewDecoder(w.Body).Decode(&decoded)
	if decoded.Title != "Access Denied" {
		t.Errorf("Title = %q, want 'Access Denied'", decoded.Title)
	}
}

func TestNewInternalProblemDoesNotContainRawError(t *testing.T) {
	p := NewInternalProblem()
	if strings.Contains(p.Detail, "err.Error") {
		t.Error("NewInternalProblem detail should not reference err.Error()")
	}
	if strings.Contains(p.Detail, "error") && !strings.Contains(p.Detail, "unexpected") {
		// The word "error" alone is fine; we just want to ensure it's not
		// a raw Go error message.
	}
	if p.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusInternalServerError)
	}
	if p.Type != TypeInternalError {
		t.Errorf("Type = %q, want %q", p.Type, TypeInternalError)
	}
}

func TestNewValidationProblemStatus(t *testing.T) {
	p := NewValidationProblem("field X is required", []FieldError{
		{Field: "x", Message: "required"},
	})
	if p.Status != http.StatusUnprocessableEntity {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusUnprocessableEntity)
	}
	if p.Type != TypeValidationFailed {
		t.Errorf("Type = %q, want %q", p.Type, TypeValidationFailed)
	}
	if len(p.InvalidParams) != 1 {
		t.Errorf("InvalidParams length = %d, want 1", len(p.InvalidParams))
	}
	if p.Detail != "field X is required" {
		t.Errorf("Detail = %q, want 'field X is required'", p.Detail)
	}
}

func TestNewUnauthorizedProblem(t *testing.T) {
	p := NewUnauthorizedProblem("Please log in.")
	if p.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusUnauthorized)
	}
	if p.Type != TypeUnauthorized {
		t.Errorf("Type = %q, want %q", p.Type, TypeUnauthorized)
	}
	if p.Title != "Unauthorized" {
		t.Errorf("Title = %q, want Unauthorized", p.Title)
	}
}

func TestNewForbiddenProblem(t *testing.T) {
	p := NewForbiddenProblem("Insufficient role.")
	if p.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusForbidden)
	}
	if p.Type != TypeForbidden {
		t.Errorf("Type = %q, want %q", p.Type, TypeForbidden)
	}
}

func TestNewNotFoundProblem(t *testing.T) {
	p := NewNotFoundProblem("Mailbox not found.")
	if p.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusNotFound)
	}
	if p.Type != TypeNotFound {
		t.Errorf("Type = %q, want %q", p.Type, TypeNotFound)
	}
}

func TestNewServiceUnavailableProblem(t *testing.T) {
	p := NewServiceUnavailableProblem("Database is starting up.")
	if p.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusServiceUnavailable)
	}
	if p.Type != TypeServiceUnavailable {
		t.Errorf("Type = %q, want %q", p.Type, TypeServiceUnavailable)
	}
}

func TestNewConflictProblem(t *testing.T) {
	p := NewConflictProblem("Resource already exists.")
	if p.Status != http.StatusConflict {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusConflict)
	}
	if p.Type != TypeConflict {
		t.Errorf("Type = %q, want %q", p.Type, TypeConflict)
	}
}

func TestNewRateLimitedProblem(t *testing.T) {
	p := NewRateLimitedProblem("Try again in 30 seconds.")
	if p.Status != http.StatusTooManyRequests {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusTooManyRequests)
	}
	if p.Type != TypeRateLimited {
		t.Errorf("Type = %q, want %q", p.Type, TypeRateLimited)
	}
}

func TestNewTokenExpiredProblem(t *testing.T) {
	p := NewTokenExpiredProblem("Your session has expired.")
	if p.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", p.Status, http.StatusUnauthorized)
	}
	if p.Type != TypeTokenExpired {
		t.Errorf("Type = %q, want %q", p.Type, TypeTokenExpired)
	}
}

func TestProblemRoundTripJSON(t *testing.T) {
	original := &Problem{
		Type:     TypeValidationFailed,
		Title:    "Validation Failed",
		Status:   http.StatusUnprocessableEntity,
		Detail:   "The 'email' field is required.",
		Instance: "/api/users",
		InvalidParams: []FieldError{
			{Field: "email", Message: "required"},
		},
	}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var decoded Problem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if decoded.Type != original.Type {
		t.Errorf("Type mismatch: got %q, want %q", decoded.Type, original.Type)
	}
	if decoded.Status != original.Status {
		t.Errorf("Status mismatch: got %d, want %d", decoded.Status, original.Status)
	}
	if decoded.Detail != original.Detail {
		t.Errorf("Detail mismatch: got %q, want %q", decoded.Detail, original.Detail)
	}
	if decoded.Title != original.Title {
		t.Errorf("Title mismatch: got %q, want %q", decoded.Title, original.Title)
	}
	if decoded.Instance != original.Instance {
		t.Errorf("Instance mismatch: got %q, want %q", decoded.Instance, original.Instance)
	}
	if len(decoded.InvalidParams) != len(original.InvalidParams) {
		t.Errorf("InvalidParams length mismatch: got %d, want %d",
			len(decoded.InvalidParams), len(original.InvalidParams))
	}
}

func TestProblemInvalidParamsOmittedWhenEmpty(t *testing.T) {
	p := &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
		Detail: "Please log in.",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(data), "invalid-params") {
		t.Error("JSON should not contain 'invalid-params' when empty")
	}
}

func TestWriteProblemSetsContentLanguage(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Accept-Language", "de")
	WriteProblem(w, r, &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
	})
	if cl := w.Header().Get("Content-Language"); cl != "de" {
		t.Errorf("Content-Language = %q, want 'de'", cl)
	}
}

func TestWriteProblemContentLanguageDefaultsToEn(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(w, r, &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
	})
	if cl := w.Header().Get("Content-Language"); cl != "en" {
		t.Errorf("Content-Language = %q, want 'en'", cl)
	}
}

func TestWriteProblemStatusCodeMatches(t *testing.T) {
	tests := []struct {
		problem *Problem
		want    int
	}{
		{NewUnauthorizedProblem("x"), http.StatusUnauthorized},
		{NewForbiddenProblem("x"), http.StatusForbidden},
		{NewNotFoundProblem("x"), http.StatusNotFound},
		{NewConflictProblem("x"), http.StatusConflict},
		{NewInternalProblem(), http.StatusInternalServerError},
		{NewServiceUnavailableProblem("x"), http.StatusServiceUnavailable},
		{NewRateLimitedProblem("x"), http.StatusTooManyRequests},
		{NewTokenExpiredProblem("x"), http.StatusUnauthorized},
	}
	for _, tt := range tests {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/test", nil)
		WriteProblem(w, r, tt.problem)
		if w.Code != tt.want {
			t.Errorf("WriteProblem status = %d, want %d (type=%s)", w.Code, tt.want, tt.problem.Type)
		}
	}
}

func TestParsePrimaryLanguage(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"en", "en"},
		{"en-US", "en-US"},
		{"en-US,en;q=0.9", "en-US"},
		{"zh-CN,zh;q=0.9,en;q=0.8", "zh-CN"},
		{"de;q=0.8,en;q=0.5", "de"},
		{"", ""},
		{"  fr  ", "fr"},
	}
	for _, tt := range tests {
		got := parsePrimaryLanguage(tt.header)
		if got != tt.want {
			t.Errorf("parsePrimaryLanguage(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestWriteProblemWithLocaleFromContextHook(t *testing.T) {
	// Save and restore the hook.
	orig := LocaleFromContext
	defer func() { LocaleFromContext = orig }()

	LocaleFromContext = func(ctx context.Context) string {
		return "de"
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("Accept-Language", "zh") // Should be overridden by hook.
	WriteProblem(w, r, &Problem{
		Type:   TypeUnauthorized,
		Title:  "Unauthorized",
		Status: http.StatusUnauthorized,
	})
	if cl := w.Header().Get("Content-Language"); cl != "de" {
		t.Errorf("Content-Language = %q, want 'de' (hook should override Accept-Language)", cl)
	}
}

func TestProblemRequestID(t *testing.T) {
	// Without middleware, returns empty string.
	// This just validates the function exists and compiles.
	id := ProblemRequestID(t.Context())
	if id != "" {
		t.Logf("RequestID from bare context: %q (expected empty)", id)
	}
}

func TestTypeConstantsAreDistinct(t *testing.T) {
	types := map[string]bool{
		TypeValidationFailed:   true,
		TypeInvalidEmail:       true,
		TypeUnauthorized:       true,
		TypeForbidden:          true,
		TypeTokenExpired:       true,
		TypeNotFound:           true,
		TypeConflict:           true,
		TypeInternalError:      true,
		TypeServiceUnavailable: true,
		TypeRateLimited:        true,
		TypeCSRFFailed:         true,
		TypeMDMRequired:        true,
		TypeMFARequired:        true,
		TypeInvalidJSON:        true,
		TypeTooLarge:           true,
	}
	if len(types) != 15 {
		t.Errorf("Expected 15 distinct problem type constants, got %d", len(types))
	}
	if types[TypeAboutBlank] {
		t.Error("TypeAboutBlank should not be in the standard type set")
	}
}

func TestWriteProblemClampsInvalidStatus(t *testing.T) {
	for _, status := range []int{0, -1, 42, 600, 99999} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/test", nil)
		WriteProblem(rec, r, &Problem{Status: status, Detail: "x"})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status %d wrote %d, want clamped 500", status, rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Fatalf("status %d content-type = %q", status, got)
		}
	}
}

func TestWriteProblemStatusClampsInvalidCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblemStatus(rec, 0, "boom")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("WriteProblemStatus(0) wrote %d, want 500", rec.Code)
	}
	var p Problem
	if err := json.NewDecoder(rec.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	if p.Status != http.StatusInternalServerError || p.Title != http.StatusText(http.StatusInternalServerError) {
		t.Fatalf("problem body = %+v", p)
	}
}

func TestWriteProblemSanitizesContentLanguage(t *testing.T) {
	for _, tc := range []struct {
		accept string
		want   string
	}{
		{"de", "de"},
		{"en-US,en;q=0.9", "en-US"},
		{"../../evil", "en"},          // path-shaped junk never reflected
		{"de\r\nX-Injected: 1", "en"}, // CRLF never reflected
		{"", "en"},
	} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/test", nil)
		if tc.accept != "" {
			r.Header.Set("Accept-Language", tc.accept)
		}
		WriteProblem(rec, r, &Problem{Status: http.StatusBadRequest, Detail: "x"})
		if got := rec.Header().Get("Content-Language"); got != tc.want {
			t.Errorf("Accept-Language %q → Content-Language %q, want %q", tc.accept, got, tc.want)
		}
	}
}

func TestWriteProblemDefaultsNoStore(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/test", nil)
	WriteProblem(rec, r, &Problem{Status: http.StatusBadRequest, Detail: "x"})
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("WriteProblem Cache-Control = %q, want no-store", cc)
	}
}
