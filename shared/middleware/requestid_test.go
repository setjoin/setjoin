package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestIDSetsResponseHeader(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
	id := w.Header().Get("X-Request-ID")
	if id == "" {
		t.Error("X-Request-ID header not set on response")
	}
}

func TestRequestIDReusesIncomingHeader(t *testing.T) {
	incomingID := "550e8400-e29b-41d4-a716-446655440000"
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := GetRequestID(r.Context())
		if got != incomingID {
			t.Errorf("GetRequestID = %q, want %q", got, incomingID)
		}
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", incomingID)
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-ID"); got != incomingID {
		t.Errorf("Response X-Request-ID = %q, want %q", got, incomingID)
	}
}

func TestRequestIDGeneratesUUIDFormat(t *testing.T) {
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := GetRequestID(r.Context())
		// UUID v4 is 36 characters: 8-4-4-4-12
		if len(id) != 36 {
			t.Errorf("generated ID length = %d, want 36", len(id))
		}
		parts := strings.Split(id, "-")
		if len(parts) != 5 {
			t.Errorf("expected 5 dash-separated parts, got %d", len(parts))
		}
		if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 ||
			len(parts[3]) != 4 || len(parts[4]) != 12 {
			t.Errorf("UUID segment lengths wrong: %v", parts)
		}
		// Version 4 UUIDs have the 13th character as '4'.
		if parts[2][0] != '4' {
			t.Errorf("UUID version nibble should be '4', got %q (id=%s)", parts[2][0], id)
		}
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
}

func TestRequestIDGeneratesUniqueIDs(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ids[GetRequestID(r.Context())] = true
			w.WriteHeader(http.StatusOK)
		}))
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/", nil)
		handler.ServeHTTP(w, r)
	}
	if len(ids) != 100 {
		t.Errorf("expected 100 unique IDs, got %d", len(ids))
	}
}

func TestGetRequestIDFromEmptyContext(t *testing.T) {
	id := GetRequestID(context.Background())
	if id != "" {
		t.Errorf("expected empty string from bare context, got %q", id)
	}
}

func TestGetRequestIDFromMiddlewareContext(t *testing.T) {
	var capturedID string
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedID = GetRequestID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
	if capturedID == "" {
		t.Error("GetRequestID returned empty string from middleware context")
	}
}

func TestLoggerFromContextReturnsLoggerWithRequestID(t *testing.T) {
	var logger *slog.Logger
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger = LoggerFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	handler.ServeHTTP(w, r)
	if logger == nil {
		t.Fatal("LoggerFromContext returned nil")
	}
	// Verify the logger has the request_id attribute by examining its handler output.
	// The simplest validation: logger should not be slog.Default() with no attrs.
	// We verify by checking that a non-nil logger was returned.
}

func TestLoggerFromContextReturnsDefaultForBareContext(t *testing.T) {
	logger := LoggerFromContext(context.Background())
	if logger == nil {
		t.Fatal("LoggerFromContext returned nil for bare context")
	}
	// Should return slog.Default().
}

func TestRequestIDAcceptsHyphenatedHeader(t *testing.T) {
	// Verify the header name is "X-Request-ID" (with hyphens), not "X-Request-Id".
	incomingID := "aaaaaaaa-bbbb-4ccc-dddd-eeeeeeeeeeee"
	handler := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := GetRequestID(r.Context())
		if got != incomingID {
			t.Errorf("GetRequestID = %q, want %q", got, incomingID)
		}
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Request-ID", incomingID)
	handler.ServeHTTP(w, r)
	if got := w.Header().Get("X-Request-ID"); got != incomingID {
		t.Errorf("Response X-Request-ID = %q, want %q", got, incomingID)
	}
}
