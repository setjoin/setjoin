package httputil

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadBodyBoundary(t *testing.T) {
	for _, tc := range []struct {
		name       string
		body       string
		wantOK     bool
		wantStatus int
	}{
		{name: "limit minus one", body: "123", wantOK: true, wantStatus: http.StatusOK},
		{name: "at limit", body: "1234", wantOK: true, wantStatus: http.StatusOK},
		{name: "limit plus one", body: "12345", wantOK: false, wantStatus: http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/dav", strings.NewReader(tc.body))
			body, ok := ReadBody(rec, req, 4)
			if ok != tc.wantOK || rec.Code != tc.wantStatus {
				t.Fatalf("ReadBody ok/status = %v/%d, want %v/%d", ok, rec.Code, tc.wantOK, tc.wantStatus)
			}
			if ok && string(body) != tc.body {
				t.Fatalf("body = %q, want %q", body, tc.body)
			}
		})
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingBody) Close() error             { return nil }

func TestReadBodyReadFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dav", io.NopCloser(strings.NewReader("")))
	req.Body = failingBody{}
	if _, ok := ReadBody(rec, req, 4); ok || rec.Code != http.StatusBadRequest {
		t.Fatalf("ReadBody ok/status = %v/%d, want false/%d", ok, rec.Code, http.StatusBadRequest)
	}
}

func TestWriteErrorEmitsProblemJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, http.StatusBadRequest, "bad thing happened")

	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if p.Detail != "bad thing happened" {
		t.Errorf("detail = %q, want %q", p.Detail, "bad thing happened")
	}
	if p.Title != http.StatusText(http.StatusBadRequest) {
		t.Errorf("title = %q, want %q", p.Title, http.StatusText(http.StatusBadRequest))
	}
	if p.Status != http.StatusBadRequest {
		t.Errorf("status field = %d, want %d", p.Status, http.StatusBadRequest)
	}
	if p.Type != TypeAboutBlank {
		t.Errorf("type = %q, want %q", p.Type, TypeAboutBlank)
	}
}

func TestParseLimitOffset(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantOffset int
	}{
		{"absent -> defaults", "", 50, 0},
		{"valid passthrough", "limit=25&offset=10", 25, 10},
		{"limit over max -> default", "limit=999", 50, 0},
		{"limit zero -> default", "limit=0", 50, 0},
		{"limit negative -> default", "limit=-5", 50, 0},
		{"limit non-numeric -> default", "limit=abc", 50, 0},
		{"offset negative -> floored to 0", "offset=-3", 50, 0},
		{"limit at max is kept", "limit=100", 100, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/?"+tt.query, nil)
			limit, offset := ParseLimitOffset(r, 50, 100)
			if limit != tt.wantLimit || offset != tt.wantOffset {
				t.Errorf("ParseLimitOffset() = (%d, %d), want (%d, %d)", limit, offset, tt.wantLimit, tt.wantOffset)
			}
		})
	}
}

func TestClientIPWithTrust(t *testing.T) {
	tests := []struct {
		name      string
		remote    string
		xff       string
		trustFunc TrustFunc
		want      string
	}{
		{
			name:      "trusts proxy, returns rightmost (proxy-appended) X-Forwarded-For IP",
			remote:    "10.0.0.1:1234",
			xff:       "203.0.113.1, 10.0.0.2",
			trustFunc: func(addr string) bool { return addr == "10.0.0.1" },
			want:      "10.0.0.2",
		},
		{
			name:      "does not trust proxy, returns RemoteAddr",
			remote:    "192.168.1.1:54321",
			xff:       "203.0.113.1",
			trustFunc: func(addr string) bool { return false },
			want:      "192.168.1.1",
		},
		{
			// Guards the net.ParseIP validation folded into clientip.ExtractWithTrust:
			// a trusted peer forwarding a non-IP value must NOT be trusted.
			name:      "trusted proxy but malformed X-Forwarded-For falls back to RemoteAddr",
			remote:    "10.0.0.1:1234",
			xff:       "not-an-ip",
			trustFunc: func(addr string) bool { return true },
			want:      "10.0.0.1",
		},
		{
			name:      "single X-Forwarded-For value, trusted",
			remote:    "10.0.0.1:9999",
			xff:       "198.51.100.1",
			trustFunc: func(addr string) bool { return true },
			want:      "198.51.100.1",
		},
		{
			name:      "no X-Forwarded-For header, trusted proxy",
			remote:    "10.0.0.1:4321",
			xff:       "",
			trustFunc: func(addr string) bool { return true },
			want:      "10.0.0.1",
		},
		{
			name:      "remote addr without port",
			remote:    "10.0.0.1",
			xff:       "",
			trustFunc: func(addr string) bool { return false },
			want:      "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			got := ClientIPWithTrust(r, tt.trustFunc)
			if got != tt.want {
				t.Errorf("ClientIPWithTrust() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeJSONRejectsTrailingDocument(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":1} {"b":2}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	var v struct {
		A int `json:"a"`
	}
	err := DecodeJSON(rec, req, &v)
	if err == nil || !strings.Contains(err.Error(), "trailing data") {
		t.Fatalf("DecodeJSON trailing document err = %v, want trailing-data error", err)
	}
	if v.A != 1 {
		t.Fatalf("first document lost: %+v", v)
	}
}

func TestDecodeJSONStillAcceptsSingleDocument(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":1}`))
	rec := httptest.NewRecorder()
	var v struct {
		A int `json:"a"`
	}
	if err := DecodeJSON(rec, req, &v); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if v.A != 1 {
		t.Fatalf("a = %d, want 1", v.A)
	}
}

func TestDecodeJSONSurfacesMaxBytesErrorAndMaps413(t *testing.T) {
	// Valid JSON that exceeds the 1 MiB cap mid-value, so the decoder hits
	// MaxBytesReader instead of a syntax error.
	body := `{"a":"` + strings.Repeat("x", 1<<20) + `"}`
	req := httptest.NewRequest("POST", "/x", strings.NewReader(body))
	rec := httptest.NewRecorder()

	var v map[string]any
	err := DecodeJSON(rec, req, &v)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("DecodeJSON cap err = %v, want *http.MaxBytesError", err)
	}

	rec2 := httptest.NewRecorder()
	r2 := httptest.NewRequest("POST", "/x", nil)
	WriteDecodeError(rec2, r2, err)
	if rec2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("WriteDecodeError status = %d, want 413", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("WriteDecodeError content-type = %q", ct)
	}
}

func TestWriteDecodeErrorMapsInvalidJSONTo400(t *testing.T) {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/x", strings.NewReader("{not json"))
	var v map[string]any
	err := DecodeJSON(rec, r, &v)
	if err == nil || errors.As(err, new(*http.MaxBytesError)) {
		t.Fatalf("expected plain decode error, got %v", err)
	}
	rec2 := httptest.NewRecorder()
	WriteDecodeError(rec2, r, err)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("WriteDecodeError status = %d, want 400", rec2.Code)
	}
}

func TestWriteJSONDefaultsNoStoreAndKeepsExplicitPolicy(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]string{"ok": "yes"})
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("WriteJSON Cache-Control = %q, want no-store", cc)
	}

	rec2 := httptest.NewRecorder()
	rec2.Header().Set("Cache-Control", "private, max-age=60")
	WriteJSON(rec2, http.StatusOK, map[string]string{"ok": "yes"})
	if cc := rec2.Header().Get("Cache-Control"); cc != "private, max-age=60" {
		t.Fatalf("explicit Cache-Control clobbered: %q", cc)
	}
}

func TestParseLimitOffsetCapsOffset(t *testing.T) {
	req := httptest.NewRequest("GET", "/list?limit=10&offset=99999999", nil)
	limit, offset := ParseLimitOffset(req, 25, 100)
	if limit != 10 || offset != maxOffset {
		t.Fatalf("limit,offset = %d,%d, want 10,%d (offset capped)", limit, offset, maxOffset)
	}
	req2 := httptest.NewRequest("GET", "/list?limit=10&offset=-5", nil)
	_, offset2 := ParseLimitOffset(req2, 25, 100)
	if offset2 != 0 {
		t.Fatalf("negative offset = %d, want 0", offset2)
	}
}
