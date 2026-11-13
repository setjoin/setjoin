package webdav

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMatchETag(t *testing.T) {
	tests := []struct {
		ifMatch, etag string
		want          bool
	}{
		{"", "abc", true},
		{"*", "abc", true},
		{`"abc"`, "abc", true},
		{`"abc"`, `"abc"`, true},
		{`"abc"`, "xyz", false},
		{"", "", true},
		{"*", "", true},
	}
	for _, tt := range tests {
		got := MatchETag(tt.ifMatch, tt.etag)
		if got != tt.want {
			t.Errorf("MatchETag(%q, %q) = %v, want %v", tt.ifMatch, tt.etag, got, tt.want)
		}
	}
}

func TestWriteMultistatus(t *testing.T) {
	w := httptest.NewRecorder()
	ms := &Multistatus{
		Xmlns:     NSDAV,
		Responses: []Response{},
	}
	err := WriteMultistatus(w, interface{}(ms))
	if err != nil {
		t.Fatalf("WriteMultistatus: %v", err)
	}
	if w.Code != http.StatusMultiStatus {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMultiStatus)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
}
