package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientVersion_MissingParams(t *testing.T) {
	h := newMinimalAuthHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rr := httptest.NewRecorder()
	h.ClientVersion(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	// Even without params, should return a valid response with server_version
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, ok := resp["server_version"]; !ok {
		t.Error("response missing server_version")
	}
	if resp["update_type"] != "up_to_date" {
		t.Errorf("expected update_type 'up_to_date' without params, got %q", resp["update_type"])
	}
}

func TestWellKnown(t *testing.T) {
	h := newMinimalAuthHandler()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/setjoin", nil)
	rr := httptest.NewRecorder()
	h.WellKnown(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if _, ok := resp["version"]; !ok {
		t.Error("response missing version")
	}
}

func TestParseSemVer(t *testing.T) {
	cases := []struct {
		v        string
		maj, min int
	}{
		{"1.0.0", 1, 0},
		{"2.5.0", 2, 5},
		{"10.20.30", 10, 20},
		{"0.0.1", 0, 0},
		{"1.0", 1, 0},
		{"1", 1, 0},
		{"invalid", 0, 0},
		{"", 0, 0},
	}
	for _, c := range cases {
		maj, min := parseSemVer(c.v)
		if maj != c.maj || min != c.min {
			t.Errorf("parseSemVer(%q) = (%d, %d), want (%d, %d)", c.v, maj, min, c.maj, c.min)
		}
	}
}

func TestSemverCompare(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
	}{
		{"1.0.0", "1.0.0", 0},
		{"2.0.0", "1.0.0", 1},
		{"1.0.0", "2.0.0", -1},
		{"1.5.0", "1.5.0", 0},
		{"1.5.1", "1.5.0", 1},
		{"1.5.0", "1.5.1", -1},
		{"2.5.0", "1.10.0", 1},
	}
	for _, c := range cases {
		got := semverCompare(c.a, c.b)
		if got != c.cmp {
			t.Errorf("semverCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.cmp)
		}
	}
}
