package ws

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseTypeFilter(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]bool // nil = "all types"
	}{
		{"", nil},
		{"*", nil},
		{"  *  ", nil},
		{"Email", map[string]bool{"Email": true}},
		{"Email,Mailbox", map[string]bool{"Email": true, "Mailbox": true}},
		{" Email , Mailbox ", map[string]bool{"Email": true, "Mailbox": true}},
		{"Email,,", map[string]bool{"Email": true}},
	}
	for _, c := range cases {
		got := parseTypeFilter(c.in)
		if c.want == nil {
			if got != nil {
				t.Errorf("parseTypeFilter(%q) = %v, want nil (all)", c.in, got)
			}
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseTypeFilter(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for k := range c.want {
			if !got[k] {
				t.Errorf("parseTypeFilter(%q) missing %q", c.in, k)
			}
		}
	}
}

func TestFilterTypes(t *testing.T) {
	changed := map[string]string{"Email": "5", "Mailbox": "3", "Calendar": "2"}

	// nil filter passes everything through unchanged.
	if got := filterTypes(changed, nil); len(got) != 3 {
		t.Errorf("nil filter should pass all, got %v", got)
	}

	// A filter drops unlisted keys.
	got := filterTypes(changed, map[string]bool{"Email": true})
	if len(got) != 1 || got["Email"] != "5" {
		t.Errorf("filter Email-only = %v, want {Email:5}", got)
	}

	// A filter that matches nothing yields an empty map (caller skips the push).
	if got := filterTypes(changed, map[string]bool{"Task": true}); len(got) != 0 {
		t.Errorf("filter for absent type should be empty, got %v", got)
	}
}

func TestWriteStateChange(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeStateChange(rec, rec, "42", map[string]string{"Email": "7"}); err != nil {
		t.Fatalf("writeStateChange: %v", err)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "event: state\ndata: ") {
		t.Errorf("missing SSE event/data prefix: %q", body)
	}
	if !strings.HasSuffix(body, "\n\n") {
		t.Errorf("SSE frame must end with a blank line: %q", body)
	}
	// The data line carries a JMAP StateChange keyed by accountId.
	if !strings.Contains(body, `"@type":"StateChange"`) || !strings.Contains(body, `"42":{"Email":"7"}`) {
		t.Errorf("StateChange payload wrong: %q", body)
	}

	// Empty changed set emits nothing (nothing the client asked for).
	rec2 := httptest.NewRecorder()
	if err := writeStateChange(rec2, rec2, "42", map[string]string{}); err != nil {
		t.Fatalf("writeStateChange empty: %v", err)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("empty changed should write nothing, got %q", rec2.Body.String())
	}
}

// A request with no bearer header and no cookie is rejected 401 before any
// dispatcher/jmap work — so a nil-dependency handler is enough to prove the gate.
func TestEventSource_MissingToken401(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.Default(), false)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jmap/eventsource", nil)
	h.EventSource(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no-token EventSource = %d, want 401", rec.Code)
	}
}

// A cookie-authed request with a disallowed origin is rejected 403 in production
// (the CSWSH backstop) before token validation — nil chain is never reached.
func TestEventSource_CookieBadOriginProduction403(t *testing.T) {
	h := NewHandler(nil, nil, nil, slog.Default(), true /* production */)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jmap/eventsource", nil)
	req.AddCookie(&http.Cookie{Name: "access_token", Value: "x"})
	req.Header.Set("Origin", "https://evil.example")
	req.Host = "mail.corp.example"
	h.EventSource(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cookie+bad-origin EventSource (prod) = %d, want 403", rec.Code)
	}
}
