package ws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWSEnvelopeRequest(t *testing.T) {
	payload := `{
		"@type": "Request",
		"using": ["urn:ietf:params:jmap:mail"],
		"methodCalls": [["Mailbox/get", {}, "call-1"]]
	}`
	var env wsEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if env.Type != "Request" {
		t.Errorf("@type = %q, want Request", env.Type)
	}
	if len(env.Using) != 1 || env.Using[0] != "urn:ietf:params:jmap:mail" {
		t.Errorf("using = %v, want [urn:ietf:params:jmap:mail]", env.Using)
	}
	if len(env.MethodCalls) != 1 {
		t.Errorf("methodCalls len = %d, want 1", len(env.MethodCalls))
	}
}

func TestWSEnvelopeStateChange(t *testing.T) {
	payload := `{
		"@type": "StateChange",
		"changed": {
			"u1": {
				"Mailbox": "state-2",
				"Email": "state-3"
			}
		}
	}`
	var env wsEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if env.Type != "StateChange" {
		t.Errorf("@type = %q, want StateChange", env.Type)
	}
	if len(env.Changed) != 1 {
		t.Fatalf("changed len = %d, want 1", len(env.Changed))
	}
	u1 := env.Changed["u1"]
	if u1 == nil {
		t.Fatal("changed[u1] is nil")
	}
	if u1["Mailbox"] != "state-2" {
		t.Errorf("Mailbox state = %q, want state-2", u1["Mailbox"])
	}
}

func TestWSEnvelopePushEnable(t *testing.T) {
	payload := `{
		"@type": "PushEnable",
		"dataTypes": ["Mailbox", "Email", "CalendarEvent"],
		"pushState": "client-state-1"
	}`
	var env wsEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if env.Type != "PushEnable" {
		t.Errorf("@type = %q, want PushEnable", env.Type)
	}
	if len(env.DataTypes) != 3 {
		t.Errorf("dataTypes len = %d, want 3", len(env.DataTypes))
	}
	if env.PushState != "client-state-1" {
		t.Errorf("pushState = %q, want client-state-1", env.PushState)
	}
}

// TestClassifyBatch locks the producer→consumer push classification contract,
// including the iTIP/RSVP family that calendar_itip.sql emits with an event_id
// but no calendar_id (so the substring/prefix rules alone would miss it and the
// CalendarEvent push would be dead at the calendar UI).
func TestClassifyBatch(t *testing.T) {
	cases := []struct {
		name            string
		payloads        []string
		wantValid       bool
		wantCalChng     bool
		wantContactChng bool
		wantTaskChng    bool
	}{
		{"email/tag state change", []string{`{"event":"state_change","state":7,"tag_id":1}`}, true, false, false, false},
		{"calendar event_created", []string{`{"event":"event_created","calendar_id":3}`}, true, true, false, false},
		{"calendar_updated prefix", []string{`{"event":"calendar_updated","calendar_id":3}`}, true, true, false, false},
		// calendar_itip.sql: rsvp / itip_reply / itip_cancel carry event_id, no calendar_id.
		{"itip rsvp (event_id only)", []string{`{"event":"rsvp","event_id":42}`}, true, true, false, false},
		{"itip_reply (event_id only)", []string{`{"event":"itip_reply","event_id":42}`}, true, true, false, false},
		{"itip_cancel (event_id only)", []string{`{"event":"itip_cancel","event_id":42}`}, true, true, false, false},
		// Even if the discriminator string were unknown, an event_id makes it a calendar change.
		{"unknown event with event_id", []string{`{"event":"mystery","event_id":42}`}, true, true, false, false},
		// Contact: keyed on contact_id presence (Decision F), now a real push.
		{"contact_created (contact_id present)", []string{`{"event":"contact_created","contact_id":9}`}, true, false, true, false},
		{"contact_group_changed (contact_id null)", []string{`{"event":"contact_group_changed","contact_id":null}`}, true, false, true, false},
		// Task: keyed on task_id presence (Decision F), now a real push.
		{"task_created (task_id present)", []string{`{"event":"task_created","task_id":5}`}, true, false, false, true},
		{"task_destroyed (task_id null)", []string{`{"event":"task_destroyed","task_id":null}`}, true, false, false, true},
		{"garbage payload", []string{`not json`}, false, false, false, false},
		{"mixed batch: email + itip rsvp", []string{
			`{"event":"state_change","state":7}`,
			`{"event":"rsvp","event_id":42}`,
		}, true, true, false, false},
		{"mixed batch: contact + task", []string{
			`{"event":"contact_updated","contact_id":1}`,
			`{"event":"task_updated","task_id":2}`,
		}, true, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotValid, gotCal, gotContact, gotTask, _ := classifyBatch(tc.payloads)
			if gotValid != tc.wantValid {
				t.Errorf("anyValid = %v, want %v", gotValid, tc.wantValid)
			}
			if gotCal != tc.wantCalChng {
				t.Errorf("calendarChanged = %v, want %v", gotCal, tc.wantCalChng)
			}
			if gotContact != tc.wantContactChng {
				t.Errorf("contactChanged = %v, want %v", gotContact, tc.wantContactChng)
			}
			if gotTask != tc.wantTaskChng {
				t.Errorf("taskChanged = %v, want %v", gotTask, tc.wantTaskChng)
			}
		})
	}
}

func TestClassifyBatchControl(t *testing.T) {
	// A control payload carries a top-level "type" in the control set and NONE of
	// the state/calendar/contact/task discriminators. Today it is silently dropped
	// (anyValid stays false, no control return existed). This guards the F1 fix.
	cases := []struct {
		name         string
		payloads     []string
		wantValid    bool
		wantControlN int
	}{
		{"offline.wipe control", []string{`{"type":"offline.wipe","deviceId":42}`}, false, 1},
		{"capsChanged control", []string{`{"type":"capsChanged"}`}, false, 1},
		{"unknown type is NOT control", []string{`{"type":"something_else"}`}, false, 0},
		{"normal state change unaffected", []string{`{"event":"state_change","state":7}`}, true, 0},
		{"mixed: state + control", []string{
			`{"event":"state_change","state":7}`,
			`{"type":"offline.wipe","deviceId":1}`,
		}, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotValid, _, _, _, gotControl := classifyBatch(tc.payloads)
			if gotValid != tc.wantValid {
				t.Errorf("anyValid = %v, want %v", gotValid, tc.wantValid)
			}
			if len(gotControl) != tc.wantControlN {
				t.Errorf("controlPayloads len = %d, want %d", len(gotControl), tc.wantControlN)
			}
		})
	}
}

func TestWSUpgraderConstants(t *testing.T) {
	if wsUpgrader.ReadBufferSize != 4096 {
		t.Errorf("ReadBufferSize = %d, want 4096", wsUpgrader.ReadBufferSize)
	}
	if wsUpgrader.WriteBufferSize != 4096 {
		t.Errorf("WriteBufferSize = %d, want 4096", wsUpgrader.WriteBufferSize)
	}
	if maxWSMessageSize != 10*1024*1024 {
		t.Errorf("maxWSMessageSize = %d, want 10485760", maxWSMessageSize)
	}
}

// TestCheckOrigin covers the CSWSH origin guard: empty-Origin acceptance is
// dev-only, and in production the Origin host must match the configured public
// hostname (or the request's own Host for multi-domain front-ends).
func TestCheckOrigin(t *testing.T) {
	req := func(origin, host string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/jmap/ws", nil)
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return r
	}
	cases := []struct {
		name        string
		production  bool
		allowedHost string
		origin      string
		host        string
		want        bool
	}{
		{"dev empty origin accepted", false, "", "", "localhost:5173", true},
		{"prod empty origin rejected", true, "mail.corp.com", "", "mail.corp.com", false},
		{"prod cross-site rejected", true, "mail.corp.com", "https://evil.com", "mail.corp.com", false},
		{"prod configured host accepted", true, "mail.corp.com", "https://mail.corp.com", "mail.corp.com", true},
		{"prod configured host case-insensitive", true, "mail.corp.com", "https://MAIL.CORP.COM", "mail.corp.com", true},
		{"prod alt-domain via request host accepted", true, "mail.corp.com", "https://imap.corp.com", "imap.corp.com", true},
		{"prod alt-domain mismatch rejected", true, "mail.corp.com", "https://imap.corp.com", "mail.corp.com", false},
		{"dev same-origin accepted", false, "", "http://localhost:5173", "localhost:5173", true},
		{"prod malformed origin rejected", true, "mail.corp.com", "::not a url", "mail.corp.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := &Handler{production: c.production, allowedHost: c.allowedHost}
			if got := h.checkOrigin(req(c.origin, c.host)); got != c.want {
				t.Errorf("checkOrigin(origin=%q host=%q) = %v, want %v", c.origin, c.host, got, c.want)
			}
		})
	}
}
