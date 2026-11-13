package caldav

import (
	"strings"
	"testing"
	"time"
)

// TestBuildIMip_HeaderInjectionStripped guards the iMIP CRLF-injection fix:
// user-controlled Title, fromName, fromEmail, and attendee name/email must not
// allow header injection via embedded CR or LF characters.
func TestBuildIMip_HeaderInjectionStripped(t *testing.T) {
	evil := CalendarEvent{
		UID:   "inj@example.com",
		Title: "Meeting\r\nX-Injected: evil",
		Start: time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC),
		End:   time.Date(2024, 6, 15, 11, 0, 0, 0, time.UTC),
		Attendees: []Attendee{
			{
				Email: "attendee@example.com",
				Name:  "Eve\r\nX-Injected: hdr",
				Role:  "required",
				RSVP:  true,
			},
		},
		Organizer: Attendee{
			Email: "org@example.com\r\nBcc: attacker@evil.com",
			Name:  "Org",
		},
	}

	mime, _, err := BuildIMip(MethodRequest, evil, "sender@example.com\r\nX-Extra: bad", "Sender\r\nX-Name: inject")
	if err != nil {
		t.Fatalf("BuildIMip: %v", err)
	}

	// Split into header section (before blank line) and body.
	parts := strings.SplitN(mime, "\r\n\r\n", 2)
	if len(parts) < 2 {
		t.Fatal("no blank line separating headers from body")
	}
	headers := parts[0]

	// Parse individual header lines: no line may be empty mid-block (which
	// would indicate a premature end-of-headers), and no additional CR/LF
	// may be embedded inside a line (which would indicate injection succeeded).
	headerLines := strings.Split(headers, "\r\n")
	for _, line := range headerLines {
		if strings.ContainsAny(line, "\r\n") {
			t.Errorf("header line contains bare CR/LF after stripping: %q", line)
		}
	}

	// Injection succeeds only if a new header NAME appears on its own line.
	// After stripping CR/LF the malicious content ends up as part of a
	// legitimate header value (e.g., in Subject), not as a separate header.
	injectedNames := []string{"X-Injected:", "X-Extra:", "X-Name:", "Bcc:"}
	for _, line := range headerLines {
		for _, bad := range injectedNames {
			if strings.HasPrefix(line, bad) {
				t.Errorf("injected header %q found as standalone header line: %q", bad, line)
			}
		}
	}

	// The MIME message must still contain the stripped title in Subject.
	if !strings.Contains(headers, "Subject:") {
		t.Error("Subject header missing")
	}
}

// TestStripHeaderCtrl verifies the stripping helper covers CR, LF, and NUL.
func TestStripHeaderCtrl(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello", "hello"},
		{"a\r\nb", "ab"},
		{"a\nb", "ab"},
		{"a\rb", "ab"},
		{"a\x00b", "ab"},
		{"no change needed", "no change needed"},
	}
	for _, tc := range cases {
		got := stripHeaderCtrl(tc.in)
		if got != tc.want {
			t.Errorf("stripHeaderCtrl(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestComponentTypeDispatch verifies that componentType="" defaults to VEVENT,
// VTODO routes to VTODO serializer, and VJOURNAL to VJOURNAL serializer.
func TestComponentTypeDispatch(t *testing.T) {
	h := &Handler{}

	vevent := &eventRow{UID: "u1", ComponentType: ""}
	got := h.eventToICal(vevent)
	if !strings.Contains(got, "BEGIN:VEVENT") {
		t.Errorf("empty ComponentType: expected VEVENT, got:\n%s", got)
	}

	vtodo := &eventRow{UID: "u2", ComponentType: "VTODO"}
	got = h.eventToICal(vtodo)
	if !strings.Contains(got, "BEGIN:VTODO") {
		t.Errorf("ComponentType=VTODO: expected VTODO, got:\n%s", got)
	}

	vjournal := &eventRow{UID: "u3", ComponentType: "VJOURNAL"}
	got = h.eventToICal(vjournal)
	if !strings.Contains(got, "BEGIN:VJOURNAL") {
		t.Errorf("ComponentType=VJOURNAL: expected VJOURNAL, got:\n%s", got)
	}
}
