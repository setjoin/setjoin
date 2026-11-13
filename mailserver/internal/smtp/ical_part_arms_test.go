package smtp

import (
	"strings"
	"testing"
)

// TestExtractICalPartArms covers the edge arms of extractICalPart:
//   - a calendar part whose headers are never terminated by a blank line
//     (neither "\r\n\r\n" nor "\n\n" inside the part) — the return that hands
//     back the raw part content unchanged;
//   - a scope with no text/calendar part at all (error);
//   - an isolated calendar with no boundary= framing (partIndex 0);
//   - a well-formed multipart control whose calendar sits in the SECOND part.
//
// partIndex = 1 + the number of opening "\n--boundary" delimiters before the
// part; the closing delimiter ("--boundary--") must NOT count. The closing
// check inspects the two characters after the boundary VALUE (checking the
// delimiter's own second dash — the pre-2026-09-10 bug — pinned partIndex at
// 1 and made a calendar in part N>1 unindexable).
func TestExtractICalPartArms(t *testing.T) {
	t.Run("part headers without blank line separator", func(t *testing.T) {
		scope := "Content-Type: multipart/mixed; boundary=BB\r\n\r\n" +
			"--BB\r\n" +
			"Content-Type: text/calendar\r\n" +
			"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n" +
			"--BB--\r\n"
		partIndex, content, start, end, err := extractICalPart(scope)
		if err != nil {
			t.Fatalf("extractICalPart: %v", err)
		}
		if partIndex != 1 {
			t.Errorf("partIndex = %d, want 1", partIndex)
		}
		want := "Content-Type: text/calendar\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--BB--"
		if content != want {
			t.Errorf("content = %q, want %q", content, want)
		}
		wantStart := int64(strings.Index(scope, "Content-Type: text/calendar"))
		if start != wantStart {
			t.Errorf("start = %d, want %d", start, wantStart)
		}
		wantEnd := int64(strings.Index(scope, "--BB--")) + int64(len("--BB--"))
		if end != wantEnd {
			t.Errorf("end = %d, want %d (through the closing delimiter)", end, wantEnd)
		}
		if scope[start:end] != content {
			t.Errorf("scope[%d:%d] = %q, want %q", start, end, scope[start:end], content)
		}
	})

	t.Run("no text/calendar part errors", func(t *testing.T) {
		scope := "Content-Type: text/plain\r\n\r\njust text\r\n"
		partIndex, content, start, end, err := extractICalPart(scope)
		if err == nil {
			t.Fatalf("expected error for scope without text/calendar, got partIndex=%d content=%q start=%d end=%d",
				partIndex, content, start, end)
		}
	})

	t.Run("isolated calendar without boundary framing", func(t *testing.T) {
		scope := "Content-Type: text/calendar\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n"
		partIndex, content, start, end, err := extractICalPart(scope)
		if err != nil {
			t.Fatalf("extractICalPart: %v", err)
		}
		if partIndex != 0 {
			t.Errorf("partIndex = %d, want 0 without a boundary= preceding the part", partIndex)
		}
		if content != scope {
			t.Errorf("content = %q, want the whole scope %q", content, scope)
		}
		if start != 0 || end != int64(len(scope)) {
			t.Errorf("start,end = %d,%d, want 0,%d", start, end, len(scope))
		}
	})

	t.Run("multipart control: calendar in second part", func(t *testing.T) {
		scope := "Content-Type: multipart/mixed; boundary=CC\r\n\r\n" +
			"--CC\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
			"--CC\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--CC--\r\n"
		partIndex, content, start, end, err := extractICalPart(scope)
		if err != nil {
			t.Fatalf("extractICalPart: %v", err)
		}
		// The one opening delimiter before the calendar makes it part 2.
		if partIndex != 2 {
			t.Errorf("partIndex = %d, want 2", partIndex)
		}
		want := "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--CC--"
		if content != want {
			t.Errorf("content = %q, want %q", content, want)
		}
		if scope[start:end] != content {
			t.Errorf("scope[%d:%d] = %q, want %q", start, end, scope[start:end], content)
		}
	})

	t.Run("closing delimiters do not count toward partIndex", func(t *testing.T) {
		// Calendar in the THIRD part: two openers precede it and one CLOSE
		// delimiter (end of part 1) sits between them — the close must not
		// increment, or the index undercounts by one.
		scope := "Content-Type: multipart/mixed; boundary=DD\r\n\r\n" +
			"--DD\r\nContent-Type: text/plain\r\n\r\none\r\n" +
			"--DD--\r\n" +
			"--DD\r\nContent-Type: text/plain\r\n\r\ntwo\r\n" +
			"--DD\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--DD--\r\n"
		partIndex, content, start, end, err := extractICalPart(scope)
		if err != nil {
			t.Fatalf("extractICalPart: %v", err)
		}
		if partIndex != 3 {
			t.Errorf("partIndex = %d, want 3 (two openers; the close delimiter must not count)", partIndex)
		}
		want := "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n--DD--"
		if content != want {
			t.Errorf("content = %q, want %q", content, want)
		}
		if scope[start:end] != content {
			t.Errorf("scope[%d:%d] = %q, want %q", start, end, scope[start:end], content)
		}
	})
}
