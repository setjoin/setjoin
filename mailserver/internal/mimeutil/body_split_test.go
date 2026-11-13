package mimeutil

import (
	"strings"
	"testing"
)

// Regression for the unbounded-Split body-truncation bug: a non-multipart body
// that itself contains a blank line (paragraph break) was split on EVERY
// separator, so only the text between the first and second blank line survived.
// SplitN(..., 2) must keep the full body in parts[1].

func TestExtractBodyTextPreservesBlankLines(t *testing.T) {
	const want = "first paragraph\r\n\r\nsecond paragraph\r\n\r\nthird"
	cases := map[string]string{
		"crlf": "Content-Type: text/plain\r\n\r\n" + want,
		"lf":   "Content-Type: text/plain\n\nfirst paragraph\n\nsecond paragraph\n\nthird",
	}
	for name, msg := range cases {
		got := ExtractBodyText(msg)
		// Normalize the LF case expectation.
		exp := want
		if name == "lf" {
			exp = "first paragraph\n\nsecond paragraph\n\nthird"
		}
		if got != exp {
			t.Errorf("%s: ExtractBodyText truncated body\n got=%q\nwant=%q", name, got, exp)
		}
	}
}

func TestExtractBodyHTMLPreservesBlankLines(t *testing.T) {
	const want = "<p>one</p>\r\n\r\n<p>two</p>\r\n\r\n<p>three</p>"
	msg := "Content-Type: text/html\r\n\r\n" + want
	if got := ExtractBodyHTML(msg); got != want {
		t.Errorf("ExtractBodyHTML truncated body\n got=%q\nwant=%q", got, want)
	}
}

// Regression for the naive bytes.Split boundary matcher (the divergence this
// package now owns for every MIME walk): a "--boundary" byte sequence embedded
// MID-LINE inside a part body — here a base64 attachment — must NOT be treated
// as a delimiter (RFC 2046 requires a delimiter to start a line). WalkMIMEParts
// must see exactly the two real parts and round-trip the message byte-for-byte.
func TestWalkMIMEPartsBoundaryLookalikeMidLine(t *testing.T) {
	const boundary = "XYZ"
	ct := `multipart/mixed; boundary="` + boundary + `"`
	body := "preamble\r\n" +
		"--XYZ\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"hello world\r\n" +
		"--XYZ\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" +
		"SGVsbG8t--XYZ-d29ybGQ=\r\n" + // '--XYZ' sits mid-line: a data byte, not a delimiter
		"--XYZ--\r\n"

	var partBodies []string
	out, err := WalkMIMEParts(ct, []byte(body), func(_, pb []byte) []byte {
		partBodies = append(partBodies, string(pb))
		return nil // keep every part unchanged
	})
	if err != nil {
		t.Fatalf("WalkMIMEParts: %v", err)
	}
	if len(partBodies) != 2 {
		t.Fatalf("mid-line --XYZ false-split: expected 2 parts, got %d", len(partBodies))
	}
	// A naive bytes.Split truncates the attachment body at the mid-line "--XYZ";
	// the line-anchored splitter must deliver it whole to the callback.
	if !strings.Contains(partBodies[1], "SGVsbG8t--XYZ-d29ybGQ=") {
		t.Errorf("attachment body truncated at mid-line lookalike: got %q", partBodies[1])
	}
	if string(out) != body {
		t.Errorf("round-trip not byte-identical:\n got=%q\nwant=%q", out, body)
	}
}
