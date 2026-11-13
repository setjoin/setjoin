package mimeutil

import (
	"bytes"
	"strings"
	"testing"
)

// Edge-branch coverage for the strict boundary extraction, the delimiter
// classifier, and the walker's rewrite (non-keep) path.

// TestExtractBoundaryStrictNonMultipartAndMissingBoundary pins the two
// benign/strict branches of ExtractBoundaryStrict: a parseable non-multipart
// type yields ("", false, nil) — the caller decides semantics — while a
// multipart type with no boundary parameter is a hard error.
func TestExtractBoundaryStrictNonMultipartAndMissingBoundary(t *testing.T) {
	boundary, isMultipart, err := ExtractBoundaryStrict("text/plain; charset=utf-8")
	if err != nil || isMultipart || boundary != "" {
		t.Fatalf("text/plain → (%q,%v,%v), want empty/false/nil", boundary, isMultipart, err)
	}

	boundary, isMultipart, err = ExtractBoundaryStrict("multipart/mixed")
	if err == nil || !isMultipart || boundary != "" {
		t.Fatalf("multipart without boundary → (%q,%v,%v), want error with isMultipart=true", boundary, isMultipart, err)
	}
	if !strings.Contains(err.Error(), "no boundary parameter") {
		t.Fatalf("error = %v, want boundary-parameter complaint", err)
	}
}

// TestWalkMIMEPartsOpenDelimiterAtEOF pins the classifier's empty-rest state:
// a delimiter token at the very end of the body has no terminator, is
// therefore content (matchAfterPrefix needs more input), and the parse fails
// closed on the missing close delimiter.
func TestWalkMIMEPartsOpenDelimiterAtEOF(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"payload\r\n" +
		"--b" // EOF immediately after the token: no EOL, no close dashes
	if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Fatal("walker accepted a body whose trailing delimiter token is unterminated")
	}
}

// TestWalkMIMEPartsPreambleCloseDelimiterLocksConvention pins the preamble
// close-delimiter state: a REAL close delimiter line in the preamble (followed
// by content) locks the line-ending convention via its CRLF and parsing
// continues with the later open delimiter.
func TestWalkMIMEPartsPreambleCloseDelimiterLocksConvention(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "preamble\r\n" +
		"--b--\r\n" + // genuine close shape, but in the preamble: content
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"real body\r\n" +
		"--b--\r\n"
	out, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil })
	if err != nil {
		t.Fatalf("walker rejected a preamble close-delimiter lookalike: %v", err)
	}
	if !strings.Contains(string(out), "real body") {
		t.Fatalf("real part lost: %q", out)
	}
}

// TestWalkMIMEPartsFailClosedCloseDelimiterConventionSwitch pins the mid-body
// close-delimiter convention switch: with CRLF locked by the open delimiter,
// an LF-terminated close line is the ambiguous rewrite state and fails closed.
func TestWalkMIMEPartsFailClosedCloseDelimiterConventionSwitch(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"first\r\n" +
		"--b--\n" // LF close after a CRLF-locked convention
	if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Fatal("walker accepted a close delimiter that switches the locked line-ending convention")
	}
}

// TestWalkMIMEPartsRejectsNonMultipartContentType pins the walker's contract:
// a non-multipart Content-Type is a caller error, not an empty walk.
func TestWalkMIMEPartsRejectsNonMultipartContentType(t *testing.T) {
	_, err := WalkMIMEParts("text/plain", []byte("body"), func(_, _ []byte) []byte { return nil })
	if err == nil || !strings.Contains(err.Error(), "needs a multipart Content-Type") {
		t.Fatalf("err = %v, want multipart-Content-Type complaint", err)
	}
}

// TestWalkMIMEPartsDepthCapWithWellformedNesting reaches the recursion cap
// with FULLY well-formed nesting: every level opens and closes properly, so
// the depth guard itself (not a framing error) is what stops the walk.
func TestWalkMIMEPartsDepthCapWithWellformedNesting(t *testing.T) {
	// Build level bodies innermost-first, each level closing cleanly.
	body := "leaf\r\n"
	for i := maxMIMENestingDepth + 2; i >= 0; i-- {
		inner := body
		body = "--L" + itoa(i) + "\r\n" +
			"Content-Type: multipart/mixed; boundary=L" + itoa(i+1) + "\r\n" +
			"\r\n" +
			inner +
			"--L" + itoa(i) + "--\r\n"
	}
	ct := `multipart/mixed; boundary="L0"`
	if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Fatal("walker accepted nesting beyond the depth cap when every level is well-formed")
	}
}

// TestWalkMIMEPartsFailClosedNestedMissingBoundary pins the nested-Content-Type
// guard: a child part declared multipart but carrying no boundary parameter is
// a hard error (the container would be unframed for a compliant client).
func TestWalkMIMEPartsFailClosedNestedMissingBoundary(t *testing.T) {
	ct := `multipart/mixed; boundary="outer"`
	body := "--outer\r\n" +
		"Content-Type: multipart/alternative\r\n" + // multipart, no boundary
		"\r\n" +
		"inner\r\n" +
		"--outer--\r\n"
	_, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil })
	if err == nil || !strings.Contains(err.Error(), "no boundary parameter") {
		t.Fatalf("err = %v, want nested missing-boundary complaint", err)
	}
}

// TestWalkMIMEPartsRewriteCallbackReplacesLeaf pins the non-keep path: a
// callback that returns replacement bytes swaps the leaf body while the
// framing EOL stays with the frame, so the output stays well-formed MIME.
func TestWalkMIMEPartsRewriteCallbackReplacesLeaf(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"original\r\n" +
		"--b--\r\n"
	out, err := WalkMIMEParts(ct, []byte(body), func(headers, _ []byte) []byte {
		return append(append([]byte{}, headers...), []byte("\r\n\r\nREWRITTEN")...)
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if !strings.Contains(string(out), "REWRITTEN") {
		t.Fatalf("replacement body missing from output: %q", out)
	}
	if strings.Contains(string(out), "original") {
		t.Fatalf("original body survived the rewrite: %q", out)
	}
	if !strings.Contains(string(out), "REWRITTEN\r\n--b--\r\n") {
		t.Fatalf("framing EOL not reattached after rewritten leaf: %q", out)
	}
}

// TestWalkMIMEPartsLeafWithUnparseableNonMultipartContentType pins the leaf
// pass-through: an unparseable NON-multipart child Content-Type is not a
// nesting candidate — the part is walked as an opaque leaf.
func TestWalkMIMEPartsLeafWithUnparseableNonMultipartContentType(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain; =broken\r\n" + // invalid parameter syntax
		"\r\n" +
		"leaf body\r\n" +
		"--b--\r\n"
	leaves := 0
	if _, err := WalkMIMEParts(ct, []byte(body), func(headers, body []byte) []byte {
		leaves++
		return nil
	}); err != nil {
		t.Fatalf("walker rejected an unparseable non-multipart leaf: %v", err)
	}
	if leaves != 1 {
		t.Fatalf("leaf visits = %d, want 1", leaves)
	}
}

// TestWalkMIMEPartsFailClosedShortPartWithoutBlankLine pins the short-segment
// echo path of the splitPartHeaders error: a part with content but no
// header/body blank line fails closed, and the error echo stays bounded for
// short segments too.
func TestWalkMIMEPartsFailClosedShortPartWithoutBlankLine(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"no blank line here\r\n" +
		"--b--\r\n"
	_, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil })
	if err == nil || !strings.Contains(err.Error(), "no header/body blank line") {
		t.Fatalf("err = %v, want blank-line complaint", err)
	}
	if !strings.Contains(err.Error(), "no blank line here") {
		t.Fatalf("error echo dropped the (short) segment: %v", err)
	}
}

// itoa keeps the depth-cap fixture self-contained.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Guard the helper itself against silent drift.
func TestItoaFixtureHelper(t *testing.T) {
	if itoa(0) != "0" || itoa(7) != "7" || itoa(23) != "23" || itoa(-5) != "-5" {
		t.Fatal("itoa fixture helper drifted")
	}
	if !bytes.Equal([]byte(itoa(123)), []byte("123")) {
		t.Fatal("itoa fixture helper drifted (bytes)")
	}
}
