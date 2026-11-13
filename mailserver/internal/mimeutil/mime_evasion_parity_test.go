package mimeutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"testing"
)

// Differential corpus tests for the shared MIME part walker
// (D-MAILSERVER-INTERNAL-MIMEUTIL-001, med-shard2-021).
//
// WalkMIMEParts is the single splitter behind link-protect rewriting, the
// anti-phish banner and body extraction: what it walks is what the scanner
// sees. For every validated evasion vector these tests compare the walker's
// leaf decomposition against a compliant reference parser (the standard
// library's multipart reader, applied recursively the way a client renders
// nested multiparts). Where the reference parser cannot render the body at
// all, the walker must fail closed with an error instead of silently walking
// a decoy framing — the SMTP delivery caller turns that error into a
// quarantine, never into delivery of the unverified original.
//
// Body comparison notes: the walker deliberately leaves the framing EOL that
// precedes the next delimiter line inside partBody (reassembly is byte-exact
// with a keep callback), while the reference parser consumes it. sameBody
// accepts the reference body plus at most one trailing EOL.

// walkerLeaf is one leaf part as the scanner's callback sees it.
type walkerLeaf struct {
	contentType string
	body        string
}

// referenceLeaves enumerates the leaf parts a compliant client renders: the
// standard library parser applied recursively into nested multipart
// containers (NextRawPart so bodies stay raw bytes). refErr records that the
// reference parser FAILED — a body a compliant client cannot render.
func referenceLeaves(t *testing.T, ct string, body []byte) (cts, bodies []string, refErr error) {
	t.Helper()
	var walk func(ct string, body []byte, depth int) error
	walk = func(ct string, body []byte, depth int) error {
		if depth > 20 {
			return fmt.Errorf("reference: nesting deeper than 20")
		}
		_, params, err := mime.ParseMediaType(ct)
		if err != nil {
			return fmt.Errorf("reference: content-type %q: %w", ct, err)
		}
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("reference: next part: %w", err)
			}
			pct := p.Header.Get("Content-Type")
			mt, _, e := mime.ParseMediaType(pct)
			if e == nil && strings.HasPrefix(strings.ToLower(mt), "multipart/") {
				pb, err := io.ReadAll(p)
				if err != nil {
					return err
				}
				if err := walk(pct, pb, depth+1); err != nil {
					return err
				}
				continue
			}
			pb, err := io.ReadAll(p)
			if err != nil {
				return err
			}
			cts = append(cts, pct)
			bodies = append(bodies, string(pb))
		}
	}
	refErr = walk(ct, body, 0)
	return cts, bodies, refErr
}

// walkLeaves drives WalkMIMEParts with a keep callback (so reassembly must be
// byte-exact) and records the leaves the scanner's callback sees.
func walkLeaves(t *testing.T, ct string, body string) (leaves []walkerLeaf, out []byte, err error) {
	t.Helper()
	out, err = WalkMIMEParts(ct, []byte(body), func(partHeaders, partBody []byte) []byte {
		leaves = append(leaves, walkerLeaf{
			contentType: ExtractHeader(string(partHeaders), "Content-Type"),
			body:        string(partBody),
		})
		return nil // keep: the reassembly must round-trip byte-for-byte
	})
	return leaves, out, err
}

// sameBody compares the walker's part body with the reference body, allowing
// exactly the one framing EOL the walker leaves attached.
func sameBody(t *testing.T, walkerBody, refBody string) bool {
	t.Helper()
	return walkerBody == refBody || walkerBody == refBody+"\r\n" || walkerBody == refBody+"\n"
}

// assertParity is the differential assertion for a body the reference parser
// renders: identical leaf count, identical content types, identical bodies
// (modulo the framing EOL), and byte-exact reassembly with a keep callback.
func assertParity(t *testing.T, ct string, body string) []walkerLeaf {
	t.Helper()
	refCTs, refBodies, refErr := referenceLeaves(t, ct, []byte(body))
	if refErr != nil {
		t.Fatalf("corpus bug: reference parser must render this body, got error: %v", refErr)
	}
	leaves, out, err := walkLeaves(t, ct, body)
	if err != nil {
		t.Fatalf("WalkMIMEParts failed on a renderable body: %v", err)
	}
	if len(leaves) != len(refBodies) {
		t.Fatalf("leaf count divergence: walker=%d reference=%d\n walker=%+v\n reference=%+v",
			len(leaves), len(refBodies), leaves, refBodies)
	}
	for i := range leaves {
		mtW, _, eW := mime.ParseMediaType(leaves[i].contentType)
		mtR, _, eR := mime.ParseMediaType(refCTs[i])
		switch {
		case eW == nil && eR == nil:
			if !strings.EqualFold(mtW, mtR) {
				t.Errorf("leaf[%d] media type divergence: walker=%q reference=%q", i, mtW, mtR)
			}
		case eW != nil && eR != nil:
			// both unparseable — same client-visible state
		default:
			t.Errorf("leaf[%d] content-type divergence: walker=%q (err=%v) reference=%q (err=%v)", i, leaves[i].contentType, eW, refCTs[i], eR)
		}
		if !sameBody(t, leaves[i].body, refBodies[i]) {
			t.Errorf("leaf[%d] body divergence:\n walker    =%q\n reference =%q", i, leaves[i].body, refBodies[i])
		}
	}
	if string(out) != body {
		t.Errorf("reassembly not byte-identical:\n got =%q\n want=%q", out, body)
	}
	return leaves
}

// assertFailClosed is the differential assertion for a body the reference
// parser CANNOT render: the walker must return an error (ambiguous parse
// state), never silently walk a decoy framing.
func assertFailClosed(t *testing.T, ct string, body string) {
	t.Helper()
	_, _, refErr := referenceLeaves(t, ct, []byte(body))
	if refErr == nil {
		t.Fatalf("corpus bug: expected the reference parser to reject this body")
	}
	_, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil })
	if err == nil {
		t.Fatalf("walker accepted a body the reference parser rejects (ref error: %v) — ambiguous parse state must fail closed", refErr)
	}
}

// ── Vector 1: boundary-prefix split ─────────────────────────────────────────
// A line-start "--alphabeta" is NOT a delimiter for boundary "alpha": a
// compliant parser requires the boundary token to be followed by optional
// linear whitespace and the line ending. The old splitter split on the
// prefix, inventing a part boundary the client never sees.

func TestWalkMIMEPartsParityBoundaryPrefixSplit(t *testing.T) {
	ct := `multipart/mixed; boundary="alpha"`
	body := "preamble\r\n" +
		"--alpha\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"line one\r\n" +
		"--alphabeta\r\n" +
		"line two\r\n" +
		"--alpha--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 {
		t.Fatalf("boundary-prefix split: expected 1 leaf, got %d", len(leaves))
	}
	if !strings.Contains(leaves[0].body, "--alphabeta\r\nline two") {
		t.Errorf("prefix lookalike line vanished from the part body: %q", leaves[0].body)
	}
}

// ── Vector 2: close-delimiter break ─────────────────────────────────────────
// "--b--decoy" at line start is neither a delimiter nor a close: the
// reference parser ends the part there and then fails ("expecting a new
// Part"). The old walker treated the segment after the prefix split as a
// close delimiter, silently STOPPED walking and never saw the straddled part
// that a renderer at least attempts — the exact scanner/client gap.

func TestWalkMIMEPartsFailClosedCloseDelimiterDecoy(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/one\">one</a>\r\n" +
		"--b--decoy\r\n" +
		"STRADDLED\r\n" +
		"--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/two\">two</a>\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

// ── Vector 6: wrong-convention close-delimiter anchor (med-shard2-021 item 2) ──
// After CRLF framing is locked by the first delimiter, the reference parser's
// part-body scan matches "\r\n--boundary" only: a bare-LF-anchored close
// lookalike ("safe\n--b--\r\n") is CONTENT there, and the reference parser
// continues. The old splitter anchored on any preceding LF, so the lookalike
// TERMINATED scanning — parts after it were never walked and the truncated
// part was treated as the whole message.

func TestWalkMIMEPartsParityWrongConventionCloseIsContent(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"safe\n--b--\r\n" + // LF-anchored close lookalike under CRLF framing: content
		"more text\r\n" +
		"--b--\r\n" // the real close delimiter
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	if !strings.Contains(leaves[0].body, "more text") {
		t.Errorf("walker terminated scanning at the LF-anchored lookalike; tail lost: %q", leaves[0].body)
	}
}

func TestWalkMIMEPartsFailClosedWrongConventionCloseTruncates(t *testing.T) {
	// Without a convention-correct close later, the reference parser's part
	// body runs to EOF and fails (unexpected EOF): the final part is not
	// client-renderable. The old walker happily "closed" at the LF-anchored
	// lookalike and walked a truncated framing.
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"safe\n--b--\r\n" +
		"<a href=\"https://evil.example/straddled\">straddled</a>\r\n"
	assertFailClosed(t, ct, body)
}

// ── Vector 7: whitespace before the closing "--" (med-shard2-021 item 2) ────
// isFinalBoundary matches the literal prefix "--boundary--": no linear
// whitespace may sit BETWEEN the boundary token and the closing dashes. A
// "--b --" line ends the part (matchAfterPrefix accepts the LWSP) and then
// fails the parse ("expecting a new Part"); it is never a close delimiter.

func TestWalkMIMEPartsFailClosedLWSPBeforeClosingDashes(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/one\">one</a>\r\n" +
		"--b --\r\n" + // LWSP before the closing dashes: part ends, parse fails
		"STRADDLED\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

func TestWalkMIMEPartsParityLWSPBeforeClosingDashesInPreamble(t *testing.T) {
	// Before the first delimiter the line is ignorable preamble content: the
	// reference parser skips it and renders the real part after it.
	ct := `multipart/mixed; boundary="b"`
	body := "--b --\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"real body\r\n" +
		"--b--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 || !strings.Contains(leaves[0].body, "real body") {
		t.Fatalf("preamble LWSP-dashes lookalike broke the real part: %+v", leaves)
	}
}

// ── Vector 8: LWSP+junk after the boundary token ────────────────────────────
// matchAfterPrefix accepts the boundary token followed by LWSP (part ends
// there); isBoundaryDelimiterLine then requires the rest of the line to be
// exactly the line ending. LWSP followed by junk therefore ends the part and
// fails the parse — the same decoy class as "--"+junk, not content.

func TestWalkMIMEPartsFailClosedLWSPThenJunkAfterBoundary(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/one\">one</a>\r\n" +
		"--b  junk\r\n" +
		"STRADDLED\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

// ── Vector 9: single dash after the token is content ────────────────────────
// matchAfterPrefix returns -1 for "--boundary-" (a single dash not followed by
// another): genuinely not a delimiter, plain content the reference parser
// renders inside the part body.

func TestWalkMIMEPartsParitySingleDashLookalikeIsContent(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"A\r\n" +
		"--b-x\r\n" +
		"B\r\n" +
		"--b--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 || !strings.Contains(leaves[0].body, "--b-x\r\nB") {
		t.Fatalf("single-dash lookalike must stay part content: %+v", leaves)
	}
}

// ── Vector 10: stray CR after the token ─────────────────────────────────────
// "\r" not followed by "\n" ends the part (matchAfterPrefix accepts CR) and
// the line then fails the parse — never a delimiter, never content.

func TestWalkMIMEPartsFailClosedStrayCRThenJunk(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/one\">one</a>\r\n" +
		"--b\rX\r\n" +
		"STRADDLED\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

// ── Vector 11: LF-terminated close line before any delimiter ────────────────
// The reference parser switches its line-ending convention on the first OPEN
// delimiter only; a close line while the convention is still the default CRLF
// is not a terminator there — the preamble skip drops it and the parse
// continues with the real delimiter after it.

func TestWalkMIMEPartsParityLFCloseBeforeAnyDelimiter(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b--\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"real body\r\n" +
		"--b--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 || !strings.Contains(leaves[0].body, "real body") {
		t.Fatalf("LF close lookalike before any delimiter broke the real part: %+v", leaves)
	}
}

func TestWalkMIMEPartsFailClosedLFCloseBeforeAnyDelimiterTruncates(t *testing.T) {
	// The same lookalike with nothing after it: the reference parser skips the
	// preamble line and fails at EOF (zero parts rendered); the walker must
	// not treat the LF close as a terminator framing an empty message.
	ct := `multipart/mixed; boundary="b"`
	if _, err := WalkMIMEParts(ct, []byte("--b--\n"), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Errorf("walker accepted a body whose only delimiter is an LF-terminated close lookalike")
	}
}

// ── Vector 3: non-recursive walk ────────────────────────────────────────────
// A nested multipart/alternative inside multipart/mixed is what compliant
// clients render leaf-by-leaf. The old walker handed the CONTAINER to the
// callback once, so leaf content inside it was never rewritten and never
// extracted.

func TestWalkMIMEPartsParityNestedMultipartRecursion(t *testing.T) {
	ct := `multipart/mixed; boundary="outer"`
	body := "--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=inner\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain https://evil.example/plain\r\n" +
		"--inner\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<i>https://evil.example/html</i>\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 2 {
		t.Fatalf("nested multipart: expected 2 leaves (plain, html), got %d: %+v", len(leaves), leaves)
	}
	if !strings.Contains(leaves[0].body, "https://evil.example/plain") ||
		!strings.Contains(leaves[1].body, "https://evil.example/html") {
		t.Errorf("nested leaves not both visible to the callback: %+v", leaves)
	}
	// Scanner visibility: body extraction must find text INSIDE the nesting.
	if got := ExtractBodyText("Content-Type: " + ct + "\r\n\r\n" + body); !strings.Contains(got, "https://evil.example/plain") {
		t.Errorf("ExtractBodyText missed the nested text/plain leaf: %q", got)
	}
	if got := ExtractBodyHTML("Content-Type: " + ct + "\r\n\r\n" + body); !strings.Contains(got, "https://evil.example/html") {
		t.Errorf("ExtractBodyHTML missed the nested text/html leaf: %q", got)
	}
}

// ── Vector 4: first-boundary decoy fallback ─────────────────────────────────
// When mime.ParseMediaType rejects the Content-Type, the old ExtractBoundary
// fallback substring-scanned for boundary= and happily adopted an
// attacker-chosen token (here the unterminated quote leaks into the
// boundary). The reference parser cannot frame the message at all, so the
// walker must fail closed instead of walking the decoy.

func TestWalkMIMEPartsFailClosedUnparseableContentType(t *testing.T) {
	ct := `multipart/mixed; boundary="unterminated`
	body := "--\"unterminated\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/decoy\">decoy</a>\r\n" +
		"--\"unterminated--\r\n"
	assertFailClosed(t, ct, body)
	// The strict extractor is the seam that closes the fallback decoy.
	if _, _, err := ExtractBoundaryStrict(ct); err == nil {
		t.Errorf("ExtractBoundaryStrict accepted an unparseable Content-Type %q", ct)
	}
}

// ── Vector 5: mixed-EOL header capture ──────────────────────────────────────
// Part headers terminated LF while the body contains CRLFCRLF: the old
// separator search preferred \r\n\r\n ANYWHERE, swallowing the first body
// line into partHeaders, so content before the body's first CRLFCRLF was
// invisible to the rewriting callback while a client rendered it.

func TestWalkMIMEPartsParityMixedEOLHeaderCapture(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\n" +
		"\n" +
		"<a href=\"https://evil.example/first\">first</a>\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/second\">second</a>\r\n" +
		"--b--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf, got %d", len(leaves))
	}
	for _, url := range []string{"https://evil.example/first", "https://evil.example/second"} {
		if !strings.Contains(leaves[0].body, url) {
			t.Errorf("mixed-EOL capture dropped %q from the part body: %q", url, leaves[0].body)
		}
	}
	if ctField := ExtractHeader("Content-Type: text/html", "Content-Type"); ctField != "text/html" {
		t.Fatalf("sanity: ExtractHeader broken: %q", ctField)
	}
	if leaves[0].contentType != "text/html" {
		t.Errorf("leaf content-type = %q, want text/html", leaves[0].contentType)
	}
}

// ── Hardening: part with content but no blank line ──────────────────────────
// net/textproto rejects a part whose first line is not a header and no blank
// line separates headers from body ("malformed MIME header: missing colon").
// The old walker silently skipped such parts (no callback, no error).

func TestWalkMIMEPartsFailClosedPartWithoutBlankLine(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/html\r\n" +
		"NO-BLANK-LINE <a href=\"https://evil.example/pay\">pay</a>\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

// ── Hardening: delimiter line-ending switch ─────────────────────────────────
// The reference parser fixes the line-ending convention on the FIRST
// delimiter line; a later delimiter line with the other convention is not a
// delimiter there (the message fails). Splitting on both is scanner/client
// divergence.

func TestWalkMIMEPartsFailClosedDelimiterEOLSwitch(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"first\r\n" +
		"--b\n" + // LF-terminated delimiter after a CRLF one
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"second\r\n" +
		"--b--\r\n"
	assertFailClosed(t, ct, body)
}

// ── Hardening: multipart framing with no delimiter lines at all ─────────────
// A multipart Content-Type whose body contains no delimiter line frames
// nothing; the reference parser renders zero parts. Treat it as ambiguous and
// fail closed rather than returning the body unchanged with nil error.

func TestWalkMIMEPartsFailClosedNoDelimiterLines(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "just text, no boundary lines at all\r\n"
	if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Errorf("walker accepted a multipart body with zero delimiter lines")
	}
}

// ── Hardening: unparseable NESTED multipart Content-Type ────────────────────
// The reference parser hands the container through as an opaque leaf and the
// renderer's fallback then differs per client — the scanner cannot establish
// which bytes a client would render, which is the definition of an ambiguous
// parse state. The walker fails closed.

func TestWalkMIMEPartsFailClosedUnparseableNestedContentType(t *testing.T) {
	ct := `multipart/mixed; boundary="outer"`
	body := "--outer\r\n" +
		`Content-Type: multipart/alternative; boundary="inner-unterminated` + "\r\n" +
		"\r\n" +
		"--\"inner-unterminated\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<a href=\"https://evil.example/nested-decoy\">nested</a>\r\n" +
		"--\"inner-unterminated--\r\n" +
		"--outer--\r\n"
	if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Errorf("walker accepted a nested multipart part whose Content-Type does not parse")
	}
}

// ── Hardening: nesting depth cap ────────────────────────────────────────────

func TestWalkMIMEPartsFailClosedNestingDepthCap(t *testing.T) {
	var b strings.Builder
	b.WriteString("--L0\r\nContent-Type: multipart/mixed; boundary=L1\r\n\r\n")
	for i := 1; i < 25; i++ {
		fmt.Fprintf(&b, "--L%d\r\nContent-Type: multipart/mixed; boundary=L%d\r\n\r\n", i, i+1)
	}
	b.WriteString("leaf body\r\n")
	ct := `multipart/mixed; boundary="L0"`
	if _, err := WalkMIMEParts(ct, []byte(b.String()), func(_, _ []byte) []byte { return nil }); err == nil {
		t.Errorf("walker accepted multipart nesting beyond the depth cap")
	}
}

// ── Benign preamble close-delimiter lookalike stays content ─────────────────
// Before the first real delimiter the reference parser skips preamble lines,
// so "--b--maybe" there is harmless content, not an error (and the old
// walker's prefix-split + close-break dropped the real part after it).

func TestWalkMIMEPartsParityPreambleCloseLookalike(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "hello\r\n" +
		"--b--maybe\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"real body\r\n" +
		"--b--\r\n"
	leaves := assertParity(t, ct, body)
	if len(leaves) != 1 || !strings.Contains(leaves[0].body, "real body") {
		t.Fatalf("preamble lookalike broke the real part: %+v", leaves)
	}
}

// ── Regression: common benign layouts are unchanged ─────────────────────────

func TestWalkMIMEPartsParityBenignCorpus(t *testing.T) {
	t.Run("flat CRLF with attachment", func(t *testing.T) {
		ct := `multipart/mixed; boundary="XYZ"`
		body := "preamble\r\n" +
			"--XYZ\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"hello world\r\n" +
			"--XYZ\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Content-Transfer-Encoding: base64\r\n" +
			"\r\n" +
			"SGVsbG8t--XYZ-d29ybGQ=\r\n" +
			"--XYZ--\r\n"
		assertParity(t, ct, body)
	})
	t.Run("flat LF-only message", func(t *testing.T) {
		ct := `multipart/mixed; boundary="b"`
		body := "--b\n" +
			"Content-Type: text/html\n" +
			"\n" +
			"<b>lf body</b>\n" +
			"--b--\n"
		assertParity(t, ct, body)
	})
	t.Run("transport padding on delimiters", func(t *testing.T) {
		ct := `multipart/mixed; boundary="b"`
		body := "--b  \r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"x\r\n" +
			"--b-- \t\r\n"
		assertParity(t, ct, body)
	})
	t.Run("epilogue after close delimiter is preserved byte-exact", func(t *testing.T) {
		// med-shard2-021 item 3: the reference parser renders nothing after
		// the close delimiter, but a keep-callback reassembly must reproduce
		// the FULL body including the epilogue (assertParity asserts
		// byte-exactness on the whole body).
		ct := `multipart/mixed; boundary="b"`
		body := "--b\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"real body\r\n" +
			"--b--\r\n" +
			"Any epilogue bytes a client never renders survive verbatim.\r\n"
		leaves := assertParity(t, ct, body)
		if len(leaves) != 1 {
			t.Fatalf("expected 1 leaf, got %d", len(leaves))
		}
	})
	t.Run("close delimiter at end of body without EOL", func(t *testing.T) {
		// The reference parser's isFinalBoundary accepts "--boundary--" at EOF
		// with no line ending; the walker must too.
		ct := `multipart/mixed; boundary="b"`
		body := "--b\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"trailing body\r\n" +
			"--b--"
		assertParity(t, ct, body)
	})
	t.Run("empty part between delimiters", func(t *testing.T) {
		ct := `multipart/mixed; boundary="b"`
		body := "--b\r\n" +
			"\r\n" +
			"--b--\r\n"
		assertParity(t, ct, body)
	})
	t.Run("nested benign round-trip", func(t *testing.T) {
		ct := `multipart/mixed; boundary="outer"`
		body := "--outer\r\n" +
			"Content-Type: multipart/alternative; boundary=inner\r\n" +
			"\r\n" +
			"--inner\r\n" +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"text body\r\n" +
			"--inner\r\n" +
			"Content-Type: text/html\r\n" +
			"\r\n" +
			"<i>html body</i>\r\n" +
			"--inner--\r\n" +
			"--outer--\r\n"
		assertParity(t, ct, body)
	})
}

// ── Hardening: missing close delimiter ──────────────────────────────────────
// RFC 2046 requires the close delimiter and the reference parser's part-body
// read fails with unexpected EOF at EOF before any terminator, so the final
// part of a close-less body is not client-renderable — EOL-terminated or not.

func TestWalkMIMEPartsFailClosedMissingCloseDelimiter(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	for name, body := range map[string]string{
		"eol-terminated": "--b\r\nContent-Type: text/plain\r\n\r\nno close delimiter, but EOL-terminated\r\n",
		"truncated":      "--b\r\nContent-Type: text/plain\r\n\r\nno close delimiter, no trailing newline",
	} {
		if _, err := WalkMIMEParts(ct, []byte(body), func(_, _ []byte) []byte { return nil }); err == nil {
			t.Errorf("%s: walker accepted a multipart body with no close delimiter", name)
		}
	}
}

// ── Regression: epilogue after the close delimiter is preserved but never walked ──
// med-shard2-021 item 3: the reassembly is byte-exact WITH a keep callback —
// the epilogue bytes survive — while the epilogue is never rendered by a
// compliant client and therefore never visited by the walk callback. The old
// assertions equated "not walked" with "deleted": the epilogue was dropped
// from the reassembly, violating the byte-exact contract.

func TestWalkMIMEPartsEpiloguePreservedNotWalked(t *testing.T) {
	ct := `multipart/mixed; boundary="b"`
	body := "--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"hi\r\n" +
		"--b--\r\n" +
		"EVIL-EPILOGUE\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"after close\r\n"
	var visited []string
	out, err := WalkMIMEParts(ct, []byte(body), func(_, pb []byte) []byte {
		visited = append(visited, string(pb))
		return nil // keep every part unchanged
	})
	if err != nil {
		t.Fatalf("WalkMIMEParts: %v", err)
	}
	if len(visited) != 1 || !strings.Contains(visited[0], "hi") {
		t.Fatalf("expected exactly the close-delimited leaf to be walked, got %+v", visited)
	}
	for _, v := range visited {
		if strings.Contains(v, "EVIL-EPILOGUE") || strings.Contains(v, "after close") {
			t.Errorf("content after the close delimiter was walked by the callback: %q", v)
		}
	}
	// Byte-exact reassembly WITH a keep callback: the epilogue survives.
	if string(out) != body {
		t.Errorf("reassembly not byte-identical (epilogue must be preserved, not deleted):\n got =%q\n want=%q", out, body)
	}
	// …but the epilogue content never becomes a walked leaf, even though it
	// carries a well-formed delimiter-plus-part shape a naive continuation
	// would parse.
}

// ── Regression: flat extraction is unchanged ────────────────────────────────

func TestWalkMIMEPartsFlatExtractionUnchanged(t *testing.T) {
	msg := "Content-Type: multipart/mixed; boundary=\"b\"\r\n" +
		"\r\n" +
		"--b\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"plain body here\r\n" +
		"--b--\r\n"
	if got := ExtractBodyText(msg); got != "plain body here" {
		t.Errorf("ExtractBodyText = %q, want %q", got, "plain body here")
	}
}
