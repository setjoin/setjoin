// Package mimeutil provides shared MIME/email parsing functions used by
// SMTP delivery, JMAP handlers, and the admin import/export tool.
package mimeutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"strings"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// ExtractAddr extracts a bare email address from a header value.
func ExtractAddr(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if s[0] == '<' {
		if idx := strings.Index(s, ">"); idx > 0 {
			return s[1:idx]
		}
	}
	if idx := strings.Index(s, "<"); idx >= 0 {
		if end := strings.Index(s[idx:], ">"); end > 0 {
			return s[idx+1 : idx+end]
		}
	}
	return strings.Trim(s, "<>")
}

// ExtractHeader finds a named header in a raw MIME message body and returns
// its decoded value. Supports RFC 2047 encoded words and header unfolding (RFC 5322).
func ExtractHeader(body, name string) string {
	headerEnd := strings.Index(body, "\r\n\r\n")
	if headerEnd == -1 {
		headerEnd = strings.Index(body, "\n\n")
	}
	var headers string
	if headerEnd >= 0 {
		headers = body[:headerEnd]
	} else {
		headers = body
	}

	headers = UnfoldHeaders(headers)

	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.Index(line, ":"); i > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:i]), name) {
				val := strings.TrimSpace(line[i+1:])
				if decoded, err := new(mime.WordDecoder).Decode(val); err == nil {
					return decoded
				}
				return val
			}
		}
	}
	return ""
}

func UnfoldHeaders(headers string) string {
	lines := strings.Split(headers, "\n")
	var unfolded []string
	var buf string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			buf = strings.TrimRight(buf, "\r") + " " + strings.TrimSpace(line)
		} else {
			if buf != "" {
				unfolded = append(unfolded, buf)
			}
			buf = line
		}
	}
	if buf != "" {
		unfolded = append(unfolded, buf)
	}
	return strings.Join(unfolded, "\n")
}

// ParseAddressList parses an RFC 5322 address list header into a JSON array
// of {name, email} objects as raw bytes.
func ParseAddressList(s string) []byte {
	if s == "" {
		return []byte("[]")
	}
	addrs, err := mail.ParseAddressList(s)
	var out []string
	if err != nil {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				name, email := ParseFrom(p)
				out = append(out, formatAddress(name, email))
			}
		}
		return []byte("[" + strings.Join(out, ",") + "]")
	}
	for _, a := range addrs {
		out = append(out, formatAddress(a.Name, a.Address))
	}
	return []byte("[" + strings.Join(out, ",") + "]")
}

func formatAddress(name, email string) string {
	if name == "" {
		return fmt.Sprintf(`{"email":%s}`, jsonString(email))
	}
	return fmt.Sprintf(`{"name":%s,"email":%s}`, jsonString(name), jsonString(email))
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// ParseFrom splits a single address into display name and email.
func ParseFrom(s string) (name, addr string) {
	if s == "" {
		return "", ""
	}
	a, err := mail.ParseAddress(s)
	if err != nil {
		return "", ExtractAddr(s)
	}
	return a.Name, a.Address
}

// ExtractBoundary parses a Content-Type header value and returns the MIME boundary.
func ExtractBoundary(contentType string) string {
	_, params, err := mime.ParseMediaType(contentType)
	if err == nil && params["boundary"] != "" {
		return params["boundary"]
	}
	// Fallback: simple string search for boundary=
	lower := strings.ToLower(contentType)
	if idx := strings.Index(lower, "boundary="); idx >= 0 {
		rest := contentType[idx+9:] // skip "boundary="
		if len(rest) > 0 && rest[0] == '"' {
			if end := strings.Index(rest[1:], "\""); end >= 0 {
				return rest[1 : end+1]
			}
		}
		end := strings.IndexAny(rest, " ;\r\n\t")
		if end < 0 {
			end = len(rest)
		}
		return strings.TrimSpace(rest[:end])
	}
	return ""
}

// ExtractBoundaryStrict is the fail-closed boundary extractor used by every
// MIME walk that gates delivery (D-MAILSERVER-INTERNAL-MIMEUTIL-001). Unlike
// ExtractBoundary it never falls back to substring scavenging: a Content-Type
// the standard parser rejects is exactly the first-boundary-decoy state — an
// attacker-chosen token from an unparseable header — and a compliant client
// cannot frame the message at all, so the caller must treat it as an error,
// not walk a decoy boundary.
//
// Returns (boundary, true, nil) for a parsable multipart type, and
// ("", false, nil) when the type parses but is not multipart (the caller
// decides what a non-multipart body means for it). Every other state is an
// error.
func ExtractBoundaryStrict(contentType string) (boundary string, isMultipart bool, err error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", false, fmt.Errorf("mimeutil: Content-Type %q does not parse: %w", contentType, err)
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(mediaType)), "multipart/") {
		return "", false, nil
	}
	boundary = params["boundary"]
	if boundary == "" {
		return "", true, fmt.Errorf("mimeutil: multipart Content-Type %q has no boundary parameter", contentType)
	}
	return boundary, true, nil
}

// mimeSegment is one framing segment of a multipart body produced by
// splitMultipart: the raw bytes that follow a delimiter token, up to (but not
// including) the next delimiter token. segs[0] is the preamble (before the
// first delimiter); every later segment opens with the remainder of its
// delimiter line (usually just its EOL), which keeps keep-callback reassembly
// byte-exact. The close segment is the close line plus the entire epilogue:
// reassembly reproduces every input byte while the walk callback never sees
// the epilogue.
type mimeSegment struct {
	raw     []byte
	isClose bool // the delimiter that opens this segment is the close delimiter
}

type delimKind int

const (
	delimNone       delimKind = iota // open-delimiter lookalike: part content
	delimOpen                        // a delimiter line opening a part
	delimClose                       // the final delimiter line
	delimDecoyClose                  // a close-delimiter lookalike ("--b--junk")
)

// skipLWSP returns b with leading linear whitespace (SPACE / HTAB) removed.
func skipLWSP(b []byte) int {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return i
}

// matchEOL returns the line ending at the start of b ("\r\n" or "\n") and its
// length, or ("", 0).
func matchEOL(b []byte) (string, int) {
	if len(b) >= 2 && b[0] == '\r' && b[1] == '\n' {
		return "\r\n", 2
	}
	if len(b) >= 1 && b[0] == '\n' {
		return "\n", 1
	}
	return "", 0
}

// classifyDelimiterRest inspects the bytes that follow a line-anchored
// "--"+boundary token, mirroring the standard library's delimiter matchers
// exactly (mime/multipart matchAfterPrefix + isBoundaryDelimiterLine /
// isFinalBoundary, med-shard2-021 item 2):
//
//	open          EOL                             a delimiter line opening a part
//	open          [ \t]+ EOL                      transport padding before the EOL
//	close   "--"  [ \t]* EOL                      the final delimiter line
//	close   "--"  [ \t]* <end of body>            the final delimiter line at EOF
//	decoy   "--"  <anything else>                 "--"+junk: the reference parser ends the part there, then fails
//	decoy   [ \t] <anything but EOL/"--">         LWSP+junk: the reference parser ends the part there, then fails
//	decoy   "\r"  <not LF>                        stray CR: same part-ends-then-fails state
//	none    <anything else>                       an open-delimiter lookalike (content)
//
// The closing "--" must sit IMMEDIATELY after the boundary token
// (isFinalBoundary matches dashBoundaryDash as a prefix — the previous
// skipLWSP before the dashes accepted "--b --", a line the reference parser
// treats as part content at best and a failed parse at worst). LWSP after the
// boundary token is accepted only up to a line ending (transport padding on an
// open delimiter); LWSP followed by anything else ends the part at the token
// (matchAfterPrefix +1) and then the line fails the parse — a decoy, never
// content. The same for "--"+junk and a stray "\r". A boundary token followed
// by ANY OTHER byte (including a single "-" not followed by "-") is
// matchAfterPrefix -1: genuinely not a delimiter, i.e. content.
//
// conv reports the line-ending convention of the delimiter line ("\r\n",
// "\n", or "" at end of body).
func classifyDelimiterRest(rest []byte) (kind delimKind, conv string, lineLen int) {
	if len(rest) == 0 {
		// Token at end of body with no terminator: matchAfterPrefix treats
		// "needs more input" as a non-match, so this is content — the parse
		// fails later on the missing close delimiter.
		return delimNone, "", 0
	}
	switch c := rest[0]; {
	case c == '-' && len(rest) >= 2 && rest[1] == '-':
		tail := rest[2:]
		k := skipLWSP(tail)
		if eol, n := matchEOL(tail[k:]); n > 0 {
			return delimClose, eol, 2 + k + n
		}
		if len(tail) == k {
			return delimClose, "", 2 + k
		}
		return delimDecoyClose, "", 0
	case c == ' ' || c == '\t':
		j := skipLWSP(rest)
		if eol, n := matchEOL(rest[j:]); n > 0 {
			return delimOpen, eol, j + n
		}
		return delimDecoyClose, "", 0
	case c == '\r':
		if eol, n := matchEOL(rest); n > 0 {
			return delimOpen, eol, n
		}
		return delimDecoyClose, "", 0
	case c == '\n':
		return delimOpen, "\n", 1
	default:
		return delimNone, "", 0
	}
}

// delimiterLineAnchored reports whether a "--boundary" candidate at offset i
// sits at the start of a line the reference parser scans at this point. Before
// the first delimiter (eol == "") the reference parser reads preamble lines by
// splitting at '\n', so any line start anchors. Afterwards the part-body scan
// matches nlDashBoundary — the CONVENTION-LOCKED line ending plus the boundary
// token: once CRLF framing is locked, only "\r\n--boundary" terminates a part
// (a bare-LF-preceded lookalike such as "safe\n--b--\r\n" is content there,
// exactly where the reference parser continues); once LF is locked, any
// preceding '\n' anchors ("\r\n" ends with '\n', and the reference parser's
// "\n--boundary" scan matches inside it).
func delimiterLineAnchored(body []byte, i int, eol string) bool {
	if i == 0 {
		return true // the reference parser also accepts a delimiter at body start
	}
	if body[i-1] != '\n' {
		return false
	}
	if eol == "\r\n" {
		return i >= 2 && body[i-2] == '\r'
	}
	return true
}

// splitMultipart frames body into RFC 2046 delimiter-delimited segments using
// the boundary from the Content-Type. A candidate counts as a delimiter only
// when delimiterLineAnchored anchors it AND the rest of the line is valid
// delimiter syntax (classifyDelimiterRest) — so a mid-line lookalike inside a
// base64 or binary part body never splits, a boundary-prefix lookalike line
// ("--alphabeta" for boundary "alpha") stays content exactly as a compliant
// client renders it, and a delimiter line of the wrong line-ending convention
// is not a delimiter at all.
//
// Fail-closed framing (D-MAILSERVER-INTERNAL-MIMEUTIL-001): the states where
// the reference parser ends a part and then fails — a close-delimiter or
// LWSP-junk lookalike after the first real delimiter, and a delimiter line
// that switches the line-ending convention mid-message — return an error so
// delivery callers quarantine instead of walking a framing no client agrees
// with. Scanning stops at the real close delimiter; the epilogue after it is
// never visited by the walk callback (no client renders it) and is preserved
// byte-exact in the close segment.
func splitMultipart(body []byte, boundary string) ([]mimeSegment, error) {
	delim := []byte("--" + boundary)
	var (
		segs   []mimeSegment
		start  = 0    // start of the current segment
		search = 0    // scan cursor
		eol    string // line-ending convention fixed by the first real delimiter
	)
	for {
		i := bytes.Index(body[search:], delim)
		if i < 0 {
			break
		}
		i += search
		if !delimiterLineAnchored(body, i, eol) {
			// Wrong-convention or mid-line lookalike: not a delimiter, keep
			// the segment intact.
			search = i + len(delim)
			continue
		}
		kind, conv, _ := classifyDelimiterRest(body[i+len(delim):])
		switch kind {
		case delimOpen:
			if conv != "" {
				if eol == "" {
					eol = conv
				} else if conv != eol {
					return nil, fmt.Errorf("mimeutil: delimiter line-ending switches from %q to %q at offset %d", eol, conv, i)
				}
			}
			segs = append(segs, mimeSegment{raw: body[start:i]})
			start = i + len(delim)
			search = start
		case delimClose:
			// conv == "" means the close delimiter sits at end of body with no
			// line ending at all — the reference parser's isFinalBoundary
			// accepts that regardless of the locked convention, so no
			// convention check applies. Otherwise: before any delimiter line
			// the reference parser has not yet switched its line-ending
			// convention (the switch fires on the first OPEN delimiter line),
			// so an LF-terminated close line there is not a terminator — the
			// reference parser's preamble skip drops the line and the parse
			// continues. With a convention already locked, a close line of the
			// other convention is the mid-message switch state: fail closed.
			if conv != "" {
				if eol == "" {
					if conv == "\n" {
						search = i + len(delim)
						continue
					}
					eol = conv
				} else if conv != eol {
					return nil, fmt.Errorf("mimeutil: delimiter line-ending switches from %q to %q at offset %d", eol, conv, i)
				}
			}
			segs = append(segs, mimeSegment{raw: body[start:i]})
			start = i + len(delim)
			// The close segment carries the close line AND everything after
			// it: the epilogue is never rendered by a compliant client and
			// never visited by the walk callback, but keeping it in the
			// reassembly preserves the byte-exact contract (med-shard2-021
			// item 3 — the epilogue bytes must survive a keep-everything walk).
			segs = append(segs, mimeSegment{raw: body[start:], isClose: true})
			return segs, nil
		case delimDecoyClose:
			// A close-delimiter or LWSP-junk lookalike at line start: the
			// reference parser ends the current part there and then fails, so
			// nothing after it is client-renderable. Before the first real
			// delimiter it is ignorable preamble content (the reference parser
			// skips preamble lines); after one it is an ambiguous parse state.
			if len(segs) > 0 {
				return nil, fmt.Errorf("mimeutil: close-delimiter lookalike at offset %d (content after it is not client-renderable)", i)
			}
			search = i + len(delim) + 2
		default: // delimNone: an open-delimiter lookalike is part content
			search = i + len(delim)
		}
	}
	// No close delimiter anywhere: RFC 2046 requires it, and the reference
	// parser's part-body read fails with ErrUnexpectedEOF at EOF before any
	// terminator — the final part is not client-renderable. Ambiguous frame,
	// fail closed (D-MAILSERVER-INTERNAL-MIMEUTIL-001).
	return nil, fmt.Errorf("mimeutil: multipart body has no close delimiter for boundary %q", boundary)
}

// maxMIMENestingDepth bounds recursion into nested multipart containers; a
// legitimate message never approaches it, while attacker-crafted nesting at
// depth is an ambiguous framing a compliant client may refuse to render.
const maxMIMENestingDepth = 20

// WalkMIMEParts parses a multipart MIME body, calls fn for each LEAF part,
// and reassembles the parts. fn receives the part headers and body; it
// returns the replacement body (nil means keep original). The contentType
// parameter is the Content-Type header value containing the boundary.
//
// Conformance and fail-closed behavior (D-MAILSERVER-INTERNAL-MIMEUTIL-001):
// the framing follows the standard library's multipart matchers exactly, so
// the scanner sees the parts a compliant client renders — nested multipart
// containers are recursed into (fn never sees a container, only leaves), a
// boundary-prefix lookalike line is content, and transport padding is
// accepted. Ambiguous states — an unparseable or boundary-less (nested)
// multipart Content-Type, a close-delimiter lookalike, a mid-message
// delimiter line-ending switch, a part with no header/body blank line, or a
// multipart body with no delimiter lines at all — return an ERROR instead of
// a nil-error partial walk. Delivery callers must treat that error as
// fail-closed (quarantine), never as "deliver the original".
//
// Byte-exact reassembly: with a keep callback the output is the input,
// byte-for-byte — including the preamble and the epilogue after the close
// delimiter, neither of which is ever visited by fn.
func WalkMIMEParts(contentType string, body []byte, fn func(partHeaders []byte, partBody []byte) []byte) ([]byte, error) {
	boundary, isMultipart, err := ExtractBoundaryStrict(contentType)
	if err != nil {
		return nil, err
	}
	if !isMultipart {
		return nil, fmt.Errorf("mimeutil: WalkMIMEParts needs a multipart Content-Type, got %q", contentType)
	}
	return walkMIMEParts(boundary, body, fn, 0)
}

func walkMIMEParts(boundary string, body []byte, fn func(partHeaders []byte, partBody []byte) []byte, depth int) ([]byte, error) {
	if depth >= maxMIMENestingDepth {
		return nil, fmt.Errorf("mimeutil: multipart nesting deeper than %d levels", maxMIMENestingDepth)
	}
	segs, err := splitMultipart(body, boundary)
	if err != nil {
		return nil, err
	}
	// A multipart Content-Type whose body contains no delimiter line frames
	// nothing: the reference parser renders zero parts, so there is no part
	// decomposition the scanner could verify against — ambiguous, fail closed.
	if len(segs) < 2 {
		return nil, fmt.Errorf("mimeutil: multipart body has no boundary delimiter lines for boundary %q", boundary)
	}

	delim := []byte("--" + boundary)
	var buf bytes.Buffer
	buf.Write(segs[0].raw) // preamble (before first boundary)

	for i := 1; i < len(segs); i++ {
		seg := segs[i]
		buf.Write(delim)
		if seg.isClose {
			// Final delimiter line plus the epilogue: the epilogue is never
			// rendered by a compliant client and never visited by the
			// callback, but it is part of the byte-exact reassembly.
			buf.Write(seg.raw)
			return buf.Bytes(), nil
		}

		partHeaders, sep, partBody, err := splitPartHeaders(seg.raw)
		if err != nil {
			return nil, err
		}
		if nestedCT, nested, err := multipartChildContentType(partHeaders); err != nil {
			return nil, err
		} else if nested {
			nestedOut, err := walkMIMEPartsFromCT(nestedCT, partBody, fn, depth+1)
			if err != nil {
				return nil, err
			}
			buf.Write(partHeaders)
			buf.Write(sep)
			buf.Write(nestedOut)
			continue
		}

		// The framing EOL that precedes the next delimiter line belongs to the
		// frame, not to the part body: the callback sees exactly the bytes a
		// compliant client renders as the part body (the reference parser
		// consumes the framing EOL), and a replacement body must not swallow
		// the EOL either — otherwise the close delimiter line merges into the
		// rewritten part and the delivered message stops being well-formed
		// MIME (unwalkable by every later parser pass, including our own).
		leafBody, framingEOL := splitTrailingEOL(partBody)
		newBody := fn(partHeaders, leafBody)
		buf.Write(partHeaders)
		buf.Write(sep)
		if newBody != nil {
			buf.Write(newBody)
			buf.Write(framingEOL)
		} else {
			buf.Write(partBody) // keep: byte-exact
		}
	}
	// Unreachable in practice: splitMultipart either returns at the close
	// delimiter or fails closed on its absence; kept as a safety net.
	return buf.Bytes(), nil
}

// walkMIMEPartsFromCT extracts the boundary from a nested part's Content-Type
// and recurses. It exists so the strict extraction error can name the nesting
// level's Content-Type.
func walkMIMEPartsFromCT(contentType string, body []byte, fn func(partHeaders []byte, partBody []byte) []byte, depth int) ([]byte, error) {
	boundary, isMultipart, err := ExtractBoundaryStrict(contentType)
	if err != nil {
		return nil, err
	}
	if !isMultipart {
		return nil, fmt.Errorf("mimeutil: nested multipart part has non-multipart Content-Type %q", contentType)
	}
	return walkMIMEParts(boundary, body, fn, depth)
}

// multipartChildContentType reports whether a part's headers make it a nested
// multipart container a compliant client would recurse into. An unparseable
// multipart Content-Type fails closed: the client-side rendering of such a
// container is renderer-dependent fallback behavior, so the scanner cannot
// establish which bytes would be displayed. A NON-multipart Content-Type that
// fails to parse is an ordinary leaf (the callback sees the raw headers and
// decides), preserving behavior for benign malformed leaf parts.
func multipartChildContentType(partHeaders []byte) (contentType string, isMultipart bool, err error) {
	raw := ExtractHeader(string(partHeaders), "Content-Type")
	if raw == "" {
		return "", false, nil
	}
	mediaType, params, err := mime.ParseMediaType(raw)
	if err != nil {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(raw)), "multipart/") {
			return "", true, fmt.Errorf("mimeutil: nested multipart Content-Type %q does not parse: %w", raw, err)
		}
		return "", false, nil
	}
	if !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		return "", false, nil
	}
	if params["boundary"] == "" {
		return "", true, fmt.Errorf("mimeutil: nested multipart Content-Type %q has no boundary parameter", raw)
	}
	return raw, true, nil
}

// splitTrailingEOL splits one trailing line ending ("\r\n" or "\n") off b:
// the remainder and the EOL ("", nil when b has no trailing EOL).
func splitTrailingEOL(b []byte) (rest, eol []byte) {
	if n := len(b); n >= 2 && b[n-2] == '\r' && b[n-1] == '\n' {
		return b[:n-2], b[n-2:]
	}
	if n := len(b); n >= 1 && b[n-1] == '\n' {
		return b[:n-1], b[n-1:]
	}
	return b, nil
}

// splitPartHeaders locates the header/body split of one MIME part segment
// (which opens with the delimiter line's own EOL). The separator is the
// EARLIEST double-EOL of either line-ending convention — preferring
// "\r\n\r\n" anywhere would mis-capture a part whose headers end LF while its
// body contains CRLFCRLF, swallowing body bytes into partHeaders where the
// rewriting callback never sees them (mixed-EOL header capture vector).
//
// A segment with content but no blank line is an ambiguous parse state: the
// standard library's header reader rejects the part ("malformed MIME header"),
// so it fails closed rather than silently skipping the part.
func splitPartHeaders(seg []byte) (partHeaders, sep, partBody []byte, err error) {
	crlf := bytes.Index(seg, []byte("\r\n\r\n"))
	lf := bytes.Index(seg, []byte("\n\n"))
	switch {
	case crlf >= 0 && (lf < 0 || crlf < lf):
		return seg[:crlf], seg[crlf : crlf+4], seg[crlf+4:], nil
	case lf >= 0:
		return seg[:lf], seg[lf : lf+2], seg[lf+2:], nil
	}
	return nil, nil, nil, fmt.Errorf("mimeutil: part has no header/body blank line (segment %q)", clipBytes(seg, 64))
}

// clipBytes bounds an error echo so a hostile part cannot bloat logs.
func clipBytes(b []byte, max int) string {
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "…"
}

// ExtractBodyText extracts the first text/plain part from a MIME message,
// with charset decoding to UTF-8.
func ExtractBodyText(msg string) string {
	// SplitN(..., 2): the body itself contains blank-line separators (e.g. between
	// paragraphs), so an unbounded Split would return only the text up to the SECOND
	// blank line, silently truncating the body. Stop at the first header/body separator.
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) < 2 {
		parts = strings.SplitN(msg, "\n\n", 2)
	}
	if len(parts) < 2 {
		return ""
	}
	ct := ExtractHeader(msg, "Content-Type")
	if strings.Contains(strings.ToLower(ct), "multipart") {
		headerEnd := strings.Index(msg, "\r\n\r\n")
		bodySepLen := 4
		if headerEnd < 0 {
			headerEnd = strings.Index(msg, "\n\n")
			bodySepLen = 2
		}
		if headerEnd < 0 {
			return ""
		}
		body := []byte(msg[headerEnd+bodySepLen:])

		var found string
		_, _ = WalkMIMEParts(ct, body, func(partHeaders []byte, partBody []byte) []byte {
			if found == "" && bytes.Contains(bytes.ToLower(partHeaders), []byte("content-type: text/plain")) {
				partCT := ExtractHeader(string(partHeaders), "Content-Type")
				found = DecodeCharset(strings.TrimSpace(string(partBody)), partCT)
			}
			return nil
		})
		return found
	}
	return DecodeCharset(strings.TrimSpace(parts[1]), ct)
}

// ExtractBodyHTML extracts the first text/html part from a MIME message,
// with charset decoding to UTF-8.
func ExtractBodyHTML(msg string) string {
	ct := ExtractHeader(msg, "Content-Type")
	if strings.Contains(strings.ToLower(ct), "multipart") {
		headerEnd := strings.Index(msg, "\r\n\r\n")
		bodySepLen := 4
		if headerEnd < 0 {
			headerEnd = strings.Index(msg, "\n\n")
			bodySepLen = 2
		}
		if headerEnd < 0 {
			return ""
		}
		body := []byte(msg[headerEnd+bodySepLen:])

		var found string
		_, _ = WalkMIMEParts(ct, body, func(partHeaders []byte, partBody []byte) []byte {
			if found == "" && bytes.Contains(bytes.ToLower(partHeaders), []byte("content-type: text/html")) {
				partCT := ExtractHeader(string(partHeaders), "Content-Type")
				found = DecodeCharset(strings.TrimSpace(string(partBody)), partCT)
			}
			return nil
		})
		return found
	}
	if strings.Contains(strings.ToLower(ct), "text/html") {
		// SplitN(..., 2): see ExtractBodyText — a blank line inside the HTML body must
		// not truncate it; stop at the first header/body separator.
		parts := strings.SplitN(msg, "\r\n\r\n", 2)
		if len(parts) < 2 {
			parts = strings.SplitN(msg, "\n\n", 2)
		}
		if len(parts) >= 2 {
			return DecodeCharset(strings.TrimSpace(parts[1]), ct)
		}
	}
	return ""
}

// DecodeCharset converts a MIME body to UTF-8 using the charset parameter
// from the Content-Type header.
func DecodeCharset(body, contentType string) string {
	if body == "" {
		return body
	}
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return body
	}
	charset := strings.ToLower(params["charset"])
	if charset == "" || charset == "utf-8" || charset == "us-ascii" {
		return body
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return body
	}
	r := transform.NewReader(strings.NewReader(body), enc.NewDecoder())
	decoded, err := io.ReadAll(r)
	if err != nil {
		return body
	}
	return string(decoded)
}
