package smtp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"setjoin.com/mailserver/internal/mimeutil"
	"setjoin.com/shared/envutil"
)

func extractAddr(s string) string            { return mimeutil.ExtractAddr(s) }
func extractHeader(body, name string) string { return mimeutil.ExtractHeader(body, name) }
func parseAddressList(s string) []byte       { return mimeutil.ParseAddressList(s) }
func parseFrom(s string) (name, addr string) { return mimeutil.ParseFrom(s) }
func extractBodyText(msg string) string      { return mimeutil.ExtractBodyText(msg) }
func extractBodyHTML(msg string) string      { return mimeutil.ExtractBodyHTML(msg) }
func randomID() string                       { return envutil.RandomID() }
func unfoldHeaders(s string) string          { return mimeutil.UnfoldHeaders(s) }

func splitHeadersBody(raw []byte) (headers []byte, body []byte) {
	if idx := bytes.Index(raw, []byte("\r\n\r\n")); idx >= 0 {
		return raw[:idx+2], raw[idx+4:]
	}
	if idx := bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		return raw[:idx+1], raw[idx+2:]
	}
	return raw, nil
}

// dkimCanonicalBody canonicalizes a body exactly the way dkimBodyHash does for
// the given c= tag (RFC 6376 §3.4 body canonicalization: "relaxed" or the
// default "simple"). The l= tag and every bh= hash are measured against THIS
// byte string, so any consumer that must relate l= to stored body bytes has to
// go through the same transformation.
func dkimCanonicalBody(body []byte, canonical string) []byte {
	mode := "simple"
	if parts := strings.Split(canonical, "/"); len(parts) >= 2 && parts[1] == "relaxed" {
		mode = "relaxed"
	}
	if mode == "relaxed" {
		return dkimRelaxedBody(body)
	}
	return dkimSimpleBody(body)
}

// dkimSignedBodyCut maps an authenticated DKIM body length from the
// CANONICALIZED byte space — the space the l= tag counts (RFC 6376 §3.5) and
// the only space the bh= hash covers — back to the STORED byte space of the
// message. The SMTP DATA intake (net/textproto DotReader) canonicalizes CRLF
// to LF before storage, while DKIM body canonicalization re-expands LF line
// breaks to CRLF (and, relaxed, strips/collapses WSP), so canonical lengths
// and stored lengths diverge line by line: a CRLF-heavy signed body yields an
// l= far larger than its stored form, and an attacker can hide appended
// unsigned content in exactly that gap (round 5, Astra HOLD — an l=1800
// signature over a body stored as 1429 LF bytes skipped the old
// `len(body) > l` fence entirely).
//
// The cut is the largest byte offset of the stored body whose canonicalized
// form still fits within limit canonical bytes — i.e. the longest processed
// prefix that is provably covered by the signature under the SAME
// transformation the signature was verified with. The canonical length of a
// prefix is monotone non-decreasing in the prefix length, so the cut is found
// by galloping + binary search over offsets. The result is exact or strictly
// shorter (never looser): at most the canonicalization's own two trailing-CRLF
// normalization bytes of SIGNED content are dropped, and content beyond the
// signed prefix is always cut away.
func dkimSignedBodyCut(body []byte, canonical string, limit int64) int64 {
	if limit <= 0 {
		return 0
	}
	if int64(len(dkimCanonicalBody(body, canonical))) <= limit {
		// The signature covers the canonicalized full body: nothing is
		// unsigned, no cut.
		return int64(len(body))
	}
	fits := func(o int) bool {
		return int64(len(dkimCanonicalBody(body[:o], canonical))) <= limit
	}
	if !fits(0) {
		return 0
	}
	// Gallop forward from a small offset to bracket the cut cheaply (typical
	// l= cuts sit far below the body size), then bisect inside the bracket.
	const step0 = 1024
	lo := 0
	for hi := step0; hi < len(body); {
		if !fits(hi) {
			break
		}
		lo = hi
		hi *= 2
	}
	hi := len(body)
	for lo < hi {
		mid := int(uint(lo+hi+1) >> 1)
		if fits(mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return int64(lo)
}

// extractICalPart locates the first text/calendar MIME part within the given
// MIME scope and returns the calendar body plus the index of the part it was
// found in — the 1-based ordinal inside the scope's outer multipart framing,
// 0 when no boundary= precedes the calendar (the scope is a single isolated
// part, e.g. an S/MIME-verified content part). start/end are the byte offsets
// of the returned calendar body within scope (round 8: the iMIP intake uses
// them to bind DKIM transport evidence to the calendar actually processed).
//
// Round 3 (Astra HOLD): the caller chooses the scope. The iMIP intake passes
// ONLY the S/MIME-verified content part — never the whole message — so a
// trailing unsigned part (e.g. METHOD:CANCEL after a signed REQUEST) can
// neither override nor be concatenated onto the signed calendar. Feeding this
// function an untrusted scope is the caller's decision, and its output is
// bounded by that scope: nothing beyond it can be returned.
func extractICalPart(scope string) (partIndex int, content string, start, end int64, err error) {
	lower := strings.ToLower(scope)
	idx := strings.Index(lower, "content-type: text/calendar")
	if idx < 0 {
		return 0, "", 0, 0, fmt.Errorf("no text/calendar part found")
	}

	partStart := idx
	for partStart > 0 && scope[partStart] != '\n' {
		partStart--
	}
	if partStart > 0 {
		partStart++
	}

	boundaryIdx := strings.Index(lower[:idx], "boundary=")
	if boundaryIdx < 0 {
		endIdx := strings.Index(scope[idx:], "\r\n--")
		if endIdx < 0 {
			endIdx = len(scope) - idx
		}
		return 0, scope[idx : endIdx+idx], int64(idx), int64(endIdx + idx), nil
	}

	boundaryVal := scope[boundaryIdx+9:]
	boundaryVal = strings.Trim(boundaryVal, " \t\";")
	if nlIdx := strings.IndexAny(boundaryVal, " \t\r\n;"); nlIdx > 0 {
		boundaryVal = boundaryVal[:nlIdx]
	}

	// partIndex = the ordinal of the part holding the calendar, counted as the
	// number of opening boundary delimiters before it (the part's own opener
	// is the last one counted; the closing delimiter "--boundary--" is not an
	// opener and must not count).
	partIndex = 0
	for pos := 0; pos < partStart; {
		i := strings.Index(scope[pos:partStart], "\n--"+boundaryVal)
		if i < 0 {
			break
		}
		i += pos + 1 // absolute index of "--"
		// Closing delimiter: "--boundaryVal" immediately followed by "--".
		// (Checking scope[i+1] here would only ever see this delimiter's own
		// second dash, which made every opener look like a closer and pinned
		// partIndex at 1 — a calendar in part N>1 was never indexed.)
		if closeAt := i + 2 + len(boundaryVal); closeAt+2 <= len(scope) && scope[closeAt:closeAt+2] == "--" {
			// closing delimiter, not an opener
		} else {
			partIndex++
		}
		pos = i + 1
		if pos >= partStart {
			break
		}
	}

	endMarker := "--" + boundaryVal + "--"
	endIdx := strings.Index(scope[partStart:], endMarker)
	if endIdx < 0 {
		endIdx = len(scope) - partStart
	} else {
		endIdx += len(endMarker)
	}

	content = scope[partStart : partStart+endIdx]

	headerEnd := strings.Index(content, "\r\n\r\n")
	if headerEnd < 0 {
		headerEnd = strings.Index(content, "\n\n")
		if headerEnd < 0 {
			return partIndex, content, int64(partStart), int64(partStart + len(content)), nil
		}
		content = content[headerEnd+2:]
		return partIndex, content, int64(partStart + headerEnd + 2), int64(partStart + endIdx), nil
	}
	content = content[headerEnd+4:]
	return partIndex, content, int64(partStart + headerEnd + 4), int64(partStart + endIdx), nil
}

func dotStuff(msg string) string {
	var b strings.Builder
	b.Grow(len(msg) + len(msg)/50)

	for i := 0; i < len(msg); i++ {
		ch := msg[i]

		// Normalize CR, CRLF, or LF to CRLF; dot-stuff after line ending.
		if ch == '\r' {
			if i+1 < len(msg) && msg[i+1] == '\n' {
				i++ // skip \n in \r\n
			}
			b.WriteString("\r\n")
			if i+1 < len(msg) && msg[i+1] == '.' {
				b.WriteByte('.')
			}
			continue
		}

		if ch == '\n' {
			b.WriteString("\r\n")
			if i+1 < len(msg) && msg[i+1] == '.' {
				b.WriteByte('.')
			}
			continue
		}

		// Dot-stuff at position 0 (start of message).
		if i == 0 && ch == '.' {
			b.WriteByte('.')
		}

		b.WriteByte(ch)
	}
	return b.String()
}

func validateLineLengths(data []byte) error {
	lines := bytes.Split(data, []byte("\n"))
	for i, line := range lines {
		l := len(line)
		if l > 0 && line[l-1] == '\r' {
			l--
		}
		if l > 998 {
			return fmt.Errorf("line %d exceeds 998 characters (%d)", i+1, l)
		}
	}
	return nil
}

const dnsTimeout = 5 * time.Second

// DNS lookup function variables — swappable for testing and for injecting
// the shared/dnsresolver DNSSEC-aware resolver. Defaults to net.DefaultResolver.

// LookupTXT resolves TXT records for a domain.
var LookupTXT func(domain string) ([]string, error) = defaultLookupTXT

// LookupMX resolves MX records for a domain.
var LookupMX func(domain string) ([]*net.MX, error) = defaultLookupMX

// LookupIP resolves A/AAAA records for a host.
var LookupIP func(host string) ([]net.IP, error) = defaultLookupIP

// LookupAddr resolves PTR records for an IP address.
var LookupAddr func(addr string) ([]string, error) = defaultLookupAddr

func defaultLookupTXT(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, domain)
}

func defaultLookupMX(domain string) ([]*net.MX, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupMX(ctx, domain)
}

func defaultLookupIP(host string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func defaultLookupAddr(addr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

// ResetDNSResolver restores the DNS lookup functions to their defaults.
func ResetDNSResolver() {
	LookupTXT = defaultLookupTXT
	LookupMX = defaultLookupMX
	LookupIP = defaultLookupIP
	LookupAddr = defaultLookupAddr
}

// lookupTXT delegates to the current LookupTXT function variable.
func lookupTXT(domain string) ([]string, error) { return LookupTXT(domain) }

// lookupMX delegates to the current LookupMX function variable.
func lookupMX(domain string) ([]*net.MX, error) { return LookupMX(domain) }

// lookupIP delegates to the current LookupIP function variable.
func lookupIP(host string) ([]net.IP, error) { return LookupIP(host) }

// lookupAddr delegates to the current LookupAddr function variable.
func lookupAddr(addr string) ([]string, error) { return LookupAddr(addr) }

// setDNSResolvers swaps in custom DNS lookup functions. Pass nil for any
// function to keep the current value. Prefer the dns_adapter.go UseDNSResolver
// for wiring a dnsresolver.Resolver at startup; this lower-level helper is for
// tests that need per-lookup-type control.
func setDNSResolvers(txt func(string) ([]string, error), mx func(string) ([]*net.MX, error), ip func(string) ([]net.IP, error), addr func(string) ([]string, error)) {
	if txt != nil {
		LookupTXT = txt
	}
	if mx != nil {
		LookupMX = mx
	}
	if ip != nil {
		LookupIP = ip
	}
	if addr != nil {
		LookupAddr = addr
	}
}

// spooledRead reads from r into a byte slice up to maxSize. Messages <= 1 MiB
// stay in memory; larger messages spill to a temp file to avoid memory pressure
// under concurrent deliveries.
// sandboxMIMETypes lists MIME types that warrant behavioral analysis.
// Office docs, PDFs, executables, and archives are high-risk for macro/script payloads.
var sandboxMIMETypes = []string{
	"application/pdf",
	"application/msword",
	"application/vnd.openxmlformats-officedocument",
	"application/vnd.ms-",
	"application/x-msdownload",
	"application/x-dosexec",
	"application/x-mach-binary",
	"application/x-elf",
	"application/x-executable",
	"application/zip",
	"application/x-rar-compressed",
	"application/x-7z-compressed",
	"application/x-tar",
	"application/gzip",
	"application/x-bzip2",
	"application/x-iso9660-image",
	"application/x-ole-storage",
	"application/x-java-archive",
}

// detectAttachmentTypes scans raw MIME for Content-Type headers matching high-risk
// types that warrant sandbox behavioral analysis. Returns deduplicated matches.
func detectAttachmentTypes(data []byte) []string {
	lower := strings.ToLower(string(data))
	seen := make(map[string]bool)
	var found []string

	searchStart := 0
	for {
		idx := strings.Index(lower[searchStart:], "content-type:")
		if idx < 0 {
			break
		}
		idx += searchStart
		// Move past "content-type:"
		valueStart := idx + len("content-type:")
		// Skip whitespace
		for valueStart < len(lower) && (lower[valueStart] == ' ' || lower[valueStart] == '\t') {
			valueStart++
		}
		// Extract until \r, \n, or ;
		valueEnd := valueStart
		for valueEnd < len(lower) && lower[valueEnd] != '\r' && lower[valueEnd] != '\n' && lower[valueEnd] != ';' {
			valueEnd++
		}
		mimeType := strings.TrimSpace(lower[valueStart:valueEnd])
		searchStart = valueEnd + 1

		if mimeType == "" {
			continue
		}

		// Check against allowlist prefixes
		for _, prefix := range sandboxMIMETypes {
			if strings.HasPrefix(mimeType, prefix) {
				if !seen[prefix] {
					seen[prefix] = true
					found = append(found, prefix)
				}
				break
			}
		}
	}
	return found
}

func spooledRead(r io.Reader, maxSize int) ([]byte, *os.File, error) {
	const memThreshold = 1 << 20 // 1 MiB

	// Read up to threshold into memory
	buf := make([]byte, memThreshold)
	n, err := io.ReadFull(r, buf)
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		return buf[:n], nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	// Spilled to disk — copy buffered prefix + remaining stream
	tmp, err := os.CreateTemp("", "smtp-inbound-*.eml")
	if err != nil {
		return nil, nil, err
	}
	if _, err := tmp.Write(buf[:n]); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	if _, err := io.CopyN(tmp, r, int64(maxSize-n+1)); err != nil && err != io.EOF {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}

	// Read back into memory for processing (could be further optimized
	// by mmap'ing, but this is a pragmatic fix for the OOM risk).
	if _, err := tmp.Seek(0, 0); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(tmp, int64(maxSize+1)))
	if err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, nil, err
	}
	return data, tmp, nil
}
