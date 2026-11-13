package jmap

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
)

// injectionDraft is the stored body-only draft the injected attachment rides on.
const injectionDraft = "From: alice@test.local\r\n" +
	"To: bob@test.local\r\n" +
	"Subject: hello\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"the body text\r\n"

// parseAssembledMIMEAtReceiver is the INDEPENDENT receiving side: it parses the assembled
// wire the way a third-party MX would (net/mail + mime/multipart) and returns
// the top-level header plus every MIME part header, so the tests can assert
// that no injected header or protocol structure survived emission.
func parseAssembledMIMEAtReceiver(t *testing.T, wire string) (mail.Header, []textproto.MIMEHeader) {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(wire))
	if err != nil {
		t.Fatalf("receiving parser could not read assembled message: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("top content-type = %q (%v)", mediaType, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var partHeaders []textproto.MIMEHeader
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("receiving parser part %d: %v", len(partHeaders)+1, err)
		}
		partHeaders = append(partHeaders, textproto.MIMEHeader(p.Header))
		io.Copy(io.Discard, p)
	}
	return msg.Header, partHeaders
}

// assertNoInjectedHeaders fails the test if any header-breaking octet or any of
// the injected header names survives anywhere in the emitted message — at the
// top level, in any part header map, or as raw wire text (the ":" makes a raw
// substring match impossible for base64 body noise).
func assertNoInjectedHeaders(t *testing.T, wire string, top mail.Header, parts []textproto.MIMEHeader) {
	t.Helper()
	for name := range top {
		if strings.EqualFold(name, "Bcc") || strings.EqualFold(name, "X-Injected") {
			t.Errorf("top-level injected header %q survived emission", name)
		}
	}
	for i, h := range parts {
		for name, vals := range h {
			if strings.EqualFold(name, "Bcc") || strings.EqualFold(name, "X-Injected") {
				t.Errorf("part %d injected header %q survived emission", i+1, name)
			}
			for _, v := range vals {
				if strings.ContainsAny(v, "\r\n\x00") {
					t.Errorf("part %d header %q value carries header-breaking octets: %q", i+1, name, v)
				}
			}
		}
	}
	for _, marker := range []string{"Bcc:", "X-Injected:"} {
		if strings.Contains(wire, marker) {
			t.Errorf("raw wire contains injected protocol structure %q", marker)
		}
	}
}

// decodeAttachmentPart re-reads the wire as a receiver would and returns the
// base64-decoded bytes of the LAST part (the attachment), proving emission
// safety did not corrupt the payload.
func decodeAttachmentPart(t *testing.T, wire string) []byte {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(wire))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse top content-type: %v", err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var last []byte
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("receiving parser: %v", err)
		}
		raw, _ := io.ReadAll(p)
		last = raw
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(string(last)))
	if err != nil {
		t.Fatalf("attachment base64 decode: %v", err)
	}
	return decoded
}

// TestAssembleMixedMIMEStoredMaliciousHeadersCannotInject is the pre-existing-row
// fixture: content_type/content_id values exactly as a pre-validation reducer
// stored them (CRLF-bearing) flow through emission and must arrive at an
// independent receiving MIME parser with no injected headers and no extra
// protocol structure — and the attachment payload must survive intact.
func TestAssembleMixedMIMEStoredMaliciousHeadersCannotInject(t *testing.T) {
	data := []byte("PDF-BYTES-plain")
	out, err := assembleMixedMIME(injectionDraft, []attachmentPart{
		{
			Filename:    "report.pdf",
			ContentType: "application/pdf\r\nBcc: victim@example.com\r\nX-Injected: yes",
			Disposition: "attachment",
			ContentID:   "cid1@test.local\r\nX-Injected: yes",
			Data:        data,
		},
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	top, parts := parseAssembledMIMEAtReceiver(t, out)
	if len(parts) != 2 {
		t.Fatalf("protocol structure changed: got %d parts, want 2 (body + attachment)", len(parts))
	}
	assertNoInjectedHeaders(t, out, top, parts)

	// The stored malicious content_type is rejected at emission in favor of the
	// neutral default; the malicious content_id is rejected by omitting it.
	att := parts[1]
	if ct := att.Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("malicious stored content_type emitted verbatim: %q", ct)
	}
	if cid := att.Get("Content-ID"); cid != "" {
		t.Errorf("malicious stored content_id emitted: %q", cid)
	}
	if got := decodeAttachmentPart(t, out); string(got) != string(data) {
		t.Errorf("attachment bytes round-trip mismatch: got %q", got)
	}
}

// TestAssembleMixedMIMEHeaderBreakingOctetCorpus drives the full header-breaking
// octet corpus through emission: bare LF, CRLF, bare CR, NUL, TAB, DEL and raw
// 8-bit bytes in content_type and content_id are all rejected (content_type
// falls back to application/octet-stream; content_id is omitted), so a newly
// persisted or pre-existing malicious value can never ride the wire.
func TestAssembleMixedMIMEHeaderBreakingOctetCorpus(t *testing.T) {
	ctCorpus := []string{
		"application/pdf\nX-Injected: yes",       // bare LF
		"application/pdf\r\nX-Injected: yes",     // CRLF
		"application/pdf\rX-Injected: yes",       // bare CR
		"application/pdf\x00X-Injected: yes",     // NUL
		"application/pdf\tX-Injected: yes",       // TAB
		"application/pdf\x7FX-Injected: yes",     // DEL
		"application/pdf\xC3\xA9X-Injected: yes", // raw 8-bit
	}
	for i, bad := range ctCorpus {
		out, err := assembleMixedMIME(injectionDraft, []attachmentPart{
			{Filename: "a.bin", ContentType: bad, Disposition: "attachment", Data: []byte("x")},
		})
		if err != nil {
			t.Fatalf("case %d: assemble: %v", i, err)
		}
		top, parts := parseAssembledMIMEAtReceiver(t, out)
		if len(parts) != 2 {
			t.Fatalf("case %d: protocol structure changed: %d parts", i, len(parts))
		}
		assertNoInjectedHeaders(t, out, top, parts)
		if ct := parts[1].Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("case %d: header-breaking content_type emitted verbatim: %q", i, ct)
		}
	}

	cidCorpus := []string{
		"cid1@test.local\nX-Injected: yes",
		"cid1@test.local\r\nX-Injected: yes",
		"cid1@test.local\rX-Injected: yes",
		"cid\x00@test.local",
		"cid\t@test.local",
		"cid\x7F@test.local",
		"cid\xC3\xA9@test.local",
	}
	for i, bad := range cidCorpus {
		out, err := assembleMixedMIME(injectionDraft, []attachmentPart{
			{Filename: "a.bin", ContentType: "application/pdf", Disposition: "attachment", ContentID: bad, Data: []byte("x")},
		})
		if err != nil {
			t.Fatalf("cid case %d: assemble: %v", i, err)
		}
		top, parts := parseAssembledMIMEAtReceiver(t, out)
		if len(parts) != 2 {
			t.Fatalf("cid case %d: protocol structure changed: %d parts", i, len(parts))
		}
		assertNoInjectedHeaders(t, out, top, parts)
		if cid := parts[1].Get("Content-ID"); cid != "" {
			t.Errorf("cid case %d: header-breaking content_id emitted: %q", i, cid)
		}
	}
}

// TestAssembleMixedMIMELegitimateContentTypeAndContentIDUnchanged pins the
// requirement that legitimate stored content_type/content_id values pass
// through emission verbatim, and that the pre-existing empty content_type
// default and absent content_id behavior are preserved.
func TestAssembleMixedMIMELegitimateContentTypeAndContentIDUnchanged(t *testing.T) {
	out, err := assembleMixedMIME(injectionDraft, []attachmentPart{
		{
			Filename:    "report.pdf",
			ContentType: `application/pdf; name="report.pdf"`,
			Disposition: "inline",
			ContentID:   "part1@test.local",
			Data:        []byte("PDF"),
		},
		{
			Filename:    "data.bin",
			ContentType: "",
			Disposition: "attachment",
			Data:        []byte("BIN"),
		},
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	top, parts := parseAssembledMIMEAtReceiver(t, out)
	if len(parts) != 3 {
		t.Fatalf("got %d parts, want 3", len(parts))
	}
	assertNoInjectedHeaders(t, out, top, parts)

	if ct := parts[1].Get("Content-Type"); ct != `application/pdf; name="report.pdf"` {
		t.Errorf("legitimate content_type changed: %q", ct)
	}
	if cid := parts[1].Get("Content-ID"); cid != "<part1@test.local>" {
		t.Errorf("legitimate content_id changed: %q", cid)
	}
	if ct := parts[2].Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("empty content_type default changed: %q", ct)
	}
	if cid := parts[2].Get("Content-ID"); cid != "" {
		t.Errorf("absent content_id should stay absent: %q", cid)
	}
}
