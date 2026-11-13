package jmap

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"strings"
)

// writeBase64Wrapped base64-encodes data into RFC 2045 lines (<=76 chars, CRLF).
func writeBase64Wrapped(w io.Writer, data []byte) error {
	enc := base64.StdEncoding.EncodeToString(data)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		if _, err := io.WriteString(w, enc[i:end]+"\r\n"); err != nil {
			return err
		}
	}
	return nil
}

// attachmentPart is one outbound attachment with its bytes already fetched from S3.
type attachmentPart struct {
	Filename    string
	ContentType string
	Disposition string // "attachment" | "inline"
	ContentID   string // for inline parts (P1); empty otherwise
	Data        []byte
}

// containsHeaderBreakingOctets reports whether s carries any octet that cannot
// safely ride inside an emitted MIME header value: C0 controls (CR, LF, NUL,
// TAB, ...), DEL, or a raw 8-bit byte. Legitimate Content-Type media types and
// Content-ID msg-ids are printable US-ASCII, so the check never rejects a valid
// stored value. This is EMISSION-TIME defense: content_type/content_id were
// persisted without CR/LF validation, so already-stored malicious values must
// never reach the wire verbatim (header injection into outbound MIME).
func containsHeaderBreakingOctets(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return true
		}
	}
	return false
}

// assembleMixedMIME wraps a body-only RFC 5322 draft (the inline raw_ref the reducer
// stored) into a multipart/mixed message carrying the attachment parts. The draft's
// own headers are preserved verbatim EXCEPT the content headers (Content-Type,
// Content-Transfer-Encoding, MIME-Version), which describe the body and are demoted
// onto the first body part; the top level gets a fresh multipart/mixed Content-Type.
//
// This is the outbound counterpart of the inbound stored MIME: the bytes only exist
// here (Go can read MinIO; the PL/pgSQL reducer cannot), so wire assembly lives in Go.
func assembleMixedMIME(rawDraft string, parts []attachmentPart) (string, error) {
	if len(parts) == 0 {
		return rawDraft, nil // nothing to assemble
	}
	top, entity, err := assembleMixedParts(rawDraft, parts)
	if err != nil {
		return "", err
	}
	return top + "MIME-Version: 1.0\r\n" + entity, nil
}

// assembleMixedParts is assembleMixedMIME split into its two byte-blocks: the
// TOP-LEVEL header block (the draft's headers minus the content headers — no
// MIME-Version, no trailing blank line) and the MIME ENTITY (the multipart/mixed
// Content-Type header + blank line + multipart body). The full wire message is
// exactly top + "MIME-Version: 1.0\r\n" + entity.
//
// The split exists for the S/MIME sign path (buildSMIMEWire): the signature must
// be computed over the ENTITY — so the inner multipart/mixed Content-Type rides
// INSIDE the signed part and the receiver can parse the attachments out of the
// verified content — while the top-level headers stay outside the signature.
func assembleMixedParts(rawDraft string, parts []attachmentPart) (top, entity string, err error) {
	msg, err := mail.ReadMessage(strings.NewReader(rawDraft))
	if err != nil {
		return "", "", fmt.Errorf("parse draft: %w", err)
	}
	bodyBytes, err := io.ReadAll(msg.Body)
	if err != nil {
		return "", "", fmt.Errorf("read draft body: %w", err)
	}

	// The draft's content headers describe the body part, not the new envelope.
	bodyContentType := msg.Header.Get("Content-Type")
	if bodyContentType == "" {
		bodyContentType = "text/plain; charset=utf-8"
	}
	bodyCTE := msg.Header.Get("Content-Transfer-Encoding")

	// Top-level (envelope) headers: everything from the draft except the content
	// headers. Order is not significant.
	var topBuf bytes.Buffer
	for k, vs := range msg.Header {
		switch textproto.CanonicalMIMEHeaderKey(k) {
		case "Content-Type", "Content-Transfer-Encoding", "Mime-Version":
			continue
		}
		for _, v := range vs {
			fmt.Fprintf(&topBuf, "%s: %s\r\n", k, v)
		}
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary())

	// Part 1 — the original body, carrying its own content headers.
	bodyHdr := textproto.MIMEHeader{"Content-Type": {bodyContentType}}
	if bodyCTE != "" {
		bodyHdr.Set("Content-Transfer-Encoding", bodyCTE)
	}
	pw, err := mw.CreatePart(bodyHdr)
	if err != nil {
		return "", "", err
	}
	if _, err := pw.Write(bodyBytes); err != nil {
		return "", "", err
	}

	// Attachment parts — base64, with disposition + filename.
	for _, a := range parts {
		ct := a.ContentType
		// Reject stored content_type values carrying header-breaking octets at
		// emission: fall back to the neutral default instead of injecting them
		// into the wire (persist-time validation is additive, not a substitute).
		if ct == "" || containsHeaderBreakingOctets(ct) {
			ct = "application/octet-stream"
		}
		disp := a.Disposition
		if disp == "" {
			disp = "attachment"
		}
		h := textproto.MIMEHeader{
			"Content-Type":              {ct},
			"Content-Transfer-Encoding": {"base64"},
			// mime.FormatMediaType escapes the filename (MIME-injection / CR-LF safe).
			"Content-Disposition": {mime.FormatMediaType(disp, map[string]string{"filename": a.Filename})},
		}
		// Reject stored content_id values carrying header-breaking octets at
		// emission by omitting the header entirely; a CID reference to such a
		// value can never be legitimately honored, so nothing of it ships.
		if a.ContentID != "" && !containsHeaderBreakingOctets(a.ContentID) {
			h.Set("Content-ID", "<"+a.ContentID+">")
		}
		aw, err := mw.CreatePart(h)
		if err != nil {
			return "", "", err
		}
		if err := writeBase64Wrapped(aw, a.Data); err != nil {
			return "", "", err
		}
	}

	if err := mw.Close(); err != nil {
		return "", "", err
	}
	return topBuf.String(), buf.String(), nil
}
