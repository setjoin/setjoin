package jmap

import (
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
)

func TestAssembleMixedMIME(t *testing.T) {
	draft := "From: alice@test.local\r\n" +
		"To: bob@test.local\r\n" +
		"Subject: hello\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"the body text\r\n"
	data := []byte("PDF-BYTES-\x00\x01\x02-here")
	out, err := assembleMixedMIME(draft, []attachmentPart{
		{Filename: "in voice.pdf", ContentType: "application/pdf", Disposition: "attachment", Data: data},
	})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	msg, err := mail.ReadMessage(strings.NewReader(out))
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	// Envelope headers preserved.
	if msg.Header.Get("Subject") != "hello" || msg.Header.Get("To") != "bob@test.local" {
		t.Errorf("envelope headers lost: %q / %q", msg.Header.Get("Subject"), msg.Header.Get("To"))
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("top content-type = %q (%v)", mediaType, err)
	}

	mr := multipart.NewReader(msg.Body, params["boundary"])
	// Part 1: the original body.
	p1, err := mr.NextPart()
	if err != nil {
		t.Fatalf("part1: %v", err)
	}
	if ct := p1.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("part1 content-type = %q", ct)
	}
	b1, _ := io.ReadAll(p1)
	if !strings.Contains(string(b1), "the body text") {
		t.Errorf("part1 body lost: %q", b1)
	}

	// Part 2: the attachment.
	p2, err := mr.NextPart()
	if err != nil {
		t.Fatalf("part2: %v", err)
	}
	if ct := p2.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Errorf("part2 content-type = %q", ct)
	}
	_, dparams, _ := mime.ParseMediaType(p2.Header.Get("Content-Disposition"))
	if dparams["filename"] != "in voice.pdf" {
		t.Errorf("part2 filename = %q (escaping lost)", dparams["filename"])
	}
	if p2.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Errorf("part2 not base64")
	}
	raw, _ := io.ReadAll(p2)
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(string(raw)), "\r\n", ""))
	if err != nil {
		t.Fatalf("part2 base64 decode: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("attachment bytes round-trip mismatch: got %q", decoded)
	}

	// No attachments → passthrough unchanged.
	if got, _ := assembleMixedMIME(draft, nil); got != draft {
		t.Errorf("empty attachments should passthrough")
	}
}
