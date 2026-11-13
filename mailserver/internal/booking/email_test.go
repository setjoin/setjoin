package booking

import (
	"mime"
	"net/mail"
	"strings"
	"testing"
)

// TestBookingEmail_StillWorks guards the established booking MIME surface.
func TestBookingEmail_StillWorks(t *testing.T) {
	mime, messageID := buildPlainMIME("owner@example.com", "Owner", "booker@example.com",
		"Confirm your booking: Test Page", "Please confirm.")
	for _, want := range []string{
		"From: \"Owner\" <owner@example.com>",
		"To: <booker@example.com>",
		"Subject: Confirm your booking: Test Page",
		"Content-Type: text/plain; charset=utf-8",
	} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q: %q", want, mime)
		}
	}
	if !strings.HasPrefix(messageID, "<booking-") {
		t.Errorf("Message-ID prefix wrong: %q", messageID)
	}
}

func TestBookingEmail_NewlineUnicodeTitleRemainsParseable(t *testing.T) {
	raw, _ := buildPlainMIME("owner@example.com", "", "booker@example.com",
		"Confirm your booking: 第一行\r\n第二行", "Please confirm.")
	if raw == "" {
		t.Fatal("booking MIME was empty")
	}
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse booking MIME: %v", err)
	}
	if got := len(msg.Header["Subject"]); got != 1 {
		t.Fatalf("Subject field count = %d, want 1", got)
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || decoded != "Confirm your booking: 第一行 第二行" {
		t.Fatalf("decoded Subject = %q, %v", decoded, err)
	}
}
