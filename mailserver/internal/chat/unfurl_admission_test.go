package chat

// Detached-unfurl admission bound tests (er5-s15, sealed anchor chat-unfurl-
// can-launch-unbounded-detached-fetch-and-storage-work): the send seam must
// admit detached unfurl work under a process-wide fixed-window cap, so a
// script minting URL-bearing sends cannot launch unbounded detached fetch and
// storage work. Excess sends skip enrichment silently (best-effort by
// contract) and their sends still succeed.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/httputil"
	"setjoin.com/shared/toggle"
)

// TestUnfurlAdmission_BoundedPerSender: exactly maxUnfurlTriggersPerWindow
// triggers are admitted per sender per window; everything past the cap within
// the same window is refused.
func TestUnfurlAdmission_BoundedPerSender(t *testing.T) {
	detachedUnfurlAdmission = map[int64]*unfurlAdmission{} // fresh table for this test
	now := time.Now()
	admitted := 0
	for i := 0; i < maxUnfurlTriggersPerWindow*3; i++ {
		if admitDetachedUnfurl(900001, now) {
			admitted++
		}
	}
	if admitted != maxUnfurlTriggersPerWindow {
		t.Fatalf("window admitted %d triggers; want exactly the cap %d", admitted, maxUnfurlTriggersPerWindow)
	}
}

// TestUnfurlAdmission_WindowResets: a new window admits again — the bound
// paces detached work admission; it never permanently disables enrichment.
func TestUnfurlAdmission_WindowResets(t *testing.T) {
	detachedUnfurlAdmission = map[int64]*unfurlAdmission{}
	start := time.Now()
	for i := 0; i < maxUnfurlTriggersPerWindow; i++ {
		if !admitDetachedUnfurl(900002, start) {
			t.Fatal("cap refused before reaching the limit")
		}
	}
	if admitDetachedUnfurl(900002, start.Add(unfurlAdmissionWindow-time.Second)) {
		t.Fatal("trigger inside the same window was admitted past the cap")
	}
	if !admitDetachedUnfurl(900002, start.Add(unfurlAdmissionWindow+time.Second)) {
		t.Fatal("first trigger of the next window refused; window did not reset")
	}
}

// TestUnfurlAdmission_PerSenderIsolation: one sender exhausting their budget
// never starves another sender — the bound scopes detached-work admission to
// the identity minting it.
func TestUnfurlAdmission_PerSenderIsolation(t *testing.T) {
	detachedUnfurlAdmission = map[int64]*unfurlAdmission{}
	now := time.Now()
	for i := 0; i < maxUnfurlTriggersPerWindow*2; i++ {
		admitDetachedUnfurl(900003, now)
	}
	if !admitDetachedUnfurl(900004, now) {
		t.Fatal("a second sender was starved by the first sender's exhausted window")
	}
}

// TestSendMessage_OversizedBodyIs413: DecodeJSON's 1MiB MaxBytesReader plus
// the WriteDecodeError classification — a body-cap violation is 413 with the
// shared too-large problem type, never a 400 "invalid JSON".
func TestSendMessage_OversizedBodyIs413(t *testing.T) {
	h := &Handler{
		flags:  toggle.NewTestFlags(map[string]bool{toggle.FeatureChat: true}),
		logger: nil,
	}

	// Valid JSON whose body string crosses the 1MiB decode cap.
	huge := `{"body":"` + string(bytes.Repeat([]byte("x"), 1<<20)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/chat/channels/1/messages", strings.NewReader(huge))
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	h.sendMessage(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized send body status = %d; want 413", rec.Code)
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(httputil.TypeTooLarge)) {
		t.Fatalf("413 body missing the too-large problem type: %s", rec.Body.String())
	}
}
