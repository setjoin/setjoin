// spam_test.go — Pillar C1 Task 4B: spamScanChatBody, the inbound spam-scan
// wired ahead of federation_apply_chat (receiver.go's handleChat). Confirms
// the shared/spam text detectors this task reuses actually fire on a body
// they're supposed to flag, and stay silent on an ordinary message — the
// two things the quarantine-on-apply contract needs to be true before the
// pgTAP layer (federation_chat_inbound.pg) proves the reducer side lands
// the verdict correctly without ever touching ordering/dedup.
package federation

import "testing"

func TestSpamScanChatBody_MixedCharsetFlagged(t *testing.T) {
	body := "URGENT click now 点击这里领取奖金现在就点击 to claim your free prize"
	quarantined, reason := spamScanChatBody(body)
	if !quarantined {
		t.Fatalf("expected a mixed-script body to be quarantined, got quarantined=false reason=%q", reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason for a quarantined body")
	}
}

func TestSpamScanChatBody_FakeHTMLFlagged(t *testing.T) {
	body := `see you tomorrow <span style="display:none">click this link now</span>`
	quarantined, reason := spamScanChatBody(body)
	if !quarantined {
		t.Fatalf("expected a hidden-text HTML body to be quarantined, got quarantined=false reason=%q", reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason for a quarantined body")
	}
}

func TestSpamScanChatBody_CleanBodyNotFlagged(t *testing.T) {
	body := "Hi Bob, are you still free for a call tomorrow afternoon?"
	quarantined, reason := spamScanChatBody(body)
	if quarantined {
		t.Fatalf("expected a clean plaintext body to NOT be quarantined, got reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected an empty reason for a clean body, got %q", reason)
	}
}

func TestSpamScanChatBody_HTMLLookingButBenignNotFlagged(t *testing.T) {
	// Contains '<' (the fake-HTML gate) but no concealment pattern — proves
	// the gate doesn't over-trigger on any stray angle bracket (e.g. "<3").
	body := "I love you <3 see you soon"
	quarantined, reason := spamScanChatBody(body)
	if quarantined {
		t.Fatalf("expected a benign '<'-containing body to NOT be quarantined, got reason=%q", reason)
	}
	if reason != "" {
		t.Fatalf("expected an empty reason, got %q", reason)
	}
}

func TestDecodeChatBody_MalformedPayloadYieldsEmpty(t *testing.T) {
	if got := decodeChatBody([]byte(`not json`)); got != "" {
		t.Fatalf("expected an empty body for malformed JSON, got %q", got)
	}
	if got := decodeChatBody([]byte(`{"body":"hi there"}`)); got != "hi there" {
		t.Fatalf("expected the decoded body field, got %q", got)
	}
}
