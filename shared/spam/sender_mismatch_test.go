package spam

import (
	"math"
	"testing"
)

func TestDetectSenderMismatch_PerfectMatch(t *testing.T) {
	mismatch, score := DetectSenderMismatch(
		"alice@example.com",
		"alice@example.com",
		true, true,
	)
	if mismatch {
		t.Error("identical addresses should not detect mismatch")
	}
	if score != 0 {
		t.Errorf("expected score 0, got %f", score)
	}
}

func TestDetectSenderMismatch_DifferentAddresses(t *testing.T) {
	// SMTP From differs from header From
	mismatch, score := DetectSenderMismatch(
		"spammer@evil.com",
		"legit@example.com",
		false, false,
	)
	if !mismatch {
		t.Error("different addresses should detect mismatch")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectSenderMismatch_DifferentAddresses_SPFPassed(t *testing.T) {
	// Different addresses but SPF passed at same domain; this is suspicious (header forgery)
	mismatch, score := DetectSenderMismatch(
		"spammer@example.com",
		"legit@example.com",
		true, false,
	)
	if !mismatch {
		t.Error("different addresses should detect mismatch even with SPF")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectSenderMismatch_DifferentAddresses_DKIMPassed(t *testing.T) {
	// Different addresses but DKIM passed. DKIM signs the header, so it is less
	// suspicious than the same scenario without DKIM.
	mismatch, score := DetectSenderMismatch(
		"newsletter@bounce.example.com",
		"noreply@example.com",
		false, true,
	)
	if !mismatch {
		t.Error("different addresses should detect mismatch")
	}
	// DKIM-passed mismatch should score lower than the same scenario without DKIM
	_, scoreNoAuth := DetectSenderMismatch(
		"newsletter@bounce.example.com",
		"noreply@example.com",
		false, false,
	)
	if score >= scoreNoAuth {
		t.Errorf("DKIM-passed mismatch (%.1f) should score lower than no-auth mismatch (%.1f)", score, scoreNoAuth)
	}
}

func TestDetectSenderMismatch_SameDomain(t *testing.T) {
	// Same domain but different local part, might be legitimate
	mismatch, score := DetectSenderMismatch(
		"bounce+xyz@example.com",
		"noreply@example.com",
		true, true,
	)
	if !mismatch {
		t.Error("different addresses on same domain should still trigger mismatch")
	}
	// Score should be lower than completely different domains
	_, scoreCrossDomain := DetectSenderMismatch(
		"spammer@evil.com",
		"legit@example.com",
		false, false,
	)
	if score >= scoreCrossDomain {
		t.Errorf("same-domain mismatch (%.1f) should score lower than cross-domain mismatch (%.1f)", score, scoreCrossDomain)
	}
}

func TestDetectSenderMismatch_MaxScore(t *testing.T) {
	// Maximum suspicion: completely different addresses, no auth
	_, score := DetectSenderMismatch(
		"hacker@evil.ru",
		"ceo@company.com",
		false, false,
	)
	if score > 15.0 {
		t.Errorf("score %f exceeds max expected 15.0", score)
	}
	if score < 8.0 {
		t.Errorf("score %f is too low for worst-case mismatch", score)
	}
}

func TestDetectSenderMismatch_EmptyInput(t *testing.T) {
	// Empty addresses should not panic
	mismatch, _ := DetectSenderMismatch("", "", false, false)
	if mismatch {
		t.Error("empty addresses should not detect mismatch")
	}

	mismatch, _ = DetectSenderMismatch("alice@example.com", "", false, false)
	if mismatch {
		t.Error("empty header From should not detect mismatch")
	}

	mismatch, _ = DetectSenderMismatch("", "alice@example.com", false, false)
	if mismatch {
		t.Error("empty SMTP From should not detect mismatch")
	}
}

func TestDetectSenderMismatch_ScoreRange(t *testing.T) {
	// Verify scores are always in [0, 15] range
	testCases := []struct {
		smtpFrom, headerFrom string
		spf, dkim            bool
	}{
		{"a@b.com", "a@b.com", true, true},
		{"a@b.com", "a@b.com", false, false},
		{"spam@evil.com", "ceo@bank.com", false, false},
		{"spam@evil.com", "ceo@bank.com", true, true},
		{"spam@evil.com", "ceo@bank.com", true, false},
		{"bounce@mail.example.com", "user@example.com", false, true},
		{"user@example.com", "user@example.com", true, false},
	}

	for _, tc := range testCases {
		_, score := DetectSenderMismatch(tc.smtpFrom, tc.headerFrom, tc.spf, tc.dkim)
		if score < 0 || score > 15.0 {
			t.Errorf("score %f out of [0,15] range for (%q, %q, spf=%v, dkim=%v)",
				score, tc.smtpFrom, tc.headerFrom, tc.spf, tc.dkim)
		}
	}
}

func TestDetectSenderMismatch_ExactScore(t *testing.T) {
	// Different domains, no auth: base 10.0
	_, score := DetectSenderMismatch(
		"attacker@evil.com",
		"admin@company.com",
		false, false,
	)
	expected := 10.0
	if math.Abs(score-expected) > 0.01 {
		t.Errorf("expected score %f for cross-domain no-auth mismatch, got %f", expected, score)
	}
}
