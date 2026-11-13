package spam

import (
	"math"
	"testing"
)

func TestDetectForgedRecipients_AllMatch(t *testing.T) {
	// SMTP recipients are all found in MIME To or CC
	forged, score := DetectForgedRecipients(
		[]string{"alice@example.com", "bob@example.com"},
		[]string{"alice@example.com"},
		[]string{"bob@example.com"},
	)
	if forged {
		t.Error("should not detect forgery when all SMTP recipients match MIME headers")
	}
	if score != 0 {
		t.Errorf("expected score 0, got %f", score)
	}
}

func TestDetectForgedRecipients_SomeMissing(t *testing.T) {
	// One SMTP recipient is not in MIME To or CC
	forged, score := DetectForgedRecipients(
		[]string{"alice@example.com", "evil@spam.com"},
		[]string{"alice@example.com"},
		nil,
	)
	if !forged {
		t.Error("should detect forgery when some SMTP recipients are absent from headers")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectForgedRecipients_AllMissing(t *testing.T) {
	// No SMTP recipients appear in MIME headers at all
	forged, score := DetectForgedRecipients(
		[]string{"victim1@example.com", "victim2@example.com"},
		[]string{"innocent@example.com"},
		nil,
	)
	if !forged {
		t.Error("should detect forgery when no SMTP recipients match headers")
	}
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestDetectForgedRecipients_EmptyRecipients(t *testing.T) {
	// No SMTP recipients (shouldn't happen in practice, but should not panic)
	forged, score := DetectForgedRecipients(
		nil,
		[]string{"alice@example.com"},
		nil,
	)
	if forged {
		t.Error("empty SMTP recipients should not detect forgery")
	}
	if score != 0 {
		t.Errorf("expected score 0, got %f", score)
	}
}

func TestDetectForgedRecipients_EmptyHeaders(t *testing.T) {
	// No MIME To/CC headers (e.g., BCC-only mail)
	forged, _ := DetectForgedRecipients(
		[]string{"alice@example.com"},
		nil,
		nil,
	)
	// BCC-only is legitimate — should not be flagged
	if forged {
		t.Error("BCC-only mail should not be flagged as forged recipients")
	}
}

func TestDetectForgedRecipients_CaseInsensitive(t *testing.T) {
	forged, _ := DetectForgedRecipients(
		[]string{"ALICE@EXAMPLE.COM"},
		[]string{"alice@example.com"},
		nil,
	)
	if forged {
		t.Error("case differences should not trigger forgery detection")
	}
}

func TestDetectForgedRecipients_ProportionalScore(t *testing.T) {
	// 2 of 2 missing → higher score than 1 of 2 missing
	_, score1 := DetectForgedRecipients(
		[]string{"alice@example.com", "evil1@spam.com"},
		[]string{"alice@example.com"},
		nil,
	)
	_, score2 := DetectForgedRecipients(
		[]string{"alice@example.com", "evil1@spam.com", "evil2@spam.com", "evil3@spam.com", "evil4@spam.com"},
		[]string{"alice@example.com"},
		nil,
	)
	if score2 <= score1 {
		t.Errorf("more missing recipients should yield higher score: %f vs %f", score1, score2)
	}
}

func TestDetectForgedRecipients_ExactScore(t *testing.T) {
	// 3 SMTP recipients, 1 match → 2/3 missing = 0.66 * 10 = 6.6
	_, score := DetectForgedRecipients(
		[]string{"alice@example.com", "bob@spam.com", "carol@spam.com"},
		[]string{"alice@example.com"},
		nil,
	)
	expected := (2.0 / 3.0) * 10.0
	if math.Abs(score-expected) > 0.01 {
		t.Errorf("expected score %f, got %f", expected, score)
	}
}
