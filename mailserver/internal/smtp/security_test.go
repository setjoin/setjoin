package smtp

import (
	"testing"
)

func TestCheckSPF(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DNS lookup test in short mode")
	}
	result := CheckSPF("google.com", "8.8.8.8", "", "")
	// Accept any result if DNS is unavailable; this test depends on live DNS
	if result == SPFTempErr || result == SPFPermErr {
		t.Skip("DNS unavailable, skipping live SPF test")
	}
	if result == SPFNone {
		t.Skip("DNS returned no SPF record, skipping live SPF test")
	}
	result = CheckSPF("example.invalid", "127.0.0.1", "", "")
	if result != SPFNone && result != SPFTempErr {
		t.Errorf("expected SPFNone or SPFTempErr for invalid domain, got %s", result)
	}
}

func TestReverseIP(t *testing.T) {
	result := reverseIP([]byte{1, 2, 3, 4})
	if result != "4.3.2.1" {
		t.Errorf("reverseIP = %s, want 4.3.2.1", result)
	}
}

func TestScoreMessage(t *testing.T) {
	msg := "Subject: WIN A MILLION DOLLARS NOW!!!\r\n" +
		"From: spam@example.com\r\n" +
		"\r\n" +
		"Click here to claim your prize."
	result := ScoreMessage([]byte(msg), nil)
	if result.Score <= 0 {
		t.Error("expected positive spam score for suspicious message")
	}
	found := false
	for _, s := range result.Symbols {
		if s == "SUSPICIOUS_SUBJECT" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected SUSPICIOUS_SUBJECT symbol")
	}
}

func TestScoreMessageMissingHeaders(t *testing.T) {
	msg := "Subject: test\r\n" +
		"From: test@example.com\r\n" +
		"\r\n" +
		"body"
	result := ScoreMessage([]byte(msg), nil)
	found := false
	for _, s := range result.Symbols {
		if s == "MISSING_MID" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected MISSING_MID symbol for message without Message-Id")
	}
}

func TestDetectCrypto(t *testing.T) {
	tests := []struct {
		msg  string
		want CryptoType
	}{
		{"Content-Type: text/plain\r\n\r\nhello", CryptoNone},
		{"Content-Type: application/pkcs7-mime; smime-type=signed-data\r\n\r\n", CryptoSMIMESigned},
		{"Content-Type: application/pkcs7-mime\r\n\r\n", CryptoSMIMEEncrypted},
		{"Content-Type: application/pgp-encrypted\r\n\r\n", CryptoPGPEncrypted},
		{"Content-Type: application/pgp-signature\r\n\r\n", CryptoPGPSigned},
	}
	for _, tc := range tests {
		got := DetectCrypto(tc.msg)
		if got != tc.want {
			t.Errorf("DetectCrypto(%q) = %s, want %s", tc.msg, got, tc.want)
		}
	}
}

func TestDMARCLookup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DNS lookup test in short mode")
	}
	rec := lookupDMARC("google.com")
	if rec != nil {
		if rec.Policy != DMARCNonePolicy && rec.Policy != DMARCQuarantinePolicy && rec.Policy != DMARCRejectPolicy {
			t.Errorf("unexpected DMARC policy for google.com: %s", rec.Policy)
		}
	}

	rec = lookupDMARC("example.invalid")
	if rec != nil {
		t.Error("expected nil DMARC record for invalid domain")
	}
}
