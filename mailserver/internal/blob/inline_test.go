package blob

import "testing"

// TestIsInlineMessage pins the raw_ref discriminator against every producer
// shape in the codebase (see IsInlineMessage's WHY comment): inline RFC 5322
// text (reducer-built drafts) vs object keys and sentinels (everything else).
func TestIsInlineMessage(t *testing.T) {
	inline := []struct{ name, ref string }{
		{"reducer draft (jmap_email.sql v_raw_msg)",
			"Message-ID: <abc@setjoin.local>\r\nFrom: a@b.test\r\nTo: c@d.test\r\nSubject: hi\r\n\r\nbody\r\n"},
		{"minimal headers CRLF", "From: a@b.test\r\n\r\nx"},
		{"LF-only line endings", "From: a@b.test\n\nx"},
	}
	for _, c := range inline {
		if !IsInlineMessage(c.ref) {
			t.Errorf("%s: IsInlineMessage = false, want true", c.name)
		}
	}

	keys := []struct{ name, ref string }{
		{"bare sha256 hex (jmap sign/encrypt/assemble store)",
			"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{"SMTP MTA inbound", "inbound/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{"SMTP MSA submission", "blobs/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		{"DMARC aggregate report", "dmarc/9f86d081884c7d659a2feaa0c55ad015.eml"},
		{"DSN synthetic", "dsn/<msg-1@test>/42"},
		{"welcome sentinel", "system:welcome:17"},
		{"imap append sentinel", "append-7"},
		{"empty", ""},
	}
	for _, c := range keys {
		if IsInlineMessage(c.ref) {
			t.Errorf("%s: IsInlineMessage = true, want false (%q)", c.name, c.ref)
		}
	}
}
