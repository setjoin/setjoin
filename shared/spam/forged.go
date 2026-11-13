package spam

import "strings"

// DetectForgedRecipients checks whether the SMTP envelope recipients (RCPT TO)
// are reflected in the MIME To/CC headers. When recipients appear in the SMTP
// envelope but not in any visible header, it is a strong signal of spam —
// the attacker is delivering to addresses they don't want the recipient to see.
//
// Returns (isForged, score). The score is proportional to the fraction of
// SMTP recipients missing from headers, scaled to 0-10.
//
// BCC-only mail (no To/CC headers) is NOT flagged — it is legitimate for
// blind-carbon-copy delivery.
func DetectForgedRecipients(smtpRcpts, mimeTo, mimeCc []string) (bool, float64) {
	if len(smtpRcpts) == 0 {
		return false, 0
	}

	// Build a lookup set of all addresses in MIME To and CC headers.
	headerAddrs := make(map[string]bool, len(mimeTo)+len(mimeCc))
	for _, addr := range mimeTo {
		headerAddrs[strings.ToLower(strings.TrimSpace(addr))] = true
	}
	for _, addr := range mimeCc {
		headerAddrs[strings.ToLower(strings.TrimSpace(addr))] = true
	}

	// If no addresses appear in To/CC at all, this is BCC-only — legitimate.
	if len(headerAddrs) == 0 {
		return false, 0
	}

	// Count how many SMTP recipients are absent from headers.
	missing := 0
	for _, rcpt := range smtpRcpts {
		if !headerAddrs[strings.ToLower(strings.TrimSpace(rcpt))] {
			missing++
		}
	}

	if missing == 0 {
		return false, 0
	}

	// Score: fraction missing * 10.0
	score := (float64(missing) / float64(len(smtpRcpts))) * 10.0
	return true, score
}
