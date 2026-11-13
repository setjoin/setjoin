package spam

import "strings"

// DetectSenderMismatch checks whether the SMTP envelope From (MAIL FROM) matches
// the message header From address. A mismatch is common in spam and phishing
// where the envelope sender is hidden from the recipient's mail client.
//
// SPF validates the envelope domain; DKIM validates the header domain.
// The scoring weights reflect the authentication context:
//
//   - Mismatch + SPF passed + DKIM failed: header forgery (high score)
//   - Mismatch + DKIM passed: DKIM signs the header — less suspicious
//   - Mismatch + same domain: possibly legitimate (newsletters, bounces)
//   - Mismatch + different domains + no auth: maximum suspicion
//
// Returns (isMismatch, score). Score range: 0-15.
func DetectSenderMismatch(smtpFrom, headerFrom string, spfPassed, dkimPassed bool) (bool, float64) {
	smtpFrom = strings.ToLower(strings.TrimSpace(smtpFrom))
	headerFrom = strings.ToLower(strings.TrimSpace(headerFrom))

	// Empty or identical addresses are not mismatches.
	if smtpFrom == "" || headerFrom == "" || smtpFrom == headerFrom {
		return false, 0
	}

	// Base score: addresses differ.
	score := 5.0

	// Cross-domain: higher suspicion.
	smtpDomain := extractDomain(smtpFrom)
	headerDomain := extractDomain(headerFrom)
	crossDomain := smtpDomain != headerDomain

	if crossDomain {
		score = 10.0
	}

	// Authentication modifiers.
	// SPF passed but addresses differ: someone is spoofing the header.
	if spfPassed && crossDomain {
		score += 2.5
	}
	// DKIM passed: the header is signed — less suspicious.
	if dkimPassed {
		score -= 3.0
	}

	if score < 0 {
		score = 0
	}
	if score > 15.0 {
		score = 15.0
	}

	return true, score
}

// extractDomain returns the domain part of an email address.
// Returns the full string if no '@' is found.
func extractDomain(addr string) string {
	parts := strings.SplitN(addr, "@", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return addr
}
