package smtp

import (
	"fmt"
	"net"
	"strings"
)

// RBLProviders is a list of common DNS blacklists.
var RBLProviders = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

// AntiSpamResult holds the score and symbols from anti-spam checks.
type AntiSpamResult struct {
	Score         float64  `json:"score"`
	Symbols       []string `json:"symbols"`
	FTRLScore     float64  `json:"ftrl_score,omitempty"`     // per-user ML score (set at delivery)
	DetectorScore float64  `json:"detector_score,omitempty"` // shared/spam detector suite (feature.spam_ml_detectors), already folded into Score
}

// CheckRBL checks if the client IP is listed on any DNS blacklists.
func CheckRBL(clientIP string) ([]string, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %s", clientIP)
	}

	var listed []string
	// Reverse IP for DNSBL lookup: 1.2.3.4 → 4.3.2.1.zen.spamhaus.org
	reversed := reverseIP(ip)

	for _, rbl := range RBLProviders {
		lookup := reversed + "." + rbl
		_, err := net.LookupHost(lookup)
		if err == nil {
			listed = append(listed, rbl)
		}
	}
	return listed, nil
}

func reverseIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
	}
	// IPv6: reverse nibble format
	ip6 := ip.To16()
	var parts []string
	for i := len(ip6) - 1; i >= 0; i-- {
		parts = append(parts, fmt.Sprintf("%x", ip6[i]&0x0f))
		parts = append(parts, fmt.Sprintf("%x", ip6[i]>>4))
	}
	return strings.Join(parts, ".")
}

// ScoreMessage performs basic heuristic scoring on a raw message.
func ScoreMessage(rawMsg []byte, rblListed []string) AntiSpamResult {
	msg := string(rawMsg)
	result := AntiSpamResult{}

	// RBL hits: +2.0 each
	if len(rblListed) > 0 {
		result.Score += float64(len(rblListed)) * 2.0
		for _, rbl := range rblListed {
			result.Symbols = append(result.Symbols, "RBL_"+rbl)
		}
	}

	// Missing Message-ID: +1.0
	if extractHeader(msg, "Message-Id") == "" {
		result.Score += 1.0
		result.Symbols = append(result.Symbols, "MISSING_MID")
	}

	// Missing Date: +0.5
	if extractHeader(msg, "Date") == "" {
		result.Score += 0.5
		result.Symbols = append(result.Symbols, "MISSING_DATE")
	}

	// HTML-only body (no text/plain): +1.0
	if extractBodyText(msg) == "" && extractBodyHTML(msg) != "" {
		result.Score += 1.0
		result.Symbols = append(result.Symbols, "HTML_ONLY")
	}

	// Suspicious subject keywords
	subject := strings.ToLower(extractHeader(msg, "Subject"))
	suspicious := []string{"viagra", "cialis", "lottery", "winner", "million", "urgent", "click here", "act now"}
	for _, kw := range suspicious {
		if strings.Contains(subject, kw) {
			result.Score += 1.5
			result.Symbols = append(result.Symbols, "SUSPICIOUS_SUBJECT")
			break
		}
	}

	// Too many caps in subject
	caps := 0
	for _, r := range subject {
		if r >= 'A' && r <= 'Z' {
			caps++
		}
	}
	if len(subject) > 0 && float64(caps)/float64(len(subject)) > 0.7 {
		result.Score += 1.0
		result.Symbols = append(result.Symbols, "ALL_CAPS")
	}

	return result
}
