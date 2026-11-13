package smtp

import (
	"context"
	"fmt"
	"strings"
)

// LookalikeDetector checks for lookalike domain attacks using Unicode homoglyph
// normalization and Levenshtein distance against protected domains.
type LookalikeDetector struct {
	protectedDomains map[string]bool // lower(normalized domain) → true
}

// NewLookalikeDetector creates a new lookalike domain detector.
func NewLookalikeDetector(protectedDomains []string) *LookalikeDetector {
	d := &LookalikeDetector{
		protectedDomains: make(map[string]bool),
	}
	for _, domain := range protectedDomains {
		domain = strings.TrimSpace(domain)
		if domain != "" {
			d.protectedDomains[strings.ToLower(domain)] = true
		}
	}
	return d
}

// Name returns the detector identifier.
func (d *LookalikeDetector) Name() string {
	return "lookalike"
}

// Check evaluates the message for lookalike domain attacks.
func (d *LookalikeDetector) Check(ctx context.Context, msg *PhishInput) (*PhishResult, error) {
	domain := d.extractDomain(msg)
	if domain == "" {
		return nil, nil
	}
	if len(d.protectedDomains) == 0 {
		return nil, nil
	}

	normalized := d.normalizeDomain(strings.ToLower(domain))

	if d.protectedDomains[normalized] && normalized != strings.ToLower(domain) {
		return &PhishResult{
			Verdict:  PhishReject,
			Detector: d.Name(),
			Evidence: []string{fmt.Sprintf("homoglyph_domain:%s:%s", normalized, domain)},
		}, nil
	}

	if d.protectedDomains[normalized] {
		return nil, nil
	}

	for protected := range d.protectedDomains {
		dist := levenshteinDistance(normalized, protected, 2)
		if dist <= 2 {
			return &PhishResult{
				Verdict:  PhishWarn,
				Detector: d.Name(),
				Evidence: []string{fmt.Sprintf("lookalike_domain:%s:%s:%d", normalized, protected, dist)},
			}, nil
		}
	}

	return nil, nil
}

func (d *LookalikeDetector) extractDomain(msg *PhishInput) string {
	if msg.ReturnPathDomain != "" {
		return msg.ReturnPathDomain
	}
	if msg.FromAddr == "" {
		return ""
	}
	addr := msg.FromAddr
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	if idx := strings.LastIndex(addr, "@"); idx >= 0 {
		return addr[idx+1:]
	}
	return ""
}

func (d *LookalikeDetector) normalizeDomain(domain string) string {
	var buf strings.Builder
	buf.Grow(len(domain))
	for _, r := range domain {
		if replacement, ok := Confusables[r]; ok {
			buf.WriteString(replacement)
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}

func levenshteinDistance(a, b string, threshold int) int {
	if a == b {
		return 0
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	ra := []rune(a)
	rb := []rune(b)
	n := len(ra)
	m := len(rb)

	// Length difference alone exceeds threshold – early exit.
	if m-n > threshold {
		return threshold + 1
	}

	prev := make([]int, n+1)
	for i := range prev {
		prev[i] = i
	}
	curr := make([]int, n+1)
	for j := 1; j <= m; j++ {
		curr[0] = j
		rowMin := curr[0]
		for i := 1; i <= n; i++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			curr[i] = min3(
				prev[i]+1,
				curr[i-1]+1,
				prev[i-1]+cost,
			)
			if curr[i] < rowMin {
				rowMin = curr[i]
			}
		}
		if rowMin > threshold {
			return threshold + 1
		}
		prev, curr = curr, prev
	}
	return prev[n]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
