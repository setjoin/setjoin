package received

import (
	"net/mail"
	"regexp"
	"strings"
)

const maxLineLen = 4096

// RE2 patterns (linear time). Anchored/bounded; no backtracking.
var (
	reFrom = regexp.MustCompile(`(?i)\bfrom\s+([A-Za-z0-9.\-_]{1,253})`)
	reBy   = regexp.MustCompile(`(?i)\bby\s+([A-Za-z0-9.\-_]{1,253})`)
	reWith = regexp.MustCompile(`(?i)\bwith\s+([A-Za-z0-9()/\-]{1,40})`)
	reIP   = regexp.MustCompile(`\[([0-9a-fA-F:.]{3,45})\]`)
	reRDNS = regexp.MustCompile(`(?i)from\s+[A-Za-z0-9.\-_]+\s+\(([A-Za-z0-9.\-_]{1,253})\s`)
)

func parseReceivedLine(index int, line string, self Identity) Hop {
	if len(line) > maxLineLen {
		line = line[:maxLineLen]
	}
	h := Hop{Index: index, RawLine: line}
	body, ts, _ := strings.Cut(line, ";")
	if m := reFrom.FindStringSubmatch(body); m != nil {
		h.FromHost = strings.ToLower(m[1])
	}
	if m := reBy.FindStringSubmatch(body); m != nil {
		h.ByHost = strings.ToLower(m[1])
	}
	if m := reWith.FindStringSubmatch(body); m != nil {
		h.WithProtocol = strings.TrimSpace(m[1])
		up := strings.ToUpper(h.WithProtocol)
		h.TLSActive = strings.Contains(up, "ESMTPS") || strings.Contains(up, "TLS")
	}
	if m := reIP.FindStringSubmatch(body); m != nil {
		h.IP = m[1]
	}
	if m := reRDNS.FindStringSubmatch(body); m != nil {
		h.RDNS = strings.ToLower(m[1])
	}
	if t, err := mail.ParseDate(strings.TrimSpace(ts)); err == nil {
		tt := t.UTC()
		h.Timestamp = &tt
	}
	h.ParseOK = h.FromHost != "" || h.ByHost != ""
	return h
}

// computeDelaysAndAnchor sets DelayMs (chronological diffs, skew preserved) and
// IsOurInfra (only the contiguous SUFFIX of self-matching hops — our verified
// ingress; lower hops are sender-forgeable even if they name our host).
func computeDelaysAndAnchor(hops []Hop, self Identity) {
	for i := 1; i < len(hops); i++ {
		if hops[i].Timestamp != nil && hops[i-1].Timestamp != nil {
			d := hops[i].Timestamp.Sub(*hops[i-1].Timestamp).Milliseconds()
			hops[i].DelayMs = &d
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if self.matches(hops[i].ByHost) {
			hops[i].IsOurInfra = true
		} else {
			break // stop at first non-ours hop from the destination end
		}
	}
}

func (id Identity) matches(host string) bool {
	if host == "" || id.Hostnames == nil {
		return false
	}
	return id.Hostnames[strings.ToLower(host)]
}
