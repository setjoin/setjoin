package smtp

import (
	"errors"
	"net"
	"strings"
)

// SPFResult is the outcome of an SPF check.
type SPFResult string

const (
	SPFPass     SPFResult = "pass"
	SPFFail     SPFResult = "fail"
	SPFSoftFail SPFResult = "softfail"
	SPFNeutral  SPFResult = "neutral"
	SPFNone     SPFResult = "none"
	SPFTempErr  SPFResult = "temperror"
	SPFPermErr  SPFResult = "permerror"
)

// CheckSPF evaluates SPF for a given sender domain and client IP.
// sender is the MAIL FROM address ("" for null sender) used for macro expansion.
// heloDomain is the EHLO hostname ("" if not available).
func CheckSPF(domain, clientIP, sender, heloDomain string) SPFResult {
	lookupCount := 0
	return checkSPFDepth(domain, clientIP, sender, heloDomain, 0, &lookupCount)
}

func countLookup(count *int) SPFResult {
	*count++
	if *count > 10 {
		return SPFPermErr // RFC 7208 §4.6.4: max 10 DNS mechanism lookups
	}
	return ""
}

func checkSPFDepth(domain, clientIP, sender, heloDomain string, depth int, lookupCount *int) SPFResult {
	if depth > 10 {
		return SPFPermErr
	}
	domain = strings.TrimPrefix(strings.ToLower(domain), "@")
	if domain == "" {
		return SPFNone
	}

	txts, err := lookupTXT(domain)
	if result := countLookup(lookupCount); result != "" {
		return result
	}
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return SPFNone // RFC 7208 §4.3: NXDOMAIN = no SPF records
		}
		return SPFTempErr
	}

	var spfRecord string
	var spfCount int
	for _, txt := range txts {
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfCount++
			spfRecord = txt
		}
	}
	if spfCount > 1 {
		return SPFPermErr // RFC 7208 §4.5: multiple SPF records
	}
	if spfCount == 0 {
		return SPFNone
	}

	return evaluateSPF(spfRecord, domain, clientIP, sender, heloDomain, depth, lookupCount)
}

func evaluateSPF(record, domain, clientIP, sender, heloDomain string, depth int, lookupCount *int) SPFResult {
	mechanisms := strings.Fields(record)
	var result SPFResult = SPFNeutral //nolint:staticcheck // style: type explicit for clarity

	for _, mech := range mechanisms[1:] { // skip v=spf1
		qualifier := '+'
		if len(mech) > 0 && strings.Contains("+-?~", string(mech[0])) { //nolint:gocritic // Contains checks if qualifier char is in "+-?~"
			qualifier = rune(mech[0])
			mech = mech[1:]
		}

		mech = strings.ToLower(mech)

		// Expand macros before evaluating mechanism (RFC 7208 §7)
		mech = expandSPFMacros(mech, domain, sender, heloDomain, clientIP)

		match := false
		switch {
		case mech == "all":
			match = true
		case strings.HasPrefix(mech, "ip4:"):
			match = matchIP4(mech[4:], clientIP)
		case strings.HasPrefix(mech, "ip6:"):
			match = matchIP6(mech[4:], clientIP)
		case mech == "a":
			match = matchA(domain, clientIP, lookupCount)
		case strings.HasPrefix(mech, "a:"):
			match = matchA(mech[2:], clientIP, lookupCount)
		case mech == "mx":
			match = matchMX(domain, clientIP, lookupCount)
		case strings.HasPrefix(mech, "mx:"):
			match = matchMX(mech[3:], clientIP, lookupCount)
		case strings.HasPrefix(mech, "include:"):
			sub := checkSPFDepth(mech[8:], clientIP, sender, heloDomain, depth+1, lookupCount)
			if sub == SPFPass {
				match = true
			} else if sub == SPFPermErr || sub == SPFTempErr {
				return sub
			}
		case strings.HasPrefix(mech, "redirect="):
			return checkSPFDepth(mech[9:], clientIP, sender, heloDomain, depth+1, lookupCount)
		case mech == "ptr":
			match = matchPTR(domain, clientIP, lookupCount)
		case strings.HasPrefix(mech, "ptr:"):
			match = matchPTR(mech[4:], clientIP, lookupCount)
		case strings.HasPrefix(mech, "exists:"):
			match = matchExists(mech[7:], lookupCount)
		}

		if match {
			switch qualifier {
			case '+':
				return SPFPass
			case '-':
				return SPFFail
			case '~':
				return SPFSoftFail
			case '?':
				return SPFNeutral
			}
		}
	}

	return result
}

func matchIP4(cidr, clientIP string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return false
		}
		return ip.Equal(net.ParseIP(clientIP))
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	return ipnet.Contains(ip)
}

func matchIP6(cidr, clientIP string) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	return ipnet.Contains(ip)
}

func matchA(domain, clientIP string, lookupCount *int) bool {
	if result := countLookup(lookupCount); result != "" {
		return false
	}
	ips, err := lookupIP(domain)
	if err != nil {
		return false
	}
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	for _, ip := range ips {
		if ip.Equal(client) {
			return true
		}
	}
	return false
}

func matchMX(domain, clientIP string, lookupCount *int) bool {
	if result := countLookup(lookupCount); result != "" {
		return false
	}
	mxs, err := lookupMX(domain)
	if err != nil {
		return false
	}
	client := net.ParseIP(clientIP)
	if client == nil {
		return false
	}
	for _, mx := range mxs {
		if result := countLookup(lookupCount); result != "" {
			return false
		}
		ips, err := lookupIP(mx.Host)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(client) {
				return true
			}
		}
	}
	return false
}

func matchPTR(domain, clientIP string, lookupCount *int) bool {
	if result := countLookup(lookupCount); result != "" {
		return false
	}
	names, err := lookupAddr(clientIP)
	if err != nil {
		return false
	}
	for _, name := range names {
		name = strings.TrimSuffix(name, ".")
		if domain == "" || strings.HasSuffix(strings.ToLower(name), "."+domain) || strings.EqualFold(name, domain) {
			if matchA(name, clientIP, lookupCount) {
				return true
			}
		}
	}
	return false
}

func matchExists(domain string, lookupCount *int) bool {
	if result := countLookup(lookupCount); result != "" {
		return false
	}
	_, err := lookupIP(domain)
	return err == nil
}

// expandSPFMacros performs basic SPF macro expansion per RFC 7208 §7.
// Letters covered: %{s}, %{l}, %{o}, %{d}, %{i}, %{p}, %{v}, %{h}
// Transformers (r=reverse, digit-figures) are deferred.
func expandSPFMacros(input, currentDomain, sender, heloDomain, clientIP string) string {
	local := ""
	domain := ""
	if idx := strings.LastIndex(sender, "@"); idx >= 0 {
		local = sender[:idx]
		domain = sender[idx+1:]
	}

	replacer := strings.NewReplacer(
		"%{s}", sender,
		"%{S}", sender,
		"%{l}", local,
		"%{L}", local,
		"%{o}", domain,
		"%{O}", domain,
		"%{d}", currentDomain,
		"%{D}", currentDomain,
		"%{i}", clientIP,
		"%{I}", clientIP,
		"%{p}", currentDomain,
		"%{P}", currentDomain,
		"%{v}", "in-addr", // simplified: always IPv4 for now
		"%{V}", "in-addr",
		"%{h}", heloDomain,
		"%{H}", heloDomain,
	)
	return replacer.Replace(input)
}
