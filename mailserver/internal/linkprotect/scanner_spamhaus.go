package linkprotect

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// SpamhausDBLScanner checks URLs against the Spamhaus DBL (Domain Block List)
// via DNSBL query. No credentials required.
type SpamhausDBLScanner struct {
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

// NewSpamhausDBLScanner creates a new Spamhaus DBL scanner.
func NewSpamhausDBLScanner() *SpamhausDBLScanner {
	return &SpamhausDBLScanner{
		lookupHost: net.DefaultResolver.LookupHost,
	}
}

// Name returns the scanner identifier.
func (s *SpamhausDBLScanner) Name() string {
	return "spamhaus"
}

// Check queries Spamhaus DBL for the domain in the given URL.
func (s *SpamhausDBLScanner) Check(ctx context.Context, url string) (Verdict, error) {
	domain, err := extractURLDomain(url)
	if err != nil {
		return VerdictUnknown, fmt.Errorf("spamhaus: cannot extract domain from URL: %w", err)
	}

	// DBL queries use the domain in FORWARD order: <domain>.dbl.spamhaus.org
	// (e.g. evil.com.dbl.spamhaus.org). The previous label reversal was the
	// IP-DNSBL octet-reversal pattern wrongly applied to a domain list:
	// reversed names are never listed in the DBL, so every query NXDOMAINed
	// and the scanner reported Safe for actually-listed domains.
	queryName := domain + ".dbl.spamhaus.org"

	addrs, err := s.lookupHost(ctx, queryName)
	if err != nil {
		// NXDOMAIN is the DBL's "not listed" signal -> genuinely safe. Every
		// other DNS error (timeout, SERVFAIL, network unreachable) is a scanner
		// OUTAGE, not a clean result: return Unknown + the error so ScanPipeline
		// counts it toward allErrors. Treating an unreachable DBL as VerdictSafe
		// silently defeated the all-errors passthrough protection.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return VerdictSafe, nil
		}
		return VerdictUnknown, fmt.Errorf("spamhaus: DBL lookup %q: %w", queryName, err)
	}

	for _, addr := range addrs {
		if strings.HasPrefix(addr, "127.0.1.") {
			return VerdictMalicious, nil
		}
	}

	return VerdictSafe, nil
}

// extractURLDomain extracts the hostname from a URL string for the DBL query.
// It delegates to the SINGLE net/url authority parser (parseURLHost), so the
// click-time scan target is the same authority the rewrite classifier saw:
// u.Hostname() excludes userinfo ("http://internal.domain:8080@evil.com/" is
// scanned at evil.com, not the decoy internal.domain), strips the port, and
// unbrackets IPv6. Bare domains (no "://") are tolerated by prepending a
// scheme before parsing. A malformed or authority-less URL is rejected with an
// error so Check returns Unknown — never a decoy "clean" domain.
func extractURLDomain(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	return parseURLHost(rawURL)
}
