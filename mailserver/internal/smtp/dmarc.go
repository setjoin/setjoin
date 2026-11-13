package smtp

import (
	"crypto/sha256"
	"errors"
	"net"
	"strconv"
	"strings"
)

// DMARCResult is the outcome of DMARC evaluation.
type DMARCResult string

const (
	DMARCPass    DMARCResult = "pass"
	DMARCFail    DMARCResult = "fail"
	DMARCNone    DMARCResult = "none"
	DMARCTempErr DMARCResult = "temperror"
	DMARCPermErr DMARCResult = "permerror"
)

// DMARCPolicy is the action requested by the domain owner.
type DMARCPolicy string

const (
	DMARCNonePolicy       DMARCPolicy = "none"
	DMARCQuarantinePolicy DMARCPolicy = "quarantine"
	DMARCRejectPolicy     DMARCPolicy = "reject"
)

// DMARCAlignment represents adkim/aspf tag values.
type DMARCAlignment string

const (
	DMARCStrict  DMARCAlignment = "s"
	DMARCRelaxed DMARCAlignment = "r"
)

// DMARCRecord holds parsed DMARC DNS record fields.
type DMARCRecord struct {
	Policy    DMARCPolicy
	Subdomain DMARCPolicy
	Pct       int
	ADKIM     DMARCAlignment
	ASPF      DMARCAlignment
	RUA       string
	RUF       string
	tempErr   bool // DNS temporary error during lookup
}

// CheckDMARC evaluates DMARC for a message.
func CheckDMARC(fromDomain, messageID string, spfResult SPFResult, spfDomain string, dkimResult DKIMResult, dkimDomain string) (DMARCResult, *DMARCRecord) {
	fromDomain = strings.ToLower(strings.TrimPrefix(fromDomain, "@"))
	if fromDomain == "" {
		return DMARCNone, nil
	}

	rec := lookupDMARC(fromDomain)
	if rec == nil {
		return DMARCNone, nil
	}
	if rec.tempErr {
		return DMARCTempErr, rec
	}

	// Alignment check with adkim/aspf modes (RFC 7489 §3.1)
	spfAligned := isDMARCAligned(spfDomain, fromDomain, rec.ASPF)
	dkimAligned := isDMARCAligned(dkimDomain, fromDomain, rec.ADKIM)

	pass := (spfResult == SPFPass && spfAligned) || (dkimResult == DKIMPass && dkimAligned)
	if pass {
		return DMARCPass, rec
	}

	// Apply pct sampling (RFC 7489 §6.6.4)
	if rec.Pct < 100 && messageID != "" {
		hash := sha256.Sum256([]byte(fromDomain + messageID))
		sample := int(hash[0]) % 100
		if sample >= rec.Pct {
			return DMARCNone, nil
		}
	}

	return DMARCFail, rec
}

// lookupDMARC walks the domain tree: exact domain → organizational domain (RFC 7489 §6.6.3).
func lookupDMARC(domain string) *DMARCRecord {
	for _, d := range dmarcWalkDomains(domain) {
		if d == "" {
			continue
		}
		rec := lookupDMARCOne(d)
		if rec != nil {
			return rec
		}
	}
	return nil
}

func dmarcWalkDomains(domain string) []string {
	domain = strings.TrimSuffix(domain, ".")
	d := orgDomain(domain)
	if d == domain || d == "" {
		return []string{domain}
	}
	return []string{domain, d}
}

func orgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func isDMARCAligned(childDomain, parentDomain string, mode DMARCAlignment) bool {
	childDomain = strings.ToLower(childDomain)
	parentDomain = strings.ToLower(parentDomain)
	if mode == DMARCStrict || mode == "" {
		return childDomain == parentDomain
	}
	return orgDomain(childDomain) == orgDomain(parentDomain)
}

// lookupDMARCOne queries and parses a single _dmarc DNS record.
func lookupDMARCOne(domain string) *DMARCRecord {
	txts, err := lookupTXT("_dmarc." + domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil // NXDOMAIN — walk up to org domain
		}
		return &DMARCRecord{Policy: DMARCNonePolicy, Pct: 100, tempErr: true}
	}

	// Concatenate all matching character-strings (RFC 7489 §6.6.2)
	var record strings.Builder
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=DMARC1") {
			record.WriteString(txt)
		}
	}
	recordStr := strings.TrimSpace(record.String())
	if recordStr == "" {
		return nil
	}

	rec := &DMARCRecord{Policy: DMARCNonePolicy, Pct: 100}
	for _, part := range strings.Split(recordStr, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "p":
			rec.Policy = DMARCPolicy(v)
		case "sp":
			rec.Subdomain = DMARCPolicy(v)
		case "pct":
			if pct, err := strconv.Atoi(v); err == nil {
				rec.Pct = pct
			}
		case "adkim":
			rec.ADKIM = DMARCAlignment(v)
		case "aspf":
			rec.ASPF = DMARCAlignment(v)
		case "rua":
			rec.RUA = v
		case "ruf":
			rec.RUF = v
		}
	}
	return rec
}
