package admin

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/httputil"
)

// DNSHandler provides DNS record generation and health checks.
type DNSHandler struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
}

// NewDNSHandler creates a DNS handler.
func NewDNSHandler(pool *pgxpool.Pool, logger *slog.Logger) *DNSHandler {
	return &DNSHandler{pool: pool, logger: logger}
}

// DNSRecords holds generated records.
type DNSRecords struct {
	Domain       string       `json:"domain"`
	MX           string       `json:"mx"`
	SPF          string       `json:"spf"`
	DKIM         []DKIMRecord `json:"dkim"`
	DMARC        string       `json:"dmarc"`
	MTASTS       string       `json:"mtasts"`
	TLSA         string       `json:"tlsa"`
	ReverseDNS   string       `json:"reverseDns,omitempty"`
	RecommendedA string       `json:"recommendedA,omitempty"`
}

// DKIMRecord per selector.
type DKIMRecord struct {
	Selector string `json:"selector"`
	Record   string `json:"record"`
}

// DNSHealth holds verification results.
type DNSHealth struct {
	Domain  string     `json:"domain"`
	Checks  []DNSCheck `json:"checks"`
	AllPass bool       `json:"allPass"`
}

// DNSCheck single check result.
type DNSCheck struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Status   string `json:"status"` // pass / fail / warn
	Value    string `json:"value,omitempty"`
	Expected string `json:"expected,omitempty"`
}

// Generate creates DNS records for a domain (scoped to the admin's domain if applicable).
func (h *DNSHandler) Generate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain required")
		return
	}

	// Enforce domain scope: a scoped admin can only generate DNS records for
	// their assigned domain.
	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 {
		var scopeName string
		if err := h.pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, domainScope).Scan(&scopeName); err != nil {
			httputil.WriteError(w, http.StatusForbidden, "domain not found")
			return
		}
		if !strings.EqualFold(domain, scopeName) {
			httputil.WriteError(w, http.StatusForbidden, "access denied: domain not in scope")
			return
		}
	}

	// Fetch gateway hostname from system_config
	var gatewayHost string
	h.pool.QueryRow(ctx, `SELECT value->>'value' FROM system_config WHERE key = 'gateway_hostname'`).Scan(&gatewayHost)
	if gatewayHost == "" {
		gatewayHost = "mail." + domain
	}

	records := DNSRecords{
		Domain:       domain,
		MX:           fmt.Sprintf("%s IN MX 10 %s.", domain, gatewayHost),
		SPF:          fmt.Sprintf("%s IN TXT \"v=spf1 mx ~all\"", domain),
		DMARC:        fmt.Sprintf("_dmarc.%s IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@%s; pct=100\"", domain, domain),
		MTASTS:       fmt.Sprintf("_mta-sts.%s IN TXT \"v=STSv1; id=%s\"", domain, time.Now().UTC().Format("20060102T150405Z")),
		TLSA:         fmt.Sprintf("_25._tcp.%s IN TLSA 3 1 1 (<sha256-hex-of-server-cert>)", gatewayHost),
		RecommendedA: fmt.Sprintf("%s IN A <your-server-ip>", gatewayHost),
		ReverseDNS:   fmt.Sprintf("<your-server-ip>.in-addr.arpa IN PTR %s.", gatewayHost),
	}

	// Fetch DKIM selectors
	rows, err := h.pool.Query(ctx, `SELECT selector FROM domain_signing_keys WHERE domain = $1`, domain)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sel string
			if err := rows.Scan(&sel); err == nil {
				records.DKIM = append(records.DKIM, DKIMRecord{
					Selector: sel,
					Record:   fmt.Sprintf("%s._domainkey.%s IN TXT \"v=DKIM1; k=rsa; p=<public-key>\"", sel, domain),
				})
			}
		}
	}
	if len(records.DKIM) == 0 {
		records.DKIM = append(records.DKIM, DKIMRecord{
			Selector: "default",
			Record:   fmt.Sprintf("default._domainkey.%s IN TXT \"v=DKIM1; k=rsa; p=<public-key>\"", domain),
		})
	}

	httputil.WriteJSON(w, http.StatusOK, records)
}

// Verify runs DNS health checks for a domain (scoped to the admin's domain if applicable).
func (h *DNSHandler) Verify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		httputil.WriteError(w, http.StatusBadRequest, "domain required")
		return
	}

	// Enforce domain scope: a scoped admin can only verify DNS for their
	// assigned domain.
	domainScope := middleware.DomainScopeFromContext(ctx)
	if domainScope > 0 {
		var scopeName string
		if err := h.pool.QueryRow(ctx, `SELECT name FROM domains WHERE id = $1`, domainScope).Scan(&scopeName); err != nil {
			httputil.WriteError(w, http.StatusForbidden, "domain not found")
			return
		}
		if !strings.EqualFold(domain, scopeName) {
			httputil.WriteError(w, http.StatusForbidden, "access denied: domain not in scope")
			return
		}
	}

	// Resolve MX via Go net
	var mxHost string
	var mxErr error
	mxRecords, mxErr := netLookupMX(domain)
	if mxErr == nil && len(mxRecords) > 0 {
		mxHost = mxRecords[0].Host
	}

	var checks []DNSCheck
	allPass := true

	// MX check
	if mxErr != nil {
		checks = append(checks, DNSCheck{Type: "MX", Name: domain, Status: "fail", Value: mxErr.Error()})
		allPass = false
	} else {
		checks = append(checks, DNSCheck{Type: "MX", Name: domain, Status: "pass", Value: mxHost})
	}

	// SPF check
	spfRecords, spfErr := netLookupTXT(domain)
	spfFound := false
	if spfErr == nil {
		for _, txt := range spfRecords {
			if strings.Contains(txt, "v=spf1") {
				spfFound = true
				checks = append(checks, DNSCheck{Type: "SPF", Name: domain, Status: "pass", Value: txt})
				break
			}
		}
	}
	if !spfFound {
		checks = append(checks, DNSCheck{Type: "SPF", Name: domain, Status: "fail", Expected: "v=spf1 ..."})
		allPass = false
	}

	// DMARC check
	dmarcRecords, dmarcErr := netLookupTXT("_dmarc." + domain)
	dmarcFound := false
	if dmarcErr == nil {
		for _, txt := range dmarcRecords {
			if strings.Contains(txt, "v=DMARC1") {
				dmarcFound = true
				checks = append(checks, DNSCheck{Type: "DMARC", Name: "_dmarc." + domain, Status: "pass", Value: txt})
				break
			}
		}
	}
	if !dmarcFound {
		checks = append(checks, DNSCheck{Type: "DMARC", Name: "_dmarc." + domain, Status: "fail", Expected: "v=DMARC1; ..."})
		allPass = false
	}

	// DKIM check (first selector)
	rows, _ := h.pool.Query(ctx, `SELECT selector FROM domain_signing_keys WHERE domain = $1 LIMIT 1`, domain)
	if rows != nil {
		defer rows.Close()
		if rows.Next() {
			var sel string
			if err := rows.Scan(&sel); err == nil {
				dkimRecords, dkimErr := netLookupTXT(sel + "._domainkey." + domain)
				dkimFound := false
				if dkimErr == nil {
					for _, txt := range dkimRecords {
						if strings.Contains(txt, "v=DKIM1") {
							dkimFound = true
							checks = append(checks, DNSCheck{Type: "DKIM", Name: sel + "._domainkey." + domain, Status: "pass", Value: txt})
							break
						}
					}
				}
				if !dkimFound {
					checks = append(checks, DNSCheck{Type: "DKIM", Name: sel + "._domainkey." + domain, Status: "fail", Expected: "v=DKIM1; ..."})
					allPass = false
				}
			}
		}
	}

	result := DNSHealth{Domain: domain, Checks: checks, AllPass: allPass}
	httputil.WriteJSON(w, http.StatusOK, result)
}

// netLookupMX wraps net.LookupMX for testability.
var netLookupMX = net.LookupMX

// netLookupTXT wraps net.LookupTXT for testability.
var netLookupTXT = net.LookupTXT
