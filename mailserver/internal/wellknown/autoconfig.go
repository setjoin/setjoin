package wellknown

import (
	"context"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// autoconfigTmpl renders Mozilla Thunderbird's autoconfig-v1.1 XML. See
// https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
//
// html/template (not text/template) is deliberate: its contextual escaper
// XML/HTML-escapes every interpolated value (text nodes and the id attribute
// alike), so even an exotic configured domain name cannot break out of the
// document structure or emit malformed XML (co-located output-escaping
// defect). For ordinary domain names the output is byte-identical.
var autoconfigTmpl = template.Must(template.New("autoconfig").Parse(`<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{{.Domain}}">
    <domain>{{.Domain}}</domain>
    <displayName>{{.Domain}}</displayName>
    <incomingServer type="imap">
      <hostname>{{.Hostname}}</hostname>
      <port>{{.IMAPPort}}</port>
      <socketType>{{.IMAPSocketType}}</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>{{.Hostname}}</hostname>
      <port>{{.SMTPPort}}</port>
      <socketType>{{.SMTPSocketType}}</socketType>
      <username>%EMAILADDRESS%</username>
      <authentication>password-cleartext</authentication>
    </outgoingServer>
  </emailProvider>
</clientConfig>
`))

type autoconfigData struct {
	Domain         string
	Hostname       string
	IMAPPort       string
	IMAPSocketType string
	SMTPPort       string
	SMTPSocketType string
}

// HandleAutoconfig serves GET /.well-known/autoconfig/mail/config-v1.1.xml —
// Thunderbird's (and compatible clients') zero-config autodiscovery. No
// authentication required — this is a discovery endpoint, and the
// domain-membership check below is the only gate.
//
// imapAddr/submissionAddr are accepted (mirroring the shape of the other
// server-wiring call sites in main.go) but are not rendered directly: the
// advertised ports are the IANA-standard ones (143/993, 587/465) — only
// whether the *TLSAddr sibling is configured decides which of the pair to
// advertise.
func HandleAutoconfig(pool *pgxpool.Pool, imapAddr, imapTLSAddr, submissionAddr, submissionTLSAddr string) http.HandlerFunc {
	imapPort, imapSocket := "143", "STARTTLS"
	if imapTLSAddr != "" {
		imapPort, imapSocket = "993", "SSL"
	}
	smtpPort, smtpSocket := "587", "STARTTLS"
	if submissionTLSAddr != "" {
		smtpPort, smtpSocket = "465", "SSL"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		domain := strings.ToLower(host)

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var exists int
		err := pool.QueryRow(ctx, `SELECT 1 FROM domains WHERE lower(name) = $1 AND is_local = TRUE LIMIT 1`, domain).Scan(&exists)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/xml")
		_ = autoconfigTmpl.Execute(w, autoconfigData{
			Domain:         domain,
			Hostname:       domain,
			IMAPPort:       imapPort,
			IMAPSocketType: imapSocket,
			SMTPPort:       smtpPort,
			SMTPSocketType: smtpSocket,
		})
	}
}
