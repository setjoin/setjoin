package tlsutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// CertMonitor periodically checks TLS certificate expiry and writes
// status to the health_history table.
type CertMonitor struct {
	pool     *pgxpool.Pool
	logger   *slog.Logger
	getCerts func() []*x509.Certificate // nilable — uses GetCertificate callback
}

// NewCertMonitor creates a certificate expiry monitor.
// getCerts is called on each check to obtain the current certificates.
func NewCertMonitor(pool *pgxpool.Pool, logger *slog.Logger, getCerts func() []*x509.Certificate) *CertMonitor {
	return &CertMonitor{pool: pool, logger: logger, getCerts: getCerts}
}

// Run starts periodic certificate expiry checks. Call in a goroutine.
func (m *CertMonitor) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run once immediately
	m.check(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx)
		}
	}
}

func (m *CertMonitor) check(ctx context.Context) {
	if m.getCerts == nil {
		return
	}
	certs := m.getCerts()
	if len(certs) == 0 {
		m.record(ctx, "tls_cert", "error", "no TLS certificates loaded", 0)
		return
	}

	// Find the earliest expiring certificate
	var earliest *x509.Certificate
	for _, cert := range certs {
		if earliest == nil || cert.NotAfter.Before(earliest.NotAfter) {
			earliest = cert
		}
	}

	daysLeft := int(time.Until(earliest.NotAfter).Hours() / 24)
	subject := earliest.Subject.CommonName
	if subject == "" && len(earliest.DNSNames) > 0 {
		subject = earliest.DNSNames[0]
	}

	var status, msg string
	switch {
	case daysLeft <= 0:
		status = "error"
		msg = fmt.Sprintf("TLS certificate for %s has EXPIRED (%s). Mail delivery impaired.", subject, earliest.NotAfter.Format("2006-01-02"))
	case daysLeft <= 7:
		status = "error"
		msg = fmt.Sprintf("TLS certificate for %s expires in %d days (%s). Immediate action required.", subject, daysLeft, earliest.NotAfter.Format("2006-01-02"))
	case daysLeft <= 14:
		status = "warn"
		msg = fmt.Sprintf("TLS certificate for %s expires in %d days (%s). Prepare renewal.", subject, daysLeft, earliest.NotAfter.Format("2006-01-02"))
	case daysLeft <= 30:
		status = "warn"
		msg = fmt.Sprintf("TLS certificate for %s expires in %d days (%s).", subject, daysLeft, earliest.NotAfter.Format("2006-01-02"))
	default:
		// "ok" — the only healthy value health_history_status_check accepts
		// (ok|warn|error). This wrote "pass" until 2026-07-07, so the monitor
		// NEVER recorded a healthy-cert row (23514 at every boot with a fresh
		// self-signed cert; found by the GA fresh-install smoke's journal).
		status = "ok"
		msg = fmt.Sprintf("TLS certificate for %s valid until %s (%d days).", subject, earliest.NotAfter.Format("2006-01-02"), daysLeft)
	}

	m.record(ctx, "tls_cert", status, msg, daysLeft)
}

func (m *CertMonitor) record(ctx context.Context, checkName, status, msg string, daysLeft int) {
	_, err := m.pool.Exec(ctx,
		`INSERT INTO health_history (check_name, status, value, threshold, details, checked_at)
		 VALUES ($1, $2, $3, $4, $5, now())`,
		checkName, status, daysLeft, 30, msg,
	)
	if err != nil {
		m.logger.Error("cert monitor: failed to record health", "error", err)
	} else {
		m.logger.Info("cert monitor: health recorded", "status", status, "days_left", daysLeft, "msg", msg)
	}
}

// CollectCertsFromTLSConfig returns all certificates from a tls.Config.
// Pass this as the getCerts function to CertMonitor.
func CollectCertsFromTLSConfig(cfg *tls.Config) func() []*x509.Certificate {
	return func() []*x509.Certificate {
		if cfg == nil {
			return nil
		}
		var certs []*x509.Certificate
		// Try to get certificates via a dummy ClientHelloInfo
		dummy := &tls.ClientHelloInfo{ServerName: ""}
		if cert, err := cfg.GetCertificate(dummy); err == nil && cert != nil {
			if cert.Leaf != nil {
				certs = append(certs, cert.Leaf)
			}
			// Parse the certificate chain
			for _, der := range cert.Certificate {
				if c, err := x509.ParseCertificate(der); err == nil {
					certs = append(certs, c)
				}
			}
		}
		return certs
	}
}
