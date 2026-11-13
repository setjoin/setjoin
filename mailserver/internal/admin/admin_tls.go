package admin

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/httputil"
)

type TLSHandler struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	certDir string
	store   *ConfigStore
}

func NewTLSHandler(pool *pgxpool.Pool, logger *slog.Logger, certDir string) *TLSHandler {
	if certDir == "" {
		certDir = "/var/cache/mailserver/tls"
	}
	return &TLSHandler{pool: pool, logger: logger, certDir: certDir, store: NewConfigStore(pool, nil)}
}

// SetConfigStore swaps in a ConfigStore wired to the shared SideEffectRegistry.
// Called from main.go after the registry is built; the constructor installs a
// hookless store for tests.
func (h *TLSHandler) SetConfigStore(s *ConfigStore) { h.store = s }

// GetConfig returns current TLS configuration from system_config. Secret tls_*
// material (the `encrypted` column OR a `_enc` key) is redacted to the
// [ENCRYPTED] sentinel, matching the AD/LDAP/config read-path discipline — the
// handler previously returned every value raw.
func (h *TLSHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rows, err := h.store.GetByPrefix(ctx, "tls_")
	if err != nil {
		h.logger.Error("tls config query failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}

	config := map[string]interface{}{}
	for _, row := range rows {
		config[row.Key] = configStringForResponse(row.Key, row.Value, row.Encrypted)
	}

	httputil.WriteJSON(w, http.StatusOK, config)
}

// SetConfig updates TLS configuration in system_config. Only tls_* keys are
// written; the store persists the authoritative `encrypted` column.
func (h *TLSHandler) SetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	filtered := map[string]interface{}{}
	for key, val := range req {
		if strings.HasPrefix(key, "tls_") {
			filtered[key] = val
		}
	}
	values, err := configValuesFromRaw(filtered)
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "invalid config value")
		return
	}
	if err := h.store.BatchSet(ctx, "TLS configuration", values); err != nil {
		h.logger.Error("tls config update failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "database error")
		return
	}
	// Audit the security-policy mutation (D-MAILSERVER-INTERNAL-ADMIN-F-009):
	// tls_* changes are core-tier admin_audit_log rows — the store fires
	// sync/notify hooks but writes no audit row itself, so this handler (and
	// cert import below) own it. Written after the committed mutation via
	// audit_write on the pool; a failure is loud in the logs rather than
	// silently swallowing the audit trail.
	if claims := auth.UserFromContext(ctx); claims != nil {
		keys := make([]string, 0, len(filtered))
		for key := range filtered {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		after, _ := json.Marshal(map[string]any{"keys": keys, "description": "TLS configuration"})
		if auditErr := audit.Write(ctx, h.pool, audit.Entry{
			Actor: claims.UserID, Action: "tls_config_set", TargetType: "system_config",
			After: after, IP: httputil.ClientIP(r), Notes: strings.Join(keys, ","), Tier: "core",
		}); auditErr != nil {
			h.logger.Error("tls config audit write failed", "error", auditErr)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// ImportCert saves uploaded TLS certificate and key files to disk.
func (h *TLSHandler) ImportCert(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)        // 10 MB max
	if err := r.ParseMultipartForm(10 << 20); err != nil { //nolint:gosec // G120: bounded by MaxBytesReader (10MB) above
		httputil.WriteError(w, http.StatusBadRequest, "failed to parse form")
		return
	}

	certFile, _, err := r.FormFile("cert")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "cert file required")
		return
	}
	defer certFile.Close()

	keyFile, _, err := r.FormFile("key")
	if err != nil {
		httputil.WriteError(w, http.StatusBadRequest, "key file required")
		return
	}
	defer keyFile.Close()

	if err := os.MkdirAll(h.certDir, 0700); err != nil {
		h.logger.Error("tls cert dir create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "storage error")
		return
	}

	certPath := filepath.Join(h.certDir, "custom.cert.pem")
	keyPath := filepath.Join(h.certDir, "custom.key.pem")

	certDest, err := os.Create(certPath) //nolint:gosec // G304: fixed filename under trusted config certDir (no request-controlled path component)
	if err != nil {
		h.logger.Error("tls cert file create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "storage error")
		return
	}
	defer certDest.Close()
	io.Copy(certDest, certFile)
	os.Chmod(certPath, 0600)

	keyDest, err := os.Create(keyPath) //nolint:gosec // G304: fixed filename under trusted config certDir (no request-controlled path component)
	if err != nil {
		h.logger.Error("tls key file create failed", "error", err)
		httputil.WriteError(w, http.StatusInternalServerError, "storage error")
		return
	}
	defer keyDest.Close()
	io.Copy(keyDest, keyFile)
	os.Chmod(keyPath, 0600)

	h.logger.Info("TLS cert imported", "cert", certPath, "key", keyPath)

	// Audit the security-policy mutation (D-MAILSERVER-INTERNAL-ADMIN-F-009):
	// importing a certificate/key pair changes the serving trust material.
	if claims := auth.UserFromContext(r.Context()); claims != nil {
		after, _ := json.Marshal(map[string]any{"certPath": certPath, "keyPath": keyPath})
		if auditErr := audit.Write(r.Context(), h.pool, audit.Entry{
			Actor: claims.UserID, Action: "tls_cert_import", TargetType: "system_config",
			After: after, IP: httputil.ClientIP(r), Tier: "core",
		}); auditErr != nil {
			h.logger.Error("tls cert import audit write failed", "error", auditErr)
		}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{
		"certPath": certPath,
		"keyPath":  keyPath,
	})
}

// tlsStatus is the structured response for the TLS status endpoint.
type tlsStatus struct {
	Enabled     bool      `json:"enabled"`
	Challenge   string    `json:"challenge"` // "tls-alpn-01", "http-01", "dns-01"
	Domains     []string  `json:"domains"`
	Email       string    `json:"email"`
	DNSProvider string    `json:"dns_provider"` // "" = not using DNS-01
	CertInfo    *certInfo `json:"cert_info,omitempty"`
	CacheDir    string    `json:"cache_dir"`
}

type certInfo struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	DaysLeft  int    `json:"days_left"`
}

// GetStatus returns structured TLS status including certificate expiry info.
func (h *TLSHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	status := tlsStatus{
		Enabled:   false,
		Challenge: "none",
	}

	// Read config keys from system_config (dot-notation keys).
	challenge := h.getConfig(ctx, "tls_autocert_challenge")
	domains := h.getConfig(ctx, "tls_autocert_domains")
	email := h.getConfig(ctx, "tls_autocert_email")
	dnsProvider := h.getConfig(ctx, "tls_dns_provider")
	cacheDir := h.getConfig(ctx, "tls_autocert_cache_dir")
	status.Domains = splitCSV(domains)
	status.Email = email
	status.DNSProvider = dnsProvider
	status.CacheDir = cacheDir
	if challenge != "" {
		status.Challenge = challenge
	}

	if challenge != "" && domains != "" {
		status.Enabled = true

		// Check for an existing cert in the cache dir.
		if cacheDir != "" && len(status.Domains) > 0 {
			certPath := certCachePath(cacheDir, status.Domains[0])
			if info := readCertInfo(certPath); info != nil {
				status.CertInfo = info
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, status)
}

// getConfig reads a single value from system_config, returning "" on any error.
func (h *TLSHandler) getConfig(ctx context.Context, key string) string {
	var value string
	row := h.pool.QueryRow(ctx, `SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = $1), '')`, key)
	if err := row.Scan(&value); err != nil {
		return ""
	}
	return value
}

// splitCSV splits a comma-separated string and trims whitespace.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// certCachePath builds the SHA-256-hashed file path for a domain's cache entry.
func certCachePath(cacheDir, domain string) string {
	h := sha256.Sum256([]byte(domain))
	return filepath.Join(cacheDir, hex.EncodeToString(h[:]))
}

// readCertInfo parses a PEM certificate file and returns expiry information.
func readCertInfo(path string) *certInfo {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is certCachePath(config cacheDir, sha256(domain)) — base from trusted config, leaf is a hex digest, no traversal
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return &certInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format(time.RFC3339),
		NotAfter:  cert.NotAfter.Format(time.RFC3339),
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
	}
}
