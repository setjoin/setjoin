package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pwhash"
)

// verifyClientCert verifies an end-user client certificate against the configured
// CA bundle: chain-to-a-trusted-root + validity window + client-auth EKU.
// Optional crls are checked for revocation after chain verification — each CRL must
// be signed by the cert's direct issuer and must not have expired.
// This is the cryptographic half of CA-3b mTLS auth; the user mapping is separate
// (lookupByCertSubject) so each is independently testable.
func verifyClientCert(cert *x509.Certificate, roots *x509.CertPool, crls ...*x509.RevocationList) error {
	if cert == nil {
		return errors.New("no client certificate presented")
	}
	if roots == nil {
		return errors.New("no client-cert CA bundle configured")
	}
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("client cert verification failed: %w", err)
	}
	// CRL revocation: checked after chain verification so the issuer cert is known.
	// ponytail: uses chains[0]; single-CA topology is the CA-3b requirement.
	for _, crl := range crls {
		if err := checkCRL(cert, chains[0], crl); err != nil {
			return err
		}
	}
	return nil
}

// checkCRL verifies one CRL: authenticates its signature from the direct issuer in
// the verified chain, rejects expired CRLs, and scans for the cert's serial number.
func checkCRL(cert *x509.Certificate, chain []*x509.Certificate, crl *x509.RevocationList) error {
	if len(chain) < 2 {
		return errors.New("cert chain too short to determine issuer for CRL check")
	}
	if err := crl.CheckSignatureFrom(chain[1]); err != nil {
		return fmt.Errorf("CRL signature invalid: %w", err)
	}
	if time.Now().After(crl.NextUpdate) {
		return fmt.Errorf("CRL has expired (NextUpdate: %v)", crl.NextUpdate)
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if cert.SerialNumber.Cmp(entry.SerialNumber) == 0 {
			return fmt.Errorf("client cert revoked (serial %s)", cert.SerialNumber)
		}
	}
	return nil
}

// loadCertRoots reads a PEM CA bundle from the path in config_json and returns
// a trusted-root pool. Expected config_json: {"ca_bundle_path": "/path/to/ca.pem"}.
// Returns an error (not panic) on any misconfiguration so ReloadMethods can skip
// the certificate method gracefully instead of bricking the auth chain.
func loadCertRoots(slug string, configJSON []byte) (*x509.CertPool, error) {
	var cfg struct {
		CABundlePath string `json:"ca_bundle_path"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("auth_methods[%s]: invalid config_json: %w", slug, err)
	}
	if cfg.CABundlePath == "" {
		return nil, fmt.Errorf("auth_methods[%s]: ca_bundle_path not configured", slug)
	}
	pem, err := os.ReadFile(cfg.CABundlePath)
	if err != nil {
		return nil, fmt.Errorf("auth_methods[%s]: reading ca_bundle_path %q: %w", slug, cfg.CABundlePath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("auth_methods[%s]: no valid PEM certs in bundle %q", slug, cfg.CABundlePath)
	}
	return pool, nil
}

// loadCRLFiles reads {"crl_paths": [...]} from the same config_json blob used by
// loadCertRoots. Empty/absent crl_paths returns (nil, nil) — revocation is skipped.
// Each path must be a DER-encoded CRL file (the most common on-disk format).
func loadCRLFiles(configJSON []byte) ([]*x509.RevocationList, error) {
	var cfg struct {
		CRLPaths []string `json:"crl_paths"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, fmt.Errorf("invalid config_json for crl_paths: %w", err)
	}
	var out []*x509.RevocationList
	for _, p := range cfg.CRLPaths {
		// #nosec G304 -- p is an operator-configured CRL file path from the
		// auth_methods config_json (admin-managed), not request-derived input.
		der, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("reading crl_path %q: %w", p, err)
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, fmt.Errorf("parsing crl %q: %w", p, err)
		}
		out = append(out, crl)
	}
	return out, nil
}

// lookupByCertSubject maps a verified client cert's CN or an email SAN to an
// enabled user. CN is tried first (the canonical subject), then each email SAN.
// Mirrors lookupByKerberosPrincipal — a single SELECT, ownership-scoped to an
// enabled account, never string-concatenating the subject into SQL. IsAdmin
// rides pwhash.GovernedAdminExpr (the occ_7512aa859c19ceb6691b64c7 closure,
// shared with the password seam): the bare legacy users.is_admin flag must
// not establish admin here either — the cert Claims surface (chain.go's
// authenticateCert) reads the same governed signal.
func lookupByCertSubject(ctx context.Context, pool *pgxpool.Pool, cn string, emailSANs []string) (*User, error) {
	candidates := make([]string, 0, len(emailSANs)+1)
	if cn != "" {
		candidates = append(candidates, cn)
	}
	candidates = append(candidates, emailSANs...)
	for _, c := range candidates {
		var u User
		err := pool.QueryRow(ctx,
			`SELECT u.id, u.email, u.display_name, `+pwhash.GovernedAdminExpr+`,
			   u.totp_enabled
			 FROM users u WHERE u.email = $1 AND u.enabled = TRUE`, c).
			Scan(&u.ID, &u.Email, &u.DisplayName, &u.IsAdmin, &u.TOTPEnabled)
		if err == nil {
			return &u, nil
		}
	}
	return nil, ErrInvalidCredentials
}
