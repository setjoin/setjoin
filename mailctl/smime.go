package main

import (
	"context"
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// smime.go — `mailctl smime import`: bulk-load users' OWN S/MIME certs (cert +
// private key) at cutover, e.g. when an org migrates from M365/Exchange with
// existing per-user certificates. Today the only path is each user self-uploading
// via POST /auth/me/smime/certs; this gives an operator a one-shot batch import.
//
// It writes user_smime_certs exactly like the self-upload handler
// (mailserver/internal/admin/admin_smime.go): cert stored as PEM, private key
// stored pgp_sym_encrypt'd. The difference: we pass DB_ENCRYPTION_KEY as a bind
// param to pgp_sym_encrypt (the modeDB pool doesn't run the gateway's AfterConnect
// that SETs app.encryption_key) — the same key VALUE the gateway later decrypts
// with via current_setting('app.encryption_key'), so the stored ciphertext
// round-trips.

// runSmime is the modeDB entrypoint for `mailctl smime <action>`. It validates the
// action FIRST so an unknown action errors without demanding a DSN.
func runSmime(c *cmdCtx, action string, args []string) error {
	switch action {
	case "import":
		return smimeImport(c, args)
	default:
		return fmt.Errorf("unknown smime action: %s. Try: import", action)
	}
}

// smimeImportRow is one manifest line: a user's email + paths to their cert/key PEM.
type smimeImportRow struct {
	email    string
	certPath string
	keyPath  string
	label    string
}

func smimeImport(c *cmdCtx, args []string) error {
	fs := flag.NewFlagSet("smime import", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "validate manifest + certs and resolve users, but write nothing")
	asDefault := fs.Bool("default", false, "make each imported cert the user's default signing cert")
	// stdlib flag stops parsing at the first positional, so split the manifest path
	// out from the (boolean) flags — this lets them appear in any order, e.g.
	// `smime import m.csv --dry-run` as well as `smime import --dry-run m.csv`.
	var flags, positional []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			positional = append(positional, a)
		}
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("usage: smime import <manifest.csv> [--dry-run] [--default]\n" +
			"  manifest CSV columns: email,cert_path,key_path[,label]")
	}
	manifestPath := positional[0]

	encKey := os.Getenv("DB_ENCRYPTION_KEY")
	if !*dryRun && encKey == "" {
		return fmt.Errorf("DB_ENCRYPTION_KEY is required to encrypt imported private keys " +
			"(set it to the SAME value the gateway uses, or pass --dry-run to validate only)")
	}

	f, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("open manifest: %w", err)
	}
	defer f.Close()
	rows, err := parseSmimeManifest(f)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("manifest %s has no data rows", manifestPath)
	}

	var pool *pgxpool.Pool
	if !*dryRun {
		if pool, err = c.openDB(); err != nil {
			return err
		}
	}

	imported, skipped := 0, 0
	for i, row := range rows {
		if smimeImportOne(context.Background(), pool, encKey, row, i+1, *dryRun, *asDefault) {
			imported++
		} else {
			skipped++
		}
	}

	verb := "imported"
	if *dryRun {
		verb = "validated"
	}
	fmt.Printf("smime import: %d %s, %d skipped (of %d rows)\n", imported, verb, skipped, len(rows))
	if imported == 0 {
		return fmt.Errorf("no rows %s — see SKIP lines above", verb)
	}
	return nil
}

// smimeImportOne processes a single manifest row. Returns true on success (or a
// clean dry-run validation), false on a skip. pool is nil iff dryRun.
func smimeImportOne(ctx context.Context, pool *pgxpool.Pool, encKey string, row smimeImportRow, n int, dryRun, asDefault bool) bool {
	certPEM, err := os.ReadFile(row.certPath)
	if err != nil {
		fmt.Printf("  [%d] %s: SKIP — read cert %s: %v\n", n, row.email, row.certPath, err)
		return false
	}
	keyPEM, err := os.ReadFile(row.keyPath)
	if err != nil {
		fmt.Printf("  [%d] %s: SKIP — read key %s: %v\n", n, row.email, row.keyPath, err)
		return false
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		fmt.Printf("  [%d] %s: SKIP — invalid certificate: %v\n", n, row.email, err)
		return false
	}
	if err := validateKeyPEM(keyPEM); err != nil {
		fmt.Printf("  [%d] %s: SKIP — invalid private key: %v\n", n, row.email, err)
		return false
	}
	if !certMatchesEmail(cert, row.email) {
		// Non-fatal: an org may bind the address via a SAN we don't list, or use a
		// shared cert. Warn so the operator can spot a wrong-file mismatch.
		fmt.Printf("  [%d] %s: WARN — cert SAN/CN does not include %s\n", n, row.email, row.email)
	}

	if dryRun {
		fmt.Printf("  [%d] %s: OK (dry-run) cert=%s label=%q\n", n, row.email, row.certPath, row.label)
		return true
	}

	var userID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE lower(email) = lower($1)`, row.email).Scan(&userID); err != nil {
		fmt.Printf("  [%d] %s: SKIP — no such user\n", n, row.email)
		return false
	}

	// Mirror admin_smime.go's upsert, but pgp_sym_encrypt with the key as a bind
	// param ($5) instead of current_setting('app.encryption_key'). is_default:
	// TRUE when --default, else only when this is the user's first cert.
	if _, err := pool.Exec(ctx,
		`INSERT INTO user_smime_certs (user_id, label, cert_pem, private_key_enc, issued_at, expires_at, is_default)
		 VALUES ($1, $2, $3, pgp_sym_encrypt($4, $5), $6, $7,
		         CASE WHEN $8 THEN TRUE
		              ELSE NOT EXISTS (SELECT 1 FROM user_smime_certs WHERE user_id = $1) END)
		 ON CONFLICT (user_id, label) DO UPDATE SET
		   cert_pem = EXCLUDED.cert_pem,
		   private_key_enc = EXCLUDED.private_key_enc,
		   issued_at = EXCLUDED.issued_at,
		   expires_at = EXCLUDED.expires_at`,
		userID, row.label, string(certPEM), string(keyPEM), encKey,
		cert.NotBefore, cert.NotAfter, asDefault,
	); err != nil {
		fmt.Printf("  [%d] %s: SKIP — store failed: %v\n", n, row.email, err)
		return false
	}

	// --default must clear the flag on the user's OTHER certs (the upsert only set
	// this one TRUE), so the imported cert becomes the SOLE default.
	if asDefault {
		if _, err := pool.Exec(ctx,
			`UPDATE user_smime_certs SET is_default = (label = $2) WHERE user_id = $1`,
			userID, row.label); err != nil {
			fmt.Printf("  [%d] %s: WARN — stored, but set-default failed: %v\n", n, row.email, err)
		}
	}

	fmt.Printf("  [%d] %s: imported (label=%q)\n", n, row.email, row.label)
	return true
}

// parseSmimeManifest reads a CSV of email,cert_path,key_path[,label]. Blank lines,
// `#` comments, and an optional `email,...` header row are skipped. label defaults
// to "imported".
func parseSmimeManifest(r io.Reader) ([]smimeImportRow, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // label column is optional
	cr.TrimLeadingSpace = true

	var out []smimeImportRow
	line := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("manifest parse error near line %d: %w", line+1, err)
		}
		line++
		if len(rec) == 0 {
			continue
		}
		first := strings.TrimSpace(rec[0])
		if first == "" || strings.HasPrefix(first, "#") {
			continue // blank / comment
		}
		if line == 1 && strings.EqualFold(first, "email") {
			continue // header
		}
		if len(rec) < 3 {
			return nil, fmt.Errorf("manifest line %d: need at least email,cert_path,key_path", line)
		}
		row := smimeImportRow{
			email:    strings.TrimSpace(rec[0]),
			certPath: strings.TrimSpace(rec[1]),
			keyPath:  strings.TrimSpace(rec[2]),
			label:    "imported",
		}
		if row.email == "" || row.certPath == "" || row.keyPath == "" {
			return nil, fmt.Errorf("manifest line %d: email, cert_path, key_path are all required", line)
		}
		if len(rec) >= 4 && strings.TrimSpace(rec[3]) != "" {
			row.label = strings.TrimSpace(rec[3])
		}
		out = append(out, row)
	}
	return out, nil
}

// parseCertPEM decodes the first PEM block and parses it as an X.509 cert.
func parseCertPEM(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("not PEM-encoded")
	}
	return x509.ParseCertificate(block.Bytes)
}

// validateKeyPEM confirms the bytes are an UNENCRYPTED private key in any of the
// formats the gateway accepts (PKCS#8 / PKCS#1 / SEC1 EC). It does not return the
// key — the import stores the PEM verbatim (pgp_sym_encrypt'd).
func validateKeyPEM(b []byte) error {
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("not PEM-encoded")
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") || strings.Contains(block.Type, "ENCRYPTED") {
		return fmt.Errorf("private key is passphrase-encrypted; decrypt it first")
	}
	if _, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		return nil
	}
	if _, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		return nil
	}
	if _, e := x509.ParseECPrivateKey(block.Bytes); e == nil {
		return nil
	}
	return fmt.Errorf("unrecognized key (need unencrypted PKCS#8, PKCS#1, or SEC1 EC PEM)")
}

// certMatchesEmail reports whether the cert binds email via a rfc822 SAN or CN.
func certMatchesEmail(cert *x509.Certificate, email string) bool {
	want := strings.ToLower(strings.TrimSpace(email))
	for _, e := range cert.EmailAddresses {
		if strings.ToLower(e) == want {
			return true
		}
	}
	return strings.ToLower(strings.TrimSpace(cert.Subject.CommonName)) == want
}
