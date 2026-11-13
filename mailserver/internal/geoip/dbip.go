// Package geoip provides automatic download of the DB-IP Lite GeoIP database
// on first startup. Requires zero manual setup — the database is downloaded
// from db-ip.com's free tier and cached locally.
//
// Integrity model (med-shard3-006): the database is the enforcement input for
// geo-block and country conditional-access conditions, so it is treated as
// security-relevant remote data (CWE-494). Two path topologies exist and they
// carry DIFFERENT integrity rules — the distinction is structural (which path
// is configured), never heuristic (how a file appears to have arrived):
//
//   - SourceDownloadCache — the default cache path the download channel
//     maintains (e.g. /var/lib/setjoin/geoip.mmdb). A file here is
//     remote-channel input REGARDLESS of how the bytes arrived (fresh
//     download, legacy cache left by an older build, or a substituted file),
//     so the pinned digest (GEOIP_DB_SHA256) is MANDATORY: the path arms only
//     from pinned-digest-matching, well-formed bytes. With no pin the cache
//     path refuses to arm — even when a well-formed file already sits there.
//
//   - SourceOperatorFile — an explicitly configured operator path
//     (GEOIP_DB_PATH). No download channel exists; the file is accepted on
//     the operator's own authority with schema validation, and digest
//     validation whenever a pin is configured, re-applied before every open.
//
// Downloads are persisted only when the pinned digest matches and the payload
// parses as a well-formed MaxMind DB. Redirects are pinned to the download
// host. Until an out-of-band signed release or independently refreshed digest
// exists, a pinned digest fetched over the same compromised publisher channel
// establishes nothing — that residual risk is recorded in the startup log
// rather than hidden.
package geoip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

const dbipLiteURL = "https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb"

// maxRedirects bounds redirect chains; each hop must also stay on the
// original download host (see HTTPDownloader.Download).
const maxRedirects = 3

// Downloader abstracts HTTP downloads for testability.
type Downloader interface {
	Download(ctx context.Context, url string) ([]byte, error)
}

// HTTPDownloader downloads content from URLs using the standard library.
// Redirects are pinned: the chain is bounded and every hop must stay on the
// host of the original request, so a compromised CDN or DNS answer cannot
// walk the client off to an attacker-chosen mirror.
type HTTPDownloader struct {
	client *http.Client
}

// NewHTTPDownloader creates a downloader with the given timeout.
func NewHTTPDownloader(timeout time.Duration) *HTTPDownloader {
	return &HTTPDownloader{
		client: &http.Client{Timeout: timeout},
	}
}

func (d *HTTPDownloader) Download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Per-request redirect policy over a shallow client copy: every hop must
	// stay on the original host, and the chain length is bounded.
	client := *d.client
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("geoip: stopped after %d redirects", len(via))
		}
		if r.URL.Host != via[0].URL.Host {
			return fmt.Errorf("geoip: refusing off-host redirect from %s to %s", via[0].URL.Host, r.URL.Host)
		}
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 100<<20)) // 100 MB max
}

// Source identifies which path topology a configured database path serves.
// The two topologies carry different integrity rules (see the package doc):
// a file at the download-cache path is remote-channel input and always
// requires the pinned digest; a file at an explicitly configured operator
// path is operator-supplied input on the operator's own authority.
type Source int

const (
	// SourceDownloadCache is the default cache path the download channel
	// maintains. The pinned digest (GEOIP_DB_SHA256) is mandatory here: the
	// path arms only from pinned-digest-matching, well-formed bytes, no
	// matter how the file at the path arrived.
	SourceDownloadCache Source = iota
	// SourceOperatorFile is an explicitly configured operator-provided path
	// (GEOIP_DB_PATH). No download channel exists; the file is accepted on
	// the operator's own authority with schema validation, and digest
	// validation whenever a pin is configured.
	SourceOperatorFile
)

// EnsureGeoIPDB ensures a database exists at the DOWNLOAD-CACHE path dbPath
// (the default path the download channel maintains).
//
// Integrity: the cache topology ALWAYS requires the pinned digest. When
// expectedDigest is empty there is no trusted authority anchoring the
// remote-channel input, so the path refuses outright — even when a file
// already sits there (med-shard3-006: a legacy downloaded/substituted
// well-formed cache at the default path must never be implicitly treated as
// operator-supplied). With a digest pinned, an already-present file is
// re-validated against the pin (SHA-256 + structural MaxMind DB parse)
// exactly like a fresh download — presence is not authority; a mismatch is a
// loud refusal (never a silent re-download that would paper over a tampering
// signal — the operator removes the file or refreshes the pin). A fresh
// download is attempted only when the file is absent, and persisted only
// after passing validateBytes. Tampered, malformed or unpinned input is
// never armed. The function does not fail open silently: every refusal is
// returned as an error so the caller can emit a loud failure signal (startup
// itself still proceeds; whether a failed country input must block startup
// or degrade is a separate posture decision).
func EnsureGeoIPDB(ctx context.Context, dbPath string, downloader Downloader, expectedDigest string) error {
	if expectedDigest == "" {
		return errors.New("download-cache path has no trusted authority (GEOIP_DB_SHA256 unset): refusing to arm a database at the default cache path without a pinned digest, regardless of file presence — pin the expected database digest out-of-band, or configure GEOIP_DB_PATH to point at a database you supply yourself (operator topology)")
	}

	if _, err := os.Stat(dbPath); err == nil {
		// Already present: the cache path is remote-channel input, so the
		// file is re-validated against the pin exactly like a fresh download.
		if verr := ValidateFile(dbPath, expectedDigest); verr != nil {
			return fmt.Errorf("cached database at %s does not match the pinned digest and will not arm: %w (remove the file to re-download, or refresh the pin)", dbPath, verr)
		}
		return nil
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create geoip directory: %w", err)
	}

	now := time.Now()
	prev := now.AddDate(0, -1, 0)
	candidates := []struct {
		year  int
		month int
	}{
		{now.Year(), int(now.Month())},
		{prev.Year(), int(prev.Month())},
	}

	var lastErr error
	for _, c := range candidates {
		data, err := tryDownload(ctx, downloader, dbipLiteURL, c.year, c.month)
		if err != nil {
			lastErr = err
			continue
		}
		// Refuse to persist anything that fails digest/schema validation.
		if err := validateBytes(data, expectedDigest); err != nil {
			lastErr = fmt.Errorf("dbip-country-lite-%04d-%02d refused: %w", c.year, c.month, err)
			continue
		}
		if err := os.WriteFile(dbPath, data, 0600); err != nil {
			return fmt.Errorf("persist geoip database: %w", err)
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("no download attempted")
	}
	return fmt.Errorf("no geoip database could be downloaded and validated: %w", lastErr)
}

// tryDownload attempts a single download from a formatted URL.
func tryDownload(ctx context.Context, downloader Downloader, urlFormat string, year, month int) ([]byte, error) {
	url := fmt.Sprintf(urlFormat, year, month)
	return downloader.Download(ctx, url)
}

// validateBytes enforces integrity and schema on a candidate database before
// it is persisted or opened. When expectedDigest is non-empty the SHA-256 of
// the payload must match it exactly (the operator pins it via GEOIP_DB_SHA256,
// refreshed out-of-band); independently of any digest the payload must parse
// as a well-formed MaxMind DB with usable metadata. This is what turns
// "some bytes arrived" into "a country database arrived". On the download-cache
// topology a non-empty digest is mandatory (enforced structurally by
// EnsureGeoIPDB and OpenValidatedFor before any bytes are fetched, persisted
// or armed); the operator-file topology may pass an empty digest and then
// relies on structural validation plus the operator's placement authority.
func validateBytes(data []byte, expectedDigest string) error {
	if expectedDigest != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, expectedDigest) {
			return fmt.Errorf("sha-256 digest mismatch (got %s): payload does not match the pinned digest", got)
		}
	}
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return fmt.Errorf("payload is not a well-formed MaxMind DB: %w", err)
	}
	// In-memory reader (FromBytes): Close releases no external resource, and
	// the function's verdict is the metadata check, not teardown.
	defer func() { _ = reader.Close() }()
	if strings.TrimSpace(reader.Metadata().DatabaseType) == "" {
		return errors.New("payload parses but metadata is missing database_type")
	}
	return nil
}

// readDatabaseFile reads the database file at dbPath. The gosec exception is
// safe: the path is the operator-configured GEOIP_DB_PATH / fixed download
// path, not request input.
func readDatabaseFile(dbPath string) ([]byte, error) {
	//nolint:gosec // G304: path is the operator-configured GEOIP_DB_PATH / fixed download path, not request input
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return nil, fmt.Errorf("read geoip database: %w", err)
	}
	return data, nil
}

// ValidateFile re-validates a database file already on disk — digest (when
// pinned) plus schema — so a cached file that was tampered with or truncated
// after a previous good download is refused instead of armed.
func ValidateFile(dbPath, expectedDigest string) error {
	data, err := readDatabaseFile(dbPath)
	if err != nil {
		return err
	}
	return validateBytes(data, expectedDigest)
}

// OpenValidated arms country resolution by opening the exact bytes that just
// passed validation — never by re-opening the path. Reading the file once,
// validating those bytes, and constructing the reader from the same slice
// (geoip2.FromBytes) closes the validate-then-swap race in which a file
// replaced between validation and open would bypass verification entirely.
// This is the OPERATOR-FILE rule: the digest is validated when pinned, and
// the payload must always parse as a well-formed MaxMind DB.
//
// Lifetime choice, documented: geoip2.FromBytes is zero-copy — the returned
// reader retains the validated slice (maxminddb stores the buffer in the
// reader and every lookup reads from it), so the bytes that serve lookups
// are exactly the bytes that passed digest and schema validation, for as
// long as the handle is open. The slice comes from a private os.ReadFile
// result and is never mutated afterwards, satisfying the library's
// no-modification-after-open requirement. A missing, tampered or malformed
// database returns an error and must be surfaced as a failure signal — never
// as a ready/healthy state.
func OpenValidated(dbPath, expectedDigest string) (*geoip2.Reader, error) {
	data, err := readDatabaseFile(dbPath)
	if err != nil {
		return nil, err
	}
	if err := validateBytes(data, expectedDigest); err != nil {
		return nil, err
	}
	reader, err := geoip2.FromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("open validated geoip database: %w", err)
	}
	return reader, nil
}

// OpenValidatedFor arms country resolution from the topology the configured
// path belongs to, applying that topology's rule (med-shard3-006):
//   - SourceDownloadCache: the pinned digest is MANDATORY. With no pin the
//     cache path refuses to arm even when a well-formed file sits at the
//     path — a file at the default cache path is remote-channel input, never
//     operator authority, no matter how the bytes arrived (fresh download,
//     legacy cache, substitution). With a pin, bytes arm only on a
//     pinned-digest match (via OpenValidated).
//   - SourceOperatorFile: OpenValidated's operator rule — digest validated
//     when pinned, schema always.
func OpenValidatedFor(source Source, dbPath, expectedDigest string) (*geoip2.Reader, error) {
	if source == SourceDownloadCache && strings.TrimSpace(expectedDigest) == "" {
		return nil, errors.New("download-cache path requires a pinned digest (GEOIP_DB_SHA256): a database at the default cache path is remote-channel input and arms only on a pinned-digest match, regardless of file presence — configure GEOIP_DB_PATH to point at a database you supply yourself (operator topology)")
	}
	return OpenValidated(dbPath, expectedDigest)
}

// EnsureOperatorGeoIPDB ensures the OPERATOR-FILE topology: an explicitly
// configured path (GEOIP_DB_PATH) holding an operator-provided database. No
// download channel exists on this topology; the file is accepted on the
// operator's own authority with structural validation, and digest validation
// whenever a pin is configured. The file must already exist — this topology
// never fetches anything.
func EnsureOperatorGeoIPDB(dbPath, expectedDigest string) error {
	if err := ValidateFile(dbPath, expectedDigest); err != nil {
		return fmt.Errorf("operator-provided geoip database at %s is unusable: %w", dbPath, err)
	}
	return nil
}

// EnsureGeoIPDBWithLogging ensures the database file exists at the
// DOWNLOAD-CACHE path dbPath and logs the outcome. It deliberately never logs
// "ready": file presence alone does not prove the enforcement input is
// usable. Readiness is claimed only by the caller after the validated open
// succeeds; every failure path here is a loud error stating that country
// resolution cannot arm.
//
// Trusted-authority note: when expectedDigest is empty there is no trusted
// authority anchoring the remote-channel input at the cache path, so that
// path refuses to arm — INCLUDING a file already present at the path (a
// cache file is not operator authority, med-shard3-006). Supplying a database
// under operator authority is the explicitly configured GEOIP_DB_PATH
// topology (EnsureOperatorGeoIPDBWithLogging).
func EnsureGeoIPDBWithLogging(ctx context.Context, dbPath, expectedDigest string, logger *slog.Logger) {
	if expectedDigest == "" {
		logger.Warn("geoip: no trusted digest authority configured (GEOIP_DB_SHA256 unset) — the download-cache path refuses to arm, and a file already at the default cache path is remote-channel input that does NOT arm without a pinned digest either; to supply a database under operator authority, configure GEOIP_DB_PATH explicitly")
	}
	downloader := NewHTTPDownloader(30 * time.Second)

	if err := EnsureGeoIPDB(ctx, dbPath, downloader, expectedDigest); err != nil {
		logger.Error("geoip: database unavailable — country resolution cannot arm (geo-block and country conditional-access conditions will not fire)", "path", dbPath, "error", err)
		return
	}

	logger.Info("geoip: cached database file present and matching the pinned digest", "path", dbPath)
}

// EnsureOperatorGeoIPDBWithLogging ensures the operator-provided database at
// the explicitly configured path dbPath (GEOIP_DB_PATH) and logs the outcome,
// mirroring the cache wrapper's never-claims-ready contract: readiness is
// claimed only by the caller after the validated open succeeds.
//
// Residual-risk note: with no pinned digest the operator file is accepted
// with structural validation only, on the operator's own authority — that
// residual risk is recorded explicitly at startup instead of being papered
// over by a same-channel digest.
func EnsureOperatorGeoIPDBWithLogging(dbPath, expectedDigest string, logger *slog.Logger) {
	if expectedDigest == "" {
		logger.Warn("geoip: operator-provided database accepted without a digest pin (GEOIP_DB_SHA256 unset) — structural validation only, on the operator's own authority (residual risk recorded)")
	}

	if err := EnsureOperatorGeoIPDB(dbPath, expectedDigest); err != nil {
		logger.Error("geoip: database unavailable — country resolution cannot arm (geo-block and country conditional-access conditions will not fire)", "path", dbPath, "error", err)
		return
	}

	logger.Info("geoip: operator database file present", "path", dbPath)
}
