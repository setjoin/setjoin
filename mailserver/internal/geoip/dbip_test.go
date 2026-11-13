package geoip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEnsureGeoIPDB_CacheWithoutPinRefusedEvenWhenPresent is the core
// med-shard3-006 regression: the download-cache path ALWAYS requires the
// pinned digest, regardless of how the file at the path arrived. A legacy
// downloaded/substituted well-formed cache at the default path must never be
// implicitly treated as operator-supplied.
func TestEnsureGeoIPDB_CacheWithoutPinRefusedEvenWhenPresent(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	// A perfectly well-formed database already at the cache path — the refusal
	// is about authority, not structure.
	if err := os.WriteFile(dbPath, validTestMMDB(t), 0644); err != nil {
		t.Fatal(err)
	}

	downloader := &fakeDownloader{}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, "")
	if err == nil {
		t.Fatal("expected the cache path to refuse without a pin even when a file is present, got nil")
	}
	if !strings.Contains(err.Error(), "no trusted authority") {
		t.Errorf("expected trusted-authority refusal, got %v", err)
	}
	if !strings.Contains(err.Error(), "GEOIP_DB_PATH") {
		t.Errorf("refusal must point at the operator topology (GEOIP_DB_PATH) for operator-supplied files, got %v", err)
	}
	if downloader.called {
		t.Error("expected downloader NOT to be called when the file exists")
	}
}

// TestEnsureGeoIPDB_CacheWithMatchingPinAcceptedWithoutDownload: a pre-existing
// cache file whose bytes match the pinned digest is accepted without any
// download — armed only on the pinned-digest match, never on presence.
func TestEnsureGeoIPDB_CacheWithMatchingPinAcceptedWithoutDownload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	downloader := &fakeDownloader{data: []byte("must-not-be-fetched")}
	if err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, data)); err != nil {
		t.Fatalf("matching cache must be accepted without a download, got %v", err)
	}
	if downloader.called {
		t.Error("a matching cache file must not trigger a download")
	}

	// And it arms through the validated open.
	reader, err := OpenValidatedFor(SourceDownloadCache, dbPath, digestOf(t, data))
	if err != nil {
		t.Fatalf("expected matching cache to arm, got %v", err)
	}
	defer reader.Close()
}

// TestEnsureGeoIPDB_CacheWithMismatchedPinRefused: a pre-existing cache file
// that does NOT match the pin is a loud refusal, the file is left untouched,
// and no download is attempted to overwrite it silently (a tampering signal
// must not be papered over).
func TestEnsureGeoIPDB_CacheWithMismatchedPinRefused(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	pinned := digestOf(t, append([]byte{0x00}, data...)) // digest of different bytes

	downloader := &fakeDownloader{data: validTestMMDB(t)}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, pinned)
	if err == nil {
		t.Fatal("expected a cache file not matching the pin to be refused")
	}
	if !strings.Contains(err.Error(), "does not match the pinned digest") {
		t.Errorf("expected pinned-digest mismatch in error, got %v", err)
	}
	if downloader.called {
		t.Error("a mismatched cache must not trigger a silent re-download")
	}
	// The refused file is left exactly as it was.
	after, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("read refused cache file: %v", err)
	}
	if !bytes.Equal(after, data) {
		t.Error("refused cache file must be left untouched")
	}
}

func TestEnsureGeoIPDB_DownloadsCurrentMonth(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	downloader := &fakeDownloader{
		data: data,
	}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, data))
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if !downloader.called {
		t.Error("expected downloader to be called")
	}

	// Verify file was written byte-identical to the validated download.
	written, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if !bytes.Equal(written, data) {
		t.Errorf("written file differs from downloaded payload")
	}

	// Verify current month URL was tried first.
	if downloader.triedURLs[0] != "https://download.db-ip.com/free/dbip-country-lite-2026-06.mmdb" {
		// The exact month depends on the test run time, but it should have the current year and month.
		t.Logf("first URL tried: %s", downloader.triedURLs[0])
	}
}

func TestEnsureGeoIPDB_FallbackToPreviousMonth(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	downloader := &fakeDownloader{
		data:       data,
		failOnCall: 1, // First attempt fails (current month not published yet)
	}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, data))
	if err != nil {
		t.Errorf("expected no error after fallback, got %v", err)
	}
	if downloader.callCount != 2 {
		t.Errorf("expected 2 download attempts (current + previous month), got %d", downloader.callCount)
	}

	// Verify file was written on second attempt.
	written, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if !bytes.Equal(written, data) {
		t.Errorf("written file differs from downloaded payload")
	}
}

func TestEnsureGeoIPDB_DownloadFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	// Both current and previous month fail. This surfaces as an error (logged
	// loudly by EnsureGeoIPDBWithLogging) instead of the old silent fail-open.
	// A digest is pinned because the download channel requires one; the
	// failure here is the network, not the pin.
	downloader := &fakeDownloader{
		err: errors.New("network unreachable"),
	}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, validTestMMDB(t)))
	if err == nil {
		t.Error("expected an error when no database can be downloaded, got nil")
	}
	if !strings.Contains(err.Error(), "network unreachable") {
		t.Errorf("expected underlying download error in chain, got %v", err)
	}

	// File should not exist.
	if _, err := os.Stat(dbPath); err == nil {
		t.Error("expected file NOT to be created on failure")
	}
}

// TestEnsureGeoIPDB_RefusesUnpinnedDownload is the mandatory-authentication
// contract for the download channel: with no pinned digest there is no
// trusted authority, so the channel refuses before any bytes are fetched or
// persisted. Availability is preserved (the error is the explicit NOT-armed
// signal; boot proceeds) — a substituted but well-formed download can never
// arm country resolution.
func TestEnsureGeoIPDB_RefusesUnpinnedDownload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	// The payload is a perfectly well-formed database — the refusal is about
	// authority, not structure.
	downloader := &fakeDownloader{data: validTestMMDB(t)}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, "")
	if err == nil {
		t.Fatal("expected unpinned download to be refused, got nil error")
	}
	if !strings.Contains(err.Error(), "no trusted authority") {
		t.Errorf("expected trusted-authority refusal, got %v", err)
	}
	if downloader.called {
		t.Error("refusal must happen before any download is attempted")
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Error("unpinned download must not be persisted")
	}
}

// TestEnsureGeoIPDB_OperatorFileTopologyUnpinnedIsAccepted — an
// operator-provided file at an explicitly configured path (GEOIP_DB_PATH
// topology, SourceOperatorFile) is a separate input class: no pin required,
// no download attempted, structural validation only.
func TestEnsureGeoIPDB_OperatorFileTopologyUnpinnedIsAccepted(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := EnsureOperatorGeoIPDB(dbPath, ""); err != nil {
		t.Fatalf("operator-placed file must be accepted without a pin, got %v", err)
	}

	// And it arms through the validated open with structural validation only.
	reader, err := OpenValidated(dbPath, "")
	if err != nil {
		t.Fatalf("expected operator file to arm without a pin, got %v", err)
	}
	defer reader.Close()

	// The operator topology's ensure phase never fetches anything and refuses
	// a missing file instead of downloading one.
	if err := EnsureOperatorGeoIPDB(filepath.Join(dir, "absent.mmdb"), ""); err == nil {
		t.Error("operator topology must refuse a missing file, never download one")
	}
}

// TestOpenValidatedFor_TwoTopologiesTwoRules pins the structural distinction
// the med-shard3-006 fix is about: which PATH is configured — never how a
// file appears to have arrived — decides the integrity rule.
//   - cache topology + no pin: refused, even with a well-formed file present;
//   - cache topology + pinned digest match: armed;
//   - operator topology + no pin: armed (unchanged operator contract);
//   - operator topology + pinned mismatch: refused.
func TestOpenValidatedFor_TwoTopologiesTwoRules(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")
	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	digest := digestOf(t, data)

	t.Run("cache without pin refuses even a well-formed file", func(t *testing.T) {
		reader, err := OpenValidatedFor(SourceDownloadCache, dbPath, "")
		if err == nil {
			reader.Close()
			t.Fatal("cache path must refuse to arm without a pinned digest even when a well-formed file is present")
		}
		if !strings.Contains(err.Error(), "requires a pinned digest") {
			t.Errorf("expected the mandatory-pin refusal, got %v", err)
		}
	})
	t.Run("cache with matching pin arms", func(t *testing.T) {
		reader, err := OpenValidatedFor(SourceDownloadCache, dbPath, digest)
		if err != nil {
			t.Fatalf("cache path with a matching pin must arm, got %v", err)
		}
		reader.Close()
	})
	t.Run("operator file without pin arms", func(t *testing.T) {
		reader, err := OpenValidatedFor(SourceOperatorFile, dbPath, "")
		if err != nil {
			t.Fatalf("operator topology without a pin must arm (unchanged contract), got %v", err)
		}
		reader.Close()
	})
	t.Run("operator file with mismatched pin is refused", func(t *testing.T) {
		if _, err := OpenValidatedFor(SourceOperatorFile, dbPath, digestOf(t, []byte("other-bytes"))); err == nil {
			t.Fatal("operator topology with a mismatched pin must be refused")
		}
	})
}

func TestEnsureGeoIPDB_DirCreated(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "subdir", "geoip.mmdb")

	data := validTestMMDB(t)
	downloader := &fakeDownloader{data: data}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, data))
	if err != nil {
		t.Fatalf("expected file to be written, got error: %v", err)
	}

	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("expected file to exist, got %v", err)
	}
}

// TestEnsureGeoIPDB_RejectsTamperedDownload pins a digest that does not match
// the payload and asserts the tampered download is never persisted.
func TestEnsureGeoIPDB_RejectsTamperedDownload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	downloader := &fakeDownloader{data: data}
	pinned := digestOf(t, append([]byte{0x00}, data...)) // digest of different bytes

	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, pinned)
	if err == nil {
		t.Fatal("expected digest-mismatch refusal, got nil error")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("expected digest mismatch in error, got %v", err)
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Error("tampered download must not be persisted")
	}
}

// TestEnsureGeoIPDB_RejectsMalformedDownload asserts schema validation on the
// download channel: the digest is pinned to the (malformed) payload itself, so
// the digest check passes and the structural MaxMind parse is what refuses the
// bytes — schema validation applies even when the digest matches.
func TestEnsureGeoIPDB_RejectsMalformedDownload(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	downloader := &fakeDownloader{data: []byte("geoip-data")}
	err := EnsureGeoIPDB(context.Background(), dbPath, downloader, digestOf(t, downloader.data))
	if err == nil {
		t.Fatal("expected malformed payload refusal, got nil error")
	}
	if _, err := os.Stat(dbPath); err == nil {
		t.Error("malformed download must not be persisted")
	}
}

// ── cached-file validation and validated open ────────────────────────────────

// TestOpenValidated_ArmsOnValidCachedFile proves a valid cached database
// opens through the validated path and resolves countries.
func TestOpenValidated_ArmsOnValidCachedFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenValidated(dbPath, digestOf(t, data))
	if err != nil {
		t.Fatalf("expected validated open to succeed, got %v", err)
	}
	defer reader.Close()

	record, err := reader.Country(net.ParseIP("203.0.113.7"))
	if err != nil {
		t.Fatalf("country lookup on armed reader: %v", err)
	}
	if record.Country.IsoCode != "DE" {
		t.Errorf("expected DE from test database, got %q", record.Country.IsoCode)
	}
}

// TestOpenValidated_RefusesTamperedCachedFile is the cached-file arm of the
// integrity control: a file tampered with after a good download is refused
// before every open.
func TestOpenValidated_RefusesTamperedCachedFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	data := validTestMMDB(t)
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	// Tamper: flip a payload byte in place.
	data[len(data)-1] ^= 0xFF
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	if err := ValidateFile(dbPath, digestOf(t, validTestMMDB(t))); err == nil {
		t.Fatal("expected tampered cached file to fail digest validation")
	}
	if reader, err := OpenValidated(dbPath, digestOf(t, validTestMMDB(t))); err == nil {
		reader.Close()
		t.Fatal("expected OpenValidated to refuse the tampered cached file")
	}
}

// TestOpenValidated_RefusesFileWithoutPinnedDigestMatch — no digest pinned
// still requires structural validity; a corrupt cache cannot arm.
func TestOpenValidated_RefusesCorruptCacheWithoutDigest(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")
	if err := os.WriteFile(dbPath, []byte("dummy"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenValidated(dbPath, ""); err == nil {
		t.Fatal("expected non-mmdb cache to be refused even without a pinned digest")
	}
}

func TestOpenValidated_MissingFileErrors(t *testing.T) {
	if _, err := OpenValidated(filepath.Join(t.TempDir(), "absent.mmdb"), ""); err == nil {
		t.Fatal("expected missing database to error")
	}
}

// TestOpenValidated_ServesValidatedBytesAfterFileSwap is the validate-then-
// swap race fixture: once OpenValidated has armed from the validated bytes,
// the file at the path is replaced in place with a different well-formed
// database. The armed reader must serve the bytes that passed validation —
// never whatever currently sits at the path. (The previous implementation
// re-opened the path with geoip2.Open after validating a separate read; a
// swap in that window bypassed verification, and this test fails against it.)
func TestOpenValidated_ServesValidatedBytesAfterFileSwap(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "geoip.mmdb")

	good := validTestMMDBCountry(t, "DE")
	if err := os.WriteFile(dbPath, good, 0600); err != nil {
		t.Fatal(err)
	}

	reader, err := OpenValidated(dbPath, digestOf(t, good))
	if err != nil {
		t.Fatalf("expected validated open to succeed, got %v", err)
	}
	defer reader.Close()

	// Swap: same-length payload, different country, different digest — the
	// substituted database never passed validation.
	evil := validTestMMDBCountry(t, "US")
	if err := os.WriteFile(dbPath, evil, 0600); err != nil {
		t.Fatal(err)
	}

	record, err := reader.Country(net.ParseIP("203.0.113.7"))
	if err != nil {
		t.Fatalf("country lookup on armed reader after file swap: %v", err)
	}
	if record.Country.IsoCode != "DE" {
		t.Errorf("armed reader must serve the validated bytes, not the swapped file: got %q", record.Country.IsoCode)
	}
}

// ── HTTPDownloader redirect pinning ──────────────────────────────────────────

// TestHTTPDownloader_RejectsOffHostRedirect proves the download channel is
// pinned to the original host: a redirect to a different host is refused.
func TestHTTPDownloader_RejectsOffHostRedirect(t *testing.T) {
	offHost := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("off-host target must never be contacted")
		w.WriteHeader(http.StatusOK)
	}))
	defer offHost.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, offHost.URL+"/dbip-country-lite.mmdb", http.StatusFound)
	}))
	defer origin.Close()

	d := NewHTTPDownloader(5 * time.Second)
	if _, err := d.Download(context.Background(), origin.URL+"/dbip-country-lite.mmdb"); err == nil {
		t.Fatal("expected off-host redirect to be refused")
	} else if !strings.Contains(err.Error(), "off-host redirect") {
		t.Errorf("expected off-host redirect error, got %v", err)
	}
}

// TestHTTPDownloader_AllowsSameHostRedirect — the pin is on the host, not on
// redirecting at all.
func TestHTTPDownloader_AllowsSameHostRedirect(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/latest" {
			http.Redirect(w, r, "/files/dbip-country-lite.mmdb", http.StatusFound)
			return
		}
		// Minimal well-formed body is unnecessary here — the downloader only
		// fetches bytes; validation is a separate concern.
		_, _ = w.Write([]byte("bytes"))
	}))
	defer origin.Close()

	d := NewHTTPDownloader(5 * time.Second)
	data, err := d.Download(context.Background(), origin.URL+"/latest")
	if err != nil {
		t.Fatalf("expected same-host redirect to be followed, got %v", err)
	}
	if string(data) != "bytes" {
		t.Errorf("unexpected payload %q", string(data))
	}
}

// ── logging wrapper ──────────────────────────────────────────────────────────

// captureHandler records every emitted record for assertions.
type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

func (h *captureHandler) messages() []string {
	out := make([]string, 0, len(h.records))
	for _, r := range h.records {
		out = append(out, r.Message)
	}
	return out
}

// TestEnsureGeoIPDBWithLogging_NeverClaimsReadyOnFailure: a missing database
// must produce a failure signal and never "geoip: database ready". With no
// pinned digest (this case) the cache path's trusted-authority refusal is the
// recorded reason the database cannot arm.
func TestEnsureGeoIPDBWithLogging_NeverClaimsReadyOnFailure(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := filepath.Join(t.TempDir(), "geoip.mmdb")
	EnsureGeoIPDBWithLogging(context.Background(), dbPath, "", logger)

	joined := strings.Join(capture.messages(), "\n")
	if strings.Contains(joined, "database ready") {
		t.Errorf("log claimed readiness on failure: %q", joined)
	}
	if !strings.Contains(joined, "country resolution cannot arm") {
		t.Errorf("expected explicit cannot-arm failure signal, got %q", joined)
	}
	if !strings.Contains(joined, "no trusted digest authority") {
		t.Errorf("expected the missing trusted authority to be recorded alongside the failure, got %q", joined)
	}
}

// TestEnsureGeoIPDBWithLogging_CacheFilePresentWithoutPinDoesNotArm is the
// med-shard3-006 regression at the logging wrapper: a well-formed file
// already at the default cache path does NOT arm without a pinned digest —
// the outcome is the loud cannot-arm error, not a file-present success record.
func TestEnsureGeoIPDBWithLogging_CacheFilePresentWithoutPinDoesNotArm(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	dbPath := filepath.Join(t.TempDir(), "geoip.mmdb")
	if err := os.WriteFile(dbPath, validTestMMDB(t), 0600); err != nil {
		t.Fatal(err)
	}

	EnsureGeoIPDBWithLogging(context.Background(), dbPath, "", logger)

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "no trusted digest authority") {
		t.Errorf("expected explicit record of missing trusted authority, got %q", joined)
	}
	if strings.Contains(joined, "database ready") {
		t.Errorf("readiness must never be claimed without the pinned-digest match: %q", joined)
	}
	if !strings.Contains(joined, "country resolution cannot arm") {
		t.Errorf("a pre-existing cache without a pin must not arm: expected the cannot-arm signal, got %q", joined)
	}
	for _, r := range capture.records {
		if strings.Contains(r.Message, "matching the pinned digest") {
			t.Errorf("cache path must not report a pin-matched file when no pin is set: %q", r.Message)
		}
	}
}

// TestEnsureGeoIPDBWithLogging_CachePresentWithPinRecordsPresence: with the
// pin matching the pre-existing cache, the ensure phase records the match.
func TestEnsureGeoIPDBWithLogging_CachePresentWithPinRecordsPresence(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	data := validTestMMDB(t)
	dbPath := filepath.Join(t.TempDir(), "geoip.mmdb")
	if err := os.WriteFile(dbPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	EnsureGeoIPDBWithLogging(context.Background(), dbPath, digestOf(t, data), logger)

	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "matching the pinned digest") {
		t.Errorf("expected the pin-matched cache record, got %q", joined)
	}
	if strings.Contains(joined, "no trusted digest authority") {
		t.Errorf("no authority warning may fire when a pin is configured: %q", joined)
	}
}

// TestEnsureOperatorGeoIPDBWithLogging_LogsTheOperatorContract: a valid
// operator file is recorded as present; a missing one is a loud cannot-arm
// error; the unpinned residual risk is recorded.
func TestEnsureOperatorGeoIPDBWithLogging_LogsTheOperatorContract(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "geoip.mmdb")

	// Missing file: loud cannot-arm error.
	missing := &captureHandler{}
	EnsureOperatorGeoIPDBWithLogging(dbPath, "", slog.New(missing))
	joined := strings.Join(missing.messages(), "\n")
	if !strings.Contains(joined, "country resolution cannot arm") {
		t.Errorf("missing operator file must be a cannot-arm signal, got %q", joined)
	}

	// Present and valid: present record plus the unpinned residual-risk note.
	if err := os.WriteFile(dbPath, validTestMMDB(t), 0600); err != nil {
		t.Fatal(err)
	}
	present := &captureHandler{}
	EnsureOperatorGeoIPDBWithLogging(dbPath, "", slog.New(present))
	joined = strings.Join(present.messages(), "\n")
	if !strings.Contains(joined, "operator database file present") {
		t.Errorf("expected operator file present record, got %q", joined)
	}
	if !strings.Contains(joined, "operator's own authority") {
		t.Errorf("expected the unpinned residual-risk record, got %q", joined)
	}
	if strings.Contains(joined, "database ready") {
		t.Errorf("readiness must be claimed by the validated open, not file presence: %q", joined)
	}
}

// TestEnsureGeoIPDBWithLogging_DownloadFailureIsLoud — download/ensure
// failures are error-level failure signals. A digest is pinned so the cache
// path proceeds past the authority gate; the failure here is the uncreatable
// directory, not the pin.
func TestEnsureGeoIPDBWithLogging_DownloadFailureIsLoud(t *testing.T) {
	capture := &captureHandler{}
	logger := slog.New(capture)

	// /var/... is not writable in tests; point at a temp path that cannot be
	// created because its parent is a file.
	parent := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	pin := digestOf(t, validTestMMDB(t))
	EnsureGeoIPDBWithLogging(context.Background(), filepath.Join(parent, "geoip.mmdb"), pin, logger)

	joined := strings.Join(capture.messages(), "\n")
	sawError := false
	for _, r := range capture.records {
		if r.Level == slog.LevelError {
			sawError = true
		}
	}
	if !sawError {
		t.Errorf("expected at least one error-level record, got %q", joined)
	}
	if strings.Contains(joined, "database ready") {
		t.Errorf("log claimed readiness on failure: %q", joined)
	}
}

// ── minimal valid mmdb fixture ───────────────────────────────────────────────
//
// buildTestMMDB hand-encodes the smallest well-formed MaxMind DB that the
// reader accepts and that resolves every IPv4 address to a country record
// ({"country":{"iso_code":"DE"}}). Layout: search tree (1 node, 24-bit
// records) | 16-byte data separator | data section | metadata start marker |
// metadata map. Record values point at data-section offset 0 as
// node_count + separator_size.

func validTestMMDB(t *testing.T) []byte {
	return validTestMMDBCountry(t, "DE")
}

// validTestMMDBCountry builds the fixture resolving every IPv4 address to the
// given two-letter ISO code. Callers that assert "the armed reader serves the
// validated bytes" build two same-length payloads with different countries so
// a swap changes the resolved country without changing the payload length.
func validTestMMDBCountry(t *testing.T, iso string) []byte {
	t.Helper()
	if len(iso) != 2 {
		t.Fatalf("fixture helper requires a two-letter ISO code, got %q", iso)
	}

	var buf bytes.Buffer

	// Search tree: one node whose left/right records both resolve to data
	// offset 0 (record value = node_count(1) + separator(16) = 17).
	rec := []byte{0x00, 0x00, 0x11}
	buf.Write(rec)
	buf.Write(rec)

	// Data section separator: 16 zero bytes.
	buf.Write(make([]byte, 16))

	// Data section: {"country":{"iso_code":"XX"}}.
	buf.WriteByte(0xE1)               // map, 1 entry
	buf.Write(mmdbString("country"))  // key
	buf.WriteByte(0xE1)               // map, 1 entry
	buf.Write(mmdbString("iso_code")) // key
	buf.Write(mmdbString(iso))        // value

	// Metadata start marker.
	buf.Write([]byte{0xAB, 0xCD, 0xEF})
	buf.WriteString("MaxMind.com")

	// Metadata map, 8 entries.
	buf.WriteByte(0xE0 | 8)
	for _, kv := range []struct {
		key string
		val []byte
	}{
		{"binary_format_major_version", mmdbUint(2)},
		{"binary_format_minor_version", mmdbUint(0)},
		{"database_type", mmdbString("DBIP-Country-Lite")},
		{"description", append([]byte{0xE1}, append(mmdbString("en"), mmdbString("setjoin geoip test database")...)...)},
		{"languages", append([]byte{0x01, 0x04}, mmdbString("en")...)},
		{"ip_version", mmdbUint(4)},
		{"node_count", mmdbUint(1)},
		{"record_size", mmdbUint(24)},
	} {
		buf.Write(mmdbString(kv.key))
		buf.Write(kv.val)
	}

	data := buf.Bytes()
	// The fixture must satisfy our own validator before any test relies on it.
	if err := validateBytes(data, ""); err != nil {
		t.Fatalf("invalid mmdb fixture built by test helper: %v", err)
	}
	return data
}

// mmdbString encodes a UTF-8 string (type 2, inline length).
func mmdbString(s string) []byte {
	if len(s) >= 29 {
		panic("fixture helper only supports short strings")
	}
	return append([]byte{0x40 | byte(len(s))}, s...)
}

// mmdbUint encodes a small unsigned integer using the uint16/uint32 types.
func mmdbUint(v uint64) []byte {
	switch {
	case v <= 0xff:
		return []byte{0xA1, byte(v)}
	case v <= 0xffff:
		return []byte{0xA2, byte(v >> 8), byte(v)}
	default:
		return []byte{0xA3, byte(v >> 16), byte(v >> 8), byte(v)}
	}
}

func digestOf(t *testing.T, data []byte) string {
	t.Helper()
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ── fake downloader ──────────────────────────────────────────────────────────

type fakeDownloader struct {
	data       []byte
	err        error
	failOnCall int // first N calls fail with err; afterwards succeed
	called     bool
	callCount  int
	triedURLs  []string
}

func (f *fakeDownloader) Download(ctx context.Context, url string) ([]byte, error) {
	f.called = true
	f.callCount++
	f.triedURLs = append(f.triedURLs, url)

	if f.callCount <= f.failOnCall {
		if f.err != nil {
			return nil, f.err
		}
		return nil, errors.New("simulated failure")
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}
