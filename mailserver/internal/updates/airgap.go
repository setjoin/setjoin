// Package updates provides air-gap update feed infrastructure.
// When a SetJoin deployment has no internet access, the admin uploads
// an update bundle via the admin UI, and clients download from the
// gateway directly.
package updates

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"setjoin.com/shared/release"
)

const (
	airgapUploadMaxBytes     = int64(100 << 20)
	airgapStoreMaxBytes      = int64(20 << 30)
	airgapRetainPerPlatform  = 3
	airgapFreeReservePercent = uint64(10)
)

var (
	checkAirgapFreeReserve = func(store *Store) error { return store.requireFreeReserveLocked() }
	copyAirgapUpload       = io.Copy
	syncAirgapUpload       = func(file *os.File) error { return file.Sync() }
	closeAirgapUpload      = func(file *os.File) error { return file.Close() }
)

var errAirgapQuota = errors.New("air-gap update store quota exceeded")

// Bundle describes an uploaded air-gap update bundle.
//
// TargetMetadata carries the exact signed offline target metadata document that
// admitted the bundle; ExpiresAt and KeyID are always re-derived from that
// authenticated document, never trusted from the sidecar's plain fields. A
// sidecar whose signed metadata is missing, expired, mutated, or signed by a
// key that is no longer trusted fails closed: it is quarantined at load and is
// never advertised or served.
type Bundle struct {
	Version         string    `json:"version"`
	Platform        string    `json:"platform"` // "desktop", "android", "server"
	Slug            string    `json:"slug"`     // e.g. "macos-arm64"
	Filename        string    `json:"filename"`
	SHA256          string    `json:"sha256"`
	SizeBytes       int64     `json:"size_bytes"`
	Uploaded        time.Time `json:"uploaded_at"`
	MetadataVersion uint64    `json:"metadata_version"`
	ExpiresAt       time.Time `json:"expires_at"`
	KeyID           string    `json:"key_id"`
	TargetMetadata  string    `json:"target_metadata"`
}

type targetMetadata struct {
	SchemaVersion   int    `json:"schema_version"`
	MetadataVersion uint64 `json:"metadata_version"`
	ExpiresAt       string `json:"expires_at"`
	Slug            string `json:"slug"`
	Version         string `json:"version"`
	Platform        string `json:"platform"`
	Filename        string `json:"filename"`
	SizeBytes       int64  `json:"size_bytes"`
	SHA256          string `json:"sha256"`
	KeyID           string `json:"key_id"`
	Signature       string `json:"signature"`
}

// Store manages air-gap update bundles on the local filesystem.
type Store struct {
	dir    string
	mu     sync.RWMutex
	bundle map[string]*Bundle // slug → servable bundle
	// floor is the highest authenticated admitted metadata version per slug.
	// It is independent of servability: bundles that have expired or been
	// pruned still hold the floor so a reload cannot rewind the
	// accepted-version floor and admit a still-valid signed older version.
	floor map[string]uint64
	trust *release.TrustStore
}

// NewStore creates an air-gap update store rooted at dir.
// It scans for existing *.json sidecar files written by HandleUpload so that
// bundle metadata survives server restarts without requiring re-upload.
func NewStore(dir string) (*Store, error) {
	var trust *release.TrustStore
	rootPath := strings.TrimSpace(os.Getenv("OFFLINE_UPDATE_TRUST_ROOTS"))
	if rootPath == "" {
		rootPath = "/etc/setjoin/offline-update-roots.json"
	}
	//nolint:gosec // G304: fixed administrator-configured trust-root file, never request input
	if raw, err := os.ReadFile(rootPath); err == nil {
		keys, parseErr := release.ParseTrustRootDocument(raw, release.PurposeOfflineUpdate, false)
		if parseErr != nil {
			return nil, fmt.Errorf("updates: parse offline trust roots: %w", parseErr)
		}
		trust, err = release.NewTrustStore(keys, false)
		if err != nil {
			return nil, fmt.Errorf("updates: build offline trust store: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("updates: read offline trust roots: %w", err)
	}
	return newStore(dir, trust)
}

func newStore(dir string, trust *release.TrustStore) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("updates: cannot create store dir: %w", err)
	}
	s := &Store{
		dir:    dir,
		bundle: make(map[string]*Bundle),
		floor:  make(map[string]uint64),
		trust:  trust,
	}
	// Populate in-memory map from sidecar files on disk.
	sidecars, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, path := range sidecars {
		//nolint:gosec // G304: path is from filepath.Glob within s.dir, not user input
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var b Bundle
		if err := json.Unmarshal(data, &b); err != nil {
			continue
		}
		if validAirgapPart(b.Slug) && validAirgapPart(b.Filename) && b.SizeBytes >= 0 {
			// Fail closed: only sidecars whose signed target metadata still
			// verifies against the installed trust roots are re-admitted.
			// Legacy unsigned sidecars, tampered metadata, and metadata signed
			// by revoked keys stay quarantined on disk: never advertised,
			// never served.
			metadata, expires, err := s.authenticatedTarget(&b)
			if err != nil {
				continue
			}
			// Authentication outlives servability. Even an expired bundle was
			// once admitted under a verified signature, so its metadata
			// version keeps raising the upload rollback floor across
			// restarts; only its serving is withheld below.
			if current, ok := s.floor[b.Slug]; !ok || metadata.MetadataVersion > current {
				s.floor[b.Slug] = metadata.MetadataVersion
			}
			if time.Now().UTC().Before(expires) {
				admitted := b
				admitted.ExpiresAt = expires
				admitted.KeyID = metadata.KeyID
				s.bundle[admitted.Slug] = &admitted
			}
		}
	}
	return s, nil
}

func validAirgapPart(part string) bool {
	return part != "" && part != "." && part != ".." &&
		!strings.ContainsRune(part, '/') && !strings.ContainsRune(part, '\\') &&
		!strings.ContainsRune(part, filepath.Separator)
}

func canonicalTargetMetadata(m targetMetadata) ([]byte, error) {
	m.Signature = ""
	return json.Marshal(m)
}

// parseTargetMetadata decodes and structurally validates an offline target
// metadata document, returning it with the expiry parsed from its signed
// ExpiresAt field. Expiry itself is NOT enforced here: the upload path
// additionally requires an unexpired document, while the reload floor must
// still authenticate documents whose validity has since lapsed.
func parseTargetMetadata(raw string) (targetMetadata, time.Time, error) {
	var m targetMetadata
	dec := json.NewDecoder(bytes.NewBufferString(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, time.Time{}, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return m, time.Time{}, errors.New("offline target metadata must contain exactly one JSON object")
	}
	if m.SchemaVersion != 1 || m.MetadataVersion == 0 || m.Slug == "" || m.Filename == "" || m.SizeBytes <= 0 || len(m.SHA256) != 64 {
		return m, time.Time{}, errors.New("invalid offline target metadata")
	}
	expires, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return m, time.Time{}, errors.New("offline target metadata is expired")
	}
	return m, expires, nil
}

// decodeTargetMetadata parses an offline target metadata document and, in
// addition, requires it to be currently unexpired. Upload admission uses this
// variant; the reload rollback floor uses parseTargetMetadata so expired but
// authentic documents still count.
func decodeTargetMetadata(raw string) (targetMetadata, error) {
	m, expires, err := parseTargetMetadata(raw)
	if err != nil {
		return m, err
	}
	if !time.Now().UTC().Before(expires) {
		return m, errors.New("offline target metadata is expired")
	}
	return m, nil
}

// authenticatedTarget verifies that a bundle's persisted signed target
// metadata authenticates against the installed trust roots and matches the
// persisted bundle fields. The detached signature covers ExpiresAt and KeyID,
// so a mutated field fails verification; a signature whose key is no longer
// present in the trust store (revoked) is rejected the same way. Expiry is
// deliberately not enforced here: the returned expiry lets callers decide
// whether the bundle is servable (authenticatedBundle) or only still counts
// toward the upload rollback floor (reload).
func (s *Store) authenticatedTarget(b *Bundle) (targetMetadata, time.Time, error) {
	if b == nil || s.trust == nil || b.TargetMetadata == "" {
		return targetMetadata{}, time.Time{}, errors.New("air-gap bundle lacks authenticated target metadata")
	}
	metadata, expires, err := parseTargetMetadata(b.TargetMetadata)
	if err != nil {
		return targetMetadata{}, time.Time{}, err
	}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		return targetMetadata{}, time.Time{}, err
	}
	if err := s.trust.VerifyDetached(release.PurposeOfflineUpdate, metadata.KeyID, canonical, metadata.Signature); err != nil {
		return targetMetadata{}, time.Time{}, err
	}
	if metadata.Slug != b.Slug || metadata.Filename != b.Filename || metadata.Version != b.Version ||
		metadata.Platform != b.Platform || metadata.SHA256 != b.SHA256 ||
		metadata.SizeBytes != b.SizeBytes || metadata.MetadataVersion != b.MetadataVersion {
		return targetMetadata{}, time.Time{}, errors.New("air-gap bundle does not match its authenticated target metadata")
	}
	return metadata, expires, nil
}

// authenticatedBundle re-derives a bundle's expiry and signing key from its
// persisted signed target metadata, enforcing authenticity rather than mere
// field presence. A bundle admitted through this function is authentic and
// currently unexpired; expired documents authenticate for the rollback floor
// via authenticatedTarget but never through here.
func (s *Store) authenticatedBundle(b *Bundle) (*Bundle, error) {
	metadata, expires, err := s.authenticatedTarget(b)
	if err != nil {
		return nil, err
	}
	if !time.Now().UTC().Before(expires) {
		return nil, errors.New("air-gap bundle target metadata is expired")
	}
	authenticated := *b
	authenticated.ExpiresAt = expires
	authenticated.KeyID = metadata.KeyID
	return &authenticated, nil
}

// servable reports whether a store-admitted bundle may currently be advertised
// or served. Only bundles whose signed target metadata verified at admission
// or reload enter the bundle map; this check additionally enforces the
// authenticated expiry at consumption time so bundles that expire while the
// server runs disappear from the appcast and 404 on serve.
func servable(b *Bundle) bool {
	return b != nil && !b.ExpiresAt.IsZero() && time.Now().UTC().Before(b.ExpiresAt)
}

// Get returns the current bundle for a platform slug.
func (s *Store) Get(slug string) *Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle[slug]
}

// List returns all currently available bundles.
func (s *Store) List() []*Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Bundle, 0, len(s.bundle))
	for _, b := range s.bundle {
		out = append(out, b)
	}
	return out
}

// HandleUpload handles POST /admin/updates/airgap/upload.
// Accepts multipart upload with "file" and "slug" fields.
// Computes SHA-256, stores the file, and records metadata.
func (s *Store) HandleUpload(logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// 100 MB hard cap per upload.
		r.Body = http.MaxBytesReader(w, r.Body, airgapUploadMaxBytes)

		//nolint:gosec // G120: bounded by MaxBytesReader (100 MB) applied to r.Body above
		if err := r.ParseMultipartForm(airgapUploadMaxBytes); err != nil {
			http.Error(w, "file too large or invalid multipart form", http.StatusBadRequest)
			return
		}
		defer func() { _ = r.MultipartForm.RemoveAll() }()

		slug := r.FormValue("slug")
		if slug == "" {
			http.Error(w, "slug is required", http.StatusBadRequest)
			return
		}
		// Reject path-traversal in the slug before it is concatenated into the
		// bundle path AND the sidecar path. The sidecar WriteFile has no absDir
		// confinement check of its own, so this is the load-bearing guard for it.
		if slug == "." || slug == ".." || strings.ContainsRune(slug, '/') || strings.ContainsRune(slug, '\\') || strings.ContainsRune(slug, filepath.Separator) {
			http.Error(w, "invalid slug", http.StatusBadRequest)
			return
		}
		if s.trust == nil {
			http.Error(w, "offline update trust roots are not installed", http.StatusServiceUnavailable)
			return
		}
		rawMetadata := r.FormValue("metadata")
		metadata, err := decodeTargetMetadata(rawMetadata)
		if err != nil {
			http.Error(w, "signed offline target metadata is required", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file is required", http.StatusBadRequest)
			return
		}
		defer func() { _ = file.Close() }()

		// Store the file on disk. Sanitize the filename to prevent path traversal.
		safeName := filepath.Base(header.Filename)
		if safeName == "." || safeName == ".." || strings.Contains(safeName, string(filepath.Separator)) {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		destPath := filepath.Join(s.dir, slug+"_"+safeName)
		// Defense-in-depth: verify the resolved path stays within s.dir.
		absDir, _ := filepath.Abs(s.dir)
		absDest, _ := filepath.Abs(destPath)
		if !strings.HasPrefix(absDest, absDir+string(filepath.Separator)) {
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		// Stage privately in the same filesystem so the final rename is atomic.
		staged, err := os.CreateTemp(s.dir, ".airgap-upload-*")
		if err != nil {
			logger.Error("updates: cannot create staged file", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		stagedPath := staged.Name()
		defer func() {
			_ = staged.Close()
			_ = os.Remove(stagedPath)
		}()

		hasher := sha256.New()
		tee := io.TeeReader(file, hasher)
		written, err := copyAirgapUpload(staged, tee)
		if err != nil {
			logger.Error("updates: write failed", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := syncAirgapUpload(staged); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := closeAirgapUpload(staged); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		sha256Sum := hex.EncodeToString(hasher.Sum(nil))
		if metadata.Slug != slug || metadata.Filename != safeName || metadata.SizeBytes != written || metadata.SHA256 != sha256Sum {
			http.Error(w, "offline target metadata does not match uploaded bytes", http.StatusBadRequest)
			return
		}
		canonical, err := canonicalTargetMetadata(metadata)
		if err != nil || s.trust.VerifyDetached(release.PurposeOfflineUpdate, metadata.KeyID, canonical, metadata.Signature) != nil {
			http.Error(w, "offline target signature verification failed", http.StatusBadRequest)
			return
		}

		bundle := &Bundle{
			Version:         metadata.Version,
			Platform:        metadata.Platform,
			Slug:            slug,
			Filename:        safeName,
			SHA256:          sha256Sum,
			SizeBytes:       written,
			Uploaded:        time.Now(),
			MetadataVersion: metadata.MetadataVersion,
			TargetMetadata:  rawMetadata,
		}
		// Bind the persisted expiry/key metadata to the verified signature and
		// guarantee the sidecar we write reloads: the exact persisted document
		// must still authenticate before the bundle is admitted.
		bundle, err = s.authenticatedBundle(bundle)
		if err != nil {
			http.Error(w, "offline target metadata failed re-verification", http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		if s.floor == nil {
			s.floor = make(map[string]uint64)
		}
		// The rollback floor is the highest authenticated metadata version ever
		// admitted for this slug, tracked independently of the servable bundle
		// map: an expired or pruned predecessor must still reject a still-valid
		// signed older version, including after a reload.
		floor := s.floor[slug]
		if current := s.bundle[slug]; current != nil && current.MetadataVersion > floor {
			floor = current.MetadataVersion
		}
		if floor != 0 && metadata.MetadataVersion <= floor {
			s.mu.Unlock()
			http.Error(w, "offline target metadata rollback detected", http.StatusConflict)
			return
		}
		if err := s.admitLocked(slug, written); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		if err := checkAirgapFreeReserve(s); err != nil {
			s.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInsufficientStorage)
			return
		}
		previous := s.bundle[slug]
		//nolint:gosec // G703: slug/filename validated and absDest confined to s.dir above
		if err := os.Rename(stagedPath, destPath); err != nil {
			s.mu.Unlock()
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		sidecarData, err := json.Marshal(bundle)
		if err != nil || writeAtomic(filepath.Join(s.dir, slug+".json"), sidecarData, 0o640) != nil {
			//nolint:gosec // G703: same validated, confined destination as the rename above
			_ = os.Remove(destPath)
			s.mu.Unlock()
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		s.bundle[slug] = bundle
		if metadata.MetadataVersion > s.floor[slug] {
			s.floor[slug] = metadata.MetadataVersion
		}
		if previous != nil && previous.Filename != safeName {
			//nolint:gosec // G703: sidecars are admitted only with validAirgapPart fields
			_ = os.Remove(filepath.Join(s.dir, slug+"_"+previous.Filename))
		}
		s.prunePlatformLocked(metadata.Platform)
		s.mu.Unlock()

		logger.Info("updates: air-gap bundle uploaded",
			"slug", slug,
			"version", bundle.Version,
			"sha256", sha256Sum,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundle)
	}
}

func (s *Store) requireFreeReserveLocked() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &stat); err != nil {
		return fmt.Errorf("cannot determine air-gap update filesystem capacity: %w", err)
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	if total == 0 || free*100 < total*airgapFreeReservePercent {
		return fmt.Errorf("air-gap update store requires at least %d%% free filesystem space", airgapFreeReservePercent)
	}
	return nil
}

// prunePlatformLocked retains only the newest accepted targets for a platform.
// Publication happens first, so a pruning failure can only leave an extra inert
// target; it cannot remove the just-verified rollback candidate.
func (s *Store) prunePlatformLocked(platform string) {
	var candidates []*Bundle
	for _, bundle := range s.bundle {
		if bundle.Platform == platform {
			candidates = append(candidates, bundle)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Uploaded.Equal(candidates[j].Uploaded) {
			return candidates[i].MetadataVersion > candidates[j].MetadataVersion
		}
		return candidates[i].Uploaded.After(candidates[j].Uploaded)
	})
	if len(candidates) <= airgapRetainPerPlatform {
		return
	}
	for _, stale := range candidates[airgapRetainPerPlatform:] {
		_ = os.Remove(filepath.Join(s.dir, stale.Slug+"_"+stale.Filename))
		_ = os.Remove(filepath.Join(s.dir, stale.Slug+".json"))
		delete(s.bundle, stale.Slug)
	}
}

func (s *Store) admitLocked(replacingSlug string, incoming int64) error {
	var used int64
	for slug, bundle := range s.bundle {
		if slug != replacingSlug {
			used += bundle.SizeBytes
		}
	}
	if incoming < 0 || used > airgapStoreMaxBytes-incoming {
		return errAirgapQuota
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".airgap-metadata-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	//nolint:gosec // G703: tmpPath was returned by CreateTemp in filepath.Dir(path)
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	//nolint:gosec // G703: caller supplies a server-generated sidecar path confined to s.dir
	return os.Rename(tmpPath, path)
}

// HandleAppcast serves GET /updates/appcast — the JSON feed for Tauri updater.
// It reads from the air-gap store and serves local file paths.
func (s *Store) HandleAppcast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bundles := s.List()

	type appcastEntry struct {
		Version string `json:"version"`
		Slug    string `json:"slug"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size_bytes"`
	}

	entries := make([]appcastEntry, 0, len(bundles))
	for _, b := range bundles {
		// Expired and never-authenticated bundles are not advertised.
		if !servable(b) {
			continue
		}
		entries = append(entries, appcastEntry{
			Version: b.Version,
			Slug:    b.Slug,
			URL:     "/updates/" + b.Slug + "/" + b.Filename,
			SHA256:  b.SHA256,
			Size:    b.SizeBytes,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"updates": entries,
	})
}

// ServeFile serves a previously uploaded bundle file by slug and filename.
func (s *Store) ServeFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	slug := r.PathValue("slug")
	filename := r.PathValue("filename")
	if slug == "" || filename == "" {
		http.Error(w, "slug and filename are required", http.StatusBadRequest)
		return
	}

	// Reject any path-traversal components in the request-controlled values before
	// joining: neither slug nor filename may contain a separator, ".", or "..".
	for _, part := range []string{slug, filename} {
		if part == "." || part == ".." || strings.ContainsRune(part, '/') || strings.ContainsRune(part, filepath.Separator) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
	}
	bundle := s.Get(slug)
	// Quarantined (legacy unsigned / failed verification) and expired bundles
	// must never be served.
	if !servable(bundle) || bundle.Filename != filename {
		http.NotFound(w, r)
		return
	}

	filePath := filepath.Join(s.dir, slug+"_"+filename)

	// Defense-in-depth: verify the resolved path stays within s.dir.
	absDir, _ := filepath.Abs(s.dir)
	absFile, _ := filepath.Abs(filePath)
	if absFile != absDir && !strings.HasPrefix(absFile, absDir+string(filepath.Separator)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(filename)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	//nolint:gosec // G703: slug/filename rejected for separators/./.. above, then confined within s.dir (abs-prefix check)
	http.ServeFile(w, r, filePath)
}
