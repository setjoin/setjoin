package updates

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

func signedTargetStore(t *testing.T, dir, slug, filename string, payload []byte, metadataVersion uint64) (*Store, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := release.NewTrustStore([]release.TrustedKey{{ID: "offline-test", Purpose: release.PurposeOfflineUpdate, PublicKey: public}}, false)
	if err != nil {
		t.Fatal(err)
	}
	store, err := newStore(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	metadata := targetMetadata{SchemaVersion: 1, MetadataVersion: metadataVersion, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339), Slug: slug, Version: "1.2.3", Platform: "desktop", Filename: filename, SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), KeyID: "offline-test"}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, canonical))
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return store, string(raw)
}

func uploadTarget(t *testing.T, store *Store, slug, filename, metadata string, payload []byte) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("slug", slug)
	_ = mw.WriteField("metadata", metadata)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(payload)
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/updates/airgap/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	store.HandleUpload(slog.New(slog.NewTextHandler(io.Discard, nil)))(rr, req)
	return rr
}

// TestHandleUpload_RejectsTraversalSlug verifies a slug containing path
// separators or ".." is rejected before any file is written, and that no
// sidecar .json escapes the store directory.
func TestHandleUpload_RejectsTraversalSlug(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := store.HandleUpload(slog.New(slog.NewTextHandler(io.Discard, nil)))

	for _, slug := range []string{"../evil", "..", ".", "a/b", `a\b`, "../../etc/cron.d/x"} {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		_ = mw.WriteField("slug", slug)
		fw, _ := mw.CreateFormFile("file", "bundle.bin")
		_, _ = fw.Write([]byte("payload"))
		mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/admin/updates/airgap/upload", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		rr := httptest.NewRecorder()
		handler(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("slug %q: got status %d, want 400", slug, rr.Code)
		}
	}

	// No file may have escaped the store directory.
	parent := filepath.Dir(dir)
	entries, _ := os.ReadDir(parent)
	for _, e := range entries {
		if filepath.Join(parent, e.Name()) != dir && e.Name() == "evil.json" {
			t.Fatalf("traversal slug wrote a file outside the store dir: %s", e.Name())
		}
	}
}

// TestHandleUpload_AcceptsValidSlug confirms the guard does not reject normal slugs.
func TestHandleUpload_AcceptsValidSlug(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("payload")
	store, metadata := signedTargetStore(t, dir, "macos-arm64", "bundle.bin", payload, 1)
	handler := store.HandleUpload(slog.New(slog.NewTextHandler(io.Discard, nil)))

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("slug", "macos-arm64")
	_ = mw.WriteField("metadata", metadata)
	fw, _ := mw.CreateFormFile("file", "bundle.bin")
	_, _ = fw.Write(payload)
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/updates/airgap/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("valid slug: got status %d, want 200", rr.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "macos-arm64.json")); err != nil {
		t.Errorf("expected sidecar written: %v", err)
	}
}

func TestServeFileIsInertAttachment(t *testing.T) {
	dir := t.TempDir()
	payload := []byte(`<html><script>parent.postMessage(document.cookie,"*")</script></html>`)
	if err := os.WriteFile(filepath.Join(dir, "desktop_payload.html"), payload, 0o640); err != nil {
		t.Fatal(err)
	}
	store := &Store{dir: dir, bundle: map[string]*Bundle{
		// Bundles in the map are admitted only with authenticated target
		// metadata; the handler enforces the authenticated expiry.
		"desktop": {Slug: "desktop", Filename: "payload.html", SizeBytes: int64(len(payload)), ExpiresAt: time.Now().UTC().Add(time.Hour)},
	}}
	req := httptest.NewRequest(http.MethodGet, "/updates/desktop/payload.html", nil)
	req.SetPathValue("slug", "desktop")
	req.SetPathValue("filename", "payload.html")
	rec := httptest.NewRecorder()
	store.ServeFile(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != `attachment; filename="payload.html"` {
		t.Fatalf("Content-Disposition = %q", got)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("missing inert-download security headers")
	}
}

func TestAirgapStoreQuotaAccountsForReplacement(t *testing.T) {
	store := &Store{bundle: map[string]*Bundle{
		"desktop": {Slug: "desktop", SizeBytes: airgapStoreMaxBytes - 10},
	}}
	if err := store.admitLocked("desktop", 20); err != nil {
		t.Fatalf("replacement should discount the old slug: %v", err)
	}
	store.bundle["server"] = &Bundle{Slug: "server", SizeBytes: 11}
	if err := store.admitLocked("desktop", airgapStoreMaxBytes); !errors.Is(err, errAirgapQuota) {
		t.Fatalf("quota error = %v, want %v", err, errAirgapQuota)
	}
}

func TestHandleUploadRejectsSignatureMutationAndRollback(t *testing.T) {
	dir := t.TempDir()
	payload := []byte("signed payload")
	store, metadata := signedTargetStore(t, dir, "desktop", "bundle.bin", payload, 2)

	var tampered map[string]any
	if err := json.Unmarshal([]byte(metadata), &tampered); err != nil {
		t.Fatal(err)
	}
	tampered["version"] = "9.9.9"
	bad, _ := json.Marshal(tampered)
	if rr := uploadTarget(t, store, "desktop", "bundle.bin", string(bad), payload); rr.Code != http.StatusBadRequest {
		t.Fatalf("tampered signature status = %d, want 400", rr.Code)
	}
	if rr := uploadTarget(t, store, "desktop", "bundle.bin", metadata, payload); rr.Code != http.StatusOK {
		t.Fatalf("initial upload status = %d, want 200", rr.Code)
	}
	if rr := uploadTarget(t, store, "desktop", "bundle.bin", metadata, payload); rr.Code != http.StatusConflict {
		t.Fatalf("rollback status = %d, want 409", rr.Code)
	}
}

func TestDecodeTargetMetadataRejectsTrailingJSONAndExpiry(t *testing.T) {
	base := targetMetadata{
		SchemaVersion: 1, MetadataVersion: 1, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Slug: "desktop", Version: "1", Platform: "desktop", Filename: "bundle.bin", SizeBytes: 1,
		SHA256: strings.Repeat("a", 64), KeyID: "key", Signature: "sig",
	}
	raw, _ := json.Marshal(base)
	if _, err := decodeTargetMetadata(string(raw) + `{}`); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	base.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	raw, _ = json.Marshal(base)
	if _, err := decodeTargetMetadata(string(raw)); err == nil {
		t.Fatal("expired metadata accepted")
	}
}

func TestPrunePlatformRetainsNewestThree(t *testing.T) {
	dir := t.TempDir()
	store := &Store{dir: dir, bundle: make(map[string]*Bundle)}
	for i := 1; i <= 4; i++ {
		slug := fmt.Sprintf("desktop-%d", i)
		filename := "bundle.bin"
		if err := os.WriteFile(filepath.Join(dir, slug+"_"+filename), []byte{byte(i)}, 0o640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, slug+".json"), []byte("{}"), 0o640); err != nil {
			t.Fatal(err)
		}
		store.bundle[slug] = &Bundle{Slug: slug, Filename: filename, Platform: "desktop", Uploaded: time.Unix(int64(i), 0), MetadataVersion: uint64(i)}
	}
	store.prunePlatformLocked("desktop")
	if len(store.bundle) != 3 || store.bundle["desktop-1"] != nil {
		t.Fatalf("retained bundles = %#v, want newest three", store.bundle)
	}
	if _, err := os.Stat(filepath.Join(dir, "desktop-1_bundle.bin")); !os.IsNotExist(err) {
		t.Fatalf("oldest payload was not pruned: %v", err)
	}
}

func TestNewStoreLoadsTrustRootsAndValidSidecars(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots := release.TrustRootDocument{SchemaVersion: 1, Purpose: release.PurposeOfflineUpdate, Keys: []release.TrustRootWire{{
		ID: "offline-local", Algorithm: "ed25519", PublicKey: base64.RawStdEncoding.EncodeToString(publicKey),
	}}}
	rawRoots, _ := json.Marshal(roots)
	rootPath := filepath.Join(dir, "roots.json")
	if err := os.WriteFile(rootPath, rawRoots, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OFFLINE_UPDATE_TRUST_ROOTS", rootPath)
	payload := []byte("sidecar payload")
	sum := sha256.Sum256(payload)
	metadata := targetMetadata{
		SchemaVersion: 1, MetadataVersion: 2, ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
		Slug: "desktop", Version: "1.2.3", Platform: "desktop", Filename: "bundle.bin",
		SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(sum[:]), KeyID: "offline-local",
	}
	canonical, err := canonicalTargetMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	metadata.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical))
	rawMetadata, _ := json.Marshal(metadata)
	sidecar, err := json.Marshal(Bundle{
		Version: "1.2.3", Platform: "desktop", Slug: "desktop", Filename: "bundle.bin",
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(payload)), MetadataVersion: 2,
		TargetMetadata: string(rawMetadata),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "desktop.json"), sidecar, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ignored.json"), []byte("not-json"), 0o640); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if store.trust == nil || len(store.List()) != 1 {
		t.Fatalf("loaded store = %#v", store)
	}
	loaded := store.Get("desktop")
	if loaded == nil || loaded.KeyID != "offline-local" || loaded.ExpiresAt.IsZero() {
		t.Fatalf("sidecar bundle was not admitted with derived authenticated metadata: %#v", loaded)
	}
}

func TestNewStoreRejectsUnreadableAndMalformedTrustRoots(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OFFLINE_UPDATE_TRUST_ROOTS", dir)
	if _, err := NewStore(t.TempDir()); err == nil || !strings.Contains(err.Error(), "read offline trust roots") {
		t.Fatalf("directory trust root error = %v", err)
	}
	malformed := filepath.Join(t.TempDir(), "roots.json")
	if err := os.WriteFile(malformed, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OFFLINE_UPDATE_TRUST_ROOTS", malformed)
	if _, err := NewStore(t.TempDir()); err == nil || !strings.Contains(err.Error(), "parse offline trust roots") {
		t.Fatalf("malformed trust root error = %v", err)
	}
}

func TestDecodeTargetMetadataRejectsMalformedAndIncompleteDocuments(t *testing.T) {
	if _, err := decodeTargetMetadata(`{`); err == nil {
		t.Fatal("malformed metadata accepted")
	}
	if _, err := decodeTargetMetadata(`{}`); err == nil {
		t.Fatal("incomplete metadata accepted")
	}
}

func TestAirgapHandlersRejectInvalidMethodsAndMissingInputs(t *testing.T) {
	store, err := newStore(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := store.HandleUpload(slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, tc := range []struct {
		method, body, contentType string
		want                      int
	}{
		{http.MethodGet, "", "", http.StatusMethodNotAllowed},
		{http.MethodPost, "", "multipart/form-data", http.StatusBadRequest},
	} {
		req := httptest.NewRequest(tc.method, "/admin/updates/airgap/upload", strings.NewReader(tc.body))
		req.Header.Set("Content-Type", tc.contentType)
		rr := httptest.NewRecorder()
		handler(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.method, rr.Code, tc.want)
		}
	}

	var form bytes.Buffer
	mw := multipart.NewWriter(&form)
	_ = mw.WriteField("slug", "desktop")
	_ = mw.WriteField("metadata", `{}`)
	file, _ := mw.CreateFormFile("file", "bundle.bin")
	_, _ = file.Write([]byte("payload"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/updates/airgap/upload", &form)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing trust roots: got %d, want 503", rr.Code)
	}
}

func TestHandleUploadRejectsMetadataMismatchQuotaAndReserve(t *testing.T) {
	payload := []byte("payload")

	store, metadata := signedTargetStore(t, t.TempDir(), "desktop", "bundle.bin", payload, 1)
	if rr := uploadTarget(t, store, "desktop", "bundle.bin", metadata, []byte("different")); rr.Code != http.StatusBadRequest {
		t.Fatalf("metadata mismatch = %d, want 400", rr.Code)
	}

	quotaStore, quotaMetadata := signedTargetStore(t, t.TempDir(), "desktop", "bundle.bin", payload, 1)
	quotaStore.bundle["occupied"] = &Bundle{Slug: "occupied", SizeBytes: airgapStoreMaxBytes}
	if rr := uploadTarget(t, quotaStore, "desktop", "bundle.bin", quotaMetadata, payload); rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("quota status = %d, want 507", rr.Code)
	}

	reserveStore, reserveMetadata := signedTargetStore(t, t.TempDir(), "desktop", "bundle.bin", payload, 1)
	originalReserveCheck := checkAirgapFreeReserve
	checkAirgapFreeReserve = func(*Store) error { return errors.New("reserve unavailable") }
	t.Cleanup(func() { checkAirgapFreeReserve = originalReserveCheck })
	if rr := uploadTarget(t, reserveStore, "desktop", "bundle.bin", reserveMetadata, payload); rr.Code != http.StatusInsufficientStorage {
		t.Fatalf("reserve status = %d, want 507", rr.Code)
	}
}

func TestHandleUploadReportsStagingRenameAndSidecarFailures(t *testing.T) {
	payload := []byte("payload")

	removedDir := t.TempDir()
	stagingStore, stagingMetadata := signedTargetStore(t, removedDir, "desktop", "bundle.bin", payload, 1)
	if err := os.RemoveAll(removedDir); err != nil {
		t.Fatal(err)
	}
	if rr := uploadTarget(t, stagingStore, "desktop", "bundle.bin", stagingMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("staging status = %d, want 500", rr.Code)
	}

	renameDir := t.TempDir()
	renameStore, renameMetadata := signedTargetStore(t, renameDir, "desktop", "bundle.bin", payload, 1)
	if err := os.Mkdir(filepath.Join(renameDir, "desktop_bundle.bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if rr := uploadTarget(t, renameStore, "desktop", "bundle.bin", renameMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("rename status = %d, want 500", rr.Code)
	}

	sidecarDir := t.TempDir()
	sidecarStore, sidecarMetadata := signedTargetStore(t, sidecarDir, "desktop", "bundle.bin", payload, 1)
	if err := os.Mkdir(filepath.Join(sidecarDir, "desktop.json"), 0o750); err != nil {
		t.Fatal(err)
	}
	if rr := uploadTarget(t, sidecarStore, "desktop", "bundle.bin", sidecarMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("sidecar status = %d, want 500", rr.Code)
	}
}

func TestHandleUploadReportsCopySyncAndCloseFailures(t *testing.T) {
	payload := []byte("payload")
	originalCopy := copyAirgapUpload
	originalSync := syncAirgapUpload
	originalClose := closeAirgapUpload
	t.Cleanup(func() {
		copyAirgapUpload = originalCopy
		syncAirgapUpload = originalSync
		closeAirgapUpload = originalClose
	})

	copyStore, copyMetadata := signedTargetStore(t, t.TempDir(), "copy", "bundle.bin", payload, 1)
	copyAirgapUpload = func(io.Writer, io.Reader) (int64, error) { return 0, errors.New("copy failed") }
	if rr := uploadTarget(t, copyStore, "copy", "bundle.bin", copyMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("copy status = %d, want 500", rr.Code)
	}
	copyAirgapUpload = originalCopy

	syncStore, syncMetadata := signedTargetStore(t, t.TempDir(), "sync", "bundle.bin", payload, 1)
	syncAirgapUpload = func(*os.File) error { return errors.New("sync failed") }
	if rr := uploadTarget(t, syncStore, "sync", "bundle.bin", syncMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("sync status = %d, want 500", rr.Code)
	}
	syncAirgapUpload = originalSync

	closeStore, closeMetadata := signedTargetStore(t, t.TempDir(), "close", "bundle.bin", payload, 1)
	closeAirgapUpload = func(*os.File) error { return errors.New("close failed") }
	if rr := uploadTarget(t, closeStore, "close", "bundle.bin", closeMetadata, payload); rr.Code != http.StatusInternalServerError {
		t.Fatalf("close status = %d, want 500", rr.Code)
	}
}

func TestAirgapMetadataAndFilesystemFailureBranches(t *testing.T) {
	payload := []byte("payload")
	store, _ := signedTargetStore(t, t.TempDir(), "desktop", "bundle.bin", payload, 1)
	if rr := uploadTarget(t, store, "desktop", "bundle.bin", "", payload); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing metadata status = %d, want 400", rr.Code)
	}
	missing := filepath.Join(t.TempDir(), "missing")
	if err := (&Store{dir: missing}).requireFreeReserveLocked(); err == nil {
		t.Fatal("missing store filesystem accepted")
	}
	if err := writeAtomic(filepath.Join(missing, "sidecar.json"), []byte(`{}`), 0o640); err == nil {
		t.Fatal("atomic write into missing directory succeeded")
	}

	tieDir := t.TempDir()
	tieStore := &Store{dir: tieDir, bundle: map[string]*Bundle{}}
	stamp := time.Now()
	for i := 1; i <= 4; i++ {
		slug := fmt.Sprintf("tie-%d", i)
		tieStore.bundle[slug] = &Bundle{Slug: slug, Filename: "bundle.bin", Platform: "desktop", Uploaded: stamp, MetadataVersion: uint64(i)}
	}
	tieStore.prunePlatformLocked("desktop")
	if len(tieStore.bundle) != airgapRetainPerPlatform || tieStore.bundle["tie-1"] != nil {
		t.Fatalf("tie pruning result = %#v", tieStore.bundle)
	}
}

func TestAppcastAndServeFileValidation(t *testing.T) {
	store := &Store{dir: t.TempDir(), bundle: map[string]*Bundle{
		"desktop": {Slug: "desktop", Filename: "bundle.bin", Version: "1.2.3", SHA256: strings.Repeat("a", 64), SizeBytes: 7, ExpiresAt: time.Now().UTC().Add(time.Hour)},
	}}
	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		req := httptest.NewRequest(method, "/updates/appcast", nil)
		rr := httptest.NewRecorder()
		store.HandleAppcast(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("appcast %s = %d", method, rr.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/updates/appcast", nil)
	rr := httptest.NewRecorder()
	store.HandleAppcast(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"version":"1.2.3"`) {
		t.Fatalf("appcast = %d %s", rr.Code, rr.Body.String())
	}

	for _, tc := range []struct {
		method, slug, filename string
		want                   int
	}{
		{http.MethodPost, "desktop", "bundle.bin", http.StatusMethodNotAllowed},
		{http.MethodGet, "", "bundle.bin", http.StatusBadRequest},
		{http.MethodGet, "..", "bundle.bin", http.StatusBadRequest},
		{http.MethodGet, "missing", "bundle.bin", http.StatusNotFound},
	} {
		req := httptest.NewRequest(tc.method, "/updates/x/y", nil)
		req.SetPathValue("slug", tc.slug)
		req.SetPathValue("filename", tc.filename)
		rr := httptest.NewRecorder()
		store.ServeFile(rr, req)
		if rr.Code != tc.want {
			t.Fatalf("serve %+v = %d", tc, rr.Code)
		}
	}
}
