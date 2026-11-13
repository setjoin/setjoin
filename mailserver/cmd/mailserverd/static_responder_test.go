package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/middleware"
)

func writeStaticTestFile(t *testing.T, root, name, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testFileDigest(t *testing.T, path string) (int64, string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	return int64(len(contents)), hex.EncodeToString(digest[:])
}

func writeStaticTestManifest(t *testing.T, root, buildID string, sidecars map[string]map[string]string) {
	t.Helper()
	writeStaticTestFile(t, root, "_app/version.json", `{"version":"`+buildID+`"}`)
	var assets []staticAssetRecord
	err := filepath.WalkDir(root, func(filePath string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, filePath)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if rel == staticRepresentationManifest || strings.HasSuffix(rel, ".br") || strings.HasSuffix(rel, ".gz") {
			return nil
		}
		identityBytes, identityHash := testFileDigest(t, filePath)
		record := staticAssetRecord{
			Path: "/" + rel, IdentityBytes: identityBytes, IdentitySHA256: identityHash,
			Representations: map[string]staticSidecar{},
		}
		for encoding, suffix := range sidecars[rel] {
			sidecarPath := filePath + suffix
			bytes, hash := testFileDigest(t, sidecarPath)
			record.Representations[encoding] = staticSidecar{Path: "/" + rel + suffix, Bytes: bytes, SHA256: hash}
		}
		assets = append(assets, record)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := json.Marshal(staticAssetManifest{SchemaVersion: 1, BuildID: buildID, Assets: assets})
	if err != nil {
		t.Fatal(err)
	}
	writeStaticTestFile(t, root, staticRepresentationManifest, string(manifest))
}

func TestSPAStaticHandlerNegotiatesRepresentationsAndHTTPValidators(t *testing.T) {
	root := t.TempDir()
	writeStaticTestFile(t, root, "index.html", strings.Repeat("<html>Setjoin</html>", 8))
	writeStaticTestFile(t, root, "_app/immutable/app.12345678.js", strings.Repeat("export const value = 1;", 20))
	writeStaticTestFile(t, root, "_app/immutable/app.12345678.js.br", "brotli-sidecar")
	writeStaticTestFile(t, root, "_app/immutable/app.12345678.js.gz", "gzip-sidecar-data")
	writeStaticTestManifest(t, root, "build-1", map[string]map[string]string{
		"_app/immutable/app.12345678.js": {"br": ".br", "gzip": ".gz"},
	})
	handler, err := newSPAStaticHandler(root, nil)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("brotli wins an equal-quality tie", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/_app/immutable/app.12345678.js", nil)
		request.Header.Set("Accept-Encoding", "gzip, br")
		response := httptest.NewRecorder()
		// WP2: Cache-Control is middleware-owned — assert through the
		// assembled chain, exactly as production serves it.
		middleware.CacheControl(handler).ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "br" || response.Body.String() != "brotli-sidecar" {
			t.Fatalf("unexpected Brotli response: status=%d encoding=%q body=%q", response.Code, response.Header().Get("Content-Encoding"), response.Body.String())
		}
		if response.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || response.Header().Get("Vary") != "Accept-Encoding" {
			t.Fatalf("unexpected cache headers: %v", response.Header())
		}
		etag := response.Header().Get("ETag")
		conditional := httptest.NewRequest(http.MethodGet, "/_app/immutable/app.12345678.js", nil)
		conditional.Header.Set("Accept-Encoding", "br")
		conditional.Header.Set("If-None-Match", etag)
		conditionalResponse := httptest.NewRecorder()
		handler.ServeHTTP(conditionalResponse, conditional)
		if conditionalResponse.Code != http.StatusNotModified || conditionalResponse.Body.Len() != 0 {
			t.Fatalf("conditional status=%d body=%q", conditionalResponse.Code, conditionalResponse.Body.String())
		}
	})

	t.Run("q values select gzip", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/_app/immutable/app.12345678.js", nil)
		request.Header.Set("Accept-Encoding", "br;q=0.2, gzip;q=0.9")
		response := httptest.NewRecorder()
		// WP2: Cache-Control is middleware-owned — assert through the
		// assembled chain, exactly as production serves it.
		middleware.CacheControl(handler).ServeHTTP(response, request)
		if response.Header().Get("Content-Encoding") != "gzip" || response.Body.String() != "gzip-sidecar-data" {
			t.Fatalf("encoding=%q body=%q", response.Header().Get("Content-Encoding"), response.Body.String())
		}
	})

	t.Run("range stays on identity", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/_app/immutable/app.12345678.js", nil)
		request.Header.Set("Accept-Encoding", "br")
		request.Header.Set("Range", "bytes=0-5")
		response := httptest.NewRecorder()
		// WP2: Cache-Control is middleware-owned — assert through the
		// assembled chain, exactly as production serves it.
		middleware.CacheControl(handler).ServeHTTP(response, request)
		if response.Code != http.StatusPartialContent || response.Header().Get("Content-Encoding") != "" || response.Body.String() != "export" {
			t.Fatalf("status=%d encoding=%q body=%q", response.Code, response.Header().Get("Content-Encoding"), response.Body.String())
		}
	})

	t.Run("HEAD has headers and no body", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodHead, "/_app/immutable/app.12345678.js", nil)
		request.Header.Set("Accept-Encoding", "br")
		response := httptest.NewRecorder()
		// WP2: Cache-Control is middleware-owned — assert through the
		// assembled chain, exactly as production serves it.
		middleware.CacheControl(handler).ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Body.Len() != 0 || response.Header().Get("Content-Encoding") != "br" {
			t.Fatalf("status=%d encoding=%q body=%q", response.Code, response.Header().Get("Content-Encoding"), response.Body.String())
		}
	})
}

func TestSPAStaticHandlerFallsBackAndFailsClosed(t *testing.T) {
	t.Run("missing optional sidecar serves identity", func(t *testing.T) {
		root := t.TempDir()
		writeStaticTestFile(t, root, "index.html", strings.Repeat("identity-shell", 30))
		writeStaticTestManifest(t, root, "build-1", nil)
		handler, err := newSPAStaticHandler(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Accept-Encoding", "br")
		response := httptest.NewRecorder()
		// WP2: Cache-Control is middleware-owned — assert through the
		// assembled chain, exactly as production serves it.
		middleware.CacheControl(handler).ServeHTTP(response, request)
		if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "" || !strings.Contains(response.Body.String(), "identity-shell") {
			t.Fatalf("status=%d encoding=%q body=%q", response.Code, response.Header().Get("Content-Encoding"), response.Body.String())
		}
		refused := httptest.NewRequest(http.MethodGet, "/", nil)
		refused.Header.Set("Accept-Encoding", "identity;q=0, *;q=0")
		refusedResponse := httptest.NewRecorder()
		handler.ServeHTTP(refusedResponse, refused)
		if refusedResponse.Code != http.StatusNotAcceptable {
			t.Fatalf("status=%d want 406", refusedResponse.Code)
		}
		wildcardRefused := httptest.NewRequest(http.MethodGet, "/", nil)
		wildcardRefused.Header.Set("Accept-Encoding", "*;q=0")
		wildcardResponse := httptest.NewRecorder()
		handler.ServeHTTP(wildcardResponse, wildcardRefused)
		if wildcardResponse.Code != http.StatusNotAcceptable {
			t.Fatalf("wildcard status=%d want 406", wildcardResponse.Code)
		}
	})

	t.Run("stale build and corrupt sidecar refuse construction", func(t *testing.T) {
		root := t.TempDir()
		writeStaticTestFile(t, root, "index.html", strings.Repeat("shell", 100))
		writeStaticTestFile(t, root, "index.html.br", "br")
		writeStaticTestManifest(t, root, "build-1", map[string]map[string]string{"index.html": {"br": ".br"}})
		writeStaticTestFile(t, root, "index.html.br", "tampered")
		if _, err := newSPAStaticHandler(root, nil); err == nil {
			t.Fatal("corrupt sidecar must fail construction")
		}
		writeStaticTestFile(t, root, "index.html.br", "br")
		writeStaticTestFile(t, root, "_app/version.json", `{"version":"build-2"}`)
		if _, err := newSPAStaticHandler(root, nil); err == nil {
			t.Fatal("cross-build manifest must fail construction")
		}
	})

	t.Run("path traversal and asset fallback are contained", func(t *testing.T) {
		root := t.TempDir()
		writeStaticTestFile(t, root, "index.html", "<html>shell</html>")
		writeStaticTestManifest(t, root, "build-1", nil)
		handler, err := newSPAStaticHandler(root, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{"/../secret", "/_app/immutable/missing.js"} {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("%s status=%d want 404", target, response.Code)
			}
		}
	})

	t.Run("missing representation manifest refuses construction", func(t *testing.T) {
		root := t.TempDir()
		writeStaticTestFile(t, root, "index.html", "<html>shell</html>")
		if _, err := newSPAStaticHandler(root, nil); err == nil || !strings.Contains(err.Error(), "manifest is missing") {
			t.Fatalf("missing manifest error = %v", err)
		}
	})
}
