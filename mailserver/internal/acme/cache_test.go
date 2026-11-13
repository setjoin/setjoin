package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func TestCachePutGet(t *testing.T) {
	dir := t.TempDir()
	cache := &DirCache{Dir: dir}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{}, &x509.Certificate{}, &key.PublicKey, key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	err := cache.Put("test.example.com", certPEM)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := cache.Get("test.example.com")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(certPEM) {
		t.Fatal("Get returned different cert than Put")
	}
}

func TestCacheDelete(t *testing.T) {
	dir := t.TempDir()
	cache := &DirCache{Dir: dir}

	cache.Put("del.example.com", []byte("test"))
	cache.Delete("del.example.com")

	_, err := cache.Get("del.example.com")
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist after Delete, got %v", err)
	}
}

func TestCacheAutoCreateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "nested")
	cache := &DirCache{Dir: dir}
	// Put should create the directory.
	err := cache.Put("auto.example.com", []byte("test"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
}

// ── writeFileAtomic failure arms ─────────────────────────────────────────────
// Each error return of the atomic write path is exercised so a failing cache
// write can never be mistaken for a stored blob.

// TestCachePutMkdirFailsWhenCacheDirIsAFile: the cache path colliding with a
// regular file makes os.MkdirAll fail — reported as "acme cache mkdir".
func TestCachePutMkdirFailsWhenCacheDirIsAFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "notadir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cache := &DirCache{Dir: filepath.Join(blocker, "cache")}
	err := cache.Put("mkdir.example.com", []byte("test"))
	if err == nil || !strings.Contains(err.Error(), "acme cache mkdir") {
		t.Fatalf("Put err = %v, want acme cache mkdir failure", err)
	}
}

// TestCachePutTempCreateFailsOnReadOnlyDir: a directory without write
// permission makes os.CreateTemp fail — reported as "acme cache temp".
func TestCachePutTempCreateFailsOnReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission-denied failures are not reproducible")
	}
	dir := filepath.Join(t.TempDir(), "ro")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil { // r-x only: no create
		t.Fatal(err)
	}
	cache := &DirCache{Dir: dir}
	err := cache.Put("ro.example.com", []byte("test"))
	if err == nil || !strings.Contains(err.Error(), "acme cache temp") {
		t.Fatalf("Put err = %v, want acme cache temp failure", err)
	}
}

// TestCachePutWriteFailurePreservesPreviousBlob: an interrupted write must
// surface ("acme cache write") and leave the PREVIOUS cache blob intact —
// the reader never observes a partial or destroyed entry (ACME-002).
func TestCachePutWriteFailurePreservesPreviousBlob(t *testing.T) {
	dir := t.TempDir()
	cache := &DirCache{Dir: dir}
	if err := cache.Put("atomic.example.com", []byte("previous-blob")); err != nil {
		t.Fatalf("seed Put: %v", err)
	}

	orig := writePayload
	writePayload = func(*os.File, []byte) error { return errors.New("injected interrupted write") }
	defer func() { writePayload = orig }()

	err := cache.Put("atomic.example.com", []byte("replacement-blob"))
	if err == nil || !strings.Contains(err.Error(), "acme cache write") {
		t.Fatalf("Put err = %v, want acme cache write failure", err)
	}
	got, err := cache.Get("atomic.example.com")
	if err != nil {
		t.Fatalf("Get after failed Put: %v", err)
	}
	if string(got) != "previous-blob" {
		t.Errorf("failed Put destroyed the previous blob: got %q", got)
	}
}

// TestCachePutSyncFailure: closing the temp fd from the write seam makes the
// subsequent Sync fail — reported as "acme cache sync".
func TestCachePutSyncFailure(t *testing.T) {
	orig := writePayload
	writePayload = func(f *os.File, data []byte) error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		return f.Close() // the closed fd makes tmp.Sync below fail
	}
	defer func() { writePayload = orig }()

	cache := &DirCache{Dir: t.TempDir()}
	err := cache.Put("sync.example.com", []byte("test"))
	if err == nil || !strings.Contains(err.Error(), "acme cache sync") {
		t.Fatalf("Put err = %v, want acme cache sync failure", err)
	}
}

// TestCachePutChmodFailureWhenTempVanishes: moving the temp file away from the
// write seam keeps Sync/Close working (they operate on the open fd) while
// os.Chmod(tmpName) fails with ENOENT — reported as "acme cache chmod".
func TestCachePutChmodFailureWhenTempVanishes(t *testing.T) {
	orig := writePayload
	writePayload = func(f *os.File, data []byte) error {
		if _, err := f.Write(data); err != nil {
			return err
		}
		return os.Rename(f.Name(), f.Name()+".moved")
	}
	defer func() { writePayload = orig }()

	cache := &DirCache{Dir: t.TempDir()}
	err := cache.Put("chmod.example.com", []byte("test"))
	if err == nil || !strings.Contains(err.Error(), "acme cache chmod") {
		t.Fatalf("Put err = %v, want acme cache chmod failure", err)
	}
}

// ── ServeFromAutocertCache ───────────────────────────────────────────────────

// TestServeFromAutocertCacheUnparseableCacheEntry: cached bytes that are not a
// valid keypair are skipped (serve-nil), never propagated as an error to the
// TLS handshake path.
func TestServeFromAutocertCacheUnparseableCacheEntry(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"srv.example.com", "srv.example.com-rsa"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("garbage, not a PEM keypair"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(dir),
		HostPolicy: autocert.HostWhitelist("srv.example.com"),
	}
	if got := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: "srv.example.com"}); got != nil {
		t.Fatalf("unparseable cache entry served a certificate: %+v", got)
	}
}

// TestServeFromAutocertCacheServesValidAndRejectsHostnameMismatch: a cached
// certificate matching the SNI is served; a cached certificate NOT matching it
// is skipped so the caller's fallback chain proceeds.
func TestServeFromAutocertCacheServesValidAndRejectsHostnameMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ok.example.com"},
		DNSNames:     []string{"ok.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	blob = append(blob, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)

	dir := t.TempDir()
	// Cache the same cert under two SNI names: "ok" matches its SANs, "other"
	// does not (the hostname-mismatch skip arm).
	for _, name := range []string{"ok.example.com", "other.example.com"} {
		if err := os.WriteFile(filepath.Join(dir, name), blob, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mgr := &autocert.Manager{
		Cache:      autocert.DirCache(dir),
		HostPolicy: autocert.HostWhitelist("ok.example.com", "other.example.com"),
	}

	cert := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: "ok.example.com"})
	if cert == nil {
		t.Fatal("valid cached certificate was not served")
	}
	if got := ServeFromAutocertCache(mgr, &tls.ClientHelloInfo{ServerName: "other.example.com"}); got != nil {
		t.Fatalf("certificate for ok.example.com served for other.example.com: %+v", got)
	}
}

// ── autocert.DirCache interoperability boundary (med-shard2-010) ────────────
// These tests pin the ACTUAL contract against the REAL autocert.DirCache:
// blob-level compatibility only. The namespace (hash vs literal), the method
// surface (context-free vs ctx-aware) and several access semantics differ by
// design; the DirCache doc comment in cache.go states the same contract.

// pemKeypairBlob builds a representative autocert blob — PEM certificate
// followed by PEM private key, the layout autocert.Manager stores.
func pemKeypairBlob(t *testing.T, dnsName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	blob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(blob, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
}

// isLowerHex64 reports whether s is exactly 64 lowercase hex characters —
// the filename namespace this cache derives from every domain.
func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

// TestCacheAutocertSharedDirNamesAndModes: with both caches pointed at ONE
// directory, the same domain produces two disjoint files — autocert under the
// literal cache key, this cache under hex(SHA-256(domain)) — with identical
// hygiene on both sides: 0600 blobs in a 0700 dir. Each store still reads
// exactly its own entry.
func TestCacheAutocertSharedDirNamesAndModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	ours := &DirCache{Dir: dir}
	theirs := autocert.DirCache(dir)
	dom := "boundary.example.com"

	if err := theirs.Put(context.Background(), dom, []byte("autocert-entry")); err != nil {
		t.Fatalf("autocert DirCache.Put: %v", err)
	}
	if err := ours.Put(dom, []byte("setjoin-entry")); err != nil {
		t.Fatalf("DirCache.Put: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	hash := filepath.Base(ours.certPath(dom))
	if len(entries) != 2 {
		t.Fatalf("shared dir has %d entries (%v), want exactly the two disjoint namespaces {%q, %q}",
			len(entries), entries, dom, hash)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name()] = true
	}
	if !seen[dom] || !seen[hash] {
		t.Fatalf("cache entries %v, want the literal key %q and the hashed name %q", seen, dom, hash)
	}
	if hash == dom || !isLowerHex64(hash) {
		t.Fatalf("hashed name %q is not a 64-char lowercase-hex namespace disjoint from the literal key", hash)
	}

	for _, name := range []string{filepath.Join(dir, dom), ours.certPath(dom)} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s mode = %v, want 0600 on both sides of the boundary", name, got)
		}
	}
	if fi, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if got := fi.Mode().Perm(); got != 0o700 {
		t.Errorf("cache dir mode = %v, want 0700 (both caches create it so)", got)
	}

	if got, err := theirs.Get(context.Background(), dom); err != nil || string(got) != "autocert-entry" {
		t.Errorf("autocert.Get = %q, %v; want its own entry", got, err)
	}
	if got, err := ours.Get(dom); err != nil || string(got) != "setjoin-entry" {
		t.Errorf("DirCache.Get = %q, %v; want its own entry", got, err)
	}
}

// TestCacheAutocertBoundaryCrossReadsMiss: neither store can reach the
// other's entry through its own key derivation, even in one shared directory.
// autocert looks up the literal domain and misses our hashed file; this cache
// hashes the domain and misses autocert's literal file. Shared-directory
// compatibility is therefore none — the namespaces are strictly disjoint.
func TestCacheAutocertBoundaryCrossReadsMiss(t *testing.T) {
	dirA := t.TempDir()
	ours := &DirCache{Dir: dirA}
	if err := ours.Put("miss.example.com", []byte("ours")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := autocert.DirCache(dirA).Get(context.Background(), "miss.example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("autocert.Get over our hashed entry: err = %v, want ErrCacheMiss", err)
	}

	dirB := t.TempDir()
	if err := autocert.DirCache(dirB).Put(context.Background(), "miss.example.com", []byte("theirs")); err != nil {
		t.Fatalf("autocert Put: %v", err)
	}
	if _, err := (&DirCache{Dir: dirB}).Get("miss.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("DirCache.Get over autocert's literal entry: err = %v, want os.ErrNotExist", err)
	}
}

// TestCacheAutocertBlobPayloadCompatibility: the interoperable layer is the
// BLOB. Both stores write the payload verbatim — no wrapping, metadata or
// transformation — so an autocert-produced blob stored by this cache is
// byte-identical on disk and round-trips exactly for any autocert-style
// consumer (ServeFromAutocertCache), and the reverse placement works too.
func TestCacheAutocertBlobPayloadCompatibility(t *testing.T) {
	blob := pemKeypairBlob(t, "blob.example.com")
	dir := t.TempDir()
	ours := &DirCache{Dir: dir}
	theirs := autocert.DirCache(dir)

	if err := theirs.Put(context.Background(), "blob.example.com", blob); err != nil {
		t.Fatalf("autocert Put: %v", err)
	}
	autocertOnDisk, err := os.ReadFile(filepath.Join(dir, "blob.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(autocertOnDisk, blob) {
		t.Fatal("autocert wrapped or transformed the payload on disk")
	}

	if err := ours.Put("blob.example.com", blob); err != nil {
		t.Fatalf("Put: %v", err)
	}
	oursOnDisk, err := os.ReadFile(ours.certPath("blob.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oursOnDisk, blob) {
		t.Fatal("this cache wrapped or transformed the payload on disk")
	}

	gotTheirs, err := theirs.Get(context.Background(), "blob.example.com")
	if err != nil || !bytes.Equal(gotTheirs, blob) {
		t.Fatalf("autocert round-trip = %d bytes, %v; want the exact blob", len(gotTheirs), err)
	}
	gotOurs, err := ours.Get("blob.example.com")
	if err != nil || !bytes.Equal(gotOurs, blob) {
		t.Fatalf("this cache round-trip = %d bytes, %v; want the exact blob", len(gotOurs), err)
	}
}

// TestCacheAutocertAccessBehavior: access semantics on each side of the
// boundary. autocert honors context cancellation, returns ErrCacheMiss for
// absent keys and treats Delete of an absent key as a no-op; this cache is
// context-free and reports os.ErrNotExist from both Get and Delete. Hash
// derivation also confines every domain — including traversal-shaped ones —
// inside Dir, where autocert must sanitize literal names instead.
func TestCacheAutocertAccessBehavior(t *testing.T) {
	dir := t.TempDir()
	ours := &DirCache{Dir: dir}
	theirs := autocert.DirCache(dir)

	if err := theirs.Put(context.Background(), "ctx.example.com", []byte("x")); err != nil {
		t.Fatalf("autocert Put: %v", err)
	}

	// autocert honors a canceled context. Deterministic proof: the Get
	// goroutine blocks opening a writerless FIFO, so only the canceled
	// context can win autocert's select. This cache has no context to
	// honor at all (no ctx parameter anywhere in its method surface).
	if runtime.GOOS != "windows" {
		fifo := filepath.Join(dir, "blocked.example.com")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Skipf("mkfifo unavailable: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := theirs.Get(ctx, "blocked.example.com"); !errors.Is(err, context.Canceled) {
			t.Errorf("autocert.Get with canceled context: err = %v, want context.Canceled", err)
		}
	}

	// Missing-entry semantics differ.
	if _, err := theirs.Get(context.Background(), "absent.example.com"); !errors.Is(err, autocert.ErrCacheMiss) {
		t.Errorf("autocert.Get miss: err = %v, want ErrCacheMiss", err)
	}
	if _, err := ours.Get("absent.example.com"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("DirCache.Get miss: err = %v, want os.ErrNotExist", err)
	}
	if err := theirs.Delete(context.Background(), "absent.example.com"); err != nil {
		t.Errorf("autocert.Delete of absent key = %v, want nil (no-op)", err)
	}
	if err := ours.Delete("absent.example.com"); err == nil {
		t.Error("DirCache.Delete of absent key = nil, want os.ErrNotExist")
	}

	// Hash confinement: even a traversal-shaped domain never escapes Dir.
	p := ours.certPath("../../etc/passwd")
	if filepath.Dir(p) != filepath.Clean(dir) {
		t.Errorf("traversal-shaped domain escaped the cache dir: %q", p)
	}
}
