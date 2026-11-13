package acme

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// writePayload writes data to an open temp file. It is a seam so tests can
// interrupt a write mid-flight and prove the previous cache blob survives.
var writePayload = func(f *os.File, data []byte) error {
	_, err := f.Write(data)
	return err
}

// writeFileAtomic writes data to path via a temp file in the same directory
// plus rename, so concurrent readers observe either the previous blob or the
// complete new one — never a partial write (ACME-002: cache replacement is
// part of the renewal idempotency contract).
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("acme cache mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".acme-*.tmp")
	if err != nil {
		return fmt.Errorf("acme cache temp: %w", err)
	}
	tmpName := tmp.Name()
	// No-op once the rename below succeeded; otherwise removes the orphan.
	defer os.Remove(tmpName) //nolint:errcheck // best-effort cleanup of our own temp file

	if err := writePayload(tmp, data); err != nil {
		tmp.Close() //nolint:errcheck // already failing; original error is what matters
		return fmt.Errorf("acme cache write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() //nolint:errcheck // already failing; original error is what matters
		return fmt.Errorf("acme cache sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("acme cache close: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("acme cache chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("acme cache rename: %w", err)
	}
	return nil
}

// DirCache stores cert cache blobs on disk. The supported interoperability
// boundary with autocert.DirCache is BLOB-LEVEL ONLY — pinned by the
// TestCacheAutocert* tests against the real autocert cache (x/crypto):
//
//   - Blob compatible: both stores keep opaque raw bytes and write them
//     verbatim — no wrapping or transformation — as 0600 files in a 0700 dir
//     via same-directory temp+rename, with no file locking. An autocert blob
//     (PEM keypair) stored here round-trips byte-identical for autocert-style
//     consumers (see ServeFromAutocertCache), and vice versa.
//
//   - NOT directory-compatible: autocert addresses files by the literal
//     sanitized cache key ("example.com"); certPath hashes the domain to
//     hex(SHA-256(domain)). In one shared directory the two namespaces are
//     disjoint — names never collide, each cache misses on the other's files
//     (autocert ErrCacheMiss vs this cache's os.ErrNotExist) — so entries are
//     never shared or migrated in place. Only a caller that derives the hash
//     itself could address our files through autocert; no autocert.Manager
//     lookup ever does.
//
//   - NOT interface-compatible: autocert.Cache carries a context on every
//     method; this cache does not, so it cannot be assigned to
//     autocert.Manager.Cache.
//
// Remaining access-behavior differences: this cache is context-free (nothing
// to cancel); hash derivation confines every domain — including
// traversal-shaped strings — inside Dir with no sanitization, while autocert
// cleans literal names and honors context cancellation. This cache fsyncs
// before rename; autocert does not. Absent keys: autocert.Get returns
// ErrCacheMiss and its Delete returns nil; this Get and Delete both surface
// os.ErrNotExist. (The ACME account key lives in the same dir under the
// literal name account.key, written directly by dns01.go — outside this
// cache's hash namespace.)
type DirCache struct {
	Dir string
}

// Put stores the blob under the domain atomically: a reader either sees the
// previous blob or the complete new one, never partial content.
func (c *DirCache) Put(domain string, data []byte) error {
	return writeFileAtomic(c.certPath(domain), data, 0600)
}

func (c *DirCache) Get(domain string) ([]byte, error) {
	data, err := os.ReadFile(c.certPath(domain)) //nolint:gosec // G304: path derived from configured cache dir + hashed domain, not request input
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *DirCache) Delete(domain string) error {
	return os.Remove(c.certPath(domain))
}

func (c *DirCache) certPath(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return filepath.Join(c.Dir, hex.EncodeToString(h[:]))
}

// ServeFromAutocertCache returns the certificate the autocert manager has
// cached for hello's SNI WITHOUT ever calling autocert.Manager.GetCertificate,
// which issues a new certificate on an allowed-domain cache miss — the
// serving-only contract (ACME-001/002) forbids any handshake-path issuance.
// It returns nil on any miss, foreign hostname or expiry so the caller's
// fallback chain proceeds.
//
// hello may be a synthetic tls.ClientHelloInfo (e.g. the cert_monitor probe):
// such values carry a nil Context, and autocert.DirCache.Get dereferences
// ctx.Done() on it — a guaranteed nil-pointer panic at startup. A background
// context is substituted for synthetic hellos; real handshakes keep theirs.
func ServeFromAutocertCache(mgr *autocert.Manager, hello *tls.ClientHelloInfo) *tls.Certificate {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hello.ServerName)), ".")
	if name == "" || mgr == nil || mgr.Cache == nil {
		return nil
	}
	probeCtx := hello.Context()
	if probeCtx == nil {
		probeCtx = context.Background()
	}
	if mgr.HostPolicy != nil {
		if err := mgr.HostPolicy(probeCtx, name); err != nil {
			return nil // outside the configured host whitelist
		}
	}
	for _, cacheKey := range []string{name, name + "-rsa"} {
		data, err := mgr.Cache.Get(probeCtx, cacheKey)
		if err != nil {
			continue
		}
		cert, err := tls.X509KeyPair(data, data)
		if err != nil {
			continue
		}
		leaf := cert.Leaf
		if leaf == nil && len(cert.Certificate) > 0 {
			if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
				continue
			}
			cert.Leaf = leaf
		}
		if leaf == nil || leaf.VerifyHostname(name) != nil || !time.Now().Before(leaf.NotAfter) {
			continue
		}
		return &cert
	}
	return nil
}
