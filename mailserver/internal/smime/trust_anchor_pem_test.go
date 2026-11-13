package smime

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// TestTrustAnchorPEMFailClosedArms exercises every fail-closed arm of
// trustAnchorPEM (verify_detached.go): the helper that extracts the VALIDATED
// chain's trust anchor for a StatusValid verdict. Any structural gap in the
// chain input — no signers, no chains for the first signer, an empty chain, or
// a nil anchor certificate — must yield "" so callers treat it as "no
// validated anchor" and never derive authority from it.
func TestTrustAnchorPEMFailClosedArms(t *testing.T) {
	t.Run("nil chains", func(t *testing.T) {
		if got := trustAnchorPEM(nil); got != "" {
			t.Errorf("trustAnchorPEM(nil) = %q, want empty", got)
		}
	})
	t.Run("zero signers", func(t *testing.T) {
		if got := trustAnchorPEM([][][]*x509.Certificate{}); got != "" {
			t.Errorf("trustAnchorPEM(empty) = %q, want empty", got)
		}
	})
	t.Run("first signer has no chains", func(t *testing.T) {
		chains := [][][]*x509.Certificate{nil}
		if got := trustAnchorPEM(chains); got != "" {
			t.Errorf("trustAnchorPEM(signer without chains) = %q, want empty", got)
		}
	})
	t.Run("empty chain", func(t *testing.T) {
		chains := [][][]*x509.Certificate{{{}}}
		if got := trustAnchorPEM(chains); got != "" {
			t.Errorf("trustAnchorPEM(empty chain) = %q, want empty", got)
		}
	})
	t.Run("nil anchor certificate", func(t *testing.T) {
		chains := [][][]*x509.Certificate{{{nil}}}
		if got := trustAnchorPEM(chains); got != "" {
			t.Errorf("trustAnchorPEM(nil anchor) = %q, want empty", got)
		}
	})
	t.Run("valid chain yields anchor PEM", func(t *testing.T) {
		root, _, _ := testCA(t, nil, time.Now().Add(time.Hour))
		chains := [][][]*x509.Certificate{{{root}}}
		got := trustAnchorPEM(chains)
		block, _ := pem.Decode([]byte(got))
		if block == nil {
			t.Fatalf("trustAnchorPEM(valid chain) did not return a PEM block: %q", got)
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("trustAnchorPEM PEM does not parse: %v", err)
		}
		if !parsed.Equal(root) {
			t.Error("trustAnchorPEM must return the chain's last certificate (the anchor)")
		}
	})
}
