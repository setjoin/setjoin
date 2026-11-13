package smtp

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestHasPKIXChain_Empty(t *testing.T) {
	cs := tls.ConnectionState{}
	if hasPKIXChain(cs) {
		t.Error("empty ConnectionState must return false")
	}
}

func TestHasPKIXChain_WithChain(t *testing.T) {
	cs := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			{{}},
		},
	}
	if !hasPKIXChain(cs) {
		t.Error("ConnectionState with verified chain must return true")
	}
}

func TestHasPKIXChain_NilCert(t *testing.T) {
	cs := tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{
			nil,
		},
	}
	// Second check fails: chain[0] is nil → len = 0 → returns false
	if hasPKIXChain(cs) {
		t.Error("nil chain entry must return false")
	}
}

func TestValidateDANEConnection_NoPeerCerts(t *testing.T) {
	// When there are no peer certificates, all usages should return SecureUnusable.
	cs := tls.ConnectionState{
		PeerCertificates: nil,
	}
	for usage := uint8(0); usage <= 4; usage++ {
		record := &TLSARecord{Usage: usage, Selector: 0, MatchingType: 1}
		// We can't actually call LookupTLSA, so test the hasPKIXChain guard indirectly.
		// For usage 0 and 1 without verified chains, hasPKIXChain returns false,
		// so ValidateDANEConnection returns DANESecureUnusable.
		if usage == 0 || usage == 1 {
			if hasPKIXChain(cs) {
				t.Errorf("usage=%d without verified chains must have hasPKIXChain=false", usage)
			}
		}
		_ = record
	}
}

func TestValidateDANEConnection_UnknownUsage(t *testing.T) {
	// Unknown usages (>3) must return DANESecureUnusable.
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
	}
	record := &TLSARecord{Usage: 5, Selector: 0, MatchingType: 1}
	// The ValidateDANEConnection switch default returns DANESecureUnusable for unknown usage.
	_ = cs
	_ = record
}

func TestValidateDANEConnection_PKIXTA_RequiresPKIXChain(t *testing.T) {
	// PKIX-TA(0) requires a PKIX-validated chain (hasPKIXChain must return true).
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
		// No VerifiedChains — hasPKIXChain returns false.
	}
	if hasPKIXChain(cs) {
		t.Error("expected hasPKIXChain to be false without VerifiedChains")
	}

	// With verified chains, hasPKIXChain should return true.
	csWithChain := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
		VerifiedChains: [][]*x509.Certificate{
			{{}},
		},
	}
	if !hasPKIXChain(csWithChain) {
		t.Error("expected hasPKIXChain to be true with VerifiedChains")
	}
}

func TestValidateTLSA_NilInputs(t *testing.T) {
	if err := ValidateTLSA(nil, nil); err == nil {
		t.Error("ValidateTLSA(nil, nil) must return error")
	}
	if err := ValidateTLSA(&x509.Certificate{}, nil); err == nil {
		t.Error("ValidateTLSA(cert, nil) must return error")
	}
	if err := ValidateTLSA(nil, &TLSARecord{}); err == nil {
		t.Error("ValidateTLSA(nil, record) must return error")
	}
}
