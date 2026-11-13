package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
)

// ReadCertificateFile reads a PEM-encoded X.509 certificate from a file path.
func ReadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

// ComputeCertAssociation computes the TLSA certificate association data
// per RFC 6698 §2.1.
//
// selector: 0 = full certificate, 1 = SubjectPublicKeyInfo
// matchingType: 0 = exact match, 1 = SHA-256, 2 = SHA-512
func ComputeCertAssociation(cert *x509.Certificate, selector, matchingType uint8) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("nil certificate")
	}

	var data []byte
	switch selector {
	case 0:
		data = cert.Raw
	case 1:
		data = cert.RawSubjectPublicKeyInfo
	default:
		return nil, fmt.Errorf("invalid selector %d: must be 0 (full cert) or 1 (SPKI)", selector)
	}

	switch matchingType {
	case 0:
		out := make([]byte, len(data))
		copy(out, data)
		return out, nil
	case 1:
		h := sha256.Sum256(data)
		return h[:], nil
	case 2:
		h := sha512.Sum512(data)
		return h[:], nil
	default:
		return nil, fmt.Errorf("invalid matching type %d: must be 0 (exact), 1 (SHA-256), or 2 (SHA-512)", matchingType)
	}
}

// validateDNSHostname enforces the RFC 1035 preferred name syntax for the
// hostname embedded in a generated zone record: 1–63 character labels of
// [A-Za-z0-9-], no leading/trailing label hyphen, dot-separated, total length
// <= 253 octets, with an optional single trailing dot already stripped by the
// caller. Everything else is rejected — a hostname carrying zone-file
// metacharacters (spaces, quotes, parentheses, newlines) must never reach the
// TLSA format string, or a bad --hostname could inject additional records
// when the operator pastes the output into an authoritative zone (D-MAILCTL-004).
func validateDNSHostname(hostname string) error {
	if hostname == "" {
		return fmt.Errorf("hostname is empty")
	}
	if len(hostname) > 253 {
		return fmt.Errorf("hostname exceeds 253 octets (%d)", len(hostname))
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 {
			return fmt.Errorf("hostname %q has an empty label", hostname)
		}
		if len(label) > 63 {
			return fmt.Errorf("hostname label %q exceeds 63 octets", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("hostname label %q must not start or end with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("hostname label %q contains character %q outside the DNS name grammar (letters, digits, hyphen)", label, rune(c))
			}
		}
	}
	return nil
}

// GenerateTLSAFromCert reads a PEM certificate, computes the TLSA cert association,
// and returns a zone-file formatted TLSA record string.
//
// usage: 0=PKIX-TA, 1=PKIX-EE, 2=DANE-TA, 3=DANE-EE
// selector: 0=full cert, 1=SubjectPublicKeyInfo
// matchingType: 0=exact, 1=SHA-256, 2=SHA-512
func GenerateTLSAFromCert(certPath, hostname string, usage, selector, matchingType uint8) (string, error) {
	// Validate usage
	if usage > 3 {
		return "", fmt.Errorf("invalid usage %d: must be 0-3 (PKIX-TA, PKIX-EE, DANE-TA, DANE-EE)", usage)
	}

	// Validate selector
	if selector > 1 {
		return "", fmt.Errorf("invalid selector %d: must be 0 (full cert) or 1 (SPKI)", selector)
	}

	// Validate matching type
	if matchingType > 2 {
		return "", fmt.Errorf("invalid matching type %d: must be 0 (exact), 1 (SHA-256), or 2 (SHA-512)", matchingType)
	}

	cert, err := ReadCertificateFile(certPath)
	if err != nil {
		return "", err
	}

	assoc, err := ComputeCertAssociation(cert, selector, matchingType)
	if err != nil {
		return "", err
	}

	hexHash := hex.EncodeToString(assoc)

	// Normalize hostname: strip trailing dot, validate the RFC 1035 grammar,
	// then add the dot back once. Validation happens on the stripped name so a
	// trailing dot is legal but nothing else outside the grammar is.
	hostname = strings.TrimSuffix(hostname, ".")
	if err := validateDNSHostname(hostname); err != nil {
		return "", err
	}
	fqdn := hostname + "."

	return fmt.Sprintf("_25._tcp.%s IN TLSA %d %d %d %s", fqdn, usage, selector, matchingType, hexHash), nil
}

// runDane handles the 'dane' subcommand (modeLocal — no server, no database;
// the ctx is unused). It parses its own flags from the raw args.
func runDane(c *cmdCtx, action string, args []string) error {
	switch action {
	case "generate":
		fs := flag.NewFlagSet("dane generate", flag.ExitOnError)
		certFile := fs.String("cert", "", "Path to PEM-encoded certificate file")
		hostname := fs.String("hostname", "", "Mail server hostname (e.g., mail.example.com)")
		usage := fs.Int("usage", 3, "TLSA usage: 2=DANE-TA, 3=DANE-EE (default 3)")
		selector := fs.Int("selector", 1, "TLSA selector: 0=full cert, 1=SPKI (default 1)")
		matching := fs.Int("matching", 1, "TLSA matching type: 0=exact, 1=SHA-256 (default), 2=SHA-512")
		fs.Parse(args)

		if *certFile == "" {
			return fmt.Errorf("--cert is required (path to PEM certificate file)")
		}
		if *hostname == "" {
			return fmt.Errorf("--hostname is required (e.g., mail.example.com)")
		}

		record, err := GenerateTLSAFromCert(*certFile, *hostname, uint8(*usage), uint8(*selector), uint8(*matching))
		if err != nil {
			return err
		}
		fmt.Println(record)
		return nil

	default:
		return fmt.Errorf("unknown dane action: %s. Try: generate", action)
	}
}
