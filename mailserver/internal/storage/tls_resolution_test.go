package storage

import "testing"

// TestResolveEndpointTLS covers the shared transport-TLS contract
// (D-MAILSERVER-INTERNAL-STORAGE-F-001): https forces TLS, plaintext is
// loopback-only, scheme-less non-loopback endpoints are rejected fail-closed,
// and scheme/Secure contradictions are rejected.
func TestResolveEndpointTLS(t *testing.T) {
	tru := true
	fals := false

	cases := []struct {
		name     string
		endpoint string
		secure   *bool
		wantHost string
		wantTLS  bool
		wantErr  bool
	}{
		// ── explicit loopback HTTP: the supported compatibility case ──
		{name: "loopback http scheme derives plaintext", endpoint: "http://127.0.0.1:9000", secure: nil, wantHost: "127.0.0.1:9000", wantTLS: false},
		{name: "loopback http scheme with explicit false", endpoint: "http://127.0.0.1:9000", secure: &fals, wantHost: "127.0.0.1:9000", wantTLS: false},
		{name: "loopback scheme-less derives plaintext", endpoint: "127.0.0.1:9000", secure: nil, wantHost: "127.0.0.1:9000", wantTLS: false},
		{name: "loopback scheme-less explicit false (deploy convention)", endpoint: "127.0.0.1:9000", secure: &fals, wantHost: "127.0.0.1:9000", wantTLS: false},
		{name: "localhost name scheme-less", endpoint: "localhost:9000", secure: nil, wantHost: "localhost:9000", wantTLS: false},
		{name: "ipv6 loopback", endpoint: "[::1]:9000", secure: nil, wantHost: "[::1]:9000", wantTLS: false},
		{name: "bare ipv6 loopback", endpoint: "::1", secure: nil, wantHost: "::1", wantTLS: false},
		{name: "whole 127/8 range is loopback", endpoint: "127.0.0.99:9000", secure: nil, wantHost: "127.0.0.99:9000", wantTLS: false},
		{name: "loopback may opt into TLS", endpoint: "127.0.0.1:9000", secure: &tru, wantHost: "127.0.0.1:9000", wantTLS: true},

		// ── https scheme: TLS, explicit-plaintext is a conflict ──
		{name: "https scheme derives TLS", endpoint: "https://minio.internal:9000", secure: nil, wantHost: "minio.internal:9000", wantTLS: true},
		{name: "https scheme with explicit true", endpoint: "https://minio.internal:9000", secure: &tru, wantHost: "minio.internal:9000", wantTLS: true},
		{name: "https scheme + Secure=false conflict rejected", endpoint: "https://minio.internal:9000", secure: &fals, wantErr: true},
		{name: "https scheme + Secure=false conflict rejected on loopback too", endpoint: "https://127.0.0.1:9000", secure: &fals, wantErr: true},
		{name: "https scheme case-insensitive", endpoint: "HTTPS://minio.internal:9000", secure: nil, wantHost: "minio.internal:9000", wantTLS: true},

		// ── http scheme to remote: the finding, rejected ──
		{name: "http remote rejected", endpoint: "http://10.1.2.3:9000", secure: nil, wantErr: true},
		{name: "http remote rejected with explicit false", endpoint: "http://10.1.2.3:9000", secure: &fals, wantErr: true},
		{name: "http scheme + Secure=true conflict rejected", endpoint: "http://127.0.0.1:9000", secure: &tru, wantErr: true},

		// ── scheme-less remote: the insecure default, rejected fail-closed ──
		{name: "scheme-less remote rejected", endpoint: "minio.internal:9000", secure: nil, wantErr: true},
		{name: "scheme-less remote rejected with explicit false", endpoint: "minio.internal:9000", secure: &fals, wantErr: true},
		{name: "scheme-less remote allowed with explicit true", endpoint: "minio.internal:9000", secure: &tru, wantHost: "minio.internal:9000", wantTLS: true},
		{name: "lookalike hostname is not loopback", endpoint: "localhost.evil.example:9000", secure: nil, wantErr: true},
		{name: "localhost.localdomain is not provably loopback", endpoint: "localhost.localdomain:9000", secure: nil, wantErr: true},

		// ── empty endpoint: caller decides (AWS-default backup path) ──
		{name: "empty endpoint reports TLS default", endpoint: "", secure: nil, wantHost: "", wantTLS: true},

		// ── scheme but no host: malformed, rejected ──
		{name: "https scheme without host rejected", endpoint: "https://", secure: nil, wantErr: true},
		{name: "http scheme without host rejected", endpoint: "http://", secure: nil, wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, useTLS, err := ResolveEndpointTLS(tc.endpoint, tc.secure)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ResolveEndpointTLS(%q) = (%q, %v), want error", tc.endpoint, host, useTLS)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEndpointTLS(%q): %v", tc.endpoint, err)
			}
			if host != tc.wantHost || useTLS != tc.wantTLS {
				t.Fatalf("ResolveEndpointTLS(%q) = (%q, %v), want (%q, %v)", tc.endpoint, host, useTLS, tc.wantHost, tc.wantTLS)
			}
		})
	}
}

func TestTLSScheme(t *testing.T) {
	if got := TLSScheme(true); got != "https" {
		t.Errorf("TLSScheme(true) = %q, want https", got)
	}
	if got := TLSScheme(false); got != "http" {
		t.Errorf("TLSScheme(false) = %q, want http", got)
	}
}
