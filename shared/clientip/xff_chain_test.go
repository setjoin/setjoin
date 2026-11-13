package clientip

// Unit corpus for the rightmost-trusted-hop XFF chain semantics
// (med-shard3-008): multi-line/comma-folded chains with a trusted immediate
// peer, untrusted-peer spoof discards for both XFF and X-Forwarded-Proto,
// malformed-rightmost fail-closed, and IPv6 zone/bracket handling.

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newXFFRequest builds a request with the given socket peer and raw
// X-Forwarded-For header lines (a slice entry == one header line).
func newXFFRequest(remote string, xffLines []string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	if len(xffLines) > 0 {
		req.Header["X-Forwarded-For"] = xffLines
	}
	return req
}

// TestXFFMultiLineTrustedPeer: with a trusted immediate peer the FULL
// multi-line/comma-folded chain is parsed and the rightmost (proxy-appended)
// value wins — the attacker-chosen first line never wins, not even when the
// chain spans multiple X-Forwarded-For header lines (which Header.Get alone
// would reduce to the first, attacker-controlled line).
func TestXFFMultiLineTrustedPeer(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })
	SetTrustedProxy("10.0.0.1")

	tests := []struct {
		name     string
		xffLines []string
		want     string
	}{
		{
			name:     "attacker first line, proxy-appended second line",
			xffLines: []string{"6.6.6.6", "203.0.113.9"},
			want:     "203.0.113.9",
		},
		{
			name:     "attacker line followed by comma-folded proxy line",
			xffLines: []string{"6.6.6.6", "6.6.6.6, 10.0.0.2"},
			want:     "10.0.0.2",
		},
		{
			name:     "comma-folded single line, attacker leftmost loses",
			xffLines: []string{"6.6.6.6, 198.51.100.4"},
			want:     "198.51.100.4",
		},
		{
			name:     "three lines with interior folding, rightmost of joined chain wins",
			xffLines: []string{"6.6.6.6, 10.0.0.2", "203.0.113.9", "198.51.100.77"},
			want:     "198.51.100.77",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newXFFRequest("10.0.0.1:5555", tt.xffLines)
			if got := Extract(req); got != tt.want {
				t.Errorf("Extract() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestXFFUntrustedPeerSpoofDiscarded: forwarded headers arriving from an
// untrusted peer are discarded as spoofed — the client IP comes from the
// socket, whatever the chain claims.
func TestXFFUntrustedPeerSpoofDiscarded(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })
	SetTrustedProxy("10.0.0.1")

	tests := []struct {
		name     string
		proxy    string
		xffLines []string
	}{
		{"multi-line chain from untrusted peer discarded", "10.0.0.1", []string{"6.6.6.6", "203.0.113.9"}},
		{"empty trust config discards chain", "", []string{"6.6.6.6"}},
		{"non-matching peer discards chain", "192.0.2.1", []string{"203.0.113.9, 6.6.6.6"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxy(tt.proxy)
			req := newXFFRequest("198.51.100.4:9", tt.xffLines)
			if got := Extract(req); got != "198.51.100.4" {
				t.Errorf("Extract() = %q, want socket peer %q", got, "198.51.100.4")
			}
		})
	}
}

// TestXFFMalformedRightmostFailsClosed: a malformed rightmost value fails
// closed to the socket peer (the trusted proxy's address) — earlier, more
// attacker-controlled chain entries are never scanned as a fallback.
func TestXFFMalformedRightmostFailsClosed(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })
	SetTrustedProxy("10.0.0.1")

	tests := []struct {
		name     string
		xffLines []string
	}{
		{"malformed rightmost of folded line", []string{"203.0.113.7, not-an-ip"}},
		{"malformed second line", []string{"203.0.113.7", "garbage"}},
		{"bracketed garbage", []string{"203.0.113.7, [not-an-ip]"}},
		{"empty rightmost entry", []string{"203.0.113.7,"}},
		{"whitespace-only rightmost entry", []string{"203.0.113.7,   "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newXFFRequest("10.0.0.1:5555", tt.xffLines)
			if got := Extract(req); got != "10.0.0.1" {
				t.Errorf("Extract() = %q, want fail-closed socket peer %q", got, "10.0.0.1")
			}
		})
	}
}

// TestXFFIPv6ZonesAndNormalization: IPv6 entries are accepted bare or
// bracketed, zone suffixes are stripped, and the validated address is
// returned normalized.
func TestXFFIPv6ZonesAndNormalization(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })
	SetTrustedProxy("10.0.0.1")

	tests := []struct {
		name string
		xff  string
		want string
	}{
		{"bare IPv6", "2001:db8::1", "2001:db8::1"},
		{"bracketed IPv6", "[2001:db8::1]", "2001:db8::1"},
		{"zone suffix stripped", "fe80::1%eth0", "fe80::1"},
		{"bracketed escaped zone stripped", "[fe80::1%25eth0]", "fe80::1"},
		{"normalized hex", "2001:0DB8::0001", "2001:db8::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := newXFFRequest("10.0.0.1:5555", []string{tt.xff})
			if got := Extract(req); got != tt.want {
				t.Errorf("Extract() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestForwardedProtoImmediatePeerTrust: X-Forwarded-Proto is accepted only
// from the trusted immediate peer; from an untrusted peer it is discarded as
// spoofed and the protocol comes from the socket. Direct TLS is always
// authoritative; a malformed value fails closed to cleartext.
func TestForwardedProtoImmediatePeerTrust(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })
	SetTrustedProxy("10.0.0.1")

	tests := []struct {
		name     string
		proxy    string
		remote   string
		tls      bool
		xfpLines []string
		want     string
	}{
		{"trusted peer https", "10.0.0.1", "10.0.0.1:5555", false, []string{"https"}, "https"},
		{"trusted peer case-insensitive https", "10.0.0.1", "10.0.0.1:5555", false, []string{"HTTPS"}, "https"},
		{"trusted peer http", "10.0.0.1", "10.0.0.1:5555", false, []string{"http"}, "http"},
		{"trusted peer multi-line, last line wins", "10.0.0.1", "10.0.0.1:5555", false, []string{"http", "https"}, "https"},
		{"trusted peer multi-line last says http", "10.0.0.1", "10.0.0.1:5555", false, []string{"https", "http"}, "http"},
		{"trusted peer malformed fails closed to http", "10.0.0.1", "10.0.0.1:5555", false, []string{"ftp"}, "http"},
		{"trusted peer absent header defaults http", "10.0.0.1", "10.0.0.1:5555", false, nil, "http"},
		{"untrusted peer https spoof discarded", "10.0.0.1", "198.51.100.4:9", false, []string{"https"}, "http"},
		{"untrusted peer, no trust config, spoof discarded", "", "198.51.100.4:9", false, []string{"https"}, "http"},
		{"direct TLS is authoritative over trusted header", "10.0.0.1", "10.0.0.1:5555", true, []string{"http"}, "https"},
		{"direct TLS without header", "", "198.51.100.4:9", true, nil, "https"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxy(tt.proxy)
			req := newXFFRequest(tt.remote, nil)
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			for _, line := range tt.xfpLines {
				req.Header.Add("X-Forwarded-Proto", line)
			}
			if got := ForwardedProto(req); got != tt.want {
				t.Errorf("ForwardedProto() = %q, want %q", got, tt.want)
			}
		})
	}
}
