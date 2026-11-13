package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExtract(t *testing.T) {
	orig := trustedProxyIP
	t.Cleanup(func() { trustedProxyIP = orig })

	tests := []struct {
		name   string
		proxy  string // TRUSTED_PROXY_IP value ("" = unset)
		remote string
		xff    string
		want   string
	}{
		{"no trusted proxy, XFF ignored", "", "203.0.113.9:1234", "10.0.0.1", "203.0.113.9"},
		{"trusted proxy matches, rightmost (proxy-appended) hop wins", "10.0.0.1", "10.0.0.1:5555", "203.0.113.7, 10.0.0.2", "10.0.0.2"},
		{"spoofed leading XFF entry is not trusted", "10.0.0.1", "10.0.0.1:5555", "6.6.6.6, 198.51.100.4", "198.51.100.4"},
		{"trusted proxy matches, single-hop XFF used", "10.0.0.1", "10.0.0.1:5555", "203.0.113.7", "203.0.113.7"},
		{"trusted proxy matches, malformed rightmost XFF falls back", "10.0.0.1", "10.0.0.1:5555", "203.0.113.7, not-an-ip", "10.0.0.1"},
		{"peer does not match proxy, spoofed XFF rejected", "10.0.0.1", "198.51.100.4:9", "203.0.113.7", "198.51.100.4"},
		{"remote addr without port", "", "192.0.2.5", "", "192.0.2.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetTrustedProxy(tt.proxy)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if got := Extract(req); got != tt.want {
				t.Errorf("Extract() = %q, want %q", got, tt.want)
			}
		})
	}
}
