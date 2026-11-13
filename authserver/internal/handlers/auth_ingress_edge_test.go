package handlers

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

// TestParseTrustedProxyCIDRs pins the defense-in-depth contract of the
// trusted-proxy allowlist parser: whitespace is trimmed, blank entries are
// skipped, and ANY malformed entry fails the WHOLE allowlist closed (nil),
// never a partially-trusted set.
func TestParseTrustedProxyCIDRs(t *testing.T) {
	cases := []struct {
		name    string
		in      []string
		wantNil bool
		wantLen int
	}{
		{name: "nil allowlist", in: nil, wantNil: true, wantLen: 0},
		{name: "single valid", in: []string{"10.8.0.0/16"}, wantLen: 1},
		{name: "valid with whitespace", in: []string{"  10.8.0.0/16  "}, wantLen: 1},
		{name: "blank entries skipped", in: []string{"", "   ", "10.8.0.0/16", ""}, wantLen: 1},
		{name: "only blanks", in: []string{"", "   "}, wantLen: 0},
		{name: "malformed drops all", in: []string{"10.8.0.0/16", "not-a-cidr"}, wantNil: true},
		{name: "bare IP is malformed", in: []string{"10.8.0.1"}, wantNil: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTrustedProxyCIDRs(tc.in)
			if tc.wantNil && got != nil {
				t.Fatalf("parseTrustedProxyCIDRs(%q) = %v, want nil", tc.in, got)
			}
			if !tc.wantNil && len(got) != tc.wantLen {
				t.Fatalf("parseTrustedProxyCIDRs(%q) len = %d, want %d", tc.in, len(got), tc.wantLen)
			}
			if !tc.wantNil && tc.wantLen == 1 && got[0].String() != "10.8.0.0/16" {
				t.Fatalf("parsed network = %v, want 10.8.0.0/16", got[0])
			}
		})
	}
}

// failingBody is an io.Reader whose Read always errors — it simulates a
// transport-level body failure between the cookie checks and the buffered
// read in WebAuthnLoginFinish.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errBodyFailed }

type errBodyFailedError struct{}

func (errBodyFailedError) Error() string { return "body read failed" }

var errBodyFailed = errBodyFailedError{}

// TestWebAuthnLoginFinish_BodyReadErrorIsBadRequest pins the bounded-ingress
// guard: when the assertion body cannot be read, the endpoint answers 400
// (problem "invalid request body") instead of panicking or forwarding a
// truncated body to the WebAuthn library.
func TestWebAuthnLoginFinish_BodyReadErrorIsBadRequest(t *testing.T) {
	pool := openHandlerPool(t)
	cookieKey := []byte("0123456789abcdef0123456789abcdef")
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), CookieKey: cookieKey, Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{}),
	})
	h.deps.passkey = &successfulPasskeyProvider{}

	sessionCookie, err := h.encryptCookieValue([]byte(`{"challenge":"session"}`))
	if err != nil {
		t.Fatal(err)
	}
	uidCookie, err := h.encryptCookieValue([]byte(strconv.FormatInt(424242, 10)))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/webauthn/login/finish", bytes.NewReader(nil))
	req.Body = readCloser{Reader: failingBody{}}
	req.AddCookie(&http.Cookie{Name: "wa_login_sess", Value: sessionCookie})
	req.AddCookie(&http.Cookie{Name: "wa_login_uid", Value: uidCookie})
	response := httptest.NewRecorder()
	h.WebAuthnLoginFinish(response, req)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", response.Code, response.Body.String())
	}
	if !bytes.Contains(response.Body.Bytes(), []byte("invalid request body")) {
		t.Fatalf("body = %s, want problem detail %q", response.Body.String(), "invalid request body")
	}
}

type readCloser struct {
	io.Reader
}

func (readCloser) Close() error { return nil }
