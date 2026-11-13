package office

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProofVerifierAcceptsCurrentKeyAndRejectsTampering(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // parse floor (minProofModulusBytes) is 2048-bit
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	stamp := windowsEpochTicks + uint64(now.UnixNano()/100)
	token := "opaque-token"
	requestTarget := "https://setjoin.example/api/office/wopi/files/42?access_token=opaque-token"
	payload, err := proofPayload(token, requestTarget, stamp)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/api/office/wopi/files/42?access_token=opaque-token", nil)
	req.Header.Set("X-WOPI-TimeStamp", strconv.FormatUint(stamp, 10))
	req.Header.Set("X-WOPI-Proof", base64.StdEncoding.EncodeToString(sig))
	v := newProofVerifier(nil)
	v.now = func() time.Time { return now }
	v.cache["https://collabora.example/hosting/discovery"] = proofKeys{current: &key.PublicKey, at: now}

	if err := v.verify(t.Context(), req, token, "https://collabora.example/hosting/discovery", "https://setjoin.example"); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	req.URL.RawQuery = "access_token=tampered"
	if err := v.verify(t.Context(), req, token, "https://collabora.example/hosting/discovery", "https://setjoin.example"); err == nil {
		t.Fatal("tampered request URL was accepted")
	}
}

func TestProofVerifierRejectsTimestampOutsideInt64NanosecondRange(t *testing.T) {
	stamp := windowsEpochTicks + uint64(math.MaxInt64/100) + 1
	req := httptest.NewRequest("GET", "/api/office/wopi/files/42", nil)
	req.Header.Set("X-WOPI-TimeStamp", strconv.FormatUint(stamp, 10))

	v := newProofVerifier(nil)
	if err := v.verify(t.Context(), req, "opaque-token", "https://collabora.example/hosting/discovery", "https://setjoin.example"); err == nil {
		t.Fatal("out-of-range WOPI proof timestamp was accepted")
	}
}

func TestProofVerifierRejectsInvalidEpochSkewAndDiscovery(t *testing.T) {
	now := time.Date(2026, 8, 24, 0, 0, 0, 0, time.UTC)
	v := newProofVerifier(nil)
	v.now = func() time.Time { return now }
	for _, tc := range []struct {
		name  string
		stamp string
	}{
		{"missing", ""},
		{"malformed", "not-a-number"},
		{"before windows epoch", strconv.FormatUint(windowsEpochTicks-1, 10)},
		{"outside skew", strconv.FormatUint(windowsEpochTicks+uint64(now.Add(-proofClockSkew-time.Second).UnixNano()/100), 10)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/office/wopi/files/42", nil)
			if tc.stamp != "" {
				req.Header.Set("X-WOPI-TimeStamp", tc.stamp)
			}
			if err := v.verify(t.Context(), req, "token", "https://collabora.example/hosting/discovery", "https://setjoin.example"); err == nil {
				t.Fatal("invalid proof timestamp accepted")
			}
		})
	}
	if _, err := v.keys(t.Context(), "http://collabora.example/hosting/discovery"); err == nil {
		t.Fatal("insecure discovery URL accepted")
	}

	network := newProofVerifier(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, io.ErrUnexpectedEOF
	})})
	if _, err := network.keys(t.Context(), "https://collabora.example/hosting/discovery"); err == nil {
		t.Fatal("discovery transport failure accepted")
	}
}

func TestDiscoveryURLAndRedirectOriginValidation(t *testing.T) {
	for _, raw := range []string{
		"http://collabora.example/hosting/discovery",
		"https://" + "user:password@" + "collabora.example/hosting/discovery",
		"https://collabora.example/hosting/discovery#fragment",
	} {
		if _, err := validDiscoveryURL(raw); err == nil {
			t.Fatalf("unsafe discovery URL accepted: %s", raw)
		}
	}
	first, _ := validDiscoveryURL("https://collabora.example/hosting/discovery")
	same, _ := validDiscoveryURL("https://collabora.example/next")
	other, _ := validDiscoveryURL("https://other.example/hosting/discovery")
	if !sameHTTPSOrigin(first, same) {
		t.Fatal("same-origin HTTPS discovery redirect was rejected")
	}
	if sameHTTPSOrigin(first, other) {
		t.Fatal("cross-origin discovery redirect was accepted")
	}
}

func TestProofKeyParsingDiscoveryFetchCacheAndFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // parse floor (minProofModulusBytes) is 2048-bit
	if err != nil {
		t.Fatal(err)
	}
	modulus := base64.StdEncoding.EncodeToString(key.PublicKey.N.Bytes())
	exponent := base64.StdEncoding.EncodeToString([]byte{1, 0, 1})
	xmlBody := `<wopi-discovery><proof-key modulus="` + modulus + `" exponent="` + exponent +
		`" oldmodulus="` + modulus + `" oldexponent="` + exponent + `"/></wopi-discovery>`
	url := "https://collabora.example/hosting/discovery"
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(xmlBody)), Request: req}, nil
	})}
	v := newProofVerifier(client)
	now := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)
	v.now = func() time.Time { return now }
	keys, err := v.keys(context.Background(), url)
	if err != nil || keys.current == nil || keys.old == nil {
		t.Fatalf("keys=%v err=%v", keys, err)
	}
	if _, err := v.keys(context.Background(), url); err != nil || calls != 1 {
		t.Fatalf("cache calls=%d err=%v", calls, err)
	}

	for _, tc := range []struct {
		name string
		body string
		code int
		move bool
	}{
		{"status", xmlBody, http.StatusBadGateway, false},
		{"malformed xml", `<broken`, http.StatusOK, false},
		{"invalid current key", `<wopi-discovery><proof-key modulus="!" exponent="AQAB"/></wopi-discovery>`, http.StatusOK, false},
		{"invalid old key", `<wopi-discovery><proof-key modulus="` + modulus + `" exponent="` + exponent + `" oldmodulus="!" oldexponent="AQAB"/></wopi-discovery>`, http.StatusOK, false},
		{"moved response", xmlBody, http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				responseReq := req
				if tc.move {
					responseReq = req.Clone(req.Context())
					responseReq.URL, _ = validDiscoveryURL("https://other.example/discovery")
				}
				return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body)), Request: responseReq}, nil
			})}
			if _, err := newProofVerifier(c).keys(t.Context(), url); err == nil {
				t.Fatal("invalid discovery accepted")
			}
		})
	}

	for _, pair := range [][2]string{{"!", "AQAB"}, {modulus, "!"}, {modulus, ""}, {modulus, "AAAAAA=="}, {modulus, "AQ=="}} {
		if _, err := parsePublicKey(pair[0], pair[1]); err == nil {
			t.Fatalf("invalid key accepted: %#v", pair)
		}
	}
}

func TestDefaultProofClientRedirectPolicy(t *testing.T) {
	v := newProofVerifier(nil)
	first := httptest.NewRequest(http.MethodGet, "https://collabora.example/discovery", nil)
	same := httptest.NewRequest(http.MethodGet, "https://collabora.example/next", nil)
	other := httptest.NewRequest(http.MethodGet, "https://other.example/next", nil)
	if err := v.client.CheckRedirect(same, []*http.Request{first}); err != nil {
		t.Fatal(err)
	}
	if err := v.client.CheckRedirect(other, []*http.Request{first}); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}
	if err := v.client.CheckRedirect(same, nil); err == nil {
		t.Fatal("redirect without origin accepted")
	}
}
