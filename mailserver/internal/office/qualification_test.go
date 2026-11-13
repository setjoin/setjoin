package office

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func qualificationFixture(t *testing.T) (QualificationTarget, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048) // the parse floor (minProofModulusBytes) is 2048-bit
	if err != nil {
		t.Fatal(err)
	}
	modulus := base64.StdEncoding.EncodeToString(key.PublicKey.N.Bytes())
	exponent := base64.StdEncoding.EncodeToString([]byte{1, 0, 1})
	body := `<wopi-discovery><proof-key modulus="` + modulus + `" exponent="` + exponent + `"/></wopi-discovery>`
	return QualificationTarget{
		ProviderID: "fixture", Generation: 1, ConfigSHA256: strings.Repeat("a", 64),
		Profile: "existing-provider", ProofDiscoveryURL: "https://office.example/hosting/discovery",
		EditorURL: "https://office.example/browser/editor", WOPIPublicBaseURL: "https://setjoin.example/wopi",
	}, body
}

func TestProbeProviderSuccessAndResponseFailures(t *testing.T) {
	target, discoveryBody := qualificationFixture(t)
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := discoveryBody
		if req.Method == http.MethodHead {
			body = ""
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	result, err := probeProvider(t.Context(), target, client, time.Now())
	if err != nil || result.Checks["discovery"] != "pass" || len(result.DiscoveryFingerprint) != 64 {
		t.Fatalf("result=%+v err=%v", result, err)
	}

	for _, tc := range []struct {
		name string
		body string
		code int
		err  error
	}{
		{"transport", "", 0, errors.New("offline")},
		{"status", discoveryBody, http.StatusBadGateway, nil},
		{"xml", "<broken", http.StatusOK, nil},
		{"proof", `<wopi-discovery><proof-key modulus="!" exponent="AQAB"/></wopi-discovery>`, http.StatusOK, nil},
		{"oversize", strings.Repeat("x", qualificationResponseLimit+1), http.StatusOK, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.code, Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
			})}
			if _, err := probeProvider(context.Background(), target, c, time.Now()); err == nil {
				t.Fatal("invalid provider response accepted")
			}
		})
	}
}

func TestLiveProviderProberAndTargetDecodeRejectInvalidInputs(t *testing.T) {
	target, _ := qualificationFixture(t)
	for _, mutate := range []func(*QualificationTarget){
		func(v *QualificationTarget) { v.PrivateAllowCIDRs = []string{"bad"} },
		func(v *QualificationTarget) { v.ProofDiscoveryURL = "http://127.0.0.1/discovery" },
		func(v *QualificationTarget) { v.EditorURL = "https://other.example/editor" },
	} {
		candidate := target
		mutate(&candidate)
		if _, err := (LiveProviderProber{}).Probe(t.Context(), candidate); err == nil {
			t.Fatal("invalid qualification target accepted")
		}
	}
	if _, err := DecodeQualificationTarget([]byte(`{`)); err == nil {
		t.Fatal("malformed target accepted")
	}
	if _, err := DecodeQualificationTarget([]byte(`{"providerId":"x"}`)); err == nil {
		t.Fatal("incomplete target accepted")
	}
	raw := []byte(`{"providerId":"x","generation":1,"configSha256":"` + strings.Repeat("a", 64) + `"}`)
	if got, err := DecodeQualificationTarget(raw); err != nil || got.ProviderID != "x" {
		t.Fatalf("target=%+v err=%v", got, err)
	}
}
