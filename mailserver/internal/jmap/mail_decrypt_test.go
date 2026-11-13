package jmap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/middleware"
)

// --- Task 5.3: parseDecryptCandidate (pure, DB-free) ---

func genRSACertKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "reader@example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return certPEM, keyPEM
}

func genECCertKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ec@example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &eckey.PublicKey, eckey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(eckey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func TestParseDecryptCandidate(t *testing.T) {
	goodCert, goodKey := genRSACertKeyPEM(t)
	ecCert, ecKey := genECCertKeyPEM(t)

	t.Run("good_rsa_pair_ok", func(t *testing.T) {
		dk, ok := parseDecryptCandidate(goodCert, goodKey)
		if !ok {
			t.Fatal("good RSA pair must be a candidate")
		}
		if dk.Cert == nil || dk.Key == nil {
			t.Fatal("candidate must carry parsed cert + key")
		}
	})
	t.Run("bad_cert_pem_skipped", func(t *testing.T) {
		if _, ok := parseDecryptCandidate("not a pem", goodKey); ok {
			t.Fatal("unparseable cert PEM must be skipped")
		}
	})
	t.Run("bad_key_pem_skipped", func(t *testing.T) {
		if _, ok := parseDecryptCandidate(goodCert, "not a key"); ok {
			t.Fatal("unparseable key PEM must be skipped")
		}
	})
	t.Run("non_rsa_key_skipped", func(t *testing.T) {
		if _, ok := parseDecryptCandidate(ecCert, ecKey); ok {
			t.Fatal("non-RSA (EC) key must be skipped")
		}
	})
	t.Run("empty_inputs_skipped", func(t *testing.T) {
		if _, ok := parseDecryptCandidate("", ""); ok {
			t.Fatal("empty inputs must be skipped")
		}
	})
}

func TestInjectCleartextBoundsPreviewAndNeverCreatesHTML(t *testing.T) {
	t.Parallel()
	plaintext := []byte(strings.Repeat("x", 300))
	email := map[string]json.RawMessage{"bodyHTML": json.RawMessage(`"existing"`)}

	injectCleartext(email, plaintext)

	if got := jsonString(email["bodyText"]); got != string(plaintext) {
		t.Fatalf("bodyText length = %d, want %d", len(got), len(plaintext))
	}
	if got := jsonString(email["preview"]); got != string(plaintext[:256]) {
		t.Fatalf("preview length = %d, want 256", len(got))
	}
	if got := jsonString(email["bodyHTML"]); got != "existing" {
		t.Fatalf("bodyHTML changed to %q; decrypted MIME must remain text-only", got)
	}

	short := map[string]json.RawMessage{}
	injectCleartext(short, []byte("short"))
	if got := jsonString(short["preview"]); got != "short" {
		t.Fatalf("short preview = %q, want short", got)
	}
}

// --- Task 5.4: decryptAllowed (per-user cost bound) ---

func TestDecryptAllowed_BudgetExhausts(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	h.decryptLimiter = middleware.NewRateLimiter(2, time.Minute)

	if !h.decryptAllowed(1) {
		t.Fatal("1st decrypt for user 1 must be allowed")
	}
	if !h.decryptAllowed(1) {
		t.Fatal("2nd decrypt for user 1 must be allowed")
	}
	if h.decryptAllowed(1) {
		t.Fatal("3rd decrypt for user 1 must be denied (budget=2)")
	}
	// A different user has an independent budget.
	if !h.decryptAllowed(2) {
		t.Fatal("user 2 must have an independent budget")
	}
}

func TestDecryptAllowed_NilLimiterAllows(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	h.decryptLimiter = nil
	if !h.decryptAllowed(1) {
		t.Fatal("nil limiter must allow (unit-test / unconfigured)")
	}
}

// --- Task 5.5: decryptEmailResult (JSON-shape, no DB) ---

func TestDecryptEmailResult_NonEncryptedPassThrough(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	in := json.RawMessage(`{"list":[{"id":"1","bodyText":"hello","cryptoType":null}]}`)
	out := h.decryptEmailResult(context.Background(), 7, 7, in)
	if string(out) != string(in) {
		t.Errorf("non-encrypted result must be byte-identical.\ngot:  %s\nwant: %s", out, in)
	}
}

func TestDecryptEmailResult_NoKeysYieldsNoKeyState(t *testing.T) {
	// nil pool ⇒ loadDecryptKeys returns no keys ⇒ no_key state, body stays null.
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	in := json.RawMessage(`{"list":[{"id":"1","cryptoType":"smime-encrypted","bodyText":null,"blobId":"abc"}]}`)
	out := h.decryptEmailResult(context.Background(), 7, 7, in)

	var resp struct {
		List []map[string]json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(resp.List) != 1 {
		t.Fatalf("want 1 email, got %d", len(resp.List))
	}
	var ds string
	_ = json.Unmarshal(resp.List[0]["decryptState"], &ds)
	if ds != "no_key" {
		t.Errorf("want decryptState=no_key, got %q", ds)
	}
	// bodyText must remain null (never injected on a non-decrypted state).
	if bt, ok := resp.List[0]["bodyText"]; ok && string(bt) != "null" {
		t.Errorf("bodyText must stay null on no_key, got %s", bt)
	}
}

func TestDecryptEmailResult_PreservesOtherEmails(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	in := json.RawMessage(`{"list":[` +
		`{"id":"1","bodyText":"plain one","cryptoType":null},` +
		`{"id":"2","cryptoType":"smime-encrypted","bodyText":null,"blobId":"abc"},` +
		`{"id":"3","bodyText":"plain three"}` +
		`]}`)
	out := h.decryptEmailResult(context.Background(), 7, 7, in)

	var resp struct {
		List []map[string]json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp.List) != 3 {
		t.Fatalf("want 3 emails preserved, got %d", len(resp.List))
	}
	// Non-encrypted entries keep their body and get no decryptState.
	var bt1 string
	_ = json.Unmarshal(resp.List[0]["bodyText"], &bt1)
	if bt1 != "plain one" {
		t.Errorf("email 1 body must be intact, got %q", bt1)
	}
	if _, ok := resp.List[0]["decryptState"]; ok {
		t.Errorf("non-encrypted email must not get a decryptState")
	}
	// The encrypted entry gets a state, no body.
	if _, ok := resp.List[1]["decryptState"]; !ok {
		t.Errorf("encrypted email must get a decryptState")
	}
	var bt3 string
	_ = json.Unmarshal(resp.List[2]["bodyText"], &bt3)
	if bt3 != "plain three" {
		t.Errorf("email 3 body must be intact, got %q", bt3)
	}
}

func TestDecryptEmailResult_CostBoundDenialIsErrorState(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	// Budget of 1, pre-consumed for user 7 so the decrypt pass is denied.
	h.decryptLimiter = middleware.NewRateLimiter(1, time.Minute)
	if !h.decryptAllowed(7) {
		t.Fatal("setup: first allow should pass")
	}
	in := json.RawMessage(`{"list":[{"id":"1","cryptoType":"smime-encrypted","bodyText":null,"blobId":"abc"}]}`)
	out := h.decryptEmailResult(context.Background(), 7, 7, in)

	var resp struct {
		List []map[string]json.RawMessage `json:"list"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	var ds string
	_ = json.Unmarshal(resp.List[0]["decryptState"], &ds)
	if ds != "error" {
		t.Errorf("cost-bound denial must yield decryptState=error, got %q", ds)
	}
}

func TestDecryptEmailResult_MalformedJSONReturnedUnchanged(t *testing.T) {
	h := newFakeHandler(&fakeCaller{returnRaw: json.RawMessage(`{}`)})
	in := json.RawMessage(`not json`)
	out := h.decryptEmailResult(context.Background(), 7, 7, in)
	if string(out) != string(in) {
		t.Errorf("malformed result must be returned unchanged")
	}
}
