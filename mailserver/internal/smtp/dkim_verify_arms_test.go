package smtp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestVerifyDKIMErrorArms is a table-driven sweep of the error/edge arms of
// VerifyDKIM (the DKIM verification helper): no signature, unparseable
// signature tags, DNS lookup failure, key records without a usable key
// payload, body-hash mismatch, algorithm/key-type mismatches (RFC 8463), an
// unsupported algorithm, and cryptographically failing signatures. Each case
// names the DKIMResult the verifier must return; the verifier's DNS lookup is
// stubbed per case, so no network is touched.
func TestVerifyDKIMErrorArms(t *testing.T) {
	const (
		domain   = "example.com"
		selector = "arms"
	)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa pubkey: %v", err)
	}
	rsaRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(rsaDER)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	edDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal ed25519 pubkey: %v", err)
	}
	edRecord := "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(edDER)

	// decoyKey signs the "rsa signature invalid" case: a real, well-formed
	// rsa-sha256 signature made by a key OTHER than the one DNS publishes.
	decoyKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate decoy rsa key: %v", err)
	}

	// signFixture builds a message whose DKIM-Signature header is correctly
	// formed for the given key/algorithm (bh= always matches the body, b= is a
	// real signature). Cases then break exactly one thing.
	signFixture := func(t *testing.T, alg string, signKey crypto.Signer) string {
		t.Helper()
		const body = "arms body\r\n"
		unsigned := "From: sender@" + domain + "\r\n\r\n" + body
		_, bodyBytes := splitHeadersBody([]byte(unsigned))
		bh := base64.StdEncoding.EncodeToString(dkimBodyHash(bodyBytes, "relaxed/relaxed", 0))

		head := "DKIM-Signature: v=1; a=" + alg + "; c=relaxed/relaxed; d=" + domain +
			"; s=" + selector + "; h=from; bh=" + bh + "; b="
		// Placeholder message with an EMPTY b= value: the signed data excludes
		// the b= value itself, so signing over this reconstruction stays valid
		// once the real base64 signature is appended after "b=".
		msg := head + "\r\n" + "From: sender@" + domain + "\r\n\r\n" + body

		// Signed data must be reconstructed exactly as the verifier does (the
		// b= value itself is excluded), so parse our own header back.
		sig := parseDKIMSignature(msg)
		if sig == nil {
			t.Fatal("test fixture: parseDKIMSignature returned nil for its own header")
		}
		digest := sha256.Sum256([]byte(dkimSignedData(msg, sig)))
		var b []byte
		switch k := signKey.(type) {
		case *rsa.PrivateKey:
			// RFC 8017 DigestInfo-prefixed signature (crypto.SHA256) — the
			// construction any external RFC 6376 signer/verifier uses.
			b, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
			if err != nil {
				t.Fatalf("rsa.SignPKCS1v15: %v", err)
			}
		case ed25519.PrivateKey:
			b = ed25519.Sign(k, []byte(dkimSignedData(msg, sig)))
		default:
			t.Fatalf("test fixture: unsupported signer %T", signKey)
		}
		return head + base64.StdEncoding.EncodeToString(b) + "\r\n" + "From: sender@" + domain + "\r\n\r\n" + body
	}

	garbageSig := func(n int) string {
		raw := make([]byte, n)
		if _, err := rand.Read(raw); err != nil {
			t.Fatalf("rand: %v", err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}

	tests := []struct {
		name    string
		msg     string
		txt     map[string][]string
		txtErr  error
		want    DKIMResult
		wantLen int64
	}{
		{
			// Line 58: no DKIM-Signature header at all.
			name: "no DKIM-Signature header",
			msg:  "From: sender@" + domain + "\r\n\r\nplain unsigned\r\n",
			want: DKIMNone,
		},
		{
			// Line 58: a DKIM-Signature header exists but the required d=/s=
			// tags are missing, so the parse is rejected as absent.
			name: "signature missing d= and s= tags",
			msg: "DKIM-Signature: v=1; a=rsa-sha256; h=from; bh=AAAA; b=AAAA\r\n" +
				"From: sender@" + domain + "\r\n\r\nbody\r\n",
			want: DKIMNone,
		},
		{
			// Line 68: TXT lookup of selector._domainkey.domain fails.
			name: "TXT lookup fails",
			msg:  signFixture(t, "rsa-sha256", rsaKey),
			// txt left empty → resolver NXDOMAINs everything.
			txtErr: fmt.Errorf("SERVFAIL"),
			want:   DKIMTempErr,
		},
		{
			// Line 79: TXT answers, but no record carries a key payload
			// (k=rsa / k=ed25519 / p=), so no public key can be selected.
			name: "key record without key payload",
			msg:  signFixture(t, "rsa-sha256", rsaKey),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {"v=DKIM1; t=s; s=email"},
			},
			want: DKIMPermErr,
		},
		{
			// Line 94: key resolves, but bh= does not match the canonicalized
			// body hash (RFC 6376 §3.4) — body was swapped.
			name: "body hash mismatch",
			msg: strings.Replace(
				signFixture(t, "rsa-sha256", rsaKey),
				"arms body", "tampered body", 1),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {rsaRecord},
			},
			want: DKIMFail,
		},
		{
			// Line 104: a=rsa-sha256 but the resolved key is Ed25519 — the
			// key type cannot satisfy the advertised algorithm.
			name: "rsa-sha256 with ed25519 key record",
			msg:  signFixture(t, "rsa-sha256", edPriv),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {edRecord},
			},
			want: DKIMPermErr,
		},
		{
			// Line 111: a=ed25519-sha256 but the resolved key is RSA.
			name: "ed25519-sha256 with rsa key record",
			msg:  signFixture(t, "ed25519-sha256", rsaKey),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {rsaRecord},
			},
			want: DKIMPermErr,
		},
		{
			// Line 117: algorithm is neither rsa-sha256 nor ed25519-sha256
			// (and not the explicitly rejected rsa-sha1) — unsupported.
			name: "unsupported algorithm rsa-sha512",
			msg:  signFixture(t, "rsa-sha512", rsaKey),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {rsaRecord},
			},
			want: DKIMPermErr,
		},
		{
			// Line 120: rsa-sha256 with a signature that is valid base64 but
			// cryptographically wrong (signed by a different key).
			name: "rsa signature invalid",
			msg:  signFixture(t, "rsa-sha256", decoyKey),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {rsaRecord},
			},
			want: DKIMFail,
		},
		{
			// Line 120: ed25519-sha256 with a garbage signature blob.
			name: "ed25519 signature invalid",
			msg: strings.Replace(
				signFixture(t, "ed25519-sha256", edPriv),
				"; b=", "; b="+garbageSig(64), 1),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {edRecord},
			},
			want: DKIMFail,
		},
		{
			// Sanity control: a correctly signed rsa-sha256 message passes.
			name: "valid rsa-sha256 signature passes",
			msg:  signFixture(t, "rsa-sha256", rsaKey),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {rsaRecord},
			},
			want:    DKIMPass,
			wantLen: 0,
		},
		{
			// Sanity control: a correctly signed ed25519-sha256 message passes.
			name: "valid ed25519-sha256 signature passes",
			msg:  signFixture(t, "ed25519-sha256", edPriv),
			txt: map[string][]string{
				selector + "._domainkey." + domain: {edRecord},
			},
			want:    DKIMPass,
			wantLen: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			setDNSResolvers(func(d string) ([]string, error) {
				if tc.txtErr != nil {
					return nil, tc.txtErr
				}
				if recs, ok := tc.txt[d]; ok {
					return recs, nil
				}
				return nil, fmt.Errorf("NXDOMAIN")
			}, nil, nil, nil)
			t.Cleanup(ResetDNSResolver)

			got, gotLen := VerifyDKIM([]byte(tc.msg), domain)
			if got != tc.want {
				t.Errorf("VerifyDKIM result = %q, want %q", got, tc.want)
			}
			if got != DKIMPass && gotLen != 0 {
				t.Errorf("VerifyDKIM signedLen = %d for non-pass result %q, want 0", gotLen, got)
			}
			if tc.want == DKIMPass && gotLen != tc.wantLen {
				t.Errorf("VerifyDKIM signedLen = %d, want %d", gotLen, tc.wantLen)
			}
		})
	}
}
