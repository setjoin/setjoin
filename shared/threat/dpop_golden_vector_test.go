package threat

import (
	"testing"
	"time"
)

// TestVerifyDPoPGoldenVectorFromWebCrypto cross-verifies the Go DPoP path
// against a proof produced independently by the browser's WebCrypto API (Node's
// webcrypto.subtle, the same ES256/P-256 primitives crypto.subtle exposes),
// not merely round-tripped through this package's own signer (dpop_test.go's
// makeProof uses golang-jwt to both sign and verify — it can't catch a
// TS<->Go wire-format mismatch). Vector regenerated via
// scripts/gen-dpop-golden-vector.mjs; see that file's header comment.
//
// iat is fixed and passed explicitly as `now`, so this never goes stale from
// the DPoP skew window regardless of when the test suite runs.
func TestVerifyDPoPGoldenVectorFromWebCrypto(t *testing.T) {
	const proof = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiTEVjVFNRdnIzUW9PLXlNdWZwYzBfWVFFWjh2NVFGNEdsZlh1UC1PVVR5SSIsInkiOiJCQ1Izd2xuRnEyM3hrX0trSDFqUEdDXzFidGdhTXVWLXZWTTVWb3FoVHJJIn19.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9tYWlsLmV4YW1wbGUuY29tL2ptYXAiLCJpYXQiOjE3NTE1MDAwMDAsImp0aSI6ImdvbGRlbi12ZWN0b3ItanRpLTEifQ.BfrV7fgEQmC0W-YdWtF2A9sPcwEEJyBDVK0ylLC45lBVZ8z8cT4uwfvomEhuvvEZ2apHgWZOmxNBXCoCj8WlBQ"
	const wantJKT = "3y_ESa858SEuRSQcy5jiAA4_LGqzSEcNc0dXiDvFOJQ"
	wantJWK := map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "LEcTSQvr3QoO-yMufpc0_YQEZ8v5QF4GlfXuP-OUTyI",
		"y":   "BCR3wlnFq23xk_KkH1jPGC_1btgaMuV-vVM5VoqhTrI",
	}
	const iatUnix = 1751500000

	jkt, err := JKTFromJWK(wantJWK)
	if err != nil {
		t.Fatalf("JKTFromJWK: %v", err)
	}
	if jkt != wantJKT {
		t.Fatalf("jkt thumbprint mismatch: Go computed %s, WebCrypto vector expects %s — canonical member order/format has drifted between TS and Go", jkt, wantJKT)
	}

	rc := NewDPoPReplayCache(time.Minute)
	if err := VerifyDPoP(proof, "POST", "https://mail.example.com/jmap", wantJKT, time.Unix(iatUnix, 0), rc); err != nil {
		t.Fatalf("WebCrypto-produced proof rejected by Go VerifyDPoP: %v", err)
	}

	// Wrong htu must still fail against the SAME real proof (proves htu is
	// actually checked against the browser-shaped value, not just Go's own).
	rc2 := NewDPoPReplayCache(time.Minute)
	if err := VerifyDPoP(proof, "POST", "https://mail.example.com/other", wantJKT, time.Unix(iatUnix, 0), rc2); err == nil {
		t.Fatal("htu mismatch on the golden vector must be rejected")
	}
}
