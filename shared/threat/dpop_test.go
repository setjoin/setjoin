package threat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func makeProof(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti string, iat time.Time) (string, string) {
	t.Helper()
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	jkt, err := JKTFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": htm, "htu": htu, "jti": jti, "iat": iat.Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, jkt
}

func TestVerifyDPoPHappyAndReplay(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof, jkt := makeProof(t, key, "POST", "https://x/jmap", "p1", time.Now())
	rc := NewDPoPReplayCache(5 * time.Minute)
	if err := VerifyDPoP(proof, "POST", "https://x/jmap", jkt, time.Now(), rc); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// Replay of the same jti → error.
	if err := VerifyDPoP(proof, "POST", "https://x/jmap", jkt, time.Now(), rc); err == nil {
		t.Fatal("replayed jti must be rejected")
	}
}

// TestDPoPReplayCacheBoundedUnderFlood pins the resource bound
// (occ_6a29c60ec678f091dba9a01b): a flood of unique jtis cannot grow the cache
// past dpopReplayCacheMaxEntries live entries, and membership stays exact for
// everything still resident.
func TestDPoPReplayCacheBoundedUnderFlood(t *testing.T) {
	rc := NewDPoPReplayCache(time.Hour)
	now := time.Now()

	if !rc.checkAndAdd("victim-jti", now) {
		t.Fatal("first insert refused")
	}
	for i := 0; i < dpopReplayCacheMaxEntries; i++ {
		if !rc.checkAndAdd(fmt.Sprintf("flood-%d", i), now) {
			t.Fatalf("unique jti flood-%d refused", i)
		}
	}
	if len(rc.seen) > dpopReplayCacheMaxEntries {
		t.Fatalf("cache grew to %d live entries, cap is %d", len(rc.seen), dpopReplayCacheMaxEntries)
	}
	if len(rc.order) > dpopReplayCacheMaxEntries+dpopReplayCacheMaxEntries/2 {
		t.Fatalf("insertion queue not tracked with evictions: %d entries", len(rc.order))
	}
	// The oldest live entry ("victim-jti" was evicted by the cap, so a replay
	// of it would now be accepted) — but the newest entries must still be
	// exactly-once within the TTL.
	if rc.checkAndAdd(fmt.Sprintf("flood-%d", dpopReplayCacheMaxEntries-1), now) {
		t.Fatal("resident recent jti accepted twice (replay)")
	}
	// Newly minted unique jtis still admitted at the cap (bounded eviction).
	if !rc.checkAndAdd("post-flood-newcomer", now) {
		t.Fatal("unique newcomer refused at cap")
	}
	if len(rc.seen) > dpopReplayCacheMaxEntries {
		t.Fatalf("cache grew past cap after newcomer insert: %d", len(rc.seen))
	}
}

// TestDPoPReplayCacheLazyExpiry pins the amortized O(1) expiry sweep: entries
// leave in insertion order once past the TTL, expired jtis become acceptable
// again exactly as with the previous full-scan sweep, and unexpired entries
// are never evicted by the expiry path.
func TestDPoPReplayCacheLazyExpiry(t *testing.T) {
	rc := NewDPoPReplayCache(time.Minute)
	t0 := time.Now()

	for _, jti := range []string{"early-1", "early-2", "early-3"} {
		if !rc.checkAndAdd(jti, t0) {
			t.Fatalf("%s first insert refused", jti)
		}
	}
	// Within the TTL a replay is rejected — no insertion-order side effect may
	// drop a live entry.
	if rc.checkAndAdd("early-2", t0.Add(30*time.Second)) {
		t.Fatal("live jti accepted twice within TTL")
	}
	// Past the TTL, the same jti is acceptable again (its claim expired), and
	// the expired prefix is purged from both the set and the queue.
	if !rc.checkAndAdd("early-1", t0.Add(2*time.Minute)) {
		t.Fatal("expired jti not re-admissible after TTL")
	}
	if _, ok := rc.seen["early-2"]; ok {
		t.Fatal("expired entry not purged from the set")
	}
	if _, ok := rc.seen["early-3"]; ok {
		t.Fatal("expired entry not purged from the set")
	}
	// early-1 was re-inserted at t0+2m; its claim is live again.
	if rc.checkAndAdd("early-1", t0.Add(2*time.Minute)) {
		t.Fatal("re-inserted jti accepted twice (replay)")
	}
}

// TestDPoPReplayCacheStaleQueueEntriesSkipped pins the eviction-consistency
// arm of the bounded cache: when the hard cap has evicted a jti from the set
// but its insertion-queue entry still sits at the front, the lazy expiry sweep
// drops the stale queue entry instead of resurrecting or panicking on it, and
// the cache remains exact afterwards.
func TestDPoPReplayCacheStaleQueueEntriesSkipped(t *testing.T) {
	rc := NewDPoPReplayCache(time.Hour)
	t0 := time.Now()

	if !rc.checkAndAdd("queue-victim", t0) {
		t.Fatal("victim insert refused")
	}
	// Flood to the cap: this evicts "queue-victim" from the set (oldest
	// insert) while its queue entry stays at the front.
	for i := 0; i < dpopReplayCacheMaxEntries; i++ {
		if !rc.checkAndAdd(fmt.Sprintf("flood2-%d", i), t0) {
			t.Fatalf("flood2-%d refused", i)
		}
	}
	if _, ok := rc.seen["queue-victim"]; ok {
		t.Fatal("victim survived the cap eviction")
	}

	// Advance past the TTL and insert: the expiry sweep must walk the queue
	// front, skip the victim's stale (already-evicted) entry via the !ok arm,
	// purge the expired floods, and accept the newcomer.
	if !rc.checkAndAdd("post-ttl-newcomer", t0.Add(2*time.Hour)) {
		t.Fatal("post-TTL newcomer refused")
	}
	if _, ok := rc.seen["queue-victim"]; ok {
		t.Fatal("stale queue entry resurrected the victim")
	}
	if len(rc.seen) != 1 {
		t.Fatalf("cache holds %d entries after full expiry, want exactly the newcomer", len(rc.seen))
	}
	if rc.checkAndAdd("post-ttl-newcomer", t0.Add(2*time.Hour)) {
		t.Fatal("post-TTL newcomer accepted twice (replay)")
	}
}

func TestVerifyDPoPWrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	proof, _ := makeProof(t, key, "POST", "https://x/jmap", "p2", time.Now())
	rc := NewDPoPReplayCache(time.Minute)
	// A cnf.jkt that does not match the proof's JWK → reject (off-device replay).
	if err := VerifyDPoP(proof, "POST", "https://x/jmap", "not-the-real-jkt", time.Now(), rc); err == nil {
		t.Fatal("jkt mismatch must be rejected")
	}
}

func TestVerifyDPoPWrongTyp(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	jkt, _ := JKTFromJWK(jwk)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST", "htu": "https://x/jmap", "jti": "wrongtyp1", "iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "JWT" // wrong — must be rejected (RFC 9449 §4.2)
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	rc := NewDPoPReplayCache(time.Minute)
	if err := VerifyDPoP(signed, "POST", "https://x/jmap", jkt, time.Now(), rc); err == nil {
		t.Fatal("wrong typ must be rejected")
	}
}

var _ = json.Marshal
var _ = big.NewInt

// makeProofWithATH mints a proof carrying an ath claim (RFC 9449 §4.3).
func makeProofWithATH(t *testing.T, key *ecdsa.PrivateKey, htm, htu, jti, ath string, iat time.Time) (string, string) {
	t.Helper()
	jwk := map[string]any{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
		"y": base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
	}
	jkt, err := JKTFromJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.MapClaims{"htm": htm, "htu": htu, "jti": jti, "iat": iat.Unix()}
	if ath != "" {
		claims["ath"] = ath
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed, jkt
}

func athFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestVerifyDPoPForToken pins the RFC 9449 §4.3 access-token binding
// (D-SHARED-THREAT-008): a proof only attests requests carrying the very
// token it was minted for, closing the captured-proof + stolen-token
// substitution window that jkt equality alone leaves open.
func TestVerifyDPoPForToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rc := NewDPoPReplayCache(5 * time.Minute)
	const accessToken = ".access-token-under-test"

	proof, jkt := makeProofWithATH(t, key, "POST", "https://x/jmap", "ath-1", athFor(accessToken), time.Now())
	if err := VerifyDPoPForToken(proof, "POST", "https://x/jmap", jkt, accessToken, time.Now(), rc); err != nil {
		t.Fatalf("bound proof rejected: %v", err)
	}

	// A different token (the stolen-token substitution) must be rejected.
	if err := VerifyDPoPForToken(proof, "POST", "https://x/jmap", jkt, "other-token", time.Now(), NewDPoPReplayCache(5*time.Minute)); err == nil {
		t.Fatal("proof bound to token A must fail verification for token B")
	}

	// A proof with NO ath claim must be rejected by the binding verifier.
	noATH, jkt2 := makeProof(t, key, "POST", "https://x/jmap", "ath-2", time.Now())
	if err := VerifyDPoPForToken(noATH, "POST", "https://x/jmap", jkt2, accessToken, time.Now(), NewDPoPReplayCache(5*time.Minute)); err == nil {
		t.Fatal("proof without ath must be rejected when the token is supplied")
	}

	// A proof minted for a different token must NOT satisfy the binding.
	other, jkt3 := makeProofWithATH(t, key, "POST", "https://x/jmap", "ath-3", athFor("some-other-token"), time.Now())
	if err := VerifyDPoPForToken(other, "POST", "https://x/jmap", jkt3, accessToken, time.Now(), NewDPoPReplayCache(5*time.Minute)); err == nil {
		t.Fatal("proof minted for another token must be rejected")
	}

	// An empty accessToken is a caller defect, never a bypass.
	if err := VerifyDPoPForToken(proof, "POST", "https://x/jmap", jkt, "", time.Now(), NewDPoPReplayCache(5*time.Minute)); err == nil {
		t.Fatal("empty access token must be rejected, not skip ath enforcement")
	}

	// The legacy seam still verifies the same proof (ath not enforced there).
	if err := VerifyDPoP(noATH, "POST", "https://x/jmap", jkt2, time.Now(), NewDPoPReplayCache(5*time.Minute)); err != nil {
		t.Fatalf("legacy VerifyDPoP must still accept a valid proof: %v", err)
	}
}
