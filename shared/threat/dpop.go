package threat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const dpopMaxSkew = 60 * time.Second

// DPoPAdmissionCode is the machine-readable problem `code` carried by every
// 401 that refused a request at the DPoP/token-binding ADMISSION layer — the
// proof was missing, unverifiable, bound to the wrong key, or lacked the ath
// binding — while the presented SESSION itself may still be perfectly alive
// (RFC 9449 per-tab token sourcing: a freshly opened or stale browser tab mints
// inadmissible proofs for a live session).
//
// It is the per-tab recovery contract's marker: the webmail client replays a
// proof-signed request after GET /auth/session/token ONLY when its 401 carries
// this code. Application-level 401s that already COMMITTED state server-side
// (e.g. the TOTP-removal invalid-code refusal, whose evaluated failure counts
// toward the factor lockout) must NEVER carry it — replaying them would
// double-count toward lockout. Emitted by shared/middleware's token-binding
// denies, authserver RequireAuth's ErrTokenBinding arm, and the possession
// endpoints' T1 admission refusal.
const DPoPAdmissionCode = "dpop_admission"

// JKTFromJWK computes the RFC 7638 base64url(SHA-256) thumbprint of an EC P-256
// public JWK (the cnf.jkt the token is bound to). Members MUST be the canonical
// lexicographic set {crv,kty,x,y} with no whitespace.
func JKTFromJWK(jwk map[string]any) (string, error) {
	crv, _ := jwk["crv"].(string)
	kty, _ := jwk["kty"].(string)
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	if kty != "EC" || crv != "P-256" || x == "" || y == "" {
		return "", errors.New("dpop: unsupported or incomplete JWK")
	}
	// Validate x and y are valid base64url before interpolating — a non-base64 value
	// would produce a malformed thumbprint silently (RFC 7638 requires canonical members).
	if _, err := base64.RawURLEncoding.DecodeString(x); err != nil {
		return "", fmt.Errorf("dpop: JWK x is not valid base64url: %w", err)
	}
	if _, err := base64.RawURLEncoding.DecodeString(y); err != nil {
		return "", fmt.Errorf("dpop: JWK y is not valid base64url: %w", err)
	}
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, crv, kty, x, y)
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// dpopReplayCacheMaxEntries bounds the replay cache so a flood of unique
// (signed!) proofs cannot grow it without limit for the whole TTL window, and
// so lookups stay O(1) instead of scanning every live entry per proof
// (uncontrolled-resource-consumption closure, occ_6a29c60ec678f091dba9a01b).
// Capacity rationale: DPoP proofs are single-use and refresh at most once per
// request; 65,536 live jtis is orders of magnitude beyond any legitimate
// process-wide request rate over a TTL window (the production cache runs a
// 5-minute TTL), while capping resident memory at a few MiB worst-case.
const dpopReplayCacheMaxEntries = 1 << 16

// DPoPReplayCache is a small bounded TTL set of seen proof jtis (replay window
// guard). Membership is O(1); expired entries are evicted lazily from the
// insertion queue (oldest inserted == earliest expiring, because a jti's
// expiry is fixed at insert time), so no operation ever scans the whole set.
// When the cache is full of unexpired entries, the oldest insert is evicted to
// admit the newcomer — the standard bounded-replay-cache trade-off: under a
// sustained flood of unique proofs the replay window degrades from TTL to the
// newest dpopReplayCacheMaxEntries inserts, and minting a flood requires an
// attacker who can sign proofs, i.e. a broken key, which DPoP's signature
// checks already gate on.
type DPoPReplayCache struct {
	mu    sync.Mutex
	seen  map[string]time.Time
	order []string // insertion order; front = oldest insert == earliest expiry
	ttl   time.Duration
}

// NewDPoPReplayCache returns a replay cache with the given TTL.
func NewDPoPReplayCache(ttl time.Duration) *DPoPReplayCache {
	return &DPoPReplayCache{seen: make(map[string]time.Time), ttl: ttl}
}

func (c *DPoPReplayCache) checkAndAdd(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Lazy expiry: entries leave strictly in insertion order (expiry is fixed
	// at insert), so the queue front yields every expired entry in O(1)
	// amortized time — no full-set scan per proof. A queue entry already
	// evicted by the hard cap below is not in the set, reads as the zero time,
	// and is therefore dropped as long-expired — so the queue can never leak
	// stale entries even though cap-eviction and expiry share this front.
	for len(c.order) > 0 {
		oldest := c.order[0]
		if now.Sub(c.seen[oldest]) > c.ttl {
			delete(c.seen, oldest)
			c.order = c.order[1:]
			continue
		}
		break
	}

	if _, ok := c.seen[jti]; ok {
		return false
	}
	if len(c.seen) >= dpopReplayCacheMaxEntries {
		// Hard cap: evict the oldest live insert to bound memory. See the
		// struct doc for the flood trade-off.
		if len(c.order) > 0 {
			oldest := c.order[0]
			delete(c.seen, oldest)
			c.order = c.order[1:]
		}
	}
	c.seen[jti] = now
	c.order = append(c.order, jti)
	return true
}

// VerifyDPoP verifies a DPoP proof header (RFC 9449) binds to expectedJKT.
// It checks: ES256 sig over the embedded JWK, jkt(JWK)==expectedJKT, htm/htu
// match the request, iat within skew, and the proof jti is not replayed.
//
// NOTE (D-SHARED-THREAT-008): this seam does NOT enforce the RFC 9449 §4.3
// ath (access-token) binding. It is retained for callers that cannot supply
// the raw access token at the verification point; any caller that holds the
// token MUST use VerifyDPoPForToken instead, which enforces ath.
func VerifyDPoP(proofHeader, htm, htu, expectedJKT string, now time.Time, replay *DPoPReplayCache) error {
	return verifyDPoP(proofHeader, htm, htu, expectedJKT, "", now, replay)
}

// VerifyDPoPForToken verifies a DPoP proof header (RFC 9449 §4.2-4.3) bound to
// both expectedJKT and the presented access token: the proof MUST carry an
// ath claim equal to base64url(SHA-256(ASCII(accessToken))). This closes the
// proof-substitution window where a captured in-window proof is replayed
// against a separately stolen token sharing the same jkt: with ath enforced,
// the proof only attests requests carrying the very token it was minted for.
// An accessToken of "" is a caller defect and is rejected, never a bypass.
func VerifyDPoPForToken(proofHeader, htm, htu, expectedJKT, accessToken string, now time.Time, replay *DPoPReplayCache) error {
	if accessToken == "" {
		return errors.New("dpop: access token is required for ath binding")
	}
	return verifyDPoP(proofHeader, htm, htu, expectedJKT, accessToken, now, replay)
}

func verifyDPoP(proofHeader, htm, htu, expectedJKT, accessToken string, now time.Time, replay *DPoPReplayCache) error {
	var embeddedJWK map[string]any
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
	tok, err := parser.Parse(proofHeader, func(t *jwt.Token) (any, error) {
		// RFC 9449 §4.2: typ MUST be exactly "dpop+jwt".
		if t.Header["typ"] != "dpop+jwt" {
			return nil, errors.New("dpop: wrong typ header, must be dpop+jwt")
		}
		jwkRaw, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, errors.New("dpop: missing jwk header")
		}
		embeddedJWK = jwkRaw
		return ecdsaPublicKeyFromJWK(jwkRaw)
	})
	if err != nil || !tok.Valid {
		return fmt.Errorf("dpop: invalid proof signature: %w", err)
	}
	jkt, err := JKTFromJWK(embeddedJWK)
	if err != nil {
		return err
	}
	if jkt != expectedJKT {
		return errors.New("dpop: proof key does not match cnf.jkt (off-device/replay)")
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("dpop: bad claims")
	}
	if claims["htm"] != htm || claims["htu"] != htu {
		return errors.New("dpop: htm/htu mismatch")
	}
	if accessToken != "" {
		// RFC 9449 §4.3: ath = base64url(SHA-256(ASCII(access_token))).
		ath, _ := claims["ath"].(string)
		sum := sha256.Sum256([]byte(accessToken))
		wantATH := base64.RawURLEncoding.EncodeToString(sum[:])
		if ath == "" {
			return errors.New("dpop: ath claim missing (access-token binding required)")
		}
		if ath != wantATH {
			return errors.New("dpop: ath mismatch (proof was minted for a different access token)")
		}
	}
	iatF, _ := claims["iat"].(float64)
	iat := time.Unix(int64(iatF), 0)
	if now.Sub(iat) > dpopMaxSkew || iat.Sub(now) > dpopMaxSkew {
		return errors.New("dpop: iat outside skew window")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" || !replay.checkAndAdd(jti, now) {
		return errors.New("dpop: replayed or missing jti")
	}
	return nil
}

func ecdsaPublicKeyFromJWK(jwk map[string]any) (any, error) {
	x, _ := jwk["x"].(string)
	y, _ := jwk["y"].(string)
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, err
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, err
	}
	return ecdsaPub(xb, yb), nil
}

func ecdsaPub(xb, yb []byte) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}
}
