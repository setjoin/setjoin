package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/testsupport"
)

// openTokenPool returns a real pool; skips if DB_DSN is not set. Provide the DSN
// postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable to run these.
func openTokenPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

// freshKeystore truncates signing_keys so each test starts from an empty
// keystore (generate-on-first-boot is observable). Skips if the table is absent.
func freshKeystore(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `TRUNCATE signing_keys RESTART IDENTITY`); err != nil {
		t.Skipf("signing_keys table not present (schema not loaded?): %v", err)
	}
}

// testEncKey returns the RAW master secret, exactly as main.go now passes
// []byte(cfg.JWTSecret) into Load. cryptokey.EncryptColumn/DecryptColumn derive
// the column key from it internally — pre-deriving here would not match the
// production path (and would double-derive).
func testEncKey() []byte {
	return []byte("test-secret-32-bytes-long-ok-now!!")
}

// TestKeySet_GenerateOnFirstBootIsIdempotent proves the first Load mints exactly
// one active key, and a second Load reuses it (no duplicate active row).
func TestKeySet_GenerateOnFirstBootIsIdempotent(t *testing.T) {
	pool := openTokenPool(t)
	freshKeystore(t, pool)
	ctx := context.Background()
	enc := testEncKey()

	ks1, err := Load(ctx, pool, enc, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("first Load: %v", err)
	}
	kid1, _, ok := ks1.ActiveSigner()
	if !ok {
		t.Fatal("first Load produced no active signer")
	}

	var nActive int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys WHERE status='active'`).Scan(&nActive); err != nil {
		t.Fatalf("count active: %v", err)
	}
	if nActive != 1 {
		t.Fatalf("expected exactly 1 active key, got %d", nActive)
	}

	ks2, err := Load(ctx, pool, enc, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("second Load: %v", err)
	}
	kid2, _, ok := ks2.ActiveSigner()
	if !ok {
		t.Fatal("second Load produced no active signer")
	}
	if kid1 != kid2 {
		t.Fatalf("second Load minted a new key: kid %q != %q", kid2, kid1)
	}

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_keys`).Scan(&nActive); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if nActive != 1 {
		t.Fatalf("expected exactly 1 key total after two Loads, got %d", nActive)
	}
}

// TestKeySet_ES256RoundTrip proves a token signed with the active ES256 key
// validates through the same JWTProvider.Validate seam.
func TestKeySet_ES256RoundTrip(t *testing.T) {
	pool := openTokenPool(t)
	freshKeystore(t, pool)
	ctx := context.Background()

	ks, err := Load(ctx, pool, testEncKey(), cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	p := NewJWTProvider("test-secret-32-bytes-long-ok-now!!", nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "test-issuer").WithKeySet(ks, SigningAlgES256)

	if p.SigningAlg() != SigningAlgES256 {
		t.Fatalf("expected ES256 signing, got %s", p.SigningAlg())
	}

	tokenStr, err := p.IssueAccess(42, "user@example.com", false)
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	// The header must declare ES256 + the active kid.
	parsed, _, err := new(jwt.Parser).ParseUnverified(tokenStr, &jwtutil.Claims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if parsed.Header["alg"] != "ES256" {
		t.Fatalf("token alg = %v, want ES256", parsed.Header["alg"])
	}
	activeKID, _, _ := ks.ActiveSigner()
	if parsed.Header["kid"] != activeKID {
		t.Fatalf("token kid = %v, want active kid %q", parsed.Header["kid"], activeKID)
	}

	claims, err := p.Validate(tokenStr)
	if err != nil {
		t.Fatalf("Validate ES256 token: %v", err)
	}
	if claims.UserID != 42 {
		t.Fatalf("UserID = %d, want 42", claims.UserID)
	}
}

// TestKeySet_JWKSPublicOnly proves JWKS() contains the active kid and ONLY
// public material (no private scalar D).
func TestKeySet_JWKSPublicOnly(t *testing.T) {
	pool := openTokenPool(t)
	freshKeystore(t, pool)
	ctx := context.Background()

	ks, err := Load(ctx, pool, testEncKey(), cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	activeKID, _, _ := ks.ActiveSigner()

	body, err := ks.MarshalJWKS()
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}

	// The active kid must be present.
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	found := false
	for _, k := range set.Keys {
		if k.KeyID == activeKID {
			found = true
			if !k.IsPublic() {
				t.Fatal("JWKS key is not public-only")
			}
		}
	}
	if !found {
		t.Fatalf("active kid %q not in JWKS", activeKID)
	}

	// The raw JSON must never carry the private EC scalar "d".
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("unmarshal raw JWKS: %v", err)
	}
	keys, _ := raw["keys"].([]any)
	for _, ki := range keys {
		km, _ := ki.(map[string]any)
		if _, hasD := km["d"]; hasD {
			t.Fatal("JWKS leaked the private scalar 'd' — must publish public keys only")
		}
	}
}

// TestKeySet_AlgConfusionRejected proves an HS256 token whose kid names the
// active EC key is rejected by Validate (RFC 8725 alg-confusion closure).
func TestKeySet_AlgConfusionRejected(t *testing.T) {
	pool := openTokenPool(t)
	freshKeystore(t, pool)
	ctx := context.Background()

	ks, err := Load(ctx, pool, testEncKey(), cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	activeKID, _, _ := ks.ActiveSigner()

	p := NewJWTProvider("test-secret-32-bytes-long-ok-now!!", nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "test-issuer").WithKeySet(ks, SigningAlgES256)

	// Forge an HS256 token that claims the EC key's kid. The HS256 branch must
	// reject it because the kid is not kidHMAC — a public key is never coerced
	// into an HMAC secret.
	now := time.Now()
	forged := jwt.NewWithClaims(jwt.SigningMethodHS256, &jwtutil.Claims{
		UserID: 99,
		Type:   jwtutil.TypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{audience},
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	})
	forged.Header["kid"] = activeKID
	forgedStr, err := forged.SignedString([]byte("test-secret-32-bytes-long-ok-now!!"))
	if err != nil {
		t.Fatalf("sign forged HS256: %v", err)
	}

	if _, err := p.Validate(forgedStr); err == nil {
		t.Fatal("expected Validate to reject an HS256 token bearing an EC kid (alg confusion), got nil")
	}
}

// TestKeySet_Rotation proves dual-verify across rotation: after marking the
// active key 'retiring' and inserting a new 'active', tokens from BOTH verify;
// a key marked 'retired' no longer verifies.
func TestKeySet_Rotation(t *testing.T) {
	pool := openTokenPool(t)
	freshKeystore(t, pool)
	ctx := context.Background()
	enc := testEncKey()

	// Boot 1: mint the first active key, sign a token with it.
	ks1, err := Load(ctx, pool, enc, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	oldKID, _, _ := ks1.ActiveSigner()
	pOld := NewJWTProvider("test-secret-32-bytes-long-ok-now!!", nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "test-issuer").WithKeySet(ks1, SigningAlgES256)
	oldToken, err := pOld.IssueAccess(1, "old@example.com", false)
	if err != nil {
		t.Fatalf("issue old token: %v", err)
	}

	// Rotate: old → retiring, then Load mints a NEW active.
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET status='retiring', rotated_at=now() WHERE kid=$1`, oldKID); err != nil {
		t.Fatalf("mark retiring: %v", err)
	}
	ks2, err := Load(ctx, pool, enc, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	newKID, _, _ := ks2.ActiveSigner()
	if newKID == oldKID {
		t.Fatal("rotation did not mint a new active key")
	}
	pNew := NewJWTProvider("test-secret-32-bytes-long-ok-now!!", nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "test-issuer").WithKeySet(ks2, SigningAlgES256)
	newToken, err := pNew.IssueAccess(2, "new@example.com", false)
	if err != nil {
		t.Fatalf("issue new token: %v", err)
	}

	// During overlap, BOTH the retiring-key token and the new-active-key token verify.
	if _, err := pNew.Validate(oldToken); err != nil {
		t.Fatalf("retiring-key token must still verify during overlap: %v", err)
	}
	if _, err := pNew.Validate(newToken); err != nil {
		t.Fatalf("new active-key token must verify: %v", err)
	}

	// Retire the old key fully → its tokens must NO LONGER verify (dropped from
	// the loaded verifier set + the JWKS).
	if _, err := pool.Exec(ctx, `UPDATE signing_keys SET status='retired' WHERE kid=$1`, oldKID); err != nil {
		t.Fatalf("mark retired: %v", err)
	}
	ks3, err := Load(ctx, pool, enc, cryptokey.ProfileStandard)
	if err != nil {
		t.Fatalf("Load 3: %v", err)
	}
	pFinal := NewJWTProvider("test-secret-32-bytes-long-ok-now!!", nil, cryptokey.ProfileStandard,
		time.Hour, 720*time.Hour, "test-issuer").WithKeySet(ks3, SigningAlgES256)

	if _, _, ok := ks3.VerifierByKID(oldKID); ok {
		t.Fatal("retired key must not be in the verifier set")
	}
	if _, err := pFinal.Validate(oldToken); err == nil {
		t.Fatal("a retired key's token must NOT verify, got nil error")
	}
	if _, err := pFinal.Validate(newToken); err != nil {
		t.Fatalf("the still-active key's token must verify: %v", err)
	}
}
