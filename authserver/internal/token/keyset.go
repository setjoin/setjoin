package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
)

// algES256 is the only asymmetric first-party signing algorithm (ADR-005).
const algES256 = "ES256"

// signing_keys.status values.
const (
	statusActive   = "active"
	statusRetiring = "retiring"
	statusRetired  = "retired"
)

// loadedKey is one decrypted, parsed signing key held in memory.
type loadedKey struct {
	kid    string
	alg    string
	priv   *ecdsa.PrivateKey // nil for keys loaded verify-only (not used today; all loaded keys carry the private half)
	pub    *ecdsa.PublicKey
	status string
}

// KeySet is the asymmetric-signing seam (ADR-005). It owns generate/load of the
// DB-backed encrypted keystore (`signing_keys`), the active signer, the
// kid→public-key verifier map (active + retiring keys only), JWKS marshaling,
// and is the single place a kid is bound to exactly one alg.
//
// It is a read-mostly snapshot: Load() builds it once at boot. The map is not
// mutated after construction, so concurrent ActiveSigner / VerifierByKID / JWKS
// reads need no lock. (Rotation re-Loads a fresh KeySet; wiring that swap is an
// operational follow-up, out of scope here.)
type KeySet struct {
	active *loadedKey
	byKID  map[string]*loadedKey
}

// Load reads the active + retiring keys from signing_keys, decrypting each
// private_key_enc (a PKCS#8-DER private key in the cryptokey column envelope)
// into an *ecdsa.PrivateKey. If NO active key exists, it generates a fresh P-256
// keypair, marshals the public key to a JWK, encrypts the PKCS#8-DER private key
// via the cryptokey seam, and INSERTs it as 'active' — race-safely: the partial
// unique index (one active row) makes a losing concurrent INSERT a conflict, on
// which Load re-SELECTs the winner. encKey is the RAW master secret (the JWT
// secret); cryptokey.EncryptColumn/DecryptColumn derive the column key from it
// internally (DeriveDBEncryptionKey) — do NOT pre-derive it here, or the column
// envelope would double-derive. profile selects the envelope algorithm.
func Load(ctx context.Context, db *pgxpool.Pool, encKey []byte, profile cryptokey.CryptoProfile) (*KeySet, error) {
	ks, err := loadFromDB(ctx, db, encKey)
	if err != nil {
		return nil, err
	}
	if ks.active != nil {
		return ks, nil
	}

	// No active key — mint one and persist it.
	if err := generateActiveKey(ctx, db, encKey, profile); err != nil {
		return nil, err
	}
	// Re-load; whether we won or lost the race, an active key now exists.
	ks, err = loadFromDB(ctx, db, encKey)
	if err != nil {
		return nil, err
	}
	if ks.active == nil {
		return nil, errors.New("token: keystore has no active key after generation")
	}
	return ks, nil
}

// loadFromDB SELECTs active + retiring keys and decrypts/parses each one.
func loadFromDB(ctx context.Context, db *pgxpool.Pool, encKey []byte) (*KeySet, error) {
	rows, err := db.Query(ctx,
		`SELECT kid, alg, private_key_enc, status
		   FROM signing_keys
		  WHERE status IN ($1, $2)`,
		statusActive, statusRetiring)
	if err != nil {
		return nil, fmt.Errorf("token: query signing_keys: %w", err)
	}
	defer rows.Close()

	ks := &KeySet{byKID: make(map[string]*loadedKey)}
	for rows.Next() {
		var kid, alg, status string
		var enc []byte
		if err := rows.Scan(&kid, &alg, &enc, &status); err != nil {
			return nil, fmt.Errorf("token: scan signing_keys: %w", err)
		}
		priv, err := decryptPrivateKey(enc, encKey)
		if err != nil {
			return nil, fmt.Errorf("token: decrypt signing key %q: %w", kid, err)
		}
		lk := &loadedKey{kid: kid, alg: alg, priv: priv, pub: &priv.PublicKey, status: status}
		ks.byKID[kid] = lk
		if status == statusActive {
			ks.active = lk
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("token: iterate signing_keys: %w", err)
	}
	return ks, nil
}

// generateActiveKey mints a P-256 keypair and INSERTs it as the active key.
// On a unique-index conflict (another instance won the race), it returns nil —
// the caller re-SELECTs the winner.
func generateActiveKey(ctx context.Context, db *pgxpool.Pool, encKey []byte, profile cryptokey.CryptoProfile) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("token: generate P-256 key: %w", err)
	}
	kid, err := deriveKID(&priv.PublicKey)
	if err != nil {
		return fmt.Errorf("token: derive kid: %w", err)
	}
	jwkJSON, err := publicJWKJSON(&priv.PublicKey, kid)
	if err != nil {
		return fmt.Errorf("token: marshal public jwk: %w", err)
	}
	enc, err := encryptPrivateKey(priv, encKey, profile)
	if err != nil {
		return fmt.Errorf("token: encrypt private key: %w", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO signing_keys (kid, alg, public_jwk, private_key_enc, status)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT DO NOTHING`,
		kid, algES256, jwkJSON, enc, statusActive)
	if err != nil {
		return fmt.Errorf("token: insert active signing key: %w", err)
	}
	// ON CONFLICT DO NOTHING covers both the kid UNIQUE and the partial
	// one-active index, so a lost race is a silent no-op; the caller re-reads.
	return nil
}

// ActiveSigner returns the kid and EC private key of the active signing key.
// ok is false if no active key is loaded.
func (k *KeySet) ActiveSigner() (kid string, key *ecdsa.PrivateKey, ok bool) {
	if k == nil || k.active == nil || k.active.priv == nil {
		return "", nil, false
	}
	return k.active.kid, k.active.priv, true
}

// VerifierByKID returns the public key + registered alg for a kid, but ONLY from
// the loaded active + retiring keys. A retired key (or any kid not loaded) is not
// found — its tokens no longer verify. The returned alg lets the caller enforce
// the RFC 8725 alg-confusion closure (header alg must equal the registered alg).
func (k *KeySet) VerifierByKID(kid string) (pub *ecdsa.PublicKey, alg string, ok bool) {
	if k == nil {
		return nil, "", false
	}
	lk, found := k.byKID[kid]
	if !found || lk.pub == nil {
		return nil, "", false
	}
	return lk.pub, lk.alg, true
}

// JWKS returns the active + retiring PUBLIC keys as a JSON Web Key Set. It never
// includes private material. The mailserver gateway fetches this to verify
// first-party tokens offline by kid.
func (k *KeySet) JWKS() jose.JSONWebKeySet {
	set := jose.JSONWebKeySet{}
	if k == nil {
		return set
	}
	for _, lk := range k.byKID {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       lk.pub,
			KeyID:     lk.kid,
			Algorithm: lk.alg,
			Use:       "sig",
		})
	}
	return set
}

// MarshalJWKS returns the JWKS as JSON bytes (the wire form for the endpoint).
// jose.JSONWebKey carries a custom MarshalJSON (EC point → x/y base64url), so
// json.Marshal of the set produces a spec-correct {"keys":[…]} document.
func (k *KeySet) MarshalJWKS() ([]byte, error) {
	set := k.JWKS()
	return json.Marshal(set)
}

// ── helpers ──

// deriveKID derives a stable, collision-resistant key id from the public key:
// "es256-" + first 16 hex chars of the SHA-256 of the SPKI DER. Deterministic in
// the key, so the same key always gets the same kid.
func deriveKID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "es256-" + hex.EncodeToString(sum[:8]), nil
}

// publicJWKJSON marshals an EC public key to a JWK JSON object (use=sig,
// alg=ES256, kid set) for the public_jwk column.
func publicJWKJSON(pub *ecdsa.PublicKey, kid string) ([]byte, error) {
	jwk := jose.JSONWebKey{
		Key:       pub,
		KeyID:     kid,
		Algorithm: algES256,
		Use:       "sig",
	}
	return jwk.MarshalJSON()
}

// encryptPrivateKey marshals the EC private key to PKCS#8 DER and wraps it in the
// cryptokey column envelope (AES-256-GCM under the derived DB key).
func encryptPrivateKey(priv *ecdsa.PrivateKey, masterKey []byte, profile cryptokey.CryptoProfile) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal PKCS#8: %w", err)
	}
	return cryptokey.EncryptColumn(der, masterKey, profile)
}

// decryptPrivateKey reverses encryptPrivateKey: opens the column envelope and
// parses the PKCS#8 DER back into an *ecdsa.PrivateKey.
func decryptPrivateKey(enc, masterKey []byte) (*ecdsa.PrivateKey, error) {
	der, err := cryptokey.DecryptColumn(enc, masterKey)
	if err != nil {
		return nil, fmt.Errorf("open column envelope: %w", err)
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	ecKey, ok := keyAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("stored signing key is %T, not *ecdsa.PrivateKey", keyAny)
	}
	return ecKey, nil
}
