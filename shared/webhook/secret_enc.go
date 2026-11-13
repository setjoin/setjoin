package webhook

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
)

// SecretCodec seals and opens webhook subscription signing secrets at rest in
// the family's AES-256-GCM EK01 column envelope (D6 / DBSCHEMA-005; the
// shared/device SecretCodec pattern applied to webhook_subscriptions.secret /
// prev_secret).
//
// The stored form mirrors devices.hmac_secret_enc: cryptokey.EncryptColumn
// seals the secret from the RAW master secret (DeriveDBEncryptionKey inside
// the seam — never pre-derive and never pass key material into SQL), and the
// envelope is self-describing across profile changes. A non-secret key-version
// id is stamped BESIDE the envelope (webhook_subscriptions.secret_key_id)
// following the system_config secret-codec convention, so a future rotation
// decision can be made without another migration.
//
// The codec is constructed once per process from the process's master secret
// and threaded explicitly to the seams that touch signing secrets: the
// user/admin webhook handlers (create/rotate writes) and the dispatcher
// (per-delivery read). A nil codec at a WRITE seam fails closed — after the
// at-rest cutover, silently persisting plaintext would defeat the control.
// The dispatcher READ seam requires the codec too (the V247 device loader
// contract): a nil codec fails closed on every read, legacy rows included —
// delivery must never depend on encryption being unavailable (V247's
// fail-closed posture; Astra D6 impl-r2 finding 3).
type SecretCodec struct {
	masterKey []byte
	profile   cryptokey.CryptoProfile
}

// SecretKeyIDV1 is the active master-key version stamped beside newly sealed
// webhook signing-secret envelopes.
const SecretKeyIDV1 = "v1"

// NewSecretCodec builds a codec over the RAW master secret (the JWT secret) —
// cryptokey derives the column key internally; do NOT pre-derive here or the
// envelope would double-derive (signing_keys contract).
func NewSecretCodec(masterKey []byte, profile cryptokey.CryptoProfile) *SecretCodec {
	return &SecretCodec{masterKey: append([]byte(nil), masterKey...), profile: profile}
}

// ActiveKeyID is the key version stamped beside newly sealed envelopes. The
// master key bytes are intentionally never exposed.
func (c *SecretCodec) ActiveKeyID() string {
	if c == nil {
		return ""
	}
	return SecretKeyIDV1
}

// Seal encrypts one webhook signing secret into the EK01 column envelope.
func (c *SecretCodec) Seal(plaintext string) ([]byte, error) {
	if c == nil || len(c.masterKey) == 0 {
		return nil, errors.New("webhook: secret codec not configured")
	}
	envelope, err := cryptokey.EncryptColumn([]byte(plaintext), c.masterKey, c.profile)
	if err != nil {
		return nil, fmt.Errorf("webhook: seal signing secret: %w", err)
	}
	return envelope, nil
}

// Open decrypts one stored envelope. keyID must be the id this codec's master
// key version stamped at seal time; an unknown or unstamped id fails closed
// (never fall back to decrypting under the wrong key generation).
func (c *SecretCodec) Open(envelope []byte, keyID string) (string, error) {
	if c == nil || len(c.masterKey) == 0 {
		return "", errors.New("webhook: secret codec not configured")
	}
	if keyID != SecretKeyIDV1 {
		return "", fmt.Errorf("webhook: signing secret requires unavailable key version %q", keyID)
	}
	plaintext, err := cryptokey.DecryptColumn(envelope, c.masterKey)
	if err != nil {
		return "", fmt.Errorf("webhook: open signing secret envelope: %w", err)
	}
	return string(plaintext), nil
}

// LoadSubscriptionSecret loads the per-subscription HMAC signing secret for
// one webhook subscription — the dispatcher's delivery seam (both the
// best-effort fan-out and the durable claim path).
//
// codec is REQUIRED — nil fails closed on every read, legacy rows included
// (the V247 device loader contract; Astra D6 impl-r2 finding 3): delivery
// must never succeed because encryption is unavailable.
//
// The stored secret is the family's AES-256-GCM _enc envelope
// (webhook_subscriptions.secret_enc, sealed by codec; D6/DBSCHEMA-005). A
// legacy row that still holds its pre-migration plaintext secret is returned
// unchanged (compatibility leg) and lazily re-sealed in ONE atomic UPDATE
// that drains BOTH plaintext cells: secret → (secret_enc, secret_key_id) and
// prev_secret → (prev_secret_enc, prev_secret_key_id). A rotated legacy row
// therefore ends ciphertext-only in all four cells — no plaintext
// prev_secret may survive the migration (Astra D6 impl-r2 finding 1). The
// lazy re-seal is best-effort: a failure never blocks the delivery this call
// feeds — the next delivery retries it.
func LoadSubscriptionSecret(ctx context.Context, pool *pgxpool.Pool, codec *SecretCodec, subscriptionID int64) (string, error) {
	if codec == nil {
		return "", errors.New("webhook: secret codec not configured")
	}
	var legacy *string     // non-nil ⇒ pre-migration plaintext row (compatibility leg)
	var prevLegacy *string // rotation-grace plaintext on a legacy rotated row
	var envelope []byte
	var keyID *string
	var prevEnvelope []byte
	var prevKeyID *string
	err := pool.QueryRow(ctx,
		`SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id
		   FROM webhook_subscriptions
		  WHERE id = $1`, subscriptionID,
	).Scan(&legacy, &prevLegacy, &envelope, &keyID, &prevEnvelope, &prevKeyID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("webhook: subscription %d not found", subscriptionID)
		}
		return "", fmt.Errorf("webhook: load signing secret: %w", err)
	}

	// Ciphertext form (every row written after V260, and every row the lazy
	// migration below has drained): open under the stamped key version.
	if envelope != nil {
		if keyID == nil {
			// Unstamped ciphertext cannot be attributed to a key generation.
			return "", fmt.Errorf("webhook: signing secret envelope missing key id")
		}
		return codec.Open(envelope, *keyID)
	}

	// Legacy plaintext row (pre-V260): sign with the issued value, then
	// migrate BOTH secret cells to the ciphertext-only form. Sealing is
	// all-or-nothing: if either value cannot be sealed, neither is stored and
	// the row keeps its plaintext until the next delivery (no half-migrated
	// row that still leaks prev_secret).
	if legacy == nil {
		return "", fmt.Errorf("webhook: subscription %d holds no usable signing secret", subscriptionID)
	}
	secret := *legacy
	sealed, sealErr := codec.Seal(secret)
	var sealedPrev []byte
	if sealErr == nil && prevLegacy != nil && prevEnvelope == nil {
		sealedPrev, sealErr = codec.Seal(*prevLegacy)
		if sealErr != nil {
			sealedPrev = nil // drop both seals; retry the whole migration next delivery
		}
	}
	if sealErr == nil {
		// Only stamp a prev key id when this call actually sealed a prev
		// envelope; COALESCE never overwrites an envelope/key id that is
		// already stored.
		var prevKeySeal any
		if sealedPrev != nil {
			prevKeySeal = codec.ActiveKeyID()
		}
		// One atomic UPDATE (R3: the ownership predicate and the mutation
		// share one WHERE, pinned to the exact values just loaded) — a
		// concurrent rotation that swapped either plaintext underneath us
		// makes the UPDATE a no-op instead of sealing a secret this call
		// never saw. IS NOT DISTINCT FROM keeps the NULL prev case correct.
		_, _ = pool.Exec(ctx,
			`UPDATE webhook_subscriptions
			    SET secret_enc = $2,
			        secret_key_id = $3,
			        secret = NULL,
			        prev_secret_enc = COALESCE(prev_secret_enc, $5),
			        prev_secret_key_id = COALESCE(prev_secret_key_id, $7),
			        prev_secret = NULL
			  WHERE id = $1
			    AND secret = $4
			    AND secret_enc IS NULL
			    AND prev_secret IS NOT DISTINCT FROM $6`,
			subscriptionID, sealed, codec.ActiveKeyID(), secret,
			sealedPrev, prevLegacy, prevKeySeal)
	}
	// Signing continues on the legacy value either way; a failed re-seal is
	// retried by the next delivery.
	return secret, nil
}
