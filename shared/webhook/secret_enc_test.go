package webhook

// Tests for D6 / DBSCHEMA-005: webhook_subscriptions.secret / prev_secret
// move from plaintext TEXT to the family's AES-256-GCM _enc envelope with
// key-id handling (the shared/device V247 pattern).
//
// Acceptance legs proven here (this package's claims ONLY — the SQL storage
// shape is pinned by mailserver/sql/tests/webhook_device_secret_enc.pg):
//
//  1. New and migrated rows store only _enc ciphertext: create-shaped writes
//     and the lazy migration of a legacy plaintext row both leave `secret`
//     NULL with a sealed envelope + key id in its place — and the migration
//     drains prev_secret in the SAME atomic UPDATE (Astra D6 impl-r2
//     finding 1): a rotated legacy row ends ciphertext-only in all four
//     cells.
//  2. The dispatcher's delivery seam (LoadSubscriptionSecret) opens migrated
//     and legacy rows; an envelope stamped with an unknown/unavailable key
//     version fails closed.
//  3. The codec is REQUIRED at the read seam: a nil codec fails closed on
//     legacy plaintext rows too — delivery never depends on encryption being
//     unavailable (Astra D6 impl-r2 finding 3).
//
// DB-backed tests need DB_DSN (testsupport skips otherwise; REQUIRE_DB makes a
// missing DB fail instead of silently passing).

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
)

const codecTestMaster = "webhook-test-master-secret-key"

// ── Pure unit: codec contract ────────────────────────────────────────────────

func TestSecretCodec_RoundTripAndFailClosed(t *testing.T) {
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)

	envelope, err := codec.Seal("a-webhook-signing-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// EK01 magic: the family's self-describing envelope, not plaintext.
	if !strings.HasPrefix(string(envelope), "EK01") {
		t.Fatalf("envelope must carry the EK01 magic, got %q", string(envelope[:4]))
	}
	if strings.Contains(string(envelope), "a-webhook-signing-secret") {
		t.Fatal("envelope must not contain the plaintext secret")
	}

	opened, err := codec.Open(envelope, SecretKeyIDV1)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if opened != "a-webhook-signing-secret" {
		t.Fatalf("round trip mismatch: %q", opened)
	}

	// Unknown / unstamped key version fails closed — never decrypts under a
	// guessed key generation.
	if _, err := codec.Open(envelope, ""); err == nil {
		t.Error("opening under an unstamped key id must fail")
	}
	if _, err := codec.Open(envelope, "v999"); err == nil {
		t.Error("opening under an unknown key version must fail")
	}

	// A nil codec fails closed at every seam (no silent plaintext fallback).
	if _, err := (*SecretCodec)(nil).Seal("x"); err == nil {
		t.Error("nil codec Seal must fail")
	}
	if _, err := (*SecretCodec)(nil).Open(envelope, SecretKeyIDV1); err == nil {
		t.Error("nil codec Open must fail")
	}
	if got := (*SecretCodec)(nil).ActiveKeyID(); got != "" {
		t.Errorf("nil codec ActiveKeyID = %q, want empty", got)
	}
}

// ── DB-backed: at-rest form + compatibility leg ─────────────────────────────

// seedSecretFixture inserts one organization-scope subscription (no user row
// needed) and returns its id.
func seedSecretFixture(t *testing.T, pool *pgxpool.Pool, secret string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO webhook_subscriptions(url, secret, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES('https://secret-enc.test/hook', $1, '["mail.received"]', true, true, 3, 'organization')
		 RETURNING id`, secret,
	).Scan(&id); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, id)
	})
	return id
}

// seedRotatedLegacyFixture inserts one organization-scope subscription in the
// pre-V260 ROTATED shape: plaintext current secret AND plaintext
// rotation-grace prev_secret, no envelopes.
func seedRotatedLegacyFixture(t *testing.T, pool *pgxpool.Pool, secret, prev string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO webhook_subscriptions(url, secret, prev_secret, event_types, is_active, retry_enabled, max_retries, scope)
		 VALUES('https://secret-enc.test/hook', $1, $2, '["mail.received"]', true, true, 3, 'organization')
		 RETURNING id`, secret, prev,
	).Scan(&id); err != nil {
		t.Fatalf("seed rotated legacy subscription: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id=$1`, id)
	})
	return id
}

func TestLoadSubscriptionSecret_LegacyPlaintextRowDeliversAndMigratesToCiphertextOnly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	secret := "legacy-issued-webhook-signing-secret"
	id := seedSecretFixture(t, pool, secret)

	// Compatibility leg: the pre-V260 plaintext row still signs deliveries.
	got, err := LoadSubscriptionSecret(ctx, pool, codec, id)
	if err != nil {
		t.Fatalf("legacy plaintext row must still deliver: %v", err)
	}
	if got != secret {
		t.Fatalf("legacy secret = %q, want issued value", got)
	}

	// The delivery lazily migrated the row: it now stores ONLY the _enc
	// ciphertext — plaintext gone, envelope + key id present.
	var gotLegacy *string
	var gotEnvelope []byte
	var keyID *string
	if err := pool.QueryRow(ctx,
		`SELECT secret, secret_enc, secret_key_id FROM webhook_subscriptions WHERE id = $1`, id,
	).Scan(&gotLegacy, &gotEnvelope, &keyID); err != nil {
		t.Fatalf("load migrated row: %v", err)
	}
	if gotLegacy != nil {
		t.Fatal("migrated row must not retain the plaintext secret")
	}
	if gotEnvelope == nil {
		t.Fatal("migrated row must hold the sealed envelope")
	}
	if keyID == nil || *keyID != SecretKeyIDV1 {
		t.Fatalf("migrated row must be stamped with the active key id, got %v", keyID)
	}

	// The migrated key still signs (same seam, now ciphertext-only).
	got2, err := LoadSubscriptionSecret(ctx, pool, codec, id)
	if err != nil {
		t.Fatalf("ciphertext-only row must deliver: %v", err)
	}
	if got2 != secret {
		t.Fatalf("opened secret = %q, want issued value", got2)
	}
}

func TestLoadSubscriptionSecret_CiphertextOnlyRowOpens(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	secret := "ciphertext-native-webhook-signing-secret"
	id := seedSecretFixture(t, pool, secret)

	// Simulate a V260-native write (create-shaped): envelope + key id in,
	// plaintext never stored.
	envelope, err := codec.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_subscriptions SET secret = NULL, secret_enc = $2, secret_key_id = $3
		  WHERE id = $1`, id, envelope, codec.ActiveKeyID()); err != nil {
		t.Fatalf("shape ciphertext-only row: %v", err)
	}

	got, err := LoadSubscriptionSecret(ctx, pool, codec, id)
	if err != nil {
		t.Fatalf("LoadSubscriptionSecret on ciphertext-only row: %v", err)
	}
	if got != secret {
		t.Fatalf("opened secret = %q, want issued value", got)
	}
}

func TestLoadSubscriptionSecret_UnknownKeyVersionFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	id := seedSecretFixture(t, pool, "unknown-key-version-secret")

	envelope, err := codec.Seal("unknown-key-version-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_subscriptions SET secret = NULL, secret_enc = $2, secret_key_id = 'v-future'
		  WHERE id = $1`, id, envelope); err != nil {
		t.Fatalf("shape unknown-key row: %v", err)
	}

	if _, err := LoadSubscriptionSecret(ctx, pool, codec, id); err == nil {
		t.Fatal("an envelope stamped with an unavailable key version must fail closed")
	}
}

// TestLoadSubscriptionSecret_NilCodecFailsClosedOnLegacyRows pins Astra D6
// impl-r2 finding 3: the codec is REQUIRED at the read seam — a nil codec
// fails closed on a legacy plaintext row too (V247's device loader contract),
// instead of delivering on plaintext while encryption is unavailable.
func TestLoadSubscriptionSecret_NilCodecFailsClosedOnLegacyRows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	legacyID := seedSecretFixture(t, pool, "nil-codec-legacy-secret")

	if _, err := LoadSubscriptionSecret(context.Background(), pool, nil, legacyID); err == nil {
		t.Fatal("a nil codec must fail closed on a legacy plaintext row (no plaintext delivery leg)")
	}

	// The refusal must not have touched the row: no re-seal, no plaintext
	// drain — the next configured read sees exactly the legacy shape.
	var secret *string
	var envelope []byte
	var keyID *string
	if err := pool.QueryRow(context.Background(),
		`SELECT secret, secret_enc, secret_key_id FROM webhook_subscriptions WHERE id = $1`, legacyID,
	).Scan(&secret, &envelope, &keyID); err != nil {
		t.Fatal(err)
	}
	if secret == nil || envelope != nil || keyID != nil {
		t.Fatalf("nil-codec read must leave the legacy row untouched, got secret=%v env=%v key=%v",
			secret != nil, envelope != nil, keyID)
	}

	// An envelope row keeps failing closed without the process codec.
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	envID := seedSecretFixture(t, pool, "nil-codec-envelope-secret")
	envelopeBytes, err := codec.Seal("nil-codec-envelope-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE webhook_subscriptions SET secret = NULL, secret_enc = $2, secret_key_id = $3
		  WHERE id = $1`, envID, envelopeBytes, codec.ActiveKeyID()); err != nil {
		t.Fatalf("shape envelope row: %v", err)
	}
	if _, err := LoadSubscriptionSecret(context.Background(), pool, nil, envID); err == nil {
		t.Fatal("an envelope row must fail closed without a configured codec")
	}
}

// TestLoadSubscriptionSecret_RotatedLegacyRowMigratesBothSecrets pins Astra
// D6 impl-r2 finding 1: a legacy row that already rotated pre-V260 holds TWO
// plaintext values (secret + prev_secret). One load must drain BOTH in the
// same atomic UPDATE — the row ends ciphertext-only in all four cells with
// both envelopes openable to their original values.
func TestLoadSubscriptionSecret_RotatedLegacyRowMigratesBothSecrets(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	const secret = "rotated-legacy-current-signing-secret"
	const prev = "rotated-legacy-previous-signing-secret"
	id := seedRotatedLegacyFixture(t, pool, secret, prev)

	got, err := LoadSubscriptionSecret(ctx, pool, codec, id)
	if err != nil {
		t.Fatalf("rotated legacy row must still deliver: %v", err)
	}
	if got != secret {
		t.Fatalf("legacy secret = %q, want issued current value", got)
	}

	// Ciphertext-only in ALL FOUR cells after the single load.
	var legacy, prevLegacy *string
	var envelope, prevEnvelope []byte
	var keyID, prevKeyID *string
	if err := pool.QueryRow(ctx,
		`SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id
		   FROM webhook_subscriptions WHERE id = $1`, id,
	).Scan(&legacy, &prevLegacy, &envelope, &keyID, &prevEnvelope, &prevKeyID); err != nil {
		t.Fatal(err)
	}
	if legacy != nil || prevLegacy != nil {
		t.Fatalf("migrated rotated row must hold NO plaintext: secret=%v prev=%v", legacy != nil, prevLegacy != nil)
	}
	if envelope == nil || prevEnvelope == nil {
		t.Fatalf("migrated rotated row must hold both envelopes: secret_enc=%v prev_secret_enc=%v",
			envelope != nil, prevEnvelope != nil)
	}
	if keyID == nil || *keyID != SecretKeyIDV1 || prevKeyID == nil || *prevKeyID != SecretKeyIDV1 {
		t.Fatalf("both envelopes must be stamped with the active key id, got key=%v prevKey=%v", keyID, prevKeyID)
	}

	// Both envelopes open to their original values (the rotation-grace
	// previous secret stays recoverable in ciphertext form).
	opened, err := codec.Open(envelope, *keyID)
	if err != nil {
		t.Fatalf("open migrated secret envelope: %v", err)
	}
	if opened != secret {
		t.Fatalf("migrated secret = %q, want issued value", opened)
	}
	openedPrev, err := codec.Open(prevEnvelope, *prevKeyID)
	if err != nil {
		t.Fatalf("open migrated prev envelope: %v", err)
	}
	if openedPrev != prev {
		t.Fatalf("migrated prev_secret = %q, want issued value", openedPrev)
	}

	// A second load serves the same secret from the migrated envelope.
	got2, err := LoadSubscriptionSecret(ctx, pool, codec, id)
	if err != nil {
		t.Fatalf("ciphertext-only rotated row must deliver: %v", err)
	}
	if got2 != secret {
		t.Fatalf("opened secret = %q, want issued value", got2)
	}
}

// TestLoadSubscriptionSecret_PreexistingPrevEnvelopeIsKept pins the COALESCE
// guard of the lazy migration: a row that already stores a prev envelope must
// not have it replaced by a fresh seal — and a load on such a row still
// drains both plaintext cells without disturbing the stored prev pair's key
// id.
func TestLoadSubscriptionSecret_PreexistingPrevEnvelopeIsKept(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	codec := NewSecretCodec([]byte(codecTestMaster), cryptokey.ProfileStandard)
	const secret = "legacy-current-with-prev-envelope"
	const prev = "already-sealed-previous-secret"
	id := seedRotatedLegacyFixture(t, pool, secret, prev)

	prevEnvelope, err := codec.Seal(prev)
	if err != nil {
		t.Fatalf("seal prev: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE webhook_subscriptions SET prev_secret_enc = $2, prev_secret_key_id = $3
		  WHERE id = $1`, id, prevEnvelope, codec.ActiveKeyID()); err != nil {
		t.Fatalf("shape pre-existing prev envelope: %v", err)
	}

	if _, err := LoadSubscriptionSecret(ctx, pool, codec, id); err != nil {
		t.Fatalf("load: %v", err)
	}

	var legacy, prevLegacy *string
	var envelope, gotPrevEnvelope []byte
	var keyID, gotPrevKeyID *string
	if err := pool.QueryRow(ctx,
		`SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id
		   FROM webhook_subscriptions WHERE id = $1`, id,
	).Scan(&legacy, &prevLegacy, &envelope, &keyID, &gotPrevEnvelope, &gotPrevKeyID); err != nil {
		t.Fatal(err)
	}
	if legacy != nil || prevLegacy != nil {
		t.Fatal("both plaintext cells must be drained after the load")
	}
	if envelope == nil {
		t.Fatal("the current secret must have been sealed")
	}
	// The pre-existing prev envelope is byte-identical and still stamped.
	if string(gotPrevEnvelope) != string(prevEnvelope) {
		t.Fatal("an already-stored prev envelope must not be re-sealed")
	}
	if gotPrevKeyID == nil || *gotPrevKeyID != SecretKeyIDV1 {
		t.Fatalf("pre-existing prev key id must be kept, got %v", gotPrevKeyID)
	}
}
