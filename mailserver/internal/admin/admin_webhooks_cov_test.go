package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/testsupport"
	wh "setjoin.com/shared/webhook"
)

// authContextForWebhookUser attaches claims for an explicit webhook owner id.
func authContextForWebhookUser(userID int64) context.Context {
	return auth.ContextWithUser(context.Background(), &auth.Claims{UserID: userID})
}

// rotateTestWebhook calls the REAL RotateSecret handler for the subscription
// and returns the recorder.
func rotateTestWebhook(t *testing.T, h *WebhooksHandler, id, userID int64) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/webhooks/"+strconv.FormatInt(id, 10)+"/rotate", nil)
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	req = req.WithContext(authContextForWebhookUser(userID))
	rec := httptest.NewRecorder()
	h.RotateSecret(rec, req)
	return rec
}

// TestAdminWebhooksRotate_EnvelopeRowRoundTripsPrevSecret drives the primary
// rotation leg (D6/DBSCHEMA-005): a row created by the REAL Create handler
// holds (secret_enc, secret_key_id). Rotation must re-seal the previous secret
// into prev_secret_enc, install the new secret as an envelope, and end the row
// plaintext-free in all four secret cells.
func TestAdminWebhooksRotate_EnvelopeRowRoundTripsPrevSecret(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)
	webhookID := createTestWebhook(t, h, pool, userID, []string{"mail.received"})

	// Snapshot the create-time secret from the row's envelope so the rotation
	// can prove the previous value round-trips into the prev envelope.
	var origEnc []byte
	var origKeyID string
	if err := pool.QueryRow(t.Context(),
		`SELECT secret_enc, secret_key_id FROM webhook_subscriptions WHERE id = $1`,
		webhookID).Scan(&origEnc, &origKeyID); err != nil {
		t.Fatalf("read created row: %v", err)
	}
	originalSecret, err := testWebhookCodec().Open(origEnc, origKeyID)
	if err != nil {
		t.Fatalf("open created envelope: %v", err)
	}

	rec := rotateTestWebhook(t, h, webhookID, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("RotateSecret: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Secret == "" {
		t.Fatalf("decode rotate response: %v (body=%s)", err, rec.Body.String())
	}
	if resp.Secret == originalSecret {
		t.Fatal("rotate returned the previous secret; want a fresh value")
	}

	var legacy, prevLegacy *string
	var enc, prevEnc []byte
	var keyID, prevKeyID *string
	if err := pool.QueryRow(t.Context(),
		`SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id
		   FROM webhook_subscriptions WHERE id = $1`, webhookID,
	).Scan(&legacy, &prevLegacy, &enc, &keyID, &prevEnc, &prevKeyID); err != nil {
		t.Fatalf("read rotated row: %v", err)
	}
	if legacy != nil || prevLegacy != nil {
		t.Fatalf("rotated row still holds plaintext: secret=%v prev_secret=%v", legacy != nil, prevLegacy != nil)
	}
	if prevEnc == nil || prevKeyID == nil {
		t.Fatal("rotation did not install a prev envelope")
	}
	prevPlain, err := testWebhookCodec().Open(prevEnc, *prevKeyID)
	if err != nil {
		t.Fatalf("open prev envelope: %v", err)
	}
	if prevPlain != originalSecret {
		t.Fatal("prev envelope does not decrypt to the create-time secret")
	}
	if enc == nil || keyID == nil {
		t.Fatal("rotation did not install a new secret envelope")
	}
	newPlain, err := testWebhookCodec().Open(enc, *keyID)
	if err != nil {
		t.Fatalf("open new envelope: %v", err)
	}
	if newPlain != resp.Secret {
		t.Fatal("stored envelope does not match the secret returned to the caller")
	}
}

// TestAdminWebhooksRotate_LegacyPlaintextDrainsToPrevEnvelope pins the
// compatibility leg: a pre-migration row holding plaintext `secret` is
// re-sealed into prev_secret_enc and the plaintext cells are drained.
func TestAdminWebhooksRotate_LegacyPlaintextDrainsToPrevEnvelope(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, secret, event_types, scope)
		 VALUES ($1, 'https://legacy.invalid/hook', 'legacy-plaintext-value', '["mail.received"]', 'self')
		 RETURNING id`, userID).Scan(&id); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id = $1`, id) //nolint:errcheck
	})

	rec := rotateTestWebhook(t, h, id, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("RotateSecret legacy row: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	var legacy, prevLegacy *string
	var enc, prevEnc []byte
	var keyID, prevKeyID *string
	if err := pool.QueryRow(t.Context(),
		`SELECT secret, prev_secret, secret_enc, secret_key_id, prev_secret_enc, prev_secret_key_id
		   FROM webhook_subscriptions WHERE id = $1`, id,
	).Scan(&legacy, &prevLegacy, &enc, &keyID, &prevEnc, &prevKeyID); err != nil {
		t.Fatalf("read rotated legacy row: %v", err)
	}
	if legacy != nil || prevLegacy != nil {
		t.Fatal("legacy rotation left plaintext in the secret cells")
	}
	if prevEnc == nil {
		t.Fatal("legacy rotation did not seal the issued value into prev_secret_enc")
	}
	prevPlain, err := testWebhookCodec().Open(prevEnc, *prevKeyID)
	if err != nil {
		t.Fatalf("open legacy prev envelope: %v", err)
	}
	if prevPlain != "legacy-plaintext-value" {
		t.Fatalf("prev envelope holds %q, want the drained legacy plaintext", prevPlain)
	}
	if enc == nil {
		t.Fatal("legacy rotation did not install the new secret envelope")
	}
}

// TestAdminWebhooksRotate_MalformedRowRecoversWithEmptyPrev pins the default
// leg: a row with NO previous secret in either form still rotates (rotation is
// the recovery path) and installs the new secret with an empty prev.
func TestAdminWebhooksRotate_MalformedRowRecoversWithEmptyPrev(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, event_types, scope)
		 VALUES ($1, 'https://malformed.invalid/hook', '["mail.received"]', 'self')
		 RETURNING id`, userID).Scan(&id); err != nil {
		t.Fatalf("seed malformed row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id = $1`, id) //nolint:errcheck
	})

	rec := rotateTestWebhook(t, h, id, userID)
	if rec.Code != http.StatusOK {
		t.Fatalf("RotateSecret malformed row: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Secret == "" {
		t.Fatalf("decode rotate response: %v (body=%s)", err, rec.Body.String())
	}

	var enc, prevEnc []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT secret_enc, prev_secret_enc FROM webhook_subscriptions WHERE id = $1`, id,
	).Scan(&enc, &prevEnc); err != nil {
		t.Fatalf("read rotated malformed row: %v", err)
	}
	if prevEnc != nil {
		t.Fatal("malformed-row rotation must not invent a prev envelope")
	}
	if enc == nil {
		t.Fatal("malformed-row rotation did not install the new secret envelope")
	}
	plain, err := testWebhookCodec().Open(enc, wh.SecretKeyIDV1)
	if err != nil {
		t.Fatalf("open new envelope: %v", err)
	}
	if plain != resp.Secret {
		t.Fatal("stored envelope does not match the returned secret")
	}
}

// TestAdminWebhooksRotate_UnknownSubscriptionFailsClosed pins the 404 leg: an
// unknown id (or another user's subscription) never rotates.
func TestAdminWebhooksRotate_UnknownSubscriptionFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	rec := rotateTestWebhook(t, h, 987654321, userID)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("RotateSecret unknown id: want 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// TestAdminWebhooksRotate_UnstampedEnvelopeFailsClosed pins the envelope
// integrity guard: ciphertext with no stamped key id cannot be attributed to a
// key generation, so rotation refuses instead of dropping an undecryptable
// secret — and the row is left untouched (transaction rolled back).
func TestAdminWebhooksRotate_UnstampedEnvelopeFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, secret_enc, event_types, scope)
		 VALUES ($1, 'https://unstamped.invalid/hook', '\x00deadbeef'::bytea, '["mail.received"]', 'self')
		 RETURNING id`, userID).Scan(&id); err != nil {
		t.Fatalf("seed unstamped row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id = $1`, id) //nolint:errcheck
	})

	rec := rotateTestWebhook(t, h, id, userID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("RotateSecret unstamped envelope: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "stored secret has no key id") {
		t.Fatalf("unstamped envelope: unexpected body %s", rec.Body.String())
	}
	// Rollback check: the row must be byte-identical (ciphertext unchanged).
	var enc []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT secret_enc FROM webhook_subscriptions WHERE id = $1`, id).Scan(&enc); err != nil {
		t.Fatalf("read row after refused rotation: %v", err)
	}
	if !bytes.Equal(enc, []byte{0x00, 0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("refused rotation mutated the stored envelope: %x", enc)
	}
}

// TestAdminWebhooksRotate_UnknownKeyVersionFailsClosed pins the unknown key
// version guard: an envelope stamped with a key version this process does not
// hold fails the rotation closed — never a silently dropped secret.
func TestAdminWebhooksRotate_UnknownKeyVersionFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), testWebhookCodec())
	userID := seedUser(t, pool)

	var id int64
	if err := pool.QueryRow(t.Context(),
		`INSERT INTO webhook_subscriptions (user_id, url, secret_enc, secret_key_id, event_types, scope)
		 VALUES ($1, 'https://oldkey.invalid/hook', '\x00deadbeef'::bytea, 'v0-unknown', '["mail.received"]', 'self')
		 RETURNING id`, userID).Scan(&id); err != nil {
		t.Fatalf("seed unknown-key row: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM webhook_subscriptions WHERE id = $1`, id) //nolint:errcheck
	})

	rec := rotateTestWebhook(t, h, id, userID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("RotateSecret unknown key version: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "previous secret cannot be opened") {
		t.Fatalf("unknown key version: unexpected body %s", rec.Body.String())
	}
	var enc []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT secret_enc FROM webhook_subscriptions WHERE id = $1`, id).Scan(&enc); err != nil {
		t.Fatalf("read row after refused rotation: %v", err)
	}
	if !bytes.Equal(enc, []byte{0x00, 0xde, 0xad, 0xbe, 0xef}) {
		t.Fatalf("refused rotation mutated the stored envelope: %x", enc)
	}
}

// TestAdminWebhooksCreate_NilCodecFailsClosed pins the fail-closed contract:
// a handler wired without a secret codec never persists a subscription —
// plaintext-at-rest is worse than a failed create.
func TestAdminWebhooksCreate_NilCodecFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewWebhooksHandler(pool, testsupport.TestLogger(), wh.NewSecretCodec(nil, cryptokey.ProfileStandard))
	userID := seedUser(t, pool)

	body, _ := json.Marshal(map[string]any{
		"url":        "https://example.invalid/hook",
		"eventTypes": []string{"mail.received"},
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/webhooks", bytes.NewReader(body))
	req = req.WithContext(authContextForWebhookUser(userID))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("Create without codec: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret sealing failed") {
		t.Fatalf("Create without codec: unexpected body %s", rec.Body.String())
	}
	var stored int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM webhook_subscriptions WHERE user_id = $1`, userID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 0 {
		t.Fatalf("failed create persisted %d subscriptions", stored)
	}
}

// TestAdminWebhooksRotate_NilCodecFailsClosed pins the rotate-side fail-closed
// contract: both values are sealed BEFORE the row is touched, so a broken
// codec cannot leave a half-rotated subscription.
func TestAdminWebhooksRotate_NilCodecFailsClosed(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	codec := testWebhookCodec()
	good := NewWebhooksHandler(pool, testsupport.TestLogger(), codec)
	userID := seedUser(t, pool)
	webhookID := createTestWebhook(t, good, pool, userID, []string{"mail.received"})

	broken := NewWebhooksHandler(pool, testsupport.TestLogger(), wh.NewSecretCodec(nil, cryptokey.ProfileStandard))
	rec := rotateTestWebhook(t, broken, webhookID, userID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("RotateSecret without codec: want 500, got %d (%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "secret sealing failed") {
		t.Fatalf("RotateSecret without codec: unexpected body %s", rec.Body.String())
	}
	// The original envelope must be untouched.
	var enc []byte
	if err := pool.QueryRow(t.Context(),
		`SELECT secret_enc FROM webhook_subscriptions WHERE id = $1`, webhookID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc == nil {
		t.Fatal("failed rotation cleared the stored envelope")
	}
}
