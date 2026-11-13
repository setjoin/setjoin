package authn

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// pushGUCGuardKey is a literal (not GUC-derived) pgcrypto key used to produce
// the encrypted bytes independent of any pool's app.encryption_key setting —
// so the seed step never depends on the very GUC these tests are attacking.
const pushGUCGuardKey = "push-guc-guard-fixed-key-32char"

// encryptPushGUCGuardToken runs pgp_sym_encrypt via the literal two-arg form
// (no GUC involved) to produce the encrypted bytes push_devices.push_token_enc
// stores, without needing a seeded row at all — push.go's decrypt call sites
// (dispatchNativePush, sendWebPush, sendWebPushPayload, dispatchSecurityNative)
// take the encrypted bytes as a bound parameter, they don't read the column
// inline, so this is a faithful fixture-free proxy of the real data shape.
func encryptPushGUCGuardToken(t *testing.T, pool *pgxpool.Pool, plaintext string) []byte {
	t.Helper()
	var tokenEnc []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT pgp_sym_encrypt($1, $2)`, plaintext, pushGUCGuardKey,
	).Scan(&tokenEnc); err != nil {
		t.Fatalf("seed guc-guard push token ciphertext: %v", err)
	}
	return tokenEnc
}

// decryptPushGUCGuardToken runs the EXACT decrypt expression every push.go
// call site uses (dispatchNativePush, sendWebPush, sendWebPushPayload,
// dispatchSecurityNative all share this identical query string) against
// tokenEnc.
func decryptPushGUCGuardToken(ctx context.Context, pool *pgxpool.Pool, tokenEnc []byte) (string, error) {
	var decrypted string
	err := pool.QueryRow(ctx,
		`SELECT pgp_sym_decrypt($1::BYTEA, current_setting('app.encryption_key'))::TEXT`, tokenEnc,
	).Scan(&decrypted)
	return decrypted, err
}

// TestPushTokenDecrypt_DBRoundTrip proves that with the GUC set correctly, the
// push_token_enc family's decrypt expression round-trips to the original
// token — the (a) case of the per-family (a)/(b)/(c) proof.
func TestPushTokenDecrypt_DBRoundTrip(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, pushGUCGuardKey)
	const want = "fake-device-push-token-abc123"
	tokenEnc := encryptPushGUCGuardToken(t, pool, want)

	got, err := decryptPushGUCGuardToken(context.Background(), pool, tokenEnc)
	if err != nil {
		t.Fatalf("decrypt with correct GUC must succeed: %v", err)
	}
	if got != want {
		t.Errorf("round-trip mismatch: got %q, want %q", got, want)
	}
}

// TestPushTokenDecrypt_GUCMissing_FailsClosed proves the push_token_enc family
// fails closed — an error, never a NULL/plaintext "success" — when the
// AfterConnect hook that sets app.encryption_key is absent (a misconfigured or
// bypassed pool). Every push.go decrypt call site shares this exact query.
func TestPushTokenDecrypt_GUCMissing_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, pushGUCGuardKey)
	tokenEnc := encryptPushGUCGuardToken(t, seedPool, "fake-device-push-token-abc123")

	noGUCPool := testsupport.OpenTestPoolWithGUC(t, "") // GUC never set
	decrypted, err := decryptPushGUCGuardToken(context.Background(), noGUCPool, tokenEnc)
	if err == nil {
		t.Fatalf("decrypt must error when app.encryption_key GUC is unset, not silently succeed (got %q)", decrypted)
	}
}

// TestPushTokenDecrypt_WrongGUC_FailsClosed proves the same family fails
// loudly (an error, not a garbage-token false success) when
// app.encryption_key is set to the WRONG value.
func TestPushTokenDecrypt_WrongGUC_FailsClosed(t *testing.T) {
	seedPool := testsupport.OpenTestPoolWithGUC(t, pushGUCGuardKey)
	tokenEnc := encryptPushGUCGuardToken(t, seedPool, "fake-device-push-token-abc123")

	wrongPool := testsupport.OpenTestPoolWithGUC(t, "definitely-the-wrong-push-key-x")
	decrypted, err := decryptPushGUCGuardToken(context.Background(), wrongPool, tokenEnc)
	if err == nil {
		t.Fatalf("decrypt must error when app.encryption_key GUC is wrong, not silently succeed (got %q)", decrypted)
	}
}
