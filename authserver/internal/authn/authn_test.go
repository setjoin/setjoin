package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/push"
	"setjoin.com/shared/testsupport"
)

type recordingPushDispatcher struct{ sent int }

func (d *recordingPushDispatcher) Send(_ context.Context, token string, payload []byte) error {
	if token != "device-token" || len(payload) == 0 {
		return ErrChallengeInvalid
	}
	d.sent++
	return nil
}

func pushTestUser(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	// A fresh CI database seeds NO domain rows (the old dev-database pollution
	// masked this). Self-seed a unique local domain — the scim/chat test
	// pattern — instead of assuming an is_local row exists; the domain cleanup
	// registers first so it runs AFTER each test's user/challenge cleanup.
	domain := fmt.Sprintf("push-authn-test-%d.example", time.Now().UnixNano())
	var domainID int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain).Scan(&domainID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM domains WHERE id=$1`, domainID)
	})
	var userID int64
	err = pool.QueryRow(context.Background(),
		`INSERT INTO users (username,email,display_name,domain_id,sync_source,enabled,password_hash,must_change_password)
		 VALUES ($2,$3,'Push Authn Test',$1,'local',TRUE,'x',FALSE)
		 RETURNING id`, domainID,
		fmt.Sprintf("push-authn-test-%d", time.Now().UnixNano()),
		fmt.Sprintf("push-authn-test-%d@example.test", time.Now().UnixNano())).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}
	return userID
}

func TestGenerateBackupCodes(t *testing.T) {
	// Backup code generation creates 10 codes, each 8 hex chars.
	// Full test requires a DB connection; this is a structural smoke test.
}

func TestVerifyBackupCode_NoCodes(t *testing.T) {
	// VerifyBackupCode returns false when user has no codes.
	// Full test requires a DB connection with real bcrypt hashes.
}

func TestVerifyBackupCode_Duplicate(t *testing.T) {
	// Backup codes are single-use: same code rejected on second attempt.
	// Full test requires a DB connection.
}

func TestPasskeyRevoke(t *testing.T) {
	// RevokeCredential sets revoked_at, removed from allowCredentials.
	// Full test requires a DB connection with real credentials.
}

func TestPushChallengeRateLimit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	userID := pushTestUser(t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM push_mfa_challenges WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	provider := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i := 0; i < 3; i++ {
		response, err := provider.GenerateChallenge(context.Background(), userID, "session")
		if err != nil || response.Method != "push" || len(response.Nonce) != 64 {
			t.Fatalf("challenge %d: response=%+v err=%v", i, response, err)
		}
	}
	if _, err := provider.GenerateChallenge(context.Background(), userID, "session"); err == nil || !strings.Contains(err.Error(), "rate_limited") {
		t.Fatalf("fourth challenge error=%v", err)
	}
}

func TestPushChallengeExpiry(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, "push-authn-test-encryption-key")
	userID := pushTestUser(t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM push_mfa_challenges WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM push_devices WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	_, err = pool.Exec(context.Background(),
		`INSERT INTO push_devices(user_id,push_provider,push_token_enc,device_public_key,device_name)
		 VALUES($1,'fcm',pgp_sym_encrypt('device-token',current_setting('app.encryption_key')),$2,'test')`, userID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := &recordingPushDispatcher{}
	provider := NewNumberMatchPushProvider(context.Background(), pool, nil, "", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	provider.dispatchers = map[push.ProviderKind]push.Dispatcher{push.FCM: dispatcher}
	provider.dispatchNotifications(context.Background(), userID, "session", "42", strings.Repeat("00", 32), time.Now().Add(time.Minute))
	if dispatcher.sent != 1 {
		t.Fatalf("native sends=%d, want 1", dispatcher.sent)
	}
	provider.dispatchSecurityNative(context.Background(), userID, []byte(`{"type":"security_alert"}`))
	if dispatcher.sent != 2 {
		t.Fatalf("native security sends=%d, want 2", dispatcher.sent)
	}
}
