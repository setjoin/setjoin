package pushjobs

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"

	"setjoin.com/shared/pgxutil"
	sharedpush "setjoin.com/shared/push"
	"setjoin.com/shared/testsupport"
)

// mailPushE2EGUCKey is a literal (not env-derived) pgcrypto key: fixture
// encrypt + worker decrypt both run through the SAME pool/GUC, so this proves
// the real push_devices decrypt seam (shared/push.ResolveDevices), not a
// hand-rolled substitute.
const mailPushE2EGUCKey = "mailpush-e2e-fixed-test-key-32ch"

// mailPushIDBase seeds a private id range (98900s) to avoid colliding with
// other integration tests.
const (
	mailPushDomainID  = 98900
	mailPushUserID    = 98901
	mailPushMailboxID = 98901
)

// pushCatcher is a fake Web Push endpoint that records the arriving requests
// and lets the test flip its response (200 vs 410) between deliveries.
type pushCatcher struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   [][]byte
	status   int
}

func newPushCatcher() *pushCatcher {
	return &pushCatcher{status: http.StatusCreated}
}

func (c *pushCatcher) handler(w http.ResponseWriter, r *http.Request) {
	// io.ReadAll, NOT a single r.Body.Read: one Read returns the first chunk
	// only, and the truncated RFC 8188 record then fails GCM authentication.
	body, _ := io.ReadAll(r.Body)

	c.mu.Lock()
	c.requests = append(c.requests, r.Clone(r.Context()))
	c.bodies = append(c.bodies, body)
	status := c.status
	c.mu.Unlock()

	w.WriteHeader(status)
}

func (c *pushCatcher) last() (*http.Request, []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.requests)
	if n == 0 {
		return nil, nil
	}
	return c.requests[n-1], c.bodies[n-1]
}

func (c *pushCatcher) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.requests)
}

func (c *pushCatcher) setStatus(status int) {
	c.mu.Lock()
	c.status = status
	c.mu.Unlock()
}

// seedMailPushFixtures creates a local domain + user + mailbox in the 98900
// range, registering cleanup, mirroring inbound_group_moderation_test.go's
// pattern.
func seedMailPushFixtures(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}

	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES ($1,'mailpush.test',TRUE) ON CONFLICT DO NOTHING`, mailPushDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1,'mailpush_u',$2,'u@mailpush.test','U',TRUE) ON CONFLICT DO NOTHING`, mailPushUserID, mailPushDomainID)
	exec(`INSERT INTO mailboxes (id, user_id, domain_id, email, display_name, type, is_primary) OVERRIDING SYSTEM VALUE VALUES
		($1,$2,$3,'u@mailpush.test','U','personal',TRUE) ON CONFLICT DO NOTHING`, mailPushMailboxID, mailPushUserID, mailPushDomainID)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM push_intents WHERE mailbox_id = $1`, mailPushMailboxID) //nolint:errcheck
		pool.Exec(c, `DELETE FROM push_devices WHERE user_id = $1`, mailPushUserID)       //nolint:errcheck
		pool.Exec(c, `DELETE FROM messages WHERE mailbox_id = $1`, mailPushMailboxID)     //nolint:errcheck
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mailPushMailboxID)            //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, mailPushUserID)                   //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, mailPushDomainID)               //nolint:errcheck
	})
}

// setMailPushToggle flips feature.mail_push, restoring it to OFF (its V107
// seed default) via t.Cleanup so the test is hermetic.
func setMailPushToggle(t *testing.T, pool *pgxpool.Pool, enabled bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.mail_push'`, enabled); err != nil {
		t.Fatalf("set feature.mail_push: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.mail_push'`) //nolint:errcheck
	})
}

// fakeWebPushSubscription generates a REAL P-256 ECDH keypair + 16-byte auth
// secret and returns the subscription JSON webpush-go's own Send path expects
// (uncompressed-point p256dh — encoding matters, see authserver's push tests)
// plus the private key/auth secret needed to decrypt the payload later.
func fakeWebPushSubscription(t *testing.T, endpoint string) (subJSON []byte, privKey []byte, authSecret []byte) {
	t.Helper()
	curve := elliptic.P256()
	priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate receiver ECDH keypair: %v", err)
	}
	pub := elliptic.Marshal(curve, x, y)

	authSecret = make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("generate auth secret: %v", err)
	}

	sub := webpush.Subscription{
		Endpoint: endpoint,
		Keys: webpush.Keys{
			P256dh: base64.RawURLEncoding.EncodeToString(pub),
			Auth:   base64.RawURLEncoding.EncodeToString(authSecret),
		},
	}
	b, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal subscription: %v", err)
	}
	return b, priv, authSecret
}

// insertPushDevice INSERTs a push_devices row exactly as
// authserver/internal/handlers/device.go's DeviceRegister does: the token
// encrypted via pgp_sym_encrypt with app.encryption_key.
func insertPushDevice(t *testing.T, pool *pgxpool.Pool, userID int64, subJSON []byte) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO push_devices (user_id, push_provider, push_token_enc, device_name)
		 VALUES ($1, 'webpush', pgp_sym_encrypt($2::TEXT, current_setting('app.encryption_key'))::BYTEA, 'e2e-test-device')`,
		userID, string(subJSON))
	if err != nil {
		t.Fatalf("insert push_devices: %v", err)
	}
}

// decryptAES128GCM reverses webpush-go's SendNotificationWithContext (RFC
// 8291) using the fake receiver's own private key, proving the payload the
// worker sent round-trips to the original JSON — the optional stretch proof.
func decryptAES128GCM(privKey, authSecret, body []byte) ([]byte, error) {
	if len(body) < 21 {
		return nil, fmt.Errorf("record too short: %d bytes", len(body))
	}
	curve := elliptic.P256()
	salt := body[:16]
	idlen := int(body[20])
	if len(body) < 21+idlen {
		return nil, fmt.Errorf("record header truncated")
	}
	senderPub := body[21 : 21+idlen]
	ciphertext := body[21+idlen:]

	sx, sy := elliptic.Unmarshal(curve, senderPub)
	if sx == nil {
		return nil, fmt.Errorf("sender public key not on curve")
	}
	shx, _ := curve.ScalarMult(sx, sy, privKey)
	mlen := curve.Params().BitSize / 8
	sharedECDHSecret := make([]byte, mlen)
	shx.FillBytes(sharedECDHSecret)

	hash := sha256.New

	// dh in webpush-go's HKDF info is the RECEIVER's own p256dh (senderPub here
	// is the ephemeral local key on the sender side, so from the receiver's
	// perspective "dh" is its own public key, "localPublicKey" is senderPub).
	rx, ry := curve.ScalarBaseMult(privKey)
	receiverPub := elliptic.Marshal(curve, rx, ry)

	prkInfo := append([]byte("WebPush: info\x00"), receiverPub...)
	prkInfo = append(prkInfo, senderPub...)
	prkHKDF := hkdf.New(hash, sharedECDHSecret, authSecret, prkInfo)
	ikm := make([]byte, 32)
	if _, err := prkHKDF.Read(ikm); err != nil {
		return nil, err
	}

	cekHKDF := hkdf.New(hash, ikm, salt, []byte("Content-Encoding: aes128gcm\x00"))
	cek := make([]byte, 16)
	if _, err := cekHKDF.Read(cek); err != nil {
		return nil, err
	}
	nonceHKDF := hkdf.New(hash, ikm, salt, []byte("Content-Encoding: nonce\x00"))
	nonce := make([]byte, 12)
	if _, err := nonceHKDF.Read(nonce); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	// Strip the padding delimiter (0x02) + trailing zero padding.
	if i := lastNonZero(plain); i >= 0 && plain[i] == 0x02 {
		return plain[:i], nil
	}
	return plain, nil
}

func lastNonZero(b []byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] != 0 {
			return i
		}
	}
	return -1
}

// TestMailPushE2E drives the full mail-push pipeline live, no vendor creds:
// deliver() (feature.mail_push ON) enqueues a push_intents row, the pushjobs
// worker claims it, resolves the fake webpush device, and dispatches a real
// RFC 8291 encrypted notification to an httptest catcher. A second sub-test
// proves the 410-prune path.
func TestMailPushE2E(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, mailPushE2EGUCKey)
	seedMailPushFixtures(t, pool)
	setMailPushToggle(t, pool, true)
	ctx := context.Background()

	vapidPriv, vapidPub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}
	_ = vapidPub

	catcher := newPushCatcher()
	server := httptest.NewServer(http.HandlerFunc(catcher.handler))
	defer server.Close()

	subJSON, recvPriv, recvAuth := fakeWebPushSubscription(t, server.URL)
	insertPushDevice(t, pool, mailPushUserID, subJSON)

	// deliver() a message to the seeded mailbox.
	var msgID int64
	err = pool.QueryRow(ctx, `SELECT deliver(
		p_raw_ref => 'raw/mailpush-e2e-1',
		p_message_id => '<mailpush-e2e-1@setjoin.test>',
		p_from_addr => 'sender@external.test',
		p_from_name => 'Sender',
		p_rcpt_addr => 'u@mailpush.test',
		p_to_addrs => '[]'::jsonb,
		p_cc_addrs => '[]'::jsonb,
		p_bcc_addrs => '[]'::jsonb,
		p_subject => 'Mail Push E2E',
		p_in_reply_to => NULL,
		p_references_hdr => NULL,
		p_body_text => 'hello',
		p_body_html => NULL,
		p_size_bytes => 100,
		p_has_attachments => FALSE,
		p_sent_at => now(),
		p_spf_result => 'pass',
		p_dkim_result => 'pass',
		p_dmarc_result => 'pass',
		p_spam_score => 0.0,
		p_spam_headers => '{}'::jsonb
	)`).Scan(&msgID)
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if msgID == 0 {
		t.Fatalf("deliver: expected a real message id, got 0")
	}

	var intentCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_intents WHERE mailbox_id = $1 AND message_id = $2`,
		mailPushMailboxID, msgID).Scan(&intentCount); err != nil {
		t.Fatalf("count push_intents: %v", err)
	}
	if intentCount != 1 {
		t.Fatalf("expected 1 push_intents row for the delivered message, got %d", intentCount)
	}

	set, statuses := sharedpush.Build(sharedpush.Config{
		VAPIDPrivateKey: vapidPriv,
		VAPIDSubject:    "mailto:test@setjoin.test",
		// TEST-ONLY seam: the E2E "push service" is a local httptest server on
		// loopback, which the production dial-time SSRF guard correctly refuses.
		WebPushHTTPClient: &http.Client{Timeout: 30 * time.Second},
	})
	for _, s := range statuses {
		if s.Kind == sharedpush.Webpush && s.State != sharedpush.Configured {
			t.Fatalf("webpush provider not configured: %+v", s)
		}
	}

	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, set, testsupport.TestLogger())

	claimed, err := worker.processOne(ctx)
	if err != nil {
		t.Fatalf("processOne: %v", err)
	}
	if !claimed {
		t.Fatalf("expected processOne to claim the seeded intent")
	}

	if got := catcher.count(); got != 1 {
		t.Fatalf("expected 1 request to the catcher, got %d", got)
	}
	req, body := catcher.last()
	if enc := req.Header.Get("Content-Encoding"); enc != "aes128gcm" {
		t.Errorf("Content-Encoding = %q, want aes128gcm", enc)
	}
	if ttl := req.Header.Get("TTL"); ttl != "60" {
		t.Errorf("TTL = %q, want 60", ttl)
	}
	auth := req.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "vapid ") {
		t.Errorf("Authorization = %q, want a vapid-prefixed JWT", auth)
	}
	// Topic is NOT set today — deliberately not asserted.

	plain, err := decryptAES128GCM(recvPriv, recvAuth, body)
	if err != nil {
		t.Fatalf("decrypt payload (RFC 8291 round-trip): %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("decrypted payload is not the rich mail-push JSON: %v (body: %q)", err, plain)
	}
	if payload["type"] != "mail" || payload["subject"] != "Mail Push E2E" {
		t.Errorf("decrypted payload mismatch: %+v", payload)
	}

	var intentStatus string
	if err := pool.QueryRow(ctx, `SELECT status FROM push_intents WHERE mailbox_id = $1 AND message_id = $2`,
		mailPushMailboxID, msgID).Scan(&intentStatus); err != nil {
		t.Fatalf("re-select intent status: %v", err)
	}
	if intentStatus != "done" {
		t.Errorf("intent status = %q, want done", intentStatus)
	}

	t.Run("410 prunes the device", func(t *testing.T) {
		// A second delivered message → a fresh intent for the same device.
		var msgID2 int64
		err := pool.QueryRow(ctx, `SELECT deliver(
			p_raw_ref => 'raw/mailpush-e2e-2',
			p_message_id => '<mailpush-e2e-2@setjoin.test>',
			p_from_addr => 'sender@external.test',
			p_from_name => 'Sender',
			p_rcpt_addr => 'u@mailpush.test',
			p_to_addrs => '[]'::jsonb,
			p_cc_addrs => '[]'::jsonb,
			p_bcc_addrs => '[]'::jsonb,
			p_subject => 'Mail Push E2E 2',
			p_in_reply_to => NULL,
			p_references_hdr => NULL,
			p_body_text => 'hello again',
			p_body_html => NULL,
			p_size_bytes => 100,
			p_has_attachments => FALSE,
			p_sent_at => now(),
			p_spf_result => 'pass',
			p_dkim_result => 'pass',
			p_dmarc_result => 'pass',
			p_spam_score => 0.0,
			p_spam_headers => '{}'::jsonb
		)`).Scan(&msgID2)
		if err != nil {
			t.Fatalf("deliver #2: %v", err)
		}

		catcher.setStatus(http.StatusGone) // 410

		claimed, err := worker.processOne(ctx)
		if err != nil {
			t.Fatalf("processOne (410 case): %v", err)
		}
		if !claimed {
			t.Fatalf("expected processOne to claim the second intent")
		}

		var revokedAt *time.Time
		if err := pool.QueryRow(ctx,
			`SELECT revoked_at FROM push_devices WHERE user_id = $1`, mailPushUserID,
		).Scan(&revokedAt); err != nil {
			t.Fatalf("select revoked_at: %v", err)
		}
		if revokedAt == nil {
			t.Fatalf("expected push_devices.revoked_at to be set after a 410, got NULL")
		}
	})
}
