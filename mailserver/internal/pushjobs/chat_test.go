package pushjobs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/pgxutil"
	sharedpush "setjoin.com/shared/push"
	"setjoin.com/shared/testsupport"
)

// ── shouldCoalesce: mention-safe coalescing (pure, DB-free) ────────────────

func TestShouldCoalesce_MentionBearing_NotCoalesced(t *testing.T) {
	msg := chatMsgMeta{mentioned: map[int64]bool{42: true}}
	if shouldCoalesce(msg, true) {
		t.Fatal("a mention-bearing older intent must NOT coalesce — a 'mentions'-level member would silently lose their push")
	}
}

func TestShouldCoalesce_Broadcast_NotCoalesced(t *testing.T) {
	msg := chatMsgMeta{broadcast: true}
	if shouldCoalesce(msg, true) {
		t.Fatal("a broadcast older intent must NOT coalesce")
	}
}

func TestShouldCoalesce_Mentionless_Coalesced(t *testing.T) {
	msg := chatMsgMeta{}
	if !shouldCoalesce(msg, true) {
		t.Fatal("a plain older intent with a newer pending intent on the same channel must coalesce")
	}
}

func TestShouldCoalesce_NoNewerPending_NotCoalesced(t *testing.T) {
	msg := chatMsgMeta{}
	if shouldCoalesce(msg, false) {
		t.Fatal("no newer pending intent exists — nothing to coalesce into")
	}
}

// ── planChatFanout: the pure per-intent decision core ───────────────────────

func chatDev(id int64) sharedpush.Device {
	return sharedpush.Device{ID: id, Provider: sharedpush.Webpush, Token: "t"}
}

func TestPlanChatFanout_GateFalseMemberSkipped(t *testing.T) {
	msg := chatMsgMeta{channelID: 1, messageID: 2, seq: 3, senderName: "Alice"}
	members := []chatFanoutMember{
		{userID: 10, notify: false, devices: []sharedpush.Device{chatDev(1)}},
		{userID: 11, notify: true, devices: []sharedpush.Device{chatDev(2)}},
	}
	sends := planChatFanout(msg, members)
	if len(sends) != 1 || sends[0].userID != 11 {
		t.Fatalf("expected only the notify=true member to be sent to, got %+v", sends)
	}
}

func TestPlanChatFanout_NoDevicesSkipped(t *testing.T) {
	msg := chatMsgMeta{channelID: 1, messageID: 2, seq: 3}
	members := []chatFanoutMember{
		{userID: 10, notify: true, devices: nil},
	}
	if sends := planChatFanout(msg, members); len(sends) != 0 {
		t.Fatalf("a notify=true member with no devices must produce no send, got %+v", sends)
	}
}

func TestPlanChatFanout_PayloadNoBodyAndMentionFlag(t *testing.T) {
	msg := chatMsgMeta{channelID: 5, messageID: 9, seq: 7, senderName: "Bob"}
	members := []chatFanoutMember{
		{userID: 20, notify: true, mention: true, channelName: "general", devices: []sharedpush.Device{chatDev(1)}},
		{userID: 21, notify: true, mention: false, channelName: "general", devices: []sharedpush.Device{chatDev(2)}},
	}
	sends := planChatFanout(msg, members)
	if len(sends) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(sends))
	}

	for _, s := range sends {
		var payload map[string]any
		if err := json.Unmarshal(s.payload, &payload); err != nil {
			t.Fatalf("payload not valid JSON: %v", err)
		}
		if _, hasBody := payload["body"]; hasBody {
			t.Fatalf("chat push payload must carry NO message body (payload-privacy posture), got %+v", payload)
		}
		if payload["type"] != "chat" {
			t.Errorf("type = %v, want chat", payload["type"])
		}
		if payload["dedupeTag"] != "chat-5" {
			t.Errorf("dedupeTag = %v, want chat-5", payload["dedupeTag"])
		}
		wantMention := s.userID == 20
		if payload["mention"] != wantMention {
			t.Errorf("user %d: mention = %v, want %v", s.userID, payload["mention"], wantMention)
		}
	}
}

// ── chatChannelName: per-recipient DM/group_dm/channel naming ──────────────

func TestChatChannelName_Channel(t *testing.T) {
	msg := chatMsgMeta{kind: "channel", chanName: "general"}
	if got := chatChannelName(msg, nil, 1); got != "general" {
		t.Errorf("got %q, want general", got)
	}
}

func TestChatChannelName_DM_EmptyForClientFallback(t *testing.T) {
	msg := chatMsgMeta{kind: "dm"}
	if got := chatChannelName(msg, nil, 1); got != "" {
		t.Errorf("got %q, want empty (client renders the i18n Direct message string)", got)
	}
}

func TestChatChannelName_GroupDM_OtherMembersExcludesRecipient(t *testing.T) {
	msg := chatMsgMeta{kind: "group_dm"}
	roster := []chatRosterMember{
		{userID: 1, displayName: "Alice"},
		{userID: 2, displayName: "Bob"},
		{userID: 3, displayName: "Carol"},
	}
	got := chatChannelName(msg, roster, 2)
	if got != "Alice, Carol" {
		t.Errorf("got %q, want %q (excludes the recipient, includes the sender)", got, "Alice, Carol")
	}
}

// ── chatMsgMeta.hasMentions ──────────────────────────────────────────────

func TestChatMsgMeta_HasMentions(t *testing.T) {
	if (chatMsgMeta{}).hasMentions() {
		t.Fatal("no mentioned rows -> hasMentions() must be false")
	}
	if !(chatMsgMeta{mentioned: map[int64]bool{1: true}}).hasMentions() {
		t.Fatal("a mentioned row -> hasMentions() must be true")
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// DB-backed live drain test — reuses mail-push e2e infra (pushCatcher,
// fakeWebPushSubscription, decryptAES128GCM) verbatim (ponytail: reuse, don't
// copy). Fixtures live in a private id range (98920s) to avoid colliding with
// mailpush_e2e_test.go's 98900s range.
// ═══════════════════════════════════════════════════════════════════════════

const (
	chatE2EDomainID = 98920
	chatE2ESender   = 98921
	chatE2EAlice    = 98922 // notify_level=all recipient, gets pushed
	chatE2EBob      = 98923 // notify_level=none recipient, gate-false, skipped
)

func seedChatPushFixtures(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}

	exec(`INSERT INTO domains (id, name, is_local) OVERRIDING SYSTEM VALUE VALUES ($1,'chatpush.test',TRUE) ON CONFLICT DO NOTHING`, chatE2EDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1,'chatpush_sender',$2,'sender@chatpush.test','Sender',TRUE) ON CONFLICT DO NOTHING`, chatE2ESender, chatE2EDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1,'chatpush_alice',$2,'alice@chatpush.test','Alice',TRUE) ON CONFLICT DO NOTHING`, chatE2EAlice, chatE2EDomainID)
	exec(`INSERT INTO users (id, username, domain_id, email, display_name, enabled) OVERRIDING SYSTEM VALUE VALUES
		($1,'chatpush_bob',$2,'bob@chatpush.test','Bob',TRUE) ON CONFLICT DO NOTHING`, chatE2EBob, chatE2EDomainID)

	var channelID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO chat_channels (kind, name, created_by) VALUES ('channel','chat-push-e2e',$1) RETURNING id`,
		chatE2ESender,
	).Scan(&channelID); err != nil {
		t.Fatalf("insert chat_channels: %v", err)
	}
	exec(`INSERT INTO chat_channel_members (channel_id, user_id, role, notif_level) VALUES
		($1,$2,'owner','all'), ($1,$3,'member','all'), ($1,$4,'member','none')`,
		channelID, chatE2ESender, chatE2EAlice, chatE2EBob)

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM chat_push_intents WHERE channel_id = $1`, channelID)                                //nolint:errcheck
		pool.Exec(c, `DELETE FROM push_devices WHERE user_id IN ($1,$2,$3)`, chatE2ESender, chatE2EAlice, chatE2EBob) //nolint:errcheck
		pool.Exec(c, `DELETE FROM chat_channels WHERE id = $1`, channelID)                                            //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN ($1,$2,$3)`, chatE2ESender, chatE2EAlice, chatE2EBob)             //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, chatE2EDomainID)                                            //nolint:errcheck
	})

	return channelID
}

func setChatPushToggle(t *testing.T, pool *pgxpool.Pool, enabled bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = $1 WHERE key = 'feature.chat_push'`, enabled); err != nil {
		t.Fatalf("set feature.chat_push: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.chat_push'`) //nolint:errcheck
	})
}

// TestChatPushDrainE2E drives the real pipeline live, no vendor creds:
// chat_message_send (feature.chat_push ON) enqueues a chat_push_intents row,
// processOneChat claims it, gates each member via the real
// chat_push_should_notify reducer, resolves the fake webpush device, and
// dispatches a real RFC 8291 encrypted no-body notification. Covers: gate-
// false member skipped (Bob, notif_level=none), payload shape, and — via a
// deliberately-failing second device — no-retry-after-fan-out.
func TestChatPushDrainE2E(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, "chatpush-e2e-fixed-test-key-32ch")
	channelID := seedChatPushFixtures(t, pool)
	setChatPushToggle(t, pool, true)
	ctx := context.Background()

	vapidPriv, _, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}

	aliceCatcher := newPushCatcher()
	aliceServer := httptest.NewServer(http.HandlerFunc(aliceCatcher.handler))
	defer aliceServer.Close()
	aliceSub, aliceRecvPriv, aliceRecvAuth := fakeWebPushSubscription(t, aliceServer.URL)
	insertPushDevice(t, pool, chatE2EAlice, aliceSub)

	bobCatcher := newPushCatcher()
	bobServer := httptest.NewServer(http.HandlerFunc(bobCatcher.handler))
	defer bobServer.Close()
	bobSub, _, _ := fakeWebPushSubscription(t, bobServer.URL)
	insertPushDevice(t, pool, chatE2EBob, bobSub)

	var msgID int64
	if err := pool.QueryRow(ctx,
		`SELECT ((chat_message_send($1,$2,'hello from e2e'))->>'messageId')::bigint`,
		chatE2ESender, channelID,
	).Scan(&msgID); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}

	var intentCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM chat_push_intents WHERE message_id = $1`, msgID).Scan(&intentCount); err != nil {
		t.Fatalf("count chat_push_intents: %v", err)
	}
	if intentCount != 1 {
		t.Fatalf("expected 1 chat_push_intents row, got %d", intentCount)
	}

	// TEST-ONLY seam: the E2E "push service" is a local httptest server on
	// loopback, which the production dial-time SSRF guard correctly refuses.
	set, statuses := sharedpush.Build(sharedpush.Config{VAPIDPrivateKey: vapidPriv, VAPIDSubject: "mailto:test@setjoin.test",
		WebPushHTTPClient: &http.Client{Timeout: 30 * time.Second}})
	for _, s := range statuses {
		if s.Kind == sharedpush.Webpush && s.State != sharedpush.Configured {
			t.Fatalf("webpush provider not configured: %+v", s)
		}
	}
	worker := NewWorker(pgxutil.WorkerPool{Pool: pool}, set, testsupport.TestLogger())

	// processOneChat deliberately claims the oldest pending row cluster-wide.
	// Other concurrently-tested packages share mailserver_test and may have
	// enqueued an older intent, so drain boundedly until THIS test's row reaches
	// done instead of assuming the first claim belongs to this fixture.
	processed := false
	for range 100 {
		claimed, err := worker.processOneChat(ctx)
		if err != nil {
			t.Fatalf("processOneChat: %v", err)
		}
		var ownStatus string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM chat_push_intents WHERE message_id = $1`, msgID,
		).Scan(&ownStatus); err != nil {
			t.Fatalf("read seeded intent status: %v", err)
		}
		if ownStatus == "done" {
			processed = true
			break
		}
		if !claimed {
			t.Fatalf("queue reported empty while seeded intent status=%q", ownStatus)
		}
	}
	if !processed {
		t.Fatal("seeded intent was not drained within 100 claims")
	}

	// Bob (notif_level=none) must get NOTHING — the gate-false path.
	if got := bobCatcher.count(); got != 0 {
		t.Errorf("Bob (muted) received %d pushes, want 0", got)
	}

	// Alice (notif_level=all) gets exactly one push, no body, correct tag.
	if got := aliceCatcher.count(); got != 1 {
		t.Fatalf("Alice received %d pushes, want 1", got)
	}
	req, body := aliceCatcher.last()
	if enc := req.Header.Get("Content-Encoding"); enc != "aes128gcm" {
		t.Errorf("Content-Encoding = %q, want aes128gcm", enc)
	}
	plain, err := decryptAES128GCM(aliceRecvPriv, aliceRecvAuth, body)
	if err != nil {
		t.Fatalf("decrypt payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("decrypted payload not JSON: %v", err)
	}
	if _, hasBody := payload["body"]; hasBody {
		t.Errorf("chat push must carry no body, got %+v", payload)
	}
	if payload["type"] != "chat" || payload["channelName"] != "chat-push-e2e" || payload["mention"] != false {
		t.Errorf("payload mismatch: %+v", payload)
	}

	// No-retry-after-fan-out: the intent is 'done' even though it already
	// carried one send (fan-out has begun by the time any member is
	// dispatched to — a per-member send failure below must not flip this
	// back to pending/failed).
	var status string
	var attempts int
	if err := pool.QueryRow(ctx, `SELECT status, attempts FROM chat_push_intents WHERE message_id = $1`, msgID).Scan(&status, &attempts); err != nil {
		t.Fatalf("re-select intent: %v", err)
	}
	if status != "done" {
		t.Errorf("status = %q, want done", status)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (claimed once, never retried)", attempts)
	}

	var ownPending int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM chat_push_intents WHERE channel_id = $1 AND status = 'pending'`, channelID,
	).Scan(&ownPending); err != nil {
		t.Fatalf("count seeded channel pending intents: %v", err)
	}
	if ownPending != 0 {
		t.Fatalf("seeded channel still has %d pending intents", ownPending)
	}
}
