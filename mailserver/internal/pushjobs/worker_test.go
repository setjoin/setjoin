package pushjobs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/pgxutil"
	sharedpush "setjoin.com/shared/push"
	"setjoin.com/shared/testsupport"
)

// fakeDispatcher returns a canned error (or nil) and records calls.
type fakeDispatcher struct {
	err   error
	calls int
}

func (f *fakeDispatcher) Send(ctx context.Context, token string, payload []byte) error {
	f.calls++
	return f.err
}

func getter(m map[sharedpush.ProviderKind]sharedpush.Dispatcher) func(sharedpush.ProviderKind) (sharedpush.Dispatcher, bool) {
	return func(k sharedpush.ProviderKind) (sharedpush.Dispatcher, bool) {
		d, ok := m[k]
		return d, ok
	}
}

func dev(id int64, k sharedpush.ProviderKind) sharedpush.Device {
	return sharedpush.Device{ID: id, Provider: k, Token: "t"}
}

func TestEvalSends_Success(t *testing.T) {
	ok := &fakeDispatcher{err: nil}
	out := evalSends(context.Background(),
		getter(map[sharedpush.ProviderKind]sharedpush.Dispatcher{sharedpush.APNs: ok}),
		[]sharedpush.Device{dev(1, sharedpush.APNs)}, []byte("{}"))
	if !out.anySuccess || out.retryable || len(out.pruneIDs) != 0 {
		t.Fatalf("expected clean success, got %+v", out)
	}
}

func TestEvalSends_UnregisteredPrunes(t *testing.T) {
	dead := &fakeDispatcher{err: fmt.Errorf("gone: %w", sharedpush.ErrUnregistered)}
	out := evalSends(context.Background(),
		getter(map[sharedpush.ProviderKind]sharedpush.Dispatcher{sharedpush.FCM: dead}),
		[]sharedpush.Device{dev(7, sharedpush.FCM)}, []byte("{}"))
	if out.anySuccess || out.retryable {
		t.Fatalf("unregistered must not be success/retryable, got %+v", out)
	}
	if len(out.pruneIDs) != 1 || out.pruneIDs[0] != 7 {
		t.Fatalf("expected device 7 pruned, got %+v", out.pruneIDs)
	}
}

func TestEvalSends_RetryableError(t *testing.T) {
	boom := &fakeDispatcher{err: errors.New("503 upstream")}
	out := evalSends(context.Background(),
		getter(map[sharedpush.ProviderKind]sharedpush.Dispatcher{sharedpush.HMS: boom}),
		[]sharedpush.Device{dev(3, sharedpush.HMS)}, []byte("{}"))
	if out.anySuccess || !out.retryable || len(out.pruneIDs) != 0 {
		t.Fatalf("expected retryable failure, got %+v", out)
	}
	if out.lastErr != "503 upstream" {
		t.Fatalf("lastErr = %q", out.lastErr)
	}
}

func TestEvalSends_PartialSuccessWins(t *testing.T) {
	// One device delivers, another has a transient error → the intent is done
	// (partial success), never retried for the failing device.
	ok := &fakeDispatcher{err: nil}
	boom := &fakeDispatcher{err: errors.New("timeout")}
	out := evalSends(context.Background(),
		getter(map[sharedpush.ProviderKind]sharedpush.Dispatcher{
			sharedpush.APNs: ok, sharedpush.FCM: boom,
		}),
		[]sharedpush.Device{dev(1, sharedpush.APNs), dev(2, sharedpush.FCM)}, []byte("{}"))
	if !out.anySuccess {
		t.Fatalf("expected a success, got %+v", out)
	}
	// retryable is set, but processOne prefers anySuccess → done.
}

func TestEvalSends_UnconfiguredProviderSkipped(t *testing.T) {
	// A device whose provider isn't configured here is skipped, not an error.
	out := evalSends(context.Background(),
		getter(map[sharedpush.ProviderKind]sharedpush.Dispatcher{}),
		[]sharedpush.Device{dev(1, sharedpush.APNs)}, []byte("{}"))
	if out.anySuccess || out.retryable || len(out.pruneIDs) != 0 {
		t.Fatalf("expected no-op outcome, got %+v", out)
	}
}

func TestBackoffFor(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 2 * time.Minute}, // clamped to 1
		{1, 2 * time.Minute},
		{2, 4 * time.Minute},
		{3, 8 * time.Minute},
		{5, 32 * time.Minute},
		{6, time.Hour}, // 64min capped
		{9, time.Hour}, // clamp guards the shift, still capped
	}
	for _, c := range cases {
		if got := backoffFor(c.attempts); got != c.want {
			t.Errorf("backoffFor(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}

type guestDigestFixture struct {
	pool     *pgxpool.Pool
	worker   *Worker
	domainID int64
	guestID  int64
	guest2ID int64
	memberID int64
}

func newGuestDigestFixture(t *testing.T) *guestDigestFixture {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("random fixture suffix: %v", err)
	}
	domain := fmt.Sprintf("digest-%x.example", suffix)
	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	insertUser := func(local, display string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO users (username, domain_id, email, display_name, enabled)
			 VALUES ($1,$2,$3,$4,TRUE) RETURNING id`,
			local, domainID, local+"@"+domain, display,
		).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", local, err)
		}
		return id
	}
	guestID := insertUser("guest1", "Guest One")
	guest2ID := insertUser("guest2", "Guest Two")
	memberID := insertUser("member", "Member Sender")
	guestMail := "guest1@external.example"
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts
			(user_id, invited_email, invited_by, invited_by_email, sponsor_user_id,
			 host_domain_id, status)
		VALUES ($1,$2,$3,$4,$3,$5,'active'),
		       ($6,$7,$3,$4,$3,$5,'active')`,
		guestID, guestMail, memberID, "member@"+domain, domainID,
		guest2ID, "guest2@external.example",
	); err != nil {
		t.Fatalf("insert guest accounts: %v", err)
	}

	w := NewWorker(pgxutil.WorkerPool{Pool: pool}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.SetGuestDigestConfig(GuestDigestConfig{
		MC: &minio.Client{}, Bucket: "test", FromAddr: "noreply@" + domain,
		FromName: "SetJoin", WebmailURL: "https://" + domain,
	})
	f := &guestDigestFixture{pool: pool, worker: w, domainID: domainID,
		guestID: guestID, guest2ID: guest2ID, memberID: memberID}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM sessions WHERE user_id IN ($1,$2)`, guestID, guest2ID)
		_, _ = pool.Exec(c, `DELETE FROM guest_notification_intents WHERE user_id IN ($1,$2)`, guestID, guest2ID)
		_, _ = pool.Exec(c, `DELETE FROM meetings WHERE owner_user_id=$1`, memberID)
		_, _ = pool.Exec(c, `DELETE FROM chat_channels WHERE created_by=$1`, memberID)
		_, _ = pool.Exec(c, `DELETE FROM guest_accounts WHERE user_id IN ($1,$2)`, guestID, guest2ID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE domain_id=$1`, domainID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id=$1`, domainID)
	})
	return f
}

func (f *guestDigestFixture) addIntent(t *testing.T, guestID int64, kind, ref string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(context.Background(),
		`INSERT INTO guest_notification_intents (user_id,kind,ref) VALUES ($1,$2,$3) RETURNING id`,
		guestID, kind, ref).Scan(&id); err != nil {
		t.Fatalf("insert intent: %v", err)
	}
	return id
}

func (f *guestDigestFixture) addDM(t *testing.T, guestID int64, body string) (channelID, messageID int64) {
	t.Helper()
	ctx := context.Background()
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO chat_channels (kind,name,visibility,created_by)
		 VALUES ('dm',NULL,'private',$1) RETURNING id`, f.memberID,
	).Scan(&channelID); err != nil {
		t.Fatalf("insert DM: %v", err)
	}
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO chat_channel_members (channel_id,user_id,role)
		 VALUES ($1,$2,'owner'),($1,$3,'member')`, channelID, f.memberID, guestID); err != nil {
		t.Fatalf("insert DM members: %v", err)
	}
	if err := f.pool.QueryRow(ctx,
		`INSERT INTO chat_messages (channel_id,seq,author_id,body)
		 VALUES ($1,1,$2,$3) RETURNING id`, channelID, f.memberID, body,
	).Scan(&messageID); err != nil {
		t.Fatalf("insert DM message: %v", err)
	}
	return channelID, messageID
}

func captureDigestMail(t *testing.T, sendErr error) (*atomic.Int32, *[]string) {
	t.Helper()
	var calls atomic.Int32
	var mu sync.Mutex
	var bodies []string
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, body string) error {
		calls.Add(1)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		return sendErr
	})
	t.Cleanup(restore)
	return &calls, &bodies
}

func TestDrainGuestDigestsNilConfig(t *testing.T) {
	w := &Worker{}
	drained, err := w.DrainGuestDigests(context.Background())
	if err != nil || drained {
		t.Fatalf("DrainGuestDigests = (%v,%v), want (false,nil)", drained, err)
	}
}

func TestDrainGuestDigestsActiveSessionReturnsPromptlyWithoutProgress(t *testing.T) {
	f := newGuestDigestFixture(t)
	f.addIntent(t, f.guestID, "dm", "1:1")
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO sessions (id,user_id,expires_at,last_seen_at)
		 VALUES ($1,$2,now()+interval '1 day',now())`,
		fmt.Sprintf("digest-active-%d", f.guestID), f.guestID); err != nil {
		t.Fatalf("insert active session: %v", err)
	}
	calls, _ := captureDigestMail(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	drained, err := f.worker.DrainGuestDigests(ctx)
	if err != nil || drained || calls.Load() != 0 {
		t.Fatalf("active drain = (%v,%v), mail=%d", drained, err, calls.Load())
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("active-session no-progress drain did not return promptly")
	}
}

func TestDrainGuestDigestsThrottleReturnsNoProgress(t *testing.T) {
	f := newGuestDigestFixture(t)
	f.addIntent(t, f.guestID, "dm", "1:1")
	if _, err := f.pool.Exec(context.Background(),
		`INSERT INTO guest_notification_intents (user_id,kind,ref,sent_at)
		 VALUES ($1,'dm','old:old',now())`, f.guestID); err != nil {
		t.Fatalf("insert throttle row: %v", err)
	}
	calls, _ := captureDigestMail(t, nil)
	drained, err := f.worker.DrainGuestDigests(context.Background())
	if err != nil || drained || calls.Load() != 0 {
		t.Fatalf("throttled drain = (%v,%v), mail=%d", drained, err, calls.Load())
	}
}

func TestDrainGuestDigestsSendsAndStampsExactlyFifty(t *testing.T) {
	f := newGuestDigestFixture(t)
	channelID, messageID := f.addDM(t, f.guestID, "hello guest")
	ref := fmt.Sprintf("%d:%d", channelID, messageID)
	for range 51 {
		f.addIntent(t, f.guestID, "dm", ref)
	}
	calls, _ := captureDigestMail(t, nil)
	drained, err := f.worker.DrainGuestDigests(context.Background())
	if err != nil || !drained || calls.Load() != 1 {
		t.Fatalf("send drain = (%v,%v), mail=%d", drained, err, calls.Load())
	}
	var sent, pending int
	if err := f.pool.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE sent_at IS NOT NULL),
		       count(*) FILTER (WHERE sent_at IS NULL)
		  FROM guest_notification_intents WHERE user_id=$1`, f.guestID,
	).Scan(&sent, &pending); err != nil {
		t.Fatalf("count batch: %v", err)
	}
	if sent != 50 || pending != 1 {
		t.Fatalf("sent/pending = %d/%d, want 50/1", sent, pending)
	}
}

func TestDrainGuestDigestsFrozenGuestTombstonesWithoutMail(t *testing.T) {
	f := newGuestDigestFixture(t)
	for range 3 {
		f.addIntent(t, f.guestID, "dm", "bad:ref")
	}
	if _, err := f.pool.Exec(context.Background(),
		`UPDATE guest_accounts SET status='disabled' WHERE user_id=$1`, f.guestID); err != nil {
		t.Fatalf("freeze guest: %v", err)
	}
	calls, _ := captureDigestMail(t, nil)
	drained, err := f.worker.DrainGuestDigests(context.Background())
	if err != nil || !drained || calls.Load() != 0 {
		t.Fatalf("frozen drain = (%v,%v), mail=%d", drained, err, calls.Load())
	}
	var pending int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM guest_notification_intents WHERE user_id=$1 AND sent_at IS NULL`,
		f.guestID).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending after tombstone=%d err=%v", pending, err)
	}
}

func TestDrainGuestDigestsSendFailureLeavesBatchPending(t *testing.T) {
	f := newGuestDigestFixture(t)
	channelID, messageID := f.addDM(t, f.guestID, "do not lose me")
	f.addIntent(t, f.guestID, "dm", fmt.Sprintf("%d:%d", channelID, messageID))
	marker := fmt.Sprintf("digest-rollback-%d", f.guestID)
	var calls atomic.Int32
	restore := notify.SetTestSender(func(ctx context.Context, q notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, _ string) error {
		calls.Add(1)
		if _, err := q.Exec(ctx, `
			INSERT INTO outbound_queue (message_id,from_addr,rcpt_addrs,raw_ref,status)
			VALUES ($1,'noreply@example.test',ARRAY['guest@example.test'],$2,'pending')`,
			marker, marker); err != nil {
			return err
		}
		return errors.New("opaque send failure")
	})
	t.Cleanup(restore)
	drained, err := f.worker.DrainGuestDigests(context.Background())
	if err == nil || drained || calls.Load() != 1 {
		t.Fatalf("failed send drain = (%v,%v), mail=%d", drained, err, calls.Load())
	}
	var pending, queued int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM guest_notification_intents WHERE user_id=$1 AND sent_at IS NULL`,
		f.guestID).Scan(&pending); err != nil {
		t.Fatalf("pending after failed send: %v", err)
	}
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM outbound_queue WHERE raw_ref=$1`, marker).Scan(&queued); err != nil {
		t.Fatalf("queue rows after failed send: %v", err)
	}
	if pending != 1 || queued != 0 {
		t.Fatalf("failed send left pending=%d queued=%d, want 1/0", pending, queued)
	}
}

func TestDrainGuestDigestsQueueAndStampCommitInOneTransaction(t *testing.T) {
	f := newGuestDigestFixture(t)
	channelID, messageID := f.addDM(t, f.guestID, "atomic digest")
	intentID := f.addIntent(t, f.guestID, "dm", fmt.Sprintf("%d:%d", channelID, messageID))
	marker := fmt.Sprintf("digest-atomic-%d", f.guestID)
	restore := notify.SetTestSender(func(ctx context.Context, q notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, _ string) error {
		_, err := q.Exec(ctx, `
			INSERT INTO outbound_queue (message_id,from_addr,rcpt_addrs,raw_ref,status)
			VALUES ($1,'noreply@example.test',ARRAY['guest@example.test'],$2,'pending')`,
			marker, marker)
		return err
	})
	t.Cleanup(restore)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM outbound_queue WHERE raw_ref=$1`, marker)
	})

	drained, err := f.worker.DrainGuestDigests(context.Background())
	if err != nil || !drained {
		t.Fatalf("atomic drain = (%v,%v)", drained, err)
	}
	var queueXID, intentXID int64
	if err := f.pool.QueryRow(context.Background(), `
		SELECT oq.xmin::text::bigint, gi.xmin::text::bigint
		  FROM outbound_queue oq CROSS JOIN guest_notification_intents gi
		 WHERE oq.raw_ref=$1 AND gi.id=$2 AND gi.sent_at IS NOT NULL`, marker, intentID,
	).Scan(&queueXID, &intentXID); err != nil {
		t.Fatalf("read atomic commit evidence: %v", err)
	}
	if queueXID != intentXID {
		t.Fatalf("queue xid=%d intent stamp xid=%d; want one transaction", queueXID, intentXID)
	}
}

func TestDrainGuestDigestsConcurrentWorkersSendExactlyOnce(t *testing.T) {
	f := newGuestDigestFixture(t)
	channelID, messageID := f.addDM(t, f.guestID, "one mail only")
	f.addIntent(t, f.guestID, "dm", fmt.Sprintf("%d:%d", channelID, messageID))
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	marker := fmt.Sprintf("digest-concurrent-%d", f.guestID)
	restore := notify.SetTestSender(func(ctx context.Context, q notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, _ string) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		_, err := q.Exec(ctx, `
			INSERT INTO outbound_queue (message_id,from_addr,rcpt_addrs,raw_ref,status)
			VALUES ($1,'noreply@example.test',ARRAY['guest@example.test'],$2,'pending')`,
			marker, marker)
		return err
	})
	t.Cleanup(restore)
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM outbound_queue WHERE raw_ref=$1`, marker)
	})

	w2 := NewWorker(pgxutil.WorkerPool{Pool: f.pool}, nil, slog.Default())
	w2.SetGuestDigestConfig(*f.worker.guestDigestCfg)
	type result struct {
		drained bool
		err     error
	}
	first := make(chan result, 1)
	go func() {
		d, err := f.worker.DrainGuestDigests(context.Background())
		first <- result{d, err}
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first worker did not reach mail sender")
	}
	second := make(chan result, 1)
	go func() {
		d, err := w2.DrainGuestDigests(context.Background())
		second <- result{d, err}
	}()
	select {
	case got := <-second:
		if got.err != nil || got.drained {
			t.Fatalf("locked second worker = (%v,%v), want false,nil", got.drained, got.err)
		}
	case <-time.After(time.Second):
		t.Fatal("second worker blocked instead of skipping locked guest")
	}
	close(release)
	got := <-first
	if got.err != nil || !got.drained || calls.Load() != 1 {
		t.Fatalf("first worker = (%v,%v), mail=%d", got.drained, got.err, calls.Load())
	}
	var sent, queued int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM guest_notification_intents WHERE user_id=$1 AND sent_at IS NOT NULL`,
		f.guestID).Scan(&sent); err != nil {
		t.Fatalf("terminal rows: %v", err)
	}
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM outbound_queue WHERE raw_ref=$1`, marker).Scan(&queued); err != nil {
		t.Fatalf("queued rows: %v", err)
	}
	if sent != 1 || queued != 1 {
		t.Fatalf("terminal/queued rows=%d/%d, want 1/1", sent, queued)
	}
}

func TestGuestDigestLockIsTransactionPoolSafe(t *testing.T) {
	source, err := os.ReadFile("worker.go")
	if err != nil {
		t.Fatalf("read worker.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "pg_try_advisory_lock(") || strings.Contains(text, "pg_advisory_unlock(") {
		t.Fatal("guest digest uses a session advisory lock, unsafe behind transaction-mode PgBouncer")
	}
	if !strings.Contains(text, "pg_try_advisory_xact_lock(") {
		t.Fatal("guest digest lacks a transaction-scoped advisory lock")
	}
	if !strings.Contains(text, "context.WithTimeout(ctx, guestDigestSendTimeout)") {
		t.Fatal("guest digest object-store/send phase lacks its finite timeout")
	}
}

func TestDrainGuestDigestsDoesNotRenderCrossGuestContent(t *testing.T) {
	f := newGuestDigestFixture(t)
	ctx := context.Background()

	// A mention for guest two must not be renderable from guest one's corrupt ref.
	mentionChannel, mentionMessage := f.addDM(t, f.guest2ID, "MENTION-SECRET")
	if _, err := f.pool.Exec(ctx,
		`INSERT INTO chat_mentions (message_id,mentioned_user_id) VALUES ($1,$2)`,
		mentionMessage, f.guest2ID); err != nil {
		t.Fatalf("insert mention: %v", err)
	}
	mentionIntent := f.addIntent(t, f.guestID, "mention", fmt.Sprintf("%d:%d", mentionChannel, mentionMessage))

	// A DM channel that guest one never joined must not render either.
	foreignChannel, foreignDM := f.addDM(t, f.guest2ID, "DM-SECRET")
	foreignIntent := f.addIntent(t, f.guestID, "dm", fmt.Sprintf("%d:%d", foreignChannel, foreignDM))

	// Meeting invites derive access from membership in the meeting chat channel.
	meetingChannel, _ := f.addDM(t, f.guest2ID, "meeting channel")
	var meetingID int64
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO meetings (title,owner_user_id,chat_channel_id,scheduled_start)
		VALUES ('MEETING-SECRET',$1,$2,now()+interval '1 day') RETURNING id`,
		f.memberID, meetingChannel).Scan(&meetingID); err != nil {
		t.Fatalf("insert meeting: %v", err)
	}
	meetingIntent := f.addIntent(t, f.guestID, "meeting_invite", fmt.Sprint(meetingID))

	// One valid line makes the mail observable without exposing any bad ref.
	ownChannel, ownMessage := f.addDM(t, f.guestID, "VISIBLE-OWN")
	f.addIntent(t, f.guestID, "dm", fmt.Sprintf("%d:%d", ownChannel, ownMessage))
	var calls atomic.Int32
	var subject, body string
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, gotSubject, gotBody string) error {
		calls.Add(1)
		subject = gotSubject
		body = gotBody
		return nil
	})
	t.Cleanup(restore)
	drained, err := f.worker.DrainGuestDigests(ctx)
	if err != nil || !drained || calls.Load() != 1 {
		t.Fatalf("scoped drain = (%v,%v), calls=%d", drained, err, calls.Load())
	}
	if !strings.Contains(body, "VISIBLE-OWN") || strings.Contains(body, "MENTION-SECRET") ||
		strings.Contains(body, "DM-SECRET") || strings.Contains(body, "MEETING-SECRET") {
		t.Fatalf("digest body violated guest scope: %q", body)
	}
	var orgName string
	if err := f.pool.QueryRow(ctx, `SELECT COALESCE(NULLIF(
		(SELECT value #>> '{}' FROM system_config WHERE key='org.name'),''),'your organization')`).Scan(&orgName); err != nil {
		t.Fatalf("read organization name: %v", err)
	}
	if want := fmt.Sprintf("New activity in %s", orgName); subject != want {
		t.Fatalf("digest subject=%q, want authorized-line count subject %q", subject, want)
	}
	var terminalized int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM guest_notification_intents
		 WHERE id=ANY($1) AND sent_at IS NOT NULL`, []int64{mentionIntent, foreignIntent, meetingIntent},
	).Scan(&terminalized); err != nil || terminalized != 3 {
		t.Fatalf("foreign intents terminalized=%d err=%v, want 3", terminalized, err)
	}
}

func TestDrainGuestDigestsInvalidWindowFailsClosed(t *testing.T) {
	for _, value := range []string{`"bad"`, `0`, `-1`} {
		t.Run(value, func(t *testing.T) {
			f := newGuestDigestFixture(t)
			f.addIntent(t, f.guestID, "dm", "1:1")
			var prior string
			priorErr := f.pool.QueryRow(context.Background(),
				`SELECT value::text FROM system_config WHERE key='guest.digest_window_minutes'`).Scan(&prior)
			if priorErr != nil && !errors.Is(priorErr, pgx.ErrNoRows) {
				t.Fatalf("read prior digest window: %v", priorErr)
			}
			if _, err := f.pool.Exec(context.Background(), `
				INSERT INTO system_config (key,value) VALUES ('guest.digest_window_minutes',$1::jsonb)
				ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, value); err != nil {
				t.Fatalf("set invalid window: %v", err)
			}
			t.Cleanup(func() {
				if errors.Is(priorErr, pgx.ErrNoRows) {
					_, _ = f.pool.Exec(context.Background(),
						`DELETE FROM system_config WHERE key='guest.digest_window_minutes'`)
				} else {
					_, _ = f.pool.Exec(context.Background(), `
						UPDATE system_config SET value=$1::jsonb
						 WHERE key='guest.digest_window_minutes'`, prior)
				}
			})
			drained, err := f.worker.DrainGuestDigests(context.Background())
			if err == nil || drained {
				t.Fatalf("invalid window drain = (%v,%v), want false,error", drained, err)
			}
		})
	}
}

func TestReapGuestIntentsDeletesSentAndTombstonesStaleUnsent(t *testing.T) {
	f := newGuestDigestFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO guest_notification_intents (user_id,kind,ref,created_at,sent_at) VALUES
		 ($1,'dm','old-sent',now()-interval '8 days',now()-interval '8 days'),
		 ($1,'dm','old-pending',now()-interval '8 days',NULL),
		 ($1,'dm','new-sent',now(),now())`, f.guestID); err != nil {
		t.Fatalf("insert reap rows: %v", err)
	}
	f.worker.reapGuestIntents(ctx)
	var oldSent, oldPendingTombstoned, newSent int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE ref='old-sent'),
		       count(*) FILTER (WHERE ref='old-pending' AND sent_at IS NOT NULL),
		       count(*) FILTER (WHERE ref='new-sent')
		  FROM guest_notification_intents WHERE user_id=$1`, f.guestID,
	).Scan(&oldSent, &oldPendingTombstoned, &newSent); err != nil {
		t.Fatalf("read reap rows: %v", err)
	}
	if oldSent != 0 || oldPendingTombstoned != 1 || newSent != 1 {
		t.Fatalf("reap result oldSent=%d tombstoned=%d newSent=%d", oldSent, oldPendingTombstoned, newSent)
	}
}
