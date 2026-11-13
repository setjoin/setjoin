package notify

import (
	"context"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minio/minio-go/v7"
)

func TestBuildSystemMIME_Structure(t *testing.T) {
	mime, messageID := BuildSystemMIME("sender@example.com", "Sender",
		"guest@partner.example", "Test Subject", "Test body.", "guest-invite-")
	for _, want := range []string{
		"From: \"Sender\" <sender@example.com>",
		"To: <guest@partner.example>",
		"Subject: Test Subject",
		"Content-Type: text/plain; charset=utf-8",
	} {
		if !strings.Contains(mime, want) {
			t.Errorf("MIME missing %q: %q", want, mime)
		}
	}
	if !regexp.MustCompile(`^<guest-invite-[0-9]+@example\.com>$`).MatchString(messageID) {
		t.Errorf("Message-ID shape wrong: %q", messageID)
	}
	msg, err := mail.ReadMessage(strings.NewReader(mime))
	if err != nil {
		t.Fatalf("parse ASCII message: %v", err)
	}
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
		t.Fatalf("Content-Transfer-Encoding = %q", got)
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil || string(decodedBody) != "Test body.\r\n" {
		t.Fatalf("decoded ASCII body = %q, %v", decodedBody, err)
	}
}

func TestBuildSystemMIME_MessageIDUniqueUnderConcurrency(t *testing.T) {
	const calls = 256
	ids := make(chan string, calls)
	var wg sync.WaitGroup
	for range calls {
		wg.Go(func() {
			_, id := BuildSystemMIME("a@example.com", "", "c@example.com", "s", "b", "pfx-")
			ids <- id
		})
	}
	wg.Wait()
	close(ids)

	seen := make(map[string]struct{}, calls)
	for id := range ids {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate Message-ID: %q", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != calls {
		t.Fatalf("unique Message-IDs = %d, want %d", len(seen), calls)
	}
}

func TestBuildSystemMIME_PlannedPrefixesAreSafe(t *testing.T) {
	for _, prefix := range []string{"invite/", "digest/", "booking-", "guest-invite-"} {
		t.Run(prefix, func(t *testing.T) {
			raw, messageID := BuildSystemMIME("sender@example.com", "", "guest@example.com", "subject", "body", prefix)
			if raw == "" || !strings.HasPrefix(messageID, "<"+prefix) {
				t.Fatalf("prefix %q rejected: MIME=%q Message-ID=%q", prefix, raw, messageID)
			}
		})
	}
	for _, prefix := range []string{"../invite/", "invite//", "invite/../", "bad/prefix", "invite/\r\nBcc:"} {
		t.Run("reject_"+strings.ReplaceAll(prefix, "/", "_"), func(t *testing.T) {
			raw, messageID := BuildSystemMIME("sender@example.com", "", "guest@example.com", "subject", "body", prefix)
			if raw != "" || messageID != "" {
				t.Fatalf("unsafe prefix %q accepted: MIME=%q Message-ID=%q", prefix, raw, messageID)
			}
		})
	}
}

func TestBuildSystemMIME_StripsHeaderInjection(t *testing.T) {
	raw, messageID := BuildSystemMIME(
		"sender@example.com\r\nBcc: victim@example.com",
		"Sender\r\nCc: victim@example.com",
		"guest@example.com\r\nReply-To: victim@example.com",
		"Hello\r\nX-Injected: yes",
		"Body.", "guest-invite-",
	)
	if raw != "" || messageID != "" {
		t.Fatalf("injected headers produced MIME=%q id=%q", raw, messageID)
	}
	raw, _ = BuildSystemMIME("sender@example.com", "Sender", "guest@example.com", "Hello", "Body.", "guest-invite-")
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse normal message: %v", err)
	}
	for _, injected := range []string{"Bcc", "Cc", "Reply-To", "X-Injected"} {
		if got := msg.Header.Get(injected); got != "" {
			t.Errorf("unexpected %s header: %q", injected, got)
		}
	}
}

func TestBuildSystemMIME_NormalizesHeaderNewlines(t *testing.T) {
	raw, _ := BuildSystemMIME("sender@example.com", "Sender\r\nTeam", "guest@example.com",
		"Hello\r\nWorld", "Body.", "invite/")
	if raw == "" {
		t.Fatal("safe header text produced an empty MIME message")
	}
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse normalized message: %v", err)
	}
	if got := len(msg.Header["Subject"]); got != 1 {
		t.Fatalf("Subject field count = %d, want 1", got)
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || decodedSubject != "Hello World" {
		t.Fatalf("decoded Subject = %q, %v", decodedSubject, err)
	}
	from, err := mail.ParseAddress(msg.Header.Get("From"))
	if err != nil || from.Name != "Sender Team" {
		t.Fatalf("parsed From = %#v, %v", from, err)
	}
}

func TestBuildSystemMIME_UnicodeRoundTrip(t *testing.T) {
	raw, _ := BuildSystemMIME("sender@example.com", "Sender", "guest@example.com",
		"你好, SetJoin", "第一行\n第二行", "guest-invite-")
	if strings.Contains(strings.ReplaceAll(raw, "\r\n", ""), "\n") {
		t.Fatalf("MIME contains a bare LF: %q", raw)
	}
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if !strings.HasPrefix(msg.Header.Get("Subject"), "=?utf-8?") {
		t.Fatalf("Subject is not RFC 2047 encoded: %q", msg.Header.Get("Subject"))
	}
	decodedSubject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || decodedSubject != "你好, SetJoin" {
		t.Fatalf("decoded Subject = %q, %v", decodedSubject, err)
	}
	if got := msg.Header.Get("Content-Transfer-Encoding"); got != "quoted-printable" {
		t.Fatalf("Content-Transfer-Encoding = %q", got)
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got, want := string(decodedBody), "第一行\r\n第二行\r\n"; got != want {
		t.Fatalf("decoded body = %q, want %q", got, want)
	}
}

func TestSendSystemMail_ValidatesBeforeWritingAndUsesTextArray(t *testing.T) {
	store := &fakeStore{}
	queue := &fakeQueue{}
	for _, input := range []struct {
		name, prefix, from, to string
	}{
		{"prefix", "bad/prefix", "sender@example.com", "guest@example.com"},
		{"sender", "guest-invite-", "not-an-address", "guest@example.com"},
		{"recipient", "guest-invite-", "sender@example.com", "not-an-address"},
	} {
		t.Run(input.name, func(t *testing.T) {
			err := sendSystemMail(context.Background(), store, queue, "bucket", input.prefix, input.from, "Sender", input.to, "subject", "body")
			if err == nil {
				t.Fatal("invalid input was accepted")
			}
			if store.calls != 0 || queue.calls != 0 {
				t.Fatalf("invalid send wrote store=%d queue=%d", store.calls, queue.calls)
			}
		})
	}
	if err := sendSystemMail(context.Background(), store, queue, "bucket", "guest-invite-", "sender@example.com", "Sender", "guest@example.com", "subject", "body"); err != nil {
		t.Fatalf("valid send: %v", err)
	}
	if store.calls != 1 || queue.calls != 1 {
		t.Fatalf("valid send calls store=%d queue=%d", store.calls, queue.calls)
	}
	if got, ok := queue.args[2].([]string); !ok || len(got) != 1 || got[0] != "guest@example.com" {
		t.Fatalf("rcpt_addrs argument = %#v (%T), want []string{guest@example.com}", queue.args[2], queue.args[2])
	}
	for _, prefix := range []string{"invite/", "digest/"} {
		store.calls, queue.calls = 0, 0
		if err := sendSystemMail(context.Background(), store, queue, "bucket", prefix, "sender@example.com", "Sender", "guest@example.com", "subject", "body"); err != nil {
			t.Fatalf("send %q: %v", prefix, err)
		}
		if !strings.HasPrefix(store.key, prefix) {
			t.Fatalf("MinIO key %q does not preserve prefix %q", store.key, prefix)
		}
	}
}

func TestSetTestSenderCanBeRestored(t *testing.T) {
	called := false
	restore := SetTestSender(func(context.Context, SystemMailQueue, *minio.Client, string, string, string, string, string, string, string) error {
		called = true
		return nil
	})
	t.Cleanup(restore)

	if err := SendSystemMail(context.Background(), nil, nil, "", "", "", "", "", "", ""); err != nil {
		t.Fatalf("test sender: %v", err)
	}
	if !called {
		t.Fatal("test sender was not called")
	}

	called = false
	restore()
	if err := SendSystemMail(context.Background(), nil, nil, "", "", "", "", "", "", ""); err != nil {
		t.Fatalf("default sender: %v", err)
	}
	if called {
		t.Fatal("test sender remained installed after restore")
	}
}

func TestSetTestSenderSerializesAndRestores(t *testing.T) {
	firstCalls := 0
	firstRestore := SetTestSender(func(context.Context, SystemMailQueue, *minio.Client, string, string, string, string, string, string, string) error {
		firstCalls++
		return nil
	})
	t.Cleanup(firstRestore)

	started := make(chan struct{})
	secondRestores := make(chan func(), 1)
	go func() {
		close(started)
		secondRestores <- SetTestSender(func(context.Context, SystemMailQueue, *minio.Client, string, string, string, string, string, string, string) error {
			return nil
		})
	}()
	<-started
	if err := SendSystemMail(context.Background(), nil, nil, "", "", "", "", "", "", ""); err != nil || firstCalls != 1 {
		t.Fatalf("first sender was not retained: calls=%d err=%v", firstCalls, err)
	}
	firstRestore()

	select {
	case restore := <-secondRestores:
		restore()
		restore() // idempotent
	case <-time.After(time.Second):
		t.Fatal("parallel sender override deadlocked")
	}
}

type fakeStore struct {
	calls int
	key   string
}

func (s *fakeStore) PutObject(_ context.Context, _ string, key string, r io.Reader, _ int64, _ minio.PutObjectOptions) (minio.UploadInfo, error) {
	s.calls++
	s.key = key
	_, _ = io.ReadAll(r)
	return minio.UploadInfo{}, nil
}

type fakeQueue struct {
	calls int
	args  []any
}

var _ SystemMailQueue = pgx.Tx(nil)

func (q *fakeQueue) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	q.calls++
	q.args = args
	return pgconn.CommandTag{}, nil
}
