// external.go holds the shared plain-text RFC 5322 system-mail egress.
package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/minio/minio-go/v7"
)

var (
	lastSystemMessageID atomic.Int64
	systemMailSender    atomic.Value // sendMailFunc
	testSenderMu        sync.Mutex
)

type sendMailFunc func(context.Context, SystemMailQueue, *minio.Client, string, string, string, string, string, string, string) error

type mailObjectStore interface {
	PutObject(context.Context, string, string, io.Reader, int64, minio.PutObjectOptions) (minio.UploadInfo, error)
}

// SystemMailQueue is the smallest queue-write seam used by system mail.
// Both *pgxpool.Pool and pgx.Tx satisfy it, allowing callers to make the
// outbound_queue insert atomic with their own state transition.
type SystemMailQueue interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// systemMailPrefix allows the two object-store namespaces used by guest mail
// and hyphen-suffixed Message-ID tokens such as booking- and guest-invite-.
var systemMailPrefix = regexp.MustCompile(`^(?:(?:invite|digest)/|[A-Za-z0-9][A-Za-z0-9_-]*-)$`)

func init() {
	systemMailSender.Store(sendMailFunc(defaultSendSystemMail))
}

// BuildSystemMIME renders a single-part, quoted-printable RFC 5322 message.
// Invalid inputs produce empty output; SendSystemMail returns their validation error.
func BuildSystemMIME(fromAddr, fromName, toAddr, subject, body, prefix string) (mime, messageID string) {
	mime, messageID, err := buildSystemMIME(fromAddr, fromName, toAddr, subject, body, prefix)
	if err != nil {
		return "", ""
	}
	return mime, messageID
}

func buildSystemMIME(fromAddr, fromName, toAddr, subject, body, prefix string) (raw, messageID string, err error) {
	fromName = normalizeHeaderText(fromName)
	subject = normalizeHeaderText(subject)
	if err := validateSystemMailInput(fromAddr, toAddr, prefix); err != nil {
		return "", "", err
	}
	from := (&mail.Address{Name: fromName, Address: fromAddr}).String()
	to := (&mail.Address{Address: toAddr}).String()
	_, domain, _ := strings.Cut(fromAddr, "@")
	messageID = fmt.Sprintf("<%s%d@%s>", prefix, nextSystemMessageID(), domain)

	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Message-ID: %s\r\n", messageID)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
	encodedBody, err := encodeQuotedPrintable(normalizeCRLF(body) + "\r\n")
	if err != nil {
		return "", "", fmt.Errorf("encode body: %w", err)
	}
	b.WriteString(encodedBody)
	return b.String(), messageID, nil
}

func validateSystemMailInput(fromAddr, toAddr, prefix string) error {
	for field, value := range map[string]string{
		"from address": fromAddr,
		"to address":   toAddr,
	} {
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid %s: newline", field)
		}
		addr, err := mail.ParseAddress(value)
		if err != nil || addr.Address != value {
			return fmt.Errorf("invalid %s", field)
		}
	}
	if !systemMailPrefix.MatchString(prefix) {
		return fmt.Errorf("invalid message-id prefix")
	}
	return nil
}

func normalizeHeaderText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", " ")
}

func normalizeCRLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func encodeQuotedPrintable(value string) (string, error) {
	var encoded bytes.Buffer
	writer := quotedprintable.NewWriter(&encoded)
	if _, err := writer.Write([]byte(value)); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	return encoded.String(), nil
}

// nextSystemMessageID stays monotonic even when concurrent calls share a clock tick.
func nextSystemMessageID() int64 {
	for {
		now := time.Now().UnixNano()
		last := lastSystemMessageID.Load()
		next := now
		if next <= last {
			next = last + 1
		}
		if lastSystemMessageID.CompareAndSwap(last, next) {
			return next
		}
	}
}

// SendSystemMail stores a plain-text message and queues it for async SMTP delivery.
func SendSystemMail(ctx context.Context, queue SystemMailQueue, mc *minio.Client,
	bucket, prefix, fromAddr, fromName, toAddr, subject, body string) error {
	return systemMailSender.Load().(sendMailFunc)(ctx, queue, mc, bucket, prefix, fromAddr, fromName, toAddr, subject, body)
}

// SetTestSender serializes a test-only sender override and returns its restore closure.
func SetTestSender(sender func(context.Context, SystemMailQueue, *minio.Client, string, string, string, string, string, string, string) error) func() {
	if sender == nil {
		panic("notify: nil test sender")
	}
	testSenderMu.Lock()
	prior := systemMailSender.Load().(sendMailFunc)
	systemMailSender.Store(sendMailFunc(sender))
	var once sync.Once
	return func() {
		once.Do(func() {
			systemMailSender.Store(prior)
			testSenderMu.Unlock()
		})
	}
}

func defaultSendSystemMail(ctx context.Context, queue SystemMailQueue, mc *minio.Client,
	bucket, prefix, fromAddr, fromName, toAddr, subject, body string) error {
	if mc == nil || queue == nil {
		// notify-lifecycle-egress-fail-open (D-MAILSERVER-INTERNAL-NOTIFY-002):
		// the nil-sink branch is the designed test seam (SetTestSender covers
		// in-test senders; production callers pass non-nil seams and boot
		// refuses without MinIO), but a SILENT success would hide a production
		// miswiring. The no-op is therefore loud: warn-level log so any real
		// occurrence is observable and diagnosable.
		slog.Warn("notify: system mail no-op — nil object store or queue seam",
			"to", toAddr, "subject", subject)
		return nil
	}
	return sendSystemMail(ctx, mc, queue, bucket, prefix, fromAddr, fromName, toAddr, subject, body)
}

func sendSystemMail(ctx context.Context, store mailObjectStore, queue SystemMailQueue,
	bucket, prefix, fromAddr, fromName, toAddr, subject, body string) error {
	mimeMsg, messageID, err := buildSystemMIME(fromAddr, fromName, toAddr, subject, body, prefix)
	if err != nil {
		return fmt.Errorf("notify: build system MIME: %w", err)
	}
	hash := sha256.Sum256([]byte(mimeMsg))
	key := prefix + hex.EncodeToString(hash[:]) + ".eml"
	if _, err := store.PutObject(ctx, bucket, key, strings.NewReader(mimeMsg), int64(len(mimeMsg)), minio.PutObjectOptions{ContentType: "message/rfc822"}); err != nil {
		return fmt.Errorf("notify: store blob: %w", err)
	}
	if _, err := queue.Exec(ctx,
		`INSERT INTO outbound_queue (message_id, from_addr, rcpt_addrs, raw_ref, status)
		 VALUES ($1, $2, $3, $4, 'pending')`,
		messageID, fromAddr, []string{toAddr}, key); err != nil {
		return fmt.Errorf("notify: enqueue: %w", err)
	}
	return nil
}
