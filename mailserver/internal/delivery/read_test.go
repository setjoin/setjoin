package delivery

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// requireDeliveryAttempts skips the test unless the delivery_attempts table
// (V017) is present in the test DB.
func requireDeliveryAttempts(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables
		   WHERE table_schema = 'public' AND table_name = 'delivery_attempts')`,
	).Scan(&exists); err != nil || !exists {
		t.Skip("delivery_attempts table (V017) not present")
	}
}

// randPK returns a random positive message_pk so concurrently-running tests
// (and other suites) never collide on the same surrogate key. delivery_attempts
// has no FK on message_pk/mailbox_id, so any value is acceptable.
func randPK(t *testing.T) int64 {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	v := int64(binary.BigEndian.Uint64(b[:]) >> 1) // clear sign bit → positive
	if v == 0 {
		v = 1
	}
	return v
}

// seedAttempt inserts one append-only delivery_attempts row.
func seedAttempt(t *testing.T, pool *pgxpool.Pool, msgPK, mailboxID int64, rcpt, mxHost string, attemptNum, code int, text, outcome string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO delivery_attempts
		   (message_pk, received_at, mailbox_id, recipient_email, mx_host, attempt_number, attempted_at, smtp_code, smtp_text, outcome, tls)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		msgPK, at, mailboxID, rcpt, mxHost, attemptNum, at, code, text, outcome, true,
	)
	if err != nil {
		t.Fatalf("seedAttempt: %v", err)
	}
}

func TestReadLatestPerRecipient_CrossMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	log := testsupport.TestLogger()
	ctx := context.Background()

	msgPK := randPK(t)
	mbA := randPK(t)
	mbB := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })

	// Same message_pk, two DIFFERENT mailbox_ids.
	seedAttempt(t, pool, msgPK, mbA, "alice@a.test", "mx.a.test", 1, 250, "2.0.0 OK", "accepted", at)
	seedAttempt(t, pool, msgPK, mbB, "bob@b.test", "mx.b.test", 1, 550, "5.1.1 nope", "rejected", at)

	// Cross-mailbox admin read: BOTH recipients returned.
	all := ReadLatestPerRecipientAdmin(ctx, pool, log, msgPK)
	if len(all) != 2 {
		t.Fatalf("cross-mailbox admin: want 2 recipients, got %d: %v", len(all), all)
	}
	if all["alice@a.test"].Outcome != "accepted" {
		t.Errorf("alice outcome: want accepted, got %q", all["alice@a.test"].Outcome)
	}
	if all["bob@b.test"].Outcome != "rejected" {
		t.Errorf("bob outcome: want rejected, got %q", all["bob@b.test"].Outcome)
	}

	// nil mailboxID on the USER-scoped read is refused (fail-closed), never
	// silently widened to global (D-MAILSERVER-INTERNAL-DELIVERY-001).
	if got := ReadLatestPerRecipient(ctx, pool, log, msgPK, nil); len(got) != 0 {
		t.Errorf("nil mailboxID on user-scoped read must return an empty map, got %v", got)
	}

	// &mbA → ownership-scoped: ONLY mailbox A's recipient.
	onlyA := ReadLatestPerRecipient(ctx, pool, log, msgPK, &mbA)
	if len(onlyA) != 1 {
		t.Fatalf("scoped to mbA: want 1 recipient, got %d: %v", len(onlyA), onlyA)
	}
	if _, ok := onlyA["alice@a.test"]; !ok {
		t.Errorf("scoped to mbA: missing alice, got %v", onlyA)
	}
	if _, ok := onlyA["bob@b.test"]; ok {
		t.Errorf("scoped to mbA: leaked bob (mailbox B) — filter not applied")
	}
}

func TestReadLatestPerRecipient_OverCount(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	log := testsupport.TestLogger()
	ctx := context.Background()

	msgPK := randPK(t)
	mb := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })

	// One recipient, two append-only attempts: deferred then accepted.
	seedAttempt(t, pool, msgPK, mb, "carol@c.test", "mx.c.test", 1, 451, "4.7.0 later", "deferred", at)
	seedAttempt(t, pool, msgPK, mb, "carol@c.test", "mx.c.test", 2, 250, "2.0.0 OK", "accepted", at.Add(time.Second))

	// DISTINCT-ON collapses to ONE LatestRow from the highest attempt_number.
	latest := ReadLatestPerRecipient(ctx, pool, log, msgPK, &mb)
	if len(latest) != 1 {
		t.Fatalf("over-count: want 1 LatestRow, got %d: %v", len(latest), latest)
	}
	if latest["carol@c.test"].Outcome != "accepted" {
		t.Errorf("over-count: want latest (accepted), got %q", latest["carol@c.test"].Outcome)
	}

	// History returns BOTH rows ordered ASC by attempt_number.
	hist := ReadAttemptHistory(ctx, pool, log, msgPK, &mb)
	attempts := hist["carol@c.test"]
	if len(attempts) != 2 {
		t.Fatalf("history: want 2 attempts, got %d", len(attempts))
	}
	if attempts[0].N != 1 || attempts[1].N != 2 {
		t.Errorf("history not ASC by attempt_number: got n=%d then n=%d", attempts[0].N, attempts[1].N)
	}
	if attempts[0].Outcome != "deferred" || attempts[1].Outcome != "accepted" {
		t.Errorf("history outcomes: want [deferred, accepted], got [%q, %q]", attempts[0].Outcome, attempts[1].Outcome)
	}
}

func TestReadAttemptHistory_CrossMailbox(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	log := testsupport.TestLogger()
	ctx := context.Background()

	msgPK := randPK(t)
	mbA := randPK(t)
	mbB := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })

	seedAttempt(t, pool, msgPK, mbA, "alice@a.test", "mx.a.test", 1, 250, "2.0.0 OK", "accepted", at)
	seedAttempt(t, pool, msgPK, mbB, "bob@b.test", "mx.b.test", 1, 550, "5.1.1 nope", "rejected", at)

	// Cross-mailbox admin history: both mailboxes' histories.
	all := ReadAttemptHistoryAdmin(ctx, pool, log, msgPK)
	if len(all) != 2 {
		t.Fatalf("cross-mailbox admin history: want 2 recipients, got %d", len(all))
	}

	// nil on the user-scoped history read is refused (fail-closed).
	if got := ReadAttemptHistory(ctx, pool, log, msgPK, nil); len(got) != 0 {
		t.Errorf("nil mailboxID on user-scoped history must return an empty map, got %v", got)
	}

	// &mbB → only mailbox B's history.
	onlyB := ReadAttemptHistory(ctx, pool, log, msgPK, &mbB)
	if len(onlyB) != 1 {
		t.Fatalf("scoped history to mbB: want 1 recipient, got %d", len(onlyB))
	}
	if _, ok := onlyB["bob@b.test"]; !ok {
		t.Errorf("scoped history to mbB: missing bob, got %v", onlyB)
	}
}

// warnCapture returns a slog logger capturing Warn records into buf. The read
// helpers' degrade paths Warn with the wording the dupl refactor preserved
// verbatim; testsupport.TestLogger's error-level handler would drop them.
func warnCapture(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// scanFailCodec delegates every plan to the ordinary int4 codec EXCEPT
// scanning, which always fails. Registered over int4 (OID 23 —
// delivery_attempts' smtp_code and attempt_number columns), it makes
// rows.Scan fail deterministically on any seeded row: those columns appear in
// both read helpers' column lists, their *int scan targets take the
// registered-codec path (pgx's built-in fast paths only cover string-ish
// targets), and a non-nil failing plan surfaces as a plain scan error.
// Parameter binding is untouched — the read helpers bind only int8
// message_pk/mailbox_id — so the failure lands exactly in the helpers'
// scan-error (Warn-and-degrade) arm.
type scanFailCodec struct{ pgtype.Int4Codec }

func (scanFailCodec) PlanScan(m *pgtype.Map, oid uint32, format int16, target any) pgtype.ScanPlan {
	return scanFailPlan{}
}

type scanFailPlan struct{}

func (scanFailPlan) Scan(src []byte, target any) error {
	return fmt.Errorf("scan sabotaged for test: int4 column unreadable")
}

// openInt4ScanFailPool returns a second pool on the same DB_DSN whose int4
// columns are registered with scanFailCodec. This is a schema-free injection
// for the helpers' scan-failure arms: delivery_attempts' other scanned columns
// are either NOT NULL text/timestamptz/bool (pgx fast-path or codec-scannable)
// or nullable-but-scanned-into-pointers (mx_host/smtp_code/smtp_text), so no
// row shape can trip rows.Scan on a normal pool. Seed and cleanup fixtures
// keep using the caller's normal pool; only the read under test runs here.
func openInt4ScanFailPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN") // non-empty: callers gate via OpenTestPool first
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgxpool.ParseConfig: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		conn.TypeMap().RegisterType(&pgtype.Type{
			Name:  "int4",
			OID:   pgtype.Int4OID,
			Codec: scanFailCodec{pgtype.Int4Codec{}},
		})
		return nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedNullAttempt inserts one delivery_attempts row with NULL mx_host,
// smtp_code and smtp_text (the columns a relay answer may legitimately omit).
func seedNullAttempt(t *testing.T, pool *pgxpool.Pool, msgPK, mailboxID int64, rcpt string, attemptNum int, outcome string, at time.Time) {
	t.Helper()
	_, err := pool.Exec(context.Background(),
		`INSERT INTO delivery_attempts
		   (message_pk, received_at, mailbox_id, recipient_email, mx_host, attempt_number, attempted_at, smtp_code, smtp_text, outcome, tls)
		 VALUES ($1,$2,$3,$4,NULL,$5,$6,NULL,NULL,$7,true)`,
		msgPK, at, mailboxID, rcpt, attemptNum, at, outcome,
	)
	if err != nil {
		t.Fatalf("seedNullAttempt: %v", err)
	}
}

func TestReadLatestPerRecipient_ScansAllFields(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	log := testsupport.TestLogger()
	ctx := context.Background()

	msgPK := randPK(t)
	mb := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })

	seedAttempt(t, pool, msgPK, mb, "full@a.test", "mx.full.test", 1, 250, "2.0.0 OK", "accepted", at)
	// The nullable columns scan into pointer fields: an attempt whose relay
	// answer is absent must come back as nil pointers, never zero values.
	seedNullAttempt(t, pool, msgPK, mb, "bare@a.test", 1, "deferred", at)

	latest := ReadLatestPerRecipient(ctx, pool, log, msgPK, &mb)
	if len(latest) != 2 {
		t.Fatalf("want 2 recipients, got %d: %v", len(latest), latest)
	}
	full := latest["full@a.test"]
	if full.MxHost == nil || *full.MxHost != "mx.full.test" {
		t.Errorf("MxHost: want mx.full.test, got %v", full.MxHost)
	}
	if full.Code == nil || *full.Code != 250 {
		t.Errorf("Code: want 250, got %v", full.Code)
	}
	if full.Text == nil || *full.Text != "2.0.0 OK" {
		t.Errorf("Text: want 2.0.0 OK, got %v", full.Text)
	}
	if full.At == nil || !full.At.Equal(at) {
		t.Errorf("At: want %v, got %v", at, full.At)
	}
	if full.Outcome != "accepted" {
		t.Errorf("Outcome: want accepted, got %q", full.Outcome)
	}
	bare := latest["bare@a.test"]
	if bare.MxHost != nil || bare.Code != nil || bare.Text != nil {
		t.Errorf("NULL columns must scan to nil pointers, got %v/%v/%v", bare.MxHost, bare.Code, bare.Text)
	}
	if bare.Outcome != "deferred" {
		t.Errorf("bare Outcome: want deferred, got %q", bare.Outcome)
	}

	// A mailbox with no attempts: the DISTINCT-ON loop never fires and the
	// helper returns the empty (never nil) map — the plain-empty path, with
	// no Warn (only query/scan failures Warn, see the failure tests below).
	emptyMB := randPK(t)
	if got := ReadLatestPerRecipient(ctx, pool, log, msgPK, &emptyMB); len(got) != 0 {
		t.Errorf("mailbox without attempts must return an empty map, got %v", got)
	}
}

func TestReadAttemptHistory_ScansAllFieldsOrdered(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	log := testsupport.TestLogger()
	ctx := context.Background()

	msgPK := randPK(t)
	mb := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })

	seedAttempt(t, pool, msgPK, mb, "hist@c.test", "mx.hist.test", 1, 451, "4.7.0 later", "deferred", at)
	seedAttempt(t, pool, msgPK, mb, "hist@c.test", "mx.hist.test", 2, 250, "2.0.0 OK", "accepted", at.Add(time.Second))

	hist := ReadAttemptHistory(ctx, pool, log, msgPK, &mb)
	attempts := hist["hist@c.test"]
	if len(attempts) != 2 {
		t.Fatalf("want 2 attempts, got %d", len(attempts))
	}
	// Chronological ASC by attempt_number (the read contract's ordering).
	if attempts[0].N != 1 || attempts[1].N != 2 {
		t.Fatalf("not ASC by attempt_number: got n=%d then n=%d", attempts[0].N, attempts[1].N)
	}
	first := attempts[0]
	if first.MxHost == nil || *first.MxHost != "mx.hist.test" {
		t.Errorf("MxHost: want mx.hist.test, got %v", first.MxHost)
	}
	if first.SmtpCode == nil || *first.SmtpCode != 451 {
		t.Errorf("SmtpCode: want 451, got %v", first.SmtpCode)
	}
	if first.SmtpText == nil || *first.SmtpText != "4.7.0 later" {
		t.Errorf("SmtpText: want 4.7.0 later, got %v", first.SmtpText)
	}
	if first.At == nil || !first.At.Equal(at) {
		t.Errorf("At: want %v, got %v", at, first.At)
	}
	if first.Outcome != "deferred" {
		t.Errorf("Outcome: want deferred, got %q", first.Outcome)
	}
	if !first.TLS {
		t.Errorf("TLS: want true (seeded), got false")
	}
	// Plain-empty mailbox: no rows, empty (never nil) map.
	emptyMB := randPK(t)
	if got := ReadAttemptHistory(ctx, pool, log, msgPK, &emptyMB); len(got) != 0 {
		t.Errorf("mailbox without attempts must return an empty map, got %v", got)
	}
}

func TestReadLatestPerRecipient_QueryFailureWarns(t *testing.T) {
	// DSN gating via OpenTestPool (the one-place skip/fail-closed policy);
	// the delivery_attempts table gate is irrelevant here — the failure is
	// injected at the pool, before any SQL reaches the server.
	_ = testsupport.OpenTestPool(t)
	closed, err := pgxpool.New(context.Background(), os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	closed.Close() // deterministic pool-level failure: Query returns ErrClosedPool

	var buf bytes.Buffer
	log := warnCapture(&buf)
	ctx := context.Background()
	msgPK := randPK(t)
	mb := randPK(t)

	got := ReadLatestPerRecipient(ctx, closed, log, msgPK, &mb)
	if len(got) != 0 {
		t.Errorf("query failure must degrade to an empty map, got %v", got)
	}
	if !strings.Contains(buf.String(), "delivery_attempts latest read failed") {
		t.Errorf("query failure must Warn with the preserved wording, got log %q", buf.String())
	}
}

func TestReadAttemptHistory_QueryFailureWarns(t *testing.T) {
	_ = testsupport.OpenTestPool(t) // DSN gating only — failure is pool-level
	closed, err := pgxpool.New(context.Background(), os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	closed.Close()

	var buf bytes.Buffer
	log := warnCapture(&buf)
	ctx := context.Background()
	msgPK := randPK(t)
	mb := randPK(t)

	got := ReadAttemptHistory(ctx, closed, log, msgPK, &mb)
	if len(got) != 0 {
		t.Errorf("query failure must degrade to an empty map, got %v", got)
	}
	if !strings.Contains(buf.String(), "delivery_attempts history read failed") {
		t.Errorf("query failure must Warn with the preserved wording, got log %q", buf.String())
	}
}

func TestReadLatestPerRecipient_ScanFailureWarns(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	sabotaged := openInt4ScanFailPool(t)
	ctx := context.Background()

	msgPK := randPK(t)
	mb := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })
	seedAttempt(t, pool, msgPK, mb, "scanfail-a@delivery.test", "mx.scanfail.test", 1, 250, "2.0.0 OK", "accepted", at)

	var buf bytes.Buffer
	log := warnCapture(&buf)

	got := ReadLatestPerRecipient(ctx, sabotaged, log, msgPK, &mb)
	if len(got) != 0 {
		t.Errorf("scan failure must degrade to an empty map, got %v", got)
	}
	if !strings.Contains(buf.String(), "delivery_attempts latest scan failed") {
		t.Errorf("scan failure must Warn with the preserved wording, got log %q", buf.String())
	}
}

func TestReadAttemptHistory_ScanFailureWarns(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	requireDeliveryAttempts(t, pool)
	sabotaged := openInt4ScanFailPool(t)
	ctx := context.Background()

	msgPK := randPK(t)
	mb := randPK(t)
	at := time.Now().Add(-time.Minute).Truncate(time.Microsecond)
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM delivery_attempts WHERE message_pk = $1`, msgPK) })
	seedAttempt(t, pool, msgPK, mb, "scanfail-b@delivery.test", "mx.scanfail.test", 1, 451, "4.7.0 later", "deferred", at)

	var buf bytes.Buffer
	log := warnCapture(&buf)

	got := ReadAttemptHistory(ctx, sabotaged, log, msgPK, &mb)
	if len(got) != 0 {
		t.Errorf("scan failure must degrade to an empty map, got %v", got)
	}
	if !strings.Contains(buf.String(), "delivery_attempts history scan failed") {
		t.Errorf("scan failure must Warn with the preserved wording, got log %q", buf.String())
	}
}
