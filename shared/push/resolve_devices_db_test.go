package push

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

// DB-backed coverage for ResolveDevices' per-row resilience contract (D-6):
// an undecryptable token (encrypted under a different pool GUC) is skipped
// and aggregated into one loud log line WITHOUT sinking the resolve —
// readable rows on both sides of the bad row still resolve, an empty
// decrypted token is skipped, an all-bad user yields zero devices (never an
// error), and a transaction caller's transaction stays usable after the bad
// row (the V263 helper isolates the decrypt failure in-sql). The fake-rows
// unit test (TestResolveDevicesFakeQuerierSkipsUndecryptableRow) pins the
// Go-side per-row skip arm.

const resolveGUCTestKey = "resolve-devices-fixed-test-key"

// seedResolveUser creates the push_devices fixture tenant (domain + user;
// push_devices FKs users) and registers its cleanup.
func seedResolveUser(t *testing.T, pool *pgxpool.Pool, label string) int64 {
	t.Helper()
	ctx := context.Background()

	var domainID, userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, label+".test").Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM push_devices WHERE user_id=$1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id=$1`, userID)
		_, _ = pool.Exec(c, `DELETE FROM domains WHERE id=$1`, domainID)
	})
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name)
		 VALUES ($1, $2, $3, 'Push Resolve') RETURNING id`,
		label, domainID, label+"@"+label+".test").Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return userID
}

// captureSlog redirects the default logger into a buffer for the duration of
// fn (ResolveDevices logs its aggregate skip line through slog.Error, i.e.
// the process default logger). The returned buffer must carry the aggregate
// skip line and MUST NOT carry any token or key material.
func captureSlog(t *testing.T, fn func()) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(prev)
	fn()
	return &buf
}

// assertNoSecretsInLog pins the aggregate-log contract: the loud skip line
// carries counts, never token or key contents.
func assertNoSecretsInLog(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	if !strings.Contains(buf.String(), "could not be decrypted") ||
		!strings.Contains(buf.String(), "skipped_rows") {
		t.Errorf("aggregate undecryptable log line missing, got: %s", buf.String())
	}
	for _, secret := range []string{resolveGUCTestKey, resolveGUCTestKey + "-wrong", "doomed-token", "readable-token", "second-good-token"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("log leaked secret material %q: %s", secret, buf.String())
		}
	}
}

// captureSlogResolve runs ResolveDevices under a captured default logger (the
// aggregate skip line goes through slog.Error, i.e. the process default) and
// returns the capture buffer alongside the resolve result.
func captureSlogResolve(t *testing.T, ctx context.Context, userID int64, q Querier) (*bytes.Buffer, []Device, error) {
	t.Helper()
	var devices []Device
	var err error
	buf := captureSlog(t, func() {
		devices, err = ResolveDevices(ctx, q, userID)
	})
	return buf, devices, err
}

// TestResolveDevicesSkipsUndecryptableAndEmptyTokens seeds four rows —
// readable, empty-decrypt, wrong-key-undecryptable, readable — and proves the
// amended D-6 contract end-to-end against the real database: all-good inputs
// resolve every readable token; after the middle row is re-encrypted under a
// different key the readable rows on BOTH sides of the bad row still resolve,
// the bad row is skipped with nil error and exactly one aggregate log line
// (no token/key contents), and a transaction caller stays usable afterward.
func TestResolveDevicesSkipsUndecryptableAndEmptyTokens(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey)
	ctx := context.Background()
	userID := seedResolveUser(t, pool, "push-resolve")

	seed := func(provider, token string) int64 {
		var id int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO push_devices (user_id, push_provider, push_token_enc)
			 VALUES ($1, $2, pgp_sym_encrypt($3, current_setting('app.encryption_key'))) RETURNING id`,
			userID, provider, token).Scan(&id); err != nil {
			t.Fatalf("seed push_devices (%s): %v", provider, err)
		}
		return id
	}
	seed("fcm", "readable-token")
	seed("apns", "") // decrypts to empty → skipped (not undecryptable)
	doomed := seed("fcm", "doomed-token")
	seed("webpush", "second-good-token")

	// All-good inputs: every readable token resolves (both sides of the row
	// that is ABOUT to go bad), the empty decrypt is silently skipped.
	allGood, err := ResolveDevices(ctx, pool, userID)
	if err != nil {
		t.Fatalf("all-good resolve: %v", err)
	}
	got := resolvedTokens(allGood)
	if len(got) != 3 || !got["readable-token"] || !got["second-good-token"] || !got["doomed-token"] {
		t.Fatalf("all-good resolve = %v, want readable-token + second-good-token + doomed-token", allGood)
	}

	// Re-encrypt the middle token under a DIFFERENT key (a second pool whose
	// GUC differs) so exactly that row is undecryptable at read time.
	wrong := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey+"-wrong")
	if _, err := wrong.Exec(ctx,
		`UPDATE push_devices SET push_token_enc = pgp_sym_encrypt('doomed-token', current_setting('app.encryption_key'))
		  WHERE id = $1`, doomed); err != nil {
		t.Fatalf("re-encrypt doomed token under wrong key: %v", err)
	}

	buf, devices, err := captureSlogResolve(t, ctx, userID, pool)
	if err != nil {
		t.Fatalf("resolve with one undecryptable row = %v, want nil (a single bad token must not sink the resolve, D-6)", err)
	}
	// Readable rows on both sides of the bad row resolve; bad + empty skipped.
	if got := resolvedTokens(devices); len(got) != 2 || !got["readable-token"] || !got["second-good-token"] {
		t.Fatalf("mixed resolve = %v, want exactly readable-token + second-good-token (bad row skipped)", devices)
	}
	if got := resolvedTokens(devices); got["doomed-token"] {
		t.Fatal("the undecryptable token must never be returned (fail-closed skip)")
	}
	assertNoSecretsInLog(t, buf)

	// Transaction usability afterward: the bad row must not abort a caller's
	// transaction (the helper isolates the failure in-sql, not via a client
	// error skip that would leave the tx poisoned).
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	// D-6b (Astra r2): the rollback is registered IMMEDIATELY after the
	// successful Begin. Any later t.Fatalf in this arm (or in ResolveDevices'
	// own fatal-wrapped assertions) must not strand the tx's checked-out
	// connection — cleanup's pool.Close() waits for it indefinitely and the
	// test would HANG instead of failing. After a successful Commit the
	// rollback is a harmless no-op error.
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	txDevices, err := ResolveDevices(ctx, tx, userID)
	if err != nil {
		t.Fatalf("ResolveDevices on a tx with an undecryptable row present = %v, want nil", err)
	}
	if len(resolvedTokens(txDevices)) != 2 {
		t.Fatalf("tx resolve = %v, want the same two readable devices", txDevices)
	}
	// The transaction must still be usable after the isolated failure.
	var live int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_devices WHERE user_id = $1 AND revoked_at IS NULL`, userID).Scan(&live); err != nil {
		t.Fatalf("query on the same tx after the bad-row resolve = %v — the transaction was poisoned, want usable", err)
	}
	if live != 4 {
		t.Fatalf("live devices on the post-resolve tx = %d, want 4", live)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit the post-resolve tx: %v", err)
	}
}

// TestResolveDevicesAllBadYieldsZeroWithoutError pins the all-bad input: every
// token undecryptable → zero devices, nil error (never a failed resolve), and
// the aggregate log fires with no token/key contents.
func TestResolveDevicesAllBadYieldsZeroWithoutError(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey)
	ctx := context.Background()
	userID := seedResolveUser(t, pool, "push-resolve-allbad")

	seed := func(provider, token string) {
		if _, err := pool.Exec(ctx,
			`INSERT INTO push_devices (user_id, push_provider, push_token_enc)
			 VALUES ($1, $2, pgp_sym_encrypt($3, current_setting('app.encryption_key')))`,
			userID, provider, token); err != nil {
			t.Fatalf("seed push_devices (%s): %v", provider, err)
		}
	}
	seed("fcm", "doomed-token")
	seed("apns", "doomed-token")

	wrong := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey+"-wrong")
	if _, err := wrong.Exec(ctx,
		`UPDATE push_devices SET push_token_enc = pgp_sym_encrypt('doomed-token', current_setting('app.encryption_key'))
		  WHERE user_id = $1`, userID); err != nil {
		t.Fatalf("re-encrypt tokens under wrong key: %v", err)
	}

	buf, devices, err := captureSlogResolve(t, ctx, userID, pool)
	if err != nil {
		t.Fatalf("all-bad resolve = %v, want nil error with zero devices", err)
	}
	if len(devices) != 0 {
		t.Fatalf("all-bad resolve devices = %v, want none", devices)
	}
	assertNoSecretsInLog(t, buf)
}

// TestResolveDevicesMissingEncryptionKeySurfacesAsError pins the
// configuration-error preservation (D-6 amendment): a pool whose AfterConnect
// never sets app.encryption_key fails the resolve LOUDLY — the helper's
// current_setting raises (42704) and propagates instead of a NULL-skip — so a
// misconfigured pooler can never read as "user has no devices".
func TestResolveDevicesMissingEncryptionKeySurfacesAsError(t *testing.T) {
	pool := testsupport.OpenTestPoolWithGUC(t, resolveGUCTestKey)
	ctx := context.Background()
	userID := seedResolveUser(t, pool, "push-resolve-nokey")
	if _, err := pool.Exec(ctx,
		`INSERT INTO push_devices (user_id, push_provider, push_token_enc)
		 VALUES ($1, 'fcm', pgp_sym_encrypt('unreadable-anyway', current_setting('app.encryption_key')))`,
		userID); err != nil {
		t.Fatalf("seed push_devices: %v", err)
	}

	keyless := testsupport.OpenTestPoolWithGUC(t, "") // never sets the GUC
	if _, err := ResolveDevices(ctx, keyless, userID); err == nil {
		t.Fatal("resolve on a pool without app.encryption_key = nil, want the loud configuration error")
	}
}

// TestResolveDevicesEmptyEncryptionKeySurfacesAsError pins the Astra r2 D-6
// regression: pgcrypto fails an EMPTY configured key with the SAME SQLSTATE
// 39000 as a wrong-key token ("Illegal argument to function"), so the
// pre-r2 blanket 39000 handler reported the misconfiguration as a NULL skip —
// the resolve silently returned zero devices and pushjobs marked the dispatch
// intent done as if the user had none. The V263 helper now reads and validates
// the key OUTSIDE its EXCEPTION-scoped decrypt: an empty app.encryption_key
// must fail the resolve LOUDLY (42704), never read as "user has no devices".
func TestResolveDevicesEmptyEncryptionKeySurfacesAsError(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	userID := seedResolveUser(t, pool, "push-resolve-emptykey")
	if _, err := pool.Exec(ctx,
		`INSERT INTO push_devices (user_id, push_provider, push_token_enc)
		 VALUES ($1, 'fcm', '\x00'::bytea)`,
		userID); err != nil {
		t.Fatalf("seed push_devices: %v", err)
	}

	// One dedicated connection whose SESSION carries the empty key — the
	// pooler-configured-with-empty-value shape. (OpenTestPoolWithGUC("")
	// never sets the GUC at all, which is the separate missing-GUC arm above;
	// an explicitly empty configuration lands here.)
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT set_config('app.encryption_key', '', false)`); err != nil {
		t.Fatalf("set an empty app.encryption_key on the session: %v", err)
	}

	devices, err := ResolveDevices(ctx, conn, userID)
	if err == nil {
		t.Fatalf("resolve with an EMPTY app.encryption_key = (%v, nil error) — the keyless configuration error was swallowed as a silent empty resolve", devices)
	}
	if len(devices) != 0 {
		t.Errorf("devices = %v, want none — the configuration error must fail the resolve, never yield a device set", devices)
	}
}

// resolvedTokens indexes the resolved devices by token for order-independent
// assertions.
func resolvedTokens(devices []Device) map[string]bool {
	out := make(map[string]bool, len(devices))
	for _, d := range devices {
		out[d.Token] = true
	}
	return out
}

// failingScanRows wraps pgx.Rows and yields one failing Scan followed by a
// clean EOF — the per-row shape the skip contract was written for (the rest of
// the pgx.Rows surface is never reached by ResolveDevices).
type failingScanRows struct {
	pgx.Rows
	scans int
}

func (r *failingScanRows) Scan(dest ...any) error {
	r.scans++
	if r.scans == 1 {
		return errors.New("simulated single-row driver failure")
	}
	// Populate the surviving row: id, provider, token.
	if len(dest) == 3 {
		if id, ok := dest[0].(*int64); ok {
			*id = 7
		}
		if p, ok := dest[1].(*string); ok {
			*p = "fcm"
		}
		if tok, ok := dest[2].(**string); ok {
			good := "good-token"
			*tok = &good
		}
	}
	return nil
}

func (r *failingScanRows) Next() bool { return r.scans < 2 }

func (r *failingScanRows) Err() error { return nil }

func (r *failingScanRows) Close() {}

type fakeQuerier struct{ rows pgx.Rows }

func (f fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return f.rows, nil
}

// TestResolveDevicesFakeQuerierSkipsUndecryptableRow pins the per-row skip and
// the aggregate undecryptable log arm at the Go level: a failing Scan is
// counted and skipped, a good row still resolves, and the dispatch is not
// sunk by the bad row.
func TestResolveDevicesFakeQuerierSkipsUndecryptableRow(t *testing.T) {
	rows := &failingScanRows{}
	devices, err := ResolveDevices(context.Background(), fakeQuerier{rows: rows}, 1)
	if err != nil {
		t.Fatalf("ResolveDevices: %v", err)
	}
	if rows.scans != 2 {
		t.Fatalf("scans = %d, want 2 (bad row + good row)", rows.scans)
	}
	if len(devices) != 1 || devices[0].Provider != ProviderKind("fcm") || devices[0].Token != "good-token" {
		t.Fatalf("devices = %+v, want the single surviving fcm row", devices)
	}
}
