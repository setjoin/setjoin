package ad

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Edge-branch coverage for the AD sync seams: DryRun error propagation, the
// empty-email unknown-entry skip, alias sync for freshly provisioned users,
// connector-level cancellation, and the between-pages cancellation check.

// TestDryRunSearchErrorSurfaces pins DryRun's contract: a search failure is
// returned as an error, never collapsed into a zero-count success.
func TestDryRunSearchErrorSurfaces(t *testing.T) {
	var logs bytes.Buffer
	w := &SyncWorker{
		client: &fakeADDirectory{searchErr: context.DeadlineExceeded},
		logger: slog.New(slog.NewTextHandler(&logs, nil)),
	}
	if _, err := w.DryRun(context.Background()); err == nil {
		t.Fatal("DryRun with a failing search: want error")
	}
}

// TestUpsertUserUnknownEmptyEmailEntrySkipped pins the creation-side guard: a
// directory-DISABLED entry that is NOT in the local DB and carries no mail
// attribute has nothing to provision or disable — past the provision-only top
// guard, the unknown-entry skip fires without error or counts.
func TestUpsertUserUnknownEmptyEmailEntrySkipped(t *testing.T) {
	pool := testPool(t)
	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	var guid string
	if err := pool.QueryRow(t.Context(), `SELECT gen_random_uuid()::TEXT`).Scan(&guid); err != nil {
		t.Fatal(err)
	}

	res := SyncResult{}
	if err := w.upsertUser(t.Context(), ADUser{
		ObjectGUID: guid, Email: "", DisplayName: "No Mail", UPN: "", USNChanged: 1,
		Disabled: true,
	}, false, false, &res); err != nil {
		t.Fatalf("upsertUser(empty email, unknown entry): %v", err)
	}
	if res.Created != 0 || res.Updated != 0 || res.Disabled != 0 {
		t.Fatalf("result = %+v, want zero counts for the skipped entry", res)
	}
	var n int
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM users WHERE ad_object_guid::TEXT = $1`, guid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("empty-email unknown entry created %d local user(s), want 0", n)
	}
}

// TestUpsertUserProvisionedUserSyncsProxyAliases pins the creation arm's alias
// attachment: a newly provisioned user's SMTP proxyAddresses land as aliases
// on the fresh mailbox in the same cycle.
func TestUpsertUserProvisionedUserSyncsProxyAliases(t *testing.T) {
	pool := testPool(t)
	ctx := t.Context()
	suffix := randSuffix(t)
	domain := "adtest-aliascreate-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var objectGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&objectGUID); err != nil {
		t.Fatal(err)
	}
	email := "ad-create-" + suffix + "@" + domain
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM aliases WHERE domain_id = $1`, domainID)
		pool.Exec(c, `DELETE FROM sync_conflicts WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM field_policy WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE user_id IN (SELECT id FROM users WHERE ad_object_guid::TEXT = $1)`, objectGUID)
		pool.Exec(c, `DELETE FROM users WHERE ad_object_guid::TEXT = $1`, objectGUID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var logs bytes.Buffer
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&logs, nil))}

	res := SyncResult{}
	if err := w.upsertUser(ctx, ADUser{
		ObjectGUID: objectGUID, Email: email, DisplayName: "Alias Create",
		UPN: email, USNChanged: 1,
		ProxyAddresses: []string{"smtp:first." + email, "SMTP:" + email},
	}, false, true, &res); err != nil {
		t.Fatalf("create upsert with proxy aliases: %v", err)
	}
	if res.Created != 1 {
		t.Fatalf("created = %d, want 1", res.Created)
	}

	var aliasCount int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM aliases a
		  JOIN users u ON u.id = (SELECT user_id FROM mailboxes WHERE id = a.mailbox_id)
		  WHERE u.ad_object_guid::TEXT = $1 AND a.email = $2`,
		objectGUID, "first."+email).Scan(&aliasCount); err != nil {
		t.Fatalf("read alias: %v", err)
	}
	if aliasCount != 1 {
		t.Fatalf("proxy alias rows for fresh user = %d, want 1", aliasCount)
	}
}

// TestFetchObservesContextCancellation pins the connector's ctx discipline:
// cancellation before connect and cancellation during connect both stop the
// fetch with wrapped-context errors, before any bind or search.
func TestFetchObservesContextCancellation(t *testing.T) {
	// Already-cancelled context: the pre-connect check fires.
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	nc := normalizedConnector{client: &fakeADDirectory{}}
	_, _, err := nc.Fetch(canceled, usnCursor(0))
	if err == nil || !strings.Contains(err.Error(), "canceled before connect") {
		t.Fatalf("pre-connect fetch err = %v, want canceled-before-connect", err)
	}

	// Cancellation while connect is in flight: the post-connect check fires
	// before bind. The fake cancels the very context Fetch is running under,
	// from inside connect (a dial that outlives its caller's patience).
	ctx2, cancel2 := context.WithCancel(context.Background())
	nc2 := normalizedConnector{client: &cancelDuringConnect{cancel: cancel2}}
	_, _, err = nc2.Fetch(ctx2, usnCursor(0))
	if err == nil || !strings.Contains(err.Error(), "canceled before bind") {
		t.Fatalf("post-connect fetch err = %v, want canceled-before-bind", err)
	}
}

// cancelDuringConnect cancels the Fetch context from inside connect, then
// returns a dead pipe connection — mirroring a dial that outlives its caller's
// patience.
type cancelDuringConnect struct {
	cancel context.CancelFunc
}

func (c *cancelDuringConnect) connect() (*ldap.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	conn := ldap.NewConn(client, false)
	conn.Start()
	c.cancel()
	return conn, nil
}

func (c *cancelDuringConnect) Bind(*ldap.Conn) error { return nil }

func (c *cancelDuringConnect) SearchUsers(_ context.Context, _ *ldap.Conn, _ int64) ([]ADUser, int64, error) {
	return nil, 0, nil
}

// TestSearchUsersCtxCancelledBeforeFirstPage pins the between-pages guard:
// SearchUsers observes an already-cancelled context before the first LDAP
// round trip (go-ldap's Search is not ctx-aware; this check is the seam).
func TestSearchUsersCtxCancelledBeforeFirstPage(t *testing.T) {
	c := &Client{bindDN: "cn=sync"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.SearchUsers(ctx, nil, 0); err == nil || !strings.Contains(err.Error(), "canceled after 0 pages") {
		t.Fatalf("SearchUsers with cancelled ctx err = %v, want canceled-after-0-pages", err)
	}
}

// TestGetLocalOnlyFields_DBErrorFailsClosed pins the field-policy read's
// fail-closed discipline: an unreachable database returns an error instead of
// an empty (lock-free) map.
func TestGetLocalOnlyFields_DBErrorFailsClosed(t *testing.T) {
	pool, err := pgxpool.New(context.Background(),
		"postgres://adtest@127.0.0.1:1/noSuchDB?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	w := &SyncWorker{pool: pool, logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))}
	if _, err := w.getLocalOnlyFields(context.Background(), 1); err == nil {
		t.Fatal("getLocalOnlyFields on broken pool: want error (fail closed)")
	}
}
