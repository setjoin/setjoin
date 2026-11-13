package directorysync

// Real-store acceptance tests (med-shard2-012, Astra waves34 HOLD 1 + HOLD 2).
// These run the engine through identitysource.NewStore and the real
// PL/pgSQL reducers against the loaded test schema (DB_DSN, e.g.
// postgres://mail@127.0.0.1:5432/mailserver_test after
// scripts/load-test-schema.sh). They verify:
//
//   - HOLD 2: a connector-attested tombstone propagates through the real
//     inbox/reducer disable path and actually disables the account and
//     revokes live sessions, OAuth tokens, and websocket subscriptions.
//     Absence-never-deletes and failed/partial-scan negatives remain pinned
//     by the fake-store tests in engine_reconciliation_test.go.
//   - HOLD 1: engine quarantine accounting is durable in
//     identity_source_quarantines BEFORE the cursor is acknowledged, and
//     survives later incremental pages and a simulated process restart
//     (fresh pool + fresh engine instance).

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/shared/testsupport"
)

type realFixture struct {
	pool      *pgxpool.Pool
	sourceKey string
	sourceID  int64
	mailboxID int64
	userID    int64
	linkID    int64
	subject   string
	mailLess  string
}

func realFixtureLabel(t *testing.T) string {
	t.Helper()
	return "dsync" + uuid.NewString()[:8]
}

func mustExec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("fixture exec %q: %v", query, err)
	}
}

// newRealFixture builds one fully isolated identity-substrate fixture: an
// active ldap source, an enabled person with an active provision-purpose hard
// anchor and source lifecycle authority, one live session, one live refresh
// token, and one websocket subscription. Cleanup removes everything the test
// created except the identity_sources row and its append-only
// identity_link_events rows (both deliberately unremovable RESTRICT/trigger
// residue, keyed uniquely like every other DB-backed test in this repo).
func newRealFixture(t *testing.T, pool *pgxpool.Pool) *realFixture {
	t.Helper()
	label := realFixtureLabel(t)
	f := &realFixture{
		pool:      pool,
		sourceKey: "dsync-test-" + label,
		subject:   "subject-" + label,
		mailLess:  "mailless-" + label,
		mailboxID: -1,
	}
	mustExec(t, pool, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,'directorysync real-store fixture','ldap',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`, f.sourceKey)
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM identity_sources WHERE source_key=$1`, f.sourceKey,
	).Scan(&f.sourceID); err != nil {
		t.Fatalf("load fixture source: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT mk_account($1)`, label,
	).Scan(&f.mailboxID); err != nil {
		t.Fatalf("mk_account fixture: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id FROM mailboxes WHERE id=$1`, f.mailboxID,
	).Scan(&f.userID); err != nil {
		t.Fatalf("load fixture user: %v", err)
	}
	mustExec(t, pool, `UPDATE users SET enabled=true WHERE id=$1`, f.userID)
	mustExec(t, pool, `
		INSERT INTO user_identity_links
			(user_id, source_id, external_subject, purposes, state, link_method, evidence)
		VALUES ($1,$2,$3,ARRAY['provision']::text[],'active','hard_anchor',
		        '{"class":"immutable"}'::jsonb)`,
		f.userID, f.sourceID, f.subject)
	if err := pool.QueryRow(context.Background(),
		`SELECT id FROM user_identity_links WHERE source_id=$1 AND external_subject=$2`,
		f.sourceID, f.subject,
	).Scan(&f.linkID); err != nil {
		t.Fatalf("load fixture link: %v", err)
	}
	// mk_account's primary-mailbox trigger seeds a 'local' authority row
	// (V164); the source link takes the authority over exactly like the
	// apply reducer does.
	mustExec(t, pool, `
		INSERT INTO user_lifecycle_authorities (user_id, authority_kind, link_id)
		VALUES ($1,'source',$2)
		ON CONFLICT (user_id) DO UPDATE SET
			authority_kind='source',
			link_id=EXCLUDED.link_id,
			generation=user_lifecycle_authorities.generation+1,
			established_by=NULL,
			established_at=statement_timestamp(),
			updated_at=statement_timestamp()`,
		f.userID, f.linkID)
	mustExec(t, pool, `
		INSERT INTO sessions (user_id, expires_at)
		VALUES ($1, statement_timestamp() + interval '1 hour')`, f.userID)
	mustExec(t, pool, `
		INSERT INTO oauth_tokens (user_id, token_hash, expires_at, family_id, token_type)
		VALUES ($1, digest('dsync-realstore-refresh','sha256'),
		        statement_timestamp() + interval '1 hour', gen_random_uuid(), 'refresh')`,
		f.userID)
	mustExec(t, pool, `
		INSERT INTO ws_subscriptions (connection_id, session_id, user_id)
		VALUES (gen_random_uuid()::text,
		        (SELECT id FROM sessions WHERE user_id=$1 LIMIT 1), $1)`, f.userID)

	t.Cleanup(func() {
		cleanup := context.Background()
		for _, stmt := range []string{
			`DELETE FROM identity_source_quarantines WHERE source_id=$1`,
			`DELETE FROM identity_source_inbox WHERE source_id=$1`,
			`DELETE FROM identity_source_batches WHERE source_id=$1`,
			`DELETE FROM identity_source_leases WHERE source_id=$1`,
			`DELETE FROM user_identity_links WHERE source_id=$1`,
			`DELETE FROM identity_sources WHERE id=$1 AND NOT EXISTS (
				 SELECT 1 FROM identity_link_events WHERE source_id=$1)`,
		} {
			_, _ = pool.Exec(cleanup, stmt, f.sourceID)
		}
		for _, stmt := range []string{
			`DELETE FROM user_lifecycle_authorities WHERE user_id=$1`,
			`DELETE FROM session_revocations WHERE user_id=$1`,
			`DELETE FROM oauth_tokens WHERE user_id=$1`,
			`DELETE FROM ws_subscriptions WHERE user_id=$1`,
			`DELETE FROM sessions WHERE user_id=$1`,
			`DELETE FROM mailboxes WHERE id=$2`,
			`DELETE FROM users WHERE id=$1`,
		} {
			_, _ = pool.Exec(cleanup, stmt, f.userID, f.mailboxID)
		}
	})
	return f
}

func countRows(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&count); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return count
}

// A connector-attested tombstone drives the real reducer disable path: the
// anchored person is disabled, every live session and websocket subscription
// is deleted, every OAuth token is revoked, the durable all-session
// revocation fence is written, the inbox entry is terminal, and the page
// cursor commits. The mail-less object in the same page is durably
// quarantined before that cursor commits, without blocking the disable.
func TestSyncTombstoneDisablesAndRevokesThroughRealStore(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
	f := newRealFixture(t, pool)

	connector := &fakeConnector{
		label:  "TEST",
		before: testCursor(""),
		after:  testCursor("t1"),
		objects: []Object{
			{Subject: f.subject, Tombstone: true},
			{Subject: f.mailLess, DisplayName: "No Mail Attribute"},
		},
	}
	result, err := (Engine{
		Store:       identitysource.NewStore(pool),
		Quarantines: PgxQuarantineStore{Pool: pool},
		Connector:   connector,
		SourceKey:   f.sourceKey,
		Instance:    uuid.New(),
		Logger:      testsupport.TestLogger(),
	}).Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if result.Updated != 1 || result.Skipped != 1 || result.Errors != 0 {
		t.Fatalf("result=%+v want Updated=1 Skipped=1 Errors=0", result)
	}

	if enabled := countRows(t, pool,
		`SELECT count(*) FROM users WHERE id=$1 AND enabled`, f.userID,
	); enabled != 0 {
		t.Fatalf("tombstone must disable the anchored person (enabled rows=%d)", enabled)
	}
	if live := countRows(t, pool,
		`SELECT count(*) FROM sessions WHERE user_id=$1`, f.userID,
	); live != 0 {
		t.Fatalf("tombstone must delete live sessions (remaining=%d)", live)
	}
	if live := countRows(t, pool,
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND revoked_at IS NULL`, f.userID,
	); live != 0 {
		t.Fatalf("tombstone must revoke live OAuth tokens (remaining=%d)", live)
	}
	if live := countRows(t, pool,
		`SELECT count(*) FROM ws_subscriptions WHERE user_id=$1`, f.userID,
	); live != 0 {
		t.Fatalf("tombstone must delete websocket subscriptions (remaining=%d)", live)
	}
	if fences := countRows(t, pool,
		`SELECT count(*) FROM session_revocations WHERE user_id=$1 AND scope='all' AND reason='identity_source_disable'`,
		f.userID,
	); fences != 1 {
		t.Fatalf("tombstone must write the durable all-session denylist fence (rows=%d)", fences)
	}
	if active := countRows(t, pool,
		`SELECT count(*) FROM user_identity_links WHERE id=$1 AND state='active'`, f.linkID,
	); active != 1 {
		t.Fatalf("disable-first must not destroy the link (active rows=%d)", active)
	}
	if applied := countRows(t, pool,
		`SELECT count(*) FROM identity_source_inbox WHERE source_id=$1 AND immutable_subject=$2 AND state='applied'`,
		f.sourceID, f.subject,
	); applied != 1 {
		t.Fatalf("tombstone entry must be terminal applied in the real inbox (rows=%d)", applied)
	}
	if advanced := countRows(t, pool,
		`SELECT count(*) FROM identity_sources WHERE id=$1 AND committed_cursor->>'cursor'='t1'`,
		f.sourceID,
	); advanced != 1 {
		t.Fatal("the disable cycle must commit the page cursor")
	}
	if quarantined := countRows(t, pool,
		`SELECT count(*) FROM identity_source_quarantines
		  WHERE source_id=$1 AND object_key=$2 AND reason_code=$3 AND occurrences=1`,
		f.sourceID, f.mailLess, QuarantineNoUsableMail,
	); quarantined != 1 {
		t.Fatalf("mail-less object must be durably quarantined before the cursor commit (rows=%d)", quarantined)
	}
	if events := countRows(t, pool,
		`SELECT count(*) FROM identity_link_events WHERE source_id=$1 AND action='source_entry_quarantined'`,
		f.sourceID,
	); events < 1 {
		t.Fatalf("quarantine must be visible in the link event stream (rows=%d)", events)
	}
}

// Durable quarantine accounting survives later incremental pages that no
// longer carry the object, and survives a simulated process restart (fresh
// pool + fresh engine instance + fresh lease holder). Re-presenting the
// object after the restart accumulates occurrences on the SAME ledger row
// instead of duplicating evidence.
func TestSyncQuarantineAccountingPersistsAcrossPagesAndRestart(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
	f := newRealFixture(t, pool)

	page := func(after string, objects ...Object) *fakeConnector {
		return &fakeConnector{
			label: "TEST", before: testCursor(""), after: testCursor(after), objects: objects,
		}
	}
	first := (Engine{
		Store:       identitysource.NewStore(pool),
		Quarantines: PgxQuarantineStore{Pool: pool},
		Connector:   page("c1", Object{Subject: f.mailLess, DisplayName: "No Mail Attribute"}),
		SourceKey:   f.sourceKey,
		Instance:    uuid.New(),
		Logger:      testsupport.TestLogger(),
	})
	if _, err := first.Sync(context.Background()); err != nil {
		t.Fatalf("cycle 1 Sync: %v", err)
	}

	var occurrences int
	var firstSeen, lastSeen time.Time
	if err := pool.QueryRow(context.Background(), `
		SELECT occurrences, first_quarantined_at, last_quarantined_at
		  FROM identity_source_quarantines
		 WHERE source_id=$1 AND object_key=$2 AND reason_code=$3`,
		f.sourceID, f.mailLess, QuarantineNoUsableMail,
	).Scan(&occurrences, &firstSeen, &lastSeen); err != nil {
		t.Fatalf("cycle 1 must durably quarantine the mail-less object: %v", err)
	}
	if occurrences != 1 {
		t.Fatalf("cycle 1 occurrences=%d want 1", occurrences)
	}
	if advanced := countRows(t, pool,
		`SELECT count(*) FROM identity_sources WHERE id=$1 AND committed_cursor->>'cursor'='c1'`,
		f.sourceID,
	); advanced != 1 {
		t.Fatal("quarantine must not wedge cycle 1 cursor advancement")
	}

	// Simulated restart: a fresh pool, a fresh engine instance, and a fresh
	// lease holder, reading only committed database state.
	// OpenTestPool already fatal-skipped without DB_DSN, so it is set here.
	restartedPool, err := pgxpool.New(context.Background(), os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("restart pool: %v", err)
	}
	defer restartedPool.Close()

	// Later incremental page after the restart no longer carries the
	// quarantined object: the cursor advances and the durable accounting
	// must survive untouched — not cleared, not re-accounted.
	second := (Engine{
		Store:       identitysource.NewStore(restartedPool),
		Quarantines: PgxQuarantineStore{Pool: restartedPool},
		Connector:   page("c2"),
		SourceKey:   f.sourceKey,
		Instance:    uuid.New(),
		Logger:      testsupport.TestLogger(),
	})
	if _, err := second.Sync(context.Background()); err != nil {
		t.Fatalf("cycle 2 Sync: %v", err)
	}
	if advanced := countRows(t, pool,
		`SELECT count(*) FROM identity_sources WHERE id=$1 AND committed_cursor->>'cursor'='c2'`,
		f.sourceID,
	); advanced != 1 {
		t.Fatal("later page must advance the cursor past the quarantined object")
	}
	var survivedOccurrences int
	var survivedFirst time.Time
	if err := restartedPool.QueryRow(context.Background(), `
		SELECT occurrences, first_quarantined_at
		  FROM identity_source_quarantines
		 WHERE source_id=$1 AND object_key=$2 AND reason_code=$3`,
		f.sourceID, f.mailLess, QuarantineNoUsableMail,
	).Scan(&survivedOccurrences, &survivedFirst); err != nil {
		t.Fatal("quarantine accounting must persist across the later page and restart")
	}
	if survivedOccurrences != 1 || !survivedFirst.Equal(firstSeen) {
		t.Fatalf("accounting must survive untouched, got occurrences=%d first=%v want occurrences=1 first=%v",
			survivedOccurrences, survivedFirst, firstSeen)
	}

	// Re-presenting the object after the restart re-accounts it on the SAME
	// ledger row (occurrences accumulate, no duplicate evidence).
	third := (Engine{
		Store:       identitysource.NewStore(restartedPool),
		Quarantines: PgxQuarantineStore{Pool: restartedPool},
		Connector:   page("c3", Object{Subject: f.mailLess, DisplayName: "No Mail Attribute"}),
		SourceKey:   f.sourceKey,
		Instance:    uuid.New(),
		Logger:      testsupport.TestLogger(),
	})
	if _, err := third.Sync(context.Background()); err != nil {
		t.Fatalf("cycle 3 Sync: %v", err)
	}
	if rows := countRows(t, restartedPool,
		`SELECT count(*) FROM identity_source_quarantines WHERE source_id=$1 AND object_key=$2`,
		f.sourceID, f.mailLess,
	); rows != 1 {
		t.Fatalf("re-accounting must accumulate one row, got %d", rows)
	}
	if err := restartedPool.QueryRow(context.Background(), `
		SELECT occurrences, last_quarantined_at
		  FROM identity_source_quarantines
		 WHERE source_id=$1 AND object_key=$2 AND reason_code=$3`,
		f.sourceID, f.mailLess, QuarantineNoUsableMail,
	).Scan(&occurrences, &lastSeen); err != nil {
		t.Fatalf("re-accounted row must exist: %v", err)
	}
	if occurrences != 2 {
		t.Fatalf("re-presented object occurrences=%d want 2", occurrences)
	}
	if lastSeen.Before(firstSeen) {
		t.Fatalf("last_quarantined_at %v must not precede first_quarantined_at %v", lastSeen, firstSeen)
	}
}
