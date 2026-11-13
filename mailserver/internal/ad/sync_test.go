package ad

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/directorysync"
	"setjoin.com/mailserver/internal/identitysource"
	"setjoin.com/shared/testsupport"
)

type fakeADDirectory struct {
	users      []ADUser
	maxUSN     int64
	err        error
	connectErr error
	bindErr    error
	searchErr  error
}

func (f *fakeADDirectory) connect() (*ldap.Conn, error) {
	if f.connectErr != nil {
		return nil, f.connectErr
	}
	if f.err != nil {
		return nil, f.err
	}
	client, server := net.Pipe()
	_ = server.Close()
	conn := ldap.NewConn(client, false)
	conn.Start()
	return conn, nil
}

func (f *fakeADDirectory) Bind(*ldap.Conn) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	return f.err
}

func (f *fakeADDirectory) SearchUsers(_ context.Context, _ *ldap.Conn, _ int64) ([]ADUser, int64, error) {
	if f.searchErr != nil {
		return nil, 0, f.searchErr
	}
	return f.users, f.maxUSN, f.err
}

var _ directoryClient = (*fakeADDirectory)(nil)

func TestBuildSyncAttrs(t *testing.T) {
	u := ADUser{
		Email: "test@corp.local", FirstName: "Test", LastName: "User",
		Department: "Engineering", Title: "Engineer", Phone: "1234",
		UPN: "test@corp.local",
	}
	attrs := buildSyncAttrs(u)

	if attrs["email"] != u.Email {
		t.Errorf("email = %q, want %q", attrs["email"], u.Email)
	}
	if _, ok := attrs["department"]; ok {
		t.Error("attrs must not contain 'department' column (doesn't exist on users table)")
	}
	if attrs["job_title"] != u.Title {
		t.Errorf("job_title = %q, want %q", attrs["job_title"], u.Title)
	}
	if attrs["phone"] != u.Phone {
		t.Errorf("phone = %q, want %q", attrs["phone"], u.Phone)
	}
}

func TestRunCycleLogsSyncFailure(t *testing.T) {
	var logs bytes.Buffer
	worker := NewSyncWorker(nil, nil,
		slog.New(slog.NewTextHandler(&logs, nil)), 15)
	worker.client = &fakeADDirectory{connectErr: errors.New("directory unavailable")}
	worker.runCycle(context.Background())

	if got := logs.String(); !strings.Contains(got, "AD sync cycle failed") ||
		!strings.Contains(got, "directory unavailable") {
		t.Fatalf("cycle failure was silent: %q", got)
	}
}

func TestRunExecutesPeriodicCycleBeforeCancellation(t *testing.T) {
	worker := NewSyncWorker(nil, nil, slog.Default(), 15)
	worker.client = &fakeADDirectory{connectErr: errors.New("directory unavailable")}
	worker.interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	worker.Run(ctx)
}

func TestBuildSyncAttrsExcludesEmptyFields(t *testing.T) {
	u := ADUser{Email: "test@corp.local"}
	attrs := buildSyncAttrs(u)

	emptyFields := []string{"job_title", "phone", "krb5_principal"}
	for _, f := range emptyFields {
		if attrs[f] != "" {
			t.Errorf("empty field %q should be empty in attrs, got %q", f, attrs[f])
		}
	}
}

func TestADUserProxyAddresses(t *testing.T) {
	u := ADUser{ProxyAddresses: []string{"smtp:alias@corp.local", "X400:something"}}
	if len(u.ProxyAddresses) != 2 {
		t.Errorf("expected 2 proxy addresses, got %d", len(u.ProxyAddresses))
	}
}

func TestParseProxyAliases(t *testing.T) {
	tests := []struct {
		name    string
		proxies []string
		primary string
		want    []string
	}{
		{
			name:    "secondary smtp address becomes an alias",
			proxies: []string{"smtp:alias@corp.local"},
			primary: "user@corp.local",
			want:    []string{"alias@corp.local"},
		},
		{
			name:    "primary SMTP entry matching the user's email is dropped",
			proxies: []string{"SMTP:user@corp.local", "smtp:alias@corp.local"},
			primary: "user@corp.local",
			want:    []string{"alias@corp.local"},
		},
		{
			name:    "uppercase SMTP prefix for a non-primary address is kept",
			proxies: []string{"SMTP:Boss@corp.local"},
			primary: "user@corp.local",
			want:    []string{"boss@corp.local"},
		},
		{
			name:    "non-SMTP proxy types are skipped",
			proxies: []string{"X400:c=US;a= ;p=Corp;o=Ex", "X500:/o=corp/cn=user", "sip:user@corp.local"},
			primary: "user@corp.local",
			want:    nil,
		},
		{
			name:    "addresses are lowercased",
			proxies: []string{"smtp:Alias@Corp.Local"},
			primary: "user@corp.local",
			want:    []string{"alias@corp.local"},
		},
		{
			name:    "duplicates collapse to one",
			proxies: []string{"smtp:alias@corp.local", "SMTP:alias@corp.local", "smtp:ALIAS@CORP.LOCAL"},
			primary: "user@corp.local",
			want:    []string{"alias@corp.local"},
		},
		{
			name:    "primary match is case-insensitive",
			proxies: []string{"smtp:USER@CORP.LOCAL"},
			primary: "user@corp.local",
			want:    nil,
		},
		{
			name:    "malformed entries are skipped",
			proxies: []string{"smtp:", "smtp:noatsign", "smtp:two@@at.local", "smtp:trailing@", "smtp:@noLocal.local", "smtp:a@b@c.local"},
			primary: "user@corp.local",
			want:    nil,
		},
		{
			name:    "mixed bag yields only valid distinct SMTP aliases in order",
			proxies: []string{"SMTP:user@corp.local", "X400:junk", "smtp:sales@corp.local", "smtp:support@corp.local", "smtp:sales@corp.local"},
			primary: "user@corp.local",
			want:    []string{"sales@corp.local", "support@corp.local"},
		},
		{
			name:    "empty input yields nothing",
			proxies: nil,
			primary: "user@corp.local",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseProxyAliases(tt.proxies, tt.primary)
			if len(got) != len(tt.want) {
				t.Fatalf("parseProxyAliases() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseProxyAliases()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestNormalizedADSyncStagesImmutableSubjectAndAdvancesCursor(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ad-normalized-" + suffix + ".local"
	sourceKey := "ad:test-" + suffix
	subject := uuid.New().String()
	email := "person@" + domain

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`,
		domain,
	); err != nil {
		t.Fatalf("create AD normalized domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'ad','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')`,
		sourceKey, "AD normalized "+suffix,
	); err != nil {
		t.Fatalf("create AD identity source: %v", err)
	}

	fake := &fakeADDirectory{
		maxUSN: 42,
		users: []ADUser{{
			ObjectGUID: subject, Email: email, DisplayName: "AD Person",
			FirstName: "AD", LastName: "Person", Department: "Platform",
			UPN: "person@" + domain, USNChanged: 42,
		}},
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = fake
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("normalized AD sync: %v", err)
	}
	if result.Checked != 1 || result.Updated != 1 || result.Errors != 0 {
		t.Fatalf("normalized AD result=%+v", result)
	}

	var gotSubject, authority string
	var enabled bool
	var cursor string
	if err := pool.QueryRow(ctx, `
		SELECT l.external_subject,a.authority_kind,u.enabled,
		       s.committed_cursor->>'usn'
		  FROM identity_sources s
		  JOIN user_identity_links l ON l.source_id=s.id
		  JOIN users u ON u.id=l.user_id
		  JOIN user_lifecycle_authorities a ON a.user_id=u.id
		 WHERE s.source_key=$1`,
		sourceKey,
	).Scan(&gotSubject, &authority, &enabled, &cursor); err != nil {
		t.Fatalf("read normalized AD result: %v", err)
	}
	if gotSubject != subject || authority != "source" || !enabled || cursor != "42" {
		t.Fatalf("normalized AD state subject=%q authority=%q enabled=%v cursor=%q",
			gotSubject, authority, enabled, cursor)
	}

	fake.users[0].Disabled = true
	fake.users[0].USNChanged = 43
	fake.maxUSN = 43
	result, err = worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("normalized AD disable sync: %v", err)
	}
	if result.Updated != 1 {
		t.Fatalf("normalized AD disable result=%+v", result)
	}
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM users WHERE email=$1`,
		email,
	).Scan(&enabled); err != nil {
		t.Fatalf("read disabled AD user: %v", err)
	}
	if enabled {
		t.Fatal("normalized AD disable did not disable the linked person")
	}
}

func TestNormalizedADSyncChunksLargeDiscoveryWithoutAdvancingEarly(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ad-large-" + suffix + ".local"
	sourceKey := "ad:large-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO domains(name,is_local) VALUES($1,TRUE)`, domain); err != nil {
		t.Fatalf("create large AD domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'ad',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey, "AD large "+suffix,
	); err != nil {
		t.Fatalf("create large AD source: %v", err)
	}

	users := make([]ADUser, identitysource.MaxEntries+1)
	for i := range users {
		users[i] = ADUser{
			ObjectGUID:  uuid.NewString(),
			Email:       fmt.Sprintf("person-%03d@%s", i, domain),
			DisplayName: fmt.Sprintf("Person %03d", i),
			USNChanged:  int64(i + 1),
		}
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeADDirectory{users: users, maxUSN: int64(len(users))}
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("large normalized AD sync: %v", err)
	}
	if result.Checked != len(users) || result.Updated != len(users) || result.Errors != 0 {
		t.Fatalf("large normalized AD result=%+v", result)
	}

	var sourceID int64
	var cursor string
	if err := pool.QueryRow(ctx,
		`SELECT id,committed_cursor->>'usn' FROM identity_sources WHERE source_key=$1`,
		sourceKey,
	).Scan(&sourceID, &cursor); err != nil {
		t.Fatalf("read large AD cursor: %v", err)
	}
	var links, batches, staleCursorBatches int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM user_identity_links
			  WHERE source_id=$1 AND state='active'),
			(SELECT count(*) FROM identity_source_batches WHERE source_id=$1),
			(SELECT count(*) FROM identity_source_batches
			  WHERE source_id=$1 AND remote_cursor->>'usn'='0')
	`, sourceID).Scan(&links, &batches, &staleCursorBatches); err != nil {
		t.Fatalf("read large AD batches: %v", err)
	}
	if cursor != strconv.Itoa(len(users)) || links != len(users) {
		t.Fatalf("large AD cursor=%q links=%d, want cursor=%d links=%d",
			cursor, links, len(users), len(users))
	}
	if batches != 4 || staleCursorBatches != 3 {
		t.Fatalf("large AD batches=%d old-cursor batches=%d, want 4 and 3",
			batches, staleCursorBatches)
	}
}

func TestNormalizedADSyncPreservesCursorOnEmptyDelta(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	sourceKey := "ad:empty-delta-" + randSuffix(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state,
			committed_cursor,committed_cursor_digest
		)
		VALUES($1,'AD empty delta','ad',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active','{"usn":"77"}'::jsonb,digest('{"usn":"77"}','sha256'))`,
		sourceKey,
	); err != nil {
		t.Fatalf("create empty-delta source: %v", err)
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeADDirectory{}
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("empty normalized AD delta: %v", err)
	}
	var cursor string
	if err := pool.QueryRow(ctx,
		`SELECT committed_cursor->>'usn' FROM identity_sources WHERE source_key=$1`,
		sourceKey,
	).Scan(&cursor); err != nil {
		t.Fatalf("read empty-delta cursor: %v", err)
	}
	if cursor != "77" {
		t.Fatalf("empty delta regressed cursor to %q, want 77", cursor)
	}
}

func TestNormalizedADDeltaKeepsUnchangedManagerAuthority(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ad-manager-delta-" + suffix + ".local"
	sourceKey := "ad:manager-delta-" + suffix
	managerSubject := uuid.NewString()
	employeeSubject := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO domains(name,is_local) VALUES($1,TRUE)`, domain); err != nil {
		t.Fatalf("create manager-delta domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,'AD manager delta','ad',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey,
	); err != nil {
		t.Fatalf("create manager-delta source: %v", err)
	}
	fake := &fakeADDirectory{
		maxUSN: 10,
		users: []ADUser{
			{
				ObjectGUID: managerSubject, Email: "manager@" + domain,
				DisplayName: "Manager", USNChanged: 9,
			},
			{
				ObjectGUID: employeeSubject, Email: "employee@" + domain,
				DisplayName: "Employee", ManagerSubject: managerSubject, USNChanged: 10,
			},
		},
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = fake
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("initial manager sync: %v", err)
	}

	fake.users = []ADUser{{
		ObjectGUID: employeeSubject, Email: "employee@" + domain,
		DisplayName: "Employee Changed", ManagerSubject: managerSubject, USNChanged: 11,
	}}
	fake.maxUSN = 11
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("employee-only manager delta: %v", err)
	}

	var gotManagerSubject string
	if err := pool.QueryRow(ctx, `
		SELECT manager_link.external_subject
		  FROM identity_sources s
		  JOIN user_identity_links employee_link
		    ON employee_link.source_id=s.id
		   AND employee_link.external_subject=$2
		  JOIN users employee ON employee.id=employee_link.user_id
		  JOIN user_identity_links manager_link
		    ON manager_link.user_id=employee.manager_id
		   AND manager_link.source_id=s.id
		 WHERE s.source_key=$1
	`, sourceKey, employeeSubject).Scan(&gotManagerSubject); err != nil {
		t.Fatalf("read employee manager after delta: %v", err)
	}
	if gotManagerSubject != managerSubject {
		t.Fatalf("manager subject after employee-only delta=%q, want %q",
			gotManagerSubject, managerSubject)
	}
}

func TestNormalizedADSyncResumesUnfinishedBatchBeforeDiscovery(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ad-recovery-" + suffix + ".local"
	sourceKey := "ad:recovery-" + suffix
	subject := uuid.NewString()
	batchID := uuid.New()
	crashedInstance := uuid.New()
	store := identitysource.NewStore(pool)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`,
		domain,
	); err != nil {
		t.Fatalf("create AD recovery domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'ad',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey, "AD recovery "+suffix,
	); err != nil {
		t.Fatalf("create AD recovery source: %v", err)
	}
	source, err := store.SourceByKey(ctx, sourceKey)
	if err != nil {
		t.Fatalf("load AD recovery source: %v", err)
	}
	if acquired, err := store.AcquireLease(ctx, source, crashedInstance); err != nil || !acquired {
		t.Fatalf("acquire crashed AD lease acquired=%v err=%v", acquired, err)
	}
	page := identitysource.Page{
		BatchID: batchID,
		Cursor:  json.RawMessage(`{"usn":"77"}`),
		Entries: []identitysource.Entry{{
			ObjectKey:        subject,
			ImmutableSubject: subject,
			Payload: json.RawMessage(fmt.Sprintf(
				`{"operation":"upsert","email":"person@%s","displayName":"Recovered AD","enabled":true,"cursorValue":"77"}`,
				domain,
			)),
		}},
	}
	if err := store.Begin(ctx, source, page, crashedInstance); err != nil {
		t.Fatalf("stage crashed AD batch: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE identity_source_leases
		   SET heartbeat_at=statement_timestamp()-interval '2 minutes',
		       lease_until=statement_timestamp()-interval '1 minute'
		 WHERE source_id=$1`,
		source.ID,
	); err != nil {
		t.Fatalf("expire crashed AD lease: %v", err)
	}

	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeADDirectory{connectErr: errors.New("recovery must precede AD discovery")}
	worker.SetIdentitySource(store, sourceKey)
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("resume crashed AD batch: %v", err)
	}
	if result.Checked != 1 || result.Updated != 1 || result.Errors != 0 {
		t.Fatalf("AD recovery result=%+v", result)
	}

	var state, cursor string
	var applied int
	if err := pool.QueryRow(ctx, `
		SELECT b.state,b.applied_count,s.committed_cursor->>'usn'
		  FROM identity_source_batches b
		  JOIN identity_sources s ON s.id=b.source_id
		 WHERE b.source_id=$1 AND b.batch_id=$2`,
		source.ID, batchID,
	).Scan(&state, &applied, &cursor); err != nil {
		t.Fatalf("read recovered AD batch: %v", err)
	}
	if state != "completed" || applied != 1 || cursor != "77" {
		t.Fatalf("recovered AD batch state=%q applied=%d cursor=%q", state, applied, cursor)
	}
}

func TestNormalizedADSyncFailsClosedAtEachExternalBoundary(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	enableIdentityModelForADTest(t, pool)
	ctx := context.Background()
	store := identitysource.NewStore(pool)
	logger := testLogger()

	missing := NewSyncWorker(nil, pool, logger, 15)
	missing.client = &fakeADDirectory{}
	missing.SetIdentitySource(store, "ad:missing-"+randSuffix(t))
	if _, err := missing.SyncNow(ctx); err == nil || !strings.Contains(err.Error(), "load AD identity source") {
		t.Fatalf("missing source error=%v", err)
	}

	newSource := func(name string, cursor string) string {
		t.Helper()
		key := "ad:" + name + "-" + randSuffix(t)
		cursorColumns := ""
		cursorValues := ""
		args := []any{key, "AD boundary " + name}
		if cursor != "" {
			cursorColumns = ",committed_cursor,committed_cursor_digest"
			cursorValues = ",$3::jsonb,digest($3::text,'sha256')"
			args = append(args, cursor)
		}
		query := `INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state` + cursorColumns + `)
			VALUES($1,$2,'ad',
			'{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active'` + cursorValues + `)`
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("create %s source: %v", name, err)
		}
		return key
	}
	run := func(key string, fake *fakeADDirectory) (SyncResult, error) {
		t.Helper()
		worker := NewSyncWorker(nil, pool, logger, 15)
		worker.client = fake
		worker.SetIdentitySource(store, key)
		return worker.SyncNow(ctx)
	}

	if _, err := run(newSource("cursor-shape", `[]`), &fakeADDirectory{}); err == nil ||
		!strings.Contains(err.Error(), "decode AD committed cursor") {
		t.Fatalf("cursor shape error=%v", err)
	}
	if _, err := run(newSource("cursor-usn", `{"usn":"not-a-number"}`), &fakeADDirectory{}); err == nil ||
		!strings.Contains(err.Error(), "decode AD committed uSNChanged") {
		t.Fatalf("cursor USN error=%v", err)
	}
	boundary := []struct {
		name string
		fake *fakeADDirectory
	}{
		{"connect", &fakeADDirectory{connectErr: fmt.Errorf("connect failed")}},
		{"bind", &fakeADDirectory{bindErr: fmt.Errorf("bind failed")}},
		{"search", &fakeADDirectory{searchErr: fmt.Errorf("search failed")}},
	}
	for _, tc := range boundary {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := run(newSource(tc.name, ""), tc.fake); err == nil {
				t.Fatalf("%s boundary unexpectedly succeeded", tc.name)
			}
		})
	}

	// Mirror of ldapsync's med-shard2-012 adjudication: a missing immutable
	// subject and an in-scope upsert without a usable mail address are
	// skip-and-QUARANTINE classes, not page-fatal errors. The page SUCCEEDS
	// (nothing staged, cursor advances) and the skip is durably accounted in
	// identity_source_quarantines through the worker-wired
	// directorysync.PgxQuarantineStore BEFORE the cursor is acknowledged.
	quarantinedPage := func(name, key string, fake *fakeADDirectory, objectKey, reasonCode string) {
		t.Helper()
		result, err := run(key, fake)
		if err != nil {
			t.Fatalf("%s must skip-and-quarantine, not fail the page: %v", name, err)
		}
		if result.Skipped != 1 || result.Updated != 0 || result.Errors != 0 {
			t.Fatalf("%s result=%+v, want one quarantined skip and no staged entries", name, result)
		}
		source, err := store.SourceByKey(ctx, key)
		if err != nil {
			t.Fatalf("load %s source for quarantine check: %v", name, err)
		}
		var occurrences int
		if err := pool.QueryRow(ctx, `
			SELECT occurrences FROM identity_source_quarantines
			 WHERE source_id=$1 AND object_key=$2 AND reason_code=$3`,
			source.ID, objectKey, reasonCode,
		).Scan(&occurrences); err != nil {
			t.Fatalf("%s must persist a durable quarantine record: %v", name, err)
		}
		if occurrences != 1 {
			t.Fatalf("%s quarantine occurrences=%d, want 1", name, occurrences)
		}
	}

	quarantinedPage("missing immutable subject", newSource("subject", ""),
		&fakeADDirectory{
			users: []ADUser{{Email: "person@example.invalid"}},
		},
		// No subject and no relation key: the ledger key is the engine's
		// digest form, "digest:" + SHA-256 of the empty key.
		"digest:"+fmt.Sprintf("%x", sha256.Sum256(nil)),
		directorysync.QuarantineMissingSubject)

	leaseKey := newSource("lease-held", "")
	source, err := store.SourceByKey(ctx, leaseKey)
	if err != nil {
		t.Fatalf("load lease test source: %v", err)
	}
	holder := uuid.New()
	acquired, err := store.AcquireLease(ctx, source, holder)
	if err != nil || !acquired {
		t.Fatalf("hold AD source lease acquired=%v err=%v", acquired, err)
	}
	worker := NewSyncWorker(nil, pool, logger, 15)
	worker.client = &fakeADDirectory{}
	worker.SetIdentitySource(store, leaseKey)
	result, err := worker.SyncNow(ctx)
	if err != nil || result.Skipped != 1 {
		t.Fatalf("contended AD source result=%+v err=%v", result, err)
	}
	if err := store.ReleaseLease(ctx, source, holder); err != nil {
		t.Fatalf("release AD source lease: %v", err)
	}

	badGUID := uuid.NewString()
	quarantinedPage("invalid address", newSource("apply-rejected", ""),
		&fakeADDirectory{
			maxUSN: 1,
			users: []ADUser{{
				ObjectGUID: badGUID, Email: "not-an-address", USNChanged: 1,
			}},
		},
		badGUID, directorysync.QuarantineNoUsableMail)
}

// --- DB-gated integration tests for syncProxyAliases ---

// testPool returns a pool connected to the local dev database.
// Skips the test if DB_DSN is not set (matches other AD/device integration tests).
func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func enableIdentityModelForADTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
}

func testLogger() *slog.Logger {
	return testsupport.TestLogger()
}

// requireAliasSchema skips the test if the tables syncProxyAliases touches
// (domains, users, mailboxes, aliases) are not all present.
func requireAliasSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM information_schema.tables
		 WHERE table_schema = 'public'
		   AND table_name IN ('domains', 'users', 'mailboxes', 'aliases')`,
	).Scan(&count); err != nil || count < 4 {
		t.Skip("alias schema not applied (need domains/users/mailboxes/aliases)")
	}
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// seedAliasFixture creates a local domain, a user, and that user's primary
// mailbox, returning the user id and the domain name. All rows are cleaned up
// on test completion.
func seedAliasFixture(t *testing.T, pool *pgxpool.Pool) (userID int64, domain string) {
	t.Helper()
	ctx := context.Background()
	suffix := randSuffix(t)
	domain = "adtest-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	email := "user-" + suffix + "@" + domain
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, lower($2), 'AD Test User', $3, '$2a$10$placeholder')
		 RETURNING id`,
		"user-"+suffix, email, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		 VALUES ($1, $2, $3, $3, 'personal', TRUE)
		 RETURNING id`,
		userID, domainID, email,
	).Scan(&mailboxID); err != nil {
		t.Fatalf("insert mailbox: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM aliases WHERE mailbox_id = $1`, mailboxID)
		pool.Exec(c, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})
	return userID, domain
}

func aliasEmails(t *testing.T, pool *pgxpool.Pool, userID int64) []string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT a.email FROM aliases a
		 JOIN mailboxes m ON m.id = a.mailbox_id
		 WHERE m.user_id = $1 ORDER BY a.email`, userID)
	if err != nil {
		t.Fatalf("query aliases: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan alias: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestSyncProxyAliasesPopulatesAndSkips(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	userID, domain := seedAliasFixture(t, pool)
	primary := "user@" + domain // not the real fixture email — irrelevant, primary is matched in parse only

	w := &SyncWorker{pool: pool, logger: testLogger()}
	u := ADUser{
		Email: primary,
		ProxyAddresses: []string{
			"SMTP:user@" + domain,          // primary form — but doesn't match the fixture's actual email; still a valid alias candidate
			"smtp:sales@" + domain,         // local secondary → should land
			"smtp:support@" + domain,       // local secondary → should land
			"X400:c=US;a= ;p=Corp",         // non-SMTP → skipped
			"smtp:remote@external.invalid", // non-local domain → skipped (logged)
		},
	}
	var aliasResult SyncResult
	w.syncProxyAliases(context.Background(), userID, u, &aliasResult)

	got := aliasEmails(t, pool, userID)
	// "user@domain" matches u.Email primary so it's filtered by parse; remote is non-local.
	want := map[string]bool{"sales@" + domain: true, "support@" + domain: true}
	if len(got) != len(want) {
		t.Fatalf("aliases = %v, want exactly %v", got, want)
	}
	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected alias %q landed", e)
		}
		// Verify mailbox_id and domain_id are correct on each row.
		var mbUser int64
		var dName string
		if err := pool.QueryRow(context.Background(),
			`SELECT m.user_id, d.name FROM aliases a
			 JOIN mailboxes m ON m.id = a.mailbox_id
			 JOIN domains d ON d.id = a.domain_id
			 WHERE a.email = $1`, e,
		).Scan(&mbUser, &dName); err != nil {
			t.Fatalf("verify alias %q: %v", e, err)
		}
		if mbUser != userID {
			t.Errorf("alias %q mailbox belongs to user %d, want %d", e, mbUser, userID)
		}
		if dName != domain {
			t.Errorf("alias %q domain_id resolves to %q, want %q", e, dName, domain)
		}
	}
}

func TestSyncProxyAliasesIdempotent(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	userID, domain := seedAliasFixture(t, pool)

	w := &SyncWorker{pool: pool, logger: testLogger()}
	u := ADUser{
		Email:          "user@" + domain,
		ProxyAddresses: []string{"smtp:sales@" + domain, "smtp:support@" + domain},
	}

	var idemResult SyncResult
	w.syncProxyAliases(context.Background(), userID, u, &idemResult)
	first := aliasEmails(t, pool, userID)
	w.syncProxyAliases(context.Background(), userID, u, &idemResult) // re-sync
	second := aliasEmails(t, pool, userID)

	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("expected 2 aliases on each pass, got first=%v second=%v", first, second)
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("re-sync changed aliases: first=%v second=%v", first, second)
		}
	}
}

// TestUpsertUserCreateCanonicalizesAddresses is the writer-canonical regression
// for the AD CREATE path: a directory user arriving with a TAB-prefixed,
// mixed-case email AND a mixed-case UPN must land in users.email / users.ad_upn
// in EXACTLY Go's canonical form (trim + ASCII-fold), not verbatim — so the
// canonicalizing matcher can never match-miss the row (the silent-lockout class).
// This is the behavioral proof of the CanonicalAddress write boundary on the
// create path (identity.ProvisionAccount).
func TestUpsertUserCreateCanonicalizesAddresses(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	// A fresh random UUID for the AD object guid (the create-path stable key).
	var objectGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&objectGUID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}

	var userID int64
	t.Cleanup(func() {
		c := context.Background()
		if userID != 0 {
			pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
			pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		}
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}
	// Non-canonical AD attributes: a leading TAB + mixed case on BOTH the email
	// and the UPN. The matcher would canonicalize its lookup input, so a verbatim
	// store would silently fail to resolve this person.
	// Package-unique local-part vs ldapsync/sync_test.go's identically-named
	// test (see that file): the derived username carries a cross-domain UNIQUE,
	// so a shared local-part races the two package binaries in parallel. Use
	// "ad-alice.smith" here, "ldap-alice.smith" there.
	u := ADUser{
		ObjectGUID:  objectGUID,
		Email:       "\tAd-Alice.Smith@" + strings.ToUpper(domain),
		DisplayName: "Alice Smith",
		UPN:         "\tAd-Alice.Smith@" + strings.ToUpper(domain),
		USNChanged:  1,
	}
	var result SyncResult
	if err := w.upsertUser(ctx, u, false, false, &result); err != nil {
		t.Fatalf("upsertUser: %v", err)
	}
	if result.Created != 1 {
		t.Fatalf("expected Created=1, got %+v", result)
	}

	var gotEmail, gotUPN string
	if err := pool.QueryRow(ctx,
		`SELECT id, email, COALESCE(ad_upn, '') FROM users WHERE ad_object_guid = $1`, objectGUID,
	).Scan(&userID, &gotEmail, &gotUPN); err != nil {
		t.Fatalf("read back user: %v", err)
	}

	wantCanon := "ad-alice.smith@" + domain // trim + ASCII-fold of the TAB/upper input
	if gotEmail != wantCanon {
		t.Errorf("stored users.email = %q, want canonical %q", gotEmail, wantCanon)
	}
	if gotUPN != wantCanon {
		t.Errorf("stored users.ad_upn = %q, want canonical %q", gotUPN, wantCanon)
	}
}

// TestManagerIDTwoPass verifies that resolveManagerIDs sets users.manager_id when
// user A's ManagerDN equals user B's DN (in the sync set), and leaves it NULL when
// the manager DN is outside the sync scope.
func TestManagerIDTwoPass(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-mgr-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var mgrGUID, empGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&mgrGUID); err != nil {
		t.Fatalf("gen mgr guid: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&empGUID); err != nil {
		t.Fatalf("gen emp guid: %v", err)
	}

	mgrDN := "CN=Manager-" + suffix + ",OU=Users,DC=corp,DC=local"
	empDN := "CN=Employee-" + suffix + ",OU=Users,DC=corp,DC=local"
	outsideDN := "CN=Outside-" + suffix + ",OU=Other,DC=corp,DC=local"

	var mgrID, empID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, ad_object_guid, password_hash)
		 VALUES ($1, $2, $3, $4, $5, '$2a$10$placeholder') RETURNING id`,
		"mgr-"+suffix, "mgr-"+suffix+"@"+domain, "Manager "+suffix, domainID, mgrGUID,
	).Scan(&mgrID); err != nil {
		t.Fatalf("insert manager: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, ad_object_guid, password_hash)
		 VALUES ($1, $2, $3, $4, $5, '$2a$10$placeholder') RETURNING id`,
		"emp-"+suffix, "emp-"+suffix+"@"+domain, "Employee "+suffix, domainID, empGUID,
	).Scan(&empID); err != nil {
		t.Fatalf("insert employee: %v", err)
	}

	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, empID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, mgrID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Pass 1: A's manager is B (in scope). ManagerDN is UPPER-CASE to prove
	// normalizeDN lowercases both sides and the match holds across case.
	users := []ADUser{
		{ObjectGUID: empGUID, DN: empDN, ManagerDN: strings.ToUpper(mgrDN)},
		{ObjectGUID: mgrGUID, DN: mgrDN, ManagerDN: ""},
	}
	w.resolveManagerIDs(ctx, users)

	var gotMgrID *int64
	if err := pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, empID,
	).Scan(&gotMgrID); err != nil {
		t.Fatalf("query manager_id: %v", err)
	}
	if gotMgrID == nil || *gotMgrID != mgrID {
		t.Errorf("manager_id for employee = %v, want %d (case-insensitive DN match failed)", gotMgrID, mgrID)
	}

	// Manager's own manager_id should be NULL (no ManagerDN in sync set).
	var mgrMgrID *int64
	if err := pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, mgrID,
	).Scan(&mgrMgrID); err != nil {
		t.Fatalf("query manager's manager_id: %v", err)
	}
	if mgrMgrID != nil {
		t.Errorf("manager's manager_id should be NULL, got %d", *mgrMgrID)
	}

	// Re-sync clears stale manager_id: employee's manager is now outside scope.
	// No manual reset — the bulk-clear in resolveManagerIDs must wipe the stale link.
	w.resolveManagerIDs(ctx, []ADUser{
		{ObjectGUID: empGUID, DN: empDN, ManagerDN: outsideDN},
		{ObjectGUID: mgrGUID, DN: mgrDN, ManagerDN: ""},
	})
	if err := pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, empID,
	).Scan(&gotMgrID); err != nil {
		t.Fatalf("query manager_id after re-sync: %v", err)
	}
	if gotMgrID != nil {
		t.Errorf("re-sync must clear stale manager_id, got %d", *gotMgrID)
	}

	// Outside-scope: employee's ManagerDN not in the set → manager_id stays NULL.
	pool.Exec(ctx, `UPDATE users SET manager_id = NULL WHERE id = $1`, empID)
	w.resolveManagerIDs(ctx, []ADUser{
		{ObjectGUID: empGUID, DN: empDN, ManagerDN: outsideDN},
	})
	if err := pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, empID,
	).Scan(&gotMgrID); err != nil {
		t.Fatalf("query manager_id outside scope: %v", err)
	}
	if gotMgrID != nil {
		t.Errorf("manager_id should be NULL for outside-scope manager, got %d", *gotMgrID)
	}
}

// TestUpsertUserDisablePath is the deprovisioning regression: a directory user
// flagged disabled must end with users.enabled = FALSE and zero live sessions,
// and the run must count it as Disabled (not silently succeed while the writes
// were swallowed — the pre-fix AD behavior). Mirrors ldapsync's twin.
func TestUpsertUserDisablePath(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-dis-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	var objectGUID string
	if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::TEXT`).Scan(&objectGUID); err != nil {
		t.Fatalf("gen uuid: %v", err)
	}

	var userID int64
	t.Cleanup(func() {
		c := context.Background()
		if userID != 0 {
			pool.Exec(c, `DELETE FROM sessions WHERE user_id = $1`, userID)
			pool.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, userID)
			pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		}
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Create the user (enabled) via the create path.
	u := ADUser{
		ObjectGUID:  objectGUID,
		Email:       "ad-disable-" + suffix + "@" + domain,
		DisplayName: "AD Disable Test",
		UPN:         "ad-disable-" + suffix + "@" + domain,
		USNChanged:  1,
	}
	var create SyncResult
	if err := w.upsertUser(ctx, u, false, false, &create); err != nil {
		t.Fatalf("create upsert: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE ad_object_guid = $1`, objectGUID).Scan(&userID); err != nil {
		t.Fatalf("read back user: %v", err)
	}

	// Give the user a live session, then disable via a second sync.
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')`, userID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	u.Disabled = true
	var result SyncResult
	if err := w.upsertUser(ctx, u, false, false, &result); err != nil {
		t.Fatalf("disable upsert: %v", err)
	}
	if result.Disabled != 1 {
		t.Errorf("result.Disabled = %d, want 1", result.Disabled)
	}

	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM users WHERE id = $1`, userID).Scan(&enabled); err != nil {
		t.Fatalf("read enabled: %v", err)
	}
	if enabled {
		t.Error("disabled directory user still has users.enabled = TRUE")
	}

	var sessionCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&sessionCount); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessionCount != 0 {
		t.Errorf("disabled user still has %d live session(s), want 0", sessionCount)
	}
}

func TestSyncProxyAliasesNoPrimaryMailbox(t *testing.T) {
	pool := testPool(t)
	requireAliasSchema(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "adtest-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash)
		 VALUES ($1, $2, 'No Mailbox', $3, '$2a$10$placeholder') RETURNING id`,
		"nomailbox-"+suffix, "nomailbox-"+suffix+"@"+domain, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, userID)
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}
	u := ADUser{Email: "user@" + domain, ProxyAddresses: []string{"smtp:sales@" + domain}}

	var noMailboxResult SyncResult
	// Must not panic or error the caller; just logs and skips.
	w.syncProxyAliases(ctx, userID, u, &noMailboxResult)

	if got := aliasEmails(t, pool, userID); len(got) != 0 {
		t.Errorf("expected no aliases without a primary mailbox, got %v", got)
	}
}
func TestSetIdentitySourceNilDoesNotCreateTypedNilInterface(t *testing.T) {
	worker := &SyncWorker{}
	worker.SetIdentitySource(nil, "ad:unused")
	if worker.source != nil {
		t.Fatal("nil store must leave normalized source unset")
	}
}
