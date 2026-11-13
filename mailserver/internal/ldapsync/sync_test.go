package ldapsync

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

type fakeLDAPDirectory struct {
	users            []LDAPUser
	subjectAttribute string
	err              error
	connectErr       error
	bindErr          error
	searchErr        error
	lastFilter       string
	lastPageSize     int
	connectCalls     int
}

func (f *fakeLDAPDirectory) Connect() (*ldap.Conn, error) {
	f.connectCalls++
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

func (f *fakeLDAPDirectory) Bind(*ldap.Conn) error {
	if f.bindErr != nil {
		return f.bindErr
	}
	return f.err
}

func (f *fakeLDAPDirectory) SearchUsers(_ *ldap.Conn, filter string, pageSize int) ([]LDAPUser, error) {
	f.lastFilter = filter
	f.lastPageSize = pageSize
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.users, f.err
}

func (f *fakeLDAPDirectory) SubjectAttribute() string { return f.subjectAttribute }

var _ directoryClient = (*fakeLDAPDirectory)(nil)

func TestSyncResultDefaults(t *testing.T) {
	r := SyncResult{}
	if r.Checked != 0 || r.Created != 0 || r.Errors != 0 {
		t.Error("SyncResult zero value should have all counts at 0")
	}
}

func TestSyncResultJSONFields(t *testing.T) {
	r := SyncResult{
		Checked: 10, Created: 2, Updated: 3, Disabled: 1, Skipped: 0, Errors: 0,
	}
	if r.Checked != 10 {
		t.Error("Checked should be 10")
	}
	if r.Created != 2 {
		t.Error("Created should be 2")
	}
	if r.Disabled != 1 {
		t.Error("Disabled should be 1")
	}
}

func TestSyncNowSkipsBeforeDirectoryAccessWhenDisabled(t *testing.T) {
	fake := &fakeLDAPDirectory{connectErr: errors.New("must not connect")}
	worker := NewSyncWorker(nil, nil, testLogger(), 15)
	worker.client = fake
	worker.SetEnabledResolver(func() bool { return false })

	result, err := worker.SyncNow(context.Background())
	if err != nil {
		t.Fatalf("disabled sync: %v", err)
	}
	if result.Skipped != 1 || fake.connectCalls != 0 {
		t.Fatalf("disabled sync result=%+v connectCalls=%d", result, fake.connectCalls)
	}
}

func TestRunCycleLogsSyncFailure(t *testing.T) {
	var logs bytes.Buffer
	worker := NewSyncWorker(nil, nil,
		slog.New(slog.NewTextHandler(&logs, nil)), 15)
	worker.client = &fakeLDAPDirectory{
		subjectAttribute: "entryUUID",
		connectErr:       errors.New("directory unavailable"),
	}
	worker.runCycle(context.Background())

	if got := logs.String(); !strings.Contains(got, "LDAP sync cycle failed") ||
		!strings.Contains(got, "directory unavailable") {
		t.Fatalf("cycle failure was silent: %q", got)
	}
}

func TestRunExecutesPeriodicCycleBeforeCancellation(t *testing.T) {
	worker := NewSyncWorker(nil, nil, slog.Default(), 15)
	worker.client = &fakeLDAPDirectory{
		subjectAttribute: "entryUUID",
		connectErr:       errors.New("directory unavailable"),
	}
	worker.interval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	worker.Run(ctx)
}

func TestNormalizedLDAPSyncStagesImmutableSubjectAndAdvancesCursor(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldap-normalized-" + suffix + ".local"
	sourceKey := "ldap:test-" + suffix
	email := "person@" + domain

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`,
		domain,
	); err != nil {
		t.Fatalf("create LDAP normalized domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,committed_cursor,committed_cursor_digest)
		VALUES($1,$2,'ldap','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active','{"modifyTimestamp":"20260724000000Z"}'::jsonb,
		       digest('{"modifyTimestamp":"20260724000000Z"}','sha256'))`,
		sourceKey, "LDAP normalized "+suffix,
	); err != nil {
		t.Fatalf("create LDAP identity source: %v", err)
	}

	fake := &fakeLDAPDirectory{
		subjectAttribute: "entryUUID",
		users: []LDAPUser{{
			ImmutableSubject: "entry-" + suffix,
			Email:            email, DisplayName: "LDAP Person", FirstName: "LDAP",
			LastName: "Person", Department: "Platform",
			UPN: email, ModifyStamp: "20260725010101Z",
		}},
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = fake
	worker.SetFilter("(objectClass=inetOrgPerson)")
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if !worker.SubjectAttributeConfigured() {
		t.Fatal("normalized LDAP worker lost immutable subject configuration")
	}
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("normalized LDAP sync: %v", err)
	}
	if result.Checked != 1 || result.Updated != 1 || result.Errors != 0 {
		t.Fatalf("normalized LDAP result=%+v", result)
	}
	if fake.lastFilter != "(&(objectClass=inetOrgPerson)(modifyTimestamp>=20260724000000Z))" ||
		fake.lastPageSize != 500 {
		t.Fatalf("LDAP search filter=%q page=%d", fake.lastFilter, fake.lastPageSize)
	}

	var subject, authority, cursor string
	var enabled bool
	if err := pool.QueryRow(ctx, `
		SELECT l.external_subject,a.authority_kind,u.enabled,
		       s.committed_cursor->>'modifyTimestamp'
		  FROM identity_sources s
		  JOIN user_identity_links l ON l.source_id=s.id
		  JOIN users u ON u.id=l.user_id
		  JOIN user_lifecycle_authorities a ON a.user_id=u.id
		 WHERE s.source_key=$1`,
		sourceKey,
	).Scan(&subject, &authority, &enabled, &cursor); err != nil {
		t.Fatalf("read normalized LDAP result: %v", err)
	}
	if subject != "entry-"+suffix || authority != "source" || !enabled ||
		cursor != "20260725010101Z" {
		t.Fatalf("normalized LDAP state subject=%q authority=%q enabled=%v cursor=%q",
			subject, authority, enabled, cursor)
	}

	fake.users[0].Disabled = true
	fake.users[0].ModifyStamp = "20260725020202Z"
	result, err = worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("normalized LDAP disable sync: %v", err)
	}
	if result.Updated != 1 {
		t.Fatalf("normalized LDAP disable result=%+v", result)
	}
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM users WHERE email=$1`,
		email,
	).Scan(&enabled); err != nil {
		t.Fatalf("read disabled LDAP user: %v", err)
	}
	if enabled {
		t.Fatal("normalized LDAP disable did not disable the linked person")
	}
}

func TestNormalizedLDAPSyncChunksLargeDiscovery(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldap-large-" + suffix + ".local"
	sourceKey := "ldap:large-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO domains(name,is_local) VALUES($1,TRUE)`, domain); err != nil {
		t.Fatalf("create large LDAP domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,'LDAP large','ldap',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey,
	); err != nil {
		t.Fatalf("create large LDAP source: %v", err)
	}
	users := make([]LDAPUser, identitysource.MaxEntries+1)
	for i := range users {
		users[i] = LDAPUser{
			ImmutableSubject: uuid.NewString(),
			Email:            fmt.Sprintf("person-%03d@%s", i, domain),
			DisplayName:      fmt.Sprintf("Person %03d", i),
			ModifyStamp:      fmt.Sprintf("20260725%06dZ", i),
		}
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeLDAPDirectory{subjectAttribute: "entryUUID", users: users}
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("large normalized LDAP sync: %v", err)
	}
	if result.Checked != len(users) || result.Updated != len(users) || result.Errors != 0 {
		t.Fatalf("large normalized LDAP result=%+v", result)
	}
	var sourceID int64
	var cursor string
	if err := pool.QueryRow(ctx,
		`SELECT id,committed_cursor->>'modifyTimestamp'
		   FROM identity_sources WHERE source_key=$1`,
		sourceKey,
	).Scan(&sourceID, &cursor); err != nil {
		t.Fatalf("read large LDAP cursor: %v", err)
	}
	var links, batches, oldCursorBatches int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM user_identity_links
			  WHERE source_id=$1 AND state='active'),
			(SELECT count(*) FROM identity_source_batches WHERE source_id=$1),
			(SELECT count(*) FROM identity_source_batches
			  WHERE source_id=$1 AND remote_cursor->>'modifyTimestamp'='')
	`, sourceID).Scan(&links, &batches, &oldCursorBatches); err != nil {
		t.Fatalf("read large LDAP batches: %v", err)
	}
	wantCursor := users[len(users)-1].ModifyStamp
	if cursor != wantCursor || links != len(users) {
		t.Fatalf("large LDAP cursor=%q links=%d, want cursor=%q links=%d",
			cursor, links, wantCursor, len(users))
	}
	if batches != 4 || oldCursorBatches != 3 {
		t.Fatalf("large LDAP batches=%d old-cursor batches=%d, want 4 and 3",
			batches, oldCursorBatches)
	}
}

func TestNormalizedLDAPSyncPreservesCursorOnEmptyDelta(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	sourceKey := "ldap:empty-delta-" + randSuffix(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state,
			committed_cursor,committed_cursor_digest
		)
		VALUES($1,'LDAP empty delta','ldap',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active','{"modifyTimestamp":"20260725010101Z"}'::jsonb,
		       digest('{"modifyTimestamp":"20260725010101Z"}','sha256'))`,
		sourceKey,
	); err != nil {
		t.Fatalf("create LDAP empty-delta source: %v", err)
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("empty normalized LDAP delta: %v", err)
	}
	var cursor string
	if err := pool.QueryRow(ctx,
		`SELECT committed_cursor->>'modifyTimestamp'
		   FROM identity_sources WHERE source_key=$1`,
		sourceKey,
	).Scan(&cursor); err != nil {
		t.Fatalf("read LDAP empty-delta cursor: %v", err)
	}
	if cursor != "20260725010101Z" {
		t.Fatalf("empty LDAP delta regressed cursor to %q", cursor)
	}
}

func TestNormalizedLDAPDeltaKeepsUnchangedManagerAuthority(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldap-manager-delta-" + suffix + ".local"
	sourceKey := "ldap:manager-delta-" + suffix
	managerSubject := "manager-" + suffix
	employeeSubject := "employee-" + suffix
	if _, err := pool.Exec(ctx, `INSERT INTO domains(name,is_local) VALUES($1,TRUE)`, domain); err != nil {
		t.Fatalf("create LDAP manager-delta domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,'LDAP manager delta','ldap',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey,
	); err != nil {
		t.Fatalf("create LDAP manager-delta source: %v", err)
	}
	fake := &fakeLDAPDirectory{
		subjectAttribute: "entryUUID",
		users: []LDAPUser{
			{
				ImmutableSubject: managerSubject, Email: "manager@" + domain,
				DisplayName: "Manager", ModifyStamp: "20260725010101Z",
			},
			{
				ImmutableSubject: employeeSubject, Email: "employee@" + domain,
				DisplayName: "Employee", ManagerSubject: managerSubject,
				ModifyStamp: "20260725010102Z",
			},
		},
	}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = fake
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("initial LDAP manager sync: %v", err)
	}
	fake.users = []LDAPUser{{
		ImmutableSubject: employeeSubject, Email: "employee@" + domain,
		DisplayName: "Employee Changed", ManagerSubject: managerSubject,
		ModifyStamp: "20260725010103Z",
	}}
	if _, err := worker.SyncNow(ctx); err != nil {
		t.Fatalf("employee-only LDAP manager delta: %v", err)
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
		t.Fatalf("read LDAP employee manager after delta: %v", err)
	}
	if gotManagerSubject != managerSubject {
		t.Fatalf("LDAP manager subject after delta=%q, want %q",
			gotManagerSubject, managerSubject)
	}
}

func TestNormalizedLDAPSyncResumesUnfinishedBatchBeforeDiscovery(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldap-recovery-" + suffix + ".local"
	sourceKey := "ldap:recovery-" + suffix
	subject := "entry-" + suffix
	batchID := uuid.New()
	crashedInstance := uuid.New()
	store := identitysource.NewStore(pool)

	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`,
		domain,
	); err != nil {
		t.Fatalf("create LDAP recovery domain: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'ldap',
		       '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		       'active')`,
		sourceKey, "LDAP recovery "+suffix,
	); err != nil {
		t.Fatalf("create LDAP recovery source: %v", err)
	}
	source, err := store.SourceByKey(ctx, sourceKey)
	if err != nil {
		t.Fatalf("load LDAP recovery source: %v", err)
	}
	if acquired, err := store.AcquireLease(ctx, source, crashedInstance); err != nil || !acquired {
		t.Fatalf("acquire crashed LDAP lease acquired=%v err=%v", acquired, err)
	}
	page := identitysource.Page{
		BatchID: batchID,
		Cursor:  json.RawMessage(`{"modifyTimestamp":"20260725030303Z"}`),
		Entries: []identitysource.Entry{{
			ObjectKey:        subject,
			ImmutableSubject: subject,
			Payload: json.RawMessage(fmt.Sprintf(
				`{"operation":"upsert","email":"person@%s","displayName":"Recovered LDAP","enabled":true,"cursorValue":"20260725030303Z"}`,
				domain,
			)),
		}},
	}
	if err := store.Begin(ctx, source, page, crashedInstance); err != nil {
		t.Fatalf("stage crashed LDAP batch: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE identity_source_leases
		   SET heartbeat_at=statement_timestamp()-interval '2 minutes',
		       lease_until=statement_timestamp()-interval '1 minute'
		 WHERE source_id=$1`,
		source.ID,
	); err != nil {
		t.Fatalf("expire crashed LDAP lease: %v", err)
	}

	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = &fakeLDAPDirectory{
		subjectAttribute: "entryUUID",
		connectErr:       errors.New("recovery must precede LDAP discovery"),
	}
	worker.SetIdentitySource(store, sourceKey)
	result, err := worker.SyncNow(ctx)
	if err != nil {
		t.Fatalf("resume crashed LDAP batch: %v", err)
	}
	if result.Checked != 1 || result.Updated != 1 || result.Errors != 0 {
		t.Fatalf("LDAP recovery result=%+v", result)
	}

	var state, cursor string
	var applied int
	if err := pool.QueryRow(ctx, `
		SELECT b.state,b.applied_count,s.committed_cursor->>'modifyTimestamp'
		  FROM identity_source_batches b
		  JOIN identity_sources s ON s.id=b.source_id
		 WHERE b.source_id=$1 AND b.batch_id=$2`,
		source.ID, batchID,
	).Scan(&state, &applied, &cursor); err != nil {
		t.Fatalf("read recovered LDAP batch: %v", err)
	}
	if state != "completed" || applied != 1 || cursor != "20260725030303Z" {
		t.Fatalf("recovered LDAP batch state=%q applied=%d cursor=%q", state, applied, cursor)
	}
}

func TestNormalizedLDAPSyncRejectsMissingOrDuplicateSubjects(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	suffix := randSuffix(t)
	sourceKey := "ldap:reject-" + suffix
	if _, err := pool.Exec(ctx, `
		INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
		VALUES($1,$2,'ldap','{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,'active')`,
		sourceKey, "LDAP reject "+suffix,
	); err != nil {
		t.Fatalf("create LDAP reject source: %v", err)
	}

	fake := &fakeLDAPDirectory{}
	worker := NewSyncWorker(nil, pool, testLogger(), 15)
	worker.client = fake
	worker.SetIdentitySource(identitysource.NewStore(pool), sourceKey)
	if _, err := worker.SyncNow(ctx); err == nil || !strings.Contains(err.Error(), "requires a uniqueness-proven") {
		t.Fatalf("missing configured subject error=%v", err)
	}

	fake.subjectAttribute = "entryUUID"
	fake.users = []LDAPUser{
		{ImmutableSubject: "duplicate", Email: "a@example.invalid"},
		{ImmutableSubject: "duplicate", Email: "b@example.invalid"},
	}
	if _, err := worker.SyncNow(ctx); err == nil || !strings.Contains(err.Error(), "not unique") {
		t.Fatalf("duplicate immutable subject error=%v", err)
	}
}

func TestNormalizedLDAPSyncFailsClosedAtEachExternalBoundary(t *testing.T) {
	pool := testPool(t)
	enableIdentityModelForLDAPTest(t, pool)
	ctx := context.Background()
	store := identitysource.NewStore(pool)
	logger := testLogger()

	missing := NewSyncWorker(nil, pool, logger, 15)
	missing.client = &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	missing.SetIdentitySource(store, "ldap:missing-"+randSuffix(t))
	if _, err := missing.SyncNow(ctx); err == nil || !strings.Contains(err.Error(), "load LDAP identity source") {
		t.Fatalf("missing source error=%v", err)
	}

	newSource := func(name string, cursor string) string {
		t.Helper()
		key := "ldap:" + name + "-" + randSuffix(t)
		cursorColumns := ""
		cursorValues := ""
		args := []any{key, "LDAP boundary " + name}
		if cursor != "" {
			cursorColumns = ",committed_cursor,committed_cursor_digest"
			cursorValues = ",$3::jsonb,digest($3::text,'sha256')"
			args = append(args, cursor)
		}
		query := `INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state` + cursorColumns + `)
			VALUES($1,$2,'ldap',
			'{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			'active'` + cursorValues + `)`
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("create %s source: %v", name, err)
		}
		return key
	}
	run := func(key string, fake *fakeLDAPDirectory) (SyncResult, error) {
		t.Helper()
		worker := NewSyncWorker(nil, pool, logger, 15)
		worker.client = fake
		worker.SetIdentitySource(store, key)
		return worker.SyncNow(ctx)
	}

	if _, err := run(newSource("cursor-shape", `[]`),
		&fakeLDAPDirectory{subjectAttribute: "entryUUID"}); err == nil ||
		!strings.Contains(err.Error(), "decode LDAP committed cursor") {
		t.Fatalf("cursor shape error=%v", err)
	}
	boundary := []struct {
		name string
		fake *fakeLDAPDirectory
	}{
		{"connect", &fakeLDAPDirectory{subjectAttribute: "entryUUID", connectErr: fmt.Errorf("connect failed")}},
		{"bind", &fakeLDAPDirectory{subjectAttribute: "entryUUID", bindErr: fmt.Errorf("bind failed")}},
		{"search", &fakeLDAPDirectory{subjectAttribute: "entryUUID", searchErr: fmt.Errorf("search failed")}},
	}
	for _, tc := range boundary {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := run(newSource(tc.name, ""), tc.fake); err == nil {
				t.Fatalf("%s boundary unexpectedly succeeded", tc.name)
			}
		})
	}

	// Med-shard2-012 adjudication: a missing immutable subject and an in-scope
	// upsert without a usable mail address are skip-and-QUARANTINE classes, not
	// page-fatal errors. The page SUCCEEDS (nothing staged, cursor advances)
	// and the skip is durably accounted in identity_source_quarantines through
	// the worker-wired directorysync.PgxQuarantineStore BEFORE the cursor is
	// acknowledged.
	quarantinedPage := func(name, key string, fake *fakeLDAPDirectory, objectKey, reasonCode string) {
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
		&fakeLDAPDirectory{
			subjectAttribute: "entryUUID",
			users:            []LDAPUser{{Email: "person@example.invalid"}},
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
		t.Fatalf("hold LDAP source lease acquired=%v err=%v", acquired, err)
	}
	worker := NewSyncWorker(nil, pool, logger, 15)
	worker.client = &fakeLDAPDirectory{subjectAttribute: "entryUUID"}
	worker.SetIdentitySource(store, leaseKey)
	result, err := worker.SyncNow(ctx)
	if err != nil || result.Skipped != 1 {
		t.Fatalf("contended LDAP source result=%+v err=%v", result, err)
	}
	if err := store.ReleaseLease(ctx, source, holder); err != nil {
		t.Fatalf("release LDAP source lease: %v", err)
	}

	badSubject := "entry-" + randSuffix(t)
	quarantinedPage("invalid address", newSource("apply-rejected", ""),
		&fakeLDAPDirectory{
			subjectAttribute: "entryUUID",
			users: []LDAPUser{{
				ImmutableSubject: badSubject,
				Email:            "not-an-address", ModifyStamp: "20260725000000Z",
			}},
		},
		badSubject, directorysync.QuarantineNoUsableMail)
}

func testPool(t *testing.T) *pgxpool.Pool {
	return testsupport.OpenTestPool(t)
}

func enableIdentityModelForLDAPTest(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	testsupport.SetFeatureToggleForTest(t, pool, "feature.identity_model_v2", true)
}

func testLogger() *slog.Logger {
	return testsupport.TestLogger()
}

func randSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// TestUpsertUserCreateCanonicalizesAddresses is the writer-canonical regression
// for the LDAP CREATE path: an LDAP user arriving with a TAB-prefixed, mixed-case
// email AND a mixed-case UPN must land in users.email / users.ad_upn in EXACTLY
// Go's canonical form (trim + ASCII-fold), so the canonicalizing matcher can never
// match-miss the row. Behavioral proof of the CanonicalAddress write boundary on
// the LDAP create path (identity.ProvisionAccount).
// TestSearchUsersRequestsManagerAttr ensures the LDAP attr list includes "manager"
// so that LDAPUser.ManagerDN is populated during SearchUsers.
func TestSearchUsersRequestsManagerAttr(t *testing.T) {
	for _, a := range ldapUserAttrs {
		if a == "manager" {
			return
		}
	}
	t.Fatal("ldapUserAttrs must include 'manager' for manager_id two-pass sync")
}

// TestLDAPManagerIDTwoPass verifies resolveManagerIDs sets users.manager_id when
// user A's ManagerDN equals user B's DN, and leaves it NULL for out-of-scope DNs.
func TestLDAPManagerIDTwoPass(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaptest-mgr-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	mgrEmail := "mgr-" + suffix + "@" + domain
	empEmail := "emp-" + suffix + "@" + domain
	mgrDN := "CN=Manager-" + suffix + ",OU=Users,DC=ldap,DC=local"
	empDN := "CN=Employee-" + suffix + ",OU=Users,DC=ldap,DC=local"
	outsideDN := "CN=Outside-" + suffix + ",OU=Other,DC=ldap,DC=local"

	var mgrID, empID int64
	// sync_source='ldap': resolveManagerIDs is anchor/ownership-gated
	// (LDAPSYNC-002) — it rewrites only accounts the LDAP engine provisions.
	// Native-account manager protection is covered by TestManagerPassSkipsNativeAccounts.
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, sync_source)
		 VALUES ($1, $2, $3, $4, '$2a$10$placeholder', 'ldap') RETURNING id`,
		"mgr-"+suffix, mgrEmail, "Manager "+suffix, domainID,
	).Scan(&mgrID); err != nil {
		t.Fatalf("insert manager: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, domain_id, password_hash, sync_source)
		 VALUES ($1, $2, $3, $4, '$2a$10$placeholder', 'ldap') RETURNING id`,
		"emp-"+suffix, empEmail, "Employee "+suffix, domainID,
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

	users := []LDAPUser{
		{DN: empDN, Email: empEmail, ManagerDN: mgrDN},
		{DN: mgrDN, Email: mgrEmail, ManagerDN: ""},
	}
	w.resolveManagerIDs(ctx, users)

	var gotMgrID *int64
	if err := pool.QueryRow(ctx,
		`SELECT manager_id FROM users WHERE id = $1`, empID,
	).Scan(&gotMgrID); err != nil {
		t.Fatalf("query manager_id: %v", err)
	}
	if gotMgrID == nil || *gotMgrID != mgrID {
		t.Errorf("manager_id for employee = %v, want %d", gotMgrID, mgrID)
	}

	// Outside-scope manager: no update, stays NULL.
	pool.Exec(ctx, `UPDATE users SET manager_id = NULL WHERE id = $1`, empID)
	w.resolveManagerIDs(ctx, []LDAPUser{
		{DN: empDN, Email: empEmail, ManagerDN: outsideDN},
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

func TestUpsertUserCreateCanonicalizesAddresses(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldaptest-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	// Package-unique local-part: ad/sync_test.go has an identically-NAMED test
	// writing into the SAME shared mailserver_test DB. The derived username
	// (email local-part) carries a cross-domain UNIQUE, so a shared local-part
	// races the two package test binaries when they run in parallel. Keep them
	// disjoint ("ldap-alice.smith" here vs "ad-alice.smith" there).
	local := "ldap-alice.smith"
	canon := local + "@" + domain
	var userID int64
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}
	// Trim+fold fixture: surrounding whitespace + mixed case exercise
	// CanonicalizeAddress's trim + ASCII-fold on BOTH the email and the UPN.
	// The formerly-used leading TAB is deliberately NOT usable here anymore:
	// the LDAPSYNC-006 printable-ASCII ingress floor refuses control
	// characters before canonicalization (pinned right below).
	u := LDAPUser{
		Email:       " Ldap-Alice.Smith@" + strings.ToUpper(domain) + " ",
		DisplayName: "Alice Smith",
		UPN:         " Ldap-Alice.Smith@" + strings.ToUpper(domain) + " ",
	}
	var result SyncResult
	if err := w.upsertUser(ctx, u, false, &result); err != nil {
		t.Fatalf("upsertUser: %v", err)
	}
	if result.Created != 1 {
		t.Fatalf("expected Created=1, got %+v", result)
	}

	var gotEmail, gotUPN string
	if err := pool.QueryRow(ctx,
		`SELECT id, email, COALESCE(ad_upn, '') FROM users WHERE lower(email) = $1`, canon,
	).Scan(&userID, &gotEmail, &gotUPN); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	// Transactional teardown: mailbox and user leave in ONE transaction so the
	// deferred primary-mailbox invariant passes without touching triggers.
	cleanupProvisionedAccount(t, pool, userID)
	if gotEmail != canon {
		t.Errorf("stored users.email = %q, want canonical %q", gotEmail, canon)
	}
	if gotUPN != canon {
		t.Errorf("stored users.ad_upn = %q, want canonical %q", gotUPN, canon)
	}

	// LDAPSYNC-006 ingress floor (same create path): a control character in the
	// directory address — the leading TAB this suite previously used as its
	// trim fixture — must be refused, counted as Skipped, and must not
	// provision anything.
	var floorResult SyncResult
	if err := w.upsertUser(ctx, LDAPUser{
		Email:       "\tLdap-Alice.Smith@" + strings.ToUpper(domain),
		DisplayName: "Alice Smith",
		UPN:         "\tLdap-Alice.Smith@" + strings.ToUpper(domain),
	}, false, &floorResult); err != nil {
		t.Fatalf("upsertUser control-char floor: %v", err)
	}
	if floorResult.Created != 0 || floorResult.Skipped != 1 {
		t.Fatalf("control-char address must be skipped, got %+v", floorResult)
	}
	var accountsInDomain int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE domain_id = $1`, domainID,
	).Scan(&accountsInDomain); err != nil {
		t.Fatalf("count users in fixture domain: %v", err)
	}
	if accountsInDomain != 1 {
		t.Fatalf("control-char entry provisioned rows: %d accounts in the fixture domain, want 1", accountsInDomain)
	}
}

// TestUpsertUserDisablePath is the deprovisioning regression: a directory user
// flagged disabled must end with users.enabled = FALSE and zero live sessions,
// and the run must count it as Disabled (not silently succeed while the writes
// were swallowed). Mirrors the security-relevant disable seam in upsertUser.
func TestUpsertUserDisablePath(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	suffix := randSuffix(t)
	domain := "ldapdis-" + suffix + ".local"

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	local := "ldap-disable-" + suffix // already canonical (lowercase, no spaces)
	email := local + "@" + domain
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM domains WHERE id = $1`, domainID)
	})

	w := &SyncWorker{pool: pool, logger: testLogger()}

	// Create the user (enabled).
	var create SyncResult
	if err := w.upsertUser(ctx, LDAPUser{Email: email, DisplayName: "Disable Test"}, false, &create); err != nil {
		t.Fatalf("create upsert: %v", err)
	}
	var userID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&userID); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	// Transactional teardown (mailbox + user in one transaction; sessions,
	// oauth tokens, and denylist rows included).
	cleanupProvisionedAccount(t, pool, userID)

	// Give the user a live session, then disable via sync.
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions (user_id, expires_at) VALUES ($1, now() + interval '1 day')`, userID,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	var result SyncResult
	if err := w.upsertUser(ctx, LDAPUser{Email: email, DisplayName: "Disable Test", Disabled: true}, false, &result); err != nil {
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
func TestSetIdentitySourceNilDoesNotCreateTypedNilInterface(t *testing.T) {
	worker := &SyncWorker{}
	worker.SetIdentitySource(nil, "ldap:unused")
	if worker.source != nil {
		t.Fatal("nil store must leave normalized source unset")
	}
}
