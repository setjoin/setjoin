package identitysource

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEntryValidateBoundsAndAllowlist(t *testing.T) {
	t.Parallel()
	valid := Entry{
		ObjectKey: "object-1", ImmutableSubject: "immutable-1",
		Payload: json.RawMessage(`{"operation":"upsert","email":"a@example.test","enabled":true}`),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid entry: %v", err)
	}
	tests := []struct {
		name string
		edit func(*Entry)
	}{
		{"blank object key", func(e *Entry) { e.ObjectKey = "" }},
		{"control subject", func(e *Entry) { e.ImmutableSubject = "bad\nsubject" }},
		{"oversize subject", func(e *Entry) { e.ImmutableSubject = strings.Repeat("x", MaxSubject+1) }},
		{"non-object payload", func(e *Entry) { e.Payload = json.RawMessage(`[]`) }},
		{"unknown payload field", func(e *Entry) { e.Payload = json.RawMessage(`{"password":"never"}`) }},
		{"oversize payload", func(e *Entry) {
			e.Payload = json.RawMessage(`{"email":"` + strings.Repeat("x", MaxPayloadBytes) + `"}`)
		}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			entry := valid
			tc.edit(&entry)
			if err := entry.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestPageValidateAssignsStableBatchAndCapsEntries(t *testing.T) {
	t.Parallel()
	page := Page{Cursor: json.RawMessage(`{"cursor":"1"}`)}
	if err := page.Validate(); err != nil {
		t.Fatalf("empty page: %v", err)
	}
	if page.BatchID == uuid.Nil {
		t.Fatal("batch id was not assigned")
	}
	first := page.BatchID
	if err := page.Validate(); err != nil || page.BatchID != first {
		t.Fatalf("batch id changed on retry: %v", err)
	}

	page.Entries = make([]Entry, MaxEntries+1)
	if err := page.Validate(); err == nil {
		t.Fatal("oversize page accepted")
	}
}

func TestStoreApplyPageAndResumeUseDurableReducerPipeline(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		t.Skip("DB_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	var priorEnabled bool
	if err := pool.QueryRow(ctx,
		`SELECT enabled FROM feature_toggles
		  WHERE key='feature.identity_model_v2'`).Scan(&priorEnabled); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE feature_toggles SET enabled=TRUE
		 WHERE key='feature.identity_model_v2'`); err != nil {
		t.Fatal(err)
	}
	sourceKey := "pipeline-" + uuid.NewString()
	var sourceID, generation int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES($1,'Pipeline integration','ad','{"users":true}'::jsonb,'active')
		RETURNING id,generation
	`, sourceKey).Scan(&sourceID, &generation); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, statement := range []string{
			`DELETE FROM identity_entitlement_grants WHERE source_id=$1`,
			`DELETE FROM identity_attribute_authority WHERE source_id=$1`,
			`DELETE FROM user_identity_links WHERE source_id=$1`,
			`DELETE FROM identity_sync_log WHERE source_id=$1`,
			`DELETE FROM identity_source_inbox WHERE source_id=$1`,
			`DELETE FROM identity_source_batches WHERE source_id=$1`,
			`DELETE FROM identity_source_leases WHERE source_id=$1`,
			`DELETE FROM identity_sources WHERE id=$1`,
		} {
			_, _ = pool.Exec(cleanupCtx, statement, sourceID)
		}
		_, _ = pool.Exec(cleanupCtx, `
			UPDATE feature_toggles SET enabled=$1
			 WHERE key='feature.identity_model_v2'
		`, priorEnabled)
	}()

	store := NewStore(pool)
	source, err := store.SourceByKey(ctx, sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	if source.ID != sourceID || source.Generation != generation || source.Cursor != nil {
		t.Fatalf("source = %+v", source)
	}
	instance := uuid.New()
	page := Page{
		Cursor: json.RawMessage(`{"page":"1"}`),
		Entries: []Entry{{
			ObjectKey: "object-1", ImmutableSubject: uuid.NewString(),
			Payload: json.RawMessage(`{"operation":"disable","enabled":false}`),
		}},
	}
	finished, err := store.ApplyPage(ctx, source, page, instance)
	if err == nil || finished.CursorAdvanced || finished.State != "blocked" ||
		!strings.Contains(err.Error(), "object-1 blocked (BZ230)") ||
		strings.Contains(err.Error(), "inbox entry not found") {
		t.Fatalf("blocked apply page = %+v, err=%v", finished, err)
	}
	for _, statement := range []string{
		`DELETE FROM identity_source_inbox WHERE source_id=$1`,
		`DELETE FROM identity_source_batches WHERE source_id=$1`,
		`UPDATE identity_sources
		    SET pending_cursor=NULL,pending_cursor_digest=NULL
		  WHERE id=$1`,
	} {
		if _, err := pool.Exec(ctx, statement, source.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReleaseLease(ctx, source, instance); err != nil {
		t.Fatal(err)
	}

	recoveryInstance := uuid.New()
	acquired, err := store.AcquireLease(ctx, source, recoveryInstance)
	if err != nil || !acquired {
		t.Fatalf("acquire recovery lease: acquired=%v err=%v", acquired, err)
	}
	second := Page{
		BatchID: uuid.New(),
		Cursor:  json.RawMessage(`{"page":"2"}`),
		Entries: []Entry{{
			ObjectKey: "object-2", ImmutableSubject: uuid.NewString(),
			Payload: json.RawMessage(`{"operation":"disable","enabled":false}`),
		}},
	}
	if err := store.Begin(ctx, source, second, recoveryInstance); err != nil {
		t.Fatal(err)
	}
	recovery, err := store.ResumeUnfinished(ctx, source, recoveryInstance)
	if err == nil || !recovery.Found || recovery.BatchID != second.BatchID ||
		recovery.EntryCount != 1 || recovery.Finish.CursorAdvanced {
		t.Fatalf("blocked recovery = %+v, err=%v", recovery, err)
	}
	if err := store.ReleaseLease(ctx, source, recoveryInstance); err != nil {
		t.Fatal(err)
	}

	empty, err := store.ResumeUnfinished(ctx, source, uuid.New())
	if err == nil || empty.Found {
		t.Fatalf("resume without a lease = %+v, err=%v", empty, err)
	}
}

func TestStoreDatabaseFailuresRemainVisibleAtEveryPipelineStage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx,
		"postgres://mail@127.0.0.1:5432/mailserver_test?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	store := NewStore(pool)
	source := Source{ID: 7, Generation: 3, Key: "corp", Kind: "ad", State: "active"}
	instance := uuid.New()
	page := Page{
		BatchID: uuid.New(),
		Cursor:  json.RawMessage(`{"cursor":"1"}`),
		Entries: []Entry{{
			ObjectKey: "object-1", ImmutableSubject: "immutable-1",
			Payload: json.RawMessage(`{"operation":"upsert"}`),
		}},
	}

	if _, err := store.SourceByKey(ctx, source.Key); err == nil {
		t.Fatal("closed database source lookup succeeded")
	}
	if _, err := store.AcquireLease(ctx, source, instance); err == nil {
		t.Fatal("closed database lease acquisition succeeded")
	}
	if err := store.ReleaseLease(ctx, source, instance); err == nil {
		t.Fatal("closed database lease release succeeded")
	}
	if err := store.Begin(ctx, source, page, instance); err == nil {
		t.Fatal("closed database batch begin succeeded")
	}
	if _, err := store.Apply(ctx, source, page.BatchID, "object-1"); err == nil ||
		!strings.Contains(err.Error(), "record connector failure") {
		t.Fatalf("closed database entry apply = %v", err)
	}
	if _, err := store.Finish(ctx, source, page, -time.Second, instance); err == nil {
		t.Fatal("closed database batch finish succeeded")
	}
	if _, err := store.ResumeUnfinished(ctx, source, instance); err == nil {
		t.Fatal("closed database unfinished batch lookup succeeded")
	}
	if _, err := store.ApplyPage(ctx, source, page, instance); err == nil ||
		!strings.Contains(err.Error(), "renew identity source lease") {
		t.Fatalf("closed database apply page = %v", err)
	}
	if _, err := store.drainBatch(
		ctx, source, page.BatchID, nil, 0, time.Now(), instance,
	); err == nil || !strings.Contains(err.Error(), "before cursor commit") {
		t.Fatalf("closed database batch drain = %v", err)
	}
}
