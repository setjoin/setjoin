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

// The cursor is the one directory-derived field persisted up to ~502 times per
// staged page, so Page.Validate must bound it exactly like every other
// connector field.
func TestPageValidateBoundsCursorBytes(t *testing.T) {
	t.Parallel()
	atLimit := json.RawMessage(`{"cursor":"` + strings.Repeat("x", MaxCursorBytes-13) + `"}`)
	if len(atLimit) != MaxCursorBytes {
		t.Fatalf("boundary cursor is %d bytes, want %d", len(atLimit), MaxCursorBytes)
	}
	page := Page{Cursor: atLimit}
	if err := page.Validate(); err != nil {
		t.Fatalf("cursor at the bound was rejected: %v", err)
	}
	page.Cursor = append(page.Cursor, 'x')
	if err := page.Validate(); err == nil ||
		!strings.Contains(err.Error(), "cursor must contain 1..4096 bytes") {
		t.Fatalf("oversized cursor = %v, want the cursor bound error", err)
	}
}

// A directory returning unbounded cursor strings fails the page before any
// storage access: a nil pool is enough because validation rejects first.
func TestOversizedCursorFailsPageBeforeAnyStorage(t *testing.T) {
	t.Parallel()
	store := &Store{}
	source := Source{ID: 1, Generation: 1, Key: "rogue", Kind: "ldap", State: "active"}
	page := Page{
		Cursor: json.RawMessage(`{"cursor":"` + strings.Repeat("x", MaxCursorBytes) + `"}`),
	}
	if err := store.Begin(context.Background(), source, page, uuid.New()); err == nil ||
		!strings.Contains(err.Error(), "cursor must contain 1..4096 bytes") {
		t.Fatalf("Begin with an oversized cursor = %v, want the cursor bound error", err)
	}
	if _, err := store.ApplyPage(context.Background(), source, page, uuid.New()); err == nil ||
		!strings.Contains(err.Error(), "cursor must contain 1..4096 bytes") {
		t.Fatalf("ApplyPage with an oversized cursor = %v, want the cursor bound error", err)
	}
}

// Integration proof against the reducer/schema layers: the rogue page is
// rejected at the pipeline and stages zero batch or inbox rows.
func TestOversizedDirectoryCursorStagesNothing(t *testing.T) {
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
	t.Cleanup(pool.Close)

	sourceKey := "pipeline-cursor-bound-" + uuid.NewString()
	var sourceID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES($1,'Cursor bound integration','ldap','{"users":true}'::jsonb,'active')
		RETURNING id
	`, sourceKey).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		for _, statement := range []string{
			`DELETE FROM identity_source_inbox WHERE source_id=$1`,
			`DELETE FROM identity_source_batches WHERE source_id=$1`,
			`DELETE FROM identity_source_leases WHERE source_id=$1`,
			`DELETE FROM identity_sources WHERE id=$1`,
		} {
			_, _ = pool.Exec(cleanupCtx, statement, sourceID)
		}
	})

	store := NewStore(pool)
	source := Source{ID: sourceID, Generation: 1, Key: sourceKey, Kind: "ldap", State: "active"}
	page := Page{
		Cursor: json.RawMessage(`{"modifyTimestamp":"` + strings.Repeat("x", 5000) + `"}`),
	}
	if _, err := store.ApplyPage(ctx, source, page, uuid.New()); err == nil ||
		!strings.Contains(err.Error(), "cursor must contain 1..4096 bytes") {
		t.Fatalf("rogue oversized cursor page = %v, want the cursor bound error", err)
	}
	var staged int
	if err := pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM identity_source_batches WHERE source_id=$1)
		     + (SELECT count(*) FROM identity_source_inbox WHERE source_id=$1)
	`, sourceID).Scan(&staged); err != nil {
		t.Fatal(err)
	}
	if staged != 0 {
		t.Fatalf("%d rows were staged from an oversized cursor page", staged)
	}
}
