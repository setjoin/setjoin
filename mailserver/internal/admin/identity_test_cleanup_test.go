package admin

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func cleanupIdentityLinkEventsForSource(
	t *testing.T,
	pool *pgxpool.Pool,
	sourceID int64,
) {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Errorf("begin identity event cleanup: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		ALTER TABLE identity_link_events
			DISABLE TRIGGER identity_link_events_append_only
	`); err != nil {
		t.Errorf("disable identity event append-only trigger: %v", err)
		return
	}
	if _, err := tx.Exec(context.Background(),
		`DELETE FROM identity_link_events WHERE source_id=$1`, sourceID,
	); err != nil {
		t.Errorf("delete identity test events: %v", err)
		return
	}
	if _, err := tx.Exec(context.Background(), `
		ALTER TABLE identity_link_events
			ENABLE TRIGGER identity_link_events_append_only
	`); err != nil {
		t.Errorf("restore identity event append-only trigger: %v", err)
		return
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Errorf("commit identity event cleanup: %v", err)
	}
}

func cleanupIdentityMatchDecision(
	t *testing.T,
	pool *pgxpool.Pool,
	candidateID string,
) {
	t.Helper()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Errorf("begin identity match decision cleanup: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `
		ALTER TABLE identity_match_decisions
			DISABLE TRIGGER identity_match_decisions_append_only
	`); err != nil {
		t.Errorf("disable identity match decision append-only trigger: %v", err)
		return
	}
	if _, err := tx.Exec(context.Background(),
		`DELETE FROM identity_match_decisions WHERE candidate_id=$1`, candidateID,
	); err != nil {
		t.Errorf("delete identity match decision fixture: %v", err)
		return
	}
	if _, err := tx.Exec(context.Background(), `
		ALTER TABLE identity_match_decisions
			ENABLE TRIGGER identity_match_decisions_append_only
	`); err != nil {
		t.Errorf("restore identity match decision append-only trigger: %v", err)
		return
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Errorf("commit identity match decision cleanup: %v", err)
	}
}
