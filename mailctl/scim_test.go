package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestParseScimCreateTokenArgsRequiresSourceBinding(t *testing.T) {
	t.Parallel()

	if _, err := parseScimCreateTokenArgs([]string{"--name", "entra"}); err == nil ||
		!strings.Contains(err.Error(), "--source is required") {
		t.Fatalf("missing source error = %v", err)
	}

	got, err := parseScimCreateTokenArgs([]string{
		"--name", "entra",
		"--source", "scim:entra",
		"--expiry", "24h",
		"--deletion-policy", "soft",
	})
	if err != nil {
		t.Fatalf("parse valid SCIM token args: %v", err)
	}
	if got.name != "entra" || got.sourceKey != "scim:entra" ||
		got.expiry != 24*time.Hour || got.deletionPolicy != "soft" {
		t.Fatalf("parsed options = %+v", got)
	}
}

func TestParseScimCreateTokenArgsRejectsOutOfBounds(t *testing.T) {
	t.Parallel()

	tests := [][]string{
		{"--name", " entra", "--source", "scim:entra"},
		{"--name", "entra", "--source", " scim:entra"},
		{"--name", "entra", "--source", "scim:entra", "--expiry", "-1h"},
		{"--name", "entra", "--source", "scim:entra", "--deletion-policy", "erase"},
		{"--name", "entra", "--source", "scim:entra", "unexpected"},
		{"--name", "entra", "--source", "scim:entra", "--expiry", "not-a-duration"},
		{"--source", "scim:entra"},
	}
	for _, args := range tests {
		if _, err := parseScimCreateTokenArgs(args); err == nil {
			t.Fatalf("arguments unexpectedly accepted: %v", args)
		}
	}
}

func TestSCIMTokenCommandsAgainstLiveReducers(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("TEST_DB_DSN/DB_DSN is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tag := time.Now().UnixNano()
	sourceKey := fmt.Sprintf("scim:mailctl-test-%d", tag)
	tokenName := fmt.Sprintf("mailctl-test-%d", tag)
	var sourceID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
			source_key,display_name,kind,capabilities,state
		) VALUES(
			$1,$2,'scim',
			'{"provision":true,"stable_immutable_subject":true}'::jsonb,
			'active'
		) RETURNING id`,
		sourceKey, tokenName,
	).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM scim_tokens WHERE name=$1`, tokenName)
		_, _ = pool.Exec(ctx, `DELETE FROM identity_sources WHERE id=$1`, sourceID)
	})
	command := &cmdCtx{
		openDB: func() (*pgxpool.Pool, error) { return pool, nil },
	}

	err = scimCreateToken(command, []string{
		"--name", tokenName + "-missing",
		"--source", "scim:missing-source",
	})
	if err == nil || !strings.Contains(err.Error(), "token creation failed") {
		t.Fatalf("missing-source token creation error=%v", err)
	}
	err = scimCreateToken(command, []string{
		"--name", tokenName,
		"--source", sourceKey,
		"--expiry", "1h",
		"--deletion-policy", "hard",
	})
	if err != nil {
		t.Fatalf("create source-bound SCIM token: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET state='paused' WHERE id=$1`, sourceID,
	); err != nil {
		t.Fatal(err)
	}
	if err := scimListTokens(command, nil); err != nil {
		t.Fatalf("list SCIM tokens: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM scim_tokens
		  WHERE name=$1 AND source_id=$2 AND deletion_policy='hard'
		    AND expires_at IS NOT NULL`,
		tokenName, sourceID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("created token rows=%d, want 1", count)
	}
}
