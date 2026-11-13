//go:build gofree_record

package main

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"setjoin.com/authserver/internal/federation"
	"setjoin.com/authserver/internal/token"
	"testing"
)

func TestRecordAuthRuntimeCleanup(t *testing.T) {
	dir := os.Getenv("AUTHRT_ORACLE_DIR")
	if dir == "" {
		t.Fatal("AUTHRT_ORACLE_DIR required")
	}
	path := filepath.Join(dir, "cleanup-go.json")
	if _, e := os.Stat(path); e == nil {
		t.Fatal("refuse overwrite")
	}
	ctx := context.Background()
	db, e := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	exec := func(name string) {
		b, e := os.ReadFile(filepath.Join(dir, name))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.Exec(ctx, string(b)); e != nil {
			t.Fatal(e)
		}
	}
	exec("cleanup.sql")
	exec("seed.sql")
	defer exec("cleanup.sql")
	token.CleanupRotatedTokens(ctx, db)
	federation.GCExpiredOIDCTokens(ctx, db)
	rows, e := db.Query(ctx, `SELECT 'oauth:'||encode(token_hash,'hex') AS k FROM oauth_tokens WHERE user_id=9420011 UNION ALL SELECT id FROM oidc_tokens WHERE user_id=9420011 ORDER BY k`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		if e = rows.Scan(&s); e != nil {
			t.Fatal(e)
		}
		out = append(out, s)
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	if e = os.WriteFile(path, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
