//go:build gofree_record

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"setjoin.com/shared/threat"
	"testing"
	"time"
)

func TestRecordAuthRuntimeDenylist(t *testing.T) {
	dir := os.Getenv("AUTHRT_ORACLE_DIR")
	out := filepath.Join(dir, "denylist-go.json")
	if dir == "" {
		t.Fatal("AUTHRT_ORACLE_DIR required")
	}
	if _, e := os.Stat(out); e == nil {
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
	exec("revocations.sql")
	fail := false
	dl := threat.NewSessionDenylist(func(ctx context.Context) ([]threat.RevocationRow, error) {
		if fail {
			return nil, fmt.Errorf("fixture: read unavailable")
		}
		rows, e := db.Query(ctx, `SELECT user_id,scope,coalesce(jti,''),coalesce(family_id,''),not_before,expires_at FROM session_revocations WHERE expires_at>now()`)
		if e != nil {
			return nil, e
		}
		defer rows.Close()
		out := []threat.RevocationRow{}
		for rows.Next() {
			var r threat.RevocationRow
			if e = rows.Scan(&r.UserID, &r.Scope, &r.JTI, &r.FamilyID, &r.NotBefore, &r.ExpiresAt); e != nil {
				return nil, e
			}
			out = append(out, r)
		}
		return out, rows.Err()
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	probe := func() []bool {
		return []bool{dl.IsRevoked(9420011, "authrt-jti", "", time.Now()), dl.IsRevoked(9420011, "", "authrt-family", time.Now()), dl.IsRevoked(9420011, "", "", time.Now().Add(-2*time.Hour)), dl.IsRevoked(9420011, "other", "other", time.Now()), dl.IsRevoked(9420099, "authrt-jti", "authrt-family", time.Now())}
	}
	if e = dl.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	outcomes := [][]bool{probe()}
	fail = true
	if e = dl.Refresh(ctx); e == nil {
		t.Fatal("expected failure")
	}
	outcomes = append(outcomes, probe())
	fail = false
	if _, e = db.Exec(ctx, "DELETE FROM session_revocations WHERE user_id=9420011"); e != nil {
		t.Fatal(e)
	}
	if e = dl.Refresh(ctx); e != nil {
		t.Fatal(e)
	}
	outcomes = append(outcomes, probe())
	b, _ := json.MarshalIndent(outcomes, "", "  ")
	if e = os.WriteFile(out, append(b, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}
