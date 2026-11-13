package main

// This recorder exercises the frozen Go worker seam. It writes a golden only
// when GOFREE_RECORD_WORKER names a new file; ordinary runs replay it.
import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"

	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

type workerOracleResult struct {
	Loaded            bool            `json:"loaded"`
	DatabaseUnchanged bool            `json:"database_unchanged"`
	ClosedSessions    []string        `json:"closed_sessions"`
	Revoked           map[string]bool `json:"revoked"`
}

type oracleSession struct {
	name   string
	closed *[]string
}

func (s oracleSession) Close() error {
	*s.closed = append(*s.closed, s.name)
	return nil
}

func TestWorkerOracleSessionDenylistOneTick(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var mailboxA, mailboxB, userA, userB int64
	t.Cleanup(func() {
		cleanup := context.Background()
		tx, err := pool.Begin(cleanup)
		if err != nil {
			t.Errorf("clean worker fixture: %v", err)
			return
		}
		defer tx.Rollback(cleanup)
		// Resolve users from any fixture mailbox created before a setup failure.
		rows, err := tx.Query(cleanup, `SELECT user_id FROM mailboxes WHERE id=ANY($1::bigint[])`, []int64{mailboxA, mailboxB})
		if err != nil {
			t.Errorf("find worker fixture users: %v", err)
			return
		}
		var users []int64
		for rows.Next() {
			var user int64
			if err := rows.Scan(&user); err != nil {
				rows.Close()
				t.Errorf("scan worker fixture user: %v", err)
				return
			}
			users = append(users, user)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Errorf("read worker fixture users: %v", err)
			return
		}
		rows.Close()
		for _, step := range []struct {
			sql string
			ids []int64
		}{
			{`DELETE FROM session_revocations WHERE user_id=ANY($1::bigint[])`, users},
			{`DELETE FROM mailboxes WHERE id=ANY($1::bigint[])`, []int64{mailboxA, mailboxB}},
			{`DELETE FROM users WHERE id=ANY($1::bigint[])`, users},
		} {
			if _, err := tx.Exec(cleanup, step.sql, step.ids); err != nil {
				t.Errorf("clean worker fixture: %v", err)
				return
			}
		}
		if err := tx.Commit(cleanup); err != nil {
			t.Errorf("clean worker fixture: %v", err)
		}
	})
	if err := pool.QueryRow(ctx, `SELECT mk_account('t9-worker-a')`).Scan(&mailboxA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT mk_account('t9-worker-b')`).Scan(&mailboxB); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxA).Scan(&userA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxB).Scan(&userB); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, row := range []struct {
		user               int64
		scope, jti, family string
		before, expires    time.Time
	}{
		{userA, "jti", "revoked-jti", "", now.Add(-time.Hour), now.Add(time.Hour)},
		{userA, "family", "", "revoked-family", now.Add(-time.Hour), now.Add(time.Hour)},
		{userB, "all", "", "", now.Add(-30 * time.Minute), now.Add(time.Hour)},
		{userA, "jti", "expired-jti", "", now.Add(-2 * time.Hour), now.Add(-time.Hour)},
	} {
		_, err := pool.Exec(ctx, `INSERT INTO session_revocations(user_id,scope,jti,family_id,reason,not_before,expires_at) VALUES($1,$2,NULLIF($3,''),NULLIF($4,''),'worker oracle',$5,$6)`, row.user, row.scope, row.jti, row.family, row.before, row.expires)
		if err != nil {
			t.Fatal(err)
		}
	}
	snapshot := func() string {
		var value string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(r) ORDER BY id),'[]')::text FROM session_revocations r WHERE user_id=ANY($1::bigint[])`, []int64{userA, userB}).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := snapshot()
	closed := []string{}
	registry := threat.NewProtocolSessionRegistry()
	registry.RegisterTokenSession(userA, now, "revoked-jti", "", oracleSession{"jti", &closed})
	registry.RegisterTokenSession(userA, now, "", "revoked-family", oracleSession{"family", &closed})
	registry.RegisterTokenSession(userA, now, "expired-jti", "", oracleSession{"expired", &closed})
	registry.RegisterTokenSession(userB, now.Add(-time.Hour), "", "", oracleSession{"old", &closed})
	registry.RegisterTokenSession(userB, now, "", "", oracleSession{"new", &closed})
	denylist := threat.NewSessionDenylist(func(ctx context.Context) ([]threat.RevocationRow, error) {
		return loadActiveSessionRevocations(ctx, pool, registry)
	}, testsupport.TestLogger())
	if err := denylist.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	sort.Strings(closed)
	got := workerOracleResult{
		Loaded: denylist.Loaded(), DatabaseUnchanged: before == snapshot(), ClosedSessions: closed,
		Revoked: map[string]bool{
			"jti":        denylist.IsRevoked(userA, "revoked-jti", "", now),
			"family":     denylist.IsRevoked(userA, "", "revoked-family", now),
			"expired":    denylist.IsRevoked(userA, "expired-jti", "", now),
			"old":        denylist.IsRevoked(userB, "", "", now.Add(-time.Hour)),
			"new":        denylist.IsRevoked(userB, "", "", now),
			"other_user": denylist.IsRevoked(userB, "revoked-jti", "revoked-family", now),
		},
	}
	if path := os.Getenv("GOFREE_RECORD_WORKER"); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		enc := json.NewEncoder(file)
		enc.SetIndent("", "  ")
		if err := enc.Encode(got); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	file, err := os.Open("../../../server-rust/bins/gateway/tests/golden/go-session-refresh.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var want workerOracleResult
	if err := json.NewDecoder(file).Decode(&want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("worker oracle: got %+v; want %+v", got, want)
	}
}

func TestWorkerOracleGoRefreshTransferSwitch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t.Setenv("GO_WORKERS_OFF", "session-denylist-refresh")
	started := make(chan struct{}, 1)
	launchWorker(ctx, testsupport.TestLogger(), "session-denylist-refresh", func(context.Context) {
		started <- struct{}{}
	})
	select {
	case <-started:
		t.Fatal("Go refresh ran after transfer")
	case <-time.After(200 * time.Millisecond):
	}
	t.Setenv("GO_WORKERS_OFF", "")
	launchWorker(ctx, testsupport.TestLogger(), "session-denylist-refresh", func(context.Context) {
		started <- struct{}{}
	})
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("Go refresh did not run when enabled")
	}
}
