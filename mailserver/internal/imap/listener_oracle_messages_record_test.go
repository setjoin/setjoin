//go:build gofree_record

package imap

// Recording adapter only (#344): FETCH, SEARCH, STORE and UID of the unmodified
// production IMAP listener over a real TCP socket, on the constrained application
// role (DB_APP_DSN). The owner DSN seeds the fixture and observes the effects.
// The Rust listener replays the immutable bytes without Go present. Sessions are
// authored by oracle/messages_cases.py; this adapter never edits a response.
import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/testsupport"
)

func TestRecordIMAPMessages(t *testing.T) {
	root := os.Getenv("IMAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("IMAP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "messages-go-sessions.json")
	if _, e := os.Stat(out); e == nil {
		t.Fatal("golden exists: add a new corpus instead of overwriting it")
	}
	appDSN := os.Getenv("DB_APP_DSN")
	if appDSN == "" {
		t.Fatal("DB_APP_DSN required")
	}
	owner := testsupport.OpenTestPool(t)
	ctx := context.Background()
	appPool, e := pgxpool.New(ctx, appDSN)
	if e != nil {
		t.Fatal(e)
	}
	defer appPool.Close()
	read := func(name string) string {
		raw, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return string(raw)
	}
	cleanup, seed := read("messages-cleanup.sql"), read("messages-seed.sql")
	var sessions []map[string]any
	if e = json.Unmarshal([]byte(read("messages-requests.json")), &sessions); e != nil {
		t.Fatal(e)
	}
	dispatcher := webhook.NewDispatcher(appPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, session := range sessions {
		name := session["name"].(string)
		for _, q := range []string{cleanup, seed} {
			if _, e := owner.Exec(ctx, q); e != nil {
				t.Fatal(name, e)
			}
		}
		addr := net.JoinHostPort("127.0.0.1", freePortString(t))
		srvCtx, cancel := context.WithCancel(ctx)
		s := NewServer(appPool, addr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), dispatcher, nil)
		if e = s.Start(srvCtx); e != nil {
			cancel()
			t.Fatal(name, e)
		}
		conns := map[int]*oracleConn{}
		dial := func(idx int) *oracleConn {
			if c := conns[idx]; c != nil {
				return c
			}
			var conn net.Conn
			var err error
			for until := time.Now().Add(4 * time.Second); time.Now().Before(until); time.Sleep(10 * time.Millisecond) {
				if conn, err = net.DialTimeout("tcp", addr, time.Second); err == nil {
					break
				}
			}
			if err != nil {
				cancel()
				t.Fatal(name, err)
			}
			c := &oracleConn{conn: conn, r: bufio.NewReader(conn)}
			conns[idx] = c
			return c
		}
		for _, stepAny := range session["steps"].([]any) {
			step := stepAny.(map[string]any)
			if action, ok := step["action"].(map[string]any); ok {
				if action["kind"] != "sql" {
					t.Fatal(name, "unknown action", action["kind"])
				}
				if _, e := owner.Exec(ctx, action["sql"].(string)); e != nil {
					cancel()
					t.Fatal(name, e)
				}
				step["response"] = ""
				continue
			}
			c := dial(0)
			if req := step["request"].(string); req != "" {
				c.conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
				if _, e = c.conn.Write([]byte(req)); e != nil {
					cancel()
					t.Fatal(name, e)
				}
			}
			step["response"] = oracleRead(t, c, step["until"].(string))
		}
		for _, c := range conns {
			c.conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
		cancel()
		session["effects"] = map[string]any{
			"messages": oracleRows(t, owner, ctx, `SELECT message_id, is_read, is_flagged, is_answered, is_draft, is_deleted
				FROM messages WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY message_id`),
			"tags": oracleRows(t, owner, ctx, `SELECT mailbox_id, name, total_count, unread_count, jmap_state
				FROM tags WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY mailbox_id, name`),
			"audit": oracleRows(t, owner, ctx, `SELECT mailbox_id, actor_user_id, action, message_id
				FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY id`),
		}
	}
	data, e := json.MarshalIndent(sessions, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(out, append(data, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
	owner.Exec(ctx, cleanup)
}

// oracleRows returns each row as a JSON array of its column values, so the same
// query text can be run by the Rust replay and compared structurally.
func oracleRows(t *testing.T, pool *pgxpool.Pool, ctx context.Context, query string) []any {
	t.Helper()
	rows, e := pool.Query(ctx, `SELECT to_jsonb(r) FROM (`+query+`) r`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var v any
		if e = rows.Scan(&v); e != nil {
			t.Fatal(e)
		}
		out = append(out, v)
	}
	return out
}
