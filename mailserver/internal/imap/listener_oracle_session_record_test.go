//go:build gofree_record

package imap

// Recording adapter only (#345): LIST, STATUS, EXPUNGE, CLOSE, CREATE, DELETE, RENAME,
// COPY, MOVE, APPEND and IDLE of the unmodified
// production IMAP listener over a real TCP socket, on the constrained application
// role (DB_APP_DSN). The owner DSN seeds the fixture and observes the effects.
// The Rust listener replays the immutable bytes without Go present. Sessions are
// authored by oracle/session_cases.py; this adapter never edits a response.
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

func TestRecordIMAPSession(t *testing.T) {
	root := os.Getenv("IMAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("IMAP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "session-go-sessions.json")
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
	cleanup, seed := read("session-cleanup.sql"), read("session-seed.sql")
	var observe map[string]string
	if e = json.Unmarshal([]byte(read("session-observe.json")), &observe); e != nil {
		t.Fatal(e)
	}
	var sessions []map[string]any
	if e = json.Unmarshal([]byte(read("session-requests.json")), &sessions); e != nil {
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
			idx := 0
			if v, ok := step["conn"].(float64); ok {
				idx = int(v)
			}
			c := dial(idx)
			if req := step["request"].(string); req != "" {
				c.conn.SetWriteDeadline(time.Now().Add(4 * time.Second))
				if _, e = c.conn.Write([]byte(req)); e != nil {
					cancel()
					t.Fatal(name, e)
				}
			}
			if step["shutdown"] == true {
				c.conn.(*net.TCPConn).CloseWrite()
			}
			step["response"] = oracleRead(t, c, step["until"].(string))
		}
		for _, c := range conns {
			c.conn.Close()
		}
		time.Sleep(200 * time.Millisecond)
		cancel()
		session["effects"] = map[string]any{}
		for key, query := range observe {
			session["effects"].(map[string]any)[key] = oracleRows(t, owner, ctx, query)
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
