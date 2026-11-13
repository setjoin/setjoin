//go:build gofree_record

package imap

// Recording adapter only (#343): every response comes from the unmodified
// production IMAP listener over a real TCP/TLS socket. The Rust listener
// replays the immutable bytes without Go present. The server runs on the
// constrained application role (DB_APP_DSN); DB_DSN is only the fixture owner.
import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/pwhash"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
)

const oracleStdPassword = "IMAP1-correct-password!"
const oracleLowPassword = "IMAP1-low-cost-password!"
const oracleSpacedPassword = "IMAP1 spaced  password"

type oracleConn struct {
	conn net.Conn
	r    *bufio.Reader
}

func oracleRead(t *testing.T, c *oracleConn, until string) string {
	t.Helper()
	var sb strings.Builder
	c.conn.SetReadDeadline(time.Now().Add(4 * time.Second))
	switch until {
	case "eof":
		b, _ := io.ReadAll(c.r)
		return string(b)
	case "none":
		c.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		b, _ := io.ReadAll(c.r)
		return string(b)
	}
	prefix := until + " "
	for {
		line, err := c.r.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String()
		}
		if strings.HasPrefix(line, prefix) {
			return sb.String()
		}
	}
}

func TestRecordIMAPListener(t *testing.T) {
	root := os.Getenv("IMAP_ORACLE_DIR")
	if root == "" {
		t.Fatal("IMAP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "go-sessions.json")
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
	for _, f := range []string{"cleanup.sql", "seed.sql"} {
		raw, e := os.ReadFile(filepath.Join(root, f))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = owner.Exec(ctx, string(raw)); e != nil {
			t.Fatal(f, e)
		}
	}
	std, e := pwhash.HashPassword(oracleStdPassword)
	if e != nil {
		t.Fatal(e)
	}
	lowRaw, e := bcrypt.GenerateFromPassword([]byte(oracleLowPassword), 4)
	if e != nil {
		t.Fatal(e)
	}
	low := string(lowRaw)
	spaced, e := pwhash.HashPassword(oracleSpacedPassword)
	if e != nil {
		t.Fatal(e)
	}
	hashes, _ := json.MarshalIndent(map[string]string{"standard": std, "low": low, "spaced": spaced}, "", " ")
	if e = os.WriteFile(filepath.Join(root, "password-hashes.json"), append(hashes, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	resetFixture := func() {
		for _, q := range []string{
			`DELETE FROM auth_event_log WHERE user_id BETWEEN 9343011 AND 9343019 OR email LIKE '%@imap1.test'`,
			`UPDATE app_passwords SET last_used_at = NULL WHERE user_id BETWEEN 9343011 AND 9343019`,
			`UPDATE users SET last_login_at = NULL WHERE id BETWEEN 9343011 AND 9343019`,
		} {
			if _, e := owner.Exec(ctx, q); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := owner.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id BETWEEN 9343011 AND 9343019`, std); e != nil {
			t.Fatal(e)
		}
		if _, e := owner.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=9343017`, low); e != nil {
			t.Fatal(e)
		}
		if _, e := owner.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=9343019`, spaced); e != nil {
			t.Fatal(e)
		}
	}
	raw, e := os.ReadFile(filepath.Join(root, "requests.json"))
	if e != nil {
		t.Fatal(e)
	}
	var sessions []map[string]any
	if e = json.Unmarshal(raw, &sessions); e != nil {
		t.Fatal(e)
	}
	certFile, keyFile := writeIMAPTestCertificate(t)
	dispatcher := webhook.NewDispatcher(appPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, session := range sessions {
		resetFixture()
		name := session["name"].(string)
		transport := session["transport"].(string)
		var beforeHashes = map[int64]string{}
		rows, e := owner.Query(ctx, `SELECT id, password_hash FROM users WHERE id BETWEEN 9343011 AND 9343019`)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var id int64
			var h string
			if e = rows.Scan(&id, &h); e != nil {
				t.Fatal(e)
			}
			beforeHashes[id] = h
		}
		rows.Close()

		registry := threat.NewProtocolSessionRegistry()
		addr := net.JoinHostPort("127.0.0.1", freePortString(t))
		srvCtx, cancel := context.WithCancel(ctx)
		s := NewServer(appPool, addr, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), dispatcher, nil)
		switch transport {
		case "starttls":
			s.SetSTARTTLS(certFile, keyFile)
		case "tls":
			s.SetTLS(certFile, keyFile)
		}
		if v, ok := session["per_user_max"].(float64); ok {
			s.SetPerUserMaxConns(int(v))
		}
		if session["registry"] == true {
			s.SetSessionRegistry(registry)
		}
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
				if transport == "tls" {
					conn, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
				} else {
					conn, err = net.DialTimeout("tcp", addr, time.Second)
				}
				if err == nil {
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
			if ms, ok := step["sleep_ms"].(float64); ok {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
			if action, ok := step["action"].(map[string]any); ok {
				offset := time.Duration(action["not_before_offset_s"].(float64)) * time.Second
				registry.Apply(threat.RevocationRow{
					UserID: int64(action["user"].(float64)), Scope: threat.ScopeAll,
					NotBefore: time.Now().Add(offset),
				})
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
				if _, e = c.conn.Write([]byte(req)); e != nil && step["until"] != "eof" {
					cancel()
					t.Fatal(name, e)
				}
			}
			step["response"] = oracleRead(t, c, step["until"].(string))
			if step["upgrade"] == true {
				tlsConn := tls.Client(c.conn, &tls.Config{InsecureSkipVerify: true})
				if e = tlsConn.Handshake(); e != nil {
					cancel()
					t.Fatal(name, "client handshake", e)
				}
				c.conn = tlsConn
				c.r = bufio.NewReader(tlsConn)
			}
		}
		for _, c := range conns {
			c.conn.Close()
		}
		time.Sleep(100 * time.Millisecond)
		cancel()

		type event struct {
			User     *int64  `json:"user"`
			Event    string  `json:"event"`
			Provider string  `json:"provider"`
			Email    *string `json:"email"`
			IP       *string `json:"ip"`
		}
		events := []event{}
		erows, e := owner.Query(ctx, `SELECT user_id, event, provider, email, host(ip_address) FROM auth_event_log
			WHERE user_id BETWEEN 9343011 AND 9343019 OR email LIKE '%@imap1.test' ORDER BY id`)
		if e != nil {
			t.Fatal(e)
		}
		for erows.Next() {
			var ev event
			if e = erows.Scan(&ev.User, &ev.Event, &ev.Provider, &ev.Email, &ev.IP); e != nil {
				t.Fatal(e)
			}
			events = append(events, ev)
		}
		erows.Close()
		appUsed := []string{}
		arows, e := owner.Query(ctx, `SELECT name FROM app_passwords WHERE last_used_at IS NOT NULL ORDER BY name`)
		if e != nil {
			t.Fatal(e)
		}
		for arows.Next() {
			var n string
			arows.Scan(&n)
			appUsed = append(appUsed, n)
		}
		arows.Close()
		lastLogin := []int64{}
		lrows, e := owner.Query(ctx, `SELECT id FROM users WHERE last_login_at IS NOT NULL AND id BETWEEN 9343011 AND 9343019 ORDER BY id`)
		if e != nil {
			t.Fatal(e)
		}
		for lrows.Next() {
			var id int64
			lrows.Scan(&id)
			lastLogin = append(lastLogin, id)
		}
		lrows.Close()
		rehashed := []int64{}
		hrows, e := owner.Query(ctx, `SELECT id, password_hash FROM users WHERE id BETWEEN 9343011 AND 9343019 ORDER BY id`)
		if e != nil {
			t.Fatal(e)
		}
		for hrows.Next() {
			var id int64
			var h string
			hrows.Scan(&id, &h)
			if h != beforeHashes[id] {
				rehashed = append(rehashed, id)
			}
		}
		hrows.Close()
		session["effects"] = map[string]any{"auth_events": events, "app_passwords_used": appUsed, "last_login": lastLogin, "rehashed": rehashed}
	}
	data, e := json.MarshalIndent(sessions, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(out, append(data, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}

func freePortString(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	_, p, e := net.SplitHostPort(l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	return p
}
