//go:build gofree_record

// Records the frozen Go federation listener's wire behaviour for the Rust port
// (#346). The production Service runs unchanged against a disposable database
// with an in-process scripted peer; every server frame and the resulting
// federation/chat rows are written to go-sessions.json. Output is immutable
// once recorded. Run (CI image, REQUIRE_DB=1, FED_ORACLE_DIR=<abs oracle dir>):
//
//	go test -tags gofree_record ./internal/federation -run '^TestRecordFederationListener$' -count=1
//
// Only this adapter is new Go; production Go stays frozen.
package federation

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/db"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

type oStep struct {
	Op        string `json:"op"`
	Body      string `json:"body"`
	Hex       string `json:"hex"`
	SQL       string `json:"sql"`
	N         int    `json:"n"`
	TimeoutMS int    `json:"timeout_ms"`
	MS        int    `json:"ms"`
	Conn      int    `json:"conn"`
	Value     bool   `json:"value"`
}

type oAllow struct {
	Domain  string `json:"domain"`
	CA      string `json:"ca"`
	Scope   string `json:"scope"`
	Enabled bool   `json:"enabled"`
}

type oCase struct {
	Name        string   `json:"name"`
	Identity    string   `json:"identity"`
	Allow       []oAllow `json:"allow"`
	SQL         []string `json:"sql"`
	Steps       []oStep  `json:"steps"`
	FlagInitial *bool    `json:"flag_initial"`
}

type oResult struct {
	Step    int      `json:"step"`
	Frames  []string `json:"frames,omitempty"`
	EOF     bool     `json:"eof,omitempty"`
	Connect string   `json:"connect,omitempty"`
}

type oOut struct {
	Name     string                     `json:"name"`
	Results  []oResult                  `json:"results"`
	Observed map[string]json.RawMessage `json:"observed"`
}

type oClient struct {
	conn net.Conn
	dead bool
}

func TestRecordFederationListener(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	dir := os.Getenv("FED_ORACLE_DIR")
	if dsn == "" || dir == "" {
		t.Skip("DB_DSN and FED_ORACLE_DIR are required")
	}
	outPath := filepath.Join(dir, os.Getenv("FED_ORACLE_VARIANT")+"go-sessions.json")
	if _, err := os.Stat(outPath); err == nil {
		t.Fatalf("%s exists: recorded goldens are immutable", outPath)
	}
	var req struct {
		Cases []oCase `json:"cases"`
	}
	readJSON(t, filepath.Join(dir, os.Getenv("FED_ORACLE_VARIANT")+"requests.json"), &req)
	var observe [][2]string
	readJSON(t, filepath.Join(dir, "observe.json"), &observe)
	cleanup, err := os.ReadFile(filepath.Join(dir, "cleanup.sql"))
	if err != nil {
		t.Fatal(err)
	}
	only := os.Getenv("FED_ORACLE_ONLY")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	directDSN := os.Getenv("DB_DIRECT_DSN")
	if directDSN == "" {
		directDSN = dsn
	}

	var outs []oOut
	for _, c := range req.Cases {
		if only != "" && !strings.Contains(c.Name, only) {
			continue
		}
		t.Logf("case %s", c.Name)
		outs = append(outs, runOracleCase(t, ctx, pool, directDSN, dir, string(cleanup), observe, c))
	}
	b, err := json.MarshalIndent(map[string]any{"cases": outs}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func runOracleCase(t *testing.T, ctx context.Context, pool *pgxpool.Pool, directDSN, dir, cleanup string, observe [][2]string, c oCase) oOut {
	t.Helper()
	mustExec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %q: %v", c.Name, sql, err)
		}
	}
	mustExec(cleanup)
	for _, s := range c.SQL {
		mustExec(s)
	}
	for _, a := range c.Allow {
		pem, err := os.ReadFile(filepath.Join(dir, "certs", "ca-"+a.CA+".crt"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO federation_allowlist (peer_domain, peer_anchor, scope, enabled) VALUES ($1,$2,$3,$4)`,
			a.Domain, string(pem), a.Scope, a.Enabled); err != nil {
			t.Fatal(err)
		}
	}
	mustExec(`UPDATE feature_toggles SET enabled = true WHERE key = 'feature.federation'`)

	flagOn := c.FlagInitial == nil || *c.FlagInitial
	flags := toggle.NewTestFlags(map[string]bool{"feature.federation": flagOn})

	lctx, lcancel := context.WithCancel(ctx)
	defer lcancel()
	dconn, err := pgx.Connect(lctx, directDSN)
	if err != nil {
		t.Fatal(err)
	}
	dl := db.NewListener(dconn, discardLogger())
	dl.SetDSN(directDSN)
	go dl.Run(lctx)

	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()

	leaf, err := tls.LoadX509KeyPair(filepath.Join(dir, "certs", "zulu.crt"), filepath.Join(dir, "certs", "zulu.key"))
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(Config{LocalDomain: "zulu.test", ListenAddr: addr}, pgxutil.WorkerPool{Pool: pool}, flags, dl, leaf, discardLogger())
	sctx, scancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { svc.Run(sctx); close(done) }()
	waitTCP(t, addr)

	clientCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "certs", c.Identity+".crt"), filepath.Join(dir, "certs", c.Identity+".key"))
	if err != nil {
		t.Fatal(err)
	}
	clients := map[int]*oClient{}
	dial := func(timeout time.Duration) (*oClient, string) {
		d := &net.Dialer{Timeout: timeout}
		cfg := &tls.Config{Certificates: []tls.Certificate{clientCert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
		ctx2, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		conn, err := (&tls.Dialer{NetDialer: d, Config: cfg}).DialContext(ctx2, "tcp", addr)
		if err != nil {
			return &oClient{dead: true}, "timeout"
		}
		return &oClient{conn: conn}, "ok"
	}
	get := func(i int) *oClient {
		if cl, ok := clients[i]; ok {
			return cl
		}
		cl, _ := dial(5 * time.Second)
		clients[i] = cl
		return cl
	}

	out := oOut{Name: c.Name, Observed: map[string]json.RawMessage{}}
	for i, s := range c.Steps {
		switch s.Op {
		case "send", "raw_hex":
			cl := get(s.Conn)
			var raw []byte
			if s.Op == "send" {
				raw = make([]byte, 4+len(s.Body))
				binary.BigEndian.PutUint32(raw, uint32(len(s.Body)))
				copy(raw[4:], s.Body)
			} else if raw, err = hex.DecodeString(s.Hex); err != nil {
				t.Fatal(err)
			}
			if !cl.dead {
				_ = cl.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if _, err := cl.conn.Write(raw); err != nil {
					cl.dead = true
				}
			}
		case "read", "quiet":
			cl := get(s.Conn)
			n, wait := s.N, time.Duration(s.TimeoutMS)*time.Millisecond
			if s.Op == "quiet" {
				n, wait = 1<<30, time.Duration(s.MS)*time.Millisecond
			}
			r := oResult{Step: i}
			deadline := time.Now().Add(wait)
			for k := 0; k < n && !cl.dead; k++ {
				body, timeout, err := readOracleFrame(cl.conn, deadline)
				if timeout {
					break
				}
				if err != nil {
					r.EOF = true
					cl.dead = true
					break
				}
				if !utf8.Valid(body) {
					t.Fatalf("%s: non-UTF-8 server frame %x", c.Name, body)
				}
				r.Frames = append(r.Frames, string(body))
			}
			if cl.dead {
				r.EOF = true
			}
			out.Results = append(out.Results, r)
		case "sql":
			mustExec(s.SQL)
		case "sleep":
			time.Sleep(time.Duration(s.MS) * time.Millisecond)
		case "reconnect":
			if cl, ok := clients[0]; ok && cl.conn != nil {
				cl.conn.Close()
			}
			time.Sleep(300 * time.Millisecond)
			delete(clients, 0)
			get(0)
		case "open":
			clients[s.Conn] = nil
			delete(clients, s.Conn)
			get(s.Conn)
		case "flag":
			flags.OnNotify("feature.federation", s.Value)
			svc.Wake()
		case "connect_timeout":
			cl, res := dial(time.Duration(s.MS) * time.Millisecond)
			clients[0] = cl
			out.Results = append(out.Results, oResult{Step: i, Connect: res})
		default:
			t.Fatalf("%s: unknown op %q", c.Name, s.Op)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, cl := range clients {
		if cl != nil && cl.conn != nil {
			cl.conn.Close()
		}
	}
	time.Sleep(200 * time.Millisecond)
	scancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s: service did not stop", c.Name)
	}
	lcancel()
	for _, q := range observe {
		var js string
		if err := pool.QueryRow(ctx, q[1]).Scan(&js); err != nil {
			t.Fatalf("%s: observe %s: %v", c.Name, q[0], err)
		}
		out.Observed[q[0]] = json.RawMessage(js)
	}
	return out
}

func waitTCP(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("service never listened on %s", addr)
}

func readOracleFrame(conn net.Conn, deadline time.Time) ([]byte, bool, error) {
	_ = conn.SetReadDeadline(deadline)
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, isTimeout(err), err
	}
	body := make([]byte, binary.BigEndian.Uint32(hdr[:]))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, isTimeout(err), err
	}
	return body, false, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func discardLogger() *slog.Logger {
	if os.Getenv("FED_ORACLE_LOG") == "1" {
		return slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return testLogger()
}
