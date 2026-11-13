//go:build gofree_record

package smtp

// Recording adapter only: drive frozen production submission over TCP with real
// AUTH/threat/reducer paths, never synthesize replies. Recorder for #501.
import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/threat"
	"setjoin.com/shared/toggle"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type subOracleSession struct {
	Name           string            `json:"name"`
	Cert           bool              `json:"cert,omitempty"`
	Threat         string            `json:"threat,omitempty"`
	PerUserMax     int               `json:"per_user_max,omitempty"`
	SetupSQL       string            `json:"setup_sql,omitempty"`
	TeardownSQL    string            `json:"teardown_sql,omitempty"`
	CaptureBlobs   bool              `json:"capture_blobs,omitempty"`
	Blobs          map[string]string `json:"blobs,omitempty"`
	Effects        json.RawMessage   `json:"effects,omitempty"`
	ObserveEffects bool              `json:"observe_effects,omitempty"`
	Steps          []smtpOracleStep  `json:"steps"`
}

func TestRecordSubmissionListener(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	out := filepath.Join(root, "submission-go.json")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("golden exists or inaccessible; create a new corpus")
	}
	raw, err := os.ReadFile(filepath.Join(root, "submission-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sessions []subOracleSession
	if err = json.Unmarshal(raw, &sessions); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	owner := testsupport.OpenTestPool(t)
	app, err := pgxpool.New(ctx, os.Getenv("DB_APP_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	sqlFile := func(name string) string {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	exec := func(sql string) {
		if _, e := owner.Exec(ctx, sql); e != nil {
			t.Fatal(e)
		}
	}
	defer exec(sqlFile("submission-cleanup.sql"))
	fixture := filepath.Join(root, "../../../../tests/conformance/directory-sync/ldap-fixture")
	ca, err := os.ReadFile(filepath.Join(fixture, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca)
	clientTLS := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := range sessions {
		s := &sessions[i]
		exec(sqlFile("submission-cleanup.sql"))
		exec(sqlFile("submission-seed.sql"))
		if s.TeardownSQL != "" {
			td := s.TeardownSQL
			defer exec(td)
		}
		if s.SetupSQL != "" {
			exec(s.SetupSQL)
		}
		flags := toggle.NewStatic(map[string]bool{})
		var gate *threat.ThreatInterceptor
		if s.Threat != "" {
			sql := "SELECT 1"
			switch s.Threat {
			case "feed":
				sql = "INSERT INTO threat_feed_blocks(cidr,source) VALUES('127.0.0.1/32','smtp5')"
			case "ip":
				sql = "INSERT INTO ip_rules(cidr,action,description) VALUES('127.0.0.1/32','block','smtp5')"
			case "lockout":
				sql = "INSERT INTO auth_lockouts(lockout_key,locked_until) VALUES('user:alice@smtp5.test',now()+interval '800 milliseconds')"
			case "device_country_null":
				sql = "INSERT INTO device_registry(user_id,device_hash,user_agent,ip_prefix,country,auth_count) VALUES(9501011,encode(sha256('|127.0.0.0'::bytea),'hex'),'','127.0.0.0',NULL,1)"
			case "rate":
				sql = "INSERT INTO rate_limit_counters(key,count,window_start) VALUES('auth:smtp:127.0.0.1',20,now())"
			case "policy":
				sql = `INSERT INTO conditional_access_policies(id,name,priority,state,scope_type,scope_target,conditions,actions) VALUES(9501900,'smtp5',9501,'on','user','9501011','{}','{"action":"block"}')`
			}
			exec(sql)
			tf := toggle.NewStatic(map[string]bool{toggle.FeatureThreatFeed: true, toggle.FeatureGeoBlock: false, toggle.FeatureSprayDetect: false, toggle.FeatureCaptcha: false, toggle.FeatureTarpit: false, toggle.FeatureRateLimit: s.Threat == "rate", toggle.FeatureConditionalAccess: s.Threat == "policy"})
			engine := threat.NewPolicyEngine(threat.NewPolicyStore(app, logger), tf, nil, nil, logger, false)
			gate = threat.New(app, owner, tf, nil, threat.ThreatConfig{RateLimitPerMin: 20}, logger, engine)
		}
		server := NewSubmissionServer(pgxutil.WorkerPool{Pool: owner}, "127.0.0.1:0", logger, flags, webhook.NewDispatcher(owner, logger), gate)
		if s.PerUserMax > 0 {
			server.SetPerUserMaxConns(s.PerUserMax)
		}
		var blobMu sync.Mutex
		blobs := map[string]string{}
		if s.CaptureBlobs {
			server.putBlob = func(_ context.Context, key string, data []byte) error {
				blobMu.Lock()
				defer blobMu.Unlock()
				blobs[key] = base64.StdEncoding.EncodeToString(data)
				return nil
			}
		}
		if s.Cert {
			server.SetTLS(filepath.Join(fixture, "server.pem"), filepath.Join(fixture, "server.p8"))
		}
		sctx, cancel := context.WithCancel(ctx)
		if err = server.Start(sctx); err != nil {
			t.Fatal(err)
		}
		addr := server.listener.Addr().String()
		conns := map[int]net.Conn{}
		readers := map[int]*bufio.Reader{}
		for j := range s.Steps {
			step := &s.Steps[j]
			if step.WaitMS > 0 {
				time.Sleep(time.Duration(step.WaitMS) * time.Millisecond)
			}
			if conns[step.Conn] == nil {
				c, e := net.Dial("tcp", addr)
				if e != nil {
					t.Fatal(e)
				}
				conns[step.Conn] = c
				readers[step.Conn] = bufio.NewReader(c)
			}
			conn, br := conns[step.Conn], readers[step.Conn]
			wait := 5 * time.Second
			if step.TimeoutMS > 0 {
				wait = time.Duration(step.TimeoutMS) * time.Millisecond
			}
			conn.SetDeadline(time.Now().Add(wait))
			if step.Send != "" {
				if _, e := io.WriteString(conn, step.Send); e != nil {
					t.Fatal(e)
				}
			}
			if step.Count > 0 {
				copies := 65536 / len(step.Repeat)
				if copies < 1 {
					copies = 1
				}
				chunk := strings.Repeat(step.Repeat, copies)
				for left := step.Count; left > 0; {
					n := left
					if n > copies {
						n = copies
					}
					if _, e := io.WriteString(conn, chunk[:n*len(step.Repeat)]); e != nil {
						t.Fatal(e)
					}
					left -= n
				}
			}
			if step.HalfClose {
				if e := conn.(interface{ CloseWrite() error }).CloseWrite(); e != nil {
					t.Fatal(e)
				}
			}
			if step.Lines == 0 {
				b, e := io.ReadAll(br)
				if e != nil && !os.IsTimeout(e) {
					t.Fatal(e)
				}
				step.Reply = string(b)
			}
			for n := 0; n < step.Lines; n++ {
				line, e := br.ReadString('\n')
				step.Reply += line
				if e != nil {
					t.Fatalf("%s step %d: %v", s.Name, j, e)
				}
			}
			if step.Upgrade {
				wrapped := tls.Client(conn, clientTLS)
				if e := wrapped.Handshake(); e != nil {
					t.Fatal(e)
				}
				conns[step.Conn] = wrapped
				readers[step.Conn] = bufio.NewReader(wrapped)
			}
		}
		for _, c := range conns {
			c.Close()
		}
		cancel()
		time.Sleep(100 * time.Millisecond)
		{
			var rawEffects string
			if e := owner.QueryRow(ctx, sqlFile("submission-observe.sql")).Scan(&rawEffects); e != nil {
				t.Fatal(e)
			}
			s.Effects = json.RawMessage(rawEffects)
		}
		if s.CaptureBlobs {
			blobMu.Lock()
			s.Blobs = blobs
			blobMu.Unlock()
		}
		if s.TeardownSQL != "" {
			exec(s.TeardownSQL)
		}
	}
	b, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(out, append(b, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
