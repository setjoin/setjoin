//go:build gofree_record

package smtp

// Recording adapter only: drive frozen production SMTP over TCP, never synthesize replies.
import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type smtpOracleStep struct {
	ObserveBatch bool            `json:"observe_batch,omitempty"`
	BatchStats   json.RawMessage `json:"batch_stats,omitempty"`
	SendBase64   string          `json:"send_base64,omitempty"`
	Repeat       string          `json:"repeat,omitempty"`
	Count        int             `json:"count,omitempty"`
	TimeoutMS    int             `json:"timeout_ms,omitempty"`
	Conn         int             `json:"conn,omitempty"`
	Observe      bool            `json:"observe,omitempty"`
	Monitor      json.RawMessage `json:"monitor,omitempty"`
	WaitMS       int             `json:"wait_ms,omitempty"`
	Upgrade      bool            `json:"upgrade,omitempty"`
	Send         string          `json:"send"`
	Lines        int             `json:"lines"`
	Reply        string          `json:"reply,omitempty"`
	HalfClose    bool            `json:"half_close,omitempty"`
}
type smtpOracleSession struct {
	ImipNotify      bool                       `json:"imip_notify,omitempty"`
	ImipEffects     json.RawMessage            `json:"imip_effects,omitempty"`
	PipelineEffects json.RawMessage            `json:"pipeline_effects,omitempty"`
	PipelineIO      []map[string]any           `json:"pipeline_io,omitempty"`
	Pipeline        *smtpOraclePipeline        `json:"pipeline,omitempty"`
	SpamStore       bool                       `json:"spam_store,omitempty"`
	TrainModels     []smtpOracleModelTrain     `json:"train_models,omitempty"`
	Models          map[string]string          `json:"models,omitempty"`
	BatchStatsAfter json.RawMessage            `json:"batch_stats_after,omitempty"`
	SecurityEffects json.RawMessage            `json:"security_effects,omitempty"`
	CaptureBlobs    bool                       `json:"capture_blobs,omitempty"`
	Blobs           map[string]string          `json:"blobs,omitempty"`
	TeardownSQL     string                     `json:"teardown_sql,omitempty"`
	AuthReports     json.RawMessage            `json:"auth_reports,omitempty"`
	MailAuth        map[string]bool            `json:"mail_auth,omitempty"`
	DNS             map[string]json.RawMessage `json:"dns,omitempty"`
	RestoreReducer  bool                       `json:"restore_reducer,omitempty"`
	Greylist        bool                       `json:"greylist,omitempty"`
	GreylistRows    json.RawMessage            `json:"greylist_rows,omitempty"`
	Audit           bool                       `json:"audit,omitempty"`
	Capture         bool                       `json:"capture,omitempty"`
	ObserveEffects  bool                       `json:"observe_effects,omitempty"`
	Notifications   []map[string]any           `json:"notifications,omitempty"`
	MaxConns        *int32                     `json:"max_conns,omitempty"`
	SetupSQL        string                     `json:"setup_sql,omitempty"`
	TLS             bool                       `json:"tls,omitempty"`
	Enforce         bool                       `json:"enforce,omitempty"`
	Effects         json.RawMessage            `json:"effects,omitempty"`
	Name            string                     `json:"name"`
	Steps           []smtpOracleStep           `json:"steps"`
}

func TestRecordSMTPListener(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	corpus := os.Getenv("SMTP_CORPUS")
	if corpus == "" {
		corpus = "session"
	}
	out := filepath.Join(root, corpus+"-go.json")
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("golden exists or inaccessible; create a new corpus")
	}
	raw, err := os.ReadFile(filepath.Join(root, corpus+"-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var sessions []smtpOracleSession
	if err = json.Unmarshal(raw, &sessions); err != nil {
		t.Fatal(err)
	}
	pool := testsupport.OpenTestPool(t)
	restoreReducer := func() {
		raw, e := os.ReadFile(filepath.Join(root, "../../../../../mailserver/sql/reducers/smtp_inbound_deliver.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = pool.Exec(context.Background(), string(raw)); e != nil {
			t.Fatal(e)
		}
	}
	for _, session := range sessions {
		if session.RestoreReducer {
			t.Cleanup(restoreReducer)
			break
		}
	}
	ctx := context.Background()
	for _, file := range []string{"cleanup.sql", "seed.sql"} {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, string(raw)); err != nil {
			t.Fatal(file, err)
		}
	}
	defer func() {
		raw, _ := os.ReadFile(filepath.Join(root, "cleanup.sql"))
		_, err := pool.Exec(ctx, string(raw))
		if err != nil {
			t.Error(err)
		}
	}()
	disabled := map[string]bool{}
	for _, key := range toggle.Keys() {
		disabled[key] = false
	}
	flags := toggle.NewStatic(disabled) // Security pipeline is injected by #349; this corpus exercises the session.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := range sessions {
		if len(sessions[i].MailAuth) > 0 {
			sql, e := os.ReadFile(filepath.Join(root, "auth-cleanup.sql"))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Exec(ctx, string(sql)); e != nil {
				t.Fatal(e)
			}
		}
		for _, file := range []string{"cleanup.sql", "seed.sql"} {
			raw, err := os.ReadFile(filepath.Join(root, file))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Exec(ctx, string(raw)); err != nil {
				t.Fatal(err)
			}
		}
		_, err = pool.Exec(ctx, "DELETE FROM rate_limit_counters WHERE key='smtp:conn:127.0.0.1'")
		if err != nil {
			t.Fatal(err)
		}
		fixture := filepath.Join(root, "../../../../tests/conformance/directory-sync/ldap-fixture")
		ca, err := os.ReadFile(filepath.Join(fixture, "ca.pem"))
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(ca) {
			t.Fatal("bad fixture CA")
		}
		clientTLS := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
		sessionFlags := map[string]bool{}
		for key, value := range disabled {
			sessionFlags[key] = value
		}
		for key, value := range sessions[i].MailAuth {
			sessionFlags[key] = value
		}
		restoreDNS := smtpOracleDNS(sessions[i].DNS)
		restoreSystemDNS := func() {}
		if sessionFlags[toggle.FeatureRBL] {
			restoreSystemDNS = smtpOracleSystemDNS(t, sessions[i].DNS)
		}
		sessionFlags[toggle.FeatureMailboxAuditLog] = sessions[i].Audit
		sessionFlags[toggle.FeatureGreylisting] = sessions[i].Greylist
		flags = toggle.NewStatic(sessionFlags)
		var notify *pgx.Conn
		if sessions[i].Capture {
			var err error
			notify, err = pgx.Connect(ctx, os.Getenv("DB_DSN"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = notify.Exec(ctx, `LISTEN "tag:9348021";LISTEN "tag:9348022";LISTEN "tag:9348023"`); err != nil {
				t.Fatal(err)
			}
		}
		server := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, "127.0.0.1:0", logger, flags, nil)
		var blobMu sync.Mutex
		blobs := map[string]string{}
		if sessions[i].CaptureBlobs {
			server.putBlob = func(_ context.Context, key string, data []byte) error {
				blobMu.Lock()
				defer blobMu.Unlock()
				blobs[key] = base64.StdEncoding.EncodeToString(data)
				return nil
			}
		}
		if sql := sessions[i].TeardownSQL; sql != "" {
			t.Cleanup(func() {
				if _, e := pool.Exec(context.Background(), sql); e != nil {
					t.Error(e)
				}
			})
		}
		if sessions[i].SetupSQL != "" {
			if _, err = pool.Exec(ctx, sessions[i].SetupSQL); err != nil {
				t.Fatal(err)
			}
		}
		if sessions[i].ImipNotify {
			if notify == nil {
				notify, err = pgx.Connect(ctx, os.Getenv("DB_DSN"))
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = notify.Exec(ctx, `LISTEN "calendar:9348021";LISTEN "calendar:9348022";LISTEN "calendar:9348023"`); err != nil {
				t.Fatal(err)
			}
		}
		finishPipeline := func() []map[string]any { return nil }
		if sessions[i].Pipeline != nil {
			finishPipeline = smtpOracleConfigurePipeline(t, server, sessions[i].Pipeline, pool, flags)
		}
		if sessions[i].SpamStore {
			server.SetSpamStore(smtpOracleSpamStore(t, pool, &sessions[i]))
		}
		if sessions[i].MaxConns != nil {
			server.SetMaxConns(*sessions[i].MaxConns)
		}
		server.SetTLSEnforce(sessions[i].Enforce)
		if sessions[i].TLS {
			server.SetTLS(filepath.Join(fixture, "server.pem"), filepath.Join(fixture, "server.p8"))
		}
		sctx, cancel := context.WithCancel(ctx)
		if err = server.Start(sctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		conn, err := net.Dial("tcp", server.listener.Addr().String())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if sessions[i].TLS {
			wrapped := tls.Client(conn, clientTLS)
			if err = wrapped.Handshake(); err != nil {
				t.Fatal(err)
			}
			conn = wrapped
		}
		br := bufio.NewReader(conn)
		conns := map[int]net.Conn{0: conn}
		readers := map[int]*bufio.Reader{0: br}
		for j := range sessions[i].Steps {
			step := &sessions[i].Steps[j]
			if step.WaitMS > 0 {
				time.Sleep(time.Duration(step.WaitMS) * time.Millisecond)
			}
			if conns[step.Conn] == nil {
				opened, e := net.Dial("tcp", server.listener.Addr().String())
				if e != nil {
					t.Fatal(e)
				}
				conns[step.Conn] = opened
				readers[step.Conn] = bufio.NewReader(opened)
			}
			conn = conns[step.Conn]
			br = readers[step.Conn]
			wait := 5 * time.Second
			if step.TimeoutMS > 0 {
				wait = time.Duration(step.TimeoutMS) * time.Millisecond
			}
			conn.SetDeadline(time.Now().Add(wait))
			if step.SendBase64 != "" {
				raw, e := base64.StdEncoding.DecodeString(step.SendBase64)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = conn.Write(raw); e != nil {
					t.Fatal(e)
				}
			}
			if step.Send != "" {
				if _, err = io.WriteString(conn, step.Send); err != nil {
					t.Fatal(err)
				}
			}
			if step.Count > 0 {
				if step.Repeat == "" {
					t.Fatal("empty repeat")
				}
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
					if _, err = io.WriteString(conn, chunk[:n*len(step.Repeat)]); err != nil {
						t.Fatal(err)
					}
					left -= n
				}
			}
			if step.HalfClose {
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if step.Lines == 0 {
				raw, e := io.ReadAll(br)
				if e != nil {
					t.Fatal(e)
				}
				step.Reply = string(raw)
			}
			for n := 0; n < step.Lines; n++ {
				line, e := br.ReadString('\n')
				step.Reply += line
				if e != nil {
					t.Fatalf("%s step %d: %v", sessions[i].Name, j, e)
				}
			}
			if step.Observe {
				sql, e := os.ReadFile(filepath.Join(root, "monitor.sql"))
				if e != nil {
					t.Fatal(e)
				}
				var raw string
				if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
					t.Fatal(e)
				}
				step.Monitor = json.RawMessage(raw)
			}
			if step.ObserveBatch {
				step.BatchStats = smtpOracleBatchStats(server)
			}
			if step.Upgrade {
				wrapped := tls.Client(conn, clientTLS)
				if err = wrapped.Handshake(); err != nil {
					t.Fatal(err)
				}
				conn = wrapped
				br = bufio.NewReader(conn)
				conns[step.Conn] = conn
				readers[step.Conn] = br
			}
		}
		conn.Close()
		cancel()
		if sessions[i].SpamStore {
			sessions[i].BatchStatsAfter = smtpOracleBatchFinished(t, server)
		}
		if notify != nil {
			for {
				nctx, done := context.WithTimeout(ctx, 200*time.Millisecond)
				n, err := notify.WaitForNotification(nctx)
				expired := nctx.Err() != nil
				done()
				if err != nil {
					if expired {
						break
					}
					t.Fatal(err)
				}
				var payload map[string]any
				if err = json.Unmarshal([]byte(n.Payload), &payload); err != nil {
					t.Fatal(err)
				}
				if id, ok := payload["tag_id"].(float64); ok {
					var name string
					if err = pool.QueryRow(ctx, "SELECT name FROM tags WHERE id=$1", int64(id)).Scan(&name); err != nil {
						t.Fatal(err)
					}
					payload["tag_id"] = name
				}
				if sessions[i].ImipNotify {
					for _, field := range []string{"event_id", "calendar_id"} {
						if id, ok := payload[field].(float64); ok {
							file := "imip-" + field + ".sql"
							query, e := os.ReadFile(filepath.Join(root, file))
							if e != nil {
								t.Fatal(e)
							}
							var raw string
							if e = pool.QueryRow(ctx, string(query), int64(id)).Scan(&raw); e != nil {
								t.Fatal(e)
							}
							var normalized any
							if e = json.Unmarshal([]byte(raw), &normalized); e != nil {
								t.Fatal(e)
							}
							payload[field] = normalized
						}
					}
				}
				sessions[i].Notifications = append(sessions[i].Notifications, map[string]any{"channel": n.Channel, "payload": payload})
			}
			if err := notify.Close(ctx); err != nil {
				t.Fatal(err)
			}
			sort.Slice(sessions[i].Notifications, func(a, b int) bool {
				x, _ := json.Marshal(sessions[i].Notifications[a])
				y, _ := json.Marshal(sessions[i].Notifications[b])
				return string(x) < string(y)
			})
		}
		if sessions[i].Greylist {
			sql, e := os.ReadFile(filepath.Join(root, "greylist-observe.sql"))
			if e != nil {
				t.Fatal(e)
			}
			var raw string
			if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			sessions[i].GreylistRows = json.RawMessage(raw)
		}
		if corpus == "delivery" || sessions[i].ObserveEffects {
			sql, err := os.ReadFile(filepath.Join(root, "observe.sql"))
			if err != nil {
				t.Fatal(err)
			}
			var raw string
			if err = pool.QueryRow(ctx, string(sql)).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			sessions[i].Effects = json.RawMessage(raw)
		}
		if strings.HasPrefix(corpus, "security-") {
			sql, e := os.ReadFile(filepath.Join(root, "security-observe.sql"))
			if e != nil {
				t.Fatal(e)
			}
			var raw string
			if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			sessions[i].SecurityEffects = json.RawMessage(raw)
		}
		if strings.HasPrefix(corpus, "security-joint") || strings.HasPrefix(corpus, "security-av") || strings.HasPrefix(corpus, "security-sandbox") || strings.HasPrefix(corpus, "security-group") || strings.HasPrefix(corpus, "security-smime") || strings.HasPrefix(corpus, "security-imip") || strings.HasPrefix(corpus, "security-link") {
			sql, e := os.ReadFile(filepath.Join(root, "pipeline-observe.sql"))
			if e != nil {
				t.Fatal(e)
			}
			var raw string
			if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			sessions[i].PipelineEffects = json.RawMessage(raw)
		}
		if strings.HasPrefix(corpus, "security-imip") {
			sql, e := os.ReadFile(filepath.Join(root, "imip-observe.sql"))
			if e != nil {
				t.Fatal(e)
			}
			var raw string
			if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			sessions[i].ImipEffects = json.RawMessage(raw)
		}
		sessions[i].PipelineIO = finishPipeline()
		if sessions[i].MailAuth[toggle.FeatureDMARC] {
			sql, e := os.ReadFile(filepath.Join(root, "auth-observe.sql"))
			if e != nil {
				t.Fatal(e)
			}
			var raw string
			if e = pool.QueryRow(ctx, string(sql)).Scan(&raw); e != nil {
				t.Fatal(e)
			}
			sessions[i].AuthReports = json.RawMessage(raw)
		}
		if sessions[i].CaptureBlobs {
			blobMu.Lock()
			sessions[i].Blobs = blobs
			smtpOracleLinkClock(t, sessions[i].Pipeline, blobs)
			blobMu.Unlock()
		}
		if sql := sessions[i].TeardownSQL; sql != "" {
			if _, e := pool.Exec(ctx, sql); e != nil {
				t.Fatal(e)
			}
		}
		restoreSystemDNS()
		restoreDNS()
		if sessions[i].RestoreReducer {
			restoreReducer()
		}
	}
	if sql, e := os.ReadFile(filepath.Join(root, "auth-cleanup.sql")); e == nil {
		if _, e = pool.Exec(ctx, string(sql)); e != nil {
			t.Fatal(e)
		}
	}
	raw, err = json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(out, append(raw, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
