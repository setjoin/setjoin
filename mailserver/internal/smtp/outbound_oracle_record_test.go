//go:build gofree_record

package smtp

// Recording adapter only: the complete processBatch/deliverOne path is frozen.
import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/miekg/dns"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"setjoin.com/shared/toggle"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

type outboundCase struct {
	PolicyGzip      bool                       `json:"policy_gzip,omitempty"`
	TransportFromDB bool                       `json:"transport_from_db,omitempty"`
	BetweenTicksSQL []string                   `json:"between_ticks_sql,omitempty"`
	PolicyBody      *string                    `json:"policy_body,omitempty"`
	PolicyStatus    int                        `json:"policy_status,omitempty"`
	Transport       map[string]bool            `json:"transport,omitempty"`
	TLSA            []json.RawMessage          `json:"tlsa,omitempty"`
	DNS             map[string]json.RawMessage `json:"dns,omitempty"`
	ObserveFile     string                     `json:"observe_file,omitempty"`
	Backlog         bool                       `json:"backlog,omitempty"`
	BlobHeaders     map[string]string          `json:"blob_headers"`
	TeardownSQL     string                     `json:"teardown_sql"`
	LinkSecret      string                     `json:"link_secret"`
	LinkPrevious    string                     `json:"link_previous"`
	LinkVersion     int                        `json:"link_version"`
	Blobs           map[string]string          `json:"blobs"`
	TimeoutMS       int                        `json:"timeout_ms"`
	DataTimeoutMS   int                        `json:"data_timeout_ms"`
	HangAt          string                     `json:"hang_at"`
	Barrier         int                        `json:"barrier"`
	TLS             bool                       `json:"tls"`
	AdvertiseTLS    bool                       `json:"advertise_tls"`
	StartTLSReply   string                     `json:"starttls_reply"`
	TLSFinal        bool                       `json:"tls_final"`
	Name            string                     `json:"name"`
	SQL             string                     `json:"sql"`
	MX              map[string][]string        `json:"mx"`
	Replies         map[string]string          `json:"replies"`
	Greeting        string                     `json:"greeting"`
	DataReply       string                     `json:"data_reply"`
	FinalReply      string                     `json:"final_reply"`
	Ticks           int                        `json:"ticks"`
}
type outboundReceipt struct {
	Host     string   `json:"host"`
	Commands []string `json:"commands"`
	Data     []string `json:"data"`
}

func TestRecordSMTPOutbound(t *testing.T) {
	root := os.Getenv("SMTP_ORACLE_DIR")
	if root == "" {
		t.Fatal("SMTP_ORACLE_DIR required")
	}
	corpus := os.Getenv("SMTP_OUTBOUND_CORPUS")
	if corpus == "" {
		corpus = "outbound"
	}
	output := filepath.Join(root, corpus+"-go.json")
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("golden exists or inaccessible")
	}
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	if os.Getenv("SMTP_OUTBOUND_GENERATE_PREP") == "1" {
		var baseline []outboundCase
		if e := json.Unmarshal(read("outbound-requests.json"), &baseline); e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(root, corpus+"-requests.json")
		if _, e := os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("stimulus already exists")
		}
		cases := outboundPreparationCases(t, baseline[0])
		if strings.HasSuffix(corpus, "-edge") {
			var edges []outboundCase
			for _, c := range cases {
				if strings.HasPrefix(c.Name, "unwrap-edge-") {
					edges = append(edges, c)
				}
			}
			cases = edges
		}
		b, e := json.MarshalIndent(cases, "", "  ")
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, append(b, '\n'), 0644); e != nil {
			t.Fatal(e)
		}
	}
	var cases []outboundCase
	if err := json.Unmarshal(read(corpus+"-requests.json"), &cases); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(root, "../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"))
	cert, e := tls.LoadX509KeyPair(filepath.Join(root, "../../../../tests/conformance/directory-sync/ldap-fixture/server.pem"), filepath.Join(root, "../../../../tests/conformance/directory-sync/ldap-fixture/server.p8"))
	if e != nil {
		t.Fatal(e)
	}
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	exec := func(sql string) {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	cleanup := string(read("outbound-cleanup.sql"))
	t.Cleanup(func() { exec(cleanup) })
	var recordings []map[string]any
	for _, c := range cases {
		exec(cleanup)
		exec(string(read("seed.sql")))
		exec(c.SQL)
		if c.TeardownSQL != "" {
			teardown := c.TeardownSQL
			t.Cleanup(func() { exec(teardown) })
		}
		restoreDNS := smtpOracleDNS(c.DNS)
		oldExchange := exchangeTLSA
		lookupIndex := 0
		exchangeTLSA = func(name string) (*dns.Msg, error) {
			if len(c.TLSA) == 0 {
				return nil, fmt.Errorf("fixture TLSA lookup failure")
			}
			i := lookupIndex
			lookupIndex++
			if i >= len(c.TLSA) {
				i = len(c.TLSA) - 1
			}
			var answer struct {
				AD      bool     `json:"ad"`
				Rcode   int      `json:"rcode"`
				Records []string `json:"records"`
			}
			if err := json.Unmarshal(c.TLSA[i], &answer); err != nil {
				return nil, fmt.Errorf("fixture TLSA lookup failure")
			}
			msg := new(dns.Msg)
			msg.AuthenticatedData = answer.AD
			msg.Rcode = answer.Rcode
			for _, text := range answer.Records {
				rr, err := dns.NewRR(name + " 60 IN TLSA " + text)
				if err != nil {
					return nil, err
				}
				msg.Answer = append(msg.Answer, rr)
			}
			return msg, nil
		}
		InitMTASTSCache(pool)
		var mu sync.Mutex
		var policyRequests []string
		oldHTTPClient := smtpTransportHTTPClient
		var policyServer *httptest.Server
		if c.PolicyBody != nil {
			if os.Getenv("SMTP_TRANSPORT_OVERLAY") != "1" {
				t.Fatal("policy HTTP fixtures require record-transport.py overlay")
			}
			policyServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				policyRequests = append(policyRequests, r.Method+" "+r.Host+" "+r.URL.Path)
				mu.Unlock()
				status := c.PolicyStatus
				if status == 0 {
					status = 200
				}
				if status == 302 {
					w.Header().Set("Location", "/other")
				}
				if c.PolicyGzip {
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.WriteHeader(status)
				if c.PolicyGzip {
					z := gzip.NewWriter(w)
					io.WriteString(z, *c.PolicyBody)
					z.Close()
				} else {
					io.WriteString(w, *c.PolicyBody)
				}
			}))
			client := policyServer.Client()
			client.Timeout = 10 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			tr := client.Transport.(*http.Transport)
			tr.TLSClientConfig.ServerName = "example.com"
			tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, policyServer.Listener.Addr().String())
			}
			smtpTransportHTTPClient = func(time.Duration) *http.Client { return client }
		}
		var receipts []*outboundReceipt
		var peers sync.WaitGroup
		gate := make(chan struct{})
		if c.Barrier == 0 {
			close(gate)
		}
		accepted := 0
		var conns []net.Conn
		var listeners []net.Listener
		addresses := map[string]string{}
		for _, hosts := range c.MX {
			for _, host := range hosts {
				if _, ok := addresses[host]; ok {
					continue
				}
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				addresses[host] = ln.Addr().String()
				listeners = append(listeners, ln)
				peers.Add(1)
				go func(host string, ln net.Listener) {
					defer peers.Done()
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						mu.Lock()
						conns = append(conns, conn)
						accepted++
						if c.Barrier > 0 && accepted == c.Barrier {
							close(gate)
						}
						r := &outboundReceipt{Host: host, Commands: []string{}, Data: []string{}}
						receipts = append(receipts, r)
						mu.Unlock()
						peers.Add(1)
						go func() {
							defer peers.Done()
							defer conn.Close()
							reader := bufio.NewReader(conn)
							reply := func(s string) { fmt.Fprint(conn, s+"\r\n") }
							if c.HangAt == "greeting" {
								io.Copy(io.Discard, conn)
								return
							}
							greeting := c.Greeting
							if greeting == "" {
								greeting = "220 fake ready"
							}
							reply(greeting)
							for {
								line, err := reader.ReadString('\n')
								if err != nil {
									return
								}
								line = strings.TrimRight(line, "\r\n")
								recorded := line
								if strings.HasPrefix(line, "EHLO ") {
									recorded = "EHLO <hostname>"
								}
								r.Commands = append(r.Commands, recorded)
								switch {
								case strings.HasPrefix(line, "EHLO "):
									<-gate
									if c.HangAt == "ehlo" {
										io.Copy(io.Discard, conn)
										return
									}
									reply("250-fake")
									if c.AdvertiseTLS {
										reply("250-STARTTLS")
									}
									if c.TLSFinal {
										reply("250 STARTTLS")
									} else {
										reply("250 PIPELINING")
									}
								case line == "STARTTLS":
									v := c.StartTLSReply
									if v == "" {
										v = "220 go ahead"
									}
									reply(v)
									if strings.HasPrefix(v, "220") {
										upgraded := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
										if e := upgraded.Handshake(); e != nil {
											return
										}
										conn = upgraded
										reader = bufio.NewReader(conn)
									}
								case strings.HasPrefix(line, "RCPT TO:"):
									v := c.Replies[line]
									if v == "" {
										v = c.Replies[host]
									}
									if v == "" {
										v = "250 recipient ok"
									}
									reply(v)
								case line == "DATA":
									if c.HangAt == "data" {
										io.Copy(io.Discard, conn)
										return
									}
									v := c.DataReply
									if v == "" {
										v = "354 send body"
									}
									reply(v)
									if !strings.HasPrefix(v, "354") {
										continue
									}
									var body strings.Builder
									for {
										s, e := reader.ReadString('\n')
										if e != nil {
											return
										}
										body.WriteString(s)
										if s == ".\r\n" {
											break
										}
									}
									r.Data = append(r.Data, base64.StdEncoding.EncodeToString([]byte(body.String())))
									if c.HangAt == "final" {
										io.Copy(io.Discard, conn)
										return
									}
									v = c.FinalReply
									if v == "" {
										v = "250 queued"
									}
									reply(v)
								default:
									reply("250 ok")
								}
							}
						}()
					}
				}(host, ln)
			}
		}
		var blobRequests []string
		store := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
			mu.Lock()
			blobRequests = append(blobRequests, request.Method+" "+request.URL.Path)
			mu.Unlock()
			key := strings.TrimPrefix(request.URL.Path, "/mail/")
			if value, ok := c.Blobs[key]; ok {
				data, e := base64.StdEncoding.DecodeString(value)
				if e != nil {
					t.Error(e)
				}
				for key, value := range c.BlobHeaders {
					rw.Header().Set(key, value)
				}
				rw.Header().Set("ETag", `"smtp3"`)
				rw.Header().Set("Content-Type", "application/octet-stream")
				rw.Header().Set("Content-Length", fmt.Sprint(len(data)))
				rw.Write(data)
				return
			}
			rw.Header().Set("Content-Type", "application/xml")
			rw.WriteHeader(404)
			io.WriteString(rw, `<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Resource>/mail/missing</Resource><RequestId>smtp3</RequestId></Error>`)
		}))
		client, e := minio.New(strings.TrimPrefix(store.URL, "http://"), &minio.Options{Creds: credentials.NewStaticV4("smtp3-access", "smtp3-secret", ""), Secure: false, Region: "us-east-1"})
		if e != nil {
			t.Fatal(e)
		}
		var logs bytes.Buffer
		var alerts []string
		var listener *pgxpool.Conn
		if c.Backlog {
			direct, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			listener = direct
			if _, err = direct.Exec(ctx, `LISTEN "admin:alert"`); err != nil {
				t.Fatal(err)
			}

		}
		flags := emptyToggles()
		if c.Transport != nil {
			flags = toggle.NewStatic(c.Transport)
		}
		if c.TransportFromDB {
			var err error
			flags, err = toggle.New(ctx, pool, nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		w := NewOutboundWorker(pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewJSONHandler(&logs, nil)), "mail", client, flags)
		w.SetLinkProtectKeys(linkprotect.NewTokenKeys([]byte(c.LinkSecret), []byte(c.LinkPrevious), c.LinkVersion))
		w.lookupMXFn = func(domain string) ([]*net.MX, error) {
			var mx []*net.MX
			for _, host := range c.MX[domain] {
				mx = append(mx, &net.MX{Host: host})
			}
			return mx, nil
		}
		w.dialMX = func(addr string) (net.Conn, error) {
			host := strings.TrimSuffix(addr, ":25") + "."
			return net.Dial("tcp", addresses[host])
		}
		w.commandTimeout = time.Second * 5
		w.dataTimeout = time.Second * 5
		if c.TimeoutMS > 0 {
			w.commandTimeout = time.Duration(c.TimeoutMS) * time.Millisecond
		}
		if c.DataTimeoutMS > 0 {
			w.dataTimeout = time.Duration(c.DataTimeoutMS) * time.Millisecond
		}
		ticks := c.Ticks
		if ticks == 0 {
			ticks = 1
		}
		for i := 0; i < ticks; i++ {
			w.processBatch(ctx)
			for j := 0; j < cap(w.sem); j++ {
				w.sem <- struct{}{}
			}
			for j := 0; j < cap(w.sem); j++ {
				<-w.sem
			}
			if i < len(c.BetweenTicksSQL) {
				exec(c.BetweenTicksSQL[i])
				if c.TransportFromDB {
					if err := w.toggles.Reload(ctx); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		for _, ln := range listeners {
			ln.Close()
		}
		mu.Lock()
		for _, conn := range conns {
			conn.Close()
		}
		mu.Unlock()
		peers.Wait()
		store.Close()
		if policyServer != nil {
			policyServer.Close()
		}
		smtpTransportHTTPClient = oldHTTPClient
		restoreDNS()
		exchangeTLSA = oldExchange
		mtaSTSCache = &MTASTSPolicyCache{cache: make(map[string]*MTASTSPolicy)}
		sort.SliceStable(receipts, func(i, j int) bool {
			a, _ := json.Marshal(receipts[i])
			b, _ := json.Marshal(receipts[j])
			return string(a) < string(b)
		})
		if receipts == nil {
			receipts = []*outboundReceipt{}
		}
		observeFile := c.ObserveFile
		if observeFile == "" {
			observeFile = "outbound-observe.sql"
		}
		var observation json.RawMessage
		if err := pool.QueryRow(ctx, string(read(observeFile))).Scan(&observation); err != nil {
			t.Fatal(err)
		}
		observation = json.RawMessage(regexp.MustCompile(`(read|write) tcp [^ ]+: i/o timeout`).ReplaceAllString(string(observation), "$1 tcp <local>-><peer>: i/o timeout"))
		if c.TeardownSQL != "" {
			exec(c.TeardownSQL)
		}
		recording := map[string]any{"case": c, "receipts": receipts, "effects": observation, "blob_requests": blobRequests}
		if c.PolicyBody != nil {
			if policyRequests == nil {
				policyRequests = []string{}
			}
			recording["policy_requests"] = policyRequests
		}
		if c.Backlog {
			wait, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			for {
				n, err := listener.Conn().WaitForNotification(wait)
				if err != nil {
					break
				}
				alerts = append(alerts, n.Payload)
			}
			cancel()
			listener.Release()
			var warnings []map[string]any
			for _, line := range bytes.Split(logs.Bytes(), []byte{'\n'}) {
				if len(line) == 0 {
					continue
				}
				var log map[string]any
				if err := json.Unmarshal(line, &log); err != nil {
					t.Fatal(err)
				}
				if log["msg"] == "outbound queue backlog" {
					delete(log, "time")
					warnings = append(warnings, log)
				}
			}
			recording["backlog_warnings"] = warnings
			recording["admin_alerts"] = alerts
		}
		recordings = append(recordings, recording)
	}
	bytes, err := json.MarshalIndent(recordings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, append(bytes, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
}
