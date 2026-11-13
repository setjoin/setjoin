//go:build gofree_record

package smtp

// Network fixtures only. Verdicts come from frozen production delivery.
import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"regexp"
	"setjoin.com/mailserver/internal/config"
	"setjoin.com/mailserver/internal/linkprotect"
	"setjoin.com/mailserver/internal/spam"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func smtpOracleSystemDNS(t *testing.T, records map[string]json.RawMessage) func() {
	t.Helper()
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			q := query.Questions[0]
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			raw, found := records["ip:"+strings.TrimSuffix(q.Name.String(), ".")]
			if !found {
				reply.RCode = dnsmessage.RCodeNameError
			} else {
				var ips []string
				if json.Unmarshal(raw, &ips) != nil {
					reply.RCode = dnsmessage.RCodeServerFailure
				} else if q.Type == dnsmessage.TypeA {
					for _, value := range ips {
						if ip := net.ParseIP(value).To4(); ip != nil {
							var address [4]byte
							copy(address[:], ip)
							reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address}})
						}
					}
				}
			}
			wire, err := reply.Pack()
			if err == nil {
				_, _ = socket.WriteTo(wire, peer)
			}
		}
	}()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return net.Dial("udp", socket.LocalAddr().String())
	}}
	return func() { net.DefaultResolver = old; _ = socket.Close(); <-done }
}

type smtpOracleModelTrain struct {
	User  int64  `json:"user"`
	Raw   string `json:"raw"`
	Spam  bool   `json:"spam"`
	Steps int    `json:"steps"`
}

func smtpOracleSpamStore(t *testing.T, pool *pgxpool.Pool, session *smtpOracleSession) *spam.PGModelStore {
	t.Helper()
	ctx := context.Background()
	store := spam.NewPGModelStore(pgxutil.WorkerPool{Pool: pool}, nil, "")
	for _, train := range session.TrainModels {
		model, err := store.LoadModel(ctx, train.User)
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < train.Steps; n++ {
			model.Train([]byte(train.Raw), train.Spam)
		}
		raw, err := model.Save()
		if err != nil {
			t.Fatal(err)
		}
		if err = store.SaveModel(ctx, train.User, raw, nil); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := pool.Query(ctx, "SELECT user_id,model_bytes FROM user_spam_model WHERE user_id BETWEEN 9348011 AND 9348013 ORDER BY user_id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	session.Models = map[string]string{}
	for rows.Next() {
		var user int64
		var raw []byte
		if err = rows.Scan(&user, &raw); err != nil {
			t.Fatal(err)
		}
		var packed bytes.Buffer
		gz := gzip.NewWriter(&packed)
		if _, err = gz.Write(raw); err != nil {
			t.Fatal(err)
		}
		if err = gz.Close(); err != nil {
			t.Fatal(err)
		}
		session.Models[strconv.FormatInt(user, 10)] = base64.StdEncoding.EncodeToString(packed.Bytes())
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return store
}
func smtpOracleBatchStats(server *InboundServer) json.RawMessage {
	store, ok := server.spamStore.(*spam.PGModelStore)
	if !ok {
		return nil
	}
	raw, _ := json.Marshal(store.BatchLoadStats())
	return raw
}
func smtpOracleBatchFinished(t *testing.T, server *InboundServer) json.RawMessage {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for atomic.LoadInt32(&server.connCount) > 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if atomic.LoadInt32(&server.connCount) != 0 {
		t.Fatal("SMTP connections did not close")
	}
	return smtpOracleBatchStats(server)
}

type smtpOraclePipeline struct {
	LinkSecret   string `json:"link_secret,omitempty"`
	LinkPrevious string `json:"link_previous,omitempty"`
	LinkVersion  int    `json:"link_version,omitempty"`
	// Observation only: recovered from Go's minted tokens, never injected into Go time.
	LinkClock        *int64   `json:"link_clock,omitempty"`
	CAPE             bool     `json:"cape,omitempty"`
	CAPEScore        float64  `json:"cape_score,omitempty"`
	CAPEStatus       string   `json:"cape_status,omitempty"`
	CAPEFamily       string   `json:"cape_family,omitempty"`
	CAPETimeoutMS    int      `json:"cape_timeout_ms,omitempty"`
	CAPEFailMode     string   `json:"cape_fail_mode,omitempty"`
	CAPESubmitStatus int      `json:"cape_submit_status,omitempty"`
	CAPEViewStatus   int      `json:"cape_view_status,omitempty"`
	CAPEZeroID       bool     `json:"cape_zero_id,omitempty"`
	CAPEMalformed    bool     `json:"cape_malformed,omitempty"`
	ClamReply        string   `json:"clam_reply,omitempty"`
	ClamPingReply    string   `json:"clam_ping_reply,omitempty"`
	ClamClose        bool     `json:"clam_close,omitempty"`
	AntiPhish        bool     `json:"anti_phish,omitempty"`
	InternalDomains  []string `json:"internal_domains,omitempty"`
	ProtectedDomains []string `json:"protected_domains,omitempty"`
	NameThreshold    float64  `json:"name_threshold,omitempty"`
}

func smtpOracleConfigurePipeline(t *testing.T, server *InboundServer, pipeline *smtpOraclePipeline, pool *pgxpool.Pool, flags *toggle.FeatureFlags) func() []map[string]any {
	peers := &smtpOraclePeers{connections: map[net.Conn]bool{}}
	if pipeline.ClamReply != "" {
		peers.clamd(t, server, pipeline)
	}
	if pipeline.CAPE {
		peers.cape(t, server, pipeline)
	}
	if pipeline.AntiPhish {
		server.SetAntiPhish(BuildAntiPhishDetectors(&config.Config{InternalDomains: strings.Join(pipeline.InternalDomains, ","), ProtectedDomains: strings.Join(pipeline.ProtectedDomains, ","), AntiphishNameThreshold: pipeline.NameThreshold}, pool, flags))
	}
	if pipeline.LinkSecret != "" {
		server.SetLinkProtect([]byte(pipeline.LinkSecret), pipeline.InternalDomains)
		server.SetLinkProtectKeys(linkprotect.NewTokenKeys([]byte(pipeline.LinkSecret), []byte(pipeline.LinkPrevious), pipeline.LinkVersion))
	}
	return peers.finish
}

func smtpOracleLinkClock(t *testing.T, pipeline *smtpOraclePipeline, blobs map[string]string) {
	t.Helper()
	if pipeline == nil || pipeline.LinkSecret == "" {
		return
	}
	pattern := regexp.MustCompile(`/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)`)
	keys := linkprotect.NewTokenKeys([]byte(pipeline.LinkSecret), []byte(pipeline.LinkPrevious), pipeline.LinkVersion)
	for _, packed := range blobs {
		raw, err := base64.StdEncoding.DecodeString(packed)
		if err != nil {
			t.Fatal(err)
		}
		message, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			continue
		}
		body, err := io.ReadAll(message.Body)
		if err != nil {
			t.Fatal(err)
		}
		mid := message.Header.Get("Message-ID")
		var visit func([]byte, string, string)
		visit = func(body []byte, ct, cte string) {
			var err error
			encoding := ""
			if fields := strings.Fields(strings.ToLower(cte)); len(fields) > 0 {
				encoding = fields[0]
			}
			switch encoding {
			case "base64":
				body, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
			case "quoted-printable":
				body, err = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
			}
			if err != nil {
				return
			}
			kind, params, _ := mime.ParseMediaType(ct)
			if strings.HasPrefix(kind, "multipart/") && params["boundary"] != "" {
				reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
				for {
					part, e := reader.NextRawPart()
					if e != nil {
						break
					}
					data, e := io.ReadAll(part)
					if e != nil {
						// Intentionally malformed MIME cases have no minted token.
						return
					}
					visit(data, part.Header.Get("Content-Type"), part.Header.Get("Content-Transfer-Encoding"))
					part.Close()
				}
				return
			}
			for _, match := range pattern.FindAllStringSubmatch(string(body), -1) {
				claims, e := linkprotect.VerifyTokenN(match[1], keys)
				if e != nil || claims.MessageID != mid {
					continue
				}
				clock := claims.ExpiresAt - int64(30*24*time.Hour/time.Second)
				if pipeline.LinkClock != nil && *pipeline.LinkClock != clock {
					t.Fatal("fixture minted across two Unix seconds; split its deliveries into separate cases")
				}
				pipeline.LinkClock = &clock
			}
		}
		visit(body, message.Header.Get("Content-Type"), message.Header.Get("Content-Transfer-Encoding"))
	}
}

type smtpOraclePeers struct {
	mu          sync.Mutex
	connections map[net.Conn]bool
	listeners   []net.Listener
	servers     []*httptest.Server
	wg          sync.WaitGroup
	events      []map[string]any
}

func (p *smtpOraclePeers) clamd(t *testing.T, server *InboundServer, cfg *smtpOraclePipeline) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.SetClamAV(listener.Addr().String())
	if cfg.ClamReply == "unavailable" {
		_ = listener.Close()
		return
	}
	p.listeners = append(p.listeners, listener)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.connections[conn] = true
			p.mu.Unlock()
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					command, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					event := map[string]any{"kind": "clamav", "command": command}
					reply := "PONG\n"
					if command == "nINSTREAM\n" {
						var data []byte
						for {
							var size uint32
							if binary.Read(reader, binary.BigEndian, &size) != nil {
								return
							}
							if size == 0 {
								break
							}
							if size > 4096 {
								return
							}
							chunk := make([]byte, size)
							if _, err = io.ReadFull(reader, chunk); err != nil {
								return
							}
							data = append(data, chunk...)
						}
						event["length"] = len(data)
						event["sha256"] = fmt.Sprintf("%x", sha256.Sum256(data))
						reply = cfg.ClamReply + "\n"
					} else if cfg.ClamPingReply != "" {
						reply = cfg.ClamPingReply + "\n"
					}
					p.mu.Lock()
					p.events = append(p.events, event)
					p.mu.Unlock()
					if cfg.ClamReply == "eof" && command == "nINSTREAM\n" {
						return
					}
					if _, err = io.WriteString(conn, reply); err != nil {
						return
					}
					if cfg.ClamClose {
						return
					}
				}
			}()
		}
	}()
}
func (p *smtpOraclePeers) finish() []map[string]any {
	for _, server := range p.servers {
		server.Close()
	}
	for _, listener := range p.listeners {
		_ = listener.Close()
	}
	p.mu.Lock()
	for conn := range p.connections {
		_ = conn.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	return p.events
}

func (p *smtpOraclePeers) cape(t *testing.T, server *InboundServer, cfg *smtpOraclePipeline) {
	t.Helper()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event := map[string]any{"kind": "cape", "method": r.Method, "path": r.URL.Path, "authorization": r.Header.Get("Authorization")}
		if r.Method == "POST" {
			file, header, err := r.FormFile("file")
			if err != nil {
				t.Error(err)
				http.Error(w, "bad multipart", 400)
				return
			}
			raw, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				t.Error(err)
				return
			}
			event["filename"] = header.Filename
			event["length"] = len(raw)
			event["sha256"] = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
		p.mu.Lock()
		p.events = append(p.events, event)
		p.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/apiv2/tasks/status/health/":
			io.WriteString(w, "{}")
		case "/apiv2/tasks/create/file/":
			if cfg.CAPESubmitStatus != 0 {
				w.WriteHeader(cfg.CAPESubmitStatus)
			}
			if cfg.CAPEZeroID {
				io.WriteString(w, `{"task_id":0}`)
			} else {
				io.WriteString(w, `{"task_id":42}`)
			}
		case "/apiv2/tasks/view/42":
			if cfg.CAPEViewStatus != 0 {
				w.WriteHeader(cfg.CAPEViewStatus)
			}
			if cfg.CAPEMalformed {
				io.WriteString(w, "not json")
				return
			}
			status := cfg.CAPEStatus
			if status == "" {
				status = "reported"
			}
			family := cfg.CAPEFamily
			if family == "" {
				family = "CAPE.Test"
			}
			json.NewEncoder(w).Encode(map[string]any{"task": map[string]any{"id": 42, "status": status}, "info": map[string]any{"score": cfg.CAPEScore, "signatures": []string{"first", family}}})
		default:
			http.Error(w, "unknown", 404)
		}
	}))
	p.servers = append(p.servers, fixture)
	timeout := time.Duration(cfg.CAPETimeoutMS) * time.Millisecond
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	fail := FailOpen
	if cfg.CAPEFailMode == "closed" {
		fail = FailClosed
	}
	server.SetSandbox(NewAttachmentAnalysisPipeline([]SandboxAnalyzer{NewCAPEAnalyzer(fixture.URL, "smtp6-cape-key", timeout)}, timeout, fail, server.logger))
}
