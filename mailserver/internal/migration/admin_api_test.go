package migration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/webhook"
	"setjoin.com/shared/testsupport"
)

func newTestAdminAPI() *AdminAPI {
	a := NewAdminAPI(&Orchestrator{logger: testsupport.TestLogger()})
	a.imapDialContext = (&net.Dialer{}).DialContext
	return a
}

func doJSON(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/migration/test-connection", strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

func TestAdminTestConnection_Validation(t *testing.T) {
	a := newTestAdminAPI()
	cases := []struct {
		name string
		body string
	}{
		{"bad json", `{`},
		{"unknown source type", `{"source_type":"pop3"}`},
		{"imap missing host", `{"source_type":"imap","port":993}`},
		{"ews missing url", `{"source_type":"ews","username":"DOM\\svc"}`},
		{"ews non-http scheme", `{"source_type":"ews","url":"file:///etc/passwd"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, a.TestConnection, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

func TestAdminTestConnection_IMAPReachable(t *testing.T) {
	s := newMockIMAPServer(t)
	defer s.close()

	a := newTestAdminAPI()
	// The admin console sends no IMAP credentials — reachability-only check.
	body := fmt.Sprintf(`{"source_type":"imap","host":"127.0.0.1","port":%d,"ssl":false}`, mustPort(s.addr))
	w := doJSON(t, a.TestConnection, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !resp.OK {
		t.Errorf("body = %s, want {\"ok\":true}", w.Body.String())
	}
}

func TestAdminTestConnection_IMAPWithCredentials(t *testing.T) {
	s := newMockIMAPServer(t)
	defer s.close()

	a := newTestAdminAPI()
	body := fmt.Sprintf(`{"source_type":"imap","host":"127.0.0.1","port":%d,"ssl":false,"username":%q,"password":%q}`,
		mustPort(s.addr), s.validUser, s.validPass)
	w := doJSON(t, a.TestConnection, body)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", w.Code, w.Body.String())
	}

	// Wrong credentials must surface as a failure, not a false success.
	body = fmt.Sprintf(`{"source_type":"imap","host":"127.0.0.1","port":%d,"ssl":false,"username":"evil","password":"wrong"}`,
		mustPort(s.addr))
	w = doJSON(t, a.TestConnection, body)
	if w.Code != http.StatusBadGateway {
		t.Errorf("bad-credentials status = %d, want 502 (body: %s)", w.Code, w.Body.String())
	}
}

func TestAdminTestConnection_IMAPRefused(t *testing.T) {
	a := newTestAdminAPI()
	// Port 1 on loopback: nothing listens there — connection refused.
	w := doJSON(t, a.TestConnection, `{"source_type":"imap","host":"127.0.0.1","port":1,"ssl":false}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "connection failed") {
		t.Errorf("body = %q, want an actionable 'connection failed: …' message", w.Body.String())
	}
}

func TestAdminTestConnection_EWSRejectsPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	defer srv.Close()

	a := newTestAdminAPI()
	body := fmt.Sprintf(`{"source_type":"ews","url":%q,"username":"DOM\\svc","password":"pw"}`, srv.URL)
	w := doJSON(t, a.TestConnection, body)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
}

func TestAdminStart_Unauthorized(t *testing.T) {
	a := newTestAdminAPI()
	req := httptest.NewRequest(http.MethodPost, "/admin/migration/start",
		strings.NewReader(`{"source_type":"imap","imap_host":"h","targets":[{"source_email":"a@b","target_email":"c@d"}]}`))
	w := httptest.NewRecorder()
	a.Start(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestAdminStart_Validation(t *testing.T) {
	a := newTestAdminAPI()
	cases := []struct {
		name string
		body string
	}{
		{"bad json", `{`},
		{"unknown source type", `{"source_type":"pop3","targets":[{"source_email":"a@b","target_email":"c@d"}]}`},
		{"no targets", `{"source_type":"imap","imap_host":"mail.example.com","targets":[]}`},
		{"imap missing host", `{"source_type":"imap","targets":[{"source_email":"a@b","target_email":"c@d"}]}`},
		{"ews missing url", `{"source_type":"ews","targets":[{"source_email":"a@b","target_email":"c@d"}]}`},
		{"ews non-http scheme", `{"source_type":"ews","ews_url":"ftp://x","targets":[{"source_email":"a@b","target_email":"c@d"}]}`},
		{"target missing emails", `{"source_type":"imap","imap_host":"h","targets":[{"source_email":"","target_email":"c@d"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/migration/start", strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
			w := httptest.NewRecorder()
			a.Start(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
			}
		})
	}
}

// adminStartFixture creates a domain + user + primary mailbox and returns
// (adminUserID, targetEmail, mailboxID). Rows are cleaned up in FK order.
func adminStartFixture(t *testing.T, pool *pgxpool.Pool) (int64, string, int64) {
	t.Helper()
	ctx := context.Background()

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ('setjoin.test')
		 ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`).Scan(&domainID); err != nil {
		t.Fatalf("fixture domain: %v", err)
	}

	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	email := fmt.Sprintf("mig-%x@setjoin.test", suffix)

	var userID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, password_hash)
		 VALUES ($1, $2, $1, 'Migration Target', '$2a$10$placeholder')
		 RETURNING id`, email, domainID).Scan(&userID); err != nil {
		t.Fatalf("fixture user: %v", err)
	}

	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO mailboxes (user_id, domain_id, email, display_name, is_primary)
		 VALUES ($1, $2, $3, 'Migration Target', true)
		 RETURNING id`, userID, domainID, email).Scan(&mailboxID); err != nil {
		t.Fatalf("fixture mailbox: %v", err)
	}

	t.Cleanup(func() {
		cctx := context.Background()
		pool.Exec(cctx, `DELETE FROM migration_jobs WHERE target_mailbox_id = $1`, mailboxID)
		pool.Exec(cctx, `DELETE FROM mailboxes WHERE id = $1`, mailboxID)
		pool.Exec(cctx, `DELETE FROM users WHERE id = $1`, userID)
	})
	return userID, email, mailboxID
}

func TestAdminStart_IMAPCreatesJob(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	orch := NewOrchestrator(pool, nil, "", "test-root-key", logger, context.Background(), webhook.NewDispatcher(pool, logger))
	a := NewAdminAPI(orch)

	adminID, targetEmail, mailboxID := adminStartFixture(t, pool)

	// A listener that accepts but never greets used to keep the background
	// job blocked in dial. Since the migration dialer gained the SSRF guard,
	// loopback is rejected before connect (permanently blocked range, not
	// allowlistable), so the job can legitimately reach "failed" within
	// milliseconds — before or after the row read below, a pure scheduling
	// race. The row-shape and credential pins are the test's subject; the
	// loopback-rejection property itself is pinned by shared/ssrf tests.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()

	body := fmt.Sprintf(`{
		"source_type": "imap",
		"auth_mode": "per_user",
		"imap_host": "127.0.0.1",
		"imap_port": %d,
		"imap_ssl": false,
		"targets": [{"source_email": "old@legacy.example", "target_email": %q, "password": "pw1"}]
	}`, mustPort(l.Addr().String()), targetEmail)

	req := httptest.NewRequest(http.MethodPost, "/admin/migration/start", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: adminID, IsAdmin: true}))
	w := httptest.NewRecorder()
	a.Start(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body: %s)", w.Code, w.Body.String())
	}
	var resp struct {
		IDs    []int64 `json:"ids"`
		Status string  `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(resp.IDs) != 1 || resp.Status != "pending" {
		t.Fatalf("response = %+v, want 1 id with status pending", resp)
	}

	// The row must have the shape the orchestrator's loadJob/createConnector
	// consume: creator user_id, source_type, resolved target mailbox, and a
	// source_config_enc that decrypts to the MigrationJobConfig wrapper with
	// the per-target credentials.
	var row struct {
		UserID     int64
		SourceType string
		Status     string
		MailboxID  int64
		ConfigEnc  []byte
		Strategy   string
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT user_id, source_type, status, target_mailbox_id, source_config_enc, conflict_strategy
		 FROM migration_jobs WHERE id = $1`, resp.IDs[0],
	).Scan(&row.UserID, &row.SourceType, &row.Status, &row.MailboxID, &row.ConfigEnc, &row.Strategy); err != nil {
		t.Fatalf("job row not created: %v", err)
	}
	if row.UserID != adminID {
		t.Errorf("user_id = %d, want creating admin %d", row.UserID, adminID)
	}
	if row.SourceType != "imap" {
		t.Errorf("source_type = %q, want imap", row.SourceType)
	}
	if row.MailboxID != mailboxID {
		t.Errorf("target_mailbox_id = %d, want %d", row.MailboxID, mailboxID)
	}
	if row.Strategy != "skip" {
		t.Errorf("conflict_strategy = %q, want skip", row.Strategy)
	}
	// Initial status is 'pending'; the started background job may have
	// advanced by read time — through the early lifecycle, or straight to
	// "failed" when the SSRF dialer rejects the loopback source before
	// connect. Any known lifecycle value is acceptable here; asserting
	// "never terminal this fast" was a scheduling race, not a contract.
	switch row.Status {
	case "pending", "testing", "fetching", "failed":
	default:
		t.Errorf("status = %q, want a known lifecycle status", row.Status)
	}

	var jobCfg MigrationJobConfig
	if err := DecryptConfigAny(row.ConfigEnc, orch.EncryptionKey(), &jobCfg); err != nil {
		t.Fatalf("decrypt job config: %v", err)
	}
	if jobCfg.SourceType != "imap" || jobCfg.IMAP == nil {
		t.Fatalf("job config = %+v, want wrapper with IMAP config", jobCfg)
	}
	if jobCfg.IMAP.Credentials.Username != "old@legacy.example" || jobCfg.IMAP.Credentials.Password != "pw1" {
		t.Errorf("per-target credentials not stored: %+v", jobCfg.IMAP.Credentials)
	}
	if jobCfg.IMAP.TLSMode != "none" {
		t.Errorf("tls_mode = %q, want none for ssl:false", jobCfg.IMAP.TLSMode)
	}
}

func TestAdminStart_UnknownTargetEmail(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	logger := testsupport.TestLogger()
	orch := NewOrchestrator(pool, nil, "", "test-root-key", logger, context.Background(), webhook.NewDispatcher(pool, logger))
	a := NewAdminAPI(orch)

	body := `{
		"source_type": "imap",
		"imap_host": "127.0.0.1",
		"targets": [{"source_email": "old@legacy.example", "target_email": "nobody@setjoin.test"}]
	}`
	req := httptest.NewRequest(http.MethodPost, "/admin/migration/start", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true}))
	w := httptest.NewRecorder()
	a.Start(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "nobody@setjoin.test") {
		t.Errorf("body = %q, want the unmatched target email named", w.Body.String())
	}
}

// TestResolveConfig_UnwrapsJobConfigWithoutGlobalAuth pins the non-global
// consumption shape: producers store the MigrationJobConfig wrapper, and the
// factories decrypt the resolved bytes straight into a bare connector config —
// so resolveConfig must unwrap the inner config when no global merge runs.
func TestResolveConfig_UnwrapsJobConfigWithoutGlobalAuth(t *testing.T) {
	key, err := DeriveKey("test-root", "migration")
	if err != nil {
		t.Fatal(err)
	}
	o := &Orchestrator{encryptionKey: key, logger: testsupport.TestLogger()}

	wrapper := MigrationJobConfig{
		SourceType: "imap",
		IMAP: &IMAPConfig{
			Host: "mail.example.com", Port: 993, TLSMode: "tls",
			Credentials: IMAPCredentials{Username: "alice@example.com", Password: "pw"},
		},
	}
	enc, err := EncryptConfigAny(wrapper, key)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := imapFactory{o}.Create(context.Background(), 0, enc, false)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	imapConn, ok := conn.(*IMAPConnector)
	if !ok {
		t.Fatalf("connector type = %T, want *IMAPConnector", conn)
	}
	if imapConn.config.Host != "mail.example.com" || imapConn.config.Credentials.Username != "alice@example.com" {
		t.Errorf("config not unwrapped: %+v", imapConn.config)
	}

	// Legacy bare-config blobs (no wrapper fields) must keep decoding as-is.
	bareEnc, err := EncryptConfigAny(wrapper.IMAP, key)
	if err != nil {
		t.Fatal(err)
	}
	conn, err = imapFactory{o}.Create(context.Background(), 0, bareEnc, false)
	if err != nil {
		t.Fatalf("Create(bare): %v", err)
	}
	if conn.(*IMAPConnector).config.Host != "mail.example.com" {
		t.Errorf("bare config regressed: %+v", conn.(*IMAPConnector).config)
	}
}
