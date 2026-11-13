//go:build integration

package admin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/mailserver/internal/approval"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/mailserver/internal/pushjobs"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

type tracerS3 struct {
	mc      *minio.Client
	bucket  string
	server  *httptest.Server
	mu      sync.Mutex
	objects map[string][]byte
}

func newTracerS3(t *testing.T) *tracerS3 {
	t.Helper()
	s := &tracerS3{bucket: "g1-tracer", objects: map[string][]byte{}}
	s.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/"+s.bucket+"/")
		if r.Method != http.MethodPut {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		s.mu.Lock()
		s.objects[key] = append([]byte(nil), body...)
		s.mu.Unlock()
		w.Header().Set("ETag", `"1"`)
		w.WriteHeader(http.StatusOK)
	}))
	host := strings.TrimPrefix(s.server.URL, "https://")
	var err error
	s.mc, err = minio.New(host, &minio.Options{
		Creds: credentials.NewStaticV4("test", "test", ""), Secure: true,
		Region: "us-east-1", Transport: s.server.Client().Transport,
	})
	if err != nil {
		s.server.Close()
		t.Fatalf("minio.New: %v", err)
	}
	t.Cleanup(s.server.Close)
	return s
}

func (s *tracerS3) get(t *testing.T, key string) []byte {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	if !ok {
		t.Fatalf("fake S3 lacks %q", key)
	}
	return append([]byte(nil), b...)
}

func (s *tracerS3) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.objects)
}

type tracerSavedConfig struct {
	value  string
	exists bool
}

type guestInviteTracerFixture struct {
	pool                         *pgxpool.Pool
	ctx                          context.Context
	s3                           *tracerS3
	handler                      *GuestsHandler
	logBuf                       *bytes.Buffer
	domainID                     int64
	adminID, requester, approver int64
	roleID                       int64
	domain, externalDomain       string
	oldGuest, oldApproval        bool
	guestToggleSaved             bool
	approvalToggleSaved          bool
	configs                      map[string]tracerSavedConfig
}

func newGuestInviteTracerFixture(t *testing.T) *guestInviteTracerFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("TEST_DB_DSN/DB_DSN unset while REQUIRE_DB is set")
		}
		t.Skip("TEST_DB_DSN/DB_DSN unset")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping test DB: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	f := &guestInviteTracerFixture{
		pool: pool, ctx: ctx, s3: newTracerS3(t),
		domain:         "g1-tracer-" + suffix + ".test",
		externalDomain: "g1-external-" + suffix + ".example",
		configs:        map[string]tracerSavedConfig{},
	}
	// Register cleanup before the first database/config mutation. The fixture
	// fields are populated in stages, and cleanup only restores stages that
	// reached their snapshot point.
	t.Cleanup(func() { f.cleanup(t) })
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id`, f.domain).Scan(&f.domainID); err != nil {
		t.Fatalf("insert tracer domain: %v", err)
	}
	insertUser := func(local, display string) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled)
			VALUES($1,$2,$3,$4,TRUE) RETURNING id`, local+suffix, f.domainID,
			local+"@"+f.domain, display).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", local, err)
		}
		return id
	}
	f.adminID = insertUser("admin", "Tracer Admin")
	f.requester = insertUser("requester", "Tracer Requester")
	f.approver = insertUser("approver", "Tracer Approver")
	if err := pool.QueryRow(ctx, `INSERT INTO admin_role_groups(name,permissions)
		VALUES($1,ARRAY['guests.manage','guests.view']) RETURNING id`, "g1-tracer-role-"+suffix).Scan(&f.roleID); err != nil {
		t.Fatalf("insert tracer role: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,$2,$1)`, f.adminID, f.roleID); err != nil {
		t.Fatalf("assign tracer role: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, toggle.FeatureGuestAccounts).Scan(&f.oldGuest); err != nil {
		t.Fatalf("read guest toggle: %v", err)
	}
	f.guestToggleSaved = true
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key='approval.guest_invite'`).Scan(&f.oldApproval); err != nil {
		t.Fatalf("read approval toggle: %v", err)
	}
	f.approvalToggleSaved = true
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=TRUE WHERE key=$1`, toggle.FeatureGuestAccounts); err != nil {
		t.Fatalf("enable guest toggle: %v", err)
	}

	for key, value := range map[string]string{
		"authserver.public_url":       "https://auth.g1-tracer.test",
		"mail.default_sender":         "invite@" + f.domain,
		"org.name":                    "G1 Tracer Org",
		"guest.invite_ttl_days":       "7",
		"guest.digest_window_minutes": "1",
	} {
		var old string
		err := pool.QueryRow(ctx, `SELECT value::text FROM system_config WHERE key=$1`, key).Scan(&old)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read config %s: %v", key, err)
		}
		f.configs[key] = tracerSavedConfig{value: old, exists: err == nil}
		if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value) VALUES($1,to_jsonb($2::text))
			ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, key, value); err != nil {
			t.Fatalf("set config %s: %v", key, err)
		}
	}

	var logs bytes.Buffer
	f.logBuf = &logs
	f.handler = NewGuestsHandler(pool,
		toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: true}),
		f.s3.mc, f.s3.bucket, slog.New(slog.NewTextHandler(&logs, nil)))
	add := f.adminRequest(http.MethodPost, "/admin/guest-invite-domains",
		fmt.Sprintf(`{"domain":%q}`, f.externalDomain))
	rr := httptest.NewRecorder()
	f.handler.AddInviteDomain(rr, add)
	if rr.Code != http.StatusCreated {
		t.Fatalf("seed allowed domain: %d %s", rr.Code, rr.Body.String())
	}
	return f
}

func (f *guestInviteTracerFixture) cleanup(t *testing.T) {
	t.Helper()
	exec := func(label, sql string, args ...any) {
		t.Helper()
		if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
			t.Errorf("cleanup %s: %v", label, err)
		}
	}
	exec("sessions", `DELETE FROM sessions WHERE user_id IN
		(SELECT user_id FROM guest_accounts WHERE host_domain_id=$1)`, f.domainID)
	exec("intents", `DELETE FROM guest_notification_intents WHERE user_id IN
		(SELECT user_id FROM guest_accounts WHERE host_domain_id=$1)`, f.domainID)
	exec("meetings", `DELETE FROM meetings WHERE owner_user_id IN ($1,$2,$3)`, f.adminID, f.requester, f.approver)
	exec("channels", `DELETE FROM chat_channels WHERE created_by IN ($1,$2,$3)`, f.adminID, f.requester, f.approver)
	exec("approval requests", `DELETE FROM approval_requests WHERE domain_id=$1`, f.domainID)
	exec("approval policies", `DELETE FROM approval_policies WHERE consumer_type='guest.invite'
		AND conditions @> jsonb_build_object('host_domain_id',$1::bigint)`, f.domainID)
	exec("outbound queue", `DELETE FROM outbound_queue WHERE EXISTS
		(SELECT 1 FROM unnest(rcpt_addrs) r WHERE r LIKE $1)`, "%@"+f.externalDomain)
	exec("invites", `DELETE FROM guest_invites WHERE host_domain_id=$1`, f.domainID)
	exec("allowed domain", `DELETE FROM guest_invite_domains WHERE domain=$1`, f.externalDomain)
	exec("guest users", `DELETE FROM users WHERE id IN
		(SELECT user_id FROM guest_accounts WHERE host_domain_id=$1)`, f.domainID)
	exec("guest profiles", `DELETE FROM guest_profiles WHERE host_domain_id=$1`, f.domainID)
	exec("role assignment", `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, f.roleID)
	exec("role", `DELETE FROM admin_role_groups WHERE id=$1`, f.roleID)
	exec("local users", `DELETE FROM users WHERE id IN ($1,$2,$3)`, f.adminID, f.requester, f.approver)
	exec("domain", `DELETE FROM domains WHERE id=$1`, f.domainID)
	if f.guestToggleSaved {
		exec("guest toggle", `UPDATE feature_toggles SET enabled=$1 WHERE key=$2`, f.oldGuest, toggle.FeatureGuestAccounts)
	}
	if f.approvalToggleSaved {
		exec("approval toggle", `UPDATE feature_toggles SET enabled=$1 WHERE key='approval.guest_invite'`, f.oldApproval)
	}
	for key, old := range f.configs {
		if old.exists {
			exec("config "+key, `UPDATE system_config SET value=$2::jsonb WHERE key=$1`, key, old.value)
		} else {
			exec("config "+key, `DELETE FROM system_config WHERE key=$1`, key)
		}
	}
	f.pool.Close()
}

func (f *guestInviteTracerFixture) adminRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: f.adminID, IsAdmin: true, Permissions: []string{permissions.PermGuestsManage},
	}))
}

func (f *guestInviteTracerFixture) invite(t *testing.T, email string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, f.adminRequest(http.MethodPost, "/admin/guests",
		fmt.Sprintf(`{"email":%q,"displayName":"Tracer Guest"}`, email)))
	return rr
}

func (f *guestInviteTracerFixture) reinvite(t *testing.T, guestID int64) *httptest.ResponseRecorder {
	t.Helper()
	req := f.adminRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/reinvite", guestID), `{}`)
	req.SetPathValue("id", fmt.Sprint(guestID))
	rr := httptest.NewRecorder()
	f.handler.Reinvite(rr, req)
	return rr
}

func (f *guestInviteTracerFixture) queuedInvite(t *testing.T, email string) (string, string) {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM outbound_queue WHERE rcpt_addrs @> ARRAY[$1]::text[]`, email).Scan(&count); err != nil {
		t.Fatalf("count queued invite: %v", err)
	}
	if count < 1 {
		t.Fatalf("queued invite count for %s = %d, want at least 1", email, count)
	}
	var rawRef string
	if err := f.pool.QueryRow(f.ctx, `SELECT raw_ref FROM outbound_queue
		WHERE rcpt_addrs @> ARRAY[$1]::text[] ORDER BY id DESC LIMIT 1`, email).Scan(&rawRef); err != nil {
		t.Fatalf("read queued invite: %v", err)
	}
	raw := f.s3.get(t, rawRef)
	parts := bytes.SplitN(raw, []byte("\r\n\r\n"), 2)
	if len(parts) != 2 {
		t.Fatalf("stored MIME lacks header/body separator: %q", raw)
	}
	body, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(parts[1])))
	if err != nil {
		t.Fatalf("decode invite MIME: %v", err)
	}
	const marker = "?token="
	pos := strings.Index(string(body), marker)
	if pos < 0 {
		t.Fatalf("invite MIME lacks token link: %q", body)
	}
	token := strings.Fields(string(body)[pos+len(marker):])[0]
	return token, string(raw)
}

func setTracerTestToken(t *testing.T, pool *pgxpool.Pool, guestID int64, raw string) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin token rewrite: %v", err)
	}
	defer tracerRollback(t, tx)
	if _, err := tx.Exec(t.Context(), `SET LOCAL app.test_mode='true'`); err != nil {
		t.Fatalf("set test mode: %v", err)
	}
	var visible string
	if err := tx.QueryRow(t.Context(), `SELECT current_setting('app.test_mode',true)`).Scan(&visible); err != nil || visible != "true" {
		t.Fatalf("test mode visible=%q err=%v", visible, err)
	}
	var got string
	if err := tx.QueryRow(t.Context(), `SELECT guest_invite_accept_test_helper($1,$2)`, guestID, raw).Scan(&got); err != nil {
		t.Fatalf("guest_invite_accept_test_helper: %v", err)
	}
	if got != raw {
		t.Fatalf("test helper returned %q, want %q", got, raw)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit token rewrite: %v", err)
	}
}

func tracerRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	if err := tx.Rollback(context.Background()); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Errorf("rollback: %v", err)
	}
}

type tracerDisclosure struct {
	OrgName, InvitedEmail, Text, Version string
	ExpiresAt                            time.Time
}

type tracerInviteState struct {
	invite string
	guest  string
	user   string
}

func readTracerInviteState(t *testing.T, pool *pgxpool.Pool, guestID int64) tracerInviteState {
	t.Helper()
	var state tracerInviteState
	if err := pool.QueryRow(t.Context(), `SELECT to_jsonb(gi)::text,to_jsonb(ga)::text,to_jsonb(u)::text
		FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
		JOIN users u ON u.id=ga.user_id
		WHERE gi.guest_user_id=$1 AND gi.used_at IS NULL
		ORDER BY gi.id DESC LIMIT 1`, guestID).Scan(&state.invite, &state.guest, &state.user); err != nil {
		t.Fatalf("read full invite state: %v", err)
	}
	return state
}

// tracerDisclosureGet is the bounded mailserver-side DB equivalent authorized
// by the plan. The real authserver route remains covered in Task 4.
func tracerDisclosureGet(t *testing.T, pool *pgxpool.Pool, raw string) (tracerDisclosure, int) {
	t.Helper()
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin disclosure helper: %v", err)
	}
	defer tracerRollback(t, tx)
	sum := sha256.Sum256([]byte(raw))
	var d tracerDisclosure
	var inviteID int64
	var status string
	var usedAt *time.Time
	if err := tx.QueryRow(t.Context(), `SELECT gi.id,d.name,u.email,ga.status,gi.expires_at,gi.used_at
		FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
		JOIN users u ON u.id=gi.guest_user_id JOIN domains d ON d.id=gi.host_domain_id
		WHERE gi.token_hash=$1`, hex.EncodeToString(sum[:])).Scan(&inviteID, &d.OrgName,
		&d.InvitedEmail, &status, &d.ExpiresAt, &usedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return d, http.StatusUnauthorized
		}
		t.Fatalf("read disclosure: %v", err)
	}
	if usedAt != nil || status != "invited" || !d.ExpiresAt.After(time.Now()) {
		return d, http.StatusUnauthorized
	}
	tag, err := tx.Exec(t.Context(), `UPDATE guest_invites SET disclosure_version=COALESCE(disclosure_version,'v1')
		WHERE id=$1 AND used_at IS NULL AND expires_at>now()`, inviteID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("stamp disclosure: rows=%d err=%v", tag.RowsAffected(), err)
	}
	if err := tx.QueryRow(t.Context(), `SELECT disclosure_version FROM guest_invites WHERE id=$1`, inviteID).Scan(&d.Version); err != nil {
		t.Fatalf("read disclosure version: %v", err)
	}
	d.Text = fmt.Sprintf("You are being onboarded as an external guest user in %s. Your content is retained and may be reviewed by authorized administrators.", d.OrgName)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit disclosure helper: %v", err)
	}
	return d, http.StatusOK
}

func tracerAccept(t *testing.T, pool *pgxpool.Pool, raw, password string, accepted bool) int {
	t.Helper()
	if !accepted {
		return http.StatusBadRequest
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt password: %v", err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin accept: %v", err)
	}
	defer tracerRollback(t, tx)
	sum := sha256.Sum256([]byte(raw))
	var inviteID, guestID int64
	var status string
	var expiresAt time.Time
	var usedAt *time.Time
	err = tx.QueryRow(t.Context(), `SELECT gi.id,gi.guest_user_id,ga.status,gi.expires_at,gi.used_at
		FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
		JOIN users u ON u.id=gi.guest_user_id WHERE gi.token_hash=$1 FOR UPDATE OF gi,ga,u`,
		hex.EncodeToString(sum[:])).Scan(&inviteID, &guestID, &status, &expiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (usedAt != nil || status != "invited" || !expiresAt.After(time.Now()))) {
		return http.StatusUnauthorized
	}
	if err != nil {
		t.Fatalf("lock invite: %v", err)
	}
	for _, write := range []struct {
		label string
		stmt  string
		args  []any
	}{
		{"invite", `UPDATE guest_invites SET used_at=now(),disclosure_accepted_at=now(),
			disclosure_version=COALESCE(disclosure_version,'v1') WHERE id=$1 AND used_at IS NULL`, []any{inviteID}},
		{"guest", `UPDATE guest_accounts SET status='active',updated_at=now() WHERE user_id=$1 AND status='invited'`, []any{guestID}},
		{"user", `UPDATE users SET password_hash=$1,enabled=TRUE,updated_at=now() WHERE id=$2`, []any{hash, guestID}},
	} {
		tag, err := tx.Exec(t.Context(), write.stmt, write.args...)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatalf("accept %s write: rows=%d err=%v", write.label, tag.RowsAffected(), err)
		}
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit accept: %v", err)
	}
	return http.StatusOK
}

func (f *guestInviteTracerFixture) createChannel(t *testing.T, owner int64, name string) int64 {
	t.Helper()
	var id int64
	if err := f.pool.QueryRow(t.Context(), `SELECT chat_channel_create($1,$2,NULL,'private')`, owner, name).Scan(&id); err != nil {
		t.Fatalf("create channel %s: %v", name, err)
	}
	if id == 0 {
		t.Fatalf("create channel %s returned zero", name)
	}
	return id
}

func (f *guestInviteTracerFixture) addChannelMember(t *testing.T, owner, channel, user int64) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), `SELECT chat_member_add($1,$2,$3)`, owner, channel, user); err != nil {
		t.Fatalf("add channel member: %v", err)
	}
}

func (f *guestInviteTracerFixture) sendMessage(t *testing.T, sender, channel int64, body string, mentions []int64) int64 {
	t.Helper()
	var result []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT chat_message_send($1,$2,$3,NULL,$4::bigint[])`,
		sender, channel, body, mentions).Scan(&result); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}
	var decoded struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil || decoded.MessageID == 0 {
		t.Fatalf("decode chat_message_send: id=%d err=%v body=%s", decoded.MessageID, err, result)
	}
	return decoded.MessageID
}

type tracerDigestMail struct {
	to, subject, body string
}

func (f *guestInviteTracerFixture) drainGuestDigest(t *testing.T) (bool, []tracerDigestMail) {
	t.Helper()
	var captured []tracerDigestMail
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, to, subject, body string) error {
		captured = append(captured, tracerDigestMail{to: to, subject: subject, body: body})
		return nil
	})
	defer restore()
	w := pushjobs.NewWorker(pgxutil.WorkerPool{Pool: f.pool}, nil, slog.Default())
	w.SetGuestDigestConfig(pushjobs.GuestDigestConfig{
		MC: f.s3.mc, Bucket: f.s3.bucket, FromAddr: "digest@" + f.domain,
		FromName: "G1 Tracer Org", WebmailURL: "https://webmail." + f.domain,
	})
	drained, err := w.DrainGuestDigests(t.Context())
	if err != nil {
		t.Fatalf("DrainGuestDigests: %v", err)
	}
	return drained, captured
}

func (f *guestInviteTracerFixture) approvalHandler(flags map[string]bool) *approval.Handler {
	h := approval.NewHandler(f.pool, pgxutil.WorkerPool{Pool: f.pool},
		slog.New(slog.NewTextHandler(f.logBuf, nil)))
	h.SetFeatureFlags(toggle.NewTestFlags(flags))
	h.SetGuestInviteDelivery(f.s3.mc, f.s3.bucket)
	return h
}

func (f *guestInviteTracerFixture) submitGuestInvite(t *testing.T, h *approval.Handler, email string) (*httptest.ResponseRecorder, int64) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"invitedEmail": email, "message": "G1 tracer collaboration"})
	if err != nil {
		t.Fatalf("marshal guest submit: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/me/guest-invites", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: f.requester, Type: jwtutil.TypeAccess}))
	rr := httptest.NewRecorder()
	h.SubmitGuestInvite(rr, req)
	var result struct {
		RequestID int64 `json:"requestId"`
	}
	if rr.Code == http.StatusCreated {
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatalf("decode guest submit: %v", err)
		}
	}
	return rr, result.RequestID
}

func (f *guestInviteTracerFixture) decideGuestInvite(t *testing.T, h *approval.Handler, requestID int64, decision string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"decision": decision})
	if err != nil {
		t.Fatalf("marshal guest decision: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/me/approvals/%d/decide", requestID), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("id", fmt.Sprint(requestID))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: f.approver, Type: jwtutil.TypeAccess}))
	rr := httptest.NewRecorder()
	h.Decide(rr, req)
	return rr
}

func TestGuestInviteTracer(t *testing.T) {
	f := newGuestInviteTracerFixture(t)
	email := "alice@" + f.externalDomain
	var guestID, firstInviteID int64
	var firstToken, firstRealToken string

	t.Run("01_admin_direct_invite", func(t *testing.T) {
		rr := f.invite(t, email)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("invite status=%d body=%s", rr.Code, rr.Body.String())
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &keys); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if len(keys) != 3 || keys["guestUserId"] == nil || keys["invitedEmail"] == nil || keys["expiresAt"] == nil {
			t.Fatalf("non-canonical response keys: %v", keys)
		}
		var got struct {
			GuestUserID  int64     `json:"guestUserId"`
			InvitedEmail string    `json:"invitedEmail"`
			ExpiresAt    time.Time `json:"expiresAt"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
			t.Fatalf("decode canonical response: %v", err)
		}
		guestID = got.GuestUserID
		if guestID == 0 || got.InvitedEmail != email || got.ExpiresAt.IsZero() {
			t.Fatalf("bad response: %+v", got)
		}
		firstRealToken, _ = f.queuedInvite(t, email)
		var queued, rawRefLeaks int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM outbound_queue WHERE rcpt_addrs @> ARRAY[$1]::text[]`, email).Scan(&queued); err != nil {
			t.Fatalf("count leg 1 queue: %v", err)
		}
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM outbound_queue
			WHERE rcpt_addrs @> ARRAY[$1]::text[] AND (raw_ref=$2 OR strpos(raw_ref,$2)>0)`,
			email, firstRealToken).Scan(&rawRefLeaks); err != nil {
			t.Fatalf("check leg 1 queue token containment: %v", err)
		}
		if queued != 1 {
			t.Fatalf("leg 1 queued mail=%d, want 1", queued)
		}
		if rawRefLeaks != 0 {
			t.Fatalf("leg 1 raw token appeared in %d outbound_queue.raw_ref values", rawRefLeaks)
		}
		if len(firstRealToken) != 43 || strings.Contains(firstRealToken, "=") {
			t.Fatalf("raw token shape len=%d", len(firstRealToken))
		}
		var status, storedHash string
		var enabled bool
		var pending int
		if err := f.pool.QueryRow(f.ctx, `SELECT gi.id,ga.status,u.enabled,gi.token_hash,
			(SELECT count(*) FROM guest_invites x WHERE x.guest_user_id=ga.user_id AND x.used_at IS NULL)
			FROM guest_accounts ga JOIN users u ON u.id=ga.user_id JOIN guest_invites gi ON gi.guest_user_id=ga.user_id
			WHERE ga.user_id=$1 AND gi.used_at IS NULL`, guestID).Scan(&firstInviteID, &status, &enabled, &storedHash, &pending); err != nil {
			t.Fatalf("read invite state: %v", err)
		}
		want := sha256.Sum256([]byte(firstRealToken))
		if firstInviteID == 0 || status != "invited" || enabled || pending != 1 || storedHash != hex.EncodeToString(want[:]) || storedHash == firstRealToken {
			t.Fatalf("invite state status=%q enabled=%v pending=%d hash-only=%v", status, enabled, pending, storedHash == hex.EncodeToString(want[:]))
		}
		if strings.Contains(rr.Body.String(), firstRealToken) || strings.Contains(f.logBuf.String(), firstRealToken) {
			t.Fatal("raw invite token leaked to response/log")
		}
		setTracerTestToken(t, f.pool, guestID, "g1-known-token-first")
		firstToken = "g1-known-token-first"
	})

	t.Run("02_domain_allowlist_rejects_without_side_effects", func(t *testing.T) {
		blocked := "blocked@g1-unlisted.example"
		beforeObjects := f.s3.count()
		var beforeMail int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM outbound_queue WHERE rcpt_addrs @> ARRAY[$1]::text[]`, blocked).Scan(&beforeMail); err != nil {
			t.Fatalf("count preexisting blocked mail: %v", err)
		}
		rr := f.invite(t, blocked)
		if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "BZ218") {
			t.Fatalf("blocked invite=%d %s", rr.Code, rr.Body.String())
		}
		var users, invites, afterMail int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, blocked).Scan(&users); err != nil {
			t.Fatalf("count blocked users: %v", err)
		}
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM guest_invites gi JOIN users u ON u.id=gi.guest_user_id WHERE lower(u.email)=lower($1)`, blocked).Scan(&invites); err != nil {
			t.Fatalf("count blocked invites: %v", err)
		}
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM outbound_queue WHERE rcpt_addrs @> ARRAY[$1]::text[]`, blocked).Scan(&afterMail); err != nil {
			t.Fatalf("count blocked mail: %v", err)
		}
		if users != 0 || invites != 0 || afterMail != beforeMail || f.s3.count() != beforeObjects {
			t.Fatalf("blocked side effects users=%d invites=%d mail=%d→%d MIME=%d→%d",
				users, invites, beforeMail, afterMail, beforeObjects, f.s3.count())
		}
	})

	t.Run("03_disclosure_false_precedes_mutation", func(t *testing.T) {
		before := readTracerInviteState(t, f.pool, guestID)
		if status := tracerAccept(t, f.pool, firstToken, "ValidPw1!", false); status != http.StatusBadRequest {
			t.Fatalf("false disclosure status=%d", status)
		}
		after := readTracerInviteState(t, f.pool, guestID)
		if before != after {
			t.Fatalf("disclosure refusal mutated state invite=%v guest=%v user=%v",
				before.invite != after.invite, before.guest != after.guest, before.user != after.user)
		}
	})

	t.Run("04_bounded_accept_get_contract", func(t *testing.T) {
		d, status := tracerDisclosureGet(t, f.pool, firstToken)
		if status != http.StatusOK || d.OrgName == "" || d.InvitedEmail != email || d.Text == "" || d.Version != "v1" || d.ExpiresAt.IsZero() {
			t.Fatalf("bounded GET status=%d disclosure=%+v", status, d)
		}
		t.Log("authserver boundary: Task 9 proves DB disclosure contract; Task 4 proves the real GET route")
	})

	t.Run("05_accept_post_is_one_transaction", func(t *testing.T) {
		if status := tracerAccept(t, f.pool, firstToken, "ValidPw1!", true); status != http.StatusOK {
			t.Fatalf("accept status=%d", status)
		}
		var status string
		var enabled, used, accepted bool
		var version, password string
		var inviteXID, guestXID, userXID int64
		if err := f.pool.QueryRow(f.ctx, `SELECT ga.status,u.enabled,gi.used_at IS NOT NULL,
			gi.disclosure_accepted_at IS NOT NULL,gi.disclosure_version,u.password_hash,
			gi.xmin::text::bigint,ga.xmin::text::bigint,u.xmin::text::bigint
			FROM guest_accounts ga JOIN users u ON u.id=ga.user_id JOIN guest_invites gi ON gi.guest_user_id=ga.user_id
			WHERE ga.user_id=$1 ORDER BY gi.id DESC LIMIT 1`, guestID).Scan(&status, &enabled, &used,
			&accepted, &version, &password, &inviteXID, &guestXID, &userXID); err != nil {
			t.Fatalf("read accepted state: %v", err)
		}
		if status != "active" || !enabled || !used || !accepted || version != "v1" || password == "" || inviteXID != guestXID || guestXID != userXID {
			t.Fatalf("accepted state status=%q enabled=%v used=%v disclosure=%v version=%q xid=%d/%d/%d", status, enabled, used, accepted, version, inviteXID, guestXID, userXID)
		}
	})

	t.Run("06_password_verifies_and_identity_is_guest", func(t *testing.T) {
		var hash string
		var isGuest bool
		if err := f.pool.QueryRow(f.ctx, `SELECT password_hash,is_guest_account(id) FROM users WHERE id=$1`, guestID).Scan(&hash, &isGuest); err != nil {
			t.Fatalf("read credential: %v", err)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("ValidPw1!")); err != nil || !isGuest {
			t.Fatalf("credential verification err=%v isGuest=%v", err, isGuest)
		}
		t.Log("authserver boundary: bcrypt and satellite identity proven here; real login/JWT remains G0/authserver coverage")
	})

	t.Run("07_bounded_replay_is_non_mutating", func(t *testing.T) {
		var beforeHash, beforeStatus string
		var beforeUsed time.Time
		if err := f.pool.QueryRow(f.ctx, `SELECT u.password_hash,ga.status,gi.used_at FROM users u
			JOIN guest_accounts ga ON ga.user_id=u.id JOIN guest_invites gi ON gi.guest_user_id=u.id
			WHERE u.id=$1 ORDER BY gi.id DESC LIMIT 1`, guestID).Scan(&beforeHash, &beforeStatus, &beforeUsed); err != nil {
			t.Fatalf("read replay baseline: %v", err)
		}
		if status := tracerAccept(t, f.pool, firstToken, "ChangedPw2!", true); status != http.StatusUnauthorized {
			t.Fatalf("replay status=%d", status)
		}
		var afterHash, afterStatus string
		var afterUsed time.Time
		if err := f.pool.QueryRow(f.ctx, `SELECT u.password_hash,ga.status,gi.used_at FROM users u
			JOIN guest_accounts ga ON ga.user_id=u.id JOIN guest_invites gi ON gi.guest_user_id=u.id
			WHERE u.id=$1 ORDER BY gi.id DESC LIMIT 1`, guestID).Scan(&afterHash, &afterStatus, &afterUsed); err != nil {
			t.Fatalf("read replay result: %v", err)
		}
		if beforeHash != afterHash || beforeStatus != afterStatus || !beforeUsed.Equal(afterUsed) {
			t.Fatal("replay changed password/status/token state")
		}
		t.Log("authserver boundary: Task 9 proves bounded replay/no-mutation; Task 4 proves the real BZ217-uniform route and body")
	})

	t.Run("08_disable_reinvite_accept_rearms", func(t *testing.T) {
		if _, err := f.pool.Exec(f.ctx, `SELECT guest_set_status($1,$2,'disable')`, f.adminID, guestID); err != nil {
			t.Fatalf("disable guest: %v", err)
		}
		rr := f.reinvite(t, guestID)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("reinvite=%d %s", rr.Code, rr.Body.String())
		}
		secondRealToken, _ := f.queuedInvite(t, email)
		if len(secondRealToken) != 43 || strings.Contains(secondRealToken, "=") || secondRealToken == firstRealToken {
			t.Fatalf("re-invite real token shape/distinctness len=%d sameAsFirst=%v",
				len(secondRealToken), secondRealToken == firstRealToken)
		}
		var status, storedHash string
		var enabled bool
		var pending, oldTombstoned int
		if err := f.pool.QueryRow(f.ctx, `SELECT ga.status,u.enabled,
			(SELECT count(*) FROM guest_invites gi WHERE gi.guest_user_id=ga.user_id AND gi.used_at IS NULL),
			(SELECT count(*) FROM guest_invites gi WHERE gi.id=$2 AND gi.guest_user_id=ga.user_id AND gi.used_at IS NOT NULL),
			(SELECT token_hash FROM guest_invites gi WHERE gi.guest_user_id=ga.user_id AND gi.used_at IS NULL)
			FROM guest_accounts ga JOIN users u ON u.id=ga.user_id WHERE ga.user_id=$1`,
			guestID, firstInviteID).Scan(&status, &enabled, &pending, &oldTombstoned, &storedHash); err != nil {
			t.Fatalf("read rearm state: %v", err)
		}
		want := sha256.Sum256([]byte(secondRealToken))
		if status != "invited" || enabled || pending != 1 || oldTombstoned != 1 ||
			storedHash != hex.EncodeToString(want[:]) || storedHash == secondRealToken {
			t.Fatalf("rearm pending status=%q enabled=%v pending=%d oldTombstoned=%d hash-only=%v",
				status, enabled, pending, oldTombstoned, storedHash == hex.EncodeToString(want[:]))
		}
		setTracerTestToken(t, f.pool, guestID, "g1-known-token-second")
		secondToken := "g1-known-token-second"
		if got := tracerAccept(t, f.pool, firstToken, "OldTokenPw!", true); got != http.StatusUnauthorized {
			t.Fatalf("old token status=%d", got)
		}
		if got := tracerAccept(t, f.pool, secondToken, "ReArmedPw3!", true); got != http.StatusOK {
			t.Fatalf("second accept status=%d", got)
		}
		if err := f.pool.QueryRow(f.ctx, `SELECT ga.status,u.enabled FROM guest_accounts ga JOIN users u ON u.id=ga.user_id WHERE ga.user_id=$1`, guestID).Scan(&status, &enabled); err != nil {
			t.Fatalf("read rearmed state: %v", err)
		}
		if status != "active" || !enabled {
			t.Fatalf("rearmed status=%q enabled=%v", status, enabled)
		}
	})

	var digestChannel, dmChannel int64
	t.Run("09_mention_digest_real_reference", func(t *testing.T) {
		if _, err := f.pool.Exec(t.Context(), `DELETE FROM sessions WHERE user_id=$1`, guestID); err != nil {
			t.Fatalf("clear guest sessions: %v", err)
		}
		digestChannel = f.createChannel(t, f.requester, "G1 tracer authorized")
		f.addChannelMember(t, f.requester, digestChannel, guestID)
		const visible = "G1-AUTHORIZED-MENTION"
		messageID := f.sendMessage(t, f.requester, digestChannel, visible, []int64{guestID})
		ref := fmt.Sprintf("%d:%d", digestChannel, messageID)
		var mentionRows, pending int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM chat_mentions WHERE message_id=$1 AND mentioned_user_id=$2`, messageID, guestID).Scan(&mentionRows); err != nil {
			t.Fatalf("count real mention: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND kind='mention' AND ref=$2 AND sent_at IS NULL`, guestID, ref).Scan(&pending); err != nil {
			t.Fatalf("count mention intent: %v", err)
		}
		if mentionRows != 1 || pending != 1 {
			t.Fatalf("mention fixture rows=%d pending=%d", mentionRows, pending)
		}

		foreignChannel := f.createChannel(t, f.requester, "G1 tracer foreign")
		const secret = "G1-FOREIGN-SECRET"
		foreignMessage := f.sendMessage(t, f.requester, foreignChannel, secret, nil)
		foreignRef := fmt.Sprintf("%d:%d", foreignChannel, foreignMessage)
		if _, err := f.pool.Exec(t.Context(), `SELECT guest_notification_intent_enqueue($1,'mention',$2)`, guestID, foreignRef); err != nil {
			t.Fatalf("enqueue foreign anti-leak fixture: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND ref=$2 AND sent_at IS NULL`, guestID, foreignRef).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("foreign anti-leak intent pending=%d err=%v", pending, err)
		}

		drained, mail := f.drainGuestDigest(t)
		if !drained || len(mail) != 1 || mail[0].to != email ||
			mail[0].subject != "New activity in G1 Tracer Org" ||
			!strings.Contains(mail[0].body, visible) || strings.Contains(mail[0].body, secret) {
			t.Fatalf("mention drain=%v mail=%+v", drained, mail)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND ref IN ($2,$3) AND sent_at IS NOT NULL`, guestID, ref, foreignRef).Scan(&pending); err != nil || pending != 2 {
			t.Fatalf("mention stamps=%d err=%v", pending, err)
		}
		if _, err := f.pool.Exec(t.Context(), `UPDATE guest_notification_intents SET sent_at=now()-interval '2 minutes'
			WHERE user_id=$1 AND sent_at IS NOT NULL`, guestID); err != nil {
			t.Fatalf("age mention digest: %v", err)
		}
	})

	t.Run("10_dm_digest_real_reference", func(t *testing.T) {
		if err := f.pool.QueryRow(t.Context(), `SELECT chat_dm_open($1,ARRAY[$2]::bigint[])`, f.requester, guestID).Scan(&dmChannel); err != nil {
			t.Fatalf("chat_dm_open: %v", err)
		}
		if dmChannel == 0 {
			t.Fatal("chat_dm_open returned zero")
		}
		const visible = "G1-AUTHORIZED-DM"
		messageID := f.sendMessage(t, f.requester, dmChannel, visible, nil)
		ref := fmt.Sprintf("%d:%d", dmChannel, messageID)
		var pending int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND kind='dm' AND ref=$2 AND sent_at IS NULL`, guestID, ref).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("DM intent pending=%d err=%v", pending, err)
		}
		drained, mail := f.drainGuestDigest(t)
		if !drained || len(mail) != 1 || mail[0].to != email || !strings.Contains(mail[0].body, visible) {
			t.Fatalf("DM drain=%v mail=%+v", drained, mail)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND ref=$2 AND sent_at IS NOT NULL`, guestID, ref).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("DM stamp=%d err=%v", pending, err)
		}
		if _, err := f.pool.Exec(t.Context(), `UPDATE guest_notification_intents SET sent_at=now()-interval '2 minutes'
			WHERE user_id=$1 AND sent_at IS NOT NULL`, guestID); err != nil {
			t.Fatalf("age DM digest: %v", err)
		}
	})

	t.Run("11_meeting_digest_real_reference", func(t *testing.T) {
		const title = "G1-AUTHORIZED-MEETING"
		var result []byte
		if err := f.pool.QueryRow(t.Context(), `SELECT meeting_create($1,$2,now()+interval '1 day',
			now()+interval '2 days',$3,NULL,FALSE)`, f.requester, title, digestChannel).Scan(&result); err != nil {
			t.Fatalf("meeting_create: %v", err)
		}
		var meeting struct {
			MeetingID int64 `json:"meetingId"`
		}
		if err := json.Unmarshal(result, &meeting); err != nil || meeting.MeetingID == 0 {
			t.Fatalf("decode meeting: id=%d err=%v body=%s", meeting.MeetingID, err, result)
		}
		var readable, pending int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM meetings m JOIN chat_channel_members cm
			ON cm.channel_id=m.chat_channel_id AND cm.user_id=$2 WHERE m.id=$1`, meeting.MeetingID, guestID).Scan(&readable); err != nil {
			t.Fatalf("read meeting fixture: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND kind='meeting_invite' AND ref=$2 AND sent_at IS NULL`, guestID,
			fmt.Sprint(meeting.MeetingID)).Scan(&pending); err != nil || pending != 1 || readable != 1 {
			t.Fatalf("meeting readable=%d pending=%d err=%v", readable, pending, err)
		}
		drained, mail := f.drainGuestDigest(t)
		if !drained || len(mail) != 1 || mail[0].to != email || !strings.Contains(mail[0].body, title) {
			t.Fatalf("meeting drain=%v mail=%+v", drained, mail)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND kind='meeting_invite' AND ref=$2 AND sent_at IS NOT NULL`, guestID,
			fmt.Sprint(meeting.MeetingID)).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("meeting stamp=%d err=%v", pending, err)
		}
		if _, err := f.pool.Exec(t.Context(), `UPDATE guest_notification_intents SET sent_at=now()-interval '2 minutes'
			WHERE user_id=$1 AND sent_at IS NOT NULL`, guestID); err != nil {
			t.Fatalf("age meeting digest: %v", err)
		}
	})

	t.Run("12_active_session_skips_and_keeps_pending", func(t *testing.T) {
		const visible = "G1-ACTIVE-SKIP-DM"
		messageID := f.sendMessage(t, f.requester, dmChannel, visible, nil)
		ref := fmt.Sprintf("%d:%d", dmChannel, messageID)
		sessionID := fmt.Sprintf("g1-tracer-session-%d", guestID)
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO sessions(id,user_id,token_hash,expires_at,last_seen_at)
			VALUES($1,$2,$3,now()+interval '1 hour',now())`, sessionID, guestID, []byte("g1-session-hash")); err != nil {
			t.Fatalf("insert active session: %v", err)
		}
		var sessions, pending int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM sessions WHERE id=$1 AND user_id=$2
			AND expires_at>now() AND last_seen_at>now()-interval '1 minute'`, sessionID, guestID).Scan(&sessions); err != nil {
			t.Fatalf("verify session fixture: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND kind='dm' AND ref=$2 AND sent_at IS NULL`, guestID, ref).Scan(&pending); err != nil {
			t.Fatalf("verify active-skip intent: %v", err)
		}
		if sessions != 1 || pending != 1 {
			t.Fatalf("active fixture sessions=%d pending=%d", sessions, pending)
		}
		drained, mail := f.drainGuestDigest(t)
		if drained || len(mail) != 0 {
			t.Fatalf("active drain=%v mail=%+v", drained, mail)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_notification_intents
			WHERE user_id=$1 AND ref=$2 AND sent_at IS NULL`, guestID, ref).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("active intent pending=%d err=%v", pending, err)
		}
	})

	if _, err := f.pool.Exec(t.Context(), `UPDATE feature_toggles SET enabled=TRUE
		WHERE key IN ('feature.guest_accounts','approval.guest_invite')`); err != nil {
		t.Fatalf("enable approval tracer toggles: %v", err)
	}
	var policyID int64
	var priority int
	if err := f.pool.QueryRow(t.Context(), `SELECT coalesce(max(priority),0)+1 FROM approval_policies
		WHERE consumer_type='guest.invite'`).Scan(&priority); err != nil {
		t.Fatalf("allocate policy priority: %v", err)
	}
	if err := f.pool.QueryRow(t.Context(), `INSERT INTO approval_policies
		(consumer_type,name,priority,conditions,approver_spec)
		VALUES('guest.invite',$1,$2,jsonb_build_object('host_domain_id',$3::bigint),
		jsonb_build_object('kind','named','user_id',$4::bigint)) RETURNING id`,
		"G1 tracer approval", priority, f.domainID, f.approver).Scan(&policyID); err != nil {
		t.Fatalf("insert guest approval policy: %v", err)
	}
	if policyID == 0 {
		t.Fatal("guest approval policy returned zero id")
	}
	approvalOn := f.approvalHandler(map[string]bool{
		toggle.FeatureGuestAccounts: true,
		"approval.guest_invite":     true,
	})

	t.Run("13_member_request_approve_real_handlers", func(t *testing.T) {
		approvedEmail := "carol@" + f.externalDomain
		rr, requestID := f.submitGuestInvite(t, approvalOn, approvedEmail)
		if rr.Code != http.StatusCreated || requestID == 0 {
			t.Fatalf("submit approve setup=%d id=%d body=%s", rr.Code, requestID, rr.Body.String())
		}
		var requestStatus, invitedEvidence, messageEvidence string
		var requestPolicyID, requesterID, approverID int64
		if err := f.pool.QueryRow(t.Context(), `SELECT status,policy_id,requester_user_id,approver_ref,
			payload->>'invited_email',payload->>'message' FROM approval_requests WHERE id=$1`, requestID).
			Scan(&requestStatus, &requestPolicyID, &requesterID, &approverID, &invitedEvidence, &messageEvidence); err != nil {
			t.Fatalf("read submitted approval: %v", err)
		}
		if requestStatus != "pending" || requestPolicyID != policyID || requesterID != f.requester || approverID != f.approver ||
			invitedEvidence != approvedEmail || messageEvidence == "" {
			t.Fatalf("approval evidence status=%q policy=%d requester=%d approver=%d email=%q message=%q",
				requestStatus, requestPolicyID, requesterID, approverID, invitedEvidence, messageEvidence)
		}
		beforeObjects := f.s3.count()
		decide := f.decideGuestInvite(t, approvalOn, requestID, "approve")
		if decide.Code != http.StatusOK || !strings.Contains(decide.Body.String(), `"status":"applied"`) {
			t.Fatalf("approve decision=%d %s", decide.Code, decide.Body.String())
		}
		rawToken, _ := f.queuedInvite(t, approvedEmail)
		if f.s3.count() != beforeObjects+1 {
			t.Fatalf("approve MIME objects=%d→%d, want +1", beforeObjects, f.s3.count())
		}
		var rawRefLeaks int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbound_queue
			WHERE rcpt_addrs @> ARRAY[$1]::text[] AND (raw_ref=$2 OR strpos(raw_ref,$2)>0)`,
			approvedEmail, rawToken).Scan(&rawRefLeaks); err != nil {
			t.Fatalf("check approved queue token containment: %v", err)
		}
		if rawRefLeaks != 0 {
			t.Fatalf("approved raw token appeared in %d outbound_queue.raw_ref values", rawRefLeaks)
		}
		var approvedGuest, invitedBy, createdBy int64
		var finalStatus, guestStatus, storedHash string
		var enabled bool
		if err := f.pool.QueryRow(t.Context(), `SELECT ar.status,u.id,ga.status,u.enabled,ga.invited_by,
			gi.created_by,gi.token_hash FROM approval_requests ar
			JOIN users u ON lower(u.email)=lower(ar.payload->>'invited_email')
			JOIN guest_accounts ga ON ga.user_id=u.id JOIN guest_invites gi ON gi.guest_user_id=u.id AND gi.used_at IS NULL
			WHERE ar.id=$1`, requestID).Scan(&finalStatus, &approvedGuest, &guestStatus, &enabled,
			&invitedBy, &createdBy, &storedHash); err != nil {
			t.Fatalf("read approved guest: %v", err)
		}
		want := sha256.Sum256([]byte(rawToken))
		if finalStatus != "applied" || approvedGuest == 0 || guestStatus != "invited" || enabled ||
			invitedBy != f.requester || createdBy != f.requester || storedHash != hex.EncodeToString(want[:]) || storedHash == rawToken {
			t.Fatalf("approved state request=%q guest=%d status=%q enabled=%v attribution=%d/%d hash-only=%v",
				finalStatus, approvedGuest, guestStatus, enabled, invitedBy, createdBy, storedHash == hex.EncodeToString(want[:]))
		}
		if strings.Contains(decide.Body.String(), rawToken) || strings.Contains(f.logBuf.String(), rawToken) {
			t.Fatal("approved raw token leaked to response/log")
		}
	})

	t.Run("14_member_request_deny_has_no_provision_or_mail", func(t *testing.T) {
		deniedEmail := "diana@" + f.externalDomain
		rr, requestID := f.submitGuestInvite(t, approvalOn, deniedEmail)
		if rr.Code != http.StatusCreated || requestID == 0 {
			t.Fatalf("submit deny setup=%d id=%d body=%s", rr.Code, requestID, rr.Body.String())
		}
		beforeObjects := f.s3.count()
		decide := f.decideGuestInvite(t, approvalOn, requestID, "deny")
		if decide.Code != http.StatusOK || !strings.Contains(decide.Body.String(), `"status":"denied"`) {
			t.Fatalf("deny decision=%d %s", decide.Code, decide.Body.String())
		}
		var status string
		var users, invites, queued int
		if err := f.pool.QueryRow(t.Context(), `SELECT status FROM approval_requests WHERE id=$1`, requestID).Scan(&status); err != nil {
			t.Fatalf("read denied request: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, deniedEmail).Scan(&users); err != nil {
			t.Fatalf("count denied users: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM guest_invites gi JOIN users u
			ON u.id=gi.guest_user_id WHERE lower(u.email)=lower($1)`, deniedEmail).Scan(&invites); err != nil {
			t.Fatalf("count denied invites: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbound_queue
			WHERE rcpt_addrs @> ARRAY[$1]::text[]`, deniedEmail).Scan(&queued); err != nil {
			t.Fatalf("count denied queue: %v", err)
		}
		if status != "denied" || users != 0 || invites != 0 || queued != 0 || f.s3.count() != beforeObjects {
			t.Fatalf("deny status=%q users=%d invites=%d queue=%d MIME=%d→%d",
				status, users, invites, queued, beforeObjects, f.s3.count())
		}
	})

	t.Run("15_approval_toggle_off_is_opaque_404", func(t *testing.T) {
		if _, err := f.pool.Exec(t.Context(), `UPDATE feature_toggles SET enabled=FALSE WHERE key='approval.guest_invite'`); err != nil {
			t.Fatalf("disable approval toggle: %v", err)
		}
		off := f.approvalHandler(map[string]bool{
			toggle.FeatureGuestAccounts: true,
			"approval.guest_invite":     false,
		})
		offEmail := "eve@" + f.externalDomain
		beforeObjects := f.s3.count()
		rr, requestID := f.submitGuestInvite(t, off, offEmail)
		if rr.Code != http.StatusNotFound || requestID != 0 {
			t.Fatalf("toggle-off submit=%d id=%d body=%s", rr.Code, requestID, rr.Body.String())
		}
		var requests, users, queued int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM approval_requests
			WHERE payload->>'invited_email'=$1`, offEmail).Scan(&requests); err != nil {
			t.Fatalf("count toggle-off requests: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, offEmail).Scan(&users); err != nil {
			t.Fatalf("count toggle-off users: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM outbound_queue
			WHERE rcpt_addrs @> ARRAY[$1]::text[]`, offEmail).Scan(&queued); err != nil {
			t.Fatalf("count toggle-off queue: %v", err)
		}
		if requests != 0 || users != 0 || queued != 0 || f.s3.count() != beforeObjects {
			t.Fatalf("toggle-off side effects requests=%d users=%d queue=%d MIME=%d→%d",
				requests, users, queued, beforeObjects, f.s3.count())
		}
	})

	t.Run("16_admin_revoke_real_route", func(t *testing.T) {
		daveEmail := "dave@" + f.externalDomain
		rr := f.invite(t, daveEmail)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("revoke setup invite=%d %s", rr.Code, rr.Body.String())
		}
		var response struct {
			GuestUserID int64 `json:"guestUserId"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil || response.GuestUserID == 0 {
			t.Fatalf("decode revoke setup: id=%d err=%v", response.GuestUserID, err)
		}
		f.queuedInvite(t, daveEmail)
		revoke := f.adminRequest(http.MethodDelete, fmt.Sprintf("/admin/guests/%d/invite", response.GuestUserID), "")
		revoke.SetPathValue("userId", fmt.Sprint(response.GuestUserID))
		revokeRR := httptest.NewRecorder()
		f.handler.DeleteInvite(revokeRR, revoke)
		if revokeRR.Code != http.StatusOK {
			t.Fatalf("first revoke=%d %s", revokeRR.Code, revokeRR.Body.String())
		}
		var used bool
		var status string
		var password *string
		if err := f.pool.QueryRow(t.Context(), `SELECT gi.used_at IS NOT NULL,ga.status,u.password_hash
			FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
			JOIN users u ON u.id=ga.user_id WHERE gi.guest_user_id=$1 ORDER BY gi.id DESC LIMIT 1`,
			response.GuestUserID).Scan(&used, &status, &password); err != nil {
			t.Fatalf("read revoked invite: %v", err)
		}
		if !used || status != "invited" || password != nil {
			t.Fatalf("revoked state used=%v status=%q passwordSet=%v", used, status, password != nil)
		}
		revoke2 := f.adminRequest(http.MethodDelete, fmt.Sprintf("/admin/guests/%d/invite", response.GuestUserID), "")
		revoke2.SetPathValue("userId", fmt.Sprint(response.GuestUserID))
		revokeRR2 := httptest.NewRecorder()
		f.handler.DeleteInvite(revokeRR2, revoke2)
		if revokeRR2.Code != http.StatusNotFound {
			t.Fatalf("second revoke=%d %s", revokeRR2.Code, revokeRR2.Body.String())
		}
	})
}
