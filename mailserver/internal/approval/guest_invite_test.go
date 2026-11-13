package approval

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func guestInviteRequest(t *testing.T, body string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/me/guest-invites", bytes.NewBufferString(body))
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: testRequesterID, Type: jwtutil.TypeAccess}))
	return r, httptest.NewRecorder()
}

type guestApprovalFixture struct {
	pool                        *pgxpool.Pool
	h                           *Handler
	requester, approver, domain int64
	logs                        *bytes.Buffer
}

func newGuestApprovalFixture(t *testing.T) *guestApprovalFixture {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	var domain, requester, approver int64
	if err := pool.QueryRow(ctx, `INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id`, "guest-approval-"+suffix+".test").Scan(&domain); err != nil {
		t.Fatal(err)
	}
	for _, u := range []struct {
		name, email, display string
		id                   *int64
	}{
		{"greq" + suffix, "requester@guest-approval-" + suffix + ".test", "Request Owner", &requester},
		{"gapr" + suffix, "approver@guest-approval-" + suffix + ".test", "Invite Approver", &approver},
	} {
		if err := pool.QueryRow(ctx, `INSERT INTO users(username,domain_id,email,display_name,enabled) VALUES($1,$2,$3,$4,TRUE) RETURNING id`, u.name, domain, u.email, u.display).Scan(u.id); err != nil {
			t.Fatal(err)
		}
	}
	type saved struct {
		value  string
		exists bool
	}
	prior := map[string]saved{}
	for _, key := range []string{"authserver.public_url", "mail.default_sender"} {
		var value string
		err := pool.QueryRow(ctx, `SELECT value::text FROM system_config WHERE key=$1`, key).Scan(&value)
		prior[key] = saved{value: value, exists: err == nil}
	}
	for key, value := range map[string]string{"authserver.public_url": "https://auth.guest-approval.test", "mail.default_sender": "invite@guest-approval-" + suffix + ".test"} {
		if _, err := pool.Exec(ctx, `INSERT INTO system_config(key,value) VALUES($1,to_jsonb($2::text)) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value`, key, value); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, slog.New(slog.NewTextHandler(&logs, nil)))
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"feature.guest_accounts": true, "approval.guest_invite": true}))
	var oldGuestAccounts, oldApproval bool
	_ = pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key='feature.guest_accounts'`).Scan(&oldGuestAccounts)
	_ = pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key='approval.guest_invite'`).Scan(&oldApproval)
	_, _ = pool.Exec(ctx, `UPDATE feature_toggles SET enabled=TRUE WHERE key IN ('feature.guest_accounts','approval.guest_invite')`)
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM guest_invites WHERE host_domain_id=$1`, domain)                                                                                  //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN (SELECT user_id FROM guest_accounts WHERE host_domain_id=$1)`, domain)                                         //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_requests WHERE domain_id=$1`, domain)                                                                                   //nolint:errcheck
		pool.Exec(c, `DELETE FROM approval_policies WHERE consumer_type='guest.invite' AND conditions @> jsonb_build_object('host_domain_id',$1::bigint)`, domain) //nolint:errcheck
		pool.Exec(c, `DELETE FROM users WHERE id IN ($1,$2)`, requester, approver)                                                                                 //nolint:errcheck
		pool.Exec(c, `DELETE FROM domains WHERE id=$1`, domain)                                                                                                    //nolint:errcheck
		pool.Exec(c, `UPDATE feature_toggles SET enabled=$1 WHERE key='feature.guest_accounts'`, oldGuestAccounts)                                                 //nolint:errcheck
		pool.Exec(c, `UPDATE feature_toggles SET enabled=$1 WHERE key='approval.guest_invite'`, oldApproval)                                                       //nolint:errcheck
		for key, s := range prior {
			if s.exists {
				pool.Exec(c, `UPDATE system_config SET value=$2::jsonb WHERE key=$1`, key, s.value)
			} else {
				pool.Exec(c, `DELETE FROM system_config WHERE key=$1`, key)
			}
		} //nolint:errcheck
	})
	return &guestApprovalFixture{pool: pool, h: h, requester: requester, approver: approver, domain: domain, logs: &logs}
}

func (f *guestApprovalFixture) submit(t *testing.T, email string) (*httptest.ResponseRecorder, int64) {
	t.Helper()
	r, w := guestInviteRequest(t, fmt.Sprintf(`{"invitedEmail":%q,"message":"Project access"}`, email))
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: f.requester, Type: jwtutil.TypeAccess}))
	f.h.SubmitGuestInvite(w, r)
	var response struct {
		RequestID int64 `json:"requestId"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &response)
	return w, response.RequestID
}

func (f *guestApprovalFixture) addPolicy(t *testing.T) {
	t.Helper()
	var priority int
	if err := f.pool.QueryRow(context.Background(), `SELECT coalesce(max(priority),0)+1 FROM approval_policies WHERE consumer_type='guest.invite'`).Scan(&priority); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO approval_policies(consumer_type,name,priority,conditions,approver_spec) VALUES('guest.invite',$1,$2,jsonb_build_object('host_domain_id',$3::bigint),jsonb_build_object('kind','named','user_id',$4::bigint))`, fmt.Sprint("guest approval ", f.domain), priority, f.domain, f.approver); err != nil {
		t.Fatal(err)
	}
}

func TestGuestInviteApprovalLifecycleAndTokenContainment(t *testing.T) {
	f := newGuestApprovalFixture(t)
	noPolicy, _ := f.submit(t, "no-policy@example.net")
	if noPolicy.Code != http.StatusUnprocessableEntity {
		t.Fatalf("no policy: want 422, got %d: %s", noPolicy.Code, noPolicy.Body.String())
	}
	f.addPolicy(t)

	denied, denyID := f.submit(t, "denied@example.net")
	if denied.Code != http.StatusCreated {
		t.Fatalf("submit deny setup: %d %s", denied.Code, denied.Body.String())
	}
	req, w := decideReq(t, f.approver, denyID, "deny")
	f.h.Decide(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"denied"`) {
		t.Fatalf("deny: %d %s", w.Code, w.Body.String())
	}
	var deniedGuests int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM users WHERE email='denied@example.net'`).Scan(&deniedGuests)
	if deniedGuests != 0 {
		t.Fatal("deny provisioned a guest")
	}

	var mailBody string
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client, _, _, _, _, _, _, body string) error {
		mailBody = body
		return nil
	})
	t.Cleanup(restore)
	approved, approveID := f.submit(t, "approved@example.net")
	if approved.Code != http.StatusCreated {
		restore()
		t.Fatalf("submit approve setup: %d %s", approved.Code, approved.Body.String())
	}
	req, w = decideReq(t, f.approver, approveID, "approve")
	f.h.Decide(w, req)
	restore()
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"applied"`) {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}
	pos := strings.Index(mailBody, "token=")
	if pos < 0 {
		t.Fatalf("invite mail has no token: %q", mailBody)
	}
	rawToken := strings.Fields(mailBody[pos+len("token="):])[0]
	if len(rawToken) != 43 || strings.Contains(rawToken, "=") {
		t.Fatalf("token is not 32-byte RawURL: %q", rawToken)
	}
	if strings.Contains(w.Body.String(), rawToken) || strings.Contains(f.logs.String(), rawToken) {
		t.Fatal("raw token leaked to response/log")
	}
	var storedHash string
	var invitedBy, createdBy int64
	if err := f.pool.QueryRow(context.Background(), `SELECT gi.token_hash,ga.invited_by,gi.created_by FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id JOIN users u ON u.id=gi.guest_user_id WHERE u.email='approved@example.net' AND gi.used_at IS NULL`).Scan(&storedHash, &invitedBy, &createdBy); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256([]byte(rawToken))
	if storedHash != hex.EncodeToString(want[:]) || storedHash == rawToken {
		t.Fatal("database did not store only SHA-256")
	}
	if invitedBy != f.requester || createdBy != f.requester {
		t.Fatalf("creator attribution invited_by=%d created_by=%d want requester=%d", invitedBy, createdBy, f.requester)
	}

	restore = notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client, _, _, _, _, _, _, body string) error {
		return errors.New("transport echoed " + body)
	})
	t.Cleanup(restore)
	failed, failedID := f.submit(t, "mail-failed@example.net")
	if failed.Code != http.StatusCreated {
		restore()
		t.Fatalf("submit mail-fail setup: %d %s", failed.Code, failed.Body.String())
	}
	req, w = decideReq(t, f.approver, failedID, "approve")
	f.h.Decide(w, req)
	restore()
	if w.Code != http.StatusOK {
		t.Fatalf("mail failure changed committed decision: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(f.logs.String(), "transport echoed") || strings.Contains(f.logs.String(), "token=") {
		t.Fatal("mail transport error/token leaked to logs")
	}
	var pending int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM guest_invites gi JOIN users u ON u.id=gi.guest_user_id WHERE u.email='mail-failed@example.net' AND gi.used_at IS NULL`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("mail failure pending invite count=%d err=%v", pending, err)
	}
}

func TestSubmitGuestInviteFailsClosedOnEitherToggle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	for _, flags := range []map[string]bool{
		{"feature.guest_accounts": true, "approval.guest_invite": false},
		{"feature.guest_accounts": false, "approval.guest_invite": true},
	} {
		h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
		h.SetFeatureFlags(toggle.NewTestFlags(flags))
		r, w := guestInviteRequest(t, `{"invitedEmail":"person@example.net"}`)
		h.SubmitGuestInvite(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("flags %v: want 404, got %d: %s", flags, w.Code, w.Body.String())
		}
	}
}

func TestSubmitGuestInviteStrictJSON(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewHandler(pool, pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())
	h.SetFeatureFlags(toggle.NewTestFlags(map[string]bool{"feature.guest_accounts": true, "approval.guest_invite": true}))
	for _, body := range []string{`{"invitedEmail":"person@example.net","unknown":true}`, `{"invitedEmail":"a@example.net"}{"invitedEmail":"b@example.net"}`, `{"email":"legacy@example.net"}`} {
		r, w := guestInviteRequest(t, body)
		h.SubmitGuestInvite(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %q: want 400, got %d", body, w.Code)
		}
	}
}
