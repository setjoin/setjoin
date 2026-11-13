package admin

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
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/notify"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func guestsOnFlags() *toggle.FeatureFlags {
	return toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: true})
}

func guestManageClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, IsAdmin: true, Permissions: []string{permissions.PermGuestsManage}}
}

func guestAdminRequest(method, target, body string, claims *auth.Claims) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(auth.ContextWithUser(req.Context(), claims))
}

func waitForBackendBlock(t *testing.T, pool *pgxpool.Pool, pid uint32, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("backend %d completed before the expected lock wait: %v", pid, err)
		default:
		}
		var blocked bool
		if err := pool.QueryRow(context.Background(),
			`SELECT cardinality(pg_blocking_pids($1)) > 0`, pid).Scan(&blocked); err != nil {
			t.Fatalf("inspect backend %d blockers: %v", pid, err)
		}
		if blocked {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("backend %d never entered the expected lock wait", pid)
}

func TestGuestsHandler_GatesAndValidation(t *testing.T) {
	for name, h := range map[string]*GuestsHandler{
		"nil toggles": NewGuestsHandler(nil, nil, nil, "", nil),
		"seeded OFF": NewGuestsHandler(nil,
			toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: false}), nil, "", nil),
	} {
		req := guestAdminRequest(http.MethodPost, "/admin/guests", `{}`, guestManageClaims(1))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s: want 404 with toggle off, got %d", name, rr.Code)
		}
	}

	h := NewGuestsHandler(nil, guestsOnFlags(), nil, "", nil)
	t.Run("permission", func(t *testing.T) {
		req := guestAdminRequest(http.MethodPost, "/admin/guests", `{}`,
			&auth.Claims{UserID: 1, Permissions: []string{permissions.PermDriveView}})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 without guests.manage, got %d", rr.Code)
		}
	})
	t.Run("invalid JSON", func(t *testing.T) {
		req := guestAdminRequest(http.MethodPost, "/admin/guests", `{`, guestManageClaims(1))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for invalid JSON, got %d", rr.Code)
		}
	})
	t.Run("invalid email", func(t *testing.T) {
		req := guestAdminRequest(http.MethodPost, "/admin/guests", `{"email":"not-an-email"}`, guestManageClaims(1))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for invalid email, got %d", rr.Code)
		}
	})
	t.Run("oversized body", func(t *testing.T) {
		body := `{"email":"guest@example.test","displayName":"` + strings.Repeat("x", (1<<20)+1) + `"}`
		req := guestAdminRequest(http.MethodPost, "/admin/guests", body, guestManageClaims(1))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for oversized body, got %d", rr.Code)
		}
	})
	t.Run("delete invalid id", func(t *testing.T) {
		req := guestAdminRequest(http.MethodDelete, "/admin/guests/nope/invite", "", guestManageClaims(1))
		req.SetPathValue("userId", "nope")
		rr := httptest.NewRecorder()
		h.DeleteInvite(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for invalid userId, got %d", rr.Code)
		}
	})
	t.Run("domain required", func(t *testing.T) {
		req := guestAdminRequest(http.MethodPost, "/admin/guest-invite-domains", `{}`, guestManageClaims(1))
		rr := httptest.NewRecorder()
		h.AddInviteDomain(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for missing domain, got %d", rr.Code)
		}
	})
	t.Run("transfer sponsor required", func(t *testing.T) {
		req := guestAdminRequest(http.MethodPost, "/admin/guests/1/transfer", `{}`, guestManageClaims(1))
		req.SetPathValue("id", "1")
		rr := httptest.NewRecorder()
		h.Transfer(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for missing sponsorUserId, got %d", rr.Code)
		}
	})
	t.Run("sponsor search bounded", func(t *testing.T) {
		req := guestAdminRequest(http.MethodGet,
			"/admin/guests/1/sponsor-options?q="+strings.Repeat("x", 201), "", guestManageClaims(1))
		req.SetPathValue("id", "1")
		rr := httptest.NewRecorder()
		h.SponsorOptions(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for oversized sponsor search, got %d", rr.Code)
		}
	})
}

type guestDrainRecorder struct {
	mu      sync.Mutex
	userIDs []int64
	err     error
}

func (d *guestDrainRecorder) DrainUser(_ context.Context, userID int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.userIDs = append(d.userIDs, userID)
	return d.err
}

type capturedGuestMail struct {
	to, subject, body string
}

type guestInviteFixture struct {
	pool         *pgxpool.Pool
	handler      *GuestsHandler
	actorID      int64
	roleID       int64
	hostDomainID int64
	domain       string
	logBuf       *bytes.Buffer
}

func newGuestInviteFixture(t *testing.T) *guestInviteFixture {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := rolesTestRandomSuffix(t)
	domain := "guest-invite-" + suffix + ".example"
	hostDomainID := ensureScopeTestDomain(t, pool, domain)

	var actorID int64
	actorEmail := "admin@" + domain
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, enabled)
		 VALUES ($1,$2,$3,'Guest Invite Admin',TRUE) RETURNING id`,
		"guest-invite-admin-"+suffix, hostDomainID, actorEmail).Scan(&actorID); err != nil {
		t.Fatalf("insert invite admin: %v", err)
	}
	var roleID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO admin_role_groups (name, permissions)
		 VALUES ($1, ARRAY['guests.manage','guests.view']) RETURNING id`,
		"guest-invite-role-"+suffix).Scan(&roleID); err != nil {
		t.Fatalf("insert invite admin role: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by)
		 VALUES ($1,$2,$1)`, actorID, roleID); err != nil {
		t.Fatalf("assign invite admin role: %v", err)
	}

	type priorConfig struct {
		value  string
		exists bool
	}
	configKeys := []string{"guest.invite_ttl_days", "authserver.public_url", "mail.default_sender"}
	priorConfigs := make(map[string]priorConfig, len(configKeys))
	for _, key := range configKeys {
		var value string
		err := pool.QueryRow(ctx, `SELECT value::text FROM system_config WHERE key=$1`, key).Scan(&value)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("read prior %s: %v", key, err)
		}
		priorConfigs[key] = priorConfig{value: value, exists: err == nil}
	}
	setConfig := func(key, value string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO system_config (key,value) VALUES ($1,to_jsonb($2::text))
			 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, key, value); err != nil {
			t.Fatalf("set %s: %v", key, err)
		}
	}
	setConfig("guest.invite_ttl_days", "3")
	setConfig("authserver.public_url", "https://auth.example.test")
	setConfig("mail.default_sender", "invite@"+domain)

	var logBuf bytes.Buffer
	h := NewGuestsHandler(pool, guestsOnFlags(), nil, "mailblobs",
		slog.New(slog.NewTextHandler(&logBuf, nil)))
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM guest_invite_domains WHERE host_domain_id=$1`, hostDomainID)
		pool.Exec(c, `DELETE FROM guest_invites WHERE host_domain_id=$1`, hostDomainID)
		pool.Exec(c, `DELETE FROM users WHERE id IN
			(SELECT user_id FROM guest_accounts WHERE host_domain_id=$1)`, hostDomainID)
		pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, roleID)
		pool.Exec(c, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		pool.Exec(c, `DELETE FROM users WHERE id=$1`, actorID)
		pool.Exec(c, `DELETE FROM domains WHERE id=$1`, hostDomainID)
		for key, prior := range priorConfigs {
			if prior.exists {
				pool.Exec(c, `UPDATE system_config SET value=$2::jsonb WHERE key=$1`, key, prior.value)
			} else {
				pool.Exec(c, `DELETE FROM system_config WHERE key=$1`, key)
			}
		}
	})
	return &guestInviteFixture{pool: pool, handler: h, actorID: actorID, roleID: roleID,
		hostDomainID: hostDomainID, domain: domain, logBuf: &logBuf}
}

func (f *guestInviteFixture) request(method, target, body string) *http.Request {
	return guestAdminRequest(method, target, body, guestManageClaims(f.actorID))
}

func (f *guestInviteFixture) invite(email string) *httptest.ResponseRecorder {
	req := f.request(http.MethodPost, "/admin/guests",
		fmt.Sprintf(`{"email":%q,"displayName":"External Guest"}`, email))
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	return rr
}

func TestGuestInvite_DomainAllowlistRejectsBeforeProvision(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()

	add := f.request(http.MethodPost, "/admin/guest-invite-domains", `{"domain":"allowed.example"}`)
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, add)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: want 201, got %d: %s", addRR.Code, addRR.Body.String())
	}

	email := "blocked-" + rolesTestRandomSuffix(t) + "@blocked.example"
	rr := f.invite(email)
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "BZ218") {
		t.Fatalf("want BZ218 403, got %d: %s", rr.Code, rr.Body.String())
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, email).Scan(&count); err != nil {
		t.Fatalf("count rejected guest: %v", err)
	}
	if count != 0 {
		t.Fatalf("BZ218 left %d partial users row(s)", count)
	}
}

func TestGuestInvite_CreateRevokeAndDomainRoutes(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	allowedDomain := "partner-" + rolesTestRandomSuffix(t) + ".example"

	add := f.request(http.MethodPost, "/admin/guest-invite-domains",
		fmt.Sprintf(`{"domain":%q}`, strings.ToUpper(allowedDomain)))
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, add)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: want 201, got %d: %s", addRR.Code, addRR.Body.String())
	}
	var domainCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM guest_invite_domains WHERE domain=$1`, allowedDomain).Scan(&domainCount); err != nil || domainCount != 1 {
		t.Fatalf("added domain count=%d err=%v", domainCount, err)
	}
	legacyPassword := f.request(http.MethodPost, "/admin/guests",
		fmt.Sprintf(`{"email":"legacy@%s","password":"must-not-be-accepted"}`, allowedDomain))
	legacyRR := httptest.NewRecorder()
	f.handler.ServeHTTP(legacyRR, legacyPassword)
	if legacyRR.Code != http.StatusBadRequest {
		t.Fatalf("removed password field must be rejected, got %d: %s", legacyRR.Code, legacyRR.Body.String())
	}

	var captured []capturedGuestMail
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, to, subject, body string) error {
		captured = append(captured, capturedGuestMail{to: to, subject: subject, body: body})
		return nil
	})
	t.Cleanup(restore)

	email := "invited-" + rolesTestRandomSuffix(t) + "@" + allowedDomain
	started := time.Now()
	rr := f.invite(email)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		GuestUserID  int64     `json:"guestUserId"`
		InviteID     string    `json:"inviteId"`
		InvitedEmail string    `json:"invitedEmail"`
		ExpiresAt    time.Time `json:"expiresAt"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	var responseKeys map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &responseKeys); err != nil {
		t.Fatalf("decode response keys: %v", err)
	}
	if len(responseKeys) != 4 || responseKeys["guestUserId"] == nil || responseKeys["inviteId"] == nil ||
		responseKeys["invitedEmail"] == nil || responseKeys["expiresAt"] == nil {
		t.Fatalf("response keys = %v, want exactly guestUserId/inviteId/invitedEmail/expiresAt", responseKeys)
	}
	if response.GuestUserID == 0 || response.InviteID == "" || response.InvitedEmail != email {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.ExpiresAt.Before(started.Add(71*time.Hour)) || response.ExpiresAt.After(started.Add(73*time.Hour)) {
		t.Fatalf("expiresAt %s does not use JSONB TTL=3 days", response.ExpiresAt)
	}
	if len(captured) != 1 || captured[0].to != email {
		t.Fatalf("captured mail = %+v, want one message to %s", captured, email)
	}
	const tokenMarker = "https://auth.example.test/guest-invite/accept?token="
	pos := strings.Index(captured[0].body, tokenMarker)
	if pos < 0 {
		t.Fatalf("invite body lacks approved accept URL: %q", captured[0].body)
	}
	rawToken := strings.Fields(captured[0].body[pos+len(tokenMarker):])[0]
	if len(rawToken) != 43 || strings.Contains(rawToken, "=") {
		t.Fatalf("raw token has wrong base64url shape: len=%d padding=%v", len(rawToken), strings.Contains(rawToken, "="))
	}
	if strings.Contains(rr.Body.String(), rawToken) || strings.Contains(f.logBuf.String(), rawToken) {
		t.Fatal("raw token leaked into HTTP response or logs")
	}

	var storedHash, status string
	var enabled bool
	var storedExpiry time.Time
	if err := f.pool.QueryRow(ctx,
		`SELECT gi.token_hash, gi.expires_at, ga.status, u.enabled
		   FROM guest_invites gi JOIN guest_accounts ga ON ga.user_id=gi.guest_user_id
		   JOIN users u ON u.id=gi.guest_user_id
		  WHERE gi.guest_user_id=$1 AND gi.used_at IS NULL`, response.GuestUserID,
	).Scan(&storedHash, &storedExpiry, &status, &enabled); err != nil {
		t.Fatalf("read pending invite: %v", err)
	}
	wantHashBytes := sha256.Sum256([]byte(rawToken))
	if storedHash != hex.EncodeToString(wantHashBytes[:]) || storedHash == rawToken {
		t.Fatalf("stored token is not only SHA-256 hex: %q", storedHash)
	}
	if status != "invited" || enabled || !storedExpiry.Equal(response.ExpiresAt) {
		t.Fatalf("pending state status=%q enabled=%v expires=%s response=%s", status, enabled, storedExpiry, response.ExpiresAt)
	}

	// A locked pending-row check makes two simultaneous revokes report exactly
	// one success; the loser observes the tombstone only after the winner commits.
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			req := f.request(http.MethodDelete, "/admin/guests/id/invite",
				fmt.Sprintf(`{"expectedInviteId":%q}`, response.InviteID))
			req.SetPathValue("userId", fmt.Sprint(response.GuestUserID))
			rec := httptest.NewRecorder()
			f.handler.DeleteInvite(rec, req)
			codes <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(codes)
	got := map[int]int{}
	for code := range codes {
		got[code]++
	}
	if got[http.StatusOK] != 1 || got[http.StatusNotFound] != 1 {
		t.Fatalf("concurrent revoke codes=%v, want one 200 and one 404", got)
	}
	var used bool
	if err := f.pool.QueryRow(ctx,
		`SELECT used_at IS NOT NULL FROM guest_invites WHERE guest_user_id=$1 ORDER BY id DESC LIMIT 1`,
		response.GuestUserID).Scan(&used); err != nil || !used {
		t.Fatalf("revoke tombstone used=%v err=%v", used, err)
	}

	remove := f.request(http.MethodDelete, "/admin/guest-invite-domains/domain", "")
	remove.SetPathValue("domain", strings.ToUpper(allowedDomain))
	removeRR := httptest.NewRecorder()
	f.handler.RemoveInviteDomain(removeRR, remove)
	if removeRR.Code != http.StatusNoContent {
		t.Fatalf("remove domain: want 204, got %d: %s", removeRR.Code, removeRR.Body.String())
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM guest_invite_domains WHERE domain=$1`, allowedDomain).Scan(&domainCount); err != nil || domainCount != 0 {
		t.Fatalf("removed domain count=%d err=%v", domainCount, err)
	}
}

func TestGuestInvite_RevokeEnforcesAdministrativeReach(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, _ string) error {
		return nil
	})
	t.Cleanup(restore)

	rr := f.invite("scoped-guest-" + rolesTestRandomSuffix(t) + "@external.example")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		GuestUserID int64  `json:"guestUserId"`
		InviteID    string `json:"inviteId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode invite response: %v", err)
	}

	otherDomain := "other-guest-owner-" + rolesTestRandomSuffix(t) + ".example"
	otherDomainID := ensureScopeTestDomain(t, f.pool, otherDomain)
	t.Cleanup(func() {
		f.pool.Exec(context.Background(), `DELETE FROM domains WHERE id=$1`, otherDomainID)
	})
	if _, err := f.pool.Exec(ctx,
		`UPDATE admin_role_assignments
		    SET scope_type=NULL, scope_id=NULL, domain_override=$1
		  WHERE user_id=$2 AND role_group_id=$3`,
		otherDomainID, f.actorID, f.roleID); err != nil {
		t.Fatalf("scope invite admin: %v", err)
	}

	revoke := func() *httptest.ResponseRecorder {
		req := f.request(http.MethodDelete, "/admin/guests/id/invite",
			fmt.Sprintf(`{"expectedInviteId":%q}`, response.InviteID))
		req.SetPathValue("userId", fmt.Sprint(response.GuestUserID))
		recorder := httptest.NewRecorder()
		f.handler.DeleteInvite(recorder, req)
		return recorder
	}
	denied := revoke()
	if denied.Code != http.StatusForbidden {
		t.Fatalf("out-of-scope revoke: want 403, got %d: %s", denied.Code, denied.Body.String())
	}
	var stillPending bool
	if err := f.pool.QueryRow(ctx,
		`SELECT used_at IS NULL FROM guest_invites WHERE guest_user_id=$1 ORDER BY id DESC LIMIT 1`,
		response.GuestUserID).Scan(&stillPending); err != nil || !stillPending {
		t.Fatalf("out-of-scope revoke changed invite: pending=%v err=%v", stillPending, err)
	}

	if _, err := f.pool.Exec(ctx,
		`UPDATE admin_role_assignments SET domain_override=$1
		  WHERE user_id=$2 AND role_group_id=$3`, f.hostDomainID, f.actorID, f.roleID); err != nil {
		t.Fatalf("move admin to guest host-domain scope: %v", err)
	}
	allowed := revoke()
	if allowed.Code != http.StatusOK {
		t.Fatalf("same-scope revoke: want 200, got %d: %s", allowed.Code, allowed.Body.String())
	}
}

func TestGuestInvite_SendFailureKeepsPendingInvite(t *testing.T) {
	f := newGuestInviteFixture(t)
	allowedDomain := "mail-fail-" + rolesTestRandomSuffix(t) + ".example"
	add := f.request(http.MethodPost, "/admin/guest-invite-domains", fmt.Sprintf(`{"domain":%q}`, allowedDomain))
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, add)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", addRR.Code, addRR.Body.String())
	}
	restore := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, body string) error {
		return errors.New("mail transport echoed " + body)
	})
	t.Cleanup(restore)

	email := "mail-fail@" + allowedDomain
	rr := f.invite(email)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("send failure: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
	var delivery struct {
		Code        string `json:"code"`
		Retryable   bool   `json:"retryable"`
		InviteID    string `json:"inviteId"`
		GuestUserID int64  `json:"guestUserId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &delivery); err != nil ||
		delivery.Code != "invite_delivery_unconfirmed" || !delivery.Retryable ||
		delivery.InviteID == "" || delivery.GuestUserID == 0 {
		t.Fatalf("unexpected delivery uncertainty response: %+v err=%v", delivery, err)
	}
	var count int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM guest_invites gi JOIN users u ON u.id=gi.guest_user_id
		  WHERE lower(u.email)=lower($1) AND gi.used_at IS NULL`, email).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pending invite after send failure count=%d err=%v", count, err)
	}
	if strings.Contains(f.logBuf.String(), "token=") || strings.Contains(f.logBuf.String(), "@"+allowedDomain) {
		t.Fatalf("send failure log leaked token or invited address: %s", f.logBuf.String())
	}
}

func TestGuestInvite_MissingAuthURLRollsBackProvision(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `DELETE FROM system_config WHERE key='authserver.public_url'`); err != nil {
		t.Fatalf("remove auth URL: %v", err)
	}
	allowedDomain := "missing-auth-" + rolesTestRandomSuffix(t) + ".example"
	add := f.request(http.MethodPost, "/admin/guest-invite-domains", fmt.Sprintf(`{"domain":%q}`, allowedDomain))
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, add)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", addRR.Code, addRR.Body.String())
	}
	email := "missing-auth@" + allowedDomain
	rr := f.invite(email)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("missing auth URL: want 500, got %d: %s", rr.Code, rr.Body.String())
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, email).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing auth URL left partial guest count=%d err=%v", count, err)
	}
}

func TestGuestsHandler_InviteAcceptsProfileAndPrefillsExpiry(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	var profileID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT guest_profile_set($1,NULL,$2,$3,true,true,false,false,false,false,true,12,ARRAY['chat'])`,
		f.actorID, f.hostDomainID, "Invite profile "+rolesTestRandomSuffix(t)).Scan(&profileID); err != nil {
		t.Fatalf("create invite profile: %v", err)
	}
	t.Cleanup(func() {
		f.pool.Exec(context.Background(), `UPDATE guest_accounts SET profile_id=NULL WHERE profile_id=$1`, profileID)
		f.pool.Exec(context.Background(), `DELETE FROM guest_profiles WHERE id=$1`, profileID)
	})
	allowedDomain := "profile-invite-" + rolesTestRandomSuffix(t) + ".example"
	add := f.request(http.MethodPost, "/admin/guest-invite-domains", fmt.Sprintf(`{"domain":%q}`, allowedDomain))
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, add)
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", addRR.Code, addRR.Body.String())
	}
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		return nil
	})
	t.Cleanup(restore)

	email := "profiled@" + allowedDomain
	req := f.request(http.MethodPost, "/admin/guests", fmt.Sprintf(
		`{"email":%q,"displayName":"Profiled guest","profileId":%d}`, email, profileID))
	rr := httptest.NewRecorder()
	f.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var assignedProfileID int64
	var expiresAt time.Time
	if err := f.pool.QueryRow(ctx,
		`SELECT ga.profile_id,ga.expires_at FROM guest_accounts ga
		 WHERE lower(ga.invited_email)=lower($1)`, email).Scan(&assignedProfileID, &expiresAt); err != nil {
		t.Fatalf("read profiled guest: %v", err)
	}
	if assignedProfileID != profileID {
		t.Fatalf("profile assignment mismatch: got %d want %d", assignedProfileID, profileID)
	}
	want := time.Now().Add(12 * 24 * time.Hour)
	if delta := expiresAt.Sub(want); delta < -time.Minute || delta > time.Minute {
		t.Fatalf("profile default expiry not applied: got %s want around %s", expiresAt, want)
	}
}

func TestGuestsHandler_ExplicitReinviteFreezesSignInAndCannotBypassAcceptance(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	allowedDomain := "reinvite-state-" + rolesTestRandomSuffix(t) + ".example"
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, f.request(http.MethodPost, "/admin/guest-invite-domains",
		fmt.Sprintf(`{"domain":%q}`, allowedDomain)))
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", addRR.Code, addRR.Body.String())
	}
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		return nil
	})
	t.Cleanup(restore)

	email := "reinvite@" + allowedDomain
	first := f.invite(email)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first invite: %d %s", first.Code, first.Body.String())
	}
	var firstResponse struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil || firstResponse.GuestUserID == 0 {
		t.Fatalf("decode first invite: id=%d err=%v", firstResponse.GuestUserID, err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE guest_accounts SET status='active' WHERE user_id=$1`, firstResponse.GuestUserID); err != nil {
		t.Fatalf("prepare active guest: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE users SET enabled=TRUE WHERE id=$1`, firstResponse.GuestUserID); err != nil {
		t.Fatalf("prepare enabled user: %v", err)
	}

	legacy := f.invite(email)
	if legacy.Code != http.StatusUnprocessableEntity {
		t.Fatalf("generic invite must not recover active guest: want 422, got %d: %s", legacy.Code, legacy.Body.String())
	}
	drain := &guestDrainRecorder{}
	f.handler.SetLifecycleDrainer(drain)
	reinviteReq := f.request(http.MethodPost,
		fmt.Sprintf("/admin/guests/%d/reinvite", firstResponse.GuestUserID), `{}`)
	reinviteReq.SetPathValue("id", fmt.Sprint(firstResponse.GuestUserID))
	second := httptest.NewRecorder()
	f.handler.Reinvite(second, reinviteReq)
	if second.Code != http.StatusAccepted {
		t.Fatalf("explicit re-invite: %d %s", second.Code, second.Body.String())
	}
	var secondResponse struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResponse); err != nil ||
		secondResponse.GuestUserID != firstResponse.GuestUserID {
		t.Fatalf("explicit re-invite must preserve the same guest identity: first=%d second=%d err=%v",
			firstResponse.GuestUserID, secondResponse.GuestUserID, err)
	}
	drain.mu.Lock()
	drained := append([]int64(nil), drain.userIDs...)
	drain.mu.Unlock()
	if len(drained) != 1 || drained[0] != firstResponse.GuestUserID {
		t.Fatalf("post-commit live eviction drain = %v, want [%d]", drained, firstResponse.GuestUserID)
	}

	enable := f.request(http.MethodPost, fmt.Sprintf("/admin/guests/%d/enable", firstResponse.GuestUserID), "")
	enable.SetPathValue("id", fmt.Sprint(firstResponse.GuestUserID))
	enableRR := httptest.NewRecorder()
	f.handler.Enable(enableRR, enable)
	if enableRR.Code != http.StatusUnprocessableEntity {
		t.Fatalf("enable invited guest: want 422, got %d: %s", enableRR.Code, enableRR.Body.String())
	}
	var status string
	var enabled bool
	var pending int
	if err := f.pool.QueryRow(ctx,
		`SELECT g.status,u.enabled,
		        (SELECT count(*) FROM guest_invites gi
		          WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL)
		   FROM guest_accounts g JOIN users u ON u.id=g.user_id
		  WHERE g.user_id=$1`, firstResponse.GuestUserID).Scan(&status, &enabled, &pending); err != nil {
		t.Fatalf("read re-invite state: %v", err)
	}
	if status != "invited" || enabled || pending != 1 {
		t.Fatalf("enable bypass mutated acceptance state: status=%s enabled=%v pending=%d", status, enabled, pending)
	}

	// SetTestSender deliberately serializes overrides. Restore the successful
	// sender before installing the failure seam below; nesting overrides would
	// block on the test-only mutex and hide the behavior this test owns.
	restore()
	var tokenBearingBody string
	restoreFailure := notify.SetTestSender(func(_ context.Context, _ notify.SystemMailQueue, _ *minio.Client,
		_, _, _, _, _, _, body string) error {
		tokenBearingBody = body
		return errors.New("mail transport echoed " + body)
	})
	t.Cleanup(restoreFailure)
	retryReq := f.request(http.MethodPost,
		fmt.Sprintf("/admin/guests/%d/reinvite", firstResponse.GuestUserID), `{}`)
	retryReq.SetPathValue("id", fmt.Sprint(firstResponse.GuestUserID))
	retryRR := httptest.NewRecorder()
	f.handler.Reinvite(retryRR, retryReq)
	if retryRR.Code != http.StatusServiceUnavailable {
		t.Fatalf("delivery failure: want 503 after committed recovery, got %d: %s", retryRR.Code, retryRR.Body.String())
	}
	if !strings.Contains(tokenBearingBody, "token=") {
		t.Fatal("delivery failure seam did not receive the token-bearing recovery mail")
	}
	if strings.Contains(retryRR.Body.String(), "token=") || strings.Contains(retryRR.Body.String(), email) ||
		strings.Contains(f.logBuf.String(), "token=") || strings.Contains(f.logBuf.String(), email) {
		t.Fatalf("delivery failure leaked recovery token or address: response=%s log=%s", retryRR.Body.String(), f.logBuf.String())
	}
	if err := f.pool.QueryRow(ctx,
		`SELECT g.status,u.enabled,
		        (SELECT count(*) FROM guest_invites gi
		          WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL)
		   FROM guest_accounts g JOIN users u ON u.id=g.user_id
		  WHERE g.user_id=$1`, firstResponse.GuestUserID).Scan(&status, &enabled, &pending); err != nil {
		t.Fatalf("read committed recovery after delivery failure: %v", err)
	}
	if status != "invited" || enabled || pending != 1 {
		t.Fatalf("delivery failure rolled back or forked recovery state: status=%s enabled=%v pending=%d", status, enabled, pending)
	}
}

func TestGuestsHandler_ExplicitReinviteRejectsFederatedGuest(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	mailCalls := 0
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		mailCalls++
		return nil
	})
	t.Cleanup(restore)

	allowedDomain := "reinvite-sso-" + rolesTestRandomSuffix(t) + ".example"
	addRR := httptest.NewRecorder()
	f.handler.AddInviteDomain(addRR, f.request(http.MethodPost, "/admin/guest-invite-domains",
		fmt.Sprintf(`{"domain":%q}`, allowedDomain)))
	if addRR.Code != http.StatusCreated {
		t.Fatalf("add domain: %d %s", addRR.Code, addRR.Body.String())
	}
	rr := f.invite("federated@" + allowedDomain)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var invited struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &invited); err != nil || invited.GuestUserID == 0 {
		t.Fatalf("decode invite: id=%d err=%v", invited.GuestUserID, err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE guest_accounts SET status='active' WHERE user_id=$1`, invited.GuestUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx,
		`UPDATE users SET enabled=TRUE,sync_source='sso',oidc_subject='external-subject',
		 oidc_issuer='https://idp.example' WHERE id=$1`, invited.GuestUserID); err != nil {
		t.Fatal(err)
	}

	reinvite := f.request(http.MethodPost,
		fmt.Sprintf("/admin/guests/%d/reinvite", invited.GuestUserID), `{}`)
	reinvite.SetPathValue("id", fmt.Sprint(invited.GuestUserID))
	reinviteRR := httptest.NewRecorder()
	f.handler.Reinvite(reinviteRR, reinvite)
	if reinviteRR.Code != http.StatusUnprocessableEntity {
		t.Fatalf("federated re-invite: want 422, got %d: %s", reinviteRR.Code, reinviteRR.Body.String())
	}

	var status string
	var enabled bool
	var pending int
	if err := f.pool.QueryRow(ctx,
		`SELECT g.status,u.enabled,
		        (SELECT count(*) FROM guest_invites gi
		          WHERE gi.guest_user_id=g.user_id AND gi.used_at IS NULL)
		   FROM guest_accounts g JOIN users u ON u.id=g.user_id
		  WHERE g.user_id=$1`, invited.GuestUserID).Scan(&status, &enabled, &pending); err != nil {
		t.Fatal(err)
	}
	if status != "active" || !enabled || pending != 1 || mailCalls != 1 {
		t.Fatalf("federated denial mutated recovery: status=%s enabled=%v pending=%d mailCalls=%d",
			status, enabled, pending, mailCalls)
	}
}

func TestGuestInvite_ProfileSnapshotSerializesConcurrentEdit(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	profileName := "Snapshot profile " + rolesTestRandomSuffix(t)
	var profileID int64
	if err := f.pool.QueryRow(ctx,
		`SELECT guest_profile_set($1,NULL,$2,$3,true,true,false,false,false,false,true,12,ARRAY['chat'])`,
		f.actorID, f.hostDomainID, profileName).Scan(&profileID); err != nil {
		t.Fatalf("create profile: %v", err)
	}

	inviteTx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin invite transaction: %v", err)
	}
	var snapshotRaw []byte
	if err := inviteTx.QueryRow(ctx,
		`SELECT guest_profile_invite_snapshot($1,$2)`, f.actorID, profileID).Scan(&snapshotRaw); err != nil {
		_ = inviteTx.Rollback(ctx)
		t.Fatalf("lock invite profile snapshot: %v", err)
	}
	var snapshot struct {
		DefaultExpiryDays *int `json:"defaultExpiryDays"`
	}
	if err := json.Unmarshal(snapshotRaw, &snapshot); err != nil || snapshot.DefaultExpiryDays == nil ||
		*snapshot.DefaultExpiryDays != 12 {
		_ = inviteTx.Rollback(ctx)
		t.Fatalf("decode invite snapshot: %+v err=%v", snapshot, err)
	}

	updater, err := f.pool.Acquire(ctx)
	if err != nil {
		_ = inviteTx.Rollback(ctx)
		t.Fatalf("acquire updater: %v", err)
	}
	updateDone := make(chan error, 1)
	go func() {
		_, updateErr := updater.Exec(context.Background(),
			`SELECT guest_profile_set($1,$2,$3,$4,false,true,false,false,false,false,false,45,ARRAY['drive'])`,
			f.actorID, profileID, f.hostDomainID, profileName)
		updateDone <- updateErr
	}()
	doneConsumed := false
	defer func() {
		_ = inviteTx.Rollback(context.Background())
		if !doneConsumed {
			select {
			case <-updateDone:
			case <-time.After(3 * time.Second):
			}
		}
		updater.Release()
	}()
	waitForBackendBlock(t, f.pool, updater.Conn().PgConn().PID(), updateDone)

	validated, err := identity.ValidateAndCanonicalizeEmail(
		"snapshot-" + rolesTestRandomSuffix(t) + "@external.example")
	if err != nil {
		t.Fatalf("validate guest email: %v", err)
	}
	expiresAt := time.Now().UTC().Add(time.Duration(*snapshot.DefaultExpiryDays) * 24 * time.Hour).
		Truncate(time.Microsecond)
	invitedBy := f.actorID
	result, err := identity.ProvisionAccount(ctx, inviteTx, identity.ProvisionAccountParams{
		Email: validated, DisplayName: "Snapshot Guest", Guest: true,
		InvitedBy: &invitedBy, GuestExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatalf("provision snapshotted guest: %v", err)
	}
	var provisioned struct {
		UserID int64 `json:"user_id"`
	}
	if err := json.Unmarshal(result, &provisioned); err != nil || provisioned.UserID == 0 {
		t.Fatalf("decode provision result: id=%d err=%v", provisioned.UserID, err)
	}
	if _, err := inviteTx.Exec(ctx, `SELECT guest_profile_apply($1,$2,$3)`,
		f.actorID, provisioned.UserID, profileID); err != nil {
		t.Fatalf("apply snapshotted profile: %v", err)
	}
	var oldChat, oldDrive bool
	if err := inviteTx.QueryRow(ctx,
		`SELECT (SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='chat'),
		        (SELECT enabled FROM user_app_entitlements WHERE user_id=$1 AND app='drive')`,
		provisioned.UserID).Scan(&oldChat, &oldDrive); err != nil {
		t.Fatalf("read policy inside invite transaction: %v", err)
	}
	if !oldChat || oldDrive {
		t.Fatalf("invite transaction mixed profile versions: chat=%v drive=%v", oldChat, oldDrive)
	}
	if err := inviteTx.Commit(ctx); err != nil {
		t.Fatalf("commit invite transaction: %v", err)
	}
	if err := <-updateDone; err != nil {
		doneConsumed = true
		t.Fatalf("concurrent profile update: %v", err)
	}
	doneConsumed = true

	var finalExpiry time.Time
	var finalChat, finalDrive bool
	if err := f.pool.QueryRow(ctx,
		`SELECT g.expires_at,
		        (SELECT enabled FROM user_app_entitlements WHERE user_id=g.user_id AND app='chat'),
		        (SELECT enabled FROM user_app_entitlements WHERE user_id=g.user_id AND app='drive')
		   FROM guest_accounts g WHERE g.user_id=$1`, provisioned.UserID).
		Scan(&finalExpiry, &finalChat, &finalDrive); err != nil {
		t.Fatalf("read serial final state: %v", err)
	}
	if !finalExpiry.Equal(expiresAt) || finalChat || !finalDrive {
		t.Fatalf("non-serial final state: expiry=%s want=%s chat=%v drive=%v",
			finalExpiry, expiresAt, finalChat, finalDrive)
	}
}

func TestGuestsHandler_DisableAttemptsImmediateLifecycleDrainAfterCommit(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		return nil
	})
	t.Cleanup(restore)

	rr := f.invite("g5-disable-" + rolesTestRandomSuffix(t) + "@external.example")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var invited struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &invited); err != nil || invited.GuestUserID == 0 {
		t.Fatalf("decode invited guest: id=%d err=%v", invited.GuestUserID, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE guest_accounts SET status='active' WHERE user_id=$1`, invited.GuestUserID); err != nil {
		t.Fatalf("activate guest: %v", err)
	}

	drainer := &guestDrainRecorder{err: errors.New("synthetic LiveKit outage")}
	f.handler.SetLifecycleDrainer(drainer)
	disable := f.request(http.MethodPost, fmt.Sprintf("/admin/guests/%d/disable", invited.GuestUserID), "")
	disable.SetPathValue("id", fmt.Sprint(invited.GuestUserID))
	disableRR := httptest.NewRecorder()
	f.handler.Disable(disableRR, disable)
	if disableRR.Code != http.StatusNoContent {
		t.Fatalf("disable: want 204 despite peripheral failure, got %d: %s", disableRR.Code, disableRR.Body.String())
	}

	var status string
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT g.status,u.enabled FROM guest_accounts g
		JOIN users u ON u.id=g.user_id WHERE g.user_id=$1`, invited.GuestUserID).Scan(&status, &enabled); err != nil {
		t.Fatalf("read disabled state: %v", err)
	}
	if status != "disabled" || enabled {
		t.Fatalf("disable did not commit before peripheral attempt: status=%s enabled=%v", status, enabled)
	}
	drainer.mu.Lock()
	defer drainer.mu.Unlock()
	if len(drainer.userIDs) != 1 || drainer.userIDs[0] != invited.GuestUserID {
		t.Fatalf("immediate drain calls=%v want [%d]", drainer.userIDs, invited.GuestUserID)
	}
}

func TestGuestsHandler_SponsorOptionsAndTransfer(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		return nil
	})
	t.Cleanup(restore)

	rr := f.invite("g5-transfer-" + rolesTestRandomSuffix(t) + "@external.example")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var invited struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &invited); err != nil || invited.GuestUserID == 0 {
		t.Fatalf("decode invited guest: id=%d err=%v", invited.GuestUserID, err)
	}

	suffix := rolesTestRandomSuffix(t)
	var sponsorID int64
	sponsorEmail := "g5-sponsor-" + suffix + "@" + f.domain
	if err := f.pool.QueryRow(ctx, `INSERT INTO users
		(username,domain_id,email,display_name,enabled)
		VALUES ($1,$2,$3,'Replacement Sponsor',TRUE) RETURNING id`,
		"g5-sponsor-"+suffix, f.hostDomainID, sponsorEmail).Scan(&sponsorID); err != nil {
		t.Fatalf("insert sponsor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, sponsorID)
	})

	optionsReq := f.request(http.MethodGet,
		fmt.Sprintf("/admin/guests/%d/sponsor-options?q=%s", invited.GuestUserID, sponsorEmail), "")
	optionsReq.SetPathValue("id", fmt.Sprint(invited.GuestUserID))
	optionsRR := httptest.NewRecorder()
	f.handler.SponsorOptions(optionsRR, optionsReq)
	if optionsRR.Code != http.StatusOK {
		t.Fatalf("sponsor options: want 200, got %d: %s", optionsRR.Code, optionsRR.Body.String())
	}
	var options []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(optionsRR.Body.Bytes(), &options); err != nil ||
		len(options) != 1 || options[0].ID != sponsorID {
		t.Fatalf("sponsor options=%v err=%v, want only %d", options, err, sponsorID)
	}

	transferReq := f.request(http.MethodPost,
		fmt.Sprintf("/admin/guests/%d/transfer", invited.GuestUserID),
		fmt.Sprintf(`{"sponsorUserId":%d}`, sponsorID))
	transferReq.SetPathValue("id", fmt.Sprint(invited.GuestUserID))
	transferRR := httptest.NewRecorder()
	f.handler.Transfer(transferRR, transferReq)
	if transferRR.Code != http.StatusOK {
		t.Fatalf("transfer: want 200, got %d: %s", transferRR.Code, transferRR.Body.String())
	}
	var storedSponsor int64
	if err := f.pool.QueryRow(ctx, `SELECT sponsor_user_id FROM guest_accounts WHERE user_id=$1`,
		invited.GuestUserID).Scan(&storedSponsor); err != nil {
		t.Fatalf("read transferred sponsor: %v", err)
	}
	if storedSponsor != sponsorID {
		t.Fatalf("stored sponsor=%d want %d", storedSponsor, sponsorID)
	}
}

func TestGuestTransferAndDisableShareLifecycleLockOrder(t *testing.T) {
	f := newGuestInviteFixture(t)
	ctx := context.Background()
	restore := notify.SetTestSender(func(context.Context, notify.SystemMailQueue, *minio.Client,
		string, string, string, string, string, string, string) error {
		return nil
	})
	t.Cleanup(restore)

	rr := f.invite("g5-lock-order-" + rolesTestRandomSuffix(t) + "@external.example")
	if rr.Code != http.StatusAccepted {
		t.Fatalf("invite: want 202, got %d: %s", rr.Code, rr.Body.String())
	}
	var invited struct {
		GuestUserID int64 `json:"guestUserId"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &invited); err != nil || invited.GuestUserID == 0 {
		t.Fatalf("decode invited guest: id=%d err=%v", invited.GuestUserID, err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE guest_accounts SET status='active' WHERE user_id=$1`, invited.GuestUserID); err != nil {
		t.Fatalf("activate guest: %v", err)
	}

	suffix := rolesTestRandomSuffix(t)
	var sponsorID int64
	if err := f.pool.QueryRow(ctx, `INSERT INTO users
		(username,domain_id,email,display_name,enabled)
		VALUES ($1,$2,$3,'Lock-order Sponsor',TRUE) RETURNING id`,
		"g5-lock-sponsor-"+suffix, f.hostDomainID, "g5-lock-sponsor-"+suffix+"@"+f.domain).
		Scan(&sponsorID); err != nil {
		t.Fatalf("insert sponsor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, sponsorID)
	})

	lifecycleTx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin lifecycle transaction: %v", err)
	}
	defer lifecycleTx.Rollback(context.Background()) //nolint:errcheck
	if _, err := lifecycleTx.Exec(ctx, `SELECT 1 FROM guest_accounts WHERE user_id=$1 FOR UPDATE`, invited.GuestUserID); err != nil {
		t.Fatalf("lock guest lifecycle row: %v", err)
	}

	transferConn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire transfer connection: %v", err)
	}
	defer transferConn.Release()
	transferDone := make(chan error, 1)
	go func() {
		_, transferErr := transferConn.Exec(context.Background(),
			`SELECT guest_transfer($1,$2,$3)`, f.actorID, invited.GuestUserID, sponsorID)
		transferDone <- transferErr
	}()
	waitForBackendBlock(t, f.pool, transferConn.Conn().PgConn().PID(), transferDone)

	// With the global guest_accounts→users order, lifecycle can now lock the
	// user row and commit. The former users→guest_accounts transfer order made
	// this exact choreography an ABBA deadlock.
	if _, err := lifecycleTx.Exec(ctx, `SELECT guest_set_status($1,$2,'disable',NULL)`,
		f.actorID, invited.GuestUserID); err != nil {
		t.Fatalf("disable while transfer waits: %v", err)
	}
	if err := lifecycleTx.Commit(ctx); err != nil {
		t.Fatalf("commit disable: %v", err)
	}
	select {
	case err := <-transferDone:
		if err != nil {
			t.Fatalf("transfer after lifecycle commit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("transfer did not resume after lifecycle commit")
	}
}
