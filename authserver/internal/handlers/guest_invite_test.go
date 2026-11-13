package handlers

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"setjoin.com/shared/pgxutil"
)

type guestInviteFixture struct {
	userID    int64
	inviteID  int64
	email     string
	token     string
	tokenHash string
	domainID  int64
}

func seedGuestInvite(t *testing.T, pool *pgxpool.Pool, state string) guestInviteFixture {
	t.Helper()
	ctx := context.Background()
	suffix := randSuffix()
	f := guestInviteFixture{
		email:     "invite-" + suffix + "@partner.example",
		token:     "guest-invite-token-" + suffix,
		tokenHash: hashGuestInviteToken("guest-invite-token-" + suffix),
	}
	createdDomain := false
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE is_local = TRUE ORDER BY id LIMIT 1`).Scan(&f.domainID); errors.Is(err, pgx.ErrNoRows) {
		if err := pool.QueryRow(ctx,
			`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, "host-"+suffix+".example",
		).Scan(&f.domainID); err != nil {
			t.Fatalf("seed local host domain: %v", err)
		}
		createdDomain = true
	} else if err != nil {
		t.Fatalf("find local host domain: %v", err)
	}
	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name = 'guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Fatalf("guest schema not loaded: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, domain_id, email, display_name, enabled)
		 VALUES ($1, $2, $1, 'Invite Test Guest', FALSE) RETURNING id`, f.email, guestDomainID,
	).Scan(&f.userID); err != nil {
		t.Fatalf("seed guest user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO guest_accounts (user_id, invited_email, invited_by_email, host_domain_id, status)
		 VALUES ($1, $2, 'inviter@example.com', $3, 'invited')`, f.userID, f.email, f.domainID,
	); err != nil {
		t.Fatalf("seed guest satellite: %v", err)
	}
	expiresAt := time.Now().Add(time.Hour)
	var usedAt any
	var terminalReason any
	if state == "expired" {
		expiresAt = time.Now().Add(-time.Hour)
	}
	if state == "used" {
		usedAt = time.Now().Add(-time.Minute)
		terminalReason = "legacy_unknown"
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO guest_invites
		 (guest_user_id, token_hash, host_domain_id, created_by_email, expires_at, used_at, terminal_reason)
		 VALUES ($1, $2, $3, 'inviter@example.com', $4, $5, $6) RETURNING id`,
		f.userID, f.tokenHash, f.domainID, expiresAt, usedAt, terminalReason,
	).Scan(&f.inviteID); err != nil {
		t.Fatalf("seed guest invite: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM admin_audit_log WHERE target_type = 'user' AND target_id = $1`, f.userID)
		pool.Exec(c, `DELETE FROM admin_audit_log WHERE target_type = 'guest_invite' AND target_id = $1`, f.inviteID)
		pool.Exec(c, `DELETE FROM guest_invites WHERE guest_user_id = $1`, f.userID)
		pool.Exec(c, `DELETE FROM guest_accounts WHERE user_id = $1`, f.userID)
		pool.Exec(c, `DELETE FROM users WHERE id = $1`, f.userID)
		if createdDomain {
			pool.Exec(c, `DELETE FROM domains WHERE id = $1`, f.domainID)
		}
	})
	return f
}

func hashGuestInviteToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func guestInviteHandler(pool *pgxpool.Pool) *AuthHandler {
	return NewAuthHandler(AuthHandlerConfig{
		Pool:           pool,
		DatabaseWorker: pgxutil.WorkerPool{Pool: pool},
		JWT:            newTestJWT(),
		Logger:         discardLogger(),
	})
}

func guestInviteRequest(method, target, ip string, body any) *http.Request {
	var b *bytes.Reader
	if body == nil {
		b = bytes.NewReader(nil)
	} else {
		raw, _ := json.Marshal(body)
		b = bytes.NewReader(raw)
	}
	r := httptest.NewRequest(method, target, b)
	r.RemoteAddr = ip + ":12345"
	return r
}

func TestGuestInviteAcceptGet_UniformTerminalFailure(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	expired := seedGuestInvite(t, pool, "expired")
	used := seedGuestInvite(t, pool, "used")

	tests := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"unknown", "unknown-token"},
		{"expired", expired.token},
		{"used", used.token},
	}
	var wantBody string
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.GuestInviteAcceptGet(rr, guestInviteRequest(http.MethodGet,
				"/auth/guest-invite/accept?token="+tc.token, fmt.Sprintf("198.51.100.%d", i+1), nil))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
			}
			if i == 0 {
				wantBody = rr.Body.String()
			} else if rr.Body.String() != wantBody {
				t.Fatalf("body differs from missing-token response: got %q want %q", rr.Body.String(), wantBody)
			}
		})
	}
}

func TestGuestInviteAcceptPost_DisclosureRequired_NoWrites(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	rr := httptest.NewRecorder()
	h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", "198.51.100.20", map[string]any{
		"token": f.token, "disclosure_accepted": false, "new_password": "ValidGuestPass1!",
	}))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	var usedAt, acceptedAt *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT used_at, disclosure_accepted_at FROM guest_invites WHERE id = $1`, f.inviteID,
	).Scan(&usedAt, &acceptedAt); err != nil {
		t.Fatal(err)
	}
	if usedAt != nil || acceptedAt != nil {
		t.Fatalf("disclosure refusal wrote invite: used=%v accepted=%v", usedAt, acceptedAt)
	}
}

func TestGuestInviteAcceptPost_UniformTerminalFailure(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	expired := seedGuestInvite(t, pool, "expired")
	used := seedGuestInvite(t, pool, "used")

	tests := []struct {
		name  string
		token string
	}{
		{"missing", ""},
		{"unknown", "unknown-post-token"},
		{"expired", expired.token},
		{"used", used.token},
	}
	var wantBody string
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost,
				"/auth/guest-invite/accept", fmt.Sprintf("198.51.100.%d", 60+i), map[string]any{
					"token": tc.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
				}))
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body=%s", rr.Code, rr.Body.String())
			}
			if i == 0 {
				wantBody = rr.Body.String()
			} else if rr.Body.String() != wantBody {
				t.Fatalf("body differs from missing-token response: got %q want %q", rr.Body.String(), wantBody)
			}
		})
	}
}

func TestGuestInviteAccept_FailsClosedForLifecycleExpiryAndFederation(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	tests := []struct {
		name    string
		prepare func(context.Context, guestInviteFixture) error
	}{
		{
			name: "guest lifecycle expired",
			prepare: func(ctx context.Context, f guestInviteFixture) error {
				_, err := pool.Exec(ctx,
					`UPDATE guest_accounts SET expires_at=now()-interval '1 minute' WHERE user_id=$1`, f.userID)
				return err
			},
		},
		{
			name: "federation attached after mint",
			prepare: func(ctx context.Context, f guestInviteFixture) error {
				_, err := pool.Exec(ctx, `UPDATE users SET sync_source='sso' WHERE id=$1`, f.userID)
				return err
			},
		},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			f := seedGuestInvite(t, pool, "valid")
			if err := tc.prepare(ctx, f); err != nil {
				t.Fatal(err)
			}

			getRR := httptest.NewRecorder()
			h.GuestInviteAcceptGet(getRR, guestInviteRequest(http.MethodGet,
				"/auth/guest-invite/accept?token="+f.token, fmt.Sprintf("198.51.100.%d", 90+i), nil))
			if getRR.Code != http.StatusUnauthorized {
				t.Fatalf("GET status = %d, want 401: %s", getRR.Code, getRR.Body.String())
			}

			postRR := httptest.NewRecorder()
			h.GuestInviteAcceptPost(postRR, guestInviteRequest(http.MethodPost,
				"/auth/guest-invite/accept", fmt.Sprintf("198.51.100.%d", 100+i), map[string]any{
					"token": f.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
				}))
			if postRR.Code != http.StatusUnauthorized {
				t.Fatalf("POST status = %d, want 401: %s", postRR.Code, postRR.Body.String())
			}

			var status string
			var enabled bool
			var passwordHash *string
			var usedAt *time.Time
			var terminalReason *string
			if err := pool.QueryRow(ctx,
				`SELECT ga.status,u.enabled,u.password_hash,gi.used_at,gi.terminal_reason
				   FROM guest_accounts ga JOIN users u ON u.id=ga.user_id
				   JOIN guest_invites gi ON gi.guest_user_id=ga.user_id
				  WHERE ga.user_id=$1`, f.userID,
			).Scan(&status, &enabled, &passwordHash, &usedAt, &terminalReason); err != nil {
				t.Fatal(err)
			}
			if status != "invited" || enabled || passwordHash != nil {
				t.Fatalf("terminal refusal mutated identity: status=%s enabled=%v password=%v",
					status, enabled, passwordHash != nil)
			}
			if tc.name == "guest lifecycle expired" {
				if usedAt == nil || terminalReason == nil || *terminalReason != "expired" {
					t.Fatalf("expired refusal terminal state: used=%v reason=%v", usedAt, terminalReason)
				}
			} else if usedAt != nil || terminalReason != nil {
				t.Fatalf("non-expiry refusal consumed invite: used=%v reason=%v", usedAt, terminalReason)
			}
		})
	}
}

func TestGuestInviteAcceptGet_ReturnsDisclosureLocalityAndChannels(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	ctx := context.Background()
	var channelID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO chat_channels (kind, name, visibility, created_by)
		 VALUES ('channel', 'Partner Launch', 'private', $1) RETURNING id`, f.userID,
	).Scan(&channelID); err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO chat_channel_members (channel_id, user_id) VALUES ($1,$2)`, channelID, f.userID); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	t.Cleanup(func() { pool.Exec(context.Background(), `DELETE FROM chat_channels WHERE id=$1`, channelID) })

	rr := httptest.NewRecorder()
	h.GuestInviteAcceptGet(rr, guestInviteRequest(http.MethodGet,
		"/auth/guest-invite/accept?token="+f.token, "198.51.100.21", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Language"); got != "en" {
		t.Fatalf("Content-Language = %q, want en fallback", got)
	}
	var got struct {
		OrgName           string   `json:"org_name"`
		InvitedEmail      string   `json:"invited_email"`
		Channels          []string `json:"channels"`
		DisclosureText    string   `json:"disclosure_text"`
		DisclosureVersion string   `json:"disclosure_version"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.OrgName == "" || got.InvitedEmail != f.email || got.DisclosureVersion != "v1" {
		t.Fatalf("bad disclosure envelope: %+v", got)
	}
	if len(got.Channels) != 1 || got.Channels[0] != "Partner Launch" {
		t.Fatalf("channels = %v", got.Channels)
	}
	for _, required := range []string{"Partner Launch", "retained", "administrators", "consent", "on-premise at your organization's location"} {
		if !bytes.Contains([]byte(got.DisclosureText), []byte(required)) {
			t.Errorf("disclosure missing %q: %s", required, got.DisclosureText)
		}
	}
	var stamped string
	if err := pool.QueryRow(ctx, `SELECT disclosure_version FROM guest_invites WHERE id=$1`, f.inviteID).Scan(&stamped); err != nil || stamped != "v1" {
		t.Fatalf("disclosure stamp = %q, err=%v", stamped, err)
	}
}

func TestGuestDisclosureCopy_LocalizesBuiltInTermsAndFallbackLocality(t *testing.T) {
	tests := []struct {
		header   string
		wantLang string
		channel  string
		needles  []string
	}{
		{"zh-CN,zh;q=0.9", "zh", "产品发布", []string{"外部来宾", "产品发布", "本地环境", "归档和监控"}},
		{"de-DE,de;q=0.9", "de", "Produktstart", []string{"externer Gast", "Produktstart", "Standort Ihrer Organisation", "Archivierung"}},
		{"fr-FR,fr;q=0.9", "en", "Product launch", []string{"external guest", "Product launch", "organization's location", "archival and monitoring"}},
	}
	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			lang := guestDisclosureLanguage(tc.header)
			if lang != tc.wantLang {
				t.Fatalf("language = %q, want %q", lang, tc.wantLang)
			}
			text := guestDisclosureCopy(lang, "Example Org", []string{tc.channel}, "", "Operator addendum.")
			for _, needle := range tc.needles {
				if !strings.Contains(text, needle) {
					t.Errorf("localized disclosure missing %q: %s", needle, text)
				}
			}
			if !strings.HasSuffix(text, "Operator addendum.") {
				t.Errorf("operator addendum missing: %s", text)
			}
		})
	}
}

func TestGuestInviteAcceptGet_PostWinsBeforeDisclosureStamp(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	afterRead := make(chan struct{})
	resumeGet := make(chan struct{})
	getDone := make(chan *httptest.ResponseRecorder, 1)

	getReq := guestInviteRequest(http.MethodGet,
		"/auth/guest-invite/accept?token="+f.token, "198.51.100.80", nil)
	getReq = getReq.WithContext(context.WithValue(getReq.Context(), guestInviteBeforeDisclosureStampKey{}, func() {
		close(afterRead)
		<-resumeGet
	}))
	go func() {
		rr := httptest.NewRecorder()
		h.GuestInviteAcceptGet(rr, getReq)
		getDone <- rr
	}()
	<-afterRead

	postRR := httptest.NewRecorder()
	h.GuestInviteAcceptPost(postRR, guestInviteRequest(http.MethodPost,
		"/auth/guest-invite/accept", "198.51.100.81", map[string]any{
			"token": f.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
		}))
	if postRR.Code != http.StatusOK {
		t.Fatalf("POST status=%d want 200: %s", postRR.Code, postRR.Body.String())
	}
	close(resumeGet)
	getRR := <-getDone
	if getRR.Code != http.StatusUnauthorized || getRR.Body.String() != "{\"error\":\"invite link is invalid or has expired\"}\n" {
		t.Fatalf("stale GET response=%d %q, want uniform 401", getRR.Code, getRR.Body.String())
	}
}

func TestGuestInviteTerminalReject_RollsBackBeforeDelay(t *testing.T) {
	pool := openHandlerPool(t)
	f := seedGuestInvite(t, pool, "used")
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT id FROM guest_invites WHERE id=$1 FOR UPDATE`, f.inviteID); err != nil {
		t.Fatal(err)
	}

	updateDone := make(chan error, 1)
	probe := "task4_lock_probe_" + randSuffix()
	go func() {
		_, err := pool.Exec(context.Background(), fmt.Sprintf(
			`/* %s */ UPDATE guest_invites SET expires_at=expires_at WHERE id=$1`, probe), f.inviteID)
		updateDone <- err
	}()
	// The updater must be waiting on this transaction before the reject helper
	// runs; pg_stat_activity provides deterministic coordination without delay guesses.
	deadline := time.Now().Add(2 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS (
			   SELECT 1 FROM pg_stat_activity
			    WHERE datname=current_database() AND wait_event_type='Lock'
			      AND query LIKE '%' || $1 || '%')`, probe,
		).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("concurrent updater never reached the row lock")
		}
		time.Sleep(time.Millisecond)
	}

	rejectDone := make(chan struct{})
	go func() {
		guestInviteRollbackAndReject(ctx, tx, httptest.NewRecorder())
		close(rejectDone)
	}()
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-rejectDone:
			t.Fatal("terminal reject completed before the row-lock waiter; rollback was not observably before the delay")
		default:
		}
	case <-rejectDone:
		t.Fatal("terminal reject retained the row lock for its response delay")
	}
	<-rejectDone
}

func TestGuestInviteAcceptPost_AtomicActivationPasswordAndAudit(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	const password = "ValidGuestPass1!"
	rr := httptest.NewRecorder()
	h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", "198.51.100.22", map[string]any{
		"token": f.token, "disclosure_accepted": true, "new_password": password,
	}))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var status string
	var enabled bool
	var passwordHash string
	var usedAt, acceptedAt *time.Time
	var disclosureVersion, terminalReason string
	if err := pool.QueryRow(context.Background(),
		`SELECT ga.status, u.enabled, u.password_hash, gi.used_at, gi.disclosure_accepted_at,
		        gi.disclosure_version, gi.terminal_reason
		 FROM guest_accounts ga JOIN users u ON u.id=ga.user_id
		 JOIN guest_invites gi ON gi.guest_user_id=ga.user_id WHERE ga.user_id=$1`, f.userID,
	).Scan(&status, &enabled, &passwordHash, &usedAt, &acceptedAt, &disclosureVersion, &terminalReason); err != nil {
		t.Fatal(err)
	}
	if status != "active" || !enabled || usedAt == nil || acceptedAt == nil || disclosureVersion != "v1" || terminalReason != "accepted" {
		t.Fatalf("incomplete activation: status=%s enabled=%v used=%v accepted=%v version=%s reason=%s", status, enabled, usedAt, acceptedAt, disclosureVersion, terminalReason)
	}
	if bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)) != nil {
		t.Fatal("stored password hash does not verify")
	}
	var auditCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log WHERE action='guest.invite_accept' AND target_type='guest_invite' AND target_id=$1`, f.inviteID,
	).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("audit count=%d err=%v, want 1", auditCount, err)
	}
	if f.tokenHash == f.token {
		t.Fatal("test token unexpectedly equals its hash")
	}
	var storedHash string
	if err := pool.QueryRow(context.Background(), `SELECT token_hash FROM guest_invites WHERE id=$1`, f.inviteID).Scan(&storedHash); err != nil || storedHash != f.tokenHash || storedHash == f.token {
		t.Fatalf("stored token=%q err=%v, want only SHA-256 hash", storedHash, err)
	}
}

func TestGuestInviteAcceptPost_RejectsPasswordBeyondHashBoundaryWithoutWrites(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	tooLong := strings.Repeat("A", 70) + "a1!"

	rr := httptest.NewRecorder()
	h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", "198.51.100.24", map[string]any{
		"token": f.token, "disclosure_accepted": true, "new_password": tooLong,
	}))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "72-byte limit") {
		t.Fatalf("body = %q, want explicit supported boundary", rr.Body.String())
	}

	var status string
	var enabled bool
	var passwordHash *string
	var usedAt, acceptedAt *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT ga.status,u.enabled,u.password_hash,gi.used_at,gi.disclosure_accepted_at
		   FROM guest_accounts ga
		   JOIN users u ON u.id=ga.user_id
		   JOIN guest_invites gi ON gi.guest_user_id=ga.user_id
		  WHERE ga.user_id=$1`, f.userID,
	).Scan(&status, &enabled, &passwordHash, &usedAt, &acceptedAt); err != nil {
		t.Fatal(err)
	}
	if status != "invited" || enabled || passwordHash != nil || usedAt != nil || acceptedAt != nil {
		t.Fatalf("rejected boundary changed state: status=%s enabled=%v hash=%v used=%v accepted=%v",
			status, enabled, passwordHash, usedAt, acceptedAt)
	}
}

func TestGuestInviteAcceptPost_RollsBackMidWriteFailure(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	ident := "fail_guest_accept_" + randSuffix()
	fn := pgx.Identifier{ident}.Sanitize()
	trigger := pgx.Identifier{ident + "_trigger"}.Sanitize()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, fmt.Sprintf(
		`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id = %d THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$`, fn, f.userID)); err != nil {
		t.Fatalf("create failure function: %v", err)
	}
	// PostgreSQL identifiers cannot be bind parameters; both names are quoted by
	// pgx.Identifier.Sanitize above before this test-only DDL is assembled.
	triggerSQL := "CREATE TRIGGER " + trigger + " BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION " + fn + "()"
	if _, err := pool.Exec(ctx, triggerSQL); err != nil {
		pool.Exec(ctx, fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
		t.Fatalf("create failure trigger: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON users`, trigger))
		pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS %s()`, fn))
	})

	rr := httptest.NewRecorder()
	h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", "198.51.100.23", map[string]any{
		"token": f.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
	}))
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500: %s", rr.Code, rr.Body.String())
	}
	var status string
	var enabled bool
	var passwordHash *string
	var usedAt, acceptedAt *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT ga.status,u.enabled,u.password_hash,gi.used_at,gi.disclosure_accepted_at
		 FROM guest_accounts ga JOIN users u ON u.id=ga.user_id JOIN guest_invites gi ON gi.guest_user_id=ga.user_id
		 WHERE ga.user_id=$1`, f.userID).Scan(&status, &enabled, &passwordHash, &usedAt, &acceptedAt); err != nil {
		t.Fatal(err)
	}
	if status != "invited" || enabled || passwordHash != nil || usedAt != nil || acceptedAt != nil {
		t.Fatalf("partial state escaped rollback: status=%s enabled=%v hash=%v used=%v accepted=%v", status, enabled, passwordHash, usedAt, acceptedAt)
	}
}

func TestGuestInviteAcceptPost_ReplayAndConcurrentDoubleAccept(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	f := seedGuestInvite(t, pool, "valid")
	start := make(chan struct{})
	statuses := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", fmt.Sprintf("198.51.100.%d", 30+i), map[string]any{
				"token": f.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
			}))
			statuses <- rr.Code
		}(i)
	}
	close(start)
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusUnauthorized] != 1 {
		t.Fatalf("concurrent statuses=%v, want one 200 and one 401", counts)
	}

	rr := httptest.NewRecorder()
	h.GuestInviteAcceptPost(rr, guestInviteRequest(http.MethodPost, "/auth/guest-invite/accept", "198.51.100.40", map[string]any{
		"token": f.token, "disclosure_accepted": true, "new_password": "ValidGuestPass1!",
	}))
	if rr.Code != http.StatusUnauthorized || rr.Body.String() != "{\"error\":\"invite link is invalid or has expired\"}\n" {
		t.Fatalf("replay response=%d %q", rr.Code, rr.Body.String())
	}
}

func TestGuestInviteAccept_RateLimitAndMalformedJSON(t *testing.T) {
	pool := openHandlerPool(t)
	h := guestInviteHandler(pool)
	for i := 1; i <= 11; i++ {
		rr := httptest.NewRecorder()
		h.GuestInviteAcceptGet(rr, guestInviteRequest(http.MethodGet,
			"/auth/guest-invite/accept?token=unknown", "203.0.113.99", nil))
		if i <= 10 && rr.Code != http.StatusUnauthorized {
			t.Fatalf("request %d status=%d, want 401", i, rr.Code)
		}
		if i == 11 && rr.Code != http.StatusTooManyRequests {
			t.Fatalf("11th request status=%d, want 429", rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/guest-invite/accept", bytes.NewBufferString("{"))
	r.RemoteAddr = "203.0.113.100:12345"
	h.GuestInviteAcceptPost(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON status=%d want 400", rr.Code)
	}
	rr = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/auth/guest-invite/accept", bytes.NewBufferString(`{} {}`))
	r.RemoteAddr = "203.0.113.101:12345"
	h.GuestInviteAcceptPost(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("second JSON value status=%d want 400", rr.Code)
	}
}

func TestGuestInviteAccept_RoutesRegistered(t *testing.T) {
	path := filepath.Join("..", "..", "cmd", "authserverd", "main.go")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{
		`mux.HandleFunc("GET /auth/guest-invite/accept", authH.GuestInviteAcceptGet)`,
		`mux.Handle("POST /auth/guest-invite/accept", limitRequestBody(guestInviteAcceptBodyLimit,`,
		`threatInterceptor.Middleware(http.HandlerFunc(authH.GuestInviteAcceptPost))))`,
	} {
		if !bytes.Contains(raw, []byte(route)) {
			t.Errorf("authserver main missing route registration %q", route)
		}
	}
}
