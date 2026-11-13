package handlers

// TestMe_ExposesNumericUserID: whole-pipeline review UX #17. /auth/me used to
// carry only email/displayName, so the webmail chat app resolved its own
// numeric selfUserId by matching displayName against a fetched roster — wrong
// in duplicate-displayName orgs. Me() now projects `user_id` straight off the
// validated JWT claims (R2 — never a request field), letting the client read
// its real identity instead of guessing. DB-backed (skipped when DB_DSN is
// unset).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/testsupport"
)

func TestMe_ExposesNumericUserIDAndCanonicalSenderAddresses(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	userID, email := seedDerivationUser(t, pool, ctx, "me-userid", "irrelevant")
	defer cleanSSOActor(t, pool, ctx, userID)
	emailParts := strings.SplitN(email, "@", 2)
	alias := "alias-" + emailParts[0] + "@" + emailParts[1]
	sendAsEmail := "send-as-" + emailParts[0] + "@" + emailParts[1]
	readOnlyEmail := "read-only-" + emailParts[0] + "@" + emailParts[1]
	if _, err := pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id)
		 SELECT m.id, $2, m.domain_id
		   FROM mailboxes m
		  WHERE m.user_id = $1 AND m.is_primary = TRUE`,
		userID, alias,
	); err != nil {
		t.Fatalf("seed sender alias: %v", err)
	}
	var sendAsMailboxID, readOnlyMailboxID int64
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM mailbox_delegates WHERE mailbox_id = ANY($1::bigint[])`,
			[]int64{sendAsMailboxID, readOnlyMailboxID})
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE id = ANY($1::bigint[])`,
			[]int64{sendAsMailboxID, readOnlyMailboxID})
	}()
	for _, mailbox := range []struct {
		email      string
		display    string
		permission string
		id         *int64
	}{
		{email: sendAsEmail, display: "Send As Shared", permission: "send_as", id: &sendAsMailboxID},
		{email: readOnlyEmail, display: "Read Only Shared", permission: "read", id: &readOnlyMailboxID},
	} {
		if err := pool.QueryRow(ctx,
			`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
			 SELECT NULL, m.domain_id, $2, $3, 'personal', FALSE
			   FROM mailboxes m
			  WHERE m.user_id = $1 AND m.is_primary = TRUE
			 RETURNING id`,
			userID, mailbox.email, mailbox.display,
		).Scan(mailbox.id); err != nil {
			t.Fatalf("seed %s mailbox: %v", mailbox.permission, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO mailbox_delegates (mailbox_id, user_id, permission, granted_by)
			 VALUES ($1, $2, $3, $2)`,
			*mailbox.id, userID, mailbox.permission,
		); err != nil {
			t.Fatalf("seed %s delegate: %v", mailbox.permission, err)
		}
	}

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})

	// Simulate an older token or alias-address login. /auth/me must still return
	// the current canonical users.email as the default sender.
	claims := &token.Claims{UserID: userID, Email: alias}
	reqCtx := ContextWithUser(context.Background(), claims)
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil).WithContext(reqCtx)
	rr := httptest.NewRecorder()

	h.Me(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Me: status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var body struct {
		UserID  int64  `json:"user_id"`
		Email   string `json:"email"`
		Aliases []struct {
			Email string `json:"email"`
		} `json:"aliases"`
		Delegates []struct {
			Email      string `json:"email"`
			Permission string `json:"permission"`
		} `json:"delegates"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal /auth/me response: %v", err)
	}
	if body.UserID != userID {
		t.Errorf("/auth/me user_id = %d, want %d (claims.UserID, not a request-supplied value)", body.UserID, userID)
	}
	if body.Email != email {
		t.Errorf("/auth/me email = %q, want canonical primary %q (claim carried %q)", body.Email, email, claims.Email)
	}
	if len(body.Aliases) != 1 || body.Aliases[0].Email != alias {
		t.Errorf("/auth/me aliases = %+v, want exactly %q", body.Aliases, alias)
	}
	if len(body.Delegates) != 1 ||
		body.Delegates[0].Email != sendAsEmail ||
		body.Delegates[0].Permission != "send_as" {
		t.Errorf("/auth/me delegates = %+v, want only send-as %q (not read-only %q)",
			body.Delegates, sendAsEmail, readOnlyEmail)
	}
}

// TestMe_Unauthorized_NoUserID: no auth context -> 401, and (defensively) no
// user_id leaks into an error body.
func TestMe_Unauthorized(t *testing.T) {
	h := newMinimalAuthHandler()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	rr := httptest.NewRecorder()

	h.Me(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Me with no auth context: status = %d, want 401", rr.Code)
	}
}
