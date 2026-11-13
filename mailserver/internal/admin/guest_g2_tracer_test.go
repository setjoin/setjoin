//go:build integration

package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/chat"
	"setjoin.com/shared/toggle"
)

func g2AdminCall(t *testing.T, req *http.Request, fn http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	fn(rr, req)
	return rr
}

func g2ChatCall(t *testing.T, h *chat.Handler, userID int64, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func g2WantSQLState(t *testing.T, err error, code string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code {
		t.Fatalf("SQLSTATE = %v, want %s", err, code)
	}
}

// TestGuestG2Tracer is the lifecycle arc from focused spec §12.3. It composes
// the approved G2a/G2b/G2c lanes; chat_test.TestGuestEventSourceChatFrame owns
// the same release gate's real SSE transport leg without an admin↔jmap import
// cycle.
func TestGuestG2Tracer(t *testing.T) {
	f := newGuestInviteTracerFixture(t)
	var oldChat bool
	if err := f.pool.QueryRow(t.Context(), `SELECT enabled FROM feature_toggles WHERE key=$1`, toggle.FeatureChat).Scan(&oldChat); err != nil {
		t.Fatalf("read chat toggle: %v", err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE feature_toggles SET enabled=TRUE WHERE key=$1`, toggle.FeatureChat); err != nil {
		t.Fatalf("enable chat toggle: %v", err)
	}
	t.Cleanup(func() {
		if _, err := f.pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=$1 WHERE key=$2`, oldChat, toggle.FeatureChat); err != nil {
			t.Errorf("restore chat toggle: %v", err)
		}
	})
	flags := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureGuestAccounts: true,
		toggle.FeatureChat:          true,
	})
	profiles := NewGuestProfilesHandler(f.pool, flags, slog.Default())
	chatHandler := chat.NewHandler(f.pool, flags, slog.Default())
	email := "g2-alice@" + f.externalDomain

	var guestID int64
	t.Run("01_invite_and_activate", func(t *testing.T) {
		rr := f.invite(t, email)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("invite=%d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			GuestUserID int64 `json:"guestUserId"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.GuestUserID == 0 {
			t.Fatalf("decode invite: id=%d err=%v", out.GuestUserID, err)
		}
		guestID = out.GuestUserID
		f.queuedInvite(t, email)
		setTracerTestToken(t, f.pool, guestID, "g2-known-token-first")
		if status := tracerAccept(t, f.pool, "g2-known-token-first", "ValidG2Pw1!", true); status != http.StatusOK {
			t.Fatalf("accept=%d", status)
		}
	})

	var profileID int64
	t.Run("02_profile_assign_entitlement_and_grant_floor", func(t *testing.T) {
		body := fmt.Sprintf(`{"hostDomainId":%d,"name":"G2 collaborator","canPost":true,"historyFromJoin":true,"allowDownload":false,"allowMeetCreate":false,"allowMeetHost":false,"canInitiateDm":false,"allowNativeShell":true,"defaultExpiryDays":null,"apps":["chat"]}`, f.domainID)
		req := f.adminRequest(http.MethodPost, "/admin/guest-profiles", body)
		rr := g2AdminCall(t, req, profiles.Create)
		if rr.Code != http.StatusCreated {
			t.Fatalf("create profile=%d %s", rr.Code, rr.Body.String())
		}
		var profile struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &profile); err != nil || profile.ID == 0 {
			t.Fatalf("decode profile: id=%d err=%v body=%s", profile.ID, err, rr.Body.String())
		}
		profileID = profile.ID

		assign := f.adminRequest(http.MethodPut, fmt.Sprintf("/admin/guests/%d/profile", guestID),
			fmt.Sprintf(`{"profileId":%d}`, profileID))
		assign.SetPathValue("id", fmt.Sprint(guestID))
		if rr := g2AdminCall(t, assign, f.handler.AssignProfile); rr.Code != http.StatusNoContent {
			t.Fatalf("assign profile=%d %s", rr.Code, rr.Body.String())
		}
		var entitlement bool
		if err := f.pool.QueryRow(t.Context(), `SELECT check_user_app_entitlement($1,'chat')`, guestID).Scan(&entitlement); err != nil || !entitlement {
			t.Fatalf("derived Chat entitlement=%v err=%v", entitlement, err)
		}
	})

	var channelID int64
	t.Run("03_grant_floor_and_guest_post", func(t *testing.T) {
		channelID = f.createChannel(t, f.adminID, "G2 tracer channel")
		f.sendMessage(t, f.adminID, channelID, "before guest join", nil)
		add := g2ChatCall(t, chatHandler, f.adminID, http.MethodPost,
			fmt.Sprintf("/chat/channels/%d/members", channelID), fmt.Sprintf(`{"userId":%d}`, guestID))
		if add.Code != http.StatusNoContent {
			t.Fatalf("add guest=%d %s", add.Code, add.Body.String())
		}
		var canPost bool
		var floor, seq int64
		if err := f.pool.QueryRow(t.Context(), `SELECT cm.can_post,cm.history_floor_seq,c.change_seq
			FROM chat_channel_members cm JOIN chat_channels c ON c.id=cm.channel_id
			WHERE cm.channel_id=$1 AND cm.user_id=$2`, channelID, guestID).Scan(&canPost, &floor, &seq); err != nil {
			t.Fatalf("read membership policy: %v", err)
		}
		if !canPost || floor != seq || floor != 1 {
			t.Fatalf("membership can_post=%v floor=%d seq=%d, want true/1/1", canPost, floor, seq)
		}
		post := g2ChatCall(t, chatHandler, guestID, http.MethodPost,
			fmt.Sprintf("/chat/channels/%d/messages", channelID), `{"body":"guest post allowed"}`)
		if post.Code != http.StatusCreated {
			t.Fatalf("guest post=%d %s", post.Code, post.Body.String())
		}
	})

	t.Run("04_live_profile_read_only_bz220", func(t *testing.T) {
		body := fmt.Sprintf(`{"hostDomainId":%d,"name":"G2 collaborator","canPost":false,"historyFromJoin":true,"allowDownload":false,"allowMeetCreate":false,"allowMeetHost":false,"canInitiateDm":false,"allowNativeShell":true,"defaultExpiryDays":null,"apps":["chat"]}`, f.domainID)
		req := f.adminRequest(http.MethodPut, fmt.Sprintf("/admin/guest-profiles/%d", profileID), body)
		req.SetPathValue("id", fmt.Sprint(profileID))
		if rr := g2AdminCall(t, req, profiles.Update); rr.Code != http.StatusOK {
			t.Fatalf("update profile=%d %s", rr.Code, rr.Body.String())
		}
		var canPost bool
		if err := f.pool.QueryRow(t.Context(), `SELECT can_post FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`,
			channelID, guestID).Scan(&canPost); err != nil || canPost {
			t.Fatalf("live can_post=%v err=%v, want false", canPost, err)
		}
		var out []byte
		err := f.pool.QueryRow(t.Context(), `SELECT chat_message_send($1,$2,'blocked by live profile')`, guestID, channelID).Scan(&out)
		g2WantSQLState(t, err, "BZ220")
	})

	t.Run("05_member_post", func(t *testing.T) {
		// This tracer proves the member-side post in the lifecycle arc. The
		// independent TestGuestEventSourceChatFrame owns its own member commit
		// and observes that separate notification through the real transport.
		messageID := f.sendMessage(t, f.adminID, channelID, "member live push", nil)
		if messageID == 0 {
			t.Fatal("member post returned zero message id")
		}
	})

	t.Run("06_expire_retains_and_blocks_then_extend_restores", func(t *testing.T) {
		if _, err := f.pool.Exec(t.Context(), `SELECT guest_set_status($1,$2,'expire')`, f.adminID, guestID); err != nil {
			t.Fatalf("expire guest: %v", err)
		}
		var memberships int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`,
			channelID, guestID).Scan(&memberships); err != nil || memberships != 1 {
			t.Fatalf("expired membership count=%d err=%v, want retained", memberships, err)
		}
		_, err := f.pool.Exec(t.Context(), `SELECT guest_require_active($1)`, guestID)
		g2WantSQLState(t, err, "BZ219")

		expiresAt := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339Nano)
		req := f.adminRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/extend", guestID),
			fmt.Sprintf(`{"expiresAt":%q}`, expiresAt))
		req.SetPathValue("id", fmt.Sprint(guestID))
		if rr := g2AdminCall(t, req, f.handler.Extend); rr.Code != http.StatusNoContent {
			t.Fatalf("extend=%d %s", rr.Code, rr.Body.String())
		}
		if _, err := f.pool.Exec(t.Context(), `SELECT guest_require_active($1)`, guestID); err != nil {
			t.Fatalf("extended guest remains blocked: %v", err)
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM chat_channel_members WHERE channel_id=$1 AND user_id=$2`,
			channelID, guestID).Scan(&memberships); err != nil || memberships != 1 {
			t.Fatalf("extended membership count=%d err=%v, want restored retained grant", memberships, err)
		}
	})

	t.Run("07_disable_enable_clean_and_reinvite_same_identity", func(t *testing.T) {
		disable := f.adminRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/disable", guestID), "")
		disable.SetPathValue("id", fmt.Sprint(guestID))
		if rr := g2AdminCall(t, disable, f.handler.Disable); rr.Code != http.StatusNoContent {
			t.Fatalf("disable=%d %s", rr.Code, rr.Body.String())
		}
		var memberships int
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM chat_channel_members WHERE user_id=$1`, guestID).Scan(&memberships); err != nil || memberships != 0 {
			t.Fatalf("disabled memberships=%d err=%v, want deleted", memberships, err)
		}

		enable := f.adminRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/enable", guestID), "")
		enable.SetPathValue("id", fmt.Sprint(guestID))
		if rr := g2AdminCall(t, enable, f.handler.Enable); rr.Code != http.StatusNoContent {
			t.Fatalf("enable=%d %s", rr.Code, rr.Body.String())
		}
		if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM chat_channel_members WHERE user_id=$1`, guestID).Scan(&memberships); err != nil || memberships != 0 {
			t.Fatalf("enabled memberships=%d err=%v, want clean slate", memberships, err)
		}

		rr := f.invite(t, email)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("reinvite=%d %s", rr.Code, rr.Body.String())
		}
		var out struct {
			GuestUserID int64 `json:"guestUserId"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.GuestUserID != guestID {
			t.Fatalf("reinvite guest id=%d err=%v, want preserved %d", out.GuestUserID, err, guestID)
		}
	})
}
