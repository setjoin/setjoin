package drive

// Chat A2 Task 5, Grill D3 — deleting a chat message revokes MEMBER access to
// its attachment via the /drive content route (a saved "Open in Drive"
// deep-link 404s), while the bytes+row are retained for A4 eDiscovery
// (deleted-for-members != purged, the A1 body-retention posture). Skip-if-
// no-DB, the memberscope_live_test.go genre — real reducers (including the
// chat_* ones, called directly by SQL; no import of internal/chat needed,
// they're just functions in the same test database), fake object store.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestContentRoute_ChatAttachment_DeletedMessageRevokesAccess_Live(t *testing.T) {
	pool := driveLivePool(t)
	ctx := context.Background()
	withFeatureToggleEnabled(t, pool, "feature.drive") // chat_message_send's own BZ173 reducer-defense check

	author := driveLiveUser(t, pool, "d3author")
	member := driveLiveUser(t, pool, "d3member")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, author, "d3-attach-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_channel_join($1, $2)`, member, channelID); err != nil {
		t.Fatalf("chat_channel_join: %v", err)
	}

	// Lazily provision the channel's Drive space and upload one real chunk
	// through the actual chunk rail (fakeStore) — the same anti-oracle path
	// a real attachment send uses, not a bypassed fixture.
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, author, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	data := []byte("d3 chat attachment bytes")
	sha := driveLiveUploadChunk(t, h, author, spaceID, data)

	attachments, _ := json.Marshal([]map[string]any{{
		"sha256":      sha,
		"size":        len(data),
		"name":        "d3.txt",
		"contentType": "text/plain",
		"manifest":    []map[string]any{{"sha256": sha, "size": len(data)}},
	}})
	var sendOut []byte
	if err := pool.QueryRow(ctx, `SELECT chat_message_send($1, $2, $3, NULL, '{}'::bigint[], NULL, $4)`,
		author, channelID, "see attached", string(attachments)).Scan(&sendOut); err != nil {
		t.Fatalf("chat_message_send with attachment: %v", err)
	}
	var sent struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(sendOut, &sent); err != nil {
		t.Fatalf("decode send: %v", err)
	}

	var versionID int64
	if err := pool.QueryRow(ctx, `SELECT version_id FROM chat_message_attachments WHERE message_id = $1`, sent.MessageID).Scan(&versionID); err != nil {
		t.Fatalf("resolve version_id: %v", err)
	}

	getContent := func(userID int64) int {
		req := httptest.NewRequest(http.MethodGet, "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/content", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	if code := getContent(member); code != http.StatusOK {
		t.Fatalf("member content GET before delete: want 200, got %d", code)
	}

	if _, err := pool.Exec(ctx, `SELECT chat_message_delete($1, $2)`, author, sent.MessageID); err != nil {
		t.Fatalf("chat_message_delete: %v", err)
	}

	if code := getContent(member); code != http.StatusNotFound {
		t.Errorf("member content GET after the message is soft-deleted: want 404 (D3 revokes access), got %d", code)
	}

	// Bytes+row are RETAINED (A4 eDiscovery posture) — the worker/BYPASSRLS
	// pool (this test's own `pool`, standing in for the eDiscovery reader)
	// still finds the version and the attachment link row untouched.
	var stillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM chat_message_attachments WHERE message_id = $1`, sent.MessageID).Scan(&stillThere); err != nil {
		t.Fatalf("count attachment rows: %v", err)
	}
	if stillThere != 1 {
		t.Errorf("attachment link row must be RETAINED after message soft-delete (eDiscovery), got count=%d", stillThere)
	}
	var versionStillThere int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM drive_file_versions WHERE id = $1`, versionID).Scan(&versionStillThere); err != nil {
		t.Fatalf("count version rows: %v", err)
	}
	if versionStillThere != 1 {
		t.Errorf("the drive_file_versions row must be RETAINED after message soft-delete (eDiscovery), got count=%d", versionStillThere)
	}
}

// TestGuestChatAttachmentHistoryFloor_Live is Guest G2's deterministic
// remembered-ID proof for all three allowlisted Drive attachment doors. A guest
// cannot probe chunk possession, resolve metadata, or stream bytes for an attachment from before its
// join floor; removal/re-add establishes a fresh floor that also revokes an
// attachment the same identity could read during its prior membership.
func TestGuestChatAttachmentHistoryFloor_Live(t *testing.T) {
	pool := driveLivePool(t)
	ctx := context.Background()
	withFeatureToggleEnabled(t, pool, "feature.drive")
	withFeatureToggleEnabled(t, pool, "feature.guest_accounts")

	author := driveLiveUser(t, pool, "g2attachauthor")
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	var guestID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO users(username, domain_id, email, display_name, enabled)
		SELECT $1, d.id, $2, 'G2 Attachment Guest', TRUE
		  FROM domains d WHERE d.name='guest.invalid'
		RETURNING id`, "g2attachguest-"+suffix, "g2attachguest-"+suffix+"@external.example").Scan(&guestID); err != nil {
		t.Fatalf("create mailboxless guest user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO guest_accounts
		       (user_id, invited_email, invited_by, invited_by_email, host_domain_id, status, expires_at)
		SELECT $1, u.email, $2, inviter.email, inviter.domain_id, 'active', now()+interval '1 day'
		  FROM users u CROSS JOIN users inviter
		 WHERE u.id=$1 AND inviter.id=$2`, guestID, author); err != nil {
		t.Fatalf("create guest satellite: %v", err)
	}
	// This test isolates the history-floor oracle. G4 independently denies raw
	// bytes to a view-only/missing-profile guest, so grant this fixture the
	// positive download posture needed to reach the later liveness predicate.
	var profileID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO guest_profiles(host_domain_id,name,allow_download,apps)
		SELECT u.domain_id,$2,TRUE,ARRAY['chat','drive']::text[] FROM users u WHERE u.id=$1
		RETURNING id`, author, "g2-attach-download-"+suffix).Scan(&profileID); err != nil {
		t.Fatalf("create download-enabled guest profile: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE guest_accounts SET profile_id=$2 WHERE user_id=$1`, guestID, profileID); err != nil {
		t.Fatalf("assign guest download profile: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_app_entitlements(user_id,app,enabled)
		VALUES ($1,'drive',TRUE)
		ON CONFLICT (user_id,app) DO UPDATE SET enabled=EXCLUDED.enabled`, guestID); err != nil {
		t.Fatalf("enable guest Drive entitlement: %v", err)
	}

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1,$2)`, author, "g2-attach-history-"+suffix).Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1,$2)`, author, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	data := []byte("g2 immutable attachment history")
	sha := driveLiveUploadChunk(t, h, author, spaceID, data)
	attachments, _ := json.Marshal([]map[string]any{{
		"sha256": sha, "size": len(data), "name": "history.txt", "contentType": "text/plain",
		"manifest": []map[string]any{{"sha256": sha, "size": len(data)}},
	}})

	type attachmentIDs struct{ node, version int64 }
	sendAttachment := func(label string) attachmentIDs {
		t.Helper()
		var out []byte
		if err := pool.QueryRow(ctx,
			`SELECT chat_message_send($1,$2,$3,NULL,'{}'::bigint[],NULL,$4)`,
			author, channelID, label, string(attachments)).Scan(&out); err != nil {
			t.Fatalf("send attachment %q: %v", label, err)
		}
		var sent struct {
			MessageID int64 `json:"messageId"`
		}
		if err := json.Unmarshal(out, &sent); err != nil {
			t.Fatalf("decode send %q: %v", label, err)
		}
		var ids attachmentIDs
		if err := pool.QueryRow(ctx,
			`SELECT file_node_id, version_id FROM chat_message_attachments WHERE message_id=$1`,
			sent.MessageID).Scan(&ids.node, &ids.version); err != nil {
			t.Fatalf("resolve attachment %q: %v", label, err)
		}
		return ids
	}
	contentStatus := func(ids attachmentIDs) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet,
			"/drive/versions/"+strconv.FormatInt(ids.version, 10)+"/content", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: guestID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	headStatus := func() int {
		t.Helper()
		req := httptest.NewRequest(http.MethodHead,
			"/drive/chunks/"+sha+"?space="+strconv.FormatInt(spaceID, 10), nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: guestID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	metaCount := func(ids ...attachmentIDs) int {
		t.Helper()
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, strconv.FormatInt(id.node, 10))
		}
		rr := driveNodesMetaGet(t, h, guestID, strings.Join(parts, ","))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET attachment metadata: want 200, got %d: %s", rr.Code, rr.Body.String())
		}
		var rows []nodeMetaRow
		if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
			t.Fatalf("decode attachment metadata: %v", err)
		}
		return len(rows)
	}

	beforeJoin := sendAttachment("before guest join")
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, author, channelID, guestID); err != nil {
		t.Fatalf("first guest add: %v", err)
	}
	if got := contentStatus(beforeJoin); got != http.StatusNotFound {
		t.Fatalf("pre-floor content status=%d, want 404", got)
	}
	if got := metaCount(beforeJoin); got != 0 {
		t.Fatalf("pre-floor metadata rows=%d, want 0", got)
	}
	if got := headStatus(); got != http.StatusNotFound {
		t.Fatalf("pre-floor remembered chunk HEAD status=%d, want 404", got)
	}

	firstMembership := sendAttachment("visible in first membership")
	if got := contentStatus(firstMembership); got != http.StatusOK {
		t.Fatalf("post-floor content status=%d, want 200", got)
	}
	if got := metaCount(firstMembership); got != 1 {
		t.Fatalf("post-floor metadata rows=%d, want 1", got)
	}
	if got := headStatus(); got != http.StatusOK {
		t.Fatalf("post-floor chunk HEAD status=%d, want 200", got)
	}

	if _, err := pool.Exec(ctx, `SELECT chat_member_remove($1,$2,$3)`, author, channelID, guestID); err != nil {
		t.Fatalf("guest remove: %v", err)
	}
	_ = sendAttachment("re-add floor barrier")
	if _, err := pool.Exec(ctx, `SELECT chat_member_add($1,$2,$3)`, author, channelID, guestID); err != nil {
		t.Fatalf("guest re-add: %v", err)
	}
	if got := contentStatus(firstMembership); got != http.StatusNotFound {
		t.Fatalf("remembered content after re-add status=%d, want 404", got)
	}
	if got := headStatus(); got != http.StatusNotFound {
		t.Fatalf("remembered chunk HEAD after re-add status=%d, want 404", got)
	}

	secondMembership := sendAttachment("visible in second membership")
	if got := contentStatus(secondMembership); got != http.StatusOK {
		t.Fatalf("second-membership content status=%d, want 200", got)
	}
	if got := headStatus(); got != http.StatusOK {
		t.Fatalf("second-membership chunk HEAD status=%d, want 200", got)
	}
	if got := metaCount(beforeJoin, firstMembership, secondMembership); got != 1 {
		t.Fatalf("mixed remembered metadata rows=%d, want only newest row", got)
	}
}
