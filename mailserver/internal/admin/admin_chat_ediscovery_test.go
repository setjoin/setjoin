package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// ── fixtures ─────────────────────────────────────────────────────────────────
// ccEnableToggle/ccCreateChannel/ccAddMember/ccManageClaims/ccViewClaims/
// ccStrPtr/ssCreateUser are shared from admin_chat_compliance_test.go and
// admin_scope_sets_test.go (same package) — reused verbatim, not redefined.

// edCreateCase inserts a bare ediscovery_cases row and registers cleanup.
func edCreateCase(t *testing.T, pool *pgxpool.Pool, name, status string, createdBy int64) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO ediscovery_cases (name, status, created_by) VALUES ($1, $2, $3) RETURNING id`,
		name, status, createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("edCreateCase: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM ediscovery_cases WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

func newChatEDiscoveryHandlerForTest(t *testing.T) (*ChatEDiscoveryHandler, *pgxpool.Pool, *toggle.FeatureFlags) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	flags := ccEnableToggle(t, pool)
	// workerPool aliases pool in this test — DB_WORKER_DSN is unset/inert
	// (Global Constraints), the exact production posture.
	return NewChatEDiscoveryHandler(pool, pool, flags, testsupport.TestLogger(), nil, ""), pool, flags
}

// ── toggle gate ──────────────────────────────────────────────────────────────

// TestChatEDiscovery_ToggleOff404 proves every A4b holds/cases route 404s
// when feature.chat_compliance is OFF, regardless of permission held — the
// ship-posture rail (Global Constraints: A4b makes the toggle shippable, it
// does not flip it).
func TestChatEDiscovery_ToggleOff404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	offFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureChatCompliance: false})
	h := NewChatEDiscoveryHandler(pool, pool, offFlags, testsupport.TestLogger(), nil, "")
	actorID := ssCreateUser(t, pool)
	claims := ccManageClaims(actorID)

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
		idParam string
	}{
		{"SetCaseHold", "POST", "/admin/chat-ediscovery/holds", `{"caseId":1,"channelId":1,"reason":"x"}`, h.SetCaseHold, ""},
		{"ReleaseCaseHold", "POST", "/admin/chat-ediscovery/holds/1/release", `{"reason":"x"}`, h.ReleaseCaseHold, "1"},
		{"ListCaseHolds", "GET", "/admin/chat-ediscovery/holds?caseId=1", "", h.ListCaseHolds, ""},
		{"ListCases", "GET", "/admin/chat-ediscovery/cases", "", h.ListCases, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
			if tc.idParam != "" {
				req.SetPathValue("id", tc.idParam)
			}
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Errorf("%s: want 404 with toggle OFF, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// ── perm split ───────────────────────────────────────────────────────────────

// TestChatEDiscoveryHolds_ViewCannotManage proves view-perm can list
// cases/holds but not set/release a hold.
func TestChatEDiscoveryHolds_ViewCannotManage(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)

	req := httptest.NewRequest("GET", "/admin/chat-ediscovery/cases", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.ListCases(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ListCases with view perm: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
		idParam string
	}{
		{"SetCaseHold", "POST", "/admin/chat-ediscovery/holds", `{"caseId":1,"channelId":1,"reason":"x"}`, h.SetCaseHold, ""},
		{"ReleaseCaseHold", "POST", "/admin/chat-ediscovery/holds/1/release", `{"reason":"x"}`, h.ReleaseCaseHold, "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
			if tc.idParam != "" {
				req.SetPathValue("id", tc.idParam)
			}
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s with view-only perm: want 403, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

// ── ListCaseHolds requires caseId ───────────────────────────────────────────

func TestChatEDiscoveryListCaseHolds_RequiresCaseID(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	req := httptest.NewRequest("GET", "/admin/chat-ediscovery/holds", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.ListCaseHolds(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("ListCaseHolds without caseId: want 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── happy path: set, list, release, re-release ──────────────────────────────

// TestChatEDiscoverySetCaseHold_CustodianHappyPathAndRelease proves the full
// custodian-hold lifecycle through the admin surface: 201 with a coverage
// row, the GET list projection, 204 release stamping released_at, and a
// second release cleanly 422ing (BZ197 through mapErr — resolved ambiguity
// 1: no duplicate act, no state change; asserted at the reducer layer in
// chat_case_holds.pg, here only the HTTP-layer idempotence-of-rejection).
func TestChatEDiscoverySetCaseHold_CustodianHappyPathAndRelease(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	adminID := ssCreateUser(t, pool)
	custodian := ssCreateUser(t, pool)
	manager := ccManageClaims(adminID)

	// Custodian hold is OU-scoped on the target (admin_can_reach); grant the
	// admin the unscoped Super Admin group (id 1, domain_scope NULL) so it
	// reaches the custodian — the org-wide-compliance-officer case (the A4a
	// custodian-hold fixture, verbatim).
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id) VALUES ($1, 1)`, adminID); err != nil {
		t.Fatalf("grant admin reach: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `
			UPDATE admin_role_assignments
			   SET expires_at = statement_timestamp() - interval '1 second'
			 WHERE user_id = $1 AND role_group_id = 1`, adminID)
		_, _ = pool.Exec(ctx,
			`DELETE FROM admin_role_assignments WHERE user_id = $1`, adminID)
	})

	caseID := edCreateCase(t, pool, "case-happy", "active", adminID)
	chanA := ccCreateChannel(t, pool, "channel", ccStrPtr("ediscovery-a"), adminID)
	ccAddMember(t, pool, chanA, custodian)

	body := fmt.Sprintf(`{"caseId":%d,"custodianUserId":%d,"reason":"case-happy-reason"}`, caseID, custodian)
	req := httptest.NewRequest("POST", "/admin/chat-ediscovery/holds", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.SetCaseHold(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("SetCaseHold: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		HoldID int64 `json:"holdId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode SetCaseHold response: %v", err)
	}
	if created.HoldID == 0 {
		t.Fatal("SetCaseHold: expected a non-zero holdId")
	}

	var coverage int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM chat_case_hold_channels WHERE hold_id = $1`, created.HoldID).Scan(&coverage); err != nil {
		t.Fatalf("coverage count: %v", err)
	}
	if coverage != 1 {
		t.Errorf("coverage: want 1 channel, got %d", coverage)
	}

	// GET list filters by caseId and projects the wire shape.
	listReq := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-ediscovery/holds?caseId=%d", caseID), nil)
	listReq = listReq.WithContext(auth.ContextWithUser(listReq.Context(), manager))
	listRec := httptest.NewRecorder()
	h.ListCaseHolds(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("ListCaseHolds: want 200, got %d (body=%s)", listRec.Code, listRec.Body.String())
	}
	var rows []caseHoldRow
	if err := json.Unmarshal(listRec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode ListCaseHolds response: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("ListCaseHolds: want 1 row, got %d", len(rows))
	}
	if rows[0].ID != created.HoldID || rows[0].CaseID != caseID ||
		rows[0].CustodianUserID == nil || *rows[0].CustodianUserID != custodian ||
		rows[0].Reason != "case-happy-reason" || rows[0].CreatedBy != adminID ||
		rows[0].ReleasedAt != nil || rows[0].Channels != 1 {
		t.Errorf("ListCaseHolds row projection mismatch: %+v", rows[0])
	}

	// release -> 204 and the hold row stamped.
	relReq := httptest.NewRequest("POST", fmt.Sprintf("/admin/chat-ediscovery/holds/%d/release", created.HoldID),
		strings.NewReader(`{"reason":"matter closed"}`))
	relReq = relReq.WithContext(auth.ContextWithUser(relReq.Context(), manager))
	relReq.SetPathValue("id", strconv.FormatInt(created.HoldID, 10))
	relRec := httptest.NewRecorder()
	h.ReleaseCaseHold(relRec, relReq)
	if relRec.Code != http.StatusNoContent {
		t.Fatalf("ReleaseCaseHold: want 204, got %d (body=%s)", relRec.Code, relRec.Body.String())
	}
	var releasedAt *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT released_at FROM chat_case_holds WHERE id = $1`, created.HoldID).Scan(&releasedAt); err != nil {
		t.Fatalf("released_at lookup: %v", err)
	}
	if releasedAt == nil {
		t.Error("ReleaseCaseHold: released_at was not stamped")
	}

	// releasing again -> 422 (BZ197 through mapErr).
	relReq2 := httptest.NewRequest("POST", fmt.Sprintf("/admin/chat-ediscovery/holds/%d/release", created.HoldID),
		strings.NewReader(`{"reason":"already released"}`))
	relReq2 = relReq2.WithContext(auth.ContextWithUser(relReq2.Context(), manager))
	relReq2.SetPathValue("id", strconv.FormatInt(created.HoldID, 10))
	relRec2 := httptest.NewRecorder()
	h.ReleaseCaseHold(relRec2, relReq2)
	if relRec2.Code != http.StatusUnprocessableEntity {
		t.Errorf("second release: want 422, got %d (body=%s)", relRec2.Code, relRec2.Body.String())
	}
}

// ── errors ───────────────────────────────────────────────────────────────────

// TestChatEDiscoverySetCaseHold_ClosedCase409 proves a hold against a closed
// case raises BZ198 -> 409 through mapErr.
func TestChatEDiscoverySetCaseHold_ClosedCase409(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	adminID := ssCreateUser(t, pool)
	manager := ccManageClaims(adminID)
	caseID := edCreateCase(t, pool, "case-closed", "closed", adminID)
	chanA := ccCreateChannel(t, pool, "channel", ccStrPtr("ediscovery-closed"), adminID)

	body := fmt.Sprintf(`{"caseId":%d,"channelId":%d,"reason":"x"}`, caseID, chanA)
	req := httptest.NewRequest("POST", "/admin/chat-ediscovery/holds", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.SetCaseHold(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("SetCaseHold on a closed case: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestChatEDiscoverySetCaseHold_OutsideReach403 proves a domain-scoped admin
// (here: an admin with NO admin_role_assignments row at all, so
// admin_can_reach is false for every target) cannot place a custodian hold
// on a user outside their administrative scope — the A4a custodian-hold fix
// (commit 6267355c) replicated per spec §9.
func TestChatEDiscoverySetCaseHold_OutsideReach403(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	adminID := ssCreateUser(t, pool)
	custodian := ssCreateUser(t, pool)
	manager := ccManageClaims(adminID)
	caseID := edCreateCase(t, pool, "case-reach", "active", adminID)

	body := fmt.Sprintf(`{"caseId":%d,"custodianUserId":%d,"reason":"x"}`, caseID, custodian)
	req := httptest.NewRequest("POST", "/admin/chat-ediscovery/holds", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.SetCaseHold(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("SetCaseHold on a custodian outside reach: want 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ══════════════════════════════════════════════════════════════════════════
// Task 6 — search + reader routes (chat.ediscovery-gated)
// ══════════════════════════════════════════════════════════════════════════

// edEDiscoveryClaims returns claims holding chat.ediscovery only.
func edEDiscoveryClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, IsAdmin: true, Permissions: []string{permissions.PermChatEDiscovery}}
}

// edCreateChannelReducer creates a real chat channel via chat_channel_create
// (not the raw-INSERT ccCreateChannel — chat_message_send needs the
// reducer's own owner-membership row).
func edCreateChannelReducer(t *testing.T, pool *pgxpool.Pool, userID int64, name string) int64 {
	t.Helper()
	var id int64
	if err := pool.QueryRow(context.Background(),
		`SELECT chat_channel_create($1, $2)`, userID, name).Scan(&id); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM chat_channels WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// edSendMessage sends a plain-body message via chat_message_send and
// returns its messageId.
func edSendMessage(t *testing.T, pool *pgxpool.Pool, userID, channelID int64, body string) int64 {
	t.Helper()
	var raw []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT chat_message_send($1, $2, $3)`, userID, channelID, body).Scan(&raw); err != nil {
		t.Fatalf("chat_message_send: %v", err)
	}
	var msg struct {
		MessageID int64 `json:"messageId"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("decode chat_message_send: %v", err)
	}
	return msg.MessageID
}

// containsStr reports whether items (a decoded []any of strings) contains want.
func containsStr(items []any, want string) bool {
	for _, it := range items {
		if s, ok := it.(string); ok && s == want {
			return true
		}
	}
	return false
}

// edSearchFixture builds the Task-3 fixture shapes (chat_ediscovery_search.pg's
// own fixture, replicated at the Go/HTTP-route layer — spec §14 "Reader (Go
// httptest, real reducers)") via direct reducer calls, all in one channel
// the eDiscovery officer is NOT a member of (DES-008): a live body, an
// edited-away body (revision), a soft-deleted body, a failed scheduled
// chat_send row, a filename-bearing attachment, and a Han-substring message
// (the trgm-routing leg).
func edSearchFixture(t *testing.T, pool *pgxpool.Pool) (caseID, channelID int64) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.drive'`); err != nil {
		t.Fatalf("enable feature.drive: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.drive'`) //nolint:errcheck
	})

	author := ssCreateUser(t, pool)
	adminID := ssCreateUser(t, pool)
	caseID = edCreateCase(t, pool, "search-happy", "active", adminID)
	channelID = edCreateChannelReducer(t, pool, author, "ediscovery-happy")

	// (a) live body leg.
	edSendMessage(t, pool, author, channelID, "the quarterly forecast update is ready")

	// (b) revision leg: sent, then edited away — the hit must land on the
	// PARENT message id, matchedIn 'revision'.
	insiderID := edSendMessage(t, pool, author, channelID, "insider price target guidance leaked")
	if _, err := pool.Exec(ctx, `SELECT chat_message_edit($1, $2, $3)`, author, insiderID, "no comment on that"); err != nil {
		t.Fatalf("chat_message_edit: %v", err)
	}

	// (c) soft-deleted leg: retained body, deleted true.
	shredID := edSendMessage(t, pool, author, channelID, "shred the memo before the audit")
	if _, err := pool.Exec(ctx, `SELECT chat_message_delete($1, $2)`, author, shredID); err != nil {
		t.Fatalf("chat_message_delete: %v", err)
	}

	// (d) scheduled chat_send leg, flipped to failed (contract #7: pending
	// AND failed are both in scope).
	var schedID string
	if err := pool.QueryRow(ctx,
		`SELECT chat_schedule_message($1, $2, $3, NULL, '{}'::bigint[], NULL, now() + interval '1 hour')`,
		author, channelID, "the delayed bombshell announcement is queued").Scan(&schedID); err != nil {
		t.Fatalf("chat_schedule_message: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scheduled_actions SET status = 'failed' WHERE id = $1::uuid`, schedID); err != nil {
		t.Fatalf("fail scheduled action: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM scheduled_actions WHERE id = $1::uuid`, schedID) //nolint:errcheck
	})

	// (e) attachment filename leg (the chat_ediscovery_search.pg att fixture
	// shape, verbatim).
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, author, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}
	sha := strings.Repeat("9", 64)
	if _, err := pool.Exec(ctx, `SELECT drive_chunk_register($1, $2, $3, 4)`, author, spaceID, sha); err != nil {
		t.Fatalf("drive_chunk_register: %v", err)
	}
	attJSON := fmt.Sprintf(`[{"sha256":%q,"size":4,"name":"Q3-restatement-draft.xlsx","manifest":[{"sha256":%q,"size":4}]}]`, sha, sha)
	if _, err := pool.Exec(ctx, `SELECT chat_message_send($1,$2,$3,NULL,'{}'::bigint[],NULL,$4)`,
		author, channelID, "", attJSON); err != nil {
		t.Fatalf("chat_message_send (attachment): %v", err)
	}

	// (f) Han-substring fixture — the 'simple' tsquery leg cannot tokenize
	// a Han run; only the trgm leg finds it.
	edSendMessage(t, pool, author, channelID, "会议记录已经发送")

	return caseID, channelID
}

// TestChatEDiscoverySearchRead_ToggleOff404 proves both Task 6 routes 404
// with feature.chat_compliance OFF, regardless of permission held (Global
// Constraints: A4b makes the toggle shippable, it does not flip it).
func TestChatEDiscoverySearchRead_ToggleOff404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	offFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureChatCompliance: false})
	h := NewChatEDiscoveryHandler(pool, pool, offFlags, testsupport.TestLogger(), nil, "")
	actorID := ssCreateUser(t, pool)
	claims := edEDiscoveryClaims(actorID)

	req := httptest.NewRequest("POST", "/admin/chat-ediscovery/search", strings.NewReader(`{"caseId":1,"terms":"x"}`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Search(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("Search: want 404 with toggle OFF, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest("GET", "/admin/chat-ediscovery/channels/1/messages?caseId=1", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	req2.SetPathValue("id", "1")
	rec2 := httptest.NewRecorder()
	h.ReadMessages(rec2, req2)
	if rec2.Code != http.StatusNotFound {
		t.Errorf("ReadMessages: want 404 with toggle OFF, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

// TestChatEDiscoverySearchRead_ManageCannotEDiscovery403 is the D-A SoD
// proof: a caller holding chat.compliance_manage (authority to destroy —
// purge/hold) but NOT chat.ediscovery is forbidden from reading chat
// content through either Task 6 route. "May destroy" does not grant "may
// read" the most privileged read in the product.
func TestChatEDiscoverySearchRead_ManageCannotEDiscovery403(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	req := httptest.NewRequest("POST", "/admin/chat-ediscovery/search", strings.NewReader(`{"caseId":1,"terms":"x"}`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.Search(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("Search with manage-only claims: want 403, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req2 := httptest.NewRequest("GET", "/admin/chat-ediscovery/channels/1/messages?caseId=1", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), manager))
	req2.SetPathValue("id", "1")
	rec2 := httptest.NewRecorder()
	h.ReadMessages(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("ReadMessages with manage-only claims: want 403, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

// TestChatEDiscoverySearch_FourContentLegsAndChainValid proves the Task-6
// Search route against real reducers: the soft-deleted body, the revision,
// the failed scheduled row, and the filename all surface as hits, a
// Han-rune query routes to trgm at the ROUTE (chat.HasHanRune, review F10),
// and the channel's audit chain stays all-valid with a search.run act on it
// afterward (spec §14 "Reader (Go httptest, real reducers)").
func TestChatEDiscoverySearch_FourContentLegsAndChainValid(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	caseID, channelID := edSearchFixture(t, pool)
	officer := ssCreateUser(t, pool)
	claims := edEDiscoveryClaims(officer)

	search := func(terms string) map[string]any {
		body := fmt.Sprintf(`{"caseId":%d,"terms":%q,"channelIds":[%d]}`, caseID, terms, channelID)
		req := httptest.NewRequest("POST", "/admin/chat-ediscovery/search", strings.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.Search(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("Search(%q): want 200, got %d (body=%s)", terms, rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode Search(%q) response: %v", terms, err)
		}
		return out
	}

	// soft-deleted body leg.
	shredResult := search("shred")
	hits, _ := shredResult["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("search 'shred': want 1 hit, got %d (%v)", len(hits), shredResult)
	}
	if deleted, _ := hits[0].(map[string]any)["deleted"].(bool); !deleted {
		t.Errorf("search 'shred': want deleted=true, got %v", hits[0])
	}

	// revision leg.
	insiderResult := search("insider")
	hits, _ = insiderResult["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("search 'insider': want 1 hit, got %d", len(hits))
	}
	matchedIn, _ := hits[0].(map[string]any)["matchedIn"].([]any)
	if !containsStr(matchedIn, "revision") {
		t.Errorf("search 'insider': matchedIn = %v, want to contain 'revision'", matchedIn)
	}

	// scheduled (failed) leg — zero live hits, one scheduledHits element.
	bombshellResult := search("bombshell")
	hits, _ = bombshellResult["hits"].([]any)
	sched, _ := bombshellResult["scheduledHits"].([]any)
	if len(hits) != 0 || len(sched) != 1 {
		t.Fatalf("search 'bombshell': want 0 hits/1 scheduledHits, got %d/%d", len(hits), len(sched))
	}
	schedRow, _ := sched[0].(map[string]any)
	if status, _ := schedRow["status"].(string); status != "failed" {
		t.Errorf("scheduled hit status = %q, want 'failed'", status)
	}
	// scheduledActionId must decode as a STRING (scheduled_actions.id is a
	// uuid, not a bigint — review F4), never a JSON number.
	if sid, ok := schedRow["scheduledActionId"].(string); !ok || sid == "" {
		t.Errorf("scheduledActionId must be a non-empty string (uuid, review F4): got %#v", schedRow["scheduledActionId"])
	}

	// filename leg.
	restatementResult := search("restatement")
	hits, _ = restatementResult["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("search 'restatement': want 1 hit, got %d", len(hits))
	}
	matchedIn, _ = hits[0].(map[string]any)["matchedIn"].([]any)
	if !containsStr(matchedIn, "filename") {
		t.Errorf("search 'restatement': matchedIn = %v, want to contain 'filename'", matchedIn)
	}

	// HasHanRune routing proven AT THE ROUTE: a Han-only query the 'simple'
	// tsquery leg cannot tokenize still finds the fixture message via trgm.
	hanResult := search("会议记录")
	hits, _ = hanResult["hits"].([]any)
	if len(hits) != 1 {
		t.Fatalf("Han-rune search: want 1 hit (trgm routing at the route), got %d", len(hits))
	}

	// the channel's audit chain stays all-valid after every search.run act
	// write, and at least one search.run act exists on it (§14).
	var allValid bool
	if err := pool.QueryRow(context.Background(),
		`SELECT bool_and(valid) FROM verify_chat_audit_chain($1)`, channelID).Scan(&allValid); err != nil {
		t.Fatalf("verify_chat_audit_chain: %v", err)
	}
	if !allValid {
		t.Error("chat_audit_log chain is not all-valid after the search.run acts")
	}
	var searchActCount int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM chat_audit_log WHERE channel_id = $1 AND action = 'search.run'`, channelID).Scan(&searchActCount); err != nil {
		t.Fatalf("count search.run acts: %v", err)
	}
	if searchActCount == 0 {
		t.Error("expected at least one search.run act on the channel's chain")
	}
}

// TestChatEDiscoveryReadMessages_PurgeProvenance proves the Task-6
// ReadMessages route carries lastPurgedSeq + purgeActs through to the wire
// (L8 record-floor data) against the read window's purge-provenance
// fixture, and returns the still-live message.
func TestChatEDiscoveryReadMessages_PurgeProvenance(t *testing.T) {
	h, pool, _ := newChatEDiscoveryHandlerForTest(t)
	ctx := context.Background()
	author := ssCreateUser(t, pool)
	adminID := ssCreateUser(t, pool)
	caseID := edCreateCase(t, pool, "read-happy", "active", adminID)
	channelID := edCreateChannelReducer(t, pool, author, "ediscovery-read-happy")
	edSendMessage(t, pool, author, channelID, "still-live message")

	if _, err := pool.Exec(ctx, `UPDATE chat_channels SET last_purged_seq = 7 WHERE id = $1`, channelID); err != nil {
		t.Fatalf("stamp last_purged_seq: %v", err)
	}
	// simulated purge provenance (cheaper than a real sweep — the act
	// shape is V126's own, per the chat_ediscovery_read.pg fixture).
	if _, err := pool.Exec(ctx,
		`SELECT chat_access_audit(NULL, $1, 'purge.execute', 'channel', $1, NULL,
		   '{"purgedCount":3,"idFrom":1,"idTo":3,"seqMax":7,"retentionDays":30,"source":"retention"}'::jsonb, NULL, NULL)`,
		channelID); err != nil {
		t.Fatalf("simulate purge.execute act: %v", err)
	}

	officer := ssCreateUser(t, pool)
	claims := edEDiscoveryClaims(officer)
	req := httptest.NewRequest("GET",
		fmt.Sprintf("/admin/chat-ediscovery/channels/%d/messages?caseId=%d", channelID, caseID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.ReadMessages(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ReadMessages: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		ChannelID     int64            `json:"channelId"`
		LastPurgedSeq int64            `json:"lastPurgedSeq"`
		PurgeActs     []map[string]any `json:"purgeActs"`
		Messages      []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode ReadMessages response: %v", err)
	}
	if out.ChannelID != channelID {
		t.Errorf("channelId = %d, want %d", out.ChannelID, channelID)
	}
	if out.LastPurgedSeq != 7 {
		t.Errorf("lastPurgedSeq = %d, want 7", out.LastPurgedSeq)
	}
	if len(out.PurgeActs) != 1 {
		t.Fatalf("purgeActs: want 1, got %d (%v)", len(out.PurgeActs), out.PurgeActs)
	}
	if len(out.Messages) != 1 {
		t.Errorf("messages: want 1 (the still-live message), got %d", len(out.Messages))
	}
}
