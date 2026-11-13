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

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

// ccEnableToggle flips feature.chat_compliance ON in the DB for the test's
// duration (purge_integration_test.go's inline-flip pattern, verbatim) and
// returns a *toggle.FeatureFlags reporting it enabled (the Go-side gate the
// handler checks — kept static so the test is not racing toggle.New's DB
// poll).
func ccEnableToggle(t *testing.T, pool *pgxpool.Pool) *toggle.FeatureFlags {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled = TRUE WHERE key = 'feature.chat_compliance'`); err != nil {
		t.Fatalf("enable feature.chat_compliance: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled = FALSE WHERE key = 'feature.chat_compliance'`) //nolint:errcheck
	})
	return toggle.NewTestFlags(map[string]bool{toggle.FeatureChatCompliance: true})
}

// ccCreateChannel inserts a bare chat_channels row (kind/name/created_by —
// the V119 NOT NULLs) and registers cleanup.
func ccCreateChannel(t *testing.T, pool *pgxpool.Pool, kind string, name *string, createdBy int64) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_channels (kind, name, created_by) VALUES ($1, $2, $3) RETURNING id`,
		kind, name, createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("ccCreateChannel: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM chat_channels WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

func ccAddMember(t *testing.T, pool *pgxpool.Pool, channelID, userID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO chat_channel_members (channel_id, user_id) VALUES ($1, $2)`, channelID, userID); err != nil {
		t.Fatalf("ccAddMember: %v", err)
	}
}

func ccCreatePolicy(t *testing.T, pool *pgxpool.Pool, name, appliesTo string, durationDays int, enabled bool) int64 {
	t.Helper()
	var id int64
	err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_retention_policies (name, applies_to, duration_days, enabled)
		 VALUES ($1, $2, $3, $4) RETURNING id`, name, appliesTo, durationDays, enabled).Scan(&id)
	if err != nil {
		t.Fatalf("ccCreatePolicy: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM chat_retention_policies WHERE id = $1`, id) //nolint:errcheck
	})
	return id
}

// ccAgeEffectiveAt fast-forwards a policy's effective_at into the past — the
// N4 test fixture's job per the plan (a real edit re-arms it forward again).
func ccAgeEffectiveAt(t *testing.T, pool *pgxpool.Pool, policyID int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_retention_policies SET effective_at = now() - interval '1 day' WHERE id = $1`, policyID); err != nil {
		t.Fatalf("ccAgeEffectiveAt: %v", err)
	}
}

func ccManageClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, IsAdmin: true, Permissions: []string{permissions.PermChatComplianceManage}}
}

func ccViewClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, IsAdmin: true, Permissions: []string{permissions.PermChatComplianceView}}
}

func newChatComplianceHandlerForTest(t *testing.T) (*ChatComplianceHandler, *pgxpool.Pool, *toggle.FeatureFlags) {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	flags := ccEnableToggle(t, pool)
	// workerPool aliases pool in this test — DB_WORKER_DSN is unset/inert
	// (Global Constraints), the exact production posture.
	return NewChatComplianceHandler(pool, pool, flags, testsupport.TestLogger()), pool, flags
}

func ccStrPtr(s string) *string { return &s }

// ── toggle gate ──────────────────────────────────────────────────────────────

// TestChatCompliance_ToggleOff404 proves every route 404s when
// feature.chat_compliance is OFF, regardless of permission held — the
// ship-posture rail (plan §"Ship posture": the toggle stays OFF at merge).
func TestChatCompliance_ToggleOff404(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	offFlags := toggle.NewTestFlags(map[string]bool{toggle.FeatureChatCompliance: false})
	h := NewChatComplianceHandler(pool, pool, offFlags, testsupport.TestLogger())
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
		{"ListPolicies", "GET", "/admin/chat-retention-policies", "", h.ListPolicies, ""},
		{"CreatePolicy", "POST", "/admin/chat-retention-policies", `{"name":"x","appliesTo":"all","durationDays":30,"enabled":true}`, h.CreatePolicy, ""},
		{"UpdatePolicy", "PUT", "/admin/chat-retention-policies/1", `{"name":"x","appliesTo":"all","durationDays":30,"enabled":true}`, h.UpdatePolicy, "1"},
		{"DeletePolicy", "DELETE", "/admin/chat-retention-policies/1", "", h.DeletePolicy, "1"},
		{"ListChannels", "GET", "/admin/chat-channels", "", h.ListChannels, ""},
		{"SetHold", "POST", "/admin/chat-channels/1/hold", `{"on":true,"reason":"x"}`, h.SetHold, "1"},
		{"SetClassification", "POST", "/admin/chat-channels/1/classification", `{"classification":"gxp","retentionDays":30,"wormMode":"governance"}`, h.SetClassification, "1"},
		{"SetRetention", "PUT", "/admin/chat-channels/1/retention", `{"retentionDays":30}`, h.SetRetention, "1"},
		{"PreviewPurge", "GET", "/admin/chat-purge/preview", "", h.PreviewPurge, ""},
		{"Overview", "GET", "/admin/chat-compliance/overview", "", h.Overview, ""},
		{"GetAudit", "GET", "/admin/chat-channels/1/audit", "", h.GetAudit, "1"},
		{"VerifyAudit", "GET", "/admin/chat-channels/1/audit/verify", "", h.VerifyAudit, "1"},
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

// TestChatCompliancePolicies_ViewCannotManage proves view-perm can list but
// not create/update/delete.
func TestChatCompliancePolicies_ViewCannotManage(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)

	req := httptest.NewRequest("GET", "/admin/chat-retention-policies", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.ListPolicies(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("ListPolicies with view perm: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	for _, tc := range []struct {
		name    string
		method  string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
		idParam string
	}{
		{"CreatePolicy", "POST", "/admin/chat-retention-policies", `{"name":"x","appliesTo":"all","durationDays":30,"enabled":true}`, h.CreatePolicy, ""},
		{"UpdatePolicy", "PUT", "/admin/chat-retention-policies/1", `{"name":"x","appliesTo":"all","durationDays":30,"enabled":true}`, h.UpdatePolicy, "1"},
		{"DeletePolicy", "DELETE", "/admin/chat-retention-policies/1", "", h.DeletePolicy, "1"},
		{"SetHold", "POST", "/admin/chat-channels/1/hold", `{"on":true,"reason":"x"}`, h.SetHold, "1"},
		{"SetClassification", "POST", "/admin/chat-channels/1/classification", `{"classification":"gxp","retentionDays":30,"wormMode":"governance"}`, h.SetClassification, "1"},
		{"SetRetention", "PUT", "/admin/chat-channels/1/retention", `{"retentionDays":30}`, h.SetRetention, "1"},
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

// ── policy CRUD round trip ───────────────────────────────────────────────────

func TestChatCompliancePolicies_CRUD(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	// Create.
	body := `{"name":"crud-test","appliesTo":"channel","durationDays":90,"enabled":true}`
	req := httptest.NewRequest("POST", "/admin/chat-retention-policies", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("CreatePolicy: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var created struct {
		ID          int64  `json:"id"`
		EffectiveAt string `json:"effectiveAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM chat_retention_policies WHERE id = $1`, created.ID)
	}) //nolint:errcheck

	// List — the created policy is present.
	req = httptest.NewRequest("GET", "/admin/chat-retention-policies", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec = httptest.NewRecorder()
	h.ListPolicies(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "crud-test") {
		t.Fatalf("ListPolicies: want 200 containing crud-test, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Update — a less-destructive edit (duration increase) does not re-arm.
	updBody := fmt.Sprintf(`{"name":"crud-test-2","appliesTo":"channel","durationDays":180,"enabled":true}`)
	req = httptest.NewRequest("PUT", "/admin/chat-retention-policies/"+strconv.FormatInt(created.ID, 10), strings.NewReader(updBody))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	req.SetPathValue("id", strconv.FormatInt(created.ID, 10))
	rec = httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("UpdatePolicy: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Delete — no exposure (only policy of its kind), no confirm needed.
	req = httptest.NewRequest("DELETE", "/admin/chat-retention-policies/"+strconv.FormatInt(created.ID, 10), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	req.SetPathValue("id", strconv.FormatInt(created.ID, 10))
	rec = httptest.NewRecorder()
	h.DeletePolicy(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DeletePolicy: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestChatCompliancePolicies_CreateValidation pins the 422 validation the
// route table specifies (applies_to must be kind∪all; duration_days > 0).
func TestChatCompliancePolicies_CreateValidation(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	for _, tc := range []struct {
		name string
		body string
	}{
		{"bad appliesTo", `{"name":"x","appliesTo":"bogus","durationDays":30,"enabled":true}`},
		{"zero duration", `{"name":"x","appliesTo":"all","durationDays":0,"enabled":true}`},
		{"negative duration", `{"name":"x","appliesTo":"all","durationDays":-5,"enabled":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/chat-retention-policies", strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
			rec := httptest.NewRecorder()
			h.CreatePolicy(rec, req)
			if rec.Code != http.StatusUnprocessableEntity {
				t.Errorf("want 422, got %d (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// ── N4: UpdatePolicy re-arm ──────────────────────────────────────────────────

func ccUpdatePolicy(t *testing.T, h *ChatComplianceHandler, claims *auth.Claims, id int64, name, appliesTo string, durationDays int, enabled bool) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"appliesTo":%q,"durationDays":%d,"enabled":%t}`, name, appliesTo, durationDays, enabled)
	req := httptest.NewRequest("PUT", "/admin/chat-retention-policies/"+strconv.FormatInt(id, 10), strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", strconv.FormatInt(id, 10))
	rec := httptest.NewRecorder()
	h.UpdatePolicy(rec, req)
	return rec
}

func ccPolicyEffectiveAt(t *testing.T, pool *pgxpool.Pool, id int64) (isFuture bool) {
	t.Helper()
	var future bool
	if err := pool.QueryRow(context.Background(),
		`SELECT effective_at > now() + interval '6 days' FROM chat_retention_policies WHERE id = $1`, id).Scan(&future); err != nil {
		t.Fatalf("query effective_at: %v", err)
	}
	return future
}

func TestChatCompliancePolicies_UpdateRearm(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	t.Run("duration decrease re-arms", func(t *testing.T) {
		id := ccCreatePolicy(t, pool, "rearm-dec", "channel", 3650, true)
		ccAgeEffectiveAt(t, pool, id)
		rec := ccUpdatePolicy(t, h, manager, id, "rearm-dec", "channel", 30, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if !ccPolicyEffectiveAt(t, pool, id) {
			t.Error("a shortening edit must re-arm effective_at forward")
		}
	})

	t.Run("duration increase does not re-arm", func(t *testing.T) {
		id := ccCreatePolicy(t, pool, "rearm-inc", "channel", 30, true)
		ccAgeEffectiveAt(t, pool, id)
		rec := ccUpdatePolicy(t, h, manager, id, "rearm-inc", "channel", 7300, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if ccPolicyEffectiveAt(t, pool, id) {
			t.Error("a lengthening edit must NOT re-arm effective_at (not punished)")
		}
	})

	t.Run("enabled false to true re-arms", func(t *testing.T) {
		id := ccCreatePolicy(t, pool, "rearm-enable", "channel", 30, false)
		ccAgeEffectiveAt(t, pool, id)
		rec := ccUpdatePolicy(t, h, manager, id, "rearm-enable", "channel", 30, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if !ccPolicyEffectiveAt(t, pool, id) {
			t.Error("false->true enable must re-arm effective_at")
		}
	})

	t.Run("dm to all re-arms", func(t *testing.T) {
		id := ccCreatePolicy(t, pool, "rearm-widen", "dm", 30, true)
		ccAgeEffectiveAt(t, pool, id)
		rec := ccUpdatePolicy(t, h, manager, id, "rearm-widen", "all", 30, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if !ccPolicyEffectiveAt(t, pool, id) {
			t.Error("dm->all widening must re-arm effective_at")
		}
	})

	t.Run("rename alone does not re-arm", func(t *testing.T) {
		id := ccCreatePolicy(t, pool, "rearm-rename", "channel", 30, true)
		ccAgeEffectiveAt(t, pool, id)
		rec := ccUpdatePolicy(t, h, manager, id, "rearm-rename-2", "channel", 30, true)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		if ccPolicyEffectiveAt(t, pool, id) {
			t.Error("a rename-only edit must NOT re-arm effective_at")
		}
	})
}

// ── FIX 3: DeletePolicy exposure guard ───────────────────────────────────────

func TestChatCompliancePolicies_DeleteExposureGuard(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	// A long DM-specific shield + a short 'all' ceiling.
	dmShield := ccCreatePolicy(t, pool, "dm-shield", "dm", 3650, true)
	allCeiling := ccCreatePolicy(t, pool, "all-ceiling", "all", 30, true)
	// Both policies effective now (skip the 7-day grace for this test).
	ccAgeEffectiveAt(t, pool, dmShield)
	ccAgeEffectiveAt(t, pool, allCeiling)

	// A DM channel with no per-channel override — resolves to the dmShield's
	// 3650 today; would drop to 30 if dmShield were deleted.
	dmName := (*string)(nil)
	dmChannel := ccCreateChannel(t, pool, "dm", dmName, actorID)

	t.Run("delete shielding policy without confirm is refused", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/admin/chat-retention-policies/"+strconv.FormatInt(dmShield, 10), nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
		req.SetPathValue("id", strconv.FormatInt(dmShield, 10))
		rec := httptest.NewRecorder()
		h.DeletePolicy(rec, req)
		if rec.Code != http.StatusConflict {
			t.Fatalf("want 409, got %d (body=%s)", rec.Code, rec.Body.String())
		}
		var body struct {
			Code            string `json:"code"`
			ExposedChannels int    `json:"exposedChannels"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode 409 body: %v", err)
		}
		if body.Code != "exposure" || body.ExposedChannels < 1 {
			t.Errorf("want code=exposure exposedChannels>=1, got %+v", body)
		}
	})

	t.Run("delete shielding policy WITH confirm succeeds", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/admin/chat-retention-policies/"+strconv.FormatInt(dmShield, 10)+"?confirm=DESTROY", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
		req.SetPathValue("id", strconv.FormatInt(dmShield, 10))
		rec := httptest.NewRecorder()
		h.DeletePolicy(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("want 204 with confirm=DESTROY, got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("delete a non-shielding policy needs no confirm", func(t *testing.T) {
		// allCeiling shields nothing (dmChannel now has no dm-specific cover
		// since dmShield is gone, but deleting allCeiling only REMOVES a
		// ceiling — never an exposure).
		req := httptest.NewRequest("DELETE", "/admin/chat-retention-policies/"+strconv.FormatInt(allCeiling, 10), nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
		req.SetPathValue("id", strconv.FormatInt(allCeiling, 10))
		rec := httptest.NewRecorder()
		h.DeletePolicy(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("want 204 (no exposure), got %d (body=%s)", rec.Code, rec.Body.String())
		}
	})

	_ = dmChannel
}

// TestChatCompliancePolicies_UpdateShieldDisableRearms proves disabling (not
// deleting) a shielding policy via UpdatePolicy also re-arms — FIX 3's
// exposesAnyChannel term catching what the per-policy heuristic reads as
// benign (an 'enabled: true -> false' edit looks like it can only shrink the
// destroyed set, UNLESS it was shielding a class from a shorter ceiling).
func TestChatCompliancePolicies_UpdateShieldDisableRearms(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	dmShield := ccCreatePolicy(t, pool, "shield-disable", "dm", 3650, true)
	allCeiling := ccCreatePolicy(t, pool, "all-ceiling-2", "all", 30, true)
	ccAgeEffectiveAt(t, pool, dmShield)
	ccAgeEffectiveAt(t, pool, allCeiling)
	// Without an actual dm channel, disabling dmShield exposes nothing (the
	// query counts real chat_channels rows) — a dm channel is what makes the
	// shield-disable exposure real.
	ccCreateChannel(t, pool, "dm", nil, actorID)

	rec := ccUpdatePolicy(t, h, manager, dmShield, "shield-disable", "dm", 3650, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !ccPolicyEffectiveAt(t, pool, dmShield) {
		t.Error("disabling a shielding policy must re-arm effective_at (FIX 3)")
	}
}

// ── ListChannels participant projection ──────────────────────────────────────

func TestChatComplianceListChannels_Participants(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	a := ssCreateUser(t, pool)
	b := ssCreateUser(t, pool)
	manager := ccManageClaims(a)

	dmChannel := ccCreateChannel(t, pool, "dm", nil, a)
	ccAddMember(t, pool, dmChannel, a)
	ccAddMember(t, pool, dmChannel, b)

	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels?userId=%d", a), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.ListChannels(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListChannels: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode ListChannels: %v", err)
	}
	found := false
	for _, row := range rows {
		if int64(row["id"].(float64)) != dmChannel {
			continue
		}
		found = true
		if _, hasName := row["name"]; hasName {
			t.Error("a dm row must have no name key (NULL name)")
		}
		parts, ok := row["participants"].([]any)
		if !ok || len(parts) != 2 {
			t.Errorf("want 2 participants on the dm row, got %#v", row["participants"])
		}
	}
	if !found {
		t.Fatalf("dm channel %d not found in ListChannels(userId=%d) output", dmChannel, a)
	}

	// q= finds the channel by a participant's email.
	var bEmail string
	if err := pool.QueryRow(context.Background(), `SELECT email FROM users WHERE id = $1`, b).Scan(&bEmail); err != nil {
		t.Fatalf("lookup b email: %v", err)
	}
	req = httptest.NewRequest("GET", "/admin/chat-channels?q="+bEmail, nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec = httptest.NewRecorder()
	h.ListChannels(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), strconv.FormatInt(dmChannel, 10)) {
		t.Errorf("q=<participant email>: want the dm channel in results, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestChatComplianceHoldTruth_CaseHoldOnlyChannelShowsHeld is the spec §14
// console predicate-truth test (plan Task 8 step 1, red before the repoint):
// a channel held ONLY by a case hold (chat_case_hold_set — the A4a boolean
// arm, chat_channels.legal_hold, stays FALSE) must still show as held
// everywhere the admin console projects hold state. Before the repoint,
// listChannelsSQL/overviewChannelsSQL read the raw boolean directly and this
// channel is invisible to both — the exact blind spot spec §2.3 names ("a
// case-held channel would show as un-held").
func TestChatComplianceHoldTruth_CaseHoldOnlyChannelShowsHeld(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	ctx := context.Background()
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)

	caseID := edCreateCase(t, pool, "case-hold-truth", "active", actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("case-held-only"), actorID)
	ccAddMember(t, pool, channelID, actorID)

	var holdID int64
	if err := pool.QueryRow(ctx, `SELECT chat_case_hold_set($1, $2, NULL, $3, $4)`,
		actorID, caseID, channelID, "case-hold-truth-reason").Scan(&holdID); err != nil {
		t.Fatalf("chat_case_hold_set: %v", err)
	}

	// The boolean arm never fired — proves this test exercises the case-hold
	// arm alone, not a redundant boolean set.
	var boolHold bool
	if err := pool.QueryRow(ctx, `SELECT legal_hold FROM chat_channels WHERE id = $1`, channelID).Scan(&boolHold); err != nil {
		t.Fatalf("check boolean arm: %v", err)
	}
	if boolHold {
		t.Fatal("fixture bug: the boolean arm must stay FALSE — this test isolates the case-hold arm")
	}

	// GET /admin/chat-channels must show legalHold:true + caseHoldCount:1.
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels?userId=%d", actorID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.ListChannels(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListChannels: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatalf("decode ListChannels: %v", err)
	}
	found := false
	for _, row := range rows {
		if int64(row["id"].(float64)) != channelID {
			continue
		}
		found = true
		if legalHold, _ := row["legalHold"].(bool); !legalHold {
			t.Errorf("channel %d: want legalHold:true (case-hold-only), got %#v", channelID, row["legalHold"])
		}
		count, ok := row["caseHoldCount"].(float64)
		if !ok || int(count) != 1 {
			t.Errorf("channel %d: want caseHoldCount:1, got %#v", channelID, row["caseHoldCount"])
		}
	}
	if !found {
		t.Fatalf("case-held-only channel %d not found in ListChannels output", channelID)
	}

	// GET /admin/chat-compliance/overview's channelsUnderHold tile must
	// include it with its caseHolds array.
	req = httptest.NewRequest("GET", "/admin/chat-compliance/overview", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec = httptest.NewRecorder()
	h.Overview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Overview: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out struct {
		ChannelsUnderHold []map[string]any `json:"channelsUnderHold"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	var tileRow map[string]any
	for _, row := range out.ChannelsUnderHold {
		if v, ok := row["id"].(float64); ok && int64(v) == channelID {
			tileRow = row
			break
		}
	}
	if tileRow == nil {
		t.Fatalf("channelsUnderHold must include case-hold-only channel %d, got %+v", channelID, out.ChannelsUnderHold)
	}
	caseHolds, ok := tileRow["caseHolds"].([]any)
	if !ok || len(caseHolds) != 1 {
		t.Fatalf("channel %d: want a 1-element caseHolds array, got %#v", channelID, tileRow["caseHolds"])
	}
	entry, ok := caseHolds[0].(map[string]any)
	if !ok || int64(entry["caseId"].(float64)) != caseID || int64(entry["holdId"].(float64)) != holdID {
		t.Errorf("channel %d: caseHolds[0] want caseId=%d holdId=%d, got %#v", channelID, caseID, holdID, entry)
	}
}

// ── holds ────────────────────────────────────────────────────────────────────

func ccSetHold(t *testing.T, h *ChatComplianceHandler, claims *auth.Claims, channelID int64, on bool, reason string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"on":%t,"reason":%q}`, on, reason)
	req := httptest.NewRequest("POST", "/admin/chat-channels/"+strconv.FormatInt(channelID, 10)+"/hold", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.SetHold(rec, req)
	return rec
}

func TestChatComplianceHold_BlocksPurge(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	author := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("hold-purge-test"), actorID)
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_channels SET retention_days = 5 WHERE id = $1`, channelID); err != nil {
		t.Fatalf("set retention_days: %v", err)
	}
	var msgID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'will be purged', now() - interval '10 days') RETURNING id`,
		channelID, author).Scan(&msgID); err != nil {
		t.Fatalf("insert aged message: %v", err)
	}

	rec := ccSetHold(t, h, manager, channelID, true, "case-42")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetHold on: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	if _, err := pool.Exec(context.Background(), `SELECT * FROM chat_purge_expired(1000, FALSE)`); err != nil {
		t.Fatalf("chat_purge_expired: %v", err)
	}
	if !ccMessageExists(t, pool, msgID) {
		t.Error("a held channel's message must survive the purge")
	}

	rec = ccSetHold(t, h, manager, channelID, false, "case-42")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetHold release: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	if _, err := pool.Exec(context.Background(), `SELECT * FROM chat_purge_expired(1000, FALSE)`); err != nil {
		t.Fatalf("chat_purge_expired: %v", err)
	}
	if ccMessageExists(t, pool, msgID) {
		t.Error("after release, the aged message must be destroyed by the purge")
	}
}

func ccMessageExists(t *testing.T, pool *pgxpool.Pool, id int64) bool {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM chat_messages WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count chat_messages: %v", err)
	}
	return n == 1
}

// TestChatComplianceHold_InvalidArgsMapToUnprocessable pins the
// reducererr.Classify(BZ195) -> 422 mapping (mapErr).
func TestChatComplianceHold_InvalidArgsMapToUnprocessable(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)

	// A channel id that does not exist -> BZ195 "channel not found" -> 422.
	rec := ccSetHold(t, h, manager, 999999999, true, "case-x")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("SetHold on a nonexistent channel: want 422, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// ── classification & per-channel retention ──────────────────────────────────

func TestChatComplianceSetClassification_UpgradesToGxp(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("gxp-upgrade-test"), actorID)

	body := `{"classification":"gxp","retentionDays":365,"wormMode":"governance"}`
	req := httptest.NewRequest("POST", "/admin/chat-channels/"+strconv.FormatInt(channelID, 10)+"/classification", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.SetClassification(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetClassification: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var class string
	var retDays int
	var worm string
	if err := pool.QueryRow(context.Background(),
		`SELECT classification, retention_days, worm_mode FROM chat_channels WHERE id = $1`, channelID).
		Scan(&class, &retDays, &worm); err != nil {
		t.Fatalf("query channel: %v", err)
	}
	if class != "gxp" || retDays != 365 || worm != "governance" {
		t.Errorf("want gxp/365/governance, got %s/%d/%s", class, retDays, worm)
	}
}

func TestChatComplianceSetRetention_ClearsWithNull(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("retention-clear-test"), actorID)

	req := httptest.NewRequest("PUT", "/admin/chat-channels/"+strconv.FormatInt(channelID, 10)+"/retention", strings.NewReader(`{"retentionDays":30}`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.SetRetention(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetRetention set: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("PUT", "/admin/chat-channels/"+strconv.FormatInt(channelID, 10)+"/retention", strings.NewReader(`{"retentionDays":null}`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec = httptest.NewRecorder()
	h.SetRetention(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetRetention clear: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var retDays *int
	if err := pool.QueryRow(context.Background(), `SELECT retention_days FROM chat_channels WHERE id = $1`, channelID).Scan(&retDays); err != nil {
		t.Fatalf("query channel: %v", err)
	}
	if retDays != nil {
		t.Errorf("want NULL retention_days after clear, got %v", *retDays)
	}
}

// ── Task 11b: preview · overview · audit · verify ───────────────────────────

func ccVerifyAudit(t *testing.T, h *ChatComplianceHandler, claims *auth.Claims, channelID int64) ccVerifyAuditResponse {
	t.Helper()
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels/%d/audit/verify", channelID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.VerifyAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("VerifyAudit: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out ccVerifyAuditResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode VerifyAudit: %v", err)
	}
	return out
}

type ccAuditHead struct {
	ID       int64  `json:"id"`
	Checksum string `json:"checksum"`
}

type ccAnchorVerdict struct {
	AnchorID            int64 `json:"anchorId"`
	IDFrom              int64 `json:"idFrom"`
	IDTo                int64 `json:"idTo"`
	Valid               bool  `json:"valid"`
	ReconciledFromPurge int   `json:"reconciledFromPurge"`
	RevisionsUnchained  int   `json:"revisionsUnchained"`
}

type ccVerifyAuditResponse struct {
	ChannelID          int64             `json:"channelId"`
	Checked            int               `json:"checked"`
	FromID             *int64            `json:"fromId"`
	ToID               *int64            `json:"toId"`
	ChainValid         bool              `json:"chainValid"`
	FirstInvalid       *int64            `json:"firstInvalid"`
	KeyVersion         string            `json:"keyVersion"`
	TruncationDetected bool              `json:"truncationDetected"`
	NotarizedHead      *ccAuditHead      `json:"notarizedHead"`
	LiveHead           *ccAuditHead      `json:"liveHead"`
	Anchors            []ccAnchorVerdict `json:"anchors"`
}

// ccContainsChannelID checks a jsonb-agg'd row list (each row a
// map[string]any decoded from JSON, so "id" is a float64) for a channel id —
// Overview's holds/gxp/overrides arrays are exactly this shape.
func ccContainsChannelID(rows []map[string]any, id int64) bool {
	for _, row := range rows {
		if v, ok := row["id"].(float64); ok && int64(v) == id {
			return true
		}
	}
	return false
}

// TestChatCompliancePreviewPurge_MatchesRealRun proves the dry-run preview
// reports the same count the real run then destroys, and that the preview
// itself destroys nothing.
func TestChatCompliancePreviewPurge_MatchesRealRun(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	author := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)

	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("preview-purge-test"), actorID)
	if _, err := pool.Exec(context.Background(), `UPDATE chat_channels SET retention_days = 5 WHERE id = $1`, channelID); err != nil {
		t.Fatalf("set retention_days: %v", err)
	}
	var msgID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'preview target', now() - interval '10 days') RETURNING id`,
		channelID, author).Scan(&msgID); err != nil {
		t.Fatalf("insert aged message: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/chat-purge/preview", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.PreviewPurge(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PreviewPurge: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var preview struct {
		TotalMessages int `json:"totalMessages"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatalf("decode preview: %v", err)
	}
	if preview.TotalMessages < 1 {
		t.Fatalf("preview must report at least the one aged message, got %d", preview.TotalMessages)
	}
	if !ccMessageExists(t, pool, msgID) {
		t.Error("a dry-run preview must not destroy anything")
	}

	if _, err := pool.Exec(context.Background(), `SELECT * FROM chat_purge_expired(1000, FALSE)`); err != nil {
		t.Fatalf("chat_purge_expired: %v", err)
	}
	if ccMessageExists(t, pool, msgID) {
		t.Error("the real run must destroy the message the preview reported")
	}
}

// TestChatComplianceOverview_SurfacesHoldsGxpOverridesAndLastRun proves
// Overview surfaces channels under hold, gxp channels, channels with
// per-channel overrides, and a stale last purge run with drained:false.
func TestChatComplianceOverview_SurfacesHoldsGxpOverridesAndLastRun(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)

	heldChannel := ccCreateChannel(t, pool, "channel", ccStrPtr("overview-hold"), actorID)
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_channels SET legal_hold = TRUE, legal_hold_reason = 'case-overview' WHERE id = $1`, heldChannel); err != nil {
		t.Fatalf("set hold: %v", err)
	}
	gxpChannel := ccCreateChannel(t, pool, "channel", ccStrPtr("overview-gxp"), actorID)
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_channels SET classification = 'gxp', retention_days = 365, worm_mode = 'governance' WHERE id = $1`, gxpChannel); err != nil {
		t.Fatalf("set gxp: %v", err)
	}
	overrideChannel := ccCreateChannel(t, pool, "channel", ccStrPtr("overview-override"), actorID)
	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_channels SET retention_days = 45 WHERE id = $1`, overrideChannel); err != nil {
		t.Fatalf("set override: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`SELECT audit_write(NULL, 'chat.purge_run', 'chat', NULL, NULL,
		   '{"channels":3,"messages":42,"drained":false}'::jsonb, NULL, NULL, 'core')`); err != nil {
		t.Fatalf("seed chat.purge_run row: %v", err)
	}

	req := httptest.NewRequest("GET", "/admin/chat-compliance/overview", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	rec := httptest.NewRecorder()
	h.Overview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Overview: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var out struct {
		ChannelsUnderHold     []map[string]any `json:"channelsUnderHold"`
		GxpChannels           []map[string]any `json:"gxpChannels"`
		ChannelsWithOverrides []map[string]any `json:"channelsWithOverrides"`
		LastPurgeRun          *struct {
			Channels int  `json:"channels"`
			Messages int  `json:"messages"`
			Drained  bool `json:"drained"`
		} `json:"lastPurgeRun"`
		NextRunAt string `json:"nextRunAt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode overview: %v", err)
	}
	if !ccContainsChannelID(out.ChannelsUnderHold, heldChannel) {
		t.Errorf("channelsUnderHold must include %d, got %+v", heldChannel, out.ChannelsUnderHold)
	}
	if !ccContainsChannelID(out.GxpChannels, gxpChannel) {
		t.Errorf("gxpChannels must include %d, got %+v", gxpChannel, out.GxpChannels)
	}
	if !ccContainsChannelID(out.ChannelsWithOverrides, overrideChannel) {
		t.Errorf("channelsWithOverrides must include %d, got %+v", overrideChannel, out.ChannelsWithOverrides)
	}
	if out.LastPurgeRun == nil {
		t.Fatal("lastPurgeRun must be populated from the seeded admin_audit_log row")
	}
	if out.LastPurgeRun.Drained {
		t.Error("the seeded run's drained:false must round-trip — a stale/incomplete run must not read as drained:true")
	}
	if out.NextRunAt == "" {
		t.Error("nextRunAt must be populated")
	}
}

// TestChatComplianceGetAudit_ShowsActs proves the audit list surfaces
// hold.set/hold.release acts and that format=csv streams a downloadable
// artifact carrying the acts.
func TestChatComplianceGetAudit_ShowsActs(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("audit-list-test"), actorID)

	ccSetHold(t, h, manager, channelID, true, "case-audit")
	ccSetHold(t, h, manager, channelID, false, "case-audit")

	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels/%d/audit", channelID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec := httptest.NewRecorder()
	h.GetAudit(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetAudit: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var acts []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &acts); err != nil {
		t.Fatalf("decode GetAudit: %v", err)
	}
	seen := map[string]bool{}
	for _, a := range acts {
		seen[a["action"].(string)] = true
	}
	if !seen["hold.set"] || !seen["hold.release"] {
		t.Errorf("want hold.set + hold.release in acts, got %+v", acts)
	}

	req = httptest.NewRequest("GET", fmt.Sprintf("/admin/chat-channels/%d/audit?format=csv", channelID), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), viewer))
	req.SetPathValue("id", strconv.FormatInt(channelID, 10))
	rec = httptest.NewRecorder()
	h.GetAudit(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("GetAudit csv: want 200 text/csv, got %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "hold.set") {
		t.Errorf("csv export must contain the acts, got:\n%s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "valid=true") {
		t.Errorf("csv export must carry a verification header an auditor can keep, got:\n%s", rec.Body.String())
	}
}

// TestChatComplianceVerifyAudit_CleanChannel is the baseline: a freshly
// anchored channel verifies chainValid=true with one valid anchor.
func TestChatComplianceVerifyAudit_CleanChannel(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-clean"), actorID)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'clean body', now() - interval '2 days')`, channelID, actorID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("chat_chain_anchor: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if !out.ChainValid {
		t.Errorf("want chainValid=true, got %+v", out)
	}
	if out.TruncationDetected {
		t.Error("want truncationDetected=false")
	}
	if len(out.Anchors) != 1 || !out.Anchors[0].Valid {
		t.Errorf("want one valid anchor, got %+v", out.Anchors)
	}
	if out.KeyVersion != "v2" && out.KeyVersion != "v3" {
		t.Errorf("keyVersion must be v2 or v3, got %q", out.KeyVersion)
	}
}

// TestChatComplianceVerifyAudit_PurgeReconciled proves a lawful purge inside
// an anchored range still verifies valid=true, reconciled from destroyedElems
// (N1 benign case).
func TestChatComplianceVerifyAudit_PurgeReconciled(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-purge-benign"), actorID)
	if _, err := pool.Exec(context.Background(), `UPDATE chat_channels SET retention_days = 10 WHERE id = $1`, channelID); err != nil {
		t.Fatalf("set retention: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at) VALUES
		   ($1, 1, $2, 'purge target', now() - interval '11 days'),
		   ($1, 2, $2, 'survivor', now() - interval '3 days')`, channelID, actorID); err != nil {
		t.Fatalf("insert messages: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT * FROM chat_purge_expired(1000, FALSE)`); err != nil {
		t.Fatalf("purge: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if !out.ChainValid || len(out.Anchors) != 1 || !out.Anchors[0].Valid {
		t.Fatalf("want a valid reconciled anchor, got %+v", out)
	}
	if out.Anchors[0].ReconciledFromPurge != 1 {
		t.Errorf("want reconciledFromPurge=1, got %d", out.Anchors[0].ReconciledFromPurge)
	}
}

// TestChatComplianceVerifyAudit_BodyRewriteDetected is N1's ATTACK case — this
// assertion is the feature (plan, verbatim): a direct body rewrite of a
// surviving message inside an anchored range must flip the anchor, even
// though the chat_audit_log chain itself is untouched.
func TestChatComplianceVerifyAudit_BodyRewriteDetected(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-rewrite"), actorID)
	var msgID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'rewrite-original', now() - interval '2 days') RETURNING id`,
		channelID, actorID).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE chat_messages SET body = 'rewrite-tampered' WHERE id = $1`, msgID); err != nil {
		t.Fatalf("rewrite body: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if !out.ChainValid {
		t.Fatalf("the chat_audit_log chain itself is untouched by a message-body rewrite: %+v", out)
	}
	if len(out.Anchors) != 1 || out.Anchors[0].Valid {
		t.Errorf("N1 attack: a direct body rewrite inside an anchored range must flip the anchor to valid=false, got %+v", out.Anchors)
	}
}

// TestChatComplianceVerifyAudit_FabricatedRevision is N6: a fabricated
// revision row carrying the true original body, followed by a free rewrite,
// must still be caught via revisionsUnchained.
func TestChatComplianceVerifyAudit_FabricatedRevision(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-fab"), actorID)
	var msgID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'fab-original', now() - interval '2 days') RETURNING id`,
		channelID, actorID).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("anchor: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO chat_message_revisions (channel_id, message_id, prior_body, edited_by)
		 VALUES ($1, $2, 'fab-original', $3)`, channelID, msgID, actorID); err != nil {
		t.Fatalf("fabricate revision: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE chat_messages SET body = 'fab-attacker-rewrite' WHERE id = $1`, msgID); err != nil {
		t.Fatalf("rewrite body: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if len(out.Anchors) != 1 || out.Anchors[0].Valid {
		t.Fatalf("N6: a fabricated revision + free rewrite must flip valid=false, got %+v", out.Anchors)
	}
	if out.Anchors[0].RevisionsUnchained != 1 {
		t.Errorf("want revisionsUnchained=1, got %d", out.Anchors[0].RevisionsUnchained)
	}
}

// TestChatComplianceVerifyAudit_TamperedChainRow proves a tampered
// chat_audit_log row reports chainValid=false and offers NO anchor verdicts
// (their inputs ride the broken chain — plan, binding).
func TestChatComplianceVerifyAudit_TamperedChainRow(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	manager := ccManageClaims(actorID)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-tamper"), actorID)

	rec := ccSetHold(t, h, manager, channelID, true, "case-tamper")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetHold: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	if _, err := pool.Exec(context.Background(),
		`UPDATE chat_audit_log SET after_state = jsonb_set(after_state, '{legalHold}', 'false'::jsonb)
		  WHERE channel_id = $1 AND action = 'hold.set'`, channelID); err != nil {
		t.Fatalf("tamper chain row: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if out.ChainValid {
		t.Error("want chainValid=false after tampering with a chained row's after_state")
	}
	if len(out.Anchors) != 0 {
		t.Errorf("a broken chain must not offer anchor verdicts, got %+v", out.Anchors)
	}
}

// TestChatComplianceVerifyAudit_TailTruncation is FIX 1's assertion: a
// contiguous tail-truncation of the whole chain (rewrite then delete every
// chat_audit_log row) is caught by the notary cross-check, even though the
// (now-empty) surviving chain would otherwise "verify" trivially.
func TestChatComplianceVerifyAudit_TailTruncation(t *testing.T) {
	h, pool, _ := newChatComplianceHandlerForTest(t)
	actorID := ssCreateUser(t, pool)
	viewer := ccViewClaims(actorID)
	channelID := ccCreateChannel(t, pool, "channel", ccStrPtr("verify-truncation"), actorID)
	var msgID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO chat_messages (channel_id, seq, author_id, body, created_at)
		 VALUES ($1, 1, $2, 'trunc-original', now() - interval '2 days') RETURNING id`,
		channelID, actorID).Scan(&msgID); err != nil {
		t.Fatalf("insert message: %v", err)
	}
	// RUN1 anchors the channel and notarizes its head.
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("anchor run 1: %v", err)
	}
	// Attacker rewrites the body, then deletes the entire chain (a contiguous
	// tail — the only act this channel had).
	if _, err := pool.Exec(context.Background(), `UPDATE chat_messages SET body = 'trunc-tampered' WHERE id = $1`, msgID); err != nil {
		t.Fatalf("rewrite body: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM chat_audit_log WHERE channel_id = $1`, channelID); err != nil {
		t.Fatalf("truncate chain: %v", err)
	}
	// RUN2: the notary floor now exceeds the (empty) live head — the anchor
	// must skip loudly rather than re-bless the rewritten range.
	if _, err := pool.Exec(context.Background(), `SELECT chat_chain_anchor()`); err != nil {
		t.Fatalf("anchor run 2: %v", err)
	}

	out := ccVerifyAudit(t, h, viewer, channelID)
	if !out.TruncationDetected {
		t.Fatalf("FIX 1: a tail-truncated chain must report truncationDetected=true, got %+v", out)
	}
	if out.NotarizedHead == nil {
		t.Error("want notarizedHead populated from the RUN1 notary")
	}
	if out.LiveHead != nil {
		t.Errorf("want liveHead nil (the chain was fully truncated), got %+v", out.LiveHead)
	}
	if len(out.Anchors) != 0 {
		t.Errorf("a truncated chain must not offer anchor verdicts, got %+v", out.Anchors)
	}
}
