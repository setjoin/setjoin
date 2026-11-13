package drive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestACLWireParsersAndCapabilityBounds(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		raw  string
		want int64
		ok   bool
	}{{"1", 1, true}, {"", 0, false}, {" 1", 0, false}, {"0", 0, false}, {"-1", -1, false}, {"x", 0, false}} {
		if got, ok := parseDecimalID(tt.raw); got != tt.want || ok != tt.ok {
			t.Errorf("parseDecimalID(%q) = (%d,%v), want (%d,%v)", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
	for _, tt := range []struct {
		raw  string
		want int64
		ok   bool
	}{{"0", 0, true}, {"7", 7, true}, {"", 0, false}, {" 7", 0, false}, {"-1", -1, false}, {"x", 0, false}} {
		if got, ok := parseEpoch(tt.raw); got != tt.want || ok != tt.ok {
			t.Errorf("parseEpoch(%q) = (%d,%v), want (%d,%v)", tt.raw, got, ok, tt.want, tt.ok)
		}
	}
	if got, ok := parseOptionalTime(nil); got != nil || !ok {
		t.Fatalf("nil optional time = (%v,%v), want (nil,true)", got, ok)
	}
	rawTime := "2026-08-04T12:00:00+08:00"
	gotTime, ok := parseOptionalTime(&rawTime)
	if !ok || gotTime == nil || gotTime.Location() != time.UTC || gotTime.Format(time.RFC3339) != "2026-08-04T04:00:00Z" {
		t.Fatalf("valid optional time = (%v,%v), want normalized UTC", gotTime, ok)
	}
	badTime := "tomorrow"
	if got, ok := parseOptionalTime(&badTime); got != nil || ok {
		t.Fatalf("invalid optional time = (%v,%v), want (nil,false)", got, ok)
	}
	for _, preset := range []string{"viewer", "contributor", "editor", "folder_manager"} {
		if !validPublicPreset(preset) {
			t.Errorf("public preset %q rejected", preset)
		}
	}
	if validPublicPreset("custom") {
		t.Error("custom must not be accepted on the public grant wire")
	}

	valid := aclGrantBody{SubjectKind: "user", SubjectID: "2", Preset: "viewer", Scope: "self"}
	if id, starts, expires, ok := validateGrantWire(valid, false); !ok || id != 2 || starts != nil || expires != nil {
		t.Fatalf("basic grant = (%d,%v,%v,%v), want valid", id, starts, expires, ok)
	}
	group := valid
	group.SubjectKind = "group"
	if _, _, _, ok := validateGrantWire(group, false); ok {
		t.Error("group accepted without access-governance feature")
	}
	if _, _, _, ok := validateGrantWire(group, true); !ok {
		t.Error("group rejected with access-governance feature")
	}
	advanced := valid
	starts, expires := "2026-08-04T04:00:00Z", "2026-08-05T04:00:00Z"
	uses := 2
	advanced.StartsAt, advanced.ExpiresAt, advanced.MaxUses = &starts, &expires, &uses
	if _, startAt, expireAt, ok := validateGrantWire(advanced, true); !ok || startAt == nil || expireAt == nil {
		t.Fatal("advanced validity window rejected")
	}
	if _, _, _, ok := validateGrantWire(advanced, false); ok {
		t.Error("advanced validity accepted while feature is disabled")
	}
	advanced.StartsAt = &badTime
	if _, _, _, ok := validateGrantWire(advanced, true); ok {
		t.Error("malformed validity timestamp accepted")
	}

	if !validRequestedCapabilities([]string{"preview", "download"}) {
		t.Error("valid capability set rejected")
	}
	tooMany := make([]string, 16)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("cap-%d", i)
	}
	for name, caps := range map[string][]string{
		"empty": {}, "too many": tooMany, "duplicate": {"preview", "preview"},
		"empty member": {""}, "oversized member": {strings.Repeat("x", 65)},
	} {
		t.Run(name, func(t *testing.T) {
			if validRequestedCapabilities(caps) {
				t.Fatalf("invalid capabilities accepted: %v", caps)
			}
		})
	}
}

func TestDecodeACLJSONRequiresExactlyOneKnownObject(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		body string
		ok   bool
	}{{"valid", `{"break":true}`, true}, {"unknown", `{"break":true,"extra":1}`, false}, {"trailing", `{"break":true}{}`, false}, {"malformed", `{"break":`, false}} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			var body inheritanceBody
			if got := decodeACLJSON(rr, req, &body); got != tt.ok {
				t.Fatalf("decode = %v, want %v", got, tt.ok)
			}
			if !tt.ok && rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
		})
	}
}

func TestACLIdempotencyRequiresOneMatchingCanonicalUUID(t *testing.T) {
	t.Parallel()
	const key = "00000000-0000-4000-8000-000000000001"
	for _, tt := range []struct {
		name, body string
		headers    []string
		want       bool
	}{
		{"matching", key, []string{key}, true},
		{"uppercase UUID", strings.ToUpper(key), []string{strings.ToUpper(key)}, true},
		{"missing header", key, nil, false},
		{"mismatch", key, []string{"00000000-0000-4000-8000-000000000002"}, false},
		{"malformed", "12345678", []string{"12345678"}, false},
		{"duplicate", key, []string{key, key}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			for _, value := range tt.headers {
				req.Header.Add("Idempotency-Key", value)
			}
			if got := validACLIdempotency(req, tt.body); got != tt.want {
				t.Fatalf("validACLIdempotency() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACLGovernanceRoutesRejectInvalidWireBeforeDatabase(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		"feature.drive": true,
	}), discardLogger())
	tests := []struct {
		name, method, path, body string
		want                     int
	}{
		{"unknown quick view", http.MethodGet, "/drive/quick-views?view=unknown", "", http.StatusUnprocessableEntity},
		{"oversized quick view", http.MethodGet, "/drive/quick-views?view=shared&max=201", "", http.StatusUnprocessableEntity},
		{"short subject search", http.MethodGet, "/drive/acl-subjects?node=1&q=a", "", http.StatusUnprocessableEntity},
		{"malformed subject node", http.MethodGet, "/drive/acl-subjects?node=x&q=alice", "", http.StatusUnprocessableEntity},
		{"malformed detail node", http.MethodGet, "/drive/nodes/x/access", "", http.StatusBadRequest},
		{"malformed grant node", http.MethodPost, "/drive/nodes/x/acl/preview", `{}`, http.StatusBadRequest},
		{"unknown grant field", http.MethodPost, "/drive/nodes/1/acl/preview", `{"subjectKind":"user","subjectId":"2","preset":"viewer","scope":"self","extra":true}`, http.StatusBadRequest},
		{"custom public preset", http.MethodPost, "/drive/nodes/1/acl/preview", `{"subjectKind":"user","subjectId":"2","preset":"custom","scope":"self"}`, http.StatusUnprocessableEntity},
		{"children public scope", http.MethodPost, "/drive/nodes/1/acl/preview", `{"subjectKind":"user","subjectId":"2","preset":"viewer","scope":"children"}`, http.StatusUnprocessableEntity},
		{"group hidden without governance", http.MethodPost, "/drive/nodes/1/acl/preview", `{"subjectKind":"group","subjectId":"2","preset":"viewer","scope":"self"}`, http.StatusUnprocessableEntity},
		{"missing grant epoch", http.MethodPost, "/drive/nodes/1/acl", `{"subjectKind":"user","subjectId":"2","preset":"viewer","scope":"self","idempotencyKey":"12345678"}`, http.StatusUnprocessableEntity},
		{"malformed revoke id", http.MethodDelete, "/drive/acl-grants/x", `{}`, http.StatusBadRequest},
		{"malformed revoke JSON", http.MethodDelete, "/drive/acl-grants/1", `{"expectedEpoch":`, http.StatusBadRequest},
		{"malformed revoke epoch", http.MethodDelete, "/drive/acl-grants/1", `{"expectedEpoch":"x","reason":"review complete"}`, http.StatusUnprocessableEntity},
		{"malformed inheritance preview id", http.MethodPost, "/drive/nodes/x/inheritance/preview", `{}`, http.StatusBadRequest},
		{"malformed inheritance preview JSON", http.MethodPost, "/drive/nodes/1/inheritance/preview", `{"break":`, http.StatusBadRequest},
		{"malformed inheritance id", http.MethodPut, "/drive/nodes/x/inheritance", `{}`, http.StatusBadRequest},
		{"malformed inheritance JSON", http.MethodPut, "/drive/nodes/1/inheritance", `{"break":`, http.StatusBadRequest},
		{"missing inheritance epoch", http.MethodPut, "/drive/nodes/1/inheritance", `{"break":true}`, http.StatusUnprocessableEntity},
		{"malformed request node", http.MethodPost, "/drive/nodes/x/access-requests/preview", `{}`, http.StatusBadRequest},
		{"malformed request JSON", http.MethodPost, "/drive/nodes/1/access-requests/preview", `{"subjectKind":`, http.StatusBadRequest},
		{"empty request capabilities", http.MethodPost, "/drive/nodes/1/access-requests/preview", `{"subjectKind":"user","subjectId":"1","capabilities":[],"propagation":"self","durationMinutes":30,"reason":"valid reason"}`, http.StatusUnprocessableEntity},
		{"short request reason", http.MethodPost, "/drive/nodes/1/access-requests/preview", `{"subjectKind":"user","subjectId":"1","capabilities":["preview"],"propagation":"self","durationMinutes":30,"reason":"short"}`, http.StatusUnprocessableEntity},
		{"missing request idempotency", http.MethodPost, "/drive/nodes/1/access-requests", `{"subjectKind":"user","subjectId":"1","capabilities":["preview"],"propagation":"self","durationMinutes":30,"reason":"valid reason"}`, http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
			if strings.Contains(tt.path, "/nodes/1/") {
				req.SetPathValue("id", "1")
			}
			if strings.Contains(tt.path, "/acl-grants/1") {
				req.SetPathValue("id", "1")
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tt.want, rr.Body.String())
			}
			if got := rr.Header().Get("Content-Type"); got != "application/problem+json" {
				t.Fatalf("Content-Type = %q, want application/problem+json", got)
			}
		})
	}
}

func TestACLGovernanceRoutesLiveRoundTripAndBoundUpload(t *testing.T) {
	pool := driveLivePool(t)
	withFeatureToggleEnabled(t, pool, toggle.FeatureDriveNodeACLReads)
	withFeatureToggleEnabled(t, pool, toggle.FeatureDriveNodeACLWrites)
	withFeatureToggleEnabled(t, pool, toggle.FeatureDriveAccessGovernance)
	owner := driveLiveUser(t, pool, "aclrouteowner")
	target := driveLiveUser(t, pool, "aclroutetarget")
	fake := newFakeStore()
	h := NewHandler(pool, nil, fake, "drive-test", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive:                 true,
		toggle.FeatureDriveAccessGovernance: true,
	}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)
	// This test owns the HTTP translation layer, not the independently pgTAP-
	// proven shadow/cutover state machine. Put its fresh fixture directly on the
	// ACL rail so every public route below exercises the real ACL reducers.
	if _, err := pool.Exec(t.Context(), `UPDATE drive_spaces SET acl_mode='acl' WHERE id=$1`, spaceID); err != nil {
		t.Fatalf("put fixture on ACL rail: %v", err)
	}
	folderID := driveLiveCreateFolder(t, h, owner, spaceID, "acl-live-folder", nil)

	type detailOut struct {
		Epoch     string `json:"epoch"`
		CanManage bool   `json:"canManage"`
	}
	readDetail := func() detailOut {
		t.Helper()
		rr := driveLiveDo(t, h, owner, http.MethodGet, fmt.Sprintf("/drive/nodes/%d/access", folderID), nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("node access detail: status=%d body=%s", rr.Code, rr.Body.String())
		}
		var out detailOut
		driveLiveDecode(t, rr, &out)
		if !out.CanManage {
			t.Fatal("owner must manage the folder ACL")
		}
		return out
	}
	detail := readDetail()

	grantBody := map[string]any{
		"subjectKind": "user", "subjectId": strconv.FormatInt(target, 10),
		"preset": "viewer", "scope": "self", "reason": "project review",
	}
	rr := driveLiveDo(t, h, owner, http.MethodPost, fmt.Sprintf("/drive/nodes/%d/acl/preview", folderID), grantBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("grant preview: status=%d body=%s", rr.Code, rr.Body.String())
	}
	grantBody["expectedEpoch"] = detail.Epoch
	grantBody["idempotencyKey"] = fmt.Sprintf("00000000-0000-4000-8000-%012d", folderID)
	rr = driveLiveDo(t, h, owner, http.MethodPost, fmt.Sprintf("/drive/nodes/%d/acl", folderID), grantBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("grant: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var grant struct {
		GrantID string `json:"grantId"`
		Epoch   string `json:"epoch"`
	}
	driveLiveDecode(t, rr, &grant)
	if _, ok := parseDecimalID(grant.GrantID); !ok {
		t.Fatalf("grantId = %q, want decimal", grant.GrantID)
	}
	// A lost success response is safe to retry with the same body/header even
	// though the committed grant already advanced the ACL epoch.
	rr = driveLiveDo(t, h, owner, http.MethodPost, fmt.Sprintf("/drive/nodes/%d/acl", folderID), grantBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("grant replay: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var grantReplay struct {
		GrantID  string `json:"grantId"`
		Replayed bool   `json:"replayed"`
	}
	driveLiveDecode(t, rr, &grantReplay)
	if grantReplay.GrantID != grant.GrantID || !grantReplay.Replayed {
		t.Fatalf("grant replay = %+v, want same grant and replayed=true", grantReplay)
	}

	rr = driveLiveDo(t, h, owner, http.MethodGet,
		fmt.Sprintf("/drive/acl-subjects?node=%d&q=aclroutetarget", folderID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("subject search: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var subjects []aclSubjectOut
	driveLiveDecode(t, rr, &subjects)
	foundTarget := false
	for _, subject := range subjects {
		foundTarget = foundTarget || subject.ID == strconv.FormatInt(target, 10)
	}
	if !foundTarget {
		t.Fatalf("subject search = %+v, want target %d", subjects, target)
	}

	for _, view := range []string{"shared", "shares", "requests"} {
		rr = driveLiveDo(t, h, owner, http.MethodGet, "/drive/quick-views?view="+view+"&max=25", nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("quick view %s: status=%d body=%s", view, rr.Code, rr.Body.String())
		}
	}
	rr = driveLiveDo(t, h, owner, http.MethodGet, fmt.Sprintf("/drive/spaces/%d/members", spaceID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("space members: status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, owner, http.MethodDelete, "/drive/acl-grants/"+grant.GrantID,
		map[string]any{"expectedEpoch": grant.Epoch, "reason": "review completed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var revoked struct {
		Epoch string `json:"epoch"`
	}
	driveLiveDecode(t, rr, &revoked)
	rr = driveLiveDo(t, h, owner, http.MethodDelete, "/drive/acl-grants/"+grant.GrantID,
		map[string]any{"expectedEpoch": grant.Epoch, "reason": "review completed"})
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke replay: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var revokeReplay struct {
		Epoch    string `json:"epoch"`
		Replayed bool   `json:"replayed"`
	}
	driveLiveDecode(t, rr, &revokeReplay)
	if revokeReplay.Epoch != revoked.Epoch || !revokeReplay.Replayed {
		t.Fatalf("revoke replay = %+v, want epoch %s and replayed=true", revokeReplay, revoked.Epoch)
	}

	requestBody := map[string]any{
		"subjectKind": "user", "subjectId": strconv.FormatInt(owner, 10),
		"capabilities": []string{"download"}, "propagation": "self",
		"durationMinutes": 30, "reason": "temporary project review",
		"idempotencyKey": fmt.Sprintf("00000000-0000-4001-8000-%012d", folderID),
	}
	rr = driveLiveDo(t, h, owner, http.MethodPost,
		fmt.Sprintf("/drive/nodes/%d/access-requests/preview", folderID), requestBody)
	if rr.Code != http.StatusOK {
		t.Fatalf("access request preview: status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, owner, http.MethodPost,
		fmt.Sprintf("/drive/nodes/%d/access-requests", folderID), requestBody)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("already-allowed access request: status=%d body=%s, want 403", rr.Code, rr.Body.String())
	}

	epoch, ok := parseEpoch(revoked.Epoch)
	if !ok {
		t.Fatalf("revoked epoch = %q, want decimal", revoked.Epoch)
	}
	data := []byte("acl-bound-upload")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	boundPath := fmt.Sprintf("/drive/chunks/%s?space=%d&target=%d&aclEpoch=%d", sha, spaceID, folderID, epoch)
	req := httptest.NewRequest(http.MethodPut, boundPath, bytes.NewReader(data))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: owner}))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("bound chunk upload: status=%d body=%s", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodHead, boundPath, nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: owner}))
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bound chunk HEAD: status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Breaking inheritance is intentionally the terminal mutation in this
	// round-trip: the owner manages this node through the inherited space role,
	// so a successful break correctly removes the access used by the earlier
	// route assertions.
	rr = driveLiveDo(t, h, owner, http.MethodPost,
		fmt.Sprintf("/drive/nodes/%d/inheritance/preview", folderID), map[string]any{"break": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("inheritance preview: status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, owner, http.MethodPut,
		fmt.Sprintf("/drive/nodes/%d/inheritance", folderID),
		map[string]any{"break": true, "expectedEpoch": revoked.Epoch})
	if rr.Code != http.StatusOK {
		t.Fatalf("inheritance set: status=%d body=%s", rr.Code, rr.Body.String())
	}
}
