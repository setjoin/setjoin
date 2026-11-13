package drive

// Chat A2 Task 4 — the Go DB test the plan calls for: a chat channel member
// with NO drive_space_members row passes the canonical bound-space adapter
// used by the HEAD/PUT chunk path, while a non-member fails.
// Skip-if-no-DB, the chunks_live_test.go genre — real reducers, fake object
// store (no live MinIO test lane).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestChatBoundSpace_DerivedMemberScope_Live(t *testing.T) {
	pool := driveLivePool(t)
	ctx := t.Context()

	owner := driveLiveUser(t, pool, "msA")
	member := driveLiveUser(t, pool, "msB")
	outsider := driveLiveUser(t, pool, "msC")

	var channelID int64
	if err := pool.QueryRow(ctx, `SELECT chat_channel_create($1, $2)`, owner, "memberscope-test-chan").Scan(&channelID); err != nil {
		t.Fatalf("chat_channel_create: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT chat_channel_join($1, $2)`, member, channelID); err != nil {
		t.Fatalf("chat_channel_join: %v", err)
	}
	var spaceID int64
	if err := pool.QueryRow(ctx, `SELECT chat_space_ensure($1, $2)`, owner, channelID).Scan(&spaceID); err != nil {
		t.Fatalf("chat_space_ensure: %v", err)
	}

	var adhocRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM drive_space_members WHERE space_id = $1`, spaceID).Scan(&adhocRows); err != nil {
		t.Fatalf("count drive_space_members: %v", err)
	}
	if adhocRows != 0 {
		t.Fatalf("chat-bound space has %d ad-hoc drive_space_members rows, want 0 (DES-009 D2)", adhocRows)
	}

	fake := newFakeStore()
	h := NewHandler(pool, pool, fake, "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceParam := strconv.FormatInt(spaceID, 10)

	// Grill D1 (Chat A2 Task 5): the chat-bound space is HIDDEN from the
	// /drive space list entirely — user AND admin — even though derivation
	// still authorizes both the owner and the plain member underneath (proven
	// by the chunk HEAD/PUT round trip below). Reached only via chat + a
	// per-file "Open in Drive" deep-link (DES-009 D5), never browsed as a
	// Drive workspace.
	for _, tc := range []struct {
		label string
		user  int64
	}{
		{"owner", owner},
		{"member", member},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/drive/spaces", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: tc.user}))
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s GET /drive/spaces: want 200, got %d: %s", tc.label, rr.Code, rr.Body.String())
		}
		var spaces []struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &spaces); err != nil {
			t.Fatalf("%s decode spaces: %v body=%s", tc.label, err, rr.Body.String())
		}
		for _, sp := range spaces {
			if sp.ID == spaceID {
				t.Errorf("%s space list includes the chat-bound space %d, want hidden (Grill D1)", tc.label, spaceID)
			}
		}
	}

	// The admin ?admin=1 list hides it too — a super admin with drive.view.
	if _, err := pool.Exec(ctx,
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, owner); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(ctx, `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, owner) //nolint:errcheck
	})
	adminRR := httptest.NewRecorder()
	adminReq := httptest.NewRequest(http.MethodGet, "/drive/spaces?admin=1", nil)
	adminReq = adminReq.WithContext(auth.ContextWithUser(adminReq.Context(), &auth.Claims{UserID: owner}))
	h.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusOK {
		t.Fatalf("admin GET /drive/spaces?admin=1: want 200, got %d: %s", adminRR.Code, adminRR.Body.String())
	}
	var adminSpaces []struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(adminRR.Body.Bytes(), &adminSpaces); err != nil {
		t.Fatalf("decode admin spaces: %v body=%s", err, adminRR.Body.String())
	}
	for _, sp := range adminSpaces {
		if sp.ID == spaceID {
			t.Errorf("admin space list includes the chat-bound space %d, want hidden (Grill D1)", spaceID)
		}
	}

	// HEAD/PUT chunk authorization: the derived member (no drive_space_members
	// row) can PUT then HEAD a chunk in the chat-bound space.
	data := []byte("chat-bound derived-membership chunk round trip")
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])

	putReq := httptest.NewRequest(http.MethodPut, "/drive/chunks/"+sha+"?space="+spaceParam, strings.NewReader(string(data)))
	putReq = putReq.WithContext(auth.ContextWithUser(putReq.Context(), &auth.Claims{UserID: member}))
	putRR := httptest.NewRecorder()
	h.ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusCreated {
		t.Fatalf("derived member PUT chunk: want 201, got %d: %s", putRR.Code, putRR.Body.String())
	}

	headReq := httptest.NewRequest(http.MethodHead, "/drive/chunks/"+sha+"?space="+spaceParam, nil)
	headReq = headReq.WithContext(auth.ContextWithUser(headReq.Context(), &auth.Claims{UserID: member}))
	headRR := httptest.NewRecorder()
	h.ServeHTTP(headRR, headReq)
	if headRR.Code != http.StatusOK {
		t.Errorf("derived member HEAD chunk after own PUT: want 200, got %d", headRR.Code)
	}

	// A non-member of the channel fails both the HEAD probe and a PUT attempt
	// — the anti-oracle 404, never a distinguishable "space exists" signal.
	outHeadReq := httptest.NewRequest(http.MethodHead, "/drive/chunks/"+sha+"?space="+spaceParam, nil)
	outHeadReq = outHeadReq.WithContext(auth.ContextWithUser(outHeadReq.Context(), &auth.Claims{UserID: outsider}))
	outHeadRR := httptest.NewRecorder()
	h.ServeHTTP(outHeadRR, outHeadReq)
	if outHeadRR.Code != http.StatusNotFound {
		t.Errorf("non-member HEAD chunk: want 404, got %d", outHeadRR.Code)
	}

	otherData := []byte(fmt.Sprintf("outsider attempt %d", outsider))
	otherSum := sha256.Sum256(otherData)
	otherSha := hex.EncodeToString(otherSum[:])
	outPutReq := httptest.NewRequest(http.MethodPut, "/drive/chunks/"+otherSha+"?space="+spaceParam, strings.NewReader(string(otherData)))
	outPutReq = outPutReq.WithContext(auth.ContextWithUser(outPutReq.Context(), &auth.Claims{UserID: outsider}))
	outPutRR := httptest.NewRecorder()
	h.ServeHTTP(outPutRR, outPutReq)
	if outPutRR.Code != http.StatusNotFound {
		t.Errorf("non-member PUT chunk: want 404, got %d: %s", outPutRR.Code, outPutRR.Body.String())
	}
}
