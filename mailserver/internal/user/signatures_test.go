package user

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
)

func TestSignaturesListEmpty(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)

	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}
	req := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec.Code)
	}

	var resp []map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp) != 0 {
		t.Errorf("expected empty list, got %d signatures", len(resp))
	}
}

func TestSignaturesCreateThenList(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	// PUT: create a signature for an alias.
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "work@setjoin.test",
		"signature_html": "<p>Best,<br/>Alice</p>",
		"signature_text": "Best,\nAlice",
		"is_default":     "true",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// GET and verify.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.List(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec2.Code)
	}

	var sigs []map[string]interface{}
	if err := json.NewDecoder(rec2.Body).Decode(&sigs); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if sigs[0]["alias_email"] != "work@setjoin.test" {
		t.Errorf("alias_email = %v, want work@setjoin.test", sigs[0]["alias_email"])
	}
	if sigs[0]["signature_html"] != "<p>Best,<br/>Alice</p>" {
		t.Errorf("signature_html = %v", sigs[0]["signature_html"])
	}
}

func TestSignaturesUpdate(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	// Create a signature first.
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "sales@setjoin.test",
		"signature_html": "Old sig",
		"signature_text": "Old sig",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Update it via PUT with same alias_email.
	body2, _ := json.Marshal(map[string]string{
		"alias_email":    "sales@setjoin.test",
		"signature_html": "New sig HTML",
		"signature_text": "New sig text",
	})
	req2 := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body2))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.Put(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("PUT update returned %d, want 200: %s", rec2.Code, rec2.Body.String())
	}

	// Verify update: still only 1 signature, with new content.
	req3 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), claims))
	rec3 := httptest.NewRecorder()
	h.List(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("GET returned %d, want 200", rec3.Code)
	}

	var sigs []map[string]interface{}
	json.NewDecoder(rec3.Body).Decode(&sigs)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if sigs[0]["signature_html"] != "New sig HTML" {
		t.Errorf("signature_html not updated: got %v", sigs[0]["signature_html"])
	}
	if sigs[0]["signature_text"] != "New sig text" {
		t.Errorf("signature_text not updated: got %v", sigs[0]["signature_text"])
	}
}

func TestSignaturesDelete(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	// Create a signature.
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "temp@setjoin.test",
		"signature_html": "Will be deleted",
		"signature_text": "Will be deleted",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Get the signature ID.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.List(rec2, req2)
	var sigs []map[string]interface{}
	json.NewDecoder(rec2.Body).Decode(&sigs)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature before delete, got %d", len(sigs))
	}
	sigID := sigs[0]["id"].(float64)

	// Delete it.
	req3 := httptest.NewRequest(http.MethodDelete, "/settings/signatures/"+fmt.Sprintf("%d", int64(sigID)), nil)
	req3.SetPathValue("id", fmt.Sprintf("%d", int64(sigID)))
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), claims))
	rec3 := httptest.NewRecorder()
	h.Delete(rec3, req3)
	if rec3.Code != http.StatusOK && rec3.Code != http.StatusNoContent {
		t.Fatalf("DELETE returned %d, want 200 or 204: %s", rec3.Code, rec3.Body.String())
	}

	// Verify empty.
	req4 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req4 = req4.WithContext(auth.ContextWithUser(req4.Context(), claims))
	rec4 := httptest.NewRecorder()
	h.List(rec4, req4)
	var sigs2 []map[string]interface{}
	json.NewDecoder(rec4.Body).Decode(&sigs2)
	if len(sigs2) != 0 {
		t.Errorf("expected 0 signatures after delete, got %d", len(sigs2))
	}
}

func TestSignaturesUnauthorized(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	req := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET without auth returned %d, want 401", rec.Code)
	}
}

// TestSignaturesRejectsOversizedBody pins the ER5
// occ_32e2290b6545ec3b8e1f780b admission bound: a PUT body beyond
// maxSignatureBodyBytes never reaches storage — the MaxBytesReader trips the
// JSON decode and the handler answers 400 before any user_signatures write.
func TestSignaturesRejectsOversizedBody(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	oversized := strings.Repeat("A", maxSignatureBodyBytes+1)
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "flood@setjoin.test",
		"signature_html": oversized,
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body returned %d, want 400", rec.Code)
	}

	// Nothing was persisted.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.List(rec2, req2)
	var sigs []map[string]interface{}
	json.NewDecoder(rec2.Body).Decode(&sigs)
	if len(sigs) != 0 {
		t.Fatalf("oversized body persisted %d signature(s), want 0", len(sigs))
	}
}

// TestSignaturesRejectsOversizedFields pins the per-field stored bounds: an
// in-budget body carrying a signature_html/text beyond the persisted caps is
// refused, so one alias can never anchor an unbounded user_signatures row.
func TestSignaturesRejectsOversizedFields(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	cases := []struct {
		name    string
		mutate  func(map[string]string)
		wantErr string
	}{
		{"signature_html over cap", func(m map[string]string) {
			// Plain ASCII (no JSON escaping) keeps the body under the body cap
			// so the FIELD cap is what rejects this request.
			m["signature_html"] = strings.Repeat("x", maxSignatureHTMLBytes+1)
		}, "signature_html is too long"},
		{"signature_text over cap", func(m map[string]string) {
			m["signature_text"] = strings.Repeat("x", maxSignatureTextBytes+1)
		}, "signature_text is too long"},
		{"alias_email over cap", func(m map[string]string) {
			m["alias_email"] = strings.Repeat("a", maxSignatureAliasEmail+1) + "@setjoin.test"
		}, "alias_email is too long"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]string{
				"alias_email":    "fields@setjoin.test",
				"signature_html": "ok",
				"signature_text": "ok",
			}
			tc.mutate(fields)
			body, _ := json.Marshal(fields)
			req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
			rec := httptest.NewRecorder()
			h.Put(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: returned %d, want 400", tc.name, rec.Code)
			}
			if !strings.Contains(rec.Body.String(), tc.wantErr) {
				t.Fatalf("%s: body %q does not name the exceeded field", tc.name, rec.Body.String())
			}
		})
	}

	// Boundary: exactly-at-cap values are accepted (the caps bind above, not at
	// the practical signature size — keep the happy path proven against the DB).
	fields := map[string]string{
		"alias_email":    "boundary@setjoin.test",
		"signature_html": strings.Repeat("h", maxSignatureHTMLBytes),
		"signature_text": strings.Repeat("t", maxSignatureTextBytes),
	}
	body, _ := json.Marshal(fields)
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("at-cap fields returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// TestSignaturesPerUserRowCap pins the ER5 occ_9979c4508a62dc7bf33c6857
// stored-row admission bound: after maxSignaturesPerUser rows, a NEW alias is
// refused 400 and persists nothing, while updating an existing alias at the
// cap still succeeds (the cap bounds rows, not edits).
func TestSignaturesPerUserRowCap(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	put := func(alias string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{
			"alias_email":    alias,
			"signature_html": "sig for " + alias,
			"signature_text": "sig for " + alias,
		})
		req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.Put(rec, req)
		return rec
	}

	// Fill the user to exactly the cap.
	for i := 0; i < maxSignaturesPerUser; i++ {
		alias := fmt.Sprintf("cap-%03d@setjoin.test", i)
		if rec := put(alias); rec.Code != http.StatusOK {
			t.Fatalf("fill PUT %s returned %d, want 200: %s", alias, rec.Code, rec.Body.String())
		}
	}

	// One more NEW alias is refused with the named limit error.
	rec := put("over-cap@setjoin.test")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-cap PUT returned %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "signature limit reached") {
		t.Fatalf("over-cap body %q does not name the limit", rec.Body.String())
	}

	// Updating an existing alias at the cap still works (row count unchanged).
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "cap-000@setjoin.test",
		"signature_html": "updated at cap",
		"signature_text": "updated at cap",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec2 := httptest.NewRecorder()
	h.Put(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("at-cap update returned %d, want 200: %s", rec2.Code, rec2.Body.String())
	}

	// Exactly cap rows exist and nothing extra was persisted by the refusal.
	var stored int
	if err := pool.QueryRow(t.Context(),
		`SELECT COUNT(*) FROM user_signatures WHERE user_id = $1`, userID,
	).Scan(&stored); err != nil {
		t.Fatalf("count stored: %v", err)
	}
	if stored != maxSignaturesPerUser {
		t.Fatalf("stored %d signatures, want exactly %d (refusal must not persist)", stored, maxSignaturesPerUser)
	}

	// Another user is unaffected by the first user's cap.
	other := createTestUser(t, pool)
	otherClaims := &auth.Claims{UserID: other, Type: auth.TypeAccess}
	body3, _ := json.Marshal(map[string]string{
		"alias_email":    "other-user@setjoin.test",
		"signature_html": "independent cap",
		"signature_text": "independent cap",
	})
	req3 := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body3))
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), otherClaims))
	rec3 := httptest.NewRecorder()
	h.Put(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("other-user PUT returned %d, want 200: %s", rec3.Code, rec3.Body.String())
	}
}

// TestSignaturesCountFailure_ClosedPool_500 drives the row-cap COUNT query's
// failure arm (closed-pool pattern from TestImport_InsertFailure_ClosedPool_500):
// the per-user admission count fails closed with 500 — a signature is never
// stored when its admission bound cannot be evaluated.
func TestSignaturesCountFailure_ClosedPool_500(t *testing.T) {
	closed := testPool(t)
	closed.Close()
	h := NewSignatureHandler(closed, testLogger())

	claims := &auth.Claims{UserID: 1, Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "closed-pool@setjoin.test",
		"signature_html": "must not persist",
		"signature_text": "must not persist",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
	rec := httptest.NewRecorder()
	h.Put(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("closed pool PUT: want 500, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestSignaturesCannotDeleteOtherUser(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID1 := createTestUser(t, pool)
	userID2 := createTestUser(t, pool)

	// User 1 creates a signature.
	claims1 := &auth.Claims{UserID: userID1, Type: auth.TypeAccess}
	body, _ := json.Marshal(map[string]string{
		"alias_email":    "private@setjoin.test",
		"signature_html": "User 1 sig",
		"signature_text": "User 1 sig",
	})
	req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), claims1))
	rec := httptest.NewRecorder()
	h.Put(rec, req)

	// Get the signature ID.
	req2 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims1))
	rec2 := httptest.NewRecorder()
	h.List(rec2, req2)
	var sigs []map[string]interface{}
	json.NewDecoder(rec2.Body).Decode(&sigs)
	if len(sigs) == 0 {
		t.Fatal("signature not created")
	}
	sigID := sigs[0]["id"].(float64)

	// User 2 tries to delete User 1's signature — should fail.
	claims2 := &auth.Claims{UserID: userID2, Type: auth.TypeAccess}
	req3 := httptest.NewRequest(http.MethodDelete, "/settings/signatures/"+fmt.Sprintf("%d", int64(sigID)), nil)
	req3.SetPathValue("id", fmt.Sprintf("%d", int64(sigID)))
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), claims2))
	rec3 := httptest.NewRecorder()
	h.Delete(rec3, req3)
	if rec3.Code != http.StatusNotFound && rec3.Code != http.StatusForbidden {
		t.Fatalf("expected 404 or 403 for cross-user delete, got %d", rec3.Code)
	}
}

func TestSignatureIsDefault(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	// Create first signature with is_default=true.
	body1, _ := json.Marshal(map[string]string{
		"alias_email":    "primary@setjoin.test",
		"signature_html": "Primary sig",
		"signature_text": "Primary sig",
		"is_default":     "true",
	})
	req1 := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body1))
	req1 = req1.WithContext(auth.ContextWithUser(req1.Context(), claims))
	h.Put(httptest.NewRecorder(), req1)

	// Create second signature with is_default=true — should replace default.
	body2, _ := json.Marshal(map[string]string{
		"alias_email":    "secondary@setjoin.test",
		"signature_html": "Secondary sig",
		"signature_text": "Secondary sig",
		"is_default":     "true",
	})
	req2 := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body2))
	req2 = req2.WithContext(auth.ContextWithUser(req2.Context(), claims))
	h.Put(httptest.NewRecorder(), req2)

	// Verify only the second is default.
	req3 := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
	req3 = req3.WithContext(auth.ContextWithUser(req3.Context(), claims))
	rec3 := httptest.NewRecorder()
	h.List(rec3, req3)
	var sigs []map[string]interface{}
	json.NewDecoder(rec3.Body).Decode(&sigs)
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
	defaultCount := 0
	for _, s := range sigs {
		if v, ok := s["is_default"].(bool); ok && v {
			defaultCount++
		}
	}
	if defaultCount != 1 {
		t.Errorf("expected exactly 1 default, got %d", defaultCount)
	}
}

// TestSignatureDefaultForRoundTrip exercises the A1 new-vs-reply discriminator:
// default_for persists and is returned by List, and the "at most one signature
// holds each role per user" invariant is enforced via the set_signature_default
// reducer wired into Put().
func TestSignatureDefaultForRoundTrip(t *testing.T) {
	pool := testPool(t)
	h := NewSignatureHandler(pool, testLogger())

	userID := createTestUser(t, pool)
	claims := &auth.Claims{UserID: userID, Type: auth.TypeAccess}

	putSig := func(alias, defaultFor string) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{
			"alias_email":    alias,
			"signature_html": "<p>" + alias + "</p>",
			"signature_text": alias,
			"default_for":    defaultFor,
		})
		req := httptest.NewRequest(http.MethodPut, "/settings/signatures", bytes.NewReader(body))
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.Put(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s default_for=%s returned %d: %s", alias, defaultFor, rec.Code, rec.Body.String())
		}
	}

	list := func() []map[string]interface{} {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/settings/signatures", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.List(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET returned %d", rec.Code)
		}
		var sigs []map[string]interface{}
		if err := json.NewDecoder(rec.Body).Decode(&sigs); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return sigs
	}

	// Signature A becomes the 'new' default.
	putSig("a@setjoin.test", "new")
	sigs := list()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if sigs[0]["default_for"] != "new" {
		t.Fatalf("A default_for = %v, want new (round-trip via List)", sigs[0]["default_for"])
	}

	// Signature B also claims 'new' — the invariant requires A to be cleared.
	putSig("b@setjoin.test", "new")
	sigs = list()
	if len(sigs) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(sigs))
	}
	byAlias := map[string]string{}
	for _, s := range sigs {
		df, _ := s["default_for"].(string)
		byAlias[s["alias_email"].(string)] = df
	}
	if byAlias["b@setjoin.test"] != "new" {
		t.Errorf("B default_for = %q, want new", byAlias["b@setjoin.test"])
	}
	if byAlias["a@setjoin.test"] != "none" {
		t.Errorf("A default_for = %q, want none (cleared when B claimed 'new')", byAlias["a@setjoin.test"])
	}

	// Exactly one signature holds the 'new' role.
	newCount := 0
	for _, df := range byAlias {
		if df == "new" {
			newCount++
		}
	}
	if newCount != 1 {
		t.Errorf("expected exactly 1 'new' default, got %d", newCount)
	}

	// 'reply' is an independent role: B can hold 'new' while A holds 'reply'.
	putSig("a@setjoin.test", "reply")
	sigs = list()
	byAlias = map[string]string{}
	for _, s := range sigs {
		df, _ := s["default_for"].(string)
		byAlias[s["alias_email"].(string)] = df
	}
	if byAlias["a@setjoin.test"] != "reply" {
		t.Errorf("A default_for = %q, want reply (independent role)", byAlias["a@setjoin.test"])
	}
	if byAlias["b@setjoin.test"] != "new" {
		t.Errorf("B default_for = %q, want new (reply flip must not clear new)", byAlias["b@setjoin.test"])
	}
}
