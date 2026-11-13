package admin

// Body-cap tests for the content-search handlers (er5-s15, sealed anchor
// admin-kql-recursive-parser): the KQL length/depth/term caps fire only AFTER
// the request has been decoded, so the decode itself must be bounded by the
// repo's MaxBytesReader precedent (telemetry 64KB) — an unbounded json.Decoder
// would buffer attacker-sized bytes before any shape check could run.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/testsupport"
)

// contentSearchOversized returns a VALID search request (parses cleanly, the
// shape checks would pass) whose byte size exceeds maxContentSearchBodyBytes.
func contentSearchOversized() []byte {
	payload := map[string]any{
		"keywords": strings.Repeat("a", maxContentSearchBodyBytes+64),
	}
	raw, _ := json.Marshal(payload)
	return raw
}

// TestContentSearch_SearchOversizedBodyRejected: an over-cap body is refused
// at the decode boundary with a bounded 400 — the request never reaches the
// FTS query path.
func TestContentSearch_SearchOversizedBodyRejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/search", bytes.NewReader(contentSearchOversized()))
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized Search body status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid request") {
		t.Fatalf("detail = %s, want the bounded decode refusal", rec.Body.String())
	}
}

// TestContentSearch_DeleteSelectedOversizedBodyRejected: the mass-delete
// handler is bounded at the decode boundary too (its 1-500 ids cap runs only
// after the body is buffered).
func TestContentSearch_DeleteSelectedOversizedBodyRejected(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	payload := map[string]any{
		"ids":    []int{1},
		"reason": strings.Repeat("r", maxContentSearchBodyBytes+64),
	}
	raw, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/delete", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	h.DeleteSelected(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized DeleteSelected body status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestContentSearch_DeleteSelectedUnderCapBodyDecodes: a valid under-cap body
// passes the decode boundary and reaches the handler's own shape validation —
// an ids-less request is rejected with the bounded ids message (never the
// decode refusal), proving the cap admits ordinary requests.
func TestContentSearch_DeleteSelectedUnderCapBodyDecodes(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{"ids": []int{}, "reason": "compliance purge request"})
	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/delete", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.DeleteSelected(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("ids-less body status = %d, want the handler's 400 (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "1-500 ids") {
		t.Fatalf("detail = %s, want the handler's own ids validation (decode must have succeeded)", rec.Body.String())
	}
}

// TestContentSearch_UnderCapBodyReachesHandler: the cap admits ordinary
// requests — a normal-sized request passes the decode boundary (its verdict
// beyond that — auth/DB — is out of scope here; a keywords-less body proves
// the handler's own validation ran, i.e. the decode itself did not refuse).
func TestContentSearch_UnderCapBodyReachesHandler(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewContentSearchHandler(pgxutil.WorkerPool{Pool: pool}, testsupport.TestLogger())

	body, _ := json.Marshal(map[string]any{"unrelated": true})
	req := httptest.NewRequest(http.MethodPost, "/admin/content-search/search", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.Search(rec, req)

	if rec.Code == http.StatusBadRequest && strings.Contains(rec.Body.String(), "invalid request") {
		t.Fatalf("under-cap body was refused at the decode boundary: %s", rec.Body.String())
	}
}
