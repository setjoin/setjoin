package drive

// P5 export-grant route tests (spec §7, §9.2). Reuses the P1 live-DB harness
// (live_helpers_test.go, content_live_test.go) plus a small gxp-space fixture
// for the approval-routed pending path.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// withFeatureToggleEnabled flips a DB-level feature_toggles row on for the
// duration of the test, restoring its prior value on cleanup. Distinct from
// the Go-side toggle.FeatureFlags NewHandler takes for G5 (feature.drive) —
// this is the DB-side gate drive_space_create checks for gxp classification
// (feature.drive_compliance).
func withFeatureToggleEnabled(t *testing.T, pool *pgxpool.Pool, key string) {
	t.Helper()
	ctx := context.Background()
	var prev bool
	if err := pool.QueryRow(ctx, `SELECT enabled FROM feature_toggles WHERE key=$1`, key).Scan(&prev); err != nil {
		t.Fatalf("read toggle %s: %v", key, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE feature_toggles SET enabled=true WHERE key=$1`, key); err != nil {
		t.Fatalf("enable toggle %s: %v", key, err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `UPDATE feature_toggles SET enabled=$2 WHERE key=$1`, key, prev) //nolint:errcheck
	})
}

// driveLiveCreateGxpSpace creates a gxp space (requires feature.drive_compliance).
func driveLiveCreateGxpSpace(t *testing.T, h *Handler, userID int64) int64 {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name": "Gxp Space", "classification": "gxp",
		"retentionDays": 30, "wormMode": "governance",
	})
	req := httptest.NewRequest(http.MethodPost, "/drive/spaces", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("POST /drive/spaces (gxp): want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode space: %v", err)
	}
	return out.ID
}

func TestMintExportToken(t *testing.T) {
	tok1, hash1, err := mintExportToken()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(tok1) != 43 {
		t.Errorf("token length = %d, want 43 (32 bytes, base64url no padding)", len(tok1))
	}
	if len(hash1) != 64 {
		t.Errorf("hash length = %d, want 64 (sha256 hex)", len(hash1))
	}
	sum := sha256.Sum256([]byte(tok1))
	if hash1 != hex.EncodeToString(sum[:]) {
		t.Error("hash does not match sha256(token)")
	}
	tok2, hash2, err := mintExportToken()
	if err != nil {
		t.Fatalf("mint 2: %v", err)
	}
	if tok1 == tok2 || hash1 == hash2 {
		t.Error("two mints produced the same token/hash")
	}
}

// TestExportRequest_ToggleOff pins G5: feature.drive OFF -> 404, even with a
// well-formed body.
func TestExportRequest_ToggleOff(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvexpoff")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": false}), discardLogger())

	body, _ := json.Marshal(map[string]any{"versionId": 1, "action": "download"})
	req := httptest.NewRequest(http.MethodPost, "/drive/export", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Errorf("toggle off: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestExportRequest_InvalidAction pins the BZ141 -> 422 mapping (drive/problem.go's
// bzSlug + reducererr.Classify — ClassUnprocessable).
func TestExportRequest_InvalidAction(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvexpbad")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "r.pdf", []byte("hi"))
	_ = versionID

	body, _ := json.Marshal(map[string]any{"versionId": versionID, "action": "email"})
	req := httptest.NewRequest(http.MethodPost, "/drive/export", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid action: want 422, got %d: %s", rr.Code, rr.Body.String())
	}
	var prob struct {
		Code string `json:"code"`
	}
	json.Unmarshal(rr.Body.Bytes(), &prob) //nolint:errcheck
	if prob.Code != "BZ141" {
		t.Errorf("problem code = %q, want BZ141", prob.Code)
	}
	_ = nodeID
}

// TestExportRequest_GrantedThenConsumeStreams covers the whole happy path on
// a regular space (export policy defaults to 'allow'): granted response
// carries a 43-char token, the DB holds ONLY its hash (never the plaintext),
// GET streams the exact bytes with Content-Disposition: attachment, and a
// second GET on the same token is refused (single-use).
func TestExportRequest_GrantedThenConsumeStreams(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvexpok")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), testsupport.TestLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	data := []byte("exportable content")
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "report.txt", data)
	_ = nodeID

	body, _ := json.Marshal(map[string]any{"versionId": versionID, "action": "download"})
	req := httptest.NewRequest(http.MethodPost, "/drive/export", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST export request: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var granted struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &granted); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if granted.Status != "granted" {
		t.Fatalf("status = %q, want granted", granted.Status)
	}
	if len(granted.Token) != 43 {
		t.Fatalf("token length = %d, want 43", len(granted.Token))
	}

	// The DB holds ONLY the hash — never the plaintext token.
	hash := hashExportToken(granted.Token)
	var dbHash string
	if err := pool.QueryRow(context.Background(),
		`SELECT token_hash FROM drive_export_grants WHERE token_hash = $1`, hash,
	).Scan(&dbHash); err != nil {
		t.Fatalf("expected a grant row keyed by the hash: %v", err)
	}

	// Consume: streams the exact bytes with an attachment disposition.
	getReq := httptest.NewRequest(http.MethodGet, "/drive/export/"+granted.Token, nil)
	getReq = getReq.WithContext(auth.ContextWithUser(getReq.Context(), &auth.Claims{UserID: userID}))
	getRR := httptest.NewRecorder()
	h.ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("GET export/token: want 200, got %d: %s", getRR.Code, getRR.Body.String())
	}
	if !bytes.Equal(getRR.Body.Bytes(), data) {
		t.Errorf("streamed body = %q, want %q", getRR.Body.Bytes(), data)
	}
	if disp := getRR.Header().Get("Content-Disposition"); !strings.HasPrefix(disp, "attachment;") {
		t.Errorf("Content-Disposition = %q, want attachment", disp)
	}

	// Second GET on the same (now-consumed) token is refused, not re-streamed.
	getReq2 := httptest.NewRequest(http.MethodGet, "/drive/export/"+granted.Token, nil)
	getReq2 = getReq2.WithContext(auth.ContextWithUser(getReq2.Context(), &auth.Claims{UserID: userID}))
	getRR2 := httptest.NewRecorder()
	h.ServeHTTP(getRR2, getReq2)
	if getRR2.Code == http.StatusOK {
		t.Errorf("second GET on a consumed token: want a refusal status, got 200 (single-use violated)")
	}
}

// TestExportRequest_UnknownTokenRefused pins the opaque BZ146 outcome for a
// token that was never minted — the shipped classification (reducererr.go)
// is ClassConflict -> 409, not a distinguishable 404/403 (drive_export_consume.sql:
// "ALL failure modes are BZ146 ... deliberately indistinguishable").
func TestExportRequest_UnknownTokenRefused(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvexpunk")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	req := httptest.NewRequest(http.MethodGet, "/drive/export/"+strings.Repeat("z", 43), nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusConflict {
		t.Errorf("unknown token: want 409 (BZ146, opaque), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestExportRequest_GxpPendingCarriesToken pins the "resolved spec conflict"
// (plan Global Constraints): a gxp space ALWAYS routes export through
// approval, and the plaintext token is returned even on "pending" — the
// approval-decide wrapper mints the grant from the payload's token_hash at
// DECIDE time, so a hash-only store cannot hand back the plaintext later.
func TestExportRequest_GxpPendingCarriesToken(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvexpgxp")
	withFeatureToggleEnabled(t, pool, "feature.drive_compliance")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), testsupport.TestLogger())
	// A healthy Retention so the version's WORM lock actually applies at
	// put-version time (G1 must not itself block the request below — this
	// test is about the SEPARATE gxp-always-requires-approval policy gate,
	// not the WORM-pending gate).
	h.SetRetention(&fakeRetention{failKeys: map[string]bool{}})
	spaceID := driveLiveCreateGxpSpace(t, h, userID)
	_, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "gxp.txt", []byte("gxp content"))

	body, _ := json.Marshal(map[string]any{"versionId": versionID, "action": "download"})
	req := httptest.NewRequest(http.MethodPost, "/drive/export", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST export request (gxp): want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var pending struct {
		Status    string `json:"status"`
		RequestID int64  `json:"requestId"`
		Token     string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if pending.Status != "pending" {
		t.Fatalf("status = %q, want pending (gxp always routes through approval)", pending.Status)
	}
	if pending.RequestID == 0 {
		t.Error("expected a non-zero requestId")
	}
	if len(pending.Token) != 43 {
		t.Fatalf("token length = %d, want 43 (pending must still carry the plaintext)", len(pending.Token))
	}
	// No grant row exists yet — it is minted at DECIDE time (G2), not now.
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM drive_export_grants WHERE token_hash = $1`, hashExportToken(pending.Token),
	).Scan(&count); err != nil {
		t.Fatalf("count grants: %v", err)
	}
	if count != 0 {
		t.Errorf("grant rows for the pending token = %d, want 0 (minted at decide time only)", count)
	}
}
