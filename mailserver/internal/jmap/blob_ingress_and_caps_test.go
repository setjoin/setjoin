package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/pgxutil"
)

// Coverage for the Blob/get ingress branches (bounded-args and ownership read)
// and the Session apps_caps_strict capability advertisement.

// TestBlobGetIngressBranches pins the Blob/get request validation branches:
// malformed JSON → invalidArguments error, empty ids → empty list echoing the
// client-controlled accountId via structured marshal, and the >256 id cap →
// empty list (never a request-sized query).
func TestBlobGetIngressBranches(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	ctx := context.Background()
	_, userID, mailboxID := insertTestUserWithMailbox(t, pool, false)
	blobSha := insertTestMessageWithAttachment(t, pool, mailboxID)
	user := &auth.Claims{UserID: userID}

	// Malformed JSON args.
	name, raw := h.blobGet(ctx, user, json.RawMessage(`{not-json`))
	if name != "error" {
		t.Fatalf("blobGet(malformed): got %s / %s", name, raw)
	}

	// Empty ids: empty list + notFound, accountId echoed verbatim (structured,
	// never concatenated).
	name, raw = h.blobGet(ctx, user, json.RawMessage(`{"accountId":"acc-1","ids":[]}`))
	if name != "Blob/get" {
		t.Fatalf("blobGet(empty ids): got %s / %s", name, raw)
	}
	var emptyResp struct {
		List      []any  `json:"list"`
		NotFound  []any  `json:"notFound"`
		AccountID string `json:"accountId"`
	}
	if err := json.Unmarshal(raw, &emptyResp); err != nil {
		t.Fatalf("unmarshal empty-ids response: %v (%s)", err, raw)
	}
	if len(emptyResp.List) != 0 || len(emptyResp.NotFound) != 0 || emptyResp.AccountID != "acc-1" {
		t.Fatalf("empty-ids response = %+v", emptyResp)
	}

	// Id-count cap: 257 ids → empty list, accountId echoed.
	ids := make([]string, 257)
	for i := range ids {
		ids[i] = fmt.Sprintf("blob-%d", i)
	}
	args, _ := json.Marshal(map[string]any{"accountId": "acc-2", "ids": ids})
	name, raw = h.blobGet(ctx, user, args)
	if name != "Blob/get" {
		t.Fatalf("blobGet(over cap): got %s / %s", name, raw)
	}
	if err := json.Unmarshal(raw, &emptyResp); err != nil {
		t.Fatalf("unmarshal over-cap response: %v (%s)", err, raw)
	}
	if len(emptyResp.List) != 0 || emptyResp.AccountID != "acc-2" {
		t.Fatalf("over-cap response = %+v", emptyResp)
	}

	// Ownership read: the user's own attached blob is found, an unknown id is
	// reported notFound with the echoed accountId.
	args, _ = json.Marshal(map[string]any{"accountId": strconv.FormatInt(mailboxID, 10), "ids": []string{blobSha, "blob-does-not-exist"}})
	name, raw = h.blobGet(ctx, user, args)
	if name != "Blob/get" {
		t.Fatalf("blobGet(owned): got %s / %s", name, raw)
	}
	var resp struct {
		List []struct {
			ID string `json:"id"`
		} `json:"list"`
		NotFound []string `json:"notFound"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal owned response: %v (%s)", err, raw)
	}
	if len(resp.List) != 1 || resp.List[0].ID != blobSha {
		t.Fatalf("owned list = %+v, want exactly [%s]", resp.List, blobSha)
	}
	if len(resp.NotFound) != 1 || resp.NotFound[0] != "blob-does-not-exist" {
		t.Fatalf("notFound = %v, want [blob-does-not-exist]", resp.NotFound)
	}
}

// TestSessionAdvertisesAppsStrictEntitlements pins the TYPES-002 capability
// advertisement: with system_config apps_caps_strict set to an accepted
// literal, the vendor capability block carries appsStrictEntitlements=true;
// with the key absent, the field is omitted (documented default-allow window).
func TestSessionAdvertisesAppsStrictEntitlements(t *testing.T) {
	pool := testPoolDB(t)
	h := NewJMAPHandler(pool, pgxutil.WorkerPool{Pool: pool}, "localhost", nil, "test-bucket", 10_000_000, testLoggerDB(t))
	_, userID, _ := insertTestUserWithMailbox(t, pool, false)
	claims := &auth.Claims{UserID: userID, Email: "apps-strict@test.example"}

	restore := func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM system_config WHERE key='apps_caps_strict'`)
	}
	restore()
	t.Cleanup(restore)

	getVendor := func(t *testing.T) map[string]any {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/jmap/session", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rr := httptest.NewRecorder()
		h.Session(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("Session status = %d: %s", rr.Code, rr.Body.String())
		}
		var sess struct {
			Capabilities map[string]map[string]any `json:"capabilities"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &sess); err != nil {
			t.Fatalf("unmarshal session: %v (%s)", err, rr.Body.String())
		}
		return sess.Capabilities[VendorCapability]
	}

	// Absent key → field omitted.
	if vendor := getVendor(t); vendor["appsStrictEntitlements"] != nil {
		t.Fatalf("absent toggle: appsStrictEntitlements = %v, want omitted", vendor["appsStrictEntitlements"])
	}

	// Accepted literal 'true' → advertised.
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO system_config (key, value) VALUES ('apps_caps_strict', 'true')
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`); err != nil {
		t.Fatalf("seed apps_caps_strict: %v", err)
	}
	if vendor := getVendor(t); vendor["appsStrictEntitlements"] != true {
		t.Fatalf("'true' toggle: appsStrictEntitlements = %v, want true", vendor["appsStrictEntitlements"])
	}

	// Accepted literal '1' → advertised.
	if _, err := pool.Exec(context.Background(),
		`UPDATE system_config SET value='1' WHERE key='apps_caps_strict'`); err != nil {
		t.Fatalf("update apps_caps_strict: %v", err)
	}
	if vendor := getVendor(t); vendor["appsStrictEntitlements"] != true {
		t.Fatalf("'1' toggle: appsStrictEntitlements = %v, want true", vendor["appsStrictEntitlements"])
	}

	// Rejected literal → omitted again (value is JSONB; a JSON string that
	// lowercases to something outside ('1','true') keeps the window posture).
	if _, err := pool.Exec(context.Background(),
		`UPDATE system_config SET value='"no"' WHERE key='apps_caps_strict'`); err != nil {
		t.Fatalf("update apps_caps_strict: %v", err)
	}
	if vendor := getVendor(t); vendor["appsStrictEntitlements"] != nil {
		t.Fatalf("'yes' toggle: appsStrictEntitlements = %v, want omitted", vendor["appsStrictEntitlements"])
	}
}
