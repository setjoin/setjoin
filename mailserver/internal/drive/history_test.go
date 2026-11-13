package drive

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func TestHistoryCursorRoundTripAndTamper(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{toggle.FeatureDrive: true}), discardLogger())
	want := historyCursor{OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRank: 20, SourceID: 42}
	raw, err := h.signHistoryCursor(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.parseHistoryCursor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
	// Tamper the signature at the byte level: decode, flip a byte, re-encode.
	// The previous string-level mutation ("A" + sig[1:]) was a silent no-op
	// whenever the real signature's first base64 char was already 'A' —
	// base64url index 0 — which happens 1/64 of runs: the "tampered" cursor
	// was byte-identical to the original, HMAC verification passed, and the
	// test failed with "tampered cursor accepted" (the once-in-CI flake). A
	// decoded byte flip is provably content-changing and re-encodes to valid
	// base64, so a rejection below can only come from the HMAC comparison on
	// the tampered content itself.
	parts := strings.Split(raw, ".")
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	parts[1] = base64.RawURLEncoding.EncodeToString(sig)
	if _, err := h.parseHistoryCursor(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered cursor accepted")
	}
}

func TestHistoryCursorRejectsEveryMalformedField(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{toggle.FeatureDrive: true}), discardLogger())
	valid := historyCursor{OccurredAt: time.Now().UTC().Format(time.RFC3339Nano), SourceRank: 1, SourceID: 1}
	validRaw, err := h.signHistoryCursor(valid)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(validRaw, ".")
	badJSON := base64.RawURLEncoding.EncodeToString([]byte(`{`))
	mac := hmac.New(sha256.New, h.historyCursorKey[:])
	_, _ = mac.Write([]byte(`{`))
	badJSON += "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	invalidRank, _ := h.signHistoryCursor(historyCursor{OccurredAt: valid.OccurredAt, SourceRank: -1, SourceID: 1})
	invalidID, _ := h.signHistoryCursor(historyCursor{OccurredAt: valid.OccurredAt, SourceRank: 1, SourceID: 0})
	invalidTime, _ := h.signHistoryCursor(historyCursor{OccurredAt: "not-a-time", SourceRank: 1, SourceID: 1})
	for _, raw := range []string{"", "one-part", "!." + parts[1], parts[0] + ".!", badJSON, invalidRank, invalidID, invalidTime} {
		if _, err := h.parseHistoryCursor(raw); err == nil {
			t.Fatalf("malformed cursor accepted: %q", raw)
		}
	}
}

func TestHistoryRouteLiveValidationPaginationAndAuthorization(t *testing.T) {
	pool := driveLivePool(t)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.drive", true)
	testsupport.SetFeatureToggleForTest(t, pool, "feature.drive_history", true)
	owner := driveLiveUser(t, pool, "history-live")
	other := driveLiveUser(t, pool, "history-other")
	var spaceID, nodeID int64
	if err := pool.QueryRow(t.Context(), `SELECT drive_space_create($1,$2,'regular')`, owner, "History Live").Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT drive_node_create($1,$2,NULL,'file','history.docx')`, owner, spaceID).Scan(&nodeID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM drive_spaces WHERE id=$1`, spaceID) })
	h := NewHandler(pool, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureDriveHistory: true,
	}), discardLogger())
	base := "/drive/files/" + strconv.FormatInt(nodeID, 10) + "/history"
	for _, tc := range []struct {
		user       int64
		path       string
		wantStatus int
	}{
		{owner, "/drive/files/bad/history", http.StatusBadRequest},
		{owner, base + "?limit=0", http.StatusUnprocessableEntity},
		{owner, base + "?limit=101", http.StatusUnprocessableEntity},
		{owner, base + "?cursor=broken", http.StatusBadRequest},
		{other, base, http.StatusNotFound},
		{owner, base + "?limit=1", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: tc.user}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("GET %s user=%d got %d want %d: %s", tc.path, tc.user, rec.Code, tc.wantStatus, rec.Body.String())
		}
		if tc.wantStatus == http.StatusOK {
			var out struct {
				Items      json.RawMessage `json:"items"`
				HasMore    bool            `json:"hasMore"`
				NextCursor *string         `json:"nextCursor"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || len(out.Items) == 0 {
				t.Fatalf("history body=%s err=%v", rec.Body.String(), err)
			}
			if out.HasMore && out.NextCursor != nil {
				nextReq := httptest.NewRequest(http.MethodGet, base+"?limit=1&cursor="+url.QueryEscape(*out.NextCursor), nil)
				nextReq = nextReq.WithContext(auth.ContextWithUser(nextReq.Context(), &auth.Claims{UserID: owner}))
				nextRec := httptest.NewRecorder()
				h.ServeHTTP(nextRec, nextReq)
				if nextRec.Code != http.StatusOK {
					t.Fatalf("next history=%d %s", nextRec.Code, nextRec.Body.String())
				}
			}
		}
	}
}

func TestHistoryToggleOffIsNotFound(t *testing.T) {
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true, toggle.FeatureDriveHistory: false,
	}), discardLogger())
	req := httptest.NewRequest(http.MethodGet, "/drive/files/1/history", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", rr.Code)
	}
}
