package drive

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

func TestAccessSyncRoutesRejectInvalidPagingBeforeDatabase(t *testing.T) {
	t.Parallel()
	h := NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{
		"feature.drive": true,
	}), discardLogger())
	tests := []struct {
		name string
		path string
		want int
	}{
		{name: "access missing space", path: "/drive/access-invalidations", want: http.StatusBadRequest},
		{name: "access negative space", path: "/drive/access-invalidations?space=-1", want: http.StatusBadRequest},
		{name: "access malformed cursor", path: "/drive/access-invalidations?space=1&cursor=not-a-uuid", want: http.StatusUnprocessableEntity},
		{name: "access zero max", path: "/drive/access-invalidations?space=1&max=0", want: http.StatusUnprocessableEntity},
		{name: "access oversized max", path: "/drive/access-invalidations?space=1&max=1001", want: http.StatusUnprocessableEntity},
		{name: "visibility missing space", path: "/drive/visibility-snapshot", want: http.StatusBadRequest},
		{name: "visibility negative after", path: "/drive/visibility-snapshot?space=1&after=-1", want: http.StatusUnprocessableEntity},
		{name: "visibility malformed after", path: "/drive/visibility-snapshot?space=1&after=x", want: http.StatusUnprocessableEntity},
		{name: "visibility negative epoch", path: "/drive/visibility-snapshot?space=1&epoch=-1", want: http.StatusUnprocessableEntity},
		{name: "visibility malformed epoch", path: "/drive/visibility-snapshot?space=1&epoch=x", want: http.StatusUnprocessableEntity},
		{name: "visibility oversized max", path: "/drive/visibility-snapshot?space=1&max=501", want: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1}))
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

func TestAccessSyncRoutesLiveReturnOpaqueInvalidationsAndEpochBoundSnapshot(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "accesssyncowner")
	h := NewHandler(pool, nil, newFakeStore(), "drive-test", toggle.NewTestFlags(map[string]bool{
		toggle.FeatureDrive: true,
	}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)
	_ = driveLiveCreateFolder(t, h, owner, spaceID, "access-sync-folder", nil)

	rr := driveLiveDo(t, h, owner, http.MethodGet,
		fmt.Sprintf("/drive/access-invalidations?space=%d&max=10", spaceID), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("access invalidations: status=%d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("access invalidations Content-Type = %q, want application/json", got)
	}
	var invalidations struct {
		Epoch         string            `json:"epoch"`
		Invalidations []json.RawMessage `json:"invalidations"`
		FullReconcile bool              `json:"fullReconcile"`
	}
	driveLiveDecode(t, rr, &invalidations)
	if _, ok := parseEpoch(invalidations.Epoch); !ok || invalidations.FullReconcile {
		t.Fatalf("invalidations response = %+v, want current decimal epoch without reconcile", invalidations)
	}

	rr = driveLiveDo(t, h, owner, http.MethodGet,
		fmt.Sprintf("/drive/visibility-snapshot?space=%d&after=0&epoch=%s&max=10", spaceID, invalidations.Epoch), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("visibility snapshot: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var snapshot struct {
		Epoch     string            `json:"epoch"`
		Nodes     []json.RawMessage `json:"nodes"`
		NextAfter string            `json:"nextAfter"`
	}
	driveLiveDecode(t, rr, &snapshot)
	if snapshot.Epoch != invalidations.Epoch || len(snapshot.Nodes) == 0 {
		t.Fatalf("snapshot = %+v, want matching epoch and visible nodes", snapshot)
	}

	// A syntactically valid but unknown opaque cursor reveals no space state;
	// it only asks the managed client to reconcile from a fresh snapshot.
	rr = driveLiveDo(t, h, owner, http.MethodGet,
		fmt.Sprintf("/drive/access-invalidations?space=%d&cursor=%s", spaceID, uuid.NewString()), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("unknown opaque cursor: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var unknownCursor struct {
		Epoch         *string `json:"epoch"`
		FullReconcile bool    `json:"fullReconcile"`
		Reason        string  `json:"reason"`
	}
	driveLiveDecode(t, rr, &unknownCursor)
	if !unknownCursor.FullReconcile || unknownCursor.Epoch != nil || unknownCursor.Reason != "cursorUnavailable" {
		t.Fatalf("unknown opaque cursor response = %+v", unknownCursor)
	}
}
