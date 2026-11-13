package drive

// Live (DB-backed) tests for P6 Task 10: name search.

import (
	"net/http"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestSearchNodes_HappyPathAndScoping(t *testing.T) {
	pool := driveLivePool(t)
	member := driveLiveUser(t, pool, "drvsrchMember")
	other := driveLiveUser(t, pool, "drvsrchOther")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())

	spaceID := drivePersonalSpaceID(t, h, member)
	nodeID := driveLiveCreateFile(t, h, member, spaceID, "Quarterly Report.docx")
	otherSpaceID := drivePersonalSpaceID(t, h, other)
	driveLiveCreateFile(t, h, other, otherSpaceID, "Quarterly Report.docx")

	// member finds their own file, case-insensitive substring.
	rr := driveLiveDo(t, h, member, "GET", "/drive/search?q=quarterly", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("search: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Items []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	driveLiveDecode(t, rr, &out)
	found := false
	for _, it := range out.Items {
		if it.ID == nodeID {
			found = true
		}
		if it.ID == 0 {
			t.Fatalf("unexpected zero id in results %v", out.Items)
		}
	}
	if !found {
		t.Fatalf("results %v do not contain node %d", out.Items, nodeID)
	}
	// acceptance #27: zero cross-space leakage into the other member's hits.
	for _, it := range out.Items {
		if it.Name == "Quarterly Report.docx" && it.ID != nodeID {
			t.Fatalf("cross-space leak: found another member's file %v", it)
		}
	}

	// space scoping: filtering to the OTHER member's space (as `member`, who
	// isn't in it) yields zero hits — no membership-probe oracle.
	rr = driveLiveDo(t, h, member, "GET", "/drive/search?q=quarterly&space="+strconv.FormatInt(otherSpaceID, 10), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("search scoped to foreign space: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	driveLiveDecode(t, rr, &out)
	if len(out.Items) != 0 {
		t.Fatalf("search scoped to a foreign space returned %v, want empty", out.Items)
	}

	// empty query -> 422 (BZ141).
	rr = driveLiveDo(t, h, member, "GET", "/drive/search?q=", nil)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("empty q: want 422, got %d: %s", rr.Code, rr.Body.String())
	}
}
