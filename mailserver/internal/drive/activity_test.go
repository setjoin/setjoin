package drive

// Live (DB-backed) test for the activity-feed route — Task 11 (LR-1/LR-2).

import (
	"net/http"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestActivityFeedPerSpaceAndPerNode(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvactivity")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userID, spaceID, "activity.docx", []byte("v1"))

	// Generate a branch.create + label.set event on this node.
	rr := driveLiveDo(t, h, userID, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/branches",
		map[string]any{"name": "draft", "fromVersionId": versionID})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create branch: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, userID, "POST", "/drive/versions/"+strconv.FormatInt(versionID, 10)+"/labels",
		map[string]any{"label": "Approved"})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("set label: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Per-space feed: at least the branch.create + label.set rows.
	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/activity", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("activity: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var feed struct {
		Items []map[string]any `json:"items"`
	}
	driveLiveDecode(t, rr, &feed)
	if len(feed.Items) == 0 {
		t.Fatal("space activity feed must not be empty after branch.create/label.set")
	}
	actions := map[string]bool{}
	for _, it := range feed.Items {
		actions[it["action"].(string)] = true
	}
	if !actions["branch.create"] || !actions["label.set"] {
		t.Errorf("activity actions = %v, want branch.create and label.set present", actions)
	}

	// Per-node filter (?node=) — same node, so still non-empty.
	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/activity?node="+strconv.FormatInt(nodeID, 10), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("activity ?node=: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	driveLiveDecode(t, rr, &feed)
	if len(feed.Items) == 0 {
		t.Fatal("per-node activity feed must include this node's own events")
	}

	// max clamps; malformed query params 400 before reaching the reducer.
	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/activity?max=bogus", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("activity ?max=bogus: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/activity?beforeId=bogus", nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("activity ?beforeId=bogus: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}
