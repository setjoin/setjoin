package drive

// Live (DB-backed) tests for P6 Task 12: the "space as of T" view and the
// watch list.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

func TestSpaceAsOf_HappyPathAndValidation(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvasofOwner")
	other := driveLiveUser(t, pool, "drvasofOther")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	before := time.Now().UTC()
	nodeID := driveLiveCreateFile(t, h, owner, spaceID, "asof.txt")
	// drive_space_as_of requires a main-line VERSION for a file to count as
	// "existing" (a file with no version at T didn't exist yet, per the
	// reducer's own WHERE clause) — put one so the "as-of now" assertion below
	// has something to find.
	data := []byte("asof fixture bytes")
	sha := driveLiveUploadChunk(t, h, owner, spaceID, data)
	sum := sha256.Sum256(data)
	contentSha := hex.EncodeToString(sum[:])
	driveLivePutVersion(t, h, owner, nodeID, contentSha, len(data), []chunkManifestEntry{{Sha256: sha, Size: len(data)}})

	// bad "at" -> 422.
	rr := driveLiveDo(t, h, owner, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/asof?at=not-a-time", nil)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad at: want 422, got %d: %s", rr.Code, rr.Body.String())
	}

	// non-member -> 404 (BZ139).
	rr = driveLiveDo(t, h, other, "GET",
		"/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/asof?at="+time.Now().UTC().Format(time.RFC3339Nano), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("non-member: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	// as-of the moment BEFORE the file was created: the folder/file doesn't
	// show up yet (temporal existence — spec §13/Task 8 ceiling #1).
	rr = driveLiveDo(t, h, owner, "GET",
		"/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/asof?at="+before.Format(time.RFC3339Nano), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("as-of before creation: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
	}
	driveLiveDecode(t, rr, &out)
	for _, it := range out.Items {
		if it.ID == nodeID {
			t.Fatalf("node %d visible as-of a time BEFORE it was created", nodeID)
		}
	}

	// as-of now: the file is visible.
	rr = driveLiveDo(t, h, owner, "GET",
		"/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/asof?at="+time.Now().UTC().Format(time.RFC3339Nano), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("as-of now: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	driveLiveDecode(t, rr, &out)
	found := false
	for _, it := range out.Items {
		if it.ID == nodeID {
			found = true
		}
	}
	if !found {
		t.Fatalf("as-of now items %v missing node %d", out.Items, nodeID)
	}
}

func TestListWatches_SelfScopedOnly(t *testing.T) {
	pool := driveLivePool(t)
	a := driveLiveUser(t, pool, "drvwatchA")
	b := driveLiveUser(t, pool, "drvwatchB")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceA := drivePersonalSpaceID(t, h, a)
	nodeA := driveLiveCreateFile(t, h, a, spaceA, "watched-by-a.txt")
	spaceB := drivePersonalSpaceID(t, h, b)
	nodeB := driveLiveCreateFile(t, h, b, spaceB, "watched-by-b.txt")

	rr := driveLiveDo(t, h, a, "PUT", "/drive/nodes/"+strconv.FormatInt(nodeA, 10)+"/watch",
		map[string]any{"ops": []string{"trash"}})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("A watch: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, b, "PUT", "/drive/nodes/"+strconv.FormatInt(nodeB, 10)+"/watch", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("B watch: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, a, "GET", "/drive/watches", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("A list watches: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var aList []struct {
		NodeID int64    `json:"nodeId"`
		Ops    []string `json:"ops"`
	}
	driveLiveDecode(t, rr, &aList)
	if len(aList) != 1 || aList[0].NodeID != nodeA {
		t.Fatalf("A's watch list = %v, want exactly [node %d]", aList, nodeA)
	}
	if len(aList[0].Ops) != 1 || aList[0].Ops[0] != "trash" {
		t.Fatalf("A's watch ops = %v, want [trash]", aList[0].Ops)
	}

	rr = driveLiveDo(t, h, b, "GET", "/drive/watches", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("B list watches: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var bList []struct {
		NodeID int64 `json:"nodeId"`
	}
	driveLiveDecode(t, rr, &bList)
	if len(bList) != 1 || bList[0].NodeID != nodeB {
		t.Fatalf("B's watch list = %v, want exactly [node %d] — cross-user leak", bList, nodeB)
	}
}
