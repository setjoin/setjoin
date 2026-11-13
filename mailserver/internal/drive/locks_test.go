package drive

// Live (DB-backed) tests for the lock/watch routes + tree branch/lock badges
// — Task 10. Also proves the BZ149->423 wire mapping (Task 9's mandate,
// exercised through the real hard-lock-vs-save collision).

import (
	"net/http"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestLockAcquireRenewHeldAndRelease(t *testing.T) {
	pool := driveLivePool(t)
	userA := driveLiveUser(t, pool, "drvlockA")
	userB := driveLiveUser(t, pool, "drvlockB")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userA)
	nodeID, _ := driveLiveFileWithVersion(t, h, userA, spaceID, "plan.docx", []byte("v1"))

	// A acquires soft.
	rr := driveLiveDo(t, h, userA, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("acquire: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var acquired map[string]any
	driveLiveDecode(t, rr, &acquired)
	if acquired["status"] != "acquired" {
		t.Fatalf("status = %v, want acquired", acquired["status"])
	}

	// A renews.
	rr = driveLiveDo(t, h, userA, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	driveLiveDecode(t, rr, &acquired)
	if acquired["status"] != "renewed" {
		t.Errorf("status = %v, want renewed", acquired["status"])
	}

	// B is granted membership so it can attempt to lock too (personal space —
	// grant editor access).
	rr = driveLiveDo(t, h, userA, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members",
		map[string]any{"userId": userB, "role": "editor"})
	if rr.Code != http.StatusOK {
		t.Fatalf("grant member: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// B requests a lock -> held (200, not an error).
	rr = driveLiveDo(t, h, userB, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("B acquire while A holds: want 200 (held), got %d: %s", rr.Code, rr.Body.String())
	}
	var held map[string]any
	driveLiveDecode(t, rr, &held)
	if held["status"] != "held" {
		t.Fatalf("status = %v, want held", held["status"])
	}

	// B releasing A's lock without ?break=1 -> 403 BZ140.
	rr = driveLiveDo(t, h, userB, "DELETE", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("B unlock (no break) another user's lock: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// A releases its own lock.
	rr = driveLiveDo(t, h, userA, "DELETE", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("A release: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	// Idempotent: releasing again is a no-op, not an error.
	rr = driveLiveDo(t, h, userA, "DELETE", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("A release again (idempotent): want 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHardLockRejectsSaveWith423 proves the BZ149->423 wire mapping end to
// end: A hard-locks a file; B's version save on the same ref is rejected
// with 423 Locked, code BZ149, and holderId naming A.
func TestHardLockRejectsSaveWith423(t *testing.T) {
	pool := driveLivePool(t)
	userA := driveLiveUser(t, pool, "drvhardA")
	userB := driveLiveUser(t, pool, "drvhardB")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userA)
	nodeID, versionID := driveLiveFileWithVersion(t, h, userA, spaceID, "locked.docx", []byte("v1"))

	rr := driveLiveDo(t, h, userA, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members",
		map[string]any{"userId": userB, "role": "editor"})
	if rr.Code != http.StatusOK {
		t.Fatalf("grant member: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, userA, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", map[string]any{"mode": "hard"})
	if rr.Code != http.StatusOK {
		t.Fatalf("hard lock: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, userB, "POST", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/versions", map[string]any{
		"contentSha256": "0000000000000000000000000000000000000000000000000000000000000000",
		"size":          2,
		"baseVersionId": versionID,
		"manifest":      []any{},
	})
	if rr.Code != http.StatusLocked {
		t.Fatalf("B save under A's hard lock: want 423, got %d: %s", rr.Code, rr.Body.String())
	}
	var prob struct {
		Code     string `json:"code"`
		HolderID int64  `json:"holderId"`
	}
	driveLiveDecode(t, rr, &prob)
	if prob.Code != "BZ149" {
		t.Errorf("code = %q, want BZ149", prob.Code)
	}
	if prob.HolderID != userA {
		t.Errorf("holderId = %d, want %d (the lock holder)", prob.HolderID, userA)
	}
}

func TestLockBreakAuthority(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvbreakOwner")
	editor := driveLiveUser(t, pool, "drvbreakEditor")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)
	nodeID, _ := driveLiveFileWithVersion(t, h, owner, spaceID, "shared.docx", []byte("v1"))

	rr := driveLiveDo(t, h, owner, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members",
		map[string]any{"userId": editor, "role": "editor"})
	if rr.Code != http.StatusOK {
		t.Fatalf("grant member: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, editor, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("editor acquire: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// owner (space manager) breaks editor's lock.
	rr = driveLiveDo(t, h, owner, "DELETE", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock?break=1", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("manager break: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestSpaceLockListAndWatch(t *testing.T) {
	pool := driveLivePool(t)
	userID := driveLiveUser(t, pool, "drvlocklist")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, userID)
	nodeID, _ := driveLiveFileWithVersion(t, h, userID, spaceID, "watch.docx", []byte("v1"))

	rr := driveLiveDo(t, h, userID, "PUT", "/drive/files/"+strconv.FormatInt(nodeID, 10)+"/lock", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("acquire: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/locks", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list locks: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var locks struct {
		Locks []map[string]any `json:"locks"`
	}
	driveLiveDecode(t, rr, &locks)
	if len(locks.Locks) != 1 || int64(locks.Locks[0]["nodeId"].(float64)) != nodeID {
		t.Fatalf("locks = %v, want exactly one row for node %d", locks.Locks, nodeID)
	}

	// Tree badges: branchCount 0, lock non-null with the holder's id.
	rr = driveLiveDo(t, h, userID, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/tree", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("tree: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var tree []nodeOut
	driveLiveDecode(t, rr, &tree)
	if len(tree) != 1 || tree[0].Lock == nil || tree[0].Lock.HolderID != userID {
		t.Fatalf("tree = %+v, want one file with a lock badge for %d", tree, userID)
	}

	// Watch: set then remove.
	rr = driveLiveDo(t, h, userID, "PUT", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/watch", map[string]any{"ops": []string{"lock"}})
	if rr.Code != http.StatusNoContent {
		t.Fatalf("set watch: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, userID, "DELETE", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/watch", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("remove watch: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	// Removing again -> 404 BZ139 (watch no longer exists).
	rr = driveLiveDo(t, h, userID, "DELETE", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/watch", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("remove already-removed watch: want 404, got %d: %s", rr.Code, rr.Body.String())
	}
}
