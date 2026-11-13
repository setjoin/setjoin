package drive

// Live (DB-backed) tests for P6 Task 9: admin tier-2 trash. Mirrors the
// worm_live_test.go Super Admin (role_group_id=1) grant pattern for the
// drive.manage-gated surfaces.

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestAdminTrashList_TierRequired(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvtrTierReq")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	rr := driveLiveDo(t, h, owner, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/trash", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("no tier param: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, owner, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/trash?tier=1", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("tier=1: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAdminTrashList_RequiresDriveManage(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvtrNoPerm")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	rr := driveLiveDo(t, h, owner, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/trash?tier=2", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no drive.manage: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, owner, "POST", "/drive/nodes/1/purge-restore", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("purge-restore, no drive.manage: want 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAdminTrashListAndPurgeRestore_RoundTrip: manager destroys a file (tier
// 2), it is invisible to the member's own tree, a Super Admin lists it via
// the tier-2 endpoint, restores it, and it reappears in the live tree.
func TestAdminTrashListAndPurgeRestore_RoundTrip(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvtrOwner")
	admin := driveLiveUser(t, pool, "drvtrAdmin")
	h := NewHandler(pool, pool, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)
	nodeID := driveLiveCreateFile(t, h, owner, spaceID, "purge-me.txt")

	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, 1, $1)`, admin); err != nil {
		t.Fatalf("grant super admin: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=1`, admin) //nolint:errcheck
	})

	// tier-1 trash then manager destroy -> tier 2.
	rr := driveLiveDo(t, h, owner, "POST", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/trash", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("trash: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, owner, "DELETE", "/drive/nodes/"+strconv.FormatInt(nodeID, 10), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("destroy: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// unknown node -> 404 (BZ139) on purge-restore.
	rr = driveLiveDo(t, h, admin, "POST", "/drive/nodes/999999999/purge-restore", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("purge-restore unknown node: want 404, got %d: %s", rr.Code, rr.Body.String())
	}

	// admin lists tier 2 — sees the fixture row.
	rr = driveLiveDo(t, h, admin, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/trash?tier=2", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin trash list: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var listed struct {
		Items []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	driveLiveDecode(t, rr, &listed)
	found := false
	for _, it := range listed.Items {
		if it.ID == nodeID {
			found = true
		}
	}
	if !found {
		t.Fatalf("tier-2 list %v does not contain node %d", listed.Items, nodeID)
	}

	// admin restores it.
	rr = driveLiveDo(t, h, admin, "POST", "/drive/nodes/"+strconv.FormatInt(nodeID, 10)+"/purge-restore", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("purge-restore: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// it's live again — visible in the owner's normal (non-deleted) tree.
	rr = driveLiveDo(t, h, owner, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/tree", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("tree: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var tree []struct {
		ID int64 `json:"id"`
	}
	driveLiveDecode(t, rr, &tree)
	found = false
	for _, n := range tree {
		if n.ID == nodeID {
			found = true
		}
	}
	if !found {
		t.Fatalf("restored node %d not in live tree %v", nodeID, tree)
	}

	// tier-2 list is now empty of it.
	rr = driveLiveDo(t, h, admin, "GET", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/trash?tier=2", nil)
	driveLiveDecode(t, rr, &listed)
	for _, it := range listed.Items {
		if it.ID == nodeID {
			t.Fatalf("node %d still listed in tier-2 trash after restore", nodeID)
		}
	}
}
