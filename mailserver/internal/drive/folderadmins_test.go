package drive

// Live (DB-backed) tests for delegated folder-admin routes — Task 11
// (LR-1: roster CRUD + the "?folder=" delegated member-management variant on
// the existing /drive/spaces/{id}/members routes).

import (
	"net/http"
	"strconv"
	"testing"

	"setjoin.com/shared/toggle"
)

func TestFolderAdminGrantListRevoke(t *testing.T) {
	pool := driveLivePool(t)
	owner := driveLiveUser(t, pool, "drvfaOwner")
	admin := driveLiveUser(t, pool, "drvfaAdmin")
	h := NewHandler(pool, nil, newFakeStore(), "b", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), discardLogger())
	spaceID := drivePersonalSpaceID(t, h, owner)

	rr := driveLiveDo(t, h, owner, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members",
		map[string]any{"userId": admin, "role": "editor"})
	if rr.Code != http.StatusOK {
		t.Fatalf("grant member: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, owner, "POST", "/drive/nodes", map[string]any{"spaceId": spaceID, "kind": "folder", "name": "dept"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create folder: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var folder struct {
		ID int64 `json:"id"`
	}
	driveLiveDecode(t, rr, &folder)

	// An ordinary editor does not hold manage_acl and cannot appoint a folder
	// administrator. Once appointed below, this same user is no longer an
	// ordinary editor: ACL compatibility projects the legacy folder-admin row
	// to a scoped manage_acl grant.
	rr = driveLiveDo(t, h, admin, "PUT", "/drive/nodes/"+strconv.FormatInt(folder.ID, 10)+"/folder-admins/"+strconv.FormatInt(admin, 10), nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("editor grant folder-admin: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// Manager grants folder-admin on "dept" to admin.
	rr = driveLiveDo(t, h, owner, "PUT", "/drive/nodes/"+strconv.FormatInt(folder.ID, 10)+"/folder-admins/"+strconv.FormatInt(admin, 10), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("grant folder-admin: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	rr = driveLiveDo(t, h, owner, "GET", "/drive/nodes/"+strconv.FormatInt(folder.ID, 10)+"/folder-admins", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list folder-admins: want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var admins []folderAdminOut
	driveLiveDecode(t, rr, &admins)
	if len(admins) != 1 || admins[0].UserID != admin {
		t.Fatalf("folder admins = %v, want exactly [%d]", admins, admin)
	}

	// Delegated member management: admin (folder-admin on "dept") grants a
	// third user viewer access via the ?folder= variant.
	viewer := driveLiveUser(t, pool, "drvfaViewer")
	rr = driveLiveDo(t, h, admin, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members?folder="+strconv.FormatInt(folder.ID, 10),
		map[string]any{"userId": viewer, "role": "viewer"})
	if rr.Code != http.StatusOK {
		t.Fatalf("delegated grant: want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Delegated grant of "manager" role is rejected (folder admins may only
	// grant editor/viewer, never manager).
	rr = driveLiveDo(t, h, admin, "POST", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members?folder="+strconv.FormatInt(folder.ID, 10),
		map[string]any{"userId": viewer, "role": "manager"})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("delegated manager grant: want 403, got %d: %s", rr.Code, rr.Body.String())
	}

	// Delegated revoke.
	rr = driveLiveDo(t, h, admin, "DELETE", "/drive/spaces/"+strconv.FormatInt(spaceID, 10)+"/members/"+strconv.FormatInt(viewer, 10)+"?folder="+strconv.FormatInt(folder.ID, 10), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delegated revoke: want 204, got %d: %s", rr.Code, rr.Body.String())
	}

	// Manager revokes the folder-admin grant.
	rr = driveLiveDo(t, h, owner, "DELETE", "/drive/nodes/"+strconv.FormatInt(folder.ID, 10)+"/folder-admins/"+strconv.FormatInt(admin, 10), nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("revoke folder-admin: want 204, got %d: %s", rr.Code, rr.Body.String())
	}
	rr = driveLiveDo(t, h, owner, "GET", "/drive/nodes/"+strconv.FormatInt(folder.ID, 10)+"/folder-admins", nil)
	driveLiveDecode(t, rr, &admins)
	if len(admins) != 0 {
		t.Errorf("folder admins after revoke = %v, want empty", admins)
	}
}
