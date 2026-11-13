package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/shared/pgxutil"
)

func TestSCIMGroupsAreIsolatedByAuthenticatedSource(t *testing.T) {
	pool := scimTestPool(t)
	enableIdentityModelForSCIMTest(t, pool)
	s := NewServer(pool, pgxutil.WorkerPool{Pool: pool}, scimTestLogger(), "", "")
	ctx := context.Background()
	suffix := scimRandomSuffix(t)

	source := func(key string) (int64, int64) {
		t.Helper()
		var id, generation int64
		if err := pool.QueryRow(ctx, `
			INSERT INTO identity_sources(
			  source_key,display_name,kind,capabilities,state
			) VALUES(
			  $1,$2,'scim',
			  '{"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
			  'active'
			) RETURNING id,generation
		`, "scim:group-"+key+"-"+suffix, "SCIM group "+key+" "+suffix).
			Scan(&id, &generation); err != nil {
			t.Fatalf("create %s source: %v", key, err)
		}
		return id, generation
	}
	sourceA, generationA := source("a")
	sourceB, generationB := source("b")

	domain := "scim-group-" + suffix + ".local"
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE)`, domain); err != nil {
		t.Fatalf("create group test domain: %v", err)
	}
	fieldsA := scimUserFields{
		displayName: "Member A", primaryEmail: "member-a@" + domain, active: true,
	}
	fieldsB := scimUserFields{
		displayName: "Member B", primaryEmail: "member-b@" + domain, active: true,
	}
	userA, err := s.applySourceUser(
		normalizedSCIMContext(sourceA, generationA, "soft"),
		"same-member", fieldsA, "", 0,
	)
	if err != nil {
		t.Fatalf("create source A member: %v", err)
	}
	userB, err := s.applySourceUser(
		normalizedSCIMContext(sourceB, generationB, "soft"),
		"same-member", fieldsB, "", 0,
	)
	if err != nil {
		t.Fatalf("create source B member: %v", err)
	}

	create := func(sourceID, generation int64) (int, GroupResource) {
		t.Helper()
		body, _ := json.Marshal(GroupResource{
			ExternalID: "same-group", DisplayName: "Group " + strconv.FormatInt(sourceID, 10),
			Members: []MemberRef{{Value: "same-member"}},
		})
		req := httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", bytes.NewReader(body)).
			WithContext(normalizedSCIMContext(sourceID, generation, "soft"))
		rec := httptest.NewRecorder()
		s.CreateGroup(rec, req)
		var resource GroupResource
		if rec.Code == http.StatusCreated {
			if err := json.Unmarshal(rec.Body.Bytes(), &resource); err != nil {
				t.Fatalf("decode created group: %v", err)
			}
		}
		return rec.Code, resource
	}
	statusA, groupA := create(sourceA, generationA)
	statusB, groupB := create(sourceB, generationB)
	if statusA != http.StatusCreated || statusB != http.StatusCreated {
		t.Fatalf("create same external id by two sources: status A/B=%d/%d", statusA, statusB)
	}
	if groupA.ID == groupB.ID || len(groupA.Members) != 1 || len(groupB.Members) != 1 {
		t.Fatalf("source groups or members collided: A=%+v B=%+v", groupA, groupB)
	}
	if groupA.Members[0].Value != "same-member" ||
		groupB.Members[0].Value != "same-member" {
		t.Fatalf("group members did not retain source-local subjects: A=%+v B=%+v",
			groupA.Members, groupB.Members)
	}

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups?startIndex=1&count=10", nil).
		WithContext(normalizedSCIMContext(sourceA, generationA, "soft"))
	rec := httptest.NewRecorder()
	s.GetGroups(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list source A groups status=%d body=%s", rec.Code, rec.Body.String())
	}
	var listed ListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode group list: %v", err)
	}
	if listed.TotalResults != 1 || listed.ItemsPerPage != 1 {
		t.Fatalf("source A group list not isolated: %+v", listed)
	}

	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/"+groupA.ID, nil).
		WithContext(normalizedSCIMContext(sourceA, generationA, "soft"))
	req.SetPathValue("id", groupA.ID)
	rec = httptest.NewRecorder()
	s.GetGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get source A group status=%d body=%s", rec.Code, rec.Body.String())
	}

	patchBody := []byte(`{"Operations":[
		{"op":"replace","path":"displayName","value":"Renamed Group"},
		{"op":"replace","path":"members","value":[{"value":"same-member"}]},
		{"op":"add","path":"members","value":{"value":"same-member"}},
		{"op":"remove","path":"members","value":{"value":"same-member"}},
		{"op":"add","path":"members","value":[{"value":"same-member"}]}
	]}`)
	req = httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/"+groupA.ID, bytes.NewReader(patchBody)).
		WithContext(normalizedSCIMContext(sourceA, generationA, "soft"))
	req.SetPathValue("id", groupA.ID)
	rec = httptest.NewRecorder()
	s.PatchGroup(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("patch source A group status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/"+groupA.ID, nil).
		WithContext(normalizedSCIMContext(sourceB, generationB, "soft"))
	req.SetPathValue("id", groupA.ID)
	rec = httptest.NewRecorder()
	s.GetGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-source group read status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+groupA.ID, nil).
		WithContext(normalizedSCIMContext(sourceB, generationB, "soft"))
	req.SetPathValue("id", groupA.ID)
	rec = httptest.NewRecorder()
	s.DeleteGroup(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-source group delete status=%d body=%s", rec.Code, rec.Body.String())
	}
	var stillOwned bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS(
		  SELECT 1 FROM distribution_groups
		   WHERE id=$1 AND scim_source_id=$2
		)`, groupA.ID, sourceA).Scan(&stillOwned); err != nil || !stillOwned {
		t.Fatalf("source A group survived cross-source delete=%v err=%v", stillOwned, err)
	}

	req = httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/"+groupB.ID, nil).
		WithContext(normalizedSCIMContext(sourceB, generationB, "soft"))
	req.SetPathValue("id", groupB.ID)
	rec = httptest.NewRecorder()
	s.DeleteGroup(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete source B group status=%d body=%s", rec.Code, rec.Body.String())
	}

	_ = userA
	_ = userB
}
