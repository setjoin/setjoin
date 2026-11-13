package scim

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSCIMHandlersRejectMissingSourceContext(t *testing.T) {
	t.Parallel()

	s := &Server{}
	tests := []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		req  *http.Request
	}{
		{
			name: "list users",
			call: s.GetUsers,
			req:  httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil),
		},
		{
			name: "get user",
			call: s.GetUser,
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users/1", nil)
				req.SetPathValue("id", "1")
				return req
			}(),
		},
		{
			name: "list groups",
			call: s.GetGroups,
			req:  httptest.NewRequest(http.MethodGet, "/scim/v2/Groups", nil),
		},
		{
			name: "get group",
			call: s.GetGroup,
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/scim/v2/Groups/1", nil)
				req.SetPathValue("id", "1")
				return req
			}(),
		},
		{
			name: "create group",
			call: s.CreateGroup,
			req:  httptest.NewRequest(http.MethodPost, "/scim/v2/Groups", nil),
		},
		{
			name: "patch group",
			call: s.PatchGroup,
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodPatch, "/scim/v2/Groups/1", nil)
				req.SetPathValue("id", "1")
				return req
			}(),
		},
		{
			name: "delete group",
			call: s.DeleteGroup,
			req: func() *http.Request {
				req := httptest.NewRequest(http.MethodDelete, "/scim/v2/Groups/1", nil)
				req.SetPathValue("id", "1")
				return req
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tt.call(rec, tt.req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestSCIMUserQueriesAndMutationsRejectMissingSourceContext(t *testing.T) {
	t.Parallel()

	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	if _, _, err := s.queryUsersFilter(req, `userName eq "a@example.test"`, 1, 10); err == nil {
		t.Fatal("filter query accepted a request without a source")
	}
	if _, _, err := s.queryUsersSyncToken(req, "unused", 10); err == nil {
		t.Fatal("sync-token query accepted a request without a source")
	}
	if _, _, err := s.queryUsersPaginated(req, 1, 10); err == nil {
		t.Fatal("paginated query accepted a request without a source")
	}
	if _, _, err := s.sourceUserForPatch(context.Background(), 1); err == nil {
		t.Fatal("patch lookup accepted a request without a source")
	}
	if _, err := s.applySourceUserPatch(
		context.Background(), "subject", scimUserFields{}, "", 1, userPatchFields{},
	); err == nil {
		t.Fatal("patch mutation accepted a request without a source")
	}

	sourceCtx := context.WithValue(context.Background(), ctxSourceID, int64(1))
	sourceCtx = context.WithValue(sourceCtx, ctxSourceGeneration, int64(1))
	if _, err := s.applySourceUserPatch(
		sourceCtx, "", scimUserFields{}, "", 1, userPatchFields{},
	); err == nil {
		t.Fatal("patch mutation accepted an empty immutable subject")
	}
}

func TestSCIMGroupPatchRejectsMalformedAndUnsupportedOperations(t *testing.T) {
	t.Parallel()

	s := &Server{}
	ctx := context.Background()
	assertHTTPError := func(t *testing.T, err error, status int, scimType string) {
		t.Helper()
		var got *httpError
		if !errors.As(err, &got) {
			t.Fatalf("error=%T %v, want *httpError", err, err)
		}
		if got.Status != status || got.ScimType != scimType {
			t.Fatalf("error=%+v, want status=%d scimType=%q", got, status, scimType)
		}
	}

	err := applyGroupPatch(s, ctx, 1, 1, 1, "group", []PatchOperation{{Op: "move"}})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidValue")

	err = patchGroupReplace(s, ctx, 1, 1, 1, "group", PatchOperation{
		Op: "replace", Path: "displayName", Value: json.RawMessage(`{"bad":true}`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidValue")

	err = patchGroupReplace(s, ctx, 1, 1, 1, "group", PatchOperation{
		Op: "replace", Path: "unknown", Value: json.RawMessage(`"value"`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidPath")

	err = patchGroupReplace(s, ctx, 1, 1, 1, "group", PatchOperation{
		Op: "replace", Path: "members", Value: json.RawMessage(`{"bad":true}`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidValue")

	err = patchGroupAdd(s, ctx, 1, 1, "group", PatchOperation{
		Op: "add", Path: "displayName", Value: json.RawMessage(`"value"`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidPath")

	err = patchGroupRemove(s, ctx, 1, 1, "group", PatchOperation{
		Op: "remove", Path: "displayName", Value: json.RawMessage(`"value"`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "noTarget")

	err = patchGroupAdd(s, ctx, 1, 1, "group", PatchOperation{
		Op: "add", Path: "members", Value: json.RawMessage(`not-json`),
	})
	assertHTTPError(t, err, http.StatusBadRequest, "invalidValue")
}

func TestGroupMemberExternalIDsAcceptsArrayAndSingleObject(t *testing.T) {
	t.Parallel()

	array, err := groupMemberExternalIDs(json.RawMessage(`[{"value":"a"},{"value":"b"}]`))
	if err != nil || len(array) != 2 || array[0] != "a" || array[1] != "b" {
		t.Fatalf("array=%v err=%v", array, err)
	}
	single, err := groupMemberExternalIDs(json.RawMessage(`{"value":"one"}`))
	if err != nil || len(single) != 1 || single[0] != "one" {
		t.Fatalf("single=%v err=%v", single, err)
	}
}

func TestSCIMSyncTokenRejectsMalformedWrongSourceAndBadTimestamp(t *testing.T) {
	t.Parallel()

	if _, err := decodeSyncToken("not-base64!", 7); err == nil {
		t.Fatal("malformed base64 token was accepted")
	}
	badJSON := base64.RawURLEncoding.EncodeToString([]byte(`{`))
	if _, err := decodeSyncToken(badJSON, 7); err == nil {
		t.Fatal("malformed JSON token was accepted")
	}
	wrongSource := encodeSyncToken(8, time.Now())
	if _, err := decodeSyncToken(wrongSource, 7); err == nil {
		t.Fatal("cross-source token was accepted")
	}
	badTime, err := json.Marshal(map[string]string{"sourceId": "7", "updatedAt": "not-a-time"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSyncToken(base64.RawURLEncoding.EncodeToString(badTime), 7); err == nil {
		t.Fatal("invalid timestamp was accepted")
	}
}

func TestUserRowToResourceMapsAllOptionalFields(t *testing.T) {
	t.Parallel()

	str := func(v string) *string { return &v }
	active := true
	now := time.Now().UTC().Truncate(time.Second)
	got := userRowToResource(
		42,
		str("immutable"), str("alice"), str("alice@example.test"), str("Alice"),
		str("Alice"), str("Example"), str("Engineer"), str("+1-555-0100"), &active,
		now, now,
	)
	if got.ID != "42" || got.ExternalID != "immutable" || got.UserName != "alice" ||
		got.DisplayName != "Alice" || got.Name == nil || got.Name.Formatted != "Alice Example" ||
		got.Title != "Engineer" || len(got.Emails) != 1 || len(got.PhoneNumbers) != 1 ||
		got.Active == nil || !*got.Active {
		t.Fatalf("resource did not retain optional fields: %+v", got)
	}
}
