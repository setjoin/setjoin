package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

func identityV2RequestWithActor(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	return req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID:            42,
		IsAdmin:           true,
		Permissions:       permissions.AllPermissions,
		GlobalPermissions: permissions.AllPermissions,
	}))
}

func TestIdentityListOptionsBoundsAndAllowlist(t *testing.T) {
	spec := identityListSpec{
		resource:    "people",
		defaultSort: "userId",
		filterBounds: map[string]int{
			"filter": identityFilterMaxBytes,
			"source": 64,
			"state":  16,
		},
		filterEnums: map[string]map[string]struct{}{
			"state": identityEnum("enabled", "disabled"),
		},
	}

	t.Run("defaults", func(t *testing.T) {
		rec := httptest.NewRecorder()
		opts, ok := parseIdentityListOptions(rec,
			httptest.NewRequest(http.MethodGet, "/admin/identity/v2/people", nil),
			spec, 42, 0)
		if !ok {
			t.Fatalf("parse defaults: %d %s", rec.Code, rec.Body.String())
		}
		if opts.limit != 100 || opts.sort != "userId" {
			t.Fatalf("unexpected defaults: %+v", opts)
		}
	})

	for name, query := range map[string]string{
		"zero limit":        "?limit=0",
		"over max limit":    "?limit=501",
		"bad limit":         "?limit=nope",
		"unknown key":       "?offset=1",
		"repeated key":      "?limit=1&limit=2",
		"unsupported sort":  "?sort=email",
		"unsupported state": "?state=pending",
		"bad source":        "?source=../../etc",
		"long filter":       "?filter=" + strings.Repeat("a", identityFilterMaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			_, ok := parseIdentityListOptions(rec,
				httptest.NewRequest(http.MethodGet, "/admin/identity/v2/people"+query, nil),
				spec, 42, 0)
			if ok || rec.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got ok=%v status=%d body=%s",
					ok, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityListCursorIsOpaqueBoundAndExpiring(t *testing.T) {
	spec := identityListSpec{
		resource:     "sources",
		defaultSort:  "sourceKey",
		filterBounds: map[string]int{"filter": identityFilterMaxBytes},
	}
	req := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/sources?filter=corp&limit=5", nil)
	rec := httptest.NewRecorder()
	opts, ok := parseIdentityListOptions(rec, req, spec, 42, 7)
	if !ok {
		t.Fatalf("parse initial options: %d %s", rec.Code, rec.Body.String())
	}
	cursor := encodeIdentityListCursor(spec, opts, func(cursor *identityListCursor) {
		cursor.Text = "legacy:ad"
	})
	if strings.Contains(cursor, "legacy:ad") {
		t.Fatal("cursor must not expose its position as plain text")
	}

	resume := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/sources?filter=corp&cursor="+cursor, nil)
	resumeRec := httptest.NewRecorder()
	resumed, ok := parseIdentityListOptions(resumeRec, resume, spec, 42, 7)
	if !ok || resumed.cursor.Text != "legacy:ad" {
		t.Fatalf("resume: ok=%v cursor=%+v status=%d body=%s",
			ok, resumed.cursor, resumeRec.Code, resumeRec.Body.String())
	}

	for name, target := range map[string]string{
		"changed filter": "/admin/identity/v2/sources?filter=other&cursor=" + cursor,
		"changed actor":  "/admin/identity/v2/sources?filter=corp&cursor=" + cursor,
		"changed scope":  "/admin/identity/v2/sources?filter=corp&cursor=" + cursor,
	} {
		t.Run(name, func(t *testing.T) {
			actor, scope := int64(42), int64(7)
			if name == "changed actor" {
				actor = 43
			}
			if name == "changed scope" {
				scope = 8
			}
			mismatchRec := httptest.NewRecorder()
			_, ok := parseIdentityListOptions(mismatchRec,
				httptest.NewRequest(http.MethodGet, target, nil),
				spec, actor, scope)
			if ok || mismatchRec.Code != http.StatusBadRequest {
				t.Fatalf("want filter-bound 400, got ok=%v status=%d body=%s",
					ok, mismatchRec.Code, mismatchRec.Body.String())
			}
		})
	}

	expired := identityListCursor{
		Version: 1, Resource: spec.resource, Binding: opts.binding,
		Expires: time.Now().Add(-time.Second).Unix(), Text: "legacy:ad",
	}
	raw, err := json.Marshal(expired)
	if err != nil {
		t.Fatal(err)
	}
	expiredToken := base64.RawURLEncoding.EncodeToString(raw)
	expiredRec := httptest.NewRecorder()
	_, ok = parseIdentityListOptions(expiredRec,
		httptest.NewRequest(http.MethodGet,
			"/admin/identity/v2/sources?filter=corp&cursor="+expiredToken, nil),
		spec, 42, 7)
	if ok || expiredRec.Code != http.StatusGone {
		t.Fatalf("want expired cursor 410, got ok=%v status=%d body=%s",
			ok, expiredRec.Code, expiredRec.Body.String())
	}
}

func TestIdentityListCursorRejectsEveryMalformedEnvelope(t *testing.T) {
	spec := identityListSpec{
		resource:     "sources",
		defaultSort:  "sourceKey",
		filterBounds: map[string]int{"filter": identityFilterMaxBytes},
	}
	baseRequest := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/sources?filter=corp", nil)
	baseRecorder := httptest.NewRecorder()
	opts, ok := parseIdentityListOptions(baseRecorder, baseRequest, spec, 42, 7)
	if !ok {
		t.Fatalf("build cursor binding: %d %s",
			baseRecorder.Code, baseRecorder.Body.String())
	}
	token := func(raw string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(raw))
	}
	valid := identityListCursor{
		Version: 1, Resource: spec.resource, Binding: opts.binding,
		Expires: time.Now().Add(time.Minute).Unix(), Text: "corp",
	}
	validRaw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion := valid
	wrongVersion.Version = 2
	wrongVersionRaw, _ := json.Marshal(wrongVersion)
	wrongResource := valid
	wrongResource.Resource = "people"
	wrongResourceRaw, _ := json.Marshal(wrongResource)
	wrongBinding := valid
	wrongBinding.Binding = strings.Repeat("0", 64)
	wrongBindingRaw, _ := json.Marshal(wrongBinding)

	for name, cursor := range map[string]string{
		"oversized":      strings.Repeat("a", identityCursorMaxBytes+1),
		"invalid base64": "!",
		"invalid JSON":   token(`{`),
		"unknown field": token(`{"v":1,"resource":"sources","binding":"` +
			opts.binding + `","expires":` +
			strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10) +
			`,"unexpected":true}`),
		"trailing JSON":  token(string(validRaw) + `{}`),
		"wrong version":  token(string(wrongVersionRaw)),
		"wrong resource": token(string(wrongResourceRaw)),
		"wrong binding":  token(string(wrongBindingRaw)),
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			_, accepted := parseIdentityListOptions(rec,
				httptest.NewRequest(http.MethodGet,
					"/admin/identity/v2/sources?filter=corp&cursor="+cursor, nil),
				spec, 42, 7)
			if accepted || rec.Code != http.StatusBadRequest {
				t.Fatalf("accepted=%v status=%d body=%s",
					accepted, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityResponseAndPermissionHelpersFailClosed(t *testing.T) {
	encodingRecorder := httptest.NewRecorder()
	writeIdentityJSON(encodingRecorder,
		httptest.NewRequest(http.MethodGet, "/", nil),
		http.StatusOK, func() {})
	if encodingRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("unencodable response status=%d body=%s",
			encodingRecorder.Code, encodingRecorder.Body.String())
	}

	for _, invalid := range []string{"", strings.Repeat("a", 65), "_source"} {
		if validIdentitySourceKey(invalid) {
			t.Fatalf("invalid source key accepted: %q", invalid)
		}
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if requireUnscopedIdentityAdmin(rec, unauthenticated) ||
		rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated required-all status=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	if requireAnyUnscopedIdentityAdmin(rec, unauthenticated,
		permissions.PermIdentityWrite, permissions.PermAuditExport) ||
		rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated required-any status=%d", rec.Code)
	}

	noGrant := identityV2RequestWithActor(http.MethodGet, "/", "")
	noGrant = noGrant.WithContext(auth.ContextWithUser(noGrant.Context(), &auth.Claims{
		UserID: 42, GlobalPermissions: []string{},
	}))
	rec = httptest.NewRecorder()
	if requireUnscopedIdentityAdmin(rec, noGrant) ||
		rec.Code != http.StatusForbidden {
		t.Fatalf("missing default grant status=%d body=%s",
			rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if requireAnyUnscopedIdentityAdmin(rec, noGrant,
		permissions.PermIdentityWrite, permissions.PermAuditExport) ||
		rec.Code != http.StatusForbidden {
		t.Fatalf("missing any grant status=%d body=%s",
			rec.Code, rec.Body.String())
	}

	scoped := identityV2RequestWithActor(http.MethodGet, "/", "")
	scoped = scoped.WithContext(
		middleware.ContextWithDomainScope(scoped.Context(), 9))
	rec = httptest.NewRecorder()
	if requireAnyUnscopedIdentityAdmin(rec, scoped,
		permissions.PermIdentityWrite) || rec.Code != http.StatusForbidden {
		t.Fatalf("scoped any-grant status=%d body=%s",
			rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	if !requireAnyUnscopedIdentityAdmin(rec,
		identityV2RequestWithActor(http.MethodGet, "/", ""),
		"permission.not-held", permissions.PermIdentityWrite) {
		t.Fatalf("valid later any-grant rejected: %d %s",
			rec.Code, rec.Body.String())
	}
}

func TestIdentityTransitionReportRejectsEveryLocalAndMissingBoundary(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	dbHandler := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	nilHandler := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	call := func(
		name string,
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s",
					rec.Code, want, rec.Body.String())
			}
		})
	}

	call("unauthenticated", nilHandler.IdentityTransitionReport,
		httptest.NewRequest(http.MethodGet, "/", nil),
		http.StatusUnauthorized)

	withoutAudit := httptest.NewRequest(http.MethodGet, "/", nil)
	withoutAudit = withoutAudit.WithContext(auth.ContextWithUser(
		withoutAudit.Context(), &auth.Claims{
			UserID: 42, GlobalPermissions: []string{permissions.PermIdentityWrite},
		}))
	call("missing audit permission", nilHandler.IdentityTransitionReport,
		withoutAudit, http.StatusForbidden)

	badID := identityV2RequestWithActor(http.MethodGet, "/", "")
	badID.SetPathValue("id", "bad")
	call("invalid id", nilHandler.IdentityTransitionReport,
		badID, http.StatusBadRequest)

	noWorker := identityV2RequestWithActor(http.MethodGet, "/", "")
	noWorker.SetPathValue("id", uuid.NewString())
	call("worker unavailable", nilHandler.IdentityTransitionReport,
		noWorker, http.StatusServiceUnavailable)

	missing := identityV2RequestWithActor(http.MethodGet, "/", "")
	missing.SetPathValue("id", uuid.NewString())
	call("missing transition", dbHandler.IdentityTransitionReport,
		missing, http.StatusNotFound)
}

func TestIdentityListHandlersRejectBadContractBeforeDatabase(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil)

	noAuth := httptest.NewRecorder()
	h.Sources(noAuth, httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/sources", nil))
	if noAuth.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth: want 401, got %d (%s)", noAuth.Code, noAuth.Body.String())
	}

	longFilter := httptest.NewRecorder()
	h.IdentityPeople(longFilter, identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/people?filter="+strings.Repeat("a", 257), ""))
	if longFilter.Code != http.StatusBadRequest {
		t.Fatalf("long filter: want 400, got %d (%s)", longFilter.Code, longFilter.Body.String())
	}
	if got := longFilter.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
		t.Fatalf("long filter error content type = %q, want application/problem+json", got)
	}

	badCursor := httptest.NewRecorder()
	h.IdentityEvents(badCursor, identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/events?cursor=not-base64!", ""))
	if badCursor.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor: want 400, got %d (%s)", badCursor.Code, badCursor.Body.String())
	}
}

func TestIdentityListHandlersRejectMissingAuthorityWorkerAndMalformedPositions(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	dbHandler := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	nilHandler := NewIdentityHandler(nil, nil, testsupport.TestLogger())

	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"sources":     nilHandler.Sources,
		"people":      nilHandler.IdentityPeople,
		"conflicts":   nilHandler.IdentityConflicts,
		"transitions": nilHandler.IdentityTransitions,
		"events":      nilHandler.IdentityEvents,
	} {
		t.Run(name+" unauthenticated", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
		t.Run(name+" worker unavailable", func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, identityV2RequestWithActor(http.MethodGet, "/", ""))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	cursorFor := func(spec identityListSpec, mutate func(*identityListCursor)) string {
		t.Helper()
		rec := httptest.NewRecorder()
		opts, ok := parseIdentityListOptions(rec,
			httptest.NewRequest(http.MethodGet, "/", nil), spec, 42, 0)
		if !ok {
			t.Fatalf("build cursor options: %d %s", rec.Code, rec.Body.String())
		}
		return encodeIdentityListCursor(spec, opts, mutate)
	}
	cases := []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		spec    identityListSpec
		mutate  func(*identityListCursor)
	}{
		{
			name: "source empty text", handler: dbHandler.Sources,
			spec: identityListSpec{
				resource: "sources", defaultSort: "sourceKey",
				filterBounds: map[string]int{"filter": 256, "source": 64, "state": 16},
				filterEnums: map[string]map[string]struct{}{"state": identityEnum(
					"draft", "validated", "active", "paused", "error", "retired")},
			},
			mutate: func(*identityListCursor) {},
		},
		{
			name: "people zero number", handler: dbHandler.IdentityPeople,
			spec: identityListSpec{
				resource: "people", defaultSort: "userId",
				filterBounds: map[string]int{"filter": 256, "source": 64, "state": 16},
				filterEnums: map[string]map[string]struct{}{"state": identityEnum(
					"enabled", "disabled")},
			},
			mutate: func(*identityListCursor) {},
		},
		{
			name: "conflict invalid tuple", handler: dbHandler.IdentityConflicts,
			spec: identityListSpec{
				resource: "conflicts", defaultSort: "-createdAt",
				filterBounds: map[string]int{"filter": 256, "source": 64, "state": 16},
				filterEnums: map[string]map[string]struct{}{"state": identityEnum(
					"pending", "deferred")},
			},
			mutate: func(c *identityListCursor) { c.Time, c.ID = "bad", "bad" },
		},
		{
			name: "transition invalid tuple", handler: dbHandler.IdentityTransitions,
			spec: identityListSpec{
				resource: "transitions", defaultSort: "-createdAt",
				filterBounds: map[string]int{"filter": 256, "source": 64, "state": 32},
				filterEnums: map[string]map[string]struct{}{"state": identityEnum(
					"draft", "previewed", "awaiting_approval", "authorized",
					"executing", "authority_committed", "effects_pending", "completed",
					"failed_precommit", "failed_recoverable", "rollback_previewed",
					"rolling_back", "rolled_back", "cancelled", "expired")},
			},
			mutate: func(c *identityListCursor) { c.Time, c.ID = "bad", "bad" },
		},
		{
			name: "event invalid tuple", handler: dbHandler.IdentityEvents,
			spec: identityListSpec{
				resource: "events", defaultSort: "-occurredAt",
				filterBounds: map[string]int{"filter": 256, "source": 64},
			},
			mutate: func(c *identityListCursor) { c.Time, c.Number = "bad", 1 },
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cursor := cursorFor(tc.spec, tc.mutate)
			rec := httptest.NewRecorder()
			tc.handler(rec, identityV2RequestWithActor(http.MethodGet,
				"/?cursor="+cursor, ""))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIdentityMutationBodyAndConcurrencyContracts(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil)

	preview := identityV2RequestWithActor(http.MethodPost,
		"/admin/identity/v2/transitions/preview",
		`{"userId":"1","reason":"approved","idempotencyKey":"00000000-0000-0000-0000-000000000001"}`)
	preview.Header.Set("X-Audit-Reason", "approved")
	preview.Header.Set("Idempotency-Key", "00000000-0000-0000-0000-000000000002")
	previewRec := httptest.NewRecorder()
	h.TransitionPreview(previewRec, preview)
	if previewRec.Code != http.StatusBadRequest {
		t.Fatalf("idempotency mismatch: want 400, got %d (%s)",
			previewRec.Code, previewRec.Body.String())
	}

	canary := identityV2RequestWithActor(http.MethodPost,
		"/admin/identity/v2/upgrade/canary",
		`{"sourceKey":"legacy:ad","expectedGeneration":"3","enabled":true,"userIds":["7","7"],"reason":"approved"}`)
	canary.Header.Set("X-Audit-Reason", "approved")
	canaryRec := httptest.NewRecorder()
	h.IdentityUpgradeCanary(canaryRec, canary)
	if canaryRec.Code != http.StatusBadRequest {
		t.Fatalf("duplicate cohort: want 400, got %d (%s)",
			canaryRec.Code, canaryRec.Body.String())
	}

	ifMatchReq := httptest.NewRequest(http.MethodPost, "/", nil)
	ifMatchReq.Header.Set("If-Match", `"old"`)
	ifMatchRec := httptest.NewRecorder()
	if identityIfMatch(ifMatchRec, ifMatchReq, "new") ||
		ifMatchRec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: want 412, got %d (%s)",
			ifMatchRec.Code, ifMatchRec.Body.String())
	}

	scopedReq := identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/upgrade/status", "")
	scopedReq = scopedReq.WithContext(
		middleware.ContextWithDomainScope(scopedReq.Context(), 9))
	scopedRec := httptest.NewRecorder()
	h.IdentityUpgradeStatus(scopedRec, scopedReq)
	if scopedRec.Code != http.StatusForbidden {
		t.Fatalf("scoped upgrade: want 403, got %d (%s)",
			scopedRec.Code, scopedRec.Body.String())
	}
}

func TestIdentityUpgradeAndPreviewRejectEveryLocalBoundary(t *testing.T) {
	h := NewIdentityHandler(nil, nil, testsupport.TestLogger())
	reason := "identity local boundary test"
	sourceKey := "local-boundary"
	key := "00000000-0000-4000-8000-000000000019"
	admin := func(method, target, body string) *http.Request {
		req := identityV2RequestWithActor(method, target, body)
		req.Header.Set("X-Audit-Reason", reason)
		return req
	}
	call := func(
		name string,
		handler func(http.ResponseWriter, *http.Request),
		req *http.Request,
		want int,
	) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, req)
			if rec.Code != want {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, want, rec.Body.String())
			}
		})
	}

	validCanary := `{"sourceKey":"` + sourceKey +
		`","expectedGeneration":"1","enabled":false,"userIds":[],` +
		`"reason":"` + reason + `"}`
	for _, tc := range []struct {
		name string
		body string
		edit func(*http.Request)
		want int
	}{
		{"malformed", `{`, nil, http.StatusBadRequest},
		{"reason mismatch", validCanary, func(r *http.Request) {
			r.Header.Set("X-Audit-Reason", "different")
		}, http.StatusBadRequest},
		{"invalid source", strings.Replace(validCanary, sourceKey, "bad key", 1),
			nil, http.StatusBadRequest},
		{"missing optional if match", validCanary, nil, http.StatusServiceUnavailable},
		{"stale if match", validCanary, func(r *http.Request) {
			r.Header.Set("If-Match", `"2"`)
		}, http.StatusPreconditionFailed},
		{"invalid user", strings.Replace(validCanary, `"userIds":[]`,
			`"userIds":["bad"]`, 1), func(r *http.Request) {
			r.Header.Set("If-Match", `"1"`)
		}, http.StatusBadRequest},
		{"duplicate user", strings.Replace(validCanary, `"userIds":[]`,
			`"userIds":["7","7"]`, 1), func(r *http.Request) {
			r.Header.Set("If-Match", `"1"`)
		}, http.StatusBadRequest},
		{"enabled empty", strings.Replace(validCanary, `"enabled":false`,
			`"enabled":true`, 1), func(r *http.Request) {
			r.Header.Set("If-Match", `"1"`)
		}, http.StatusBadRequest},
		{"worker missing", validCanary, func(r *http.Request) {
			r.Header.Set("If-Match", `"1"`)
		}, http.StatusServiceUnavailable},
	} {
		req := admin(http.MethodPost, "/admin/identity/v2/upgrade/canary", tc.body)
		if tc.edit != nil {
			tc.edit(req)
		}
		call("canary "+tc.name, h.IdentityUpgradeCanary, req, tc.want)
	}
	users := make([]string, 501)
	for index := range users {
		users[index] = strconv.Itoa(index + 1)
	}
	oversized, err := json.Marshal(map[string]any{
		"sourceKey": sourceKey, "expectedGeneration": "1",
		"enabled": false, "userIds": users, "reason": reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	oversizedReq := admin(http.MethodPost,
		"/admin/identity/v2/upgrade/canary", string(oversized))
	oversizedReq.Header.Set("If-Match", `"1"`)
	call("canary oversized cohort", h.IdentityUpgradeCanary,
		oversizedReq, http.StatusBadRequest)

	unauthCanary := httptest.NewRequest(http.MethodPost,
		"/admin/identity/v2/upgrade/canary", strings.NewReader(validCanary))
	unauthCanary.Header.Set("X-Audit-Reason", reason)
	unauthCanary.Header.Set("If-Match", `"1"`)
	call("canary unauthenticated", h.IdentityUpgradeCanary,
		unauthCanary, http.StatusUnauthorized)

	validRollback := `{"readPath":"legacy","reason":"` + reason + `"}`
	call("rollback malformed", h.IdentityUpgradeRollback,
		admin(http.MethodPost, "/upgrade/rollback", `{`), http.StatusBadRequest)
	call("rollback wrong path", h.IdentityUpgradeRollback,
		admin(http.MethodPost, "/upgrade/rollback",
			`{"readPath":"normalized","reason":"`+reason+`"}`),
		http.StatusBadRequest)
	unauthRollback := httptest.NewRequest(http.MethodPost, "/upgrade/rollback",
		strings.NewReader(validRollback))
	unauthRollback.Header.Set("X-Audit-Reason", reason)
	call("rollback unauthenticated", h.IdentityUpgradeRollback,
		unauthRollback, http.StatusUnauthorized)
	call("rollback worker missing", h.IdentityUpgradeRollback,
		admin(http.MethodPost, "/upgrade/rollback", validRollback),
		http.StatusServiceUnavailable)

	validPreview := `{"userId":"42","reason":"` + reason +
		`","idempotencyKey":"` + key + `"}`
	for _, tc := range []struct {
		name string
		body string
		edit func(*http.Request)
		want int
	}{
		{"malformed", `{`, nil, http.StatusBadRequest},
		{"reason mismatch", validPreview, func(r *http.Request) {
			r.Header.Set("X-Audit-Reason", "different")
		}, http.StatusBadRequest},
		{"key mismatch", validPreview, func(r *http.Request) {
			r.Header.Set("Idempotency-Key", uuid.NewString())
		}, http.StatusBadRequest},
		{"invalid user", strings.Replace(validPreview, `"42"`, `"bad"`, 1),
			nil, http.StatusBadRequest},
		{"worker missing", validPreview, func(r *http.Request) {
			r.Header.Set("Idempotency-Key", key)
		}, http.StatusServiceUnavailable},
	} {
		req := admin(http.MethodPost, "/transitions/preview", tc.body)
		if tc.edit != nil {
			tc.edit(req)
		}
		call("preview "+tc.name, h.TransitionPreview, req, tc.want)
	}
	unauthPreview := httptest.NewRequest(http.MethodPost, "/transitions/preview",
		strings.NewReader(validPreview))
	unauthPreview.Header.Set("X-Audit-Reason", reason)
	call("preview unauthenticated", h.TransitionPreview,
		unauthPreview, http.StatusUnauthorized)
}

func TestIdentityStrictJSONReasonAndETag(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":  `{"reason":"ok","unknown":true}`,
		"trailing": `{"reason":"ok"}{"reason":"again"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var request struct {
				Reason string `json:"reason"`
			}
			rec := httptest.NewRecorder()
			if decodeIdentityJSON(rec,
				httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)),
				&request, "invalid") ||
				rec.Code != http.StatusBadRequest {
				t.Fatalf("want strict 400, got %d (%s)", rec.Code, rec.Body.String())
			}
		})
	}
	oversized := `{"reason":"` + strings.Repeat("x", identityBodyMaxBytes) + `"}`
	oversizedRec := httptest.NewRecorder()
	var oversizedRequest struct {
		Reason string `json:"reason"`
	}
	if decodeIdentityJSON(oversizedRec,
		httptest.NewRequest(http.MethodPost, "/", strings.NewReader(oversized)),
		&oversizedRequest, "invalid") ||
		oversizedRec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: want 413, got %d (%s)",
			oversizedRec.Code, oversizedRec.Body.String())
	}

	for _, reason := range []string{"", "   ", "line\nbreak", strings.Repeat("x", 1025)} {
		if validIdentityReason(reason) {
			t.Fatalf("reason unexpectedly accepted: %q", reason)
		}
	}

	first := httptest.NewRecorder()
	writeIdentityJSON(first, httptest.NewRequest(http.MethodGet, "/", nil),
		http.StatusOK, map[string]any{"items": []any{}})
	if first.Code != http.StatusOK || first.Header().Get("ETag") == "" {
		t.Fatalf("first response: status=%d etag=%q", first.Code, first.Header().Get("ETag"))
	}
	secondReq := httptest.NewRequest(http.MethodGet, "/", nil)
	secondReq.Header.Set("If-None-Match", first.Header().Get("ETag"))
	second := httptest.NewRecorder()
	writeIdentityJSON(second, secondReq, http.StatusOK,
		map[string]any{"items": []any{}})
	if second.Code != http.StatusNotModified || second.Body.Len() != 0 {
		t.Fatalf("conditional response: status=%d body=%q", second.Code, second.Body.String())
	}
}

func TestIdentitySourcesCursorPaginationLive(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(rolesTestRandomSuffix(t))
	prefix := "api-page-" + suffix
	keys := []string{prefix + "-a", prefix + "-b"}
	for _, key := range keys {
		if _, err := pool.Exec(ctx, `
			INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state)
			VALUES($1,$2,'ldap','{"immutableSubject":true}'::jsonb,'draft')
		`, key, key); err != nil {
			t.Fatalf("seed identity source %s: %v", key, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_sources WHERE source_key=ANY($1::text[])`, keys)
	})

	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	firstReq := identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/sources?filter="+prefix+"&limit=1", "")
	firstRec := httptest.NewRecorder()
	h.Sources(firstRec, firstReq)
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first page: status=%d body=%s", firstRec.Code, firstRec.Body.String())
	}
	var first struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(firstRec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first page: %v", err)
	}
	if len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("first page shape: %+v", first)
	}

	secondReq := identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/sources?filter="+prefix+"&limit=1&cursor="+first.NextCursor, "")
	secondRec := httptest.NewRecorder()
	h.Sources(secondRec, secondReq)
	if secondRec.Code != http.StatusOK {
		t.Fatalf("second page: status=%d body=%s", secondRec.Code, secondRec.Body.String())
	}
	var second struct {
		Items      []map[string]any `json:"items"`
		NextCursor string           `json:"nextCursor"`
	}
	if err := json.Unmarshal(secondRec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second page: %v", err)
	}
	if len(second.Items) != 1 || second.NextCursor != "" {
		t.Fatalf("second page shape: %+v", second)
	}
	if first.Items[0]["sourceKey"] == second.Items[0]["sourceKey"] {
		t.Fatalf("cursor repeated source %v", first.Items[0]["sourceKey"])
	}
}
