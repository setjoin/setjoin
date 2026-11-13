package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

const identityConflictTestID = "10000000-0000-4000-8000-000000000001"
const identityConflictTestKey = "20000000-0000-4000-8000-000000000002"

func newIdentityConflictDecisionRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	req := identityV2RequestWithActor(http.MethodPost,
		"/admin/identity/v2/conflicts/"+identityConflictTestID+"/decision", body)
	req.SetPathValue("id", identityConflictTestID)
	req.Header.Set("Idempotency-Key", identityConflictTestKey)
	req.Header.Set("If-Match", `"1"`)
	req.Header.Set("X-Audit-Reason", "reviewed evidence")
	return req
}

func TestIdentityPeopleConflictPathValidation(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil)

	person := identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/people/nope", "")
	person.SetPathValue("id", "nope")
	personRec := httptest.NewRecorder()
	h.IdentityPersonDetail(personRec, person)
	if personRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid person id: got %d (%s)", personRec.Code, personRec.Body.String())
	}

	conflict := identityV2RequestWithActor(http.MethodGet,
		"/admin/identity/v2/conflicts/nope", "")
	conflict.SetPathValue("id", "nope")
	conflictRec := httptest.NewRecorder()
	h.IdentityConflictDetail(conflictRec, conflict)
	if conflictRec.Code != http.StatusBadRequest {
		t.Fatalf("invalid conflict id: got %d (%s)",
			conflictRec.Code, conflictRec.Body.String())
	}

	noAuth := httptest.NewRequest(http.MethodGet,
		"/admin/identity/v2/people/1", nil)
	noAuth.SetPathValue("id", "1")
	noAuthRec := httptest.NewRecorder()
	h.IdentityPersonDetail(noAuthRec, noAuth)
	if noAuthRec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated detail: got %d (%s)",
			noAuthRec.Code, noAuthRec.Body.String())
	}
}

func TestIdentityPeopleConflictMissingAndUnauthenticatedCasesAreOpaque(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	missingConflict := uuid.NewString()

	for name, tc := range map[string]struct {
		handler func(http.ResponseWriter, *http.Request)
		req     *http.Request
	}{
		"person": {
			handler: h.IdentityPersonDetail,
			req:     httptest.NewRequest(http.MethodGet, "/people/1", nil),
		},
		"conflict": {
			handler: h.IdentityConflictDetail,
			req:     httptest.NewRequest(http.MethodGet, "/conflicts/"+missingConflict, nil),
		},
		"decision": {
			handler: h.IdentityConflictDecision,
			req: httptest.NewRequest(http.MethodPost, "/conflicts/"+missingConflict+"/decision",
				strings.NewReader(`{"decision":"reject"}`)),
		},
	} {
		t.Run(name+" unauthenticated", func(t *testing.T) {
			if name == "person" {
				tc.req.SetPathValue("id", "1")
			} else {
				tc.req.SetPathValue("id", missingConflict)
			}
			rec := httptest.NewRecorder()
			tc.handler(rec, tc.req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	person := identityV2RequestWithActor(http.MethodGet, "/people/9223372036854775807", "")
	person.SetPathValue("id", "9223372036854775807")
	personRec := httptest.NewRecorder()
	h.IdentityPersonDetail(personRec, person)
	if personRec.Code != http.StatusNotFound {
		t.Fatalf("missing person status=%d body=%s", personRec.Code, personRec.Body.String())
	}

	conflict := identityV2RequestWithActor(http.MethodGet, "/conflicts/"+missingConflict, "")
	conflict.SetPathValue("id", missingConflict)
	conflictRec := httptest.NewRecorder()
	h.IdentityConflictDetail(conflictRec, conflict)
	if conflictRec.Code != http.StatusNotFound {
		t.Fatalf("missing conflict status=%d body=%s", conflictRec.Code, conflictRec.Body.String())
	}

	decision := newIdentityConflictDecisionRequest(t,
		`{"decision":"reject","expectedGeneration":"1","reason":"reviewed evidence",`+
			`"idempotencyKey":"`+identityConflictTestKey+`"}`)
	decision.SetPathValue("id", missingConflict)
	decisionRec := httptest.NewRecorder()
	h.IdentityConflictDecision(decisionRec, decision)
	if decisionRec.Code != http.StatusNotFound {
		t.Fatalf("missing decision status=%d body=%s", decisionRec.Code, decisionRec.Body.String())
	}
}

func TestIdentityConflictDecisionRejectsInvalidContractsBeforeDatabase(t *testing.T) {
	h := NewIdentityHandler(nil, nil, nil)
	valid := `{"decision":"reject","expectedGeneration":"1","reason":"reviewed evidence",` +
		`"idempotencyKey":"` + identityConflictTestKey + `"}`

	tests := []struct {
		name string
		req  func() *http.Request
		code int
	}{
		{
			name: "unknown field",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.TrimSuffix(valid, "}")+`,"bulk":true}`)
			},
			code: http.StatusBadRequest,
		},
		{
			name: "unsupported decision",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.Replace(valid, `"reject"`, `"merge"`, 1))
			},
			code: http.StatusBadRequest,
		},
		{
			name: "control character reason",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.Replace(valid, `"reviewed evidence"`, `"bad\nreason"`, 1))
			},
			code: http.StatusBadRequest,
		},
		{
			name: "idempotency mismatch",
			req: func() *http.Request {
				req := newIdentityConflictDecisionRequest(t, valid)
				req.Header.Set("Idempotency-Key",
					"30000000-0000-4000-8000-000000000003")
				return req
			},
			code: http.StatusBadRequest,
		},
		{
			name: "audit reason mismatch",
			req: func() *http.Request {
				req := newIdentityConflictDecisionRequest(t, valid)
				req.Header.Set("X-Audit-Reason", "different reason")
				return req
			},
			code: http.StatusBadRequest,
		},
		{
			name: "stale generation fence",
			req: func() *http.Request {
				req := newIdentityConflictDecisionRequest(t, valid)
				req.Header.Set("If-Match", `"2"`)
				return req
			},
			code: http.StatusPreconditionFailed,
		},
		{
			name: "person only for link",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.TrimSuffix(valid, "}")+`,"personId":"7"}`)
			},
			code: http.StatusBadRequest,
		},
		{
			name: "link requires person",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.Replace(valid, `"reject"`, `"link"`, 1))
			},
			code: http.StatusBadRequest,
		},
		{
			name: "link rejects invalid person",
			req: func() *http.Request {
				return newIdentityConflictDecisionRequest(t,
					strings.TrimSuffix(
						strings.Replace(valid, `"reject"`, `"link"`, 1), "}")+
						`,"personId":"bad"}`)
			},
			code: http.StatusBadRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.IdentityConflictDecision(rec, test.req())
			if rec.Code != test.code {
				t.Fatalf("got %d (%s), want %d",
					rec.Code, rec.Body.String(), test.code)
			}
		})
	}

	ready := newIdentityConflictDecisionRequest(t, valid)
	readyRec := httptest.NewRecorder()
	h.IdentityConflictDecision(readyRec, ready)
	if readyRec.Code != http.StatusServiceUnavailable {
		t.Fatalf("valid contract should reach worker gate: got %d (%s)",
			readyRec.Code, readyRec.Body.String())
	}
}

func TestIdentityPeopleConflictHandlersWithReducers(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := strings.ToLower(uuid.NewString()[:8])
	var actorMailbox, personMailbox int64
	if err := pool.QueryRow(ctx,
		`SELECT mk_account($1)`, "identity-api-actor-"+suffix).Scan(&actorMailbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT mk_account($1)`, "identity-api-person-"+suffix).Scan(&personMailbox); err != nil {
		t.Fatal(err)
	}
	var actorID, personID int64
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, actorMailbox).Scan(&actorID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT user_id FROM mailboxes WHERE id=$1`, personMailbox).Scan(&personID); err != nil {
		t.Fatal(err)
	}
	var roleID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO admin_role_groups(name,permissions)
		VALUES($1,ARRAY['users.read','identity.write'])
		RETURNING id
	`, "identity-api-"+uuid.NewString()).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
		VALUES($1,$2,$1)
	`, actorID, roleID); err != nil {
		t.Fatal(err)
	}
	var sourceID int64
	sourceKey := "test:" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if err := pool.QueryRow(ctx, `
		INSERT INTO identity_sources(
		    source_key,display_name,kind,capabilities,state
		) VALUES(
		    $1,'Identity API test','ldap',
		    '{"authenticate":false,"provision_lifecycle":true,"stable_immutable_subject":true}'::jsonb,
		    'active'
		) RETURNING id
	`, sourceKey).Scan(&sourceID); err != nil {
		t.Fatal(err)
	}
	rawSubject := "handler-secret-subject-" + uuid.NewString()
	var candidateID string
	if err := pool.QueryRow(ctx, `
		SELECT identity_match_record(
		    $1,$2,1,$3,$4,'hard',digest($3,'sha256'),
		    'immutable anchor matched',statement_timestamp()+interval '1 day'
		)->>'id'
	`, actorID, sourceID, rawSubject, personID).Scan(&candidateID); err != nil {
		t.Fatal(err)
	}
	var secondCandidateID string
	if err := pool.QueryRow(ctx, `
		SELECT identity_match_record(
		    $1,$2,1,$3,$4,'hard',digest($3,'sha256'),
		    'second immutable anchor matched',statement_timestamp()+interval '1 day'
		)->>'id'
	`, actorID, sourceID, rawSubject+"-second", personID).Scan(&secondCandidateID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.Background()
		for _, id := range []string{candidateID, secondCandidateID} {
			cleanupIdentityMatchDecision(t, pool, id)
			if _, err := pool.Exec(cleanup,
				`DELETE FROM identity_match_candidates WHERE id=$1`, id,
			); err != nil {
				t.Errorf("delete identity match candidate fixture: %v", err)
			}
		}
		cleanupIdentityLinkEventsForSource(t, pool, sourceID)
		_, _ = pool.Exec(cleanup,
			`DELETE FROM admin_role_assignments WHERE user_id=$1 AND role_group_id=$2`,
			actorID, roleID)
		_, _ = pool.Exec(cleanup, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		if _, err := pool.Exec(cleanup,
			`DELETE FROM identity_sources WHERE id=$1`, sourceID,
		); err != nil {
			t.Errorf("delete identity source fixture: %v", err)
		}
		_, _ = pool.Exec(cleanup,
			`DELETE FROM mailboxes WHERE id=ANY($1::bigint[])`,
			[]int64{actorMailbox, personMailbox})
		_, _ = pool.Exec(cleanup,
			`DELETE FROM users WHERE id=ANY($1::bigint[])`, []int64{actorID, personID})
	})

	h := NewIdentityHandler(pool, pool, testsupport.TestLogger())
	requestForActor := func(method, target, body string) *http.Request {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		return req.WithContext(auth.ContextWithUser(
			req.Context(), &auth.Claims{UserID: actorID}))
	}
	for name, test := range map[string]struct {
		target  string
		handler func(http.ResponseWriter, *http.Request)
		needle  string
	}{
		"sources": {
			target:  "/admin/identity/v2/sources?source=" + sourceKey,
			handler: h.Sources,
			needle:  sourceKey,
		},
		"people": {
			target:  "/admin/identity/v2/people?filter=identity-api-person-" + suffix,
			handler: h.IdentityPeople,
			needle:  strconv.FormatInt(personID, 10),
		},
		"conflicts": {
			target:  "/admin/identity/v2/conflicts?source=" + sourceKey + "&state=pending",
			handler: h.IdentityConflicts,
			needle:  candidateID,
		},
	} {
		t.Run("list "+name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			test.handler(rec, requestForActor(http.MethodGet, test.target, ""))
			if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), test.needle) {
				t.Fatalf("%s list: status=%d body=%s",
					name, rec.Code, rec.Body.String())
			}
		})
	}

	for _, tc := range []struct {
		name    string
		target  string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"people", "/admin/identity/v2/people?limit=1", h.IdentityPeople},
		{"conflicts", "/admin/identity/v2/conflicts?source=" + sourceKey +
			"&state=pending&limit=1", h.IdentityConflicts},
	} {
		first := httptest.NewRecorder()
		tc.handler(first, requestForActor(http.MethodGet, tc.target, ""))
		if first.Code != http.StatusOK {
			t.Fatalf("%s first page: status=%d body=%s",
				tc.name, first.Code, first.Body.String())
		}
		var page struct {
			NextCursor string `json:"nextCursor"`
		}
		if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil ||
			page.NextCursor == "" {
			t.Fatalf("%s missing bounded cursor: %v body=%s",
				tc.name, err, first.Body.String())
		}
		separator := "&"
		if !strings.Contains(tc.target, "?") {
			separator = "?"
		}
		second := httptest.NewRecorder()
		tc.handler(second, requestForActor(http.MethodGet,
			tc.target+separator+"cursor="+page.NextCursor, ""))
		if second.Code != http.StatusOK {
			t.Fatalf("%s second page: status=%d body=%s",
				tc.name, second.Code, second.Body.String())
		}
	}

	personReq := requestForActor(http.MethodGet,
		"/admin/identity/v2/people/"+strconv.FormatInt(personID, 10), "")
	personReq.SetPathValue("id", strconv.FormatInt(personID, 10))
	personRec := httptest.NewRecorder()
	h.IdentityPersonDetail(personRec, personReq)
	if personRec.Code != http.StatusOK ||
		strings.Contains(personRec.Body.String(), rawSubject) {
		t.Fatalf("person detail: status=%d body=%s",
			personRec.Code, personRec.Body.String())
	}

	conflictReq := requestForActor(http.MethodGet,
		"/admin/identity/v2/conflicts/"+candidateID, "")
	conflictReq.SetPathValue("id", candidateID)
	conflictRec := httptest.NewRecorder()
	h.IdentityConflictDetail(conflictRec, conflictReq)
	if conflictRec.Code != http.StatusOK ||
		strings.Contains(conflictRec.Body.String(), rawSubject) {
		t.Fatalf("conflict detail: status=%d body=%s",
			conflictRec.Code, conflictRec.Body.String())
	}
	var conflict identityConflictDecisionRequest
	if err := json.Unmarshal([]byte(`{
		"decision":"reject","expectedGeneration":"1",
		"reason":"handler integration decision",
		"idempotencyKey":"20000000-0000-4000-8000-000000000099"
	}`), &conflict); err != nil {
		t.Fatal(err)
	}
	decisionBody, err := json.Marshal(conflict)
	if err != nil {
		t.Fatal(err)
	}
	decisionReq := requestForActor(http.MethodPost,
		"/admin/identity/v2/conflicts/"+candidateID+"/decision",
		string(decisionBody))
	decisionReq.SetPathValue("id", candidateID)
	decisionReq.Header.Set("Idempotency-Key", conflict.IdempotencyKey)
	decisionReq.Header.Set("If-Match", `"1"`)
	decisionReq.Header.Set("X-Audit-Reason", conflict.Reason)
	decisionRec := httptest.NewRecorder()
	h.IdentityConflictDecision(decisionRec, decisionReq)
	if decisionRec.Code != http.StatusOK {
		t.Fatalf("conflict decision: status=%d body=%s",
			decisionRec.Code, decisionRec.Body.String())
	}
	var result struct {
		State    string `json:"state"`
		Replayed bool   `json:"replayed"`
	}
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.State != "rejected" || result.Replayed {
		t.Fatalf("unexpected conflict decision: %+v", result)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE identity_match_candidates
		   SET candidate_user_id=NULL
		 WHERE id=$1
	`, secondCandidateID); err != nil {
		t.Fatal(err)
	}
	deferKey := uuid.NewString()
	deferBody := `{"decision":"defer","expectedGeneration":"1",` +
		`"reason":"defer unmatched anchor","idempotencyKey":"` + deferKey + `"}`
	deferReq := requestForActor(http.MethodPost,
		"/admin/identity/v2/conflicts/"+secondCandidateID+"/decision", deferBody)
	deferReq = deferReq.WithContext(auth.ContextWithUser(
		deferReq.Context(), &auth.Claims{
			UserID: actorID, GlobalPermissions: permissions.AllPermissions,
		}))
	deferReq.SetPathValue("id", secondCandidateID)
	deferReq.Header.Set("Idempotency-Key", deferKey)
	deferReq.Header.Set("If-Match", `"1"`)
	deferReq.Header.Set("X-Audit-Reason", "defer unmatched anchor")
	deferRec := httptest.NewRecorder()
	h.IdentityConflictDecision(deferRec, deferReq)
	if deferRec.Code != http.StatusOK ||
		!strings.Contains(deferRec.Body.String(), `"state": "deferred"`) {
		t.Fatalf("unmatched conflict defer: status=%d body=%s",
			deferRec.Code, deferRec.Body.String())
	}

	eventsReq := requestForActor(http.MethodGet,
		"/admin/identity/v2/events?source="+sourceKey, "")
	eventsRec := httptest.NewRecorder()
	h.IdentityEvents(eventsRec, eventsReq)
	if eventsRec.Code != http.StatusOK ||
		!strings.Contains(eventsRec.Body.String(), sourceKey) {
		t.Fatalf("identity events: status=%d body=%s",
			eventsRec.Code, eventsRec.Body.String())
	}
	firstEvents := requestForActor(http.MethodGet,
		"/admin/identity/v2/events?source="+sourceKey+"&limit=1", "")
	firstEventsRec := httptest.NewRecorder()
	h.IdentityEvents(firstEventsRec, firstEvents)
	var eventPage struct {
		NextCursor string `json:"nextCursor"`
	}
	if firstEventsRec.Code != http.StatusOK ||
		json.Unmarshal(firstEventsRec.Body.Bytes(), &eventPage) != nil ||
		eventPage.NextCursor == "" {
		t.Fatalf("identity event first page: status=%d body=%s",
			firstEventsRec.Code, firstEventsRec.Body.String())
	}
	secondEvents := requestForActor(http.MethodGet,
		"/admin/identity/v2/events?source="+sourceKey+
			"&limit=1&cursor="+eventPage.NextCursor, "")
	secondEventsRec := httptest.NewRecorder()
	h.IdentityEvents(secondEventsRec, secondEvents)
	if secondEventsRec.Code != http.StatusOK {
		t.Fatalf("identity event second page: status=%d body=%s",
			secondEventsRec.Code, secondEventsRec.Body.String())
	}
}
