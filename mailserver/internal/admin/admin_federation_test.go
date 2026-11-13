package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// fedTestAnchorPEM is a real, self-signed, structurally-valid X.509
// certificate (openssl req -x509 -newkey ed25519 …) — needed because
// UpsertPeer runs a real smime.Fingerprint/x509 parse, not just a PEM-shape
// check.
const fedTestAnchorPEM = `-----BEGIN CERTIFICATE-----
MIIBRDCB96ADAgECAhR3pWQWRoEA80HoVpp5P81E+Q/E0zAFBgMrZXAwGDEWMBQG
A1UEAwwNZmVkdGVzdC5sb2NhbDAeFw0yNjA3MTcwNDA2NDdaFw0yNjA3MTgwNDA2
NDdaMBgxFjAUBgNVBAMMDWZlZHRlc3QubG9jYWwwKjAFBgMrZXADIQD9C5lOivHc
0cgWAiZHctuCCOwrOuP6J2nKXnGHV2UmOKNTMFEwHQYDVR0OBBYEFO2LuohceG3F
BxKZjrq4eK4ipVPNMB8GA1UdIwQYMBaAFO2LuohceG3FBxKZjrq4eK4ipVPNMA8G
A1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA8gfkKxaphDGkMhmhp7zoDKE+fgvWdFMK
b1Az+qkRfrpk9jWqHMpPPWQQNtUJNF/oYce/ZsSW3217tsz+Acm+AA==
-----END CERTIFICATE-----`

func newFederationHandlerForTest(t *testing.T) *FederationHandler {
	t.Helper()
	return newFederationHandlerForTestWithDomain(t, "")
}

// newFederationHandlerForTestWithDomain builds a FederationHandler with a
// specific FederationLocalDomain (Task 5: config.Config.FederationLocalDomain,
// no more process-env read inside the handler) — used by
// TestFederationPeers_SelfDomainRefused below.
func newFederationHandlerForTestWithDomain(t *testing.T, localDomain string) *FederationHandler {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	// mail (DB_DSN's role in dev/test) is a superuser, which implicitly
	// bypasses FORCE RLS the same way setjoin_worker's BYPASSRLS attribute
	// does in production — so passing the same pool for both args mirrors
	// the documented "workerPool aliases pool until DB_WORKER_DSN is set"
	// INERT-today posture everywhere else in this codebase.
	return NewFederationHandler(pool, pool, localDomain, testsupport.TestLogger())
}

func fedTestActor(t *testing.T) int64 {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	return ssCreateUser(t, pool)
}

// TestFederationPeers_RequiresManagePerm pins the route-level gate: every
// federation console endpoint 403s a caller without federation.manage.
func TestFederationPeers_RequiresManagePerm(t *testing.T) {
	h := newFederationHandlerForTest(t)
	actorID := fedTestActor(t)

	var perms []string
	for _, p := range permissions.AllPermissions {
		if p != permissions.PermFederationManage {
			perms = append(perms, p)
		}
	}
	noPerm := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: perms}

	for _, tc := range []struct {
		method  string
		path    string
		body    string
		handler func(w http.ResponseWriter, r *http.Request)
		domain  string
	}{
		{"GET", "/admin/federation/peers", "", h.ListPeers, ""},
		{"POST", "/admin/federation/peers", `{"domain":"x.test","anchorPem":"x","scope":"dm","enabled":true}`, h.UpsertPeer, ""},
		{"DELETE", "/admin/federation/peers/x.test", "", h.DeletePeer, "x.test"},
	} {
		tc := tc
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req = req.WithContext(auth.ContextWithUser(req.Context(), noPerm))
			if tc.domain != "" {
				req.SetPathValue("domain", tc.domain)
			}
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: want 403, got %d (body=%s)", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestFederationPeers_ListWithPerm pins the 200 path.
func TestFederationPeers_ListWithPerm(t *testing.T) {
	h := newFederationHandlerForTest(t)
	actorID := fedTestActor(t)
	manager := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermFederationManage}}

	req := httptest.NewRequest("GET", "/admin/federation/peers", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.ListPeers(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListPeers: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var out []federationPeerResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ListPeers: response is not a JSON array: %v (body=%s)", err, rec.Body.String())
	}
}

// TestFederationPeers_SelfDomainRefused pins the Go-side self-domain
// refusal against config.Config.FederationLocalDomain (Task 5) — the reducer
// cannot see process config, so this check exists ONLY in the handler.
func TestFederationPeers_SelfDomainRefused(t *testing.T) {
	h := newFederationHandlerForTestWithDomain(t, "Alpha.Test")
	actorID := fedTestActor(t)
	manager := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermFederationManage}}

	body := `{"domain":"alpha.test","anchorPem":` + jsonStr(fedTestAnchorPEM) + `,"scope":"dm","enabled":false}`
	req := httptest.NewRequest("POST", "/admin/federation/peers", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.UpsertPeer(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("UpsertPeer(self-domain): want 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestFederationPeers_InvalidAnchorRejected pins the real x509 parse — a
// PEM-shaped-but-garbage anchor (the reducer's own shallow check would let
// this through) must 400 at the Go layer.
func TestFederationPeers_InvalidAnchorRejected(t *testing.T) {
	h := newFederationHandlerForTest(t)
	actorID := fedTestActor(t)
	manager := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermFederationManage}}

	body := `{"domain":"badanchor.test","anchorPem":"-----BEGIN CERTIFICATE-----\nbm90IGEgcmVhbCBjZXJ0\n-----END CERTIFICATE-----","scope":"dm","enabled":false}`
	req := httptest.NewRequest("POST", "/admin/federation/peers", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.UpsertPeer(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("UpsertPeer(invalid anchor): want 400, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestFederationPeers_UpsertThenToggleThenDelete exercises the full
// lifecycle a real admin console drives: add (real anchor required) ->
// toggle enabled with a BLANK anchorPem (carries the existing anchor
// forward, the DES-011 fast-disable affordance) -> delete requires
// disabled-first -> disable -> delete succeeds.
func TestFederationPeers_UpsertThenToggleThenDelete(t *testing.T) {
	h := newFederationHandlerForTest(t)
	pool := testsupport.OpenTestPool(t)
	actorID := fedTestActor(t)
	manager := &auth.Claims{UserID: actorID, IsAdmin: true, Permissions: []string{permissions.PermFederationManage}}
	domain := "lifecycle-" + rolesTestRandomSuffix(t) + ".test"
	t.Cleanup(func() {
		pool.Exec(t.Context(), `DELETE FROM federation_allowlist WHERE peer_domain = $1`, domain)
	})

	// add, enabled=true, a real anchor.
	addBody := `{"domain":"` + domain + `","anchorPem":` + jsonStr(fedTestAnchorPEM) + `,"scope":"dm","enabled":true}`
	req := httptest.NewRequest("POST", "/admin/federation/peers", strings.NewReader(addBody))
	req = req.WithContext(auth.ContextWithUser(req.Context(), manager))
	rec := httptest.NewRecorder()
	h.UpsertPeer(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("add: want 204, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// delete while enabled -> 409-classified (BZ208).
	delReq := httptest.NewRequest("DELETE", "/admin/federation/peers/"+domain, nil)
	delReq = delReq.WithContext(auth.ContextWithUser(delReq.Context(), manager))
	delReq.SetPathValue("domain", domain)
	delRec := httptest.NewRecorder()
	h.DeletePeer(delRec, delReq)
	if delRec.Code != http.StatusConflict {
		t.Fatalf("delete while enabled: want 409, got %d (body=%s)", delRec.Code, delRec.Body.String())
	}

	// toggle to disabled with a BLANK anchorPem — must succeed by carrying
	// the existing anchor forward, never demanding a re-paste.
	toggleBody := `{"domain":"` + domain + `","anchorPem":"","scope":"dm","enabled":false}`
	toggleReq := httptest.NewRequest("POST", "/admin/federation/peers", strings.NewReader(toggleBody))
	toggleReq = toggleReq.WithContext(auth.ContextWithUser(toggleReq.Context(), manager))
	toggleRec := httptest.NewRecorder()
	h.UpsertPeer(toggleRec, toggleReq)
	if toggleRec.Code != http.StatusNoContent {
		t.Fatalf("toggle disable (blank anchorPem): want 204, got %d (body=%s)", toggleRec.Code, toggleRec.Body.String())
	}
	var storedAnchor string
	if err := pool.QueryRow(t.Context(), `SELECT peer_anchor FROM federation_allowlist WHERE peer_domain = $1`, domain).Scan(&storedAnchor); err != nil {
		t.Fatalf("read back stored anchor: %v", err)
	}
	if !strings.Contains(storedAnchor, "fedtest.local") && storedAnchor == "" {
		t.Fatalf("toggle wiped the anchor instead of carrying it forward: %q", storedAnchor)
	}

	// now disabled -> delete succeeds.
	delReq2 := httptest.NewRequest("DELETE", "/admin/federation/peers/"+domain, nil)
	delReq2 = delReq2.WithContext(auth.ContextWithUser(delReq2.Context(), manager))
	delReq2.SetPathValue("domain", domain)
	delRec2 := httptest.NewRecorder()
	h.DeletePeer(delRec2, delReq2)
	if delRec2.Code != http.StatusNoContent {
		t.Fatalf("delete while disabled: want 204, got %d (body=%s)", delRec2.Code, delRec2.Body.String())
	}

	// deleting again (already gone) -> 404.
	delReq3 := httptest.NewRequest("DELETE", "/admin/federation/peers/"+domain, nil)
	delReq3 = delReq3.WithContext(auth.ContextWithUser(delReq3.Context(), manager))
	delReq3.SetPathValue("domain", domain)
	delRec3 := httptest.NewRecorder()
	h.DeletePeer(delRec3, delReq3)
	if delRec3.Code != http.StatusNotFound {
		t.Fatalf("delete already-gone: want 404, got %d (body=%s)", delRec3.Code, delRec3.Body.String())
	}
}

// jsonStr JSON-encodes s as a quoted string literal, for embedding a
// multi-line PEM into a hand-written JSON request body.
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
