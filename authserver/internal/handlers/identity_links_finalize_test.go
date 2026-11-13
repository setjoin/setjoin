package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/authserver/internal/federation"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

func TestFinalizeFederatedIdentityLink(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	mapper := newNoMappings("oidc")
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	flow := seedAuthorizedIdentityLinkFlow(
		t, pool, seeded.userID, "oidc", mapper.SSOProviderKey(),
	)
	provider := "https://link.example/" + randSuffix()
	subject := "subject-" + randSuffix()
	if !h.finalizeFederatedIdentityLink(rec, req, flow, provider, subject, []string{}, mapper) {
		t.Fatalf("federated link failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/settings?identity=linked" {
		t.Fatalf("terminal redirect = %d %q", rec.Code, rec.Header().Get("Location"))
	}

	var linkID, sourceID int64
	if err := pool.QueryRow(context.Background(), `
		SELECT l.id,s.id
		  FROM user_identity_links l
		  JOIN identity_sources s ON s.id=l.source_id
		 WHERE l.user_id=$1 AND s.kind='oidc'
		   AND s.provider_key=$2 AND l.external_subject=$3
		   AND l.state='active' AND 'authenticate'=ANY(l.purposes)`,
		seeded.userID, mapper.SSOProviderKey(), subject,
	).Scan(&linkID, &sourceID); err != nil {
		t.Fatalf("read finalized identity link: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Errorf("begin finalized link cleanup: %v", err)
			return
		}
		defer tx.Rollback(ctx) //nolint:errcheck
		if _, err := tx.Exec(ctx,
			`SET LOCAL session_replication_role = replica`); err != nil {
			t.Errorf("isolate finalized link cleanup: %v", err)
			return
		}
		for _, cleanup := range []struct {
			query string
			args  []any
		}{
			{`DELETE FROM identity_link_events WHERE link_id=$1 OR source_id=$2`,
				[]any{linkID, sourceID}},
			{`DELETE FROM identity_entitlement_grants WHERE link_id=$1`,
				[]any{linkID}},
			{`DELETE FROM user_identity_links WHERE id=$1`, []any{linkID}},
			{`DELETE FROM identity_sources WHERE id=$1`, []any{sourceID}},
		} {
			if _, err := tx.Exec(ctx, cleanup.query, cleanup.args...); err != nil {
				t.Errorf("delete finalized link fixture: %v", err)
				return
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Errorf("commit finalized link cleanup: %v", err)
		}
	})

	claims := &token.Claims{
		UserID: seeded.userID,
		ACR:    jwtutil.ACRAAL2,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
	}
	listReq := httptest.NewRequest(http.MethodGet, "/auth/identity-links", nil)
	listReq = listReq.WithContext(ContextWithUser(listReq.Context(), claims))
	listRec := httptest.NewRecorder()
	h.IdentityLinks(listRec, listReq)
	if listRec.Code != http.StatusOK ||
		!strings.Contains(listRec.Body.String(), strconv.FormatInt(linkID, 10)) {
		t.Fatalf("identity links status=%d body=%s",
			listRec.Code, listRec.Body.String())
	}

	if _, err := pool.Exec(context.Background(),
		`UPDATE users SET password_hash='identity-link-local-recovery' WHERE id=$1`,
		seeded.userID,
	); err != nil {
		t.Fatalf("seed unlink recovery: %v", err)
	}
	unlinkReq := httptest.NewRequest(http.MethodDelete,
		"/auth/identity-links/"+strconv.FormatInt(linkID, 10),
		strings.NewReader(`{"reason":"remove test identity provider"}`))
	unlinkReq.SetPathValue("id", strconv.FormatInt(linkID, 10))
	unlinkReq = unlinkReq.WithContext(ContextWithUser(unlinkReq.Context(), claims))
	unlinkRec := httptest.NewRecorder()
	h.IdentityUnlink(unlinkRec, unlinkReq)
	if unlinkRec.Code != http.StatusOK ||
		!strings.Contains(unlinkRec.Body.String(), `"unlinked": true`) {
		t.Fatalf("identity unlink status=%d body=%s",
			unlinkRec.Code, unlinkRec.Body.String())
	}
}

func TestFinalizeFederatedIdentityLinkStopsOnReducerRejection(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	mapper := newNoMappings("saml")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/saml/idp/acs", nil)
	flow := identityLinkFlow{
		UserID: -1, Kind: "saml", ProviderKey: mapper.SSOProviderKey(),
		FlowID: uuid.NewString(), SessionJTI: "missing",
		SessionHash: hex.EncodeToString(make([]byte, sha256.Size)),
	}
	if h.finalizeFederatedIdentityLink(rec, req, flow,
		"https://idp.example/"+randSuffix(), "nameid-"+randSuffix(), []string{}, mapper) {
		t.Fatal("federated link unexpectedly succeeded for an unavailable user")
	}
	if rec.Code < 400 {
		t.Fatalf("rejected federated link returned status %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("rejected federated link emitted a success redirect")
	}
}

func TestFinalizeFederatedIdentityLinkRejectsUnavailableTransactionAndMalformedBinding(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	if h.finalizeFederatedIdentityLink(rec, req, identityLinkFlow{
		UserID: 1, Kind: "oidc", ProviderKey: "oidc:workforce",
		FlowID: uuid.NewString(), SessionHash: "bad",
	}, "issuer", "subject", nil, nil) {
		t.Fatal("malformed session binding was accepted")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed binding status=%d body=%s", rec.Code, rec.Body.String())
	}

	pool.Close()
	rec = httptest.NewRecorder()
	if h.finalizeFederatedIdentityLink(rec, req, identityLinkFlow{
		UserID: 1, Kind: "oidc", ProviderKey: "oidc:workforce",
		FlowID:      uuid.NewString(),
		SessionHash: hex.EncodeToString(make([]byte, sha256.Size)),
	}, "issuer", "subject", nil, nil) {
		t.Fatal("link completed without a transaction")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable transaction status=%d body=%s",
			rec.Code, rec.Body.String())
	}
}

func TestAtomicIdentityLinkMappingRejectsUnboundedAndInvalidProviderInputs(t *testing.T) {
	pool := openHandlerPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	h := &deps{logger: discardLogger()}

	tooManyGroups := make([]string, identity.MaxSSOGroupClaims+1)
	if err := h.applyGroupMappingsAtomic(t.Context(), tx, 1, tooManyGroups,
		&staticMapper{providerKey: "oidc:bounded"}); err == nil {
		t.Fatal("unbounded group claims accepted")
	}
	tooManyMappings := make([]federation.GroupMapping, identity.MaxSSOGroupMappings+1)
	for index := range tooManyMappings {
		tooManyMappings[index].IDPGroup = "Engineering"
	}
	if err := h.applyGroupMappingsAtomic(t.Context(), tx, 1,
		[]string{"Engineering"},
		&staticMapper{providerKey: "oidc:bounded", mappings: tooManyMappings},
	); err == nil {
		t.Fatal("unbounded group mappings accepted")
	}
	if err := h.applyGroupMappingsAtomic(t.Context(), tx, 1,
		[]string{"Engineering"},
		&staticMapper{
			providerKey: "invalid provider key",
			mappings: []federation.GroupMapping{{
				IDPGroup: "Engineering",
			}},
		},
	); err == nil {
		t.Fatal("invalid provider key accepted")
	}
	if err := h.applyGroupMappingsAtomic(t.Context(), tx, 1, nil,
		&staticMapper{providerKey: "oidc:bounded"}); err != nil {
		t.Fatalf("nil claims should be a no-op: %v", err)
	}
}

func TestAtomicIdentityLinkMappingAppliesDistributionAdminAndDepartmentGrants(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	groupID := seedSSODistributionGroup(t, pool, t.Context(), "atomic-all")
	var personMailboxID int64
	if err := pool.QueryRow(t.Context(), `
		SELECT id FROM mailboxes
		 WHERE user_id=$1 AND is_primary=TRUE
		 ORDER BY id LIMIT 1
	`, seeded.userID).Scan(&personMailboxID); err != nil {
		t.Fatal(err)
	}
	var departmentID int64
	if err := pool.QueryRow(t.Context(), `
		INSERT INTO departments(name,path,ldap_ou)
		VALUES($1,$2,$3) RETURNING id
	`, "Atomic "+randSuffix(), "/atomic/"+randSuffix(), "ou=atomic").Scan(
		&departmentID,
	); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`UPDATE users SET department_id=NULL WHERE id=$1`, seeded.userID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM departments WHERE id=$1`, departmentID)
	})
	adminRole := "user_admin"
	mapper := &staticMapper{
		providerKey: "oidc:atomic-all-" + randSuffix(),
		mappings: []federation.GroupMapping{
			{IDPGroup: "distribution", DistributionGroupID: &groupID},
			{IDPGroup: "administrators", AdminRole: &adminRole},
			{IDPGroup: "department", DepartmentID: &departmentID},
			{IDPGroup: "not-present", DistributionGroupID: &groupID},
		},
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context()) //nolint:errcheck
	h := &deps{logger: discardLogger()}
	if err := h.applyGroupMappingsAtomic(
		t.Context(), tx, seeded.userID,
		[]string{"distribution", "administrators", "department"}, mapper,
	); err != nil {
		t.Fatalf("apply all governed mapping classes: %v", err)
	}
	var membership, assignment int
	var gotDepartment *int64
	if err := tx.QueryRow(t.Context(), `
		SELECT
		  (SELECT count(*) FROM distribution_group_members
		    WHERE group_id=$1 AND mailbox_id=$2 AND source='sso'),
		  (SELECT count(*) FROM admin_role_assignments
		    WHERE user_id=$3 AND role_group_id=2),
		  (SELECT department_id FROM users WHERE id=$3)
	`, groupID, personMailboxID, seeded.userID).Scan(
		&membership, &assignment, &gotDepartment,
	); err != nil {
		t.Fatal(err)
	}
	if membership != 1 || assignment != 1 || gotDepartment == nil ||
		*gotDepartment != departmentID {
		t.Fatalf("mapping results membership=%d assignment=%d department=%v",
			membership, assignment, gotDepartment)
	}
}

func TestFinalizeFederatedIdentityLinkRollsBackOnMappingFailure(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	missingGroupID := int64(9_223_372_036_854_000_000)
	mapper := &staticMapper{
		providerKey: "oidc:atomic-" + randSuffix(),
		mappings: []federation.GroupMapping{{
			IDPGroup: "atomic-linkers", DistributionGroupID: &missingGroupID,
		}},
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	provider := "https://atomic-link.example/" + randSuffix()
	subject := "subject-" + randSuffix()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	flow := seedAuthorizedIdentityLinkFlow(
		t, pool, seeded.userID, "oidc", mapper.SSOProviderKey(),
	)
	if h.finalizeFederatedIdentityLink(
		rec, req, flow, provider, subject, []string{"atomic-linkers"}, mapper,
	) {
		t.Fatal("link unexpectedly succeeded after a governed mapping failure")
	}
	if rec.Code != http.StatusConflict || rec.Header().Get("Location") != "" {
		t.Fatalf("mapping failure status/location = %d/%q", rec.Code, rec.Header().Get("Location"))
	}
	var links int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*)
		  FROM user_identity_links l
		  JOIN identity_sources s ON s.id=l.source_id
		 WHERE l.user_id=$1 AND s.provider_key=$2
		   AND l.external_subject=$3`,
		seeded.userID, mapper.SSOProviderKey(), subject,
	).Scan(&links); err != nil {
		t.Fatalf("read rolled-back link: %v", err)
	}
	if links != 0 {
		t.Fatalf("mapping failure left %d durable identity links", links)
	}
}

func TestAuthorizedIdentityLinkWaitsForRevocationAndFailsClosed(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	mapper := newNoMappings("oidc")
	flow := seedAuthorizedIdentityLinkFlow(
		t, pool, seeded.userID, "oidc", mapper.SSOProviderKey(),
	)
	sessionHash, err := hex.DecodeString(flow.SessionHash)
	if err != nil {
		t.Fatal(err)
	}

	revokeTx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer revokeTx.Rollback(t.Context()) //nolint:errcheck
	if _, err := revokeTx.Exec(t.Context(), `
		SELECT revoke_user_sessions($1,'all','concurrent test',NULL,NULL,NULL)`,
		seeded.userID); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		var result []byte
		done <- pool.QueryRow(context.Background(), `
			SELECT identity_auth_link_authorized(
				$1,$1,'oidc',$2,$3,$4,$5,$6::uuid,$7
			)`,
			seeded.userID, "https://race.example",
			"subject-"+randSuffix(), mapper.SSOProviderKey(),
			"concurrent callback", flow.FlowID, sessionHash,
		).Scan(&result)
	}()
	select {
	case err := <-done:
		t.Fatalf("link completed before revocation transaction committed: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := revokeTx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("link succeeded after the earlier revocation committed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("link did not resume after revocation committed")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*) FROM user_identity_links
		 WHERE user_id=$1 AND external_subject LIKE 'subject-%'`,
		seeded.userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("concurrent revocation left %d durable links", count)
	}
}

func seedAuthorizedIdentityLinkFlow(
	t *testing.T,
	pool *pgxpool.Pool,
	userID int64,
	kind string,
	providerKey string,
) identityLinkFlow {
	t.Helper()
	ctx := context.Background()
	flowID := uuid.NewString()
	sessionJTI := uuid.NewString()
	sessionToken := "identity-link-session-" + uuid.NewString()
	sessionHash := sha256.Sum256([]byte(sessionToken))
	expiresAt := time.Now().Add(10 * time.Minute)
	if _, err := pool.Exec(ctx, `
		INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method)
		VALUES($1,$2,$3,$4,'webauthn')`,
		sessionJTI, userID, sessionHash[:], expiresAt,
	); err != nil {
		t.Fatalf("seed identity-link session: %v", err)
	}
	var result []byte
	if err := pool.QueryRow(ctx, `
		SELECT identity_auth_link_elevation_begin(
			$1,$2::uuid,$3,$4,$5,$6,$7
		)`,
		userID, flowID, sessionJTI, sessionHash[:], kind, providerKey, expiresAt,
	).Scan(&result); err != nil {
		t.Fatalf("seed identity-link elevation: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM identity_auth_link_elevations WHERE flow_id=$1::uuid`,
			flowID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM sessions WHERE id=$1`, sessionJTI)
	})
	return identityLinkFlow{
		UserID: userID, Kind: kind, ProviderKey: providerKey,
		FlowID: flowID, SessionJTI: sessionJTI,
		SessionHash: hex.EncodeToString(sessionHash[:]),
		ExpiresAt:   expiresAt.Unix(),
	}
}

func TestHandleFederatedIdentityLinkDistinguishesLoginFromInvalidFlow(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	mapper := newNoMappings("oidc")

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	link := federatedIdentityLink{"oidc", mapper.SSOProviderKey(), "https://issuer.example", "subject", nil, mapper}
	if h.handleFederatedIdentityLink(rec, req, link) {
		t.Fatal("ordinary login without a link cookie was treated as a link attempt")
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: identityLinkFlowCookie, Value: "malformed"})
	rec = httptest.NewRecorder()
	if !h.handleFederatedIdentityLink(rec, req, link) {
		t.Fatal("present link cookie was not treated as a terminal link attempt")
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid link flow status=%d want 400", rec.Code)
	}
}

func TestConsumeIdentityLinkAcceptsOnlyTheOriginalLiveAAL2Session(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	jwtProvider := newTestJWT()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: jwtProvider, Logger: discardLogger(),
		CookieKey: []byte("0123456789abcdef0123456789abcdef"),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	access, err := jwtProvider.IssueAccessFull(
		seeded.userID, seeded.primaryEmail, false,
		nil, nil, nil, nil,
		token.AuthContext{
			ACR: jwtutil.ACRAAL2,
			AMR: []string{
				jwtutil.AMRPassword,
				jwtutil.AMROTP,
				jwtutil.AMRMultiFactor,
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwtProvider.Validate(access)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.NewString()
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO sessions(id,user_id,token_hash,expires_at,auth_method)
		VALUES($1,$2,digest($3,'sha256'),statement_timestamp()+interval '1 hour','totp')
	`, sessionID, seeded.userID, access); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM sessions WHERE id=$1`, sessionID)
	})
	sum := sha256.Sum256([]byte(access))
	flow := identityLinkFlow{
		UserID: seeded.userID, Kind: "oidc", ProviderKey: "oidc:workforce",
		FlowID: uuid.NewString(), SessionJTI: claims.JTI,
		SessionHash: hex.EncodeToString(sum[:]),
		ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
	}
	raw, err := json.Marshal(flow)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := h.encryptCookieValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: identityLinkFlowCookie, Value: sealed})
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	rec := httptest.NewRecorder()
	got, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	)
	if !attempted || !valid || got.FlowID != flow.FlowID {
		t.Fatalf("live bound flow attempted=%v valid=%v flow=%+v status=%d body=%s",
			attempted, valid, got, rec.Code, rec.Body.String())
	}

	if _, err := pool.Exec(t.Context(),
		`DELETE FROM sessions WHERE id=$1`, sessionID); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	req.AddCookie(&http.Cookie{Name: identityLinkFlowCookie, Value: sealed})
	req.AddCookie(&http.Cookie{Name: "access_token", Value: access})
	rec = httptest.NewRecorder()
	if _, attempted, valid := h.consumeIdentityLink(
		rec, req, "oidc", "oidc:workforce",
	); !attempted || valid || rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session attempted=%v valid=%v status=%d body=%s",
			attempted, valid, rec.Code, rec.Body.String())
	}
}

func TestRejectFederatedGroupError(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{Logger: discardLogger()})
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	if h.rejectFederatedGroupError(rec, req, "OIDC", nil) {
		t.Fatal("nil group extraction error was rejected")
	}
	if !h.rejectFederatedGroupError(rec, req, "OIDC", context.Canceled) {
		t.Fatal("group extraction error was accepted")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("group extraction rejection status=%d want 401", rec.Code)
	}
}

func TestCompleteFederatedCallback(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{Logger: discardLogger()})
	mapper := newNoMappings("oidc")
	link := federatedIdentityLink{"oidc", mapper.SSOProviderKey(), "https://issuer.example", "subject", nil, mapper}

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec := httptest.NewRecorder()
	if h.completeFederatedCallback(rec, req, "OIDC", []string{"engineering"}, nil, link) {
		t.Fatal("ordinary callback without link flow was terminal")
	}

	req = httptest.NewRequest(http.MethodGet, "/auth/oidc/callback", nil)
	rec = httptest.NewRecorder()
	if !h.completeFederatedCallback(rec, req, "OIDC", nil, context.Canceled, link) {
		t.Fatal("group extraction failure was not terminal")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("group extraction failure status=%d want 401", rec.Code)
	}
}

func TestBindSSOProviderSupportsBothProtocolsAndNoOpInputs(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	ctx := context.Background()

	h.bindSSOProvider(ctx, identityKeys{}, nil)
	h.bindSSOProvider(ctx, identityKeys{}, newNoMappings("oidc"))

	for _, tc := range []struct {
		kind     string
		provider string
		keys     identityKeys
	}{
		{
			kind: "oidc", provider: "https://issuer.example/" + randSuffix(),
		},
		{
			kind: "saml", provider: "https://idp.example/" + randSuffix(),
		},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			mapper := newNoMappings(tc.kind)
			keys := tc.keys
			if tc.kind == "oidc" {
				keys.oidcSub, keys.oidcIss = "subject", tc.provider
			} else {
				keys.samlNameID, keys.samlIDP = "nameid", tc.provider
			}
			h.bindSSOProvider(ctx, keys, mapper)
			var count int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM identity_sources WHERE kind=$1 AND provider_key=$2`,
				tc.kind, mapper.SSOProviderKey(),
			).Scan(&count); err != nil {
				t.Fatalf("read provider binding: %v", err)
			}
			if count != 1 {
				t.Fatalf("%s provider binding count=%d want 1", tc.kind, count)
			}
		})
	}
}

func TestBindSSOProviderLogsAndReturnsOnDatabaseFailure(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	pool.Close()
	h.bindSSOProvider(context.Background(), identityKeys{
		oidcSub: "subject", oidcIss: "https://issuer.invalid",
	}, newNoMappings("oidc"))
}

func TestSettleSSOMappingsFailsClosedWhenEntitlementTransactionUnavailable(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	workerPool, err := pgxpool.New(context.Background(), os.Getenv("DB_DSN"))
	if err != nil {
		t.Fatalf("open isolated worker pool: %v", err)
	}
	workerPool.Close()
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, DatabaseWorker: pgxutil.WorkerPool{Pool: workerPool},
		JWT: newTestJWT(), Logger: discardLogger(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	h.settleSSOMappingsThenIssue(rec, req,
		&userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		seeded.primaryEmail,
		[]string{}, newNoMappings("oidc"), "oidc")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable entitlement transaction status=%d want 503: %s",
			rec.Code, rec.Body.String())
	}
}
