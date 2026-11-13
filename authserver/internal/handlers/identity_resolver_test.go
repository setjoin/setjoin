package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/shared/toggle"
)

// TestIdentityKeys_Predicates pins the stable-id presence gates the cascade uses
// to decide whether to attempt the OIDC / SAML leg. Both halves of a pair must be
// non-empty — a lone sub without an iss (or a lone NameID without an IdP) is NOT a
// usable stable identity, matching the original `oidcSub != "" && oidcIss != ""`
// (and SAML) guards in lookupOrJITUser.
func TestIdentityKeys_Predicates(t *testing.T) {
	cases := []struct {
		name               string
		keys               identityKeys
		wantOIDC, wantSAML bool
	}{
		{"empty", identityKeys{}, false, false},
		{"oidc both", identityKeys{oidcSub: "s", oidcIss: "i"}, true, false},
		{"oidc sub only", identityKeys{oidcSub: "s"}, false, false},
		{"oidc iss only", identityKeys{oidcIss: "i"}, false, false},
		{"saml both", identityKeys{samlNameID: "n", samlIDP: "idp"}, false, true},
		{"saml nameid only", identityKeys{samlNameID: "n"}, false, false},
		{"saml idp only", identityKeys{samlIDP: "idp"}, false, false},
		{"both pairs", identityKeys{oidcSub: "s", oidcIss: "i", samlNameID: "n", samlIDP: "idp"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.keys.hasOIDC(); got != tc.wantOIDC {
				t.Fatalf("hasOIDC() = %v, want %v", got, tc.wantOIDC)
			}
			if got := tc.keys.hasSAML(); got != tc.wantSAML {
				t.Fatalf("hasSAML() = %v, want %v", got, tc.wantSAML)
			}
		})
	}
}

// fakeResolver is a fake IdentityResolver: it records the keys it was called with
// and returns a scripted result. This is the seam the extraction exists to
// enable — a lookupOrJITUser test no longer has to wire full OIDC/SAML DB rows to
// exercise the post-resolution branches.
type fakeResolver struct {
	user    *userRow
	src     resolveSource
	err     error
	gotKeys identityKeys
	calls   int
}

func (f *fakeResolver) ResolveExisting(_ context.Context, keys identityKeys) (*userRow, resolveSource, error) {
	f.calls++
	f.gotKeys = keys
	return f.user, f.src, f.err
}

var _ IdentityResolver = (*fakeResolver)(nil)

// TestLookupOrJITUser_PassesKeysToResolver proves lookupOrJITUser funnels every
// inbound identifier into a single identityKeys bundle handed to the injected
// resolver — the named seam — preserving the exact field mapping the old
// positional cascade used. An address candidate is deliberately rejected until
// the already-authenticated person completes explicit linking.
func TestLookupOrJITUser_PassesKeysToResolver(t *testing.T) {
	pool := openHandlerPool(t) // skips when DB_DSN is unset (issueTokens needs the pool)
	seeded := seedAddressAwarePerson(t, pool)

	fake := &fakeResolver{
		user: &userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		src:  resolveAddress,
	}

	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	// Inject the fake into the shared deps — every sub-handler shares it by
	// reference, so loginHandler.lookupOrJITUser now consults the fake.
	h.deps.identityResolver = fake

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/saml/idp/acs", nil)
	h.lookupOrJITUser(rr, req,
		seeded.primaryEmail, "oidc-sub", "oidc-iss", "saml-nameid", "saml-idp",
		nil, true, newNoMappings("oidc"))

	if fake.calls != 1 {
		t.Fatalf("resolver called %d times, want exactly 1", fake.calls)
	}
	want := identityKeys{
		email:      seeded.primaryEmail,
		oidcSub:    "oidc-sub",
		oidcIss:    "oidc-iss",
		samlNameID: "saml-nameid",
		samlIDP:    "saml-idp",
	}
	if fake.gotKeys != want {
		t.Fatalf("resolver got keys %+v, want %+v", fake.gotKeys, want)
	}
	if rr.Code != http.StatusConflict {
		t.Fatalf("address-hit path should require explicit linking (409), got %d: %s",
			rr.Code, rr.Body.String())
	}
}

// TestLookupOrJITUser_ResolveNoneFallsThroughToJIT proves a resolveNone result
// (no existing person) with JIT disabled produces the unchanged 401 — i.e. the
// resolver miss is the JIT-provisioning signal, exactly as the inline cascade's
// address-lookup error was.
func TestLookupOrJITUser_ResolveNoneFallsThroughToJIT(t *testing.T) {
	pool := openHandlerPool(t)

	fake := &fakeResolver{src: resolveNone, err: errors.New("no row")}
	h := NewAuthHandler(AuthHandlerConfig{Pool: pool, JWT: newTestJWT(), Logger: discardLogger()})
	h.deps.identityResolver = fake

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/saml/idp/acs", nil)
	// jitEnabled = false → unauthorized, no provisioning.
	h.lookupOrJITUser(rr, req, "ghost@example.test", "", "", "", "", nil, false, newNoMappings("saml"))

	if fake.calls != 1 {
		t.Fatalf("resolver called %d times, want 1", fake.calls)
	}
	if rr.Code != 401 {
		t.Fatalf("resolveNone + JIT disabled should be 401, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestLookupOrJITUser_NormalizedResolutionErrorFailsClosedBeforeJIT(t *testing.T) {
	pool := openHandlerPool(t)
	const assertedEmail = "must-not-provision@example.test"

	fake := &fakeResolver{
		src: resolveNone,
		err: fmt.Errorf("%w: rejected stable subject", errNormalizedIdentityResolution),
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool:   pool,
		JWT:    newTestJWT(),
		Logger: discardLogger(),
	})
	h.deps.identityResolver = fake

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	h.lookupOrJITUser(
		rr, req, assertedEmail,
		"invalid-subject", "https://issuer.example",
		"", "", nil, true, newNoMappings("oidc"),
	)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("normalized resolver error status=%d body=%s, want 503", rr.Code, rr.Body.String())
	}
	var count int
	if err := pool.QueryRow(req.Context(),
		`SELECT COUNT(*) FROM users WHERE email=$1`, assertedEmail,
	).Scan(&count); err != nil {
		t.Fatalf("count unexpected JIT user: %v", err)
	}
	if count != 0 {
		t.Fatalf("normalized resolver error provisioned %d user(s), want 0", count)
	}
}

// TestNormalizedIdentityResolutionAndJIT exercises the I4 authentication
// cutover as one DB-backed contract: an exact issuer+subject is served from the
// normalized link, an unknown subject never falls through to address matching,
// and normalized JIT atomically creates the person, mailbox, link, and local
// lifecycle authority. Authority: identity-model-modernization I4/I5.
func TestNormalizedIdentityResolutionAndJIT(t *testing.T) {
	pool := openHandlerPool(t)
	ctx := context.Background()
	suffix := randSuffix()
	domain := "normalized-" + suffix + ".local"
	issuer := "https://issuer.example/" + suffix
	firstEmail := "first@" + domain
	secondEmail := "second@" + domain
	samlEmail := "saml@" + domain

	var domainID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains(name,is_local) VALUES($1,TRUE) RETURNING id`,
		domain,
	).Scan(&domainID); err != nil {
		t.Fatalf("create normalized test domain: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id=$1`, domainID)
	})

	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})

	first, err := h.createNormalizedJITUser(ctx, firstEmail, "subject-1", issuer, "", "")
	if err != nil {
		t.Fatalf("create normalized OIDC JIT user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, first.ID)
	})
	if first.Email != firstEmail {
		t.Fatalf("normalized JIT email=%q want %q", first.Email, firstEmail)
	}

	sourceKey := "oidc:"
	var sourceID, sourceGeneration int64
	if err := pool.QueryRow(ctx,
		`SELECT source_key,id,generation FROM identity_sources
		  WHERE kind='oidc' AND id IN (
		    SELECT source_id FROM user_identity_links
		     WHERE user_id=$1 AND external_subject='subject-1'
		  )`,
		first.ID,
	).Scan(&sourceKey, &sourceID, &sourceGeneration); err != nil {
		t.Fatalf("read normalized source: %v", err)
	}
	if !strings.HasPrefix(sourceKey, "oidc:") {
		t.Fatalf("source key=%q want oidc prefix", sourceKey)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`UPDATE identity_sources SET read_mode='shadow' WHERE id=$1`,
			sourceID)
		_, _ = pool.Exec(ctx,
			`DELETE FROM identity_auth_shadow_link_evidence
			  WHERE source_id=$1`, sourceID)
		_, _ = pool.Exec(ctx,
			`DELETE FROM identity_auth_shadow_hours WHERE source_id=$1`,
			sourceID)
	})

	resolver := dbIdentityResolver{deps: h.deps}
	got, source, err := resolver.ResolveExisting(ctx, identityKeys{
		email: "unrelated@" + domain, oidcSub: "subject-1", oidcIss: issuer,
	})
	if err != nil {
		t.Fatalf("resolve matching shadow identity: %v", err)
	}
	if source != resolveOIDC || got == nil || got.ID != first.ID {
		t.Fatalf("shadow resolve=(%+v,%v) want legacy user %d via OIDC",
			got, source, first.ID)
	}
	var observedSourceGeneration, observedLinkGeneration int64
	var matched, mismatched int
	if err := pool.QueryRow(ctx, `
		SELECT h.source_generation,e.link_generation,
		       h.matched_count,h.mismatched_count
		  FROM identity_auth_shadow_hours h
		  JOIN identity_auth_shadow_link_evidence e
		    ON e.source_id=h.source_id
		 WHERE h.source_id=$1 AND e.user_id=$2`,
		sourceID, first.ID,
	).Scan(
		&observedSourceGeneration, &observedLinkGeneration,
		&matched, &mismatched,
	); err != nil {
		t.Fatalf("read authentication shadow evidence: %v", err)
	}
	if observedSourceGeneration != sourceGeneration ||
		observedLinkGeneration <= 0 || matched != 1 || mismatched != 0 {
		t.Fatalf(
			"shadow evidence sourceGen=%d linkGen=%d match=%d mismatch=%d",
			observedSourceGeneration, observedLinkGeneration, matched, mismatched,
		)
	}

	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET read_mode='normalized' WHERE source_key=$1`,
		sourceKey,
	); err != nil {
		t.Fatalf("activate normalized reads: %v", err)
	}

	got, source, err = resolver.ResolveExisting(ctx, identityKeys{
		email: "unrelated@" + domain, oidcSub: "subject-1", oidcIss: issuer,
	})
	if err != nil {
		t.Fatalf("resolve exact normalized identity: %v", err)
	}
	if source != resolveOIDC || got == nil || got.ID != first.ID {
		t.Fatalf("normalized resolve=(%+v,%v) want user %d via OIDC", got, source, first.ID)
	}

	got, source, err = resolver.ResolveExisting(ctx, identityKeys{
		email: firstEmail, oidcSub: "unknown-subject", oidcIss: issuer,
	})
	if err != nil {
		t.Fatalf("resolve unknown normalized identity: %v", err)
	}
	if got != nil || source != resolveNormalizedNone {
		t.Fatalf("unknown normalized subject resolved (%+v,%v); address fallback must be fenced", got, source)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/oidc/callback", nil)
	h.lookupOrJITUser(rr, req, secondEmail, "subject-2", issuer, "", "",
		nil, true, newNoMappings("oidc"))
	if rr.Code != 200 {
		t.Fatalf("normalized JIT login status=%d body=%s", rr.Code, rr.Body.String())
	}
	var secondID int64
	var authority string
	if err := pool.QueryRow(ctx, `
		SELECT u.id,a.authority_kind
		  FROM users u
		  JOIN user_lifecycle_authorities a ON a.user_id=u.id
		 WHERE u.email=$1`, secondEmail,
	).Scan(&secondID, &authority); err != nil {
		t.Fatalf("read normalized JIT lifecycle authority: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, secondID)
	})
	if authority != "local" {
		t.Fatalf("normalized JIT authority=%q want local", authority)
	}

	samlIDP := "https://idp.example/" + suffix
	samlUser, err := h.createNormalizedJITUser(ctx, samlEmail, "", "", "nameid-1", samlIDP)
	if err != nil {
		t.Fatalf("create normalized SAML JIT user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, samlUser.ID)
	})
	var samlSourceKey string
	if err := pool.QueryRow(ctx,
		`SELECT s.source_key
		   FROM identity_sources s
		   JOIN user_identity_links l ON l.source_id=s.id
		  WHERE s.kind='saml' AND l.user_id=$1 AND l.external_subject='nameid-1'`,
		samlUser.ID,
	).Scan(&samlSourceKey); err != nil {
		t.Fatalf("read normalized SAML source: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`UPDATE identity_sources SET read_mode='shadow'
			  WHERE source_key=$1`, samlSourceKey)
	})
	got, source, err = resolver.ResolveExisting(ctx, identityKeys{
		email: samlEmail, samlNameID: "nameid-1", samlIDP: samlIDP,
	})
	if err != nil {
		t.Fatalf("resolve matching shadow SAML identity: %v", err)
	}
	if source != resolveSAML || got == nil || got.ID != samlUser.ID {
		t.Fatalf("shadow SAML resolve=(%+v,%v) want user %d", got, source, samlUser.ID)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE identity_sources SET read_mode='normalized' WHERE source_key=$1`,
		samlSourceKey,
	); err != nil {
		t.Fatalf("activate normalized SAML reads: %v", err)
	}
	got, source, err = resolver.ResolveExisting(ctx, identityKeys{
		email: samlEmail, samlNameID: "nameid-1", samlIDP: samlIDP,
	})
	if err != nil {
		t.Fatalf("resolve exact normalized SAML identity: %v", err)
	}
	if source != resolveSAML || got == nil || got.ID != samlUser.ID {
		t.Fatalf("normalized SAML resolve=(%+v,%v) want user %d", got, source, samlUser.ID)
	}
	got, source, err = resolver.ResolveExisting(ctx, identityKeys{
		email: samlEmail, samlNameID: "unknown-nameid", samlIDP: samlIDP,
	})
	if err != nil {
		t.Fatalf("resolve unknown normalized SAML identity: %v", err)
	}
	if got != nil || source != resolveNormalizedNone {
		t.Fatalf("unknown normalized SAML subject resolved (%+v,%v)", got, source)
	}

	if _, err := h.createNormalizedJITUser(ctx, "not-an-email", "subject-x", issuer, "", ""); err == nil {
		t.Fatal("normalized JIT accepted an invalid email")
	}
	if _, err := h.createNormalizedJITUser(ctx, "missing-pair@"+domain, "", "", "", ""); err == nil {
		t.Fatal("normalized JIT accepted a missing stable identity pair")
	}
	if _, err := h.createNormalizedJITUser(ctx, firstEmail, "different-subject", issuer, "", ""); err == nil {
		t.Fatal("normalized JIT silently attached a new subject to an occupied address")
	}
}

func TestNormalizedIdentityResolutionPropagatesDatabaseFailure(t *testing.T) {
	pool := openHandlerPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	pool.Close()

	resolver := dbIdentityResolver{deps: h.deps}
	if _, _, err := resolver.ResolveExisting(context.Background(), identityKeys{
		oidcSub: "subject", oidcIss: "https://issuer.invalid",
	}); err == nil {
		t.Fatal("normalized identity resolution swallowed a database failure")
	}
	if _, _, err := resolver.ResolveExisting(context.Background(), identityKeys{
		samlNameID: "nameid", samlIDP: "https://idp.invalid",
	}); err == nil {
		t.Fatal("normalized SAML resolution swallowed a database failure")
	}
	resolver.observeAuthShadow(context.Background(), "oidc", "provider", "subject",
		normalizedIdentityShadowEvidence{SourceID: 1, SourceGeneration: 1}, nil)
}

func TestLegacyIdentityResolutionPropagatesStableLookupFailures(t *testing.T) {
	pool := createClosedPool(t)
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	resolver := dbIdentityResolver{deps: h.deps}

	if _, _, err := resolver.ResolveExisting(context.Background(), identityKeys{
		oidcSub: "subject", oidcIss: "https://issuer.invalid",
	}); err == nil {
		t.Fatal("legacy OIDC lookup swallowed a closed-pool failure")
	}
	if _, _, err := resolver.ResolveExisting(context.Background(), identityKeys{
		samlNameID: "nameid", samlIDP: "https://idp.invalid",
	}); err == nil {
		t.Fatal("legacy SAML lookup swallowed a closed-pool failure")
	}
}

func TestAddressResolutionNeverAuthenticatesWhenIdentityModelIsOff(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)

	fake := &fakeResolver{
		user: &userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		src:  resolveAddress,
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	h.deps.identityResolver = fake
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/oidc/callback", nil)
	h.lookupOrJITUser(rec, req, seeded.primaryEmail,
		strings.Repeat("s", 2049), "https://issuer.example",
		"saml-nameid", "https://idp.example",
		[]string{}, false, newNoMappings("oidc"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("soft-address match status=%d want 409: %s",
			rec.Code, rec.Body.String())
	}
	var links, tokens int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM user_identity_links WHERE user_id=$1`,
		seeded.userID).Scan(&links); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`,
		seeded.userID).Scan(&tokens); err != nil {
		t.Fatal(err)
	}
	if links != 0 || tokens != 0 {
		t.Fatalf("soft-address match left links=%d tokens=%d, want zero", links, tokens)
	}
}

func TestAddressResolutionRequiresExplicitLinkWhenIdentityModelEnabled(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	fake := &fakeResolver{
		user: &userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		src:  resolveAddress,
	}
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: toggle.NewTestFlags(map[string]bool{
			toggle.FeatureIdentityModelV2: true,
		}),
	})
	h.deps.identityResolver = fake
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/auth/oidc/callback", nil)
	h.lookupOrJITUser(rec, req, seeded.primaryEmail,
		"new-subject", "https://issuer.example",
		"", "", []string{}, false, newNoMappings("oidc"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("address-authorized login status=%d want 409: %s",
			rec.Code, rec.Body.String())
	}
	var links, tokens int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM user_identity_links
		 WHERE user_id=$1 AND external_subject='new-subject'`,
		seeded.userID,
	).Scan(&links); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM oauth_tokens WHERE user_id=$1`,
		seeded.userID,
	).Scan(&tokens); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if links != 0 || tokens != 0 {
		t.Fatalf("address match left links=%d tokens=%d, want zero", links, tokens)
	}
}

func TestNormalizedProviderBindingFailuresBlockExistingAndJITLogins(t *testing.T) {
	pool := openHandlerPool(t)
	seeded := seedAddressAwarePerson(t, pool)
	subject := "binding-subject-" + randSuffix()
	oversizedIssuer := "https://issuer.example/" + randSuffix() + strings.Repeat("x", 2200)
	flags := toggle.NewTestFlags(map[string]bool{
		toggle.FeatureIdentityModelV2: true,
	})

	existing := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(), Toggles: flags,
	})
	existing.deps.identityResolver = &fakeResolver{
		user: &userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		src:  resolveOIDC,
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	existing.lookupOrJITUser(
		rec, req, seeded.primaryEmail, subject, oversizedIssuer,
		"", "", nil, false, newNoMappings("oidc"),
	)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("existing binding failure status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM oauth_tokens WHERE user_id=$1`, seeded.userID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM sessions WHERE user_id=$1`, seeded.userID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM login_events WHERE user_id=$1`, seeded.userID)
	})
	legacy := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
	})
	legacy.deps.identityResolver = &fakeResolver{
		user: &userRow{ID: seeded.userID, Email: seeded.primaryEmail},
		src:  resolveOIDC,
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	legacy.lookupOrJITUser(
		rec, req, seeded.primaryEmail, subject, oversizedIssuer,
		"", "", nil, false, newNoMappings("oidc"),
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy binding compatibility status=%d, want 200: %s",
			rec.Code, rec.Body.String())
	}

	jitEmail := "binding-jit-" + randSuffix() + "@" + splitDomain(seeded.primaryEmail)
	jit := NewAuthHandler(AuthHandlerConfig{
		Pool: pool, JWT: newTestJWT(), Logger: discardLogger(),
		Toggles: flags, JITEnabled: true,
	})
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM mailboxes WHERE user_id IN (
			     SELECT id FROM users WHERE lower(email)=lower($1)
			 )`,
			jitEmail)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM users WHERE lower(email)=lower($1)`, jitEmail)
	})
	jit.deps.identityResolver = &fakeResolver{src: resolveNone, err: errors.New("not found")}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/oidc/callback", nil)
	jit.lookupOrJITUser(
		rec, req, jitEmail, subject, oversizedIssuer,
		"", "", nil, true, newNoMappings("oidc"),
	)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("JIT binding failure status=%d, want 503: %s",
			rec.Code, rec.Body.String())
	}
}

func TestCreateNormalizedJITUserPropagatesStoreFailure(t *testing.T) {
	h := NewAuthHandler(AuthHandlerConfig{
		Pool: createClosedPool(t), JWT: newTestJWT(), Logger: discardLogger(),
	})
	if _, err := h.createNormalizedJITUser(
		context.Background(),
		"normalized-jit-store@example.com",
		"subject", "https://issuer.example", "", "",
	); err == nil {
		t.Fatal("closed normalized JIT store unexpectedly succeeded")
	}
}

func TestParseNormalizedIdentityResolutionRejectsMalformedResults(t *testing.T) {
	lookup := func(userID int64) (*userRow, error) {
		if userID == 42 {
			return &userRow{ID: userID}, nil
		}
		return nil, errors.New("lookup failed")
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"malformed JSON", `{`},
		{"invalid user id", `{"found":true,"serveNormalized":true,"userId":"x"}`},
		{"lookup failure", `{"found":true,"serveNormalized":true,"userId":"41"}`},
		{"invalid source id", `{"found":true,"serveNormalized":true,"userId":"42","sourceId":"x"}`},
		{"invalid source generation", `{"found":true,"serveNormalized":true,"userId":"42","sourceId":"1","sourceGeneration":"x"}`},
		{"invalid link id", `{"found":true,"serveNormalized":true,"userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"x"}`},
		{"invalid link generation", `{"found":true,"serveNormalized":true,"userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"3","linkGeneration":"x"}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := parseNormalizedIdentityResolution(
				[]byte(test.raw), lookup,
			); err == nil {
				t.Fatal("malformed normalized result unexpectedly succeeded")
			}
		})
	}
}

func TestParseNormalizedIdentityResolutionStates(t *testing.T) {
	user, found, serve, err := parseNormalizedIdentityResolution(
		[]byte(`{"found":false,"serveNormalized":true}`),
		func(int64) (*userRow, error) {
			t.Fatal("not-found result must not perform a user lookup")
			return nil, nil
		},
	)
	if err != nil || user != nil || found || !serve {
		t.Fatalf("not-found result = (%+v,%v,%v,%v)", user, found, serve, err)
	}

	user, found, serve, err = parseNormalizedIdentityResolution(
		[]byte(`{"found":true,"serveNormalized":true,"userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"3","linkGeneration":"4"}`),
		func(userID int64) (*userRow, error) { return &userRow{ID: userID}, nil },
	)
	if err != nil || !found || !serve || user == nil ||
		user.ID != 42 || user.IdentitySourceID != 1 ||
		user.IdentitySourceGeneration != 2 || user.IdentityLinkID != 3 ||
		user.IdentityLinkGeneration != 4 {
		t.Fatalf("resolved result = (%+v,%v,%v,%v)", user, found, serve, err)
	}
}

func TestParseNormalizedIdentityShadowEvidence(t *testing.T) {
	tests := []struct {
		name    string
		wire    normalizedIdentityResolution
		wantErr string
	}{
		{"empty", normalizedIdentityResolution{}, ""},
		{"valid", normalizedIdentityResolution{SourceID: "41", SourceGeneration: "7"}, ""},
		{"invalid source", normalizedIdentityResolution{SourceID: "x", SourceGeneration: "7"}, "source id"},
		{"zero source", normalizedIdentityResolution{SourceID: "0", SourceGeneration: "7"}, "source id"},
		{"invalid generation", normalizedIdentityResolution{SourceID: "41", SourceGeneration: "x"}, "source generation"},
		{"zero generation", normalizedIdentityResolution{SourceID: "41", SourceGeneration: "0"}, "source generation"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence, err := parseNormalizedIdentityShadowEvidence(test.wire)
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse evidence: %v", err)
			}
			if test.wire.SourceID != "" && (evidence.SourceID != 41 || evidence.SourceGeneration != 7) {
				t.Fatalf("evidence = %+v", evidence)
			}
		})
	}
}

func TestParseNormalizedJITResultRejectsUnsafeResults(t *testing.T) {
	lookup := func(userID int64) (*userRow, error) {
		if userID == 42 {
			return &userRow{ID: userID}, nil
		}
		return nil, errors.New("lookup failed")
	}
	cases := []struct {
		name string
		raw  string
	}{
		{"malformed JSON", `{`},
		{"blocked", `{"state":"blocked","code":"conflict"}`},
		{"missing user", `{"state":"created"}`},
		{"invalid user id", `{"state":"created","userId":"x"}`},
		{"lookup failure", `{"state":"created","userId":"41"}`},
		{"invalid source id", `{"state":"created","userId":"42","sourceId":"x"}`},
		{"invalid source generation", `{"state":"created","userId":"42","sourceId":"1","sourceGeneration":"x"}`},
		{"invalid link id", `{"state":"created","userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"x"}`},
		{"invalid link generation", `{"state":"created","userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"3","linkGeneration":"x"}`},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseNormalizedJITResult([]byte(test.raw), lookup); err == nil {
				t.Fatal("unsafe normalized JIT result unexpectedly accepted")
			}
		})
	}
}

func TestParseNormalizedJITResultSuccess(t *testing.T) {
	user, err := parseNormalizedJITResult(
		[]byte(`{"state":"created","userId":"42","sourceId":"1","sourceGeneration":"2","linkId":"3","linkGeneration":"4"}`),
		func(userID int64) (*userRow, error) { return &userRow{ID: userID}, nil },
	)
	if err != nil || user == nil || user.ID != 42 ||
		user.IdentitySourceID != 1 || user.IdentitySourceGeneration != 2 ||
		user.IdentityLinkID != 3 || user.IdentityLinkGeneration != 4 {
		t.Fatalf("parsed JIT result = (%+v,%v)", user, err)
	}
}
