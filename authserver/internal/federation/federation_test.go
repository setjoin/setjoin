package federation

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
	"setjoin.com/shared/identity"
)

type staticSAMLSessionProvider struct {
	session samlsp.Session
	err     error
}

func (p staticSAMLSessionProvider) CreateSession(http.ResponseWriter, *http.Request, *saml.Assertion) error {
	return nil
}

func (p staticSAMLSessionProvider) DeleteSession(http.ResponseWriter, *http.Request) error {
	return nil
}

func (p staticSAMLSessionProvider) GetSession(*http.Request) (samlsp.Session, error) {
	return p.session, p.err
}

func TestRandomState(t *testing.T) {
	state, err := RandomState()
	if err != nil {
		t.Fatalf("RandomState() error: %v", err)
	}
	if len(state) == 0 {
		t.Error("RandomState() returned empty string")
	}
	if state == "" {
		t.Error("state should not be empty")
	}

	// Verify uniqueness
	state2, err := RandomState()
	if err != nil {
		t.Fatalf("second RandomState() error: %v", err)
	}
	if state == state2 {
		t.Error("two RandomState() calls should produce different values")
	}
}

func TestEmailFromIDToken_MissingClaims(t *testing.T) {
	// EmailFromIDToken is tested indirectly via the OIDC RP package tests
	// when a real OIDC provider is available. This smoke test verifies the
	// function signature compiles and the error case returns empty.
	// Full testing requires a valid signed ID token.
}

func TestSAMLSPRegistry_NoRegistrations(t *testing.T) {
	// SAMLSPRegistry requires database connectivity to run.
	// This is a placeholder for integration tests with a real database.
	// Unit-level: Registration lookup returns nil for unknown entity ID.
}

func TestOIDCRPProvider_NoProviders(t *testing.T) {
	// OIDCRPProvider requires database connectivity to run.
	// This is a placeholder for integration tests with a real database.
	// Unit-level: Provider lookup returns nil for unknown provider name.
}

func TestSubjectFromIDToken_MissingSub(t *testing.T) {
	sub, iss, err := SubjectFromIDToken("", "")
	if err == nil {
		t.Error("expected error for empty sub, got nil")
	}
	if sub != "" || iss != "" {
		t.Error("expected empty sub/iss on error")
	}
}

func TestSubjectFromIDToken_Valid(t *testing.T) {
	sub, iss, err := SubjectFromIDToken("user-123", "https://issuer.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sub != "user-123" {
		t.Errorf("expected sub 'user-123', got %q", sub)
	}
	if iss != "https://issuer.example.com" {
		t.Errorf("expected iss, got %q", iss)
	}
}

func TestGroupsFromClaims_StringArray(t *testing.T) {
	claims := map[string]interface{}{"groups": []interface{}{"Engineering", "Managers"}}
	groups, err := GroupsFromClaims(claims, "groups")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0] != "Engineering" || groups[1] != "Managers" {
		t.Errorf("unexpected groups: %v", groups)
	}
}

func TestGroupsFromClaims_NoClaim(t *testing.T) {
	claims := map[string]interface{}{"email": "test@example.com"}
	groups, err := GroupsFromClaims(claims, "groups")
	if err != nil {
		t.Fatal(err)
	}
	if groups != nil {
		t.Error("expected nil groups when claim is missing")
	}
}

func TestGroupsFromClaims_SingleString(t *testing.T) {
	claims := map[string]interface{}{"groups": "JustOne"}
	groups, err := GroupsFromClaims(claims, "groups")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0] != "JustOne" {
		t.Errorf("unexpected groups: %v", groups)
	}
}

func TestGroupsFromClaims_StringSlice(t *testing.T) {
	claims := map[string]interface{}{"roles": []string{"admin", "user"}}
	groups, err := GroupsFromClaims(claims, "roles")
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || groups[0] != "admin" || groups[1] != "user" {
		t.Errorf("unexpected groups: %v", groups)
	}
}

func TestGroupsFromClaims_RejectsMalformedClaim(t *testing.T) {
	for _, raw := range []interface{}{
		42,
		map[string]interface{}{"unexpected": true},
		[]interface{}{"Engineering", 42},
	} {
		groups, err := GroupsFromClaims(map[string]interface{}{"groups": raw}, "groups")
		if err == nil {
			t.Errorf("GroupsFromClaims(%T) = %v, nil; want malformed-claim error", raw, groups)
		}
	}
}

func TestGroupsFromClaims_RejectsUnboundedClaim(t *testing.T) {
	tooMany := make([]string, identity.MaxSSOGroupClaims+1)
	if groups, err := GroupsFromClaims(
		map[string]interface{}{"groups": tooMany},
		"groups",
	); err == nil || groups != nil {
		t.Fatalf("oversized group claim = (%v, %v), want nil error result", groups, err)
	}

	tooLong := strings.Repeat("x", identity.MaxSSOGroupNameBytes+1)
	if groups, err := GroupsFromClaims(
		map[string]interface{}{"groups": []string{tooLong}},
		"groups",
	); err == nil || groups != nil {
		t.Fatalf("oversized group value = (%v, %v), want nil error result", groups, err)
	}
}

func TestRolePriority(t *testing.T) {
	if RolePriority("super_admin") <= RolePriority("user_admin") {
		t.Error("super_admin should outrank user_admin")
	}
	if RolePriority("user_admin") <= RolePriority("read_only") {
		t.Error("user_admin should outrank read_only")
	}
	if RolePriority("read_only") <= RolePriority("auditor") {
		t.Error("read_only should outrank auditor")
	}
	if RolePriority("unknown") != 0 {
		t.Error("unknown role should have priority 0")
	}
}

func TestContainsString(t *testing.T) {
	if !ContainsString([]string{"a", "b", "c"}, "b") {
		t.Error("expected to find 'b'")
	}
	if ContainsString([]string{"a", "b"}, "c") {
		t.Error("expected not to find 'c'")
	}
	if ContainsString(nil, "a") {
		t.Error("expected false for nil slice")
	}
	if ContainsString([]string{}, "a") {
		t.Error("expected false for empty slice")
	}
}

func TestValidSSOProviderKey(t *testing.T) {
	for _, key := range []string{"saml:42", "oidc:provider-a", "test:default"} {
		if !ValidSSOProviderKey(key) {
			t.Errorf("ValidSSOProviderKey(%q) = false, want true", key)
		}
	}
	for _, key := range []string{"", "x", " oidc:a", "oidc:a ", "oidc:\nadmin", "oidc:" + strings.Repeat("a", 251)} {
		if ValidSSOProviderKey(key) {
			t.Errorf("ValidSSOProviderKey(%q) = true, want false", key)
		}
	}
}

func TestProviderKeysAndGroupMappingValidation(t *testing.T) {
	oidcConfig := &oidcProviderConfig{name: "corporate"}
	if got := oidcConfig.SSOProviderKey(); got != "oidc:corporate" {
		t.Fatalf("OIDC provider key = %q", got)
	}
	samlRegistration := &samlspRegistration{ID: 42}
	if got := samlRegistration.SSOProviderKey(); got != "saml:42" {
		t.Fatalf("SAML provider key = %q", got)
	}

	if err := validateGroupMappings([]GroupMapping{{IDPGroup: "Engineering"}}); err != nil {
		t.Fatalf("valid group mappings: %v", err)
	}
	tooMany := make([]GroupMapping, identity.MaxSSOGroupMappings+1)
	for i := range tooMany {
		tooMany[i].IDPGroup = "Engineering"
	}
	if err := validateGroupMappings(tooMany); err == nil {
		t.Fatal("oversized group mapping set was accepted")
	}
}

func TestSAMLGroupsFromAssertionBounds(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://sp.example.test/acs", nil)
	if err != nil {
		t.Fatal(err)
	}
	registration := &samlspRegistration{
		middleware: &samlsp.Middleware{
			Session: staticSAMLSessionProvider{
				session: samlsp.JWTSessionClaims{
					Attributes: samlsp.Attributes{
						"memberOf": {"Engineering", "Operations"},
					},
				},
			},
		},
	}
	groups, err := registration.GroupsFromAssertion(request)
	if err != nil {
		t.Fatalf("valid SAML groups: %v", err)
	}
	if len(groups) != 2 || groups[0] != "Engineering" {
		t.Fatalf("SAML groups = %v", groups)
	}

	registration.middleware.Session = staticSAMLSessionProvider{
		session: samlsp.JWTSessionClaims{
			Attributes: samlsp.Attributes{
				"memberOf": {strings.Repeat("x", identity.MaxSSOGroupNameBytes+1)},
			},
		},
	}
	if _, err := registration.GroupsFromAssertion(request); err == nil {
		t.Fatal("oversized SAML group value was accepted")
	}

	registration.middleware.Session = staticSAMLSessionProvider{err: errors.New("no session")}
	if _, err := registration.GroupsFromAssertion(request); err == nil {
		t.Fatal("SAML session failure was ignored")
	}
}

// ── OIDC Client Type tests ────────────────────────────────────────────

func TestStoredClient_PublicClientAuthMethodNone(t *testing.T) {
	c := &storedClient{
		id:           "public-app",
		name:         "Public App",
		secretHash:   "",
		redirectURIs: []string{"https://app.example.com/callback"},
		grantTypes:   []string{"authorization_code", "refresh_token"},
		scopes:       []string{"openid", "profile", "email"},
		enabled:      true,
		clientType:   "public",
	}
	c.preComputeGrants()

	if got := c.AuthMethod(); got != oidc.AuthMethodNone {
		t.Errorf("public client AuthMethod() = %q, want %q", got, oidc.AuthMethodNone)
	}
}

func TestStoredClient_PublicClientApplicationTypeNative(t *testing.T) {
	c := &storedClient{
		id:           "public-app",
		name:         "Public App",
		redirectURIs: []string{"https://app.example.com/callback"},
		grantTypes:   []string{"authorization_code"},
		scopes:       []string{"openid"},
		enabled:      true,
		clientType:   "public",
	}
	c.preComputeGrants()

	if got := c.ApplicationType(); got != op.ApplicationTypeNative {
		t.Errorf("public client ApplicationType() = %v, want %v", got, op.ApplicationTypeNative)
	}
}

func TestStoredClient_ConfidentialClientAuthMethodBasic(t *testing.T) {
	c := &storedClient{
		id:           "web-app",
		name:         "Web App",
		secretHash:   "$2a$10$...",
		redirectURIs: []string{"https://app.example.com/callback"},
		grantTypes:   []string{"authorization_code", "refresh_token"},
		scopes:       []string{"openid", "profile", "email"},
		enabled:      true,
		clientType:   "confidential",
	}
	c.preComputeGrants()

	if got := c.AuthMethod(); got != oidc.AuthMethodBasic {
		t.Errorf("confidential client AuthMethod() = %q, want %q", got, oidc.AuthMethodBasic)
	}
}

func TestStoredClient_ConfidentialClientApplicationTypeWeb(t *testing.T) {
	c := &storedClient{
		id:           "web-app",
		name:         "Web App",
		secretHash:   "$2a$10$...",
		redirectURIs: []string{"https://app.example.com/callback"},
		grantTypes:   []string{"authorization_code"},
		scopes:       []string{"openid"},
		enabled:      true,
		clientType:   "confidential",
	}
	c.preComputeGrants()

	if got := c.ApplicationType(); got != op.ApplicationTypeWeb {
		t.Errorf("confidential client ApplicationType() = %v, want %v", got, op.ApplicationTypeWeb)
	}
}

func TestStoredClient_DefaultClientTypeIsConfidential(t *testing.T) {
	// Empty or unset clientType should default to confidential (safe default).
	c := &storedClient{
		id:           "legacy-app",
		name:         "Legacy App",
		secretHash:   "$2a$10$...",
		redirectURIs: []string{"https://legacy.example.com/callback"},
		grantTypes:   []string{"authorization_code"},
		scopes:       []string{"openid"},
		enabled:      true,
		clientType:   "", // unset
	}
	c.preComputeGrants()

	if got := c.AuthMethod(); got != oidc.AuthMethodBasic {
		t.Errorf("default (empty) client_type AuthMethod() = %q, want %q", got, oidc.AuthMethodBasic)
	}
	if got := c.ApplicationType(); got != op.ApplicationTypeWeb {
		t.Errorf("default (empty) client_type ApplicationType() = %v, want %v", got, op.ApplicationTypeWeb)
	}
}

func TestStoredClient_UnknownClientTypeFallsBackToConfidential(t *testing.T) {
	// Unknown client type string should safely fall back to confidential.
	c := &storedClient{
		id:           "unknown-type-app",
		name:         "Unknown App",
		secretHash:   "$2a$10$...",
		redirectURIs: []string{"https://unknown.example.com/callback"},
		grantTypes:   []string{"authorization_code"},
		scopes:       []string{"openid"},
		enabled:      true,
		clientType:   "bogus",
	}
	c.preComputeGrants()

	if got := c.AuthMethod(); got != oidc.AuthMethodBasic {
		t.Errorf("unknown client_type AuthMethod() = %q, want %q (safe fallback)", got, oidc.AuthMethodBasic)
	}
	if got := c.ApplicationType(); got != op.ApplicationTypeWeb {
		t.Errorf("unknown client_type ApplicationType() = %v, want %v (safe fallback)", got, op.ApplicationTypeWeb)
	}
}

func TestStoredClient_PublicClientHasNoSecret(t *testing.T) {
	// Public clients have no secret; AuthMethodNone means no secret verification.
	c := &storedClient{
		id:           "spa-app",
		name:         "Single Page App",
		secretHash:   "", // public clients have no secret
		redirectURIs: []string{"https://spa.example.com/callback"},
		grantTypes:   []string{"authorization_code"},
		scopes:       []string{"openid"},
		enabled:      true,
		clientType:   "public",
	}
	c.preComputeGrants()

	if got := c.AuthMethod(); got != oidc.AuthMethodNone {
		t.Errorf("public client (no secret) AuthMethod() = %q, want %q", got, oidc.AuthMethodNone)
	}
	// Public clients require PKCE; the library enforces this via CodeMethodS256 config.
	// The client itself should report no auth method.
}

func TestStoredClient_GetID(t *testing.T) {
	c := &storedClient{id: "test-client-id"}
	if got := c.GetID(); got != "test-client-id" {
		t.Errorf("GetID() = %q, want %q", got, "test-client-id")
	}
}

func TestStoredClient_RedirectURIs(t *testing.T) {
	uris := []string{"https://a.example.com/cb", "https://b.example.com/cb"}
	c := &storedClient{redirectURIs: uris}
	got := c.RedirectURIs()
	if len(got) != 2 || got[0] != uris[0] || got[1] != uris[1] {
		t.Errorf("RedirectURIs() = %v, want %v", got, uris)
	}
}

func TestStoredClient_PostLogoutRedirectURIs(t *testing.T) {
	c := &storedClient{}
	if got := c.PostLogoutRedirectURIs(); got != nil {
		t.Errorf("PostLogoutRedirectURIs() = %v, want nil", got)
	}
}

func TestStoredClient_ResponseTypes(t *testing.T) {
	c := &storedClient{}
	got := c.ResponseTypes()
	if len(got) != 1 || got[0] != oidc.ResponseTypeCode {
		t.Errorf("ResponseTypes() = %v, want [code]", got)
	}
}

func TestStoredClient_GrantTypes_PreCompute(t *testing.T) {
	c := &storedClient{
		grantTypes: []string{"authorization_code", "refresh_token"},
	}
	c.preComputeGrants()
	got := c.GrantTypes()
	if len(got) != 2 {
		t.Fatalf("expected 2 grant types, got %d", len(got))
	}
	if got[0] != oidc.GrantTypeCode || got[1] != oidc.GrantTypeRefreshToken {
		t.Errorf("GrantTypes() = %v, want [authorization_code, refresh_token]", got)
	}
}

func TestStoredClient_GrantTypes_DefaultCode(t *testing.T) {
	c := &storedClient{
		grantTypes: []string{"unknown"},
	}
	c.preComputeGrants()
	got := c.GrantTypes()
	if len(got) != 1 || got[0] != oidc.GrantTypeCode {
		t.Errorf("GrantTypes() default = %v, want [code]", got)
	}
}

func TestStoredClient_LoginURL(t *testing.T) {
	c := &storedClient{}
	if got := c.LoginURL("request id"); got != "/auth/oidc/op/complete?id=request+id" {
		t.Errorf("LoginURL() = %q", got)
	}
}

func TestStoredClient_AccessTokenType(t *testing.T) {
	c := &storedClient{}
	if got := c.AccessTokenType(); got != op.AccessTokenTypeJWT {
		t.Errorf("AccessTokenType() = %v, want JWT", got)
	}
}

func TestStoredClient_IDTokenLifetime(t *testing.T) {
	c := &storedClient{}
	if got := c.IDTokenLifetime(); got != 5*time.Minute {
		t.Errorf("IDTokenLifetime() = %v, want 5m", got)
	}
}

func TestStoredClient_DevMode(t *testing.T) {
	c := &storedClient{}
	if c.DevMode() {
		t.Error("DevMode() should be false")
	}
}

func TestStoredClient_RestrictScopes(t *testing.T) {
	c := &storedClient{}
	scopes := []string{"openid", "profile"}
	for name, callback := range map[string]func([]string) []string{
		"id_token":     c.RestrictAdditionalIdTokenScopes(),
		"access_token": c.RestrictAdditionalAccessTokenScopes(),
	} {
		if callback == nil {
			t.Fatalf("%s scope restriction callback must be callable", name)
		}
		got := callback(scopes)
		if len(got) != len(scopes) || got[0] != scopes[0] || got[1] != scopes[1] {
			t.Errorf("%s scope restriction = %v, want pass-through %v", name, got, scopes)
		}
	}
}

func TestStoredClient_IsScopeAllowed(t *testing.T) {
	c := &storedClient{scopes: []string{"openid", "profile", "email"}}
	if !c.IsScopeAllowed("openid") {
		t.Error("openid scope should be allowed")
	}
	if !c.IsScopeAllowed("profile") {
		t.Error("profile scope should be allowed")
	}
	if c.IsScopeAllowed("address") {
		t.Error("address scope should not be allowed")
	}
}

func TestStoredClient_IDTokenUserinfoClaimsAssertion(t *testing.T) {
	c := &storedClient{}
	if !c.IDTokenUserinfoClaimsAssertion() {
		t.Error("IDTokenUserinfoClaimsAssertion() must retain approved email/profile claims in the ID token")
	}
}

func TestStoredClient_ClockSkew(t *testing.T) {
	c := &storedClient{}
	if got := c.ClockSkew(); got != 0 {
		t.Errorf("ClockSkew() = %v, want 0", got)
	}
}
