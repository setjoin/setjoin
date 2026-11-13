// Package federation provides SAML 2.0 SP and OIDC RP implementations.
//
// OIDC RP uses zitadel/oidc v3 for the relying party.
package federation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"setjoin.com/authserver/internal/federation/pkce"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgnotify"
	"setjoin.com/shared/ssrf"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// configChangeListener is the narrow durable LISTEN seam used by both
// federation caches. The shared listener owns reconnect replay while this
// interface keeps registration behavior independently testable.
type configChangeListener interface {
	OnReconnect(func(context.Context) error)
	SubscribeDurable(context.Context, string, pgnotify.NotifyHandler) (int, error)
}

// oidcDiscoveryTimeout bounds the OIDC discovery + JWKS fetch performed during
// rp.NewRelyingPartyOIDC, matching the SAML metadata fetch timeout.
const oidcDiscoveryTimeout = 10 * time.Second

// validateOIDCIssuerScheme rejects an OIDC issuer URL that is not https before
// the discovery fetch ({issuer}/.well-known/openid-configuration) is made. The
// provider URL is admin-set, but this mirrors saml_sp.go's https check so a
// misconfigured (or downgraded) issuer can never be fetched over a plaintext
// or non-http(s) scheme. It is the cheap fail-fast pre-check; the dial-time
// SafeHTTPClient guard below is the authoritative DNS-rebinding defense.
func validateOIDCIssuerScheme(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid OIDC issuer URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing to fetch OIDC discovery over %q (https required)", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("OIDC issuer URL %q has no host (https required)", rawURL)
	}
	return nil
}

// safeOIDCDiscoveryClient returns the SSRF-guarded HTTP client used for the
// OIDC discovery + JWKS fetch. Like the SAML metadata fetch and the mailserver
// JWKS / MTA-STS / TLS-RPT paths, the issuer host is admin-set but still
// routed through shared/ssrf so a host that resolves (or is rebound) to a
// loopback / private / link-local address is refused at dial time.
func safeOIDCDiscoveryClient() *http.Client {
	return ssrf.SafeHTTPClient(oidcDiscoveryTimeout)
}

// OIDCRPProvider manages OpenID Connect Relying Party configurations
// loaded from the system_config table for multi-provider support.
type OIDCRPProvider struct {
	mu        sync.RWMutex
	reloadMu  sync.Mutex
	providers map[string]*oidcProviderConfig
	pool      *pgxpool.Pool
	ctx       context.Context
	// masterKey is the raw deployment DB-encryption master secret. Per the
	// cryptokey contract the column key is derived internally
	// (DeriveDBEncryptionKey) — pass the RAW secret, never a pre-derived key.
	masterKey []byte
}

type oidcProviderConfig struct {
	name         string
	providerURL  string
	clientID     string
	clientSecret string
	redirectURL  string
	jitEnabled   bool
	enabled      bool
	groupClaim   string

	relyingParty rp.RelyingParty

	groupMappings []GroupMapping
}

// oidcProviderConfigJSON is the JSON-decodable representation.
type oidcProviderConfigJSON struct {
	Name         string `json:"name"`
	ProviderURL  string `json:"provider_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	JITEnabled   bool   `json:"jit_enabled"`
	Enabled      bool   `json:"enabled"`
	GroupClaim   string `json:"group_claim"`
}

// GroupMapping is a single mapping from an IdP group to local entities.
type GroupMapping struct {
	IDPGroup            string  `json:"idp_group"`
	DistributionGroupID *int64  `json:"distribution_group_id,omitempty"`
	AdminRole           *string `json:"admin_role,omitempty"`
	DepartmentID        *int64  `json:"department_id,omitempty"`
}

// GroupMappingProvider abstracts reading group mappings from provider config.
type GroupMappingProvider interface {
	GetGroupMappings() []GroupMapping
	SSOProviderKey() string
}

// ValidSSOProviderKey mirrors V153's database constraint for the stable
// reconciliation discriminator. Validate configuration before discovery/login
// as well as at the write boundary so an invalid provider cannot silently skip
// entitlement reconciliation.
func ValidSSOProviderKey(providerKey string) bool {
	if len(providerKey) < 3 || len(providerKey) > 255 || providerKey != strings.TrimSpace(providerKey) {
		return false
	}
	for _, r := range providerKey {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// NewOIDCRPProvider creates an OIDC RP provider that loads configurations
// from system_config keys matching "oidc_provider_*_config". masterKey is the
// raw deployment DB-encryption master secret (e.g. the JWT secret); client
// secrets are cryptokey-sealed at rest and every non-empty value must verify
// and decrypt under it — plaintext rows fail closed (the startup re-seal
// migration, ResealOIDCProviderClientSecrets, upgrades legacy rows first).
func NewOIDCRPProvider(ctx context.Context, pool *pgxpool.Pool, masterKey []byte) (*OIDCRPProvider, error) {
	p := &OIDCRPProvider{
		pool:      pool,
		ctx:       ctx,
		masterKey: masterKey,
	}
	if err := p.loadProviders(ctx); err != nil {
		// loadProviders has already atomically installed the fail-closed healthy
		// subset. Return it with the error so one bad provider cannot disable
		// unrelated healthy providers or preserve a revoked prior provider.
		return p, fmt.Errorf("load OIDC providers: %w", err)
	}
	return p, nil
}

// loadProviders reads OIDC provider configs from system_config.
// Keys are "oidc_provider_<name>_config" with JSON values.
func (p *OIDCRPProvider) loadProviders(ctx context.Context) error {
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()

	rows, err := p.pool.Query(ctx,
		`SELECT key,value,encrypted FROM system_config
		  WHERE key LIKE 'oidc_provider_%_config' ORDER BY key`)
	if err != nil {
		p.replaceProviders(nil)
		return err
	}
	defer rows.Close()

	providers := make(map[string]*oidcProviderConfig)
	var loadErrs []error
	for rows.Next() {
		var key string
		var raw json.RawMessage
		var encrypted bool
		if err := rows.Scan(&key, &raw, &encrypted); err != nil {
			p.replaceProviders(nil)
			return err
		}
		var rawCfg struct {
			oidcProviderConfigJSON
			GroupMappings []GroupMapping `json:"group_mappings"`
		}
		if err := json.Unmarshal(raw, &rawCfg); err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("unmarshal OIDC provider config %q: %w", key, err))
			continue
		}
		if !rawCfg.Enabled {
			continue
		}

		// At-rest contract: the stored client_secret must be cryptokey-sealed
		// ciphertext. The `encrypted` column flag alone is insufficient — the
		// value itself has to verify and decrypt, and plaintext rows fail
		// closed here so no plaintext secret reaches the RP client. Startup
		// runs ResealOIDCProviderClientSecrets first, upgrading legacy rows.
		clientSecret, err := OpenOIDCClientSecret(rawCfg.ClientSecret, p.masterKey)
		if err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("OIDC provider %q (key %q, encrypted flag %t): %w",
					rawCfg.Name, key, encrypted, err))
			continue
		}
		rawCfg.ClientSecret = clientSecret

		if err := validateGroupMappings(rawCfg.GroupMappings); err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("OIDC provider %q: %w", rawCfg.Name, err))
			continue
		}
		if providerKey := "oidc:" + rawCfg.Name; !ValidSSOProviderKey(providerKey) {
			loadErrs = append(loadErrs,
				fmt.Errorf("OIDC provider %q has invalid stable name", key))
			continue
		}

		// Enforce https on the admin-set issuer before any discovery fetch,
		// and route that fetch through the SSRF-guarded client (DNS-rebinding
		// defense), matching saml_sp.go / mailserver JWKS / MTA-STS.
		if err := validateOIDCIssuerScheme(rawCfg.ProviderURL); err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("OIDC provider %q: %w", rawCfg.Name, err))
			continue
		}

		scopes := []string{oidc.ScopeOpenID, "email", "profile", "groups"}

		relyingParty, err := rp.NewRelyingPartyOIDC(ctx,
			rawCfg.ProviderURL,
			rawCfg.ClientID,
			rawCfg.ClientSecret,
			rawCfg.RedirectURL,
			scopes,
			rp.WithHTTPClient(safeOIDCDiscoveryClient()),
			// OIDCCallback validates the request-bound nonce against its
			// HttpOnly cookie after exchange. zitadel's default verifier instead
			// expects an empty nonce and rejects every correctly nonced token.
			rp.WithVerifierOpts(oidcRPVerifierOptions()...),
		)
		if err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("OIDC discovery for %q: %w", rawCfg.Name, err))
			continue
		}

		groupClaim := rawCfg.GroupClaim
		if groupClaim == "" {
			groupClaim = "groups"
		}

		cfg := &oidcProviderConfig{
			name:         rawCfg.Name,
			providerURL:  rawCfg.ProviderURL,
			clientID:     rawCfg.ClientID,
			clientSecret: rawCfg.ClientSecret,
			redirectURL:  rawCfg.RedirectURL,
			jitEnabled:   rawCfg.JITEnabled,
			enabled:      rawCfg.Enabled,
			groupClaim:   groupClaim,
			relyingParty: relyingParty,
		}
		cfg.groupMappings = rawCfg.GroupMappings

		providers[cfg.name] = cfg
	}
	if err := rows.Err(); err != nil {
		p.replaceProviders(nil)
		return err
	}

	p.replaceProviders(providers)
	return errors.Join(loadErrs...)
}

func (p *OIDCRPProvider) replaceProviders(providers map[string]*oidcProviderConfig) {
	if providers == nil {
		providers = make(map[string]*oidcProviderConfig)
	}
	p.mu.Lock()
	p.providers = providers
	p.mu.Unlock()
}

func oidcRPVerifierOptions() []rp.VerifierOption {
	return []rp.VerifierOption{rp.WithNonce(nil)}
}

// Provider returns the OIDC provider config by name.
func (p *OIDCRPProvider) Provider(name string) *oidcProviderConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.providers[name]
}

// Providers returns all currently loaded provider configs.
func (p *OIDCRPProvider) Providers() []*oidcProviderConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*oidcProviderConfig, 0, len(p.providers))
	for _, cfg := range p.providers {
		out = append(out, cfg)
	}
	return out
}

// NewOIDCRPProviderForTest returns a registry holding a single provider under
// name whose token exchanges go through party. TEST-ONLY seam: production
// registries are populated exclusively by loadProviders from system_config,
// and the SSRF-guarded discovery client intentionally refuses loopback IdPs
// at dial time, so handler regression tests cannot stand up an in-process IdP
// any other way. Never wire this from main.
func NewOIDCRPProviderForTest(name string, party rp.RelyingParty) *OIDCRPProvider {
	if name == "" || party == nil {
		panic("federation: NewOIDCRPProviderForTest requires a provider name and relying party")
	}
	return &OIDCRPProvider{
		providers: map[string]*oidcProviderConfig{
			name: {name: name, relyingParty: party, enabled: true},
		},
	}
}

// ListenForChanges durably subscribes to config_changed and reloads the
// authoritative provider snapshot after every reconnect, repairing any NOTIFY
// payloads PostgreSQL could not replay while the direct connection was down.
func (p *OIDCRPProvider) ListenForChanges(ctx context.Context, listener configChangeListener, logger *slog.Logger) error {
	listener.OnReconnect(p.loadProviders)
	_, err := listener.SubscribeDurable(ctx, "config_changed", func(notification *pgconn.Notification) {
		var n struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(notification.Payload), &n) != nil {
			return
		}
		if isOIDCConfigNotification(n.Key) {
			if err := p.loadProviders(p.ctx); err != nil {
				logger.Warn("OIDC reload failed", "error", err)
			}
		}
	})
	if err != nil {
		return err
	}
	// Close the startup-to-first-LISTEN mutation window. A failure already
	// replaces the cache with only the healthy authoritative subset, and the
	// outer listener supervisor retries until the snapshot is complete.
	return p.loadProviders(ctx)
}

func isOIDCConfigNotification(key string) bool {
	if key == "auth_methods" || key == "oidc_rp" {
		return true
	}
	const prefix = "oidc_provider_"
	const suffix = "_config"
	if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
	if name == "" || len(name) > 200 {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// AuthCodeURL returns the IdP authorization redirect URL and the PKCE
// code_verifier bound to it (FEDERATION-003, RFC 7636). The URL carries a
// code_challenge (S256) derived from the returned verifier; the caller must
// persist the verifier in request-bound flow state (HttpOnly SameSite=Strict
// cookie, like state/nonce) and pass it back to Exchange at the callback. The
// IdP rejects the token request unless its code_verifier derives the challenge
// sent here, so an intercepted authorization code alone is worthless.
func (cfg *oidcProviderConfig) AuthCodeURL(state, nonce string) (string, string, error) {
	verifier, err := pkce.NewVerifier()
	if err != nil {
		return "", "", fmt.Errorf("pkce: %w", err)
	}
	challenge, err := pkce.ChallengeS256(verifier)
	if err != nil {
		return "", "", fmt.Errorf("pkce: %w", err)
	}
	authURL := rp.AuthURL(state, cfg.relyingParty,
		func() []oauth2.AuthCodeOption {
			return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", nonce)}
		},
		rp.WithCodeChallenge(challenge),
	)
	return authURL, verifier, nil
}

// Exchange trades an authorization code for ID token claims, presenting the
// PKCE code_verifier minted by AuthCodeURL. An empty or malformed verifier
// fails closed before any network request (FEDERATION-003); a well-formed but
// mismatched verifier is rejected by the IdP's RFC 7636 §4.6 check.
// The library handles at_hash and c_hash validation automatically.
func (cfg *oidcProviderConfig) Exchange(ctx context.Context, code, codeVerifier string) (*oidc.Tokens[*oidc.IDTokenClaims], error) {
	if err := pkce.ValidateVerifier(codeVerifier); err != nil {
		return nil, err
	}
	return rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, cfg.relyingParty, rp.WithCodeVerifier(codeVerifier))
}

// EmailFromIDToken extracts the email claim from ID token claims.
func EmailFromIDToken(claims *oidc.IDTokenClaims) (string, error) {
	if claims.Email != "" {
		return claims.Email, nil
	}
	if claims.PreferredUsername != "" {
		return claims.PreferredUsername, nil
	}
	if claims.Claims != nil {
		if upn, ok := claims.Claims["upn"].(string); ok && upn != "" {
			return upn, nil
		}
	}
	return "", fmt.Errorf("no email claim in ID token")
}

// EmailVerifiedFromIDToken checks the email_verified claim (OIDC Core section 5.1).
func EmailVerifiedFromIDToken(claims *oidc.IDTokenClaims) bool {
	return bool(claims.EmailVerified)
}

// JITEnabled returns whether just-in-time provisioning is enabled for this provider.
func (cfg *oidcProviderConfig) JITEnabled() bool { return cfg.jitEnabled }

// RedirectURL returns the configured OAuth2 redirect URL.
func (cfg *oidcProviderConfig) RedirectURL() string { return cfg.redirectURL }

// Name returns the provider's configured name.
func (cfg *oidcProviderConfig) Name() string { return cfg.name }

// GroupClaim returns the claim name for group extraction (default "groups").
func (cfg *oidcProviderConfig) GroupClaim() string {
	if cfg.groupClaim == "" {
		return "groups"
	}
	return cfg.groupClaim
}

// GetGroupMappings returns the group mappings for this provider.
// Implements GroupMappingProvider.
func (cfg *oidcProviderConfig) GetGroupMappings() []GroupMapping {
	return cfg.groupMappings
}

// SSOProviderKey returns the stable config identifier used to scope entitlement
// reconciliation to this provider. The name is the key of the multi-provider
// OIDC configuration, not a mutable issuer display value.
func (cfg *oidcProviderConfig) SSOProviderKey() string {
	return "oidc:" + cfg.name
}

// RandomState generates a cryptographically random state/nonce parameter.
func RandomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// SubjectFromIDToken extracts the stable subject identifier and issuer.
func SubjectFromIDToken(sub, iss string) (string, string, error) {
	if sub == "" {
		return "", "", fmt.Errorf("missing sub claim in ID token")
	}
	return sub, iss, nil
}

// GroupsFromClaims extracts group claims from a parsed claims map.
func GroupsFromClaims(claims map[string]interface{}, claimName string) ([]string, error) {
	raw, ok := claims[claimName]
	if !ok {
		return nil, nil
	}
	var groups []string
	switch v := raw.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("group claim %q contains a non-string value", claimName)
			}
			out = append(out, s)
		}
		groups = out
	case []string:
		groups = v
	case string:
		groups = []string{v}
	default:
		return nil, fmt.Errorf("group claim %q has unsupported type %T", claimName, raw)
	}
	if err := identity.ValidateSSOGroupClaims(groups); err != nil {
		return nil, fmt.Errorf("group claim %q is invalid: %w", claimName, err)
	}
	return groups, nil
}

func validateGroupMappings(mappings []GroupMapping) error {
	groups := make([]string, len(mappings))
	for i := range mappings {
		groups[i] = mappings[i].IDPGroup
	}
	return identity.ValidateSSOGroupMappings(groups)
}

// RolePriority returns a numeric priority for an admin role (higher = more privileged).
func RolePriority(role string) int {
	switch role {
	case "super_admin":
		return 4
	case "user_admin":
		return 3
	case "read_only":
		return 2
	case "auditor":
		return 1
	default:
		return 0
	}
}

// ContainsString reports whether s is present in slice.
func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
