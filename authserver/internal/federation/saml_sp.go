// Package federation provides SAML 2.0 SP and OIDC RP implementations
// extracted from the mailserver gateway for the standalone auth server.
package federation

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/identity"
	"setjoin.com/shared/ssrf"
)

// SAMLSPRegistry manages multiple SAML Service Provider registrations
// loaded from the saml_sp_registrations database table.
// Each registration maps to an IdP and uses the shared SP signing keypair.
type SAMLSPRegistry struct {
	mu       sync.RWMutex
	reloadMu sync.Mutex
	entries  map[string]*samlspRegistration // keyed by idp_entity_id
	pool     *pgxpool.Pool
	spKey    *rsa.PrivateKey
	spCert   *x509.Certificate
	ctx      context.Context
}

type samlspRegistration struct {
	ID             int64
	IDPEntityID    string
	IDPMetadataURL string
	IDPSSOURL      string
	IDPCertPEM     string
	SPEntityID     string
	SPACSURL       string
	AttributeMap   map[string]string
	jitEnabled     bool
	Enabled        bool
	middleware     *samlsp.Middleware
	groupAttribute string          // SAML attribute for group membership (default "memberOf")
	groupMappings  json.RawMessage // JSONB from saml_sp_registrations.group_mappings
}

// NewSAMLSPRegistry creates a registry that loads SAML SP registrations from
// the database. spCertFile and spKeyFile provide the SP's signing keypair
// (shared across all registrations).
func NewSAMLSPRegistry(ctx context.Context, pool *pgxpool.Pool, spCertFile, spKeyFile string) (*SAMLSPRegistry, error) {
	pair, err := tls.LoadX509KeyPair(spCertFile, spKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load SAML SP cert/key: %w", err)
	}
	privateKey, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SAML SP private key is not RSA")
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("SAML SP certificate chain is empty")
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse SAML SP cert: %w", err)
	}

	r := &SAMLSPRegistry{
		pool:   pool,
		spKey:  privateKey,
		spCert: cert,
		ctx:    ctx,
	}

	if err := r.loadRegistrations(ctx); err != nil {
		return r, fmt.Errorf("load SAML SP registrations: %w", err)
	}

	return r, nil
}

// loadRegistrations reads enabled SAML SP registrations from the database.
func (r *SAMLSPRegistry) loadRegistrations(ctx context.Context) error {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	rows, err := r.pool.Query(ctx,
		`SELECT id, idp_entity_id, idp_metadata_url, idp_sso_url,
		        pgp_sym_decrypt(idp_cert_enc, current_setting('app.encryption_key')) AS idp_cert_pem,
		        sp_entity_id, sp_acs_url, attribute_map, jit_enabled, enabled,
		        group_attribute, group_mappings
		 FROM saml_sp_registrations WHERE enabled = TRUE`)
	if err != nil {
		r.replaceEntries(nil)
		return err
	}
	defer rows.Close()

	entries := make(map[string]*samlspRegistration)
	var loadErrs []error
	for rows.Next() {
		var reg samlspRegistration
		var attrMap map[string]string
		if err := rows.Scan(&reg.ID, &reg.IDPEntityID, &reg.IDPMetadataURL, &reg.IDPSSOURL,
			&reg.IDPCertPEM, &reg.SPEntityID, &reg.SPACSURL, &attrMap, &reg.jitEnabled, &reg.Enabled,
			&reg.groupAttribute, &reg.groupMappings); err != nil {
			r.replaceEntries(nil)
			return err
		}
		reg.AttributeMap = attrMap
		var mappings []GroupMapping
		if len(reg.groupMappings) > 0 {
			if err := json.Unmarshal(reg.groupMappings, &mappings); err != nil {
				loadErrs = append(loadErrs,
					fmt.Errorf("decode group mappings for IdP %q: %w", reg.IDPEntityID, err))
				continue
			}
		}
		if err := validateGroupMappings(mappings); err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("SAML registration %q: %w", reg.IDPEntityID, err))
			continue
		}

		mw, err := r.buildMiddleware(&reg)
		if err != nil {
			loadErrs = append(loadErrs,
				fmt.Errorf("build middleware for IdP %q: %w", reg.IDPEntityID, err))
			continue
		}
		reg.middleware = mw
		entries[reg.IDPEntityID] = &reg
	}
	if err := rows.Err(); err != nil {
		r.replaceEntries(nil)
		return err
	}

	r.replaceEntries(entries)
	return errors.Join(loadErrs...)
}

func (r *SAMLSPRegistry) replaceEntries(entries map[string]*samlspRegistration) {
	if entries == nil {
		entries = make(map[string]*samlspRegistration)
	}
	r.mu.Lock()
	r.entries = entries
	r.mu.Unlock()
}

// buildMiddleware creates a samlsp.Middleware for a single registration.
func (r *SAMLSPRegistry) buildMiddleware(reg *samlspRegistration) (*samlsp.Middleware, error) {
	rootURL, err := url.Parse(reg.SPEntityID)
	if err != nil {
		return nil, fmt.Errorf("parse SP entity ID: %w", err)
	}
	rootURL.Path = ""

	// Parse IdP metadata — validate URL protocol before fetching
	idpMetadata, err := samlsp.ParseMetadata([]byte(reg.IDPMetadataURL))
	if err != nil {
		if mdURL, parseErr := url.Parse(reg.IDPMetadataURL); parseErr == nil {
			if mdURL.Scheme != "https" {
				return nil, fmt.Errorf("refusing to fetch IdP metadata over %s (https required)", mdURL.Scheme)
			}
			idpMetadata, err = samlsp.FetchMetadata(r.ctx, ssrf.SafeHTTPClient(10*time.Second), *mdURL)
		}
		if err != nil {
			return nil, fmt.Errorf("parse/fetch IdP metadata: %w", err)
		}
	}

	mw, err := samlsp.New(samlsp.Options{
		URL:               *rootURL,
		Key:               r.spKey,
		Certificate:       r.spCert,
		IDPMetadata:       idpMetadata,
		AllowIDPInitiated: false,
		SignRequest:       true,
	})
	if err != nil {
		return nil, err
	}

	mw.ServiceProvider.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	return mw, nil
}

// Registration returns the SAML SP registration for a given IdP entity ID.
func (r *SAMLSPRegistry) Registration(idpEntityID string) *samlspRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.entries[idpEntityID]
}

// Entries returns all currently loaded registrations.
func (r *SAMLSPRegistry) Entries() []*samlspRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*samlspRegistration, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

// ListenForChanges durably subscribes to config_changed and reloads the
// authoritative registration snapshot after every reconnect, repairing any
// NOTIFY payloads PostgreSQL could not replay while the connection was down.
func (r *SAMLSPRegistry) ListenForChanges(ctx context.Context, listener configChangeListener, logger *slog.Logger) error {
	listener.OnReconnect(r.loadRegistrations)
	_, err := listener.SubscribeDurable(ctx, "config_changed", func(notification *pgconn.Notification) {
		var n struct {
			Key string `json:"key"`
		}
		if json.Unmarshal([]byte(notification.Payload), &n) != nil {
			return
		}
		if n.Key == "auth_methods" || n.Key == "saml_sp" {
			if err := r.loadRegistrations(r.ctx); err != nil {
				logger.Warn("SAML reload failed", "error", err)
			}
		}
	})
	if err != nil {
		return err
	}
	return r.loadRegistrations(ctx)
}

// Middleware returns the samlsp.Middleware for the given IdP entity ID.
func (reg *samlspRegistration) Middleware() *samlsp.Middleware {
	return reg.middleware
}

// NameIDFromRequest extracts the authenticated NameID from a request that
// has been processed by the SAML middleware (inside the ACS handler).
func (reg *samlspRegistration) NameIDFromRequest(r *http.Request) (string, error) {
	session, err := reg.middleware.Session.GetSession(r)
	if err != nil {
		return "", err
	}
	sa, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return "", fmt.Errorf("unexpected session type")
	}
	return sa.Subject, nil
}

// GroupsFromAssertion extracts group membership from SAML assertion attributes.
func (reg *samlspRegistration) GroupsFromAssertion(r *http.Request) ([]string, error) {
	session, err := reg.middleware.Session.GetSession(r)
	if err != nil {
		return nil, err
	}
	sa, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected session type")
	}
	attrName := reg.groupAttribute
	if attrName == "" {
		attrName = "memberOf"
	}
	groups := sa.Attributes[attrName]
	if err := identity.ValidateSSOGroupClaims(groups); err != nil {
		return nil, fmt.Errorf("SAML group attribute %q is invalid: %w", attrName, err)
	}
	return groups, nil
}

// EmailFromAssertion extracts email from SAML assertion attributes.
func (reg *samlspRegistration) EmailFromAssertion(r *http.Request) (string, error) {
	session, err := reg.middleware.Session.GetSession(r)
	if err != nil {
		return "", err
	}
	sa, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return "", fmt.Errorf("unexpected session type")
	}
	for _, attrName := range []string{"email", "mail", "emailaddress", "upn"} {
		if v := sa.Attributes.Get(attrName); v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("no email attribute in SAML assertion")
}

// JITEnabled returns whether just-in-time provisioning is enabled for this registration.
func (reg *samlspRegistration) JITEnabled() bool { return reg.jitEnabled }

// GetGroupMappings decodes and returns the group mappings for this registration.
// Implements GroupMappingProvider.
func (reg *samlspRegistration) GetGroupMappings() []GroupMapping {
	if len(reg.groupMappings) == 0 {
		return nil
	}
	var mappings []GroupMapping
	json.Unmarshal(reg.groupMappings, &mappings)
	return mappings
}

// SSOProviderKey returns the immutable internal registration identifier used to
// keep one SAML IdP's entitlement reconciliation isolated from every other IdP.
func (reg *samlspRegistration) SSOProviderKey() string {
	return fmt.Sprintf("saml:%d", reg.ID)
}

// AssertionID extracts the assertion ID from a request processed by the SAML middleware.
func (reg *samlspRegistration) AssertionID(r *http.Request) (string, error) {
	session, err := reg.middleware.Session.GetSession(r)
	if err != nil {
		return "", err
	}
	sa, ok := session.(samlsp.JWTSessionClaims)
	if !ok {
		return "", fmt.Errorf("unexpected session type")
	}
	return sa.Id, nil
}
