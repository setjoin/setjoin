package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// ctxCredentialsKey is the context key gokrb5 uses internally to store validated
// credentials after AcceptSecContext. It is intentionally an untyped string so
// it can be used across package boundaries without importing the unexported type.
// Source: github.com/jcmturner/gokrb5/v8/spnego/http.go
const ctxCredentialsKey = "github.com/jcmturner/gokrb5/v8/ctxCredentials" //nolint:gosec // G101: context-key constant (a gokrb5 package-path string), not a credential value.

// KerberosProvider validates SPNEGO/Kerberos tokens against a service keytab.
//
// Flow (Windows domain-joined client, zero-prompt SSO):
//  1. Client sends request; gateway returns 401 + WWW-Authenticate: Negotiate.
//  2. Windows SSPI silently obtains a Kerberos ticket for HTTP/<hostname>@REALM.
//  3. Client re-sends with Authorization: Negotiate <base64-SPNEGO>.
//  4. ValidateSPNEGO decodes and verifies the token, returns the client principal.
//  5. Gateway looks up the principal in users.krb5_principal → issues JWT.
type KerberosProvider struct {
	keytab   *keytab.Keytab
	settings []func(*service.Settings)
	realm    string
}

// NewKerberosProvider loads the HTTP service keytab from keytabPath.
// The keytab must contain an entry for HTTP/<hostname>@REALM.
func NewKerberosProvider(keytabPath, realm string) (*KerberosProvider, error) {
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("load keytab %q: %w", keytabPath, err)
	}
	p := &KerberosProvider{
		keytab: kt,
		realm:  realm,
		settings: []func(*service.Settings){
			service.RequireHostAddr(true),
			service.MaxClockSkew(5 * time.Minute),
		},
	}
	return p, nil
}

// ValidateSPNEGO validates the SPNEGO token from the Authorization header.
// Returns the authenticated Kerberos client principal, e.g. "alice@COMPANY.COM".
func (p *KerberosProvider) ValidateSPNEGO(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Negotiate ") {
		return "", errors.New("no Negotiate header")
	}

	tokenBytes, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Negotiate "))
	if err != nil {
		return "", errors.New("malformed Negotiate token: base64 decode failed")
	}

	// Parse the outer SPNEGO envelope.
	var spnegoTok spnego.SPNEGOToken
	if err := spnegoTok.Unmarshal(tokenBytes); err != nil {
		return "", fmt.Errorf("SPNEGO unmarshal: %w", err)
	}

	// SPNEGOService creates a server-side SPNEGO handler with the service keytab.
	// AcceptSecContext validates the token and returns a context enriched with
	// the client's credentials at key ctxCredentialsKey.
	svc := spnego.SPNEGOService(p.keytab, p.settings...)
	ok, ctx, status := svc.AcceptSecContext(&spnegoTok)
	if !ok {
		return "", fmt.Errorf("SPNEGO authentication failed: %s", status.Message)
	}

	// Extract credentials from the context using the known internal string key.
	creds, ok := ctx.Value(ctxCredentialsKey).(*credentials.Credentials)
	if !ok || creds == nil {
		return "", errors.New("no credentials in SPNEGO context")
	}

	// Enforce realm match if configured
	if p.realm != "" && creds.Realm() != p.realm {
		return "", fmt.Errorf("SPNEGO realm mismatch: got %q, expected %q", creds.Realm(), p.realm)
	}

	return fmt.Sprintf("%s@%s", creds.UserName(), creds.Realm()), nil
}

// IsNegotiateRequest reports whether the request carries a SPNEGO/Kerberos token.
func IsNegotiateRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Negotiate ")
}
