// Package ad provides an Active Directory connector using LDAPS on port 636.
package ad

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/authserver/internal/connector"
	"setjoin.com/shared/identity"
)

// Connector authenticates against Active Directory via LDAPS.
type Connector struct {
	id           int64
	pool         *pgxpool.Pool
	host         string
	bindDN       string
	bindPassword string
	baseDN       string
}

// dialTLS is the LDAPS dial seam — a var so tests can capture the exact
// *tls.Config the connector builds (the CONNECTOR-001 flag-matrix acceptance
// surface) and redirect the dial to an in-process listener without altering
// any verification semantics. The production value is ldap.DialTLS.
var dialTLS = func(network, addr string, cfg *tls.Config) (*ldap.Conn, error) {
	return ldap.DialTLS(network, addr, cfg)
}

// Factory is the AD connector factory. main() registers it explicitly on its
// connector.ConnectorManager (no import-side-effect init()).
func Factory(ctx context.Context, id int64, config map[string]interface{}, attrMap map[string]string) (connector.Connector, error) {
	host, _ := config["host"].(string)
	bindDN, _ := config["bind_dn"].(string)
	bindPassword, _ := config["bind_password"].(string)
	baseDN, _ := config["base_dn"].(string)
	pool, _ := config["pool"].(*pgxpool.Pool)
	if host == "" || bindDN == "" {
		return nil, fmt.Errorf("AD connector requires host and bind_dn")
	}
	return &Connector{
		id: id, pool: pool, host: host,
		bindDN: bindDN, bindPassword: bindPassword, baseDN: baseDN,
	}, nil
}

func (c *Connector) ID() int64    { return c.id }
func (c *Connector) Type() string { return "ad" }

func (c *Connector) HealthCheck(ctx context.Context) error {
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(c.bindDN, c.bindPassword)
}

func (c *Connector) VerifyPassword(ctx context.Context, extID, password string) error {
	// Empty-credential guard (D-AUTHSERVER-INTERNAL-CONNECTOR-008): a simple
	// bind with an empty password is an UNAUTHENTICATED bind on permissive
	// LDAP backends — the directory, not this connector, would be making the
	// authentication decision. Fail closed here so the connector never
	// delegates an empty-credential verdict to the remote directory.
	if strings.TrimSpace(extID) == "" || password == "" {
		return fmt.Errorf("ad: verify password requires a user DN and a non-empty password")
	}
	// extID is the user's DN for bind-based auth
	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(extID, password)
}

// ChangePassword uses LDAP Password Modify Extended Operation (RFC 3062).
//
// Old-credential proof (D-AUTHSERVER-INTERNAL-CONNECTOR-009): when the exop
// runs under the SERVICE bind, the directory does not verify oldPassword —
// the caller's assertion would be taken on faith. Ownership is therefore
// enforced, not assumed: the connector first binds AS the target principal
// with the OLD password (a real directory authentication against that DN)
// and only then performs the service-authority write. Any proof failure
// aborts the change before the privileged write is attempted.
func (c *Connector) ChangePassword(ctx context.Context, userDN, oldPassword, newPassword string) error {
	if strings.TrimSpace(userDN) == "" || oldPassword == "" || newPassword == "" {
		return fmt.Errorf("ad: change password requires a user DN and non-empty old and new passwords")
	}

	// Proof bind: authenticate AS the principal whose password is changing.
	proof, err := c.connect()
	if err != nil {
		return err
	}
	if err := proof.Bind(userDN, oldPassword); err != nil {
		proof.Close()
		return fmt.Errorf("AD old-credential proof bind: %w", err)
	}
	proof.Close()

	conn, err := c.connect()
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := conn.Bind(c.bindDN, c.bindPassword); err != nil {
		return fmt.Errorf("AD service bind: %w", err)
	}
	req := ldap.NewPasswordModifyRequest(userDN, oldPassword, newPassword)
	if _, err := conn.PasswordModify(req); err != nil {
		return fmt.Errorf("AD password modify: %w", err)
	}
	return nil
}

// LookupByAddress resolves a person by ANY of their addresses (the
// resolve_identity seam, ADR-004). For AD the authoritative identity store is the
// local `users` table populated by the sync engine (proxyAddresses → aliases,
// userPrincipalName → ad_upn), so when a pool is available this connector resolves
// against it via connector.ResolveIdentitySQL — unioning every forest's addresses
// onto the one person. Without a pool (LDAP-only configuration) it falls back to
// echoing the address, as the prior stub did.
func (c *Connector) LookupByAddress(ctx context.Context, address string) (*connector.Identity, error) {
	// Canonicalize through the one match-side seam (same as the local connector
	// and resolveUserByAddress) so the match key equals the provision key. A bare
	// UPN / Kerberos principal is preserved (no rejection) so it still hits ad_upn.
	canon := identity.CanonicalizeAddress(address).String()
	if c.pool == nil {
		// No-pool (LDAP-only) fallback echoes the address; echo the CANONICAL form
		// so the echoed identity is consistent with the pool-backed resolution.
		return &connector.Identity{ExternalID: canon, Email: canon}, nil
	}
	var id int64
	var email, displayName, givenName, surname string
	err := c.pool.QueryRow(ctx,
		`SELECT u.id, u.email, coalesce(u.display_name, ''),
		        coalesce(u.first_name, ''), coalesce(u.last_name, '')`+
			connector.ResolveIdentitySQL, canon,
	).Scan(&id, &email, &displayName, &givenName, &surname)
	if err != nil {
		return nil, err
	}
	return &connector.Identity{
		ExternalID:  email,
		Email:       email,
		DisplayName: displayName,
		GivenName:   givenName,
		Surname:     surname,
		Attributes:  map[string]string{"user_id": fmt.Sprint(id)},
	}, nil
}

// connect dials the configured AD host over LDAPS.
//
// CONNECTOR-001 contract: certificate and hostname verification are
// UNCONDITIONAL. There is deliberately no AD_SKIP_TLS_VERIFY-style knob — the
// former env kill switch was removed (undocumented, unwired elsewhere in the
// repo, and it sat on a registered-but-never-instantiated path; the mailserver
// AD client already runs the same protocol knob-free). The *tls.Config below
// carries no InsecureSkipVerify field at all, so verification cannot be
// re-enabled-short-of-deletion from this constructor. ServerName is derived
// explicitly from the configured host (retiring the implicit dial-address
// fallback), MinVersion pins TLS 1.2, and there is no plaintext fallback:
// dial/handshake failures are errors, never downgrades.
func (c *Connector) connect() (*ldap.Conn, error) {
	addr := c.host
	if !strings.Contains(addr, ":") {
		addr = addr + ":636"
	}
	serverName, _, err := net.SplitHostPort(addr)
	if err != nil {
		serverName = addr
	}
	return dialTLS("tcp", addr, &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	})
}
