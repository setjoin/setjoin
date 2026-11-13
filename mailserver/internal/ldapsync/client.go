// Package ldapsync provides a generic LDAP identity sync engine supporting
// OpenLDAP, FreeIPA, Samba AD DC, 389 DS, and other RFC 4511-compatible servers.
package ldapsync

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/mailserver/internal/tlsutil"
	"setjoin.com/shared/identity"
)

// LDAPUser represents a user entry synced from an LDAP directory.
type LDAPUser struct {
	DN        string // entry's own distinguished name
	ManagerDN string // manager attribute (DN of the manager entry)
	// ManagerSubject is the manager's configured immutable anchor. It is
	// resolved independently of the current delta because an unchanged manager
	// is normally absent from an incremental result.
	ManagerSubject string
	Email          string
	DisplayName    string
	FirstName      string
	LastName       string
	Title          string
	Phone          string
	Department     string
	UPN            string
	Disabled       bool
	ModifyStamp    string // OpenLDAP modifyTimestamp or equivalent
	// ImmutableSubject is populated only from the configured, uniqueness-proven
	// subject attribute. DN and mail are never implicit identity anchors.
	ImmutableSubject string
}

// ldapUserAttrs is the set of user attributes requested from the LDAP directory.
// Package-level so tests can assert that "manager" is included.
var ldapUserAttrs = []string{
	"dn", "mail", "displayName", "givenName", "sn",
	"title", "telephoneNumber", "department",
	"userPrincipalName", "modifyTimestamp", "manager",
	// Lock-state attributes across the supported directory types.
	"nsAccountLock", "pwdAccountLockedTime", "userAccountControl",
}

// Client is an LDAP client for a directory server.
type Client struct {
	host             string
	port             int
	transport        string
	bindDN           string
	password         string
	baseDN           string
	subjectAttribute string
}

// NewClient creates a new LDAP client.
func NewClient(host string, port int, useTLS bool, bindDN, password, baseDN string) *Client {
	transport := "starttls"
	if useTLS {
		transport = "ldaps"
	}
	return &Client{
		host: host, port: port, transport: transport,
		bindDN: bindDN, password: password, baseDN: baseDN,
	}
}

// NewClientWithTransport constructs a normalized LDAP source. Credentialed
// normalized sources fail closed unless transport security is configured.
func NewClientWithTransport(
	host string,
	port int,
	transport string,
	bindDN string,
	password string,
	baseDN string,
) (*Client, error) {
	if host == "" || port < 1 || port > 65535 {
		return nil, fmt.Errorf("LDAP endpoint is invalid")
	}
	if baseDN == "" {
		return nil, fmt.Errorf("LDAP base DN is required")
	}
	if transport != "ldaps" && transport != "starttls" {
		return nil, fmt.Errorf("LDAP transport must be ldaps or starttls")
	}
	return &Client{
		host: host, port: port, transport: transport,
		bindDN: bindDN, password: password, baseDN: baseDN,
	}, nil
}

var ldapAttributeName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,63}$`)

// SetSubjectAttribute selects the operator-approved immutable anchor. Empty
// keeps normalized provisioning fail-closed.
func (c *Client) SetSubjectAttribute(attribute string) error {
	if attribute == "" {
		c.subjectAttribute = ""
		return nil
	}
	if !ldapAttributeName.MatchString(attribute) {
		return fmt.Errorf("invalid LDAP subject attribute %q", attribute)
	}
	c.subjectAttribute = attribute
	return nil
}

func (c *Client) SubjectAttribute() string { return c.subjectAttribute }

// buildLDAPSyncAttrs returns the attribute map for syncing an LDAP user. The
// email is canonicalized through the ONE seam before the UPDATE-path writer
// (SyncAttrs demands CanonicalAddress), so users.email stays Go-canonical on
// every sync.
func buildLDAPSyncAttrs(u LDAPUser) map[string]string {
	return ldaputil.SyncAttrs(identity.CanonicalizeAddress(u.Email), u.DisplayName,
		u.FirstName, u.LastName, u.Title, u.Phone, u.UPN)
}

// Connect dials the LDAP server.
func (c *Client) Connect() (*ldap.Conn, error) {
	addr := fmt.Sprintf("%s:%d", c.host, c.port)
	tlsConfig := &tls.Config{
		ServerName:       c.host,
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     tlsutil.DefaultCipherSuites,
		CurvePreferences: tlsutil.DefaultCurves,
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	setTimeout := func(conn *ldap.Conn, err error) (*ldap.Conn, error) {
		if err == nil {
			conn.SetTimeout(30 * time.Second)
		}
		return conn, err
	}
	switch c.transport {
	case "ldaps":
		return setTimeout(ldap.DialURL(
			"ldaps://"+addr,
			ldap.DialWithDialer(dialer),
			ldap.DialWithTLSConfig(tlsConfig),
		))
	case "starttls":
		conn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(dialer))
		if err != nil {
			return nil, err
		}
		if err := conn.StartTLS(tlsConfig); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("STARTTLS: %w", err)
		}
		return setTimeout(conn, nil)
	default:
		return nil, fmt.Errorf("unsupported LDAP transport")
	}
}

// Bind authenticates as the service account.
func (c *Client) Bind(conn *ldap.Conn) error {
	if _, ok := conn.TLSConnectionState(); !ok {
		return fmt.Errorf("refusing LDAP bind without TLS")
	}
	return conn.Bind(c.bindDN, c.password)
}

// SearchUsers searches for user entries in the directory.
func (c *Client) SearchUsers(conn *ldap.Conn, filter string, pageSize int) ([]LDAPUser, error) {
	req, effectivePageSize := c.userSearchRequest(filter, pageSize)

	sr, err := conn.SearchWithPaging(req, effectivePageSize)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}

	var users []LDAPUser
	for _, entry := range sr.Entries {
		users = append(users, c.userFromEntry(entry))
	}

	if err := c.resolveManagerSubjects(conn, users); err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Client) userSearchRequest(filter string, pageSize int) (*ldap.SearchRequest, uint32) {
	if filter == "" {
		filter = "(objectClass=person)"
	}
	if pageSize <= 0 {
		pageSize = 500
	}

	attrs := append([]string(nil), ldapUserAttrs...)
	if c.subjectAttribute != "" {
		attrs = append(attrs, c.subjectAttribute)
	}
	req := ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attrs, nil,
	)
	return req, uint32(pageSize)
}

func (c *Client) userFromEntry(entry *ldap.Entry) LDAPUser {
	return LDAPUser{
		DN:               entry.DN,
		ManagerDN:        entry.GetAttributeValue("manager"),
		Email:            entry.GetAttributeValue("mail"),
		DisplayName:      entry.GetAttributeValue("displayName"),
		FirstName:        entry.GetAttributeValue("givenName"),
		LastName:         entry.GetAttributeValue("sn"),
		Title:            entry.GetAttributeValue("title"),
		Phone:            entry.GetAttributeValue("telephoneNumber"),
		Department:       entry.GetAttributeValue("department"),
		UPN:              entry.GetAttributeValue("userPrincipalName"),
		ModifyStamp:      entry.GetAttributeValue("modifyTimestamp"),
		ImmutableSubject: entry.GetAttributeValue(c.subjectAttribute),
		Disabled: entryDisabled(
			entry.GetAttributeValue("nsAccountLock"),
			entry.GetAttributeValue("pwdAccountLockedTime"),
			entry.GetAttributeValue("userAccountControl"),
		),
	}
}

const managerLookupChunkSize = 100

func (c *Client) resolveManagerSubjects(conn *ldap.Conn, users []LDAPUser) error {
	if c.subjectAttribute == "" {
		return nil
	}
	subjectByDN, missing := knownManagerSubjects(users)
	for start := 0; start < len(missing); start += managerLookupChunkSize {
		end := min(start+managerLookupChunkSize, len(missing))
		res, err := conn.Search(c.managerSearchRequest(missing[start:end]))
		if err != nil {
			return fmt.Errorf("LDAP manager anchor lookup: %w", err)
		}
		for _, entry := range res.Entries {
			if subject := entry.GetAttributeValue(c.subjectAttribute); subject != "" {
				subjectByDN[ldaputil.NormalizeDN(entry.DN)] = subject
			}
		}
	}
	applyManagerSubjects(users, subjectByDN)
	return nil
}

func knownManagerSubjects(users []LDAPUser) (map[string]string, []string) {
	subjectByDN := make(map[string]string, len(users))
	for i := range users {
		if users[i].DN != "" && users[i].ImmutableSubject != "" {
			subjectByDN[ldaputil.NormalizeDN(users[i].DN)] = users[i].ImmutableSubject
		}
	}
	missing := make([]string, 0)
	seen := make(map[string]struct{})
	for i := range users {
		managerDN := ldaputil.NormalizeDN(users[i].ManagerDN)
		if managerDN == "" {
			continue
		}
		if subject := subjectByDN[managerDN]; subject != "" {
			users[i].ManagerSubject = subject
			continue
		}
		if _, ok := seen[managerDN]; !ok {
			seen[managerDN] = struct{}{}
			missing = append(missing, users[i].ManagerDN)
		}
	}
	return subjectByDN, missing
}

func (c *Client) managerSearchRequest(dns []string) *ldap.SearchRequest {
	parts := make([]string, 0, len(dns))
	for _, dn := range dns {
		parts = append(parts, "(distinguishedName="+ldap.EscapeFilter(dn)+")")
	}
	return ldap.NewSearchRequest(
		c.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		"(|"+strings.Join(parts, "")+")",
		[]string{c.subjectAttribute},
		nil,
	)
}

func applyManagerSubjects(users []LDAPUser, subjectByDN map[string]string) {
	for i := range users {
		if users[i].ManagerSubject == "" {
			users[i].ManagerSubject = subjectByDN[ldaputil.NormalizeDN(users[i].ManagerDN)]
		}
	}
}

// entryDisabled reports whether a directory entry is locked/disabled. Each
// supported directory family signals this differently, so all three lock
// attributes are honoured — otherwise a user disabled in OpenLDAP or Samba/AD is
// never deprovisioned locally and keeps an active setjoin account and sessions:
//
//   - FreeIPA / 389 DS: nsAccountLock = TRUE.
//   - OpenLDAP ppolicy: pwdAccountLockedTime present (any non-empty value is
//     locked; the special 000001010000Z means permanently locked).
//   - Samba / AD:       userAccountControl ACCOUNTDISABLE bit (0x2) set.
func entryDisabled(nsAccountLock, pwdAccountLockedTime, userAccountControl string) bool {
	if nsAccountLock == "TRUE" {
		return true
	}
	if pwdAccountLockedTime != "" {
		return true
	}
	if userAccountControl != "" {
		if v, err := strconv.ParseInt(userAccountControl, 10, 64); err == nil && v&0x2 != 0 {
			return true
		}
	}
	return false
}
