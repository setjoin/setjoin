package ad

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"setjoin.com/mailserver/internal/ldaputil"
	"setjoin.com/mailserver/internal/tlsutil"
)

type Client struct {
	domain           string
	baseDN           string
	bindDN           string
	password         string
	serverHosts      []string
	transport        string
	subjectAttribute string
	userFilter       string
	logger           *slog.Logger
}

func NewClient(domain, bindDN, password, overrideHost string, logger *slog.Logger) (*Client, error) {
	c := &Client{
		domain: domain, bindDN: bindDN, password: password, logger: logger,
		transport: "ldaps", subjectAttribute: "objectGUID",
	}

	if overrideHost != "" {
		c.serverHosts = []string{overrideHost + ":636"}
	} else {
		hosts, err := discoverDC(domain)
		if err != nil {
			return nil, fmt.Errorf("AD discovery failed for %s: %w", domain, err)
		}
		c.serverHosts = hosts
	}

	return c, nil
}

// ClientConfig is the non-secret runtime shape of one normalized AD source.
// Password is carried separately from the declarative source document and is
// never included in errors or logs.
type ClientConfig struct {
	Host             string
	Port             int
	Transport        string
	BaseDN           string
	BindDN           string
	Password         string
	SubjectAttribute string
	UserFilter       string
}

// NewConfiguredClient builds an AD client from the normalized identity-source
// catalog. Unlike NewClient's legacy domain discovery, this path honors the
// exact endpoint, TLS mode, base DN, and operator-approved immutable anchor.
func NewConfiguredClient(cfg ClientConfig, logger *slog.Logger) (*Client, error) {
	if strings.TrimSpace(cfg.Host) == "" || cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("AD endpoint is invalid")
	}
	if strings.TrimSpace(cfg.BaseDN) == "" {
		return nil, fmt.Errorf("AD base DN is required")
	}
	if cfg.Transport != "ldaps" && cfg.Transport != "starttls" {
		return nil, fmt.Errorf("AD transport must be ldaps or starttls")
	}
	if cfg.SubjectAttribute != "objectGUID" &&
		cfg.SubjectAttribute != "msDS-ConsistencyGuid" {
		return nil, fmt.Errorf("AD immutable subject attribute is invalid")
	}
	if cfg.UserFilter != "" {
		if _, err := ldap.CompileFilter(cfg.UserFilter); err != nil {
			return nil, fmt.Errorf("AD user filter is invalid: %w", err)
		}
	}
	return &Client{
		baseDN:           cfg.BaseDN,
		bindDN:           cfg.BindDN,
		password:         cfg.Password,
		serverHosts:      []string{net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))},
		transport:        cfg.Transport,
		subjectAttribute: cfg.SubjectAttribute,
		userFilter:       cfg.UserFilter,
		logger:           logger,
	}, nil
}

func discoverDC(domain string) ([]string, error) {
	_, addrs, err := net.LookupSRV("ldap", "tcp", domain)
	if err != nil {
		return nil, fmt.Errorf("SRV lookup for _ldap._tcp.%s: %w", domain, err)
	}
	var hosts []string
	for _, a := range addrs {
		hosts = append(hosts, fmt.Sprintf("%s:636", strings.TrimSuffix(a.Target, ".")))
	}
	return hosts, nil
}

func (c *Client) connect() (*ldap.Conn, error) {
	for _, host := range c.serverHosts {
		serverName, _, splitErr := net.SplitHostPort(host)
		if splitErr != nil {
			serverName = host
		}
		tlsConfig := &tls.Config{
			ServerName:       serverName,
			MinVersion:       tls.VersionTLS12,
			CipherSuites:     tlsutil.DefaultCipherSuites,
			CurvePreferences: tlsutil.DefaultCurves,
		}
		var conn *ldap.Conn
		var err error
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		switch c.transport {
		case "ldaps":
			conn, err = ldap.DialURL(
				"ldaps://"+host,
				ldap.DialWithDialer(dialer),
				ldap.DialWithTLSConfig(tlsConfig),
			)
		case "starttls":
			conn, err = ldap.DialURL("ldap://"+host, ldap.DialWithDialer(dialer))
			if err == nil {
				err = conn.StartTLS(tlsConfig)
				if err != nil {
					_ = conn.Close()
					conn = nil
				}
			}
		default:
			err = fmt.Errorf("unsupported AD transport")
		}
		if err == nil {
			conn.SetTimeout(30 * time.Second)
			return conn, nil
		}
		c.logger.Warn("AD connection failed", "host", host, "error", err)
	}
	return nil, fmt.Errorf("all AD servers unreachable")
}

func (c *Client) Bind(conn *ldap.Conn) error {
	if _, ok := conn.TLSConnectionState(); !ok {
		return fmt.Errorf("refusing AD bind without TLS")
	}
	return conn.Bind(c.bindDN, c.password)
}

type ADUser struct {
	DN             string // entry's own distinguished name
	ObjectGUID     string
	Email          string
	DisplayName    string
	FirstName      string
	LastName       string
	SamAccountName string
	UPN            string
	Disabled       bool
	Department     string
	Title          string
	ManagerDN      string
	ManagerSubject string
	Phone          string
	ProxyAddresses []string
	USNChanged     int64
}

// maxSearchPages caps the paged search loop. It is a backstop against a
// directory that keeps returning non-empty paging cookies forever (a server
// fault would otherwise make one cycle effectively unbounded — the worker
// contract requires every worker to exit on context cancellation, and the
// per-page ctx checks below are what honor cancellation between pages).
const maxSearchPages = 1000

func (c *Client) SearchUsers(ctx context.Context, conn *ldap.Conn, cursor int64) ([]ADUser, int64, error) {
	req := c.userSearchRequest(cursor)

	var users []ADUser
	var maxUSN int64

	for page := 0; ; page++ {
		// go-ldap's Search is not ctx-aware; these checks are what let an
		// in-flight cycle observe cancellation between pages (and the dialer
		// timeout bounds each page's round trip).
		if err := ctx.Err(); err != nil {
			return nil, 0, fmt.Errorf("AD search canceled after %d pages: %w", page, err)
		}
		if page >= maxSearchPages {
			return nil, 0, fmt.Errorf("AD search exceeded %d pages (paging cookie never emptied)", maxSearchPages)
		}
		res, err := conn.Search(req)
		if err != nil {
			return nil, 0, fmt.Errorf("AD search: %w", err)
		}

		for _, entry := range res.Entries {
			u, include, err := c.userFromEntry(entry)
			if err != nil {
				return nil, 0, err
			}
			if !include {
				continue
			}
			if u.USNChanged > maxUSN {
				maxUSN = u.USNChanged
			}
			users = append(users, u)
		}

		// Check for more pages
		var hasMore bool
		for _, ctrl := range res.Controls {
			if p, ok := ctrl.(*ldap.ControlPaging); ok {
				if len(p.Cookie) == 0 {
					hasMore = false
				} else {
					hasMore = true
					pc := ldap.NewControlPaging(500)
					pc.SetCookie(p.Cookie)
					req.Controls[0] = pc
				}
			}
		}
		if !hasMore {
			break
		}
	}

	if err := c.resolveManagerSubjects(ctx, conn, users); err != nil {
		return nil, 0, err
	}
	return users, maxUSN, nil
}

func (c *Client) userSearchRequest(cursor int64) *ldap.SearchRequest {
	baseFilter := c.userFilter
	if baseFilter == "" {
		baseFilter = "(&(objectClass=user)(objectCategory=person))"
	}
	filter := fmt.Sprintf("(&%s(uSNChanged>=%d))", baseFilter, cursor)
	attrs := []string{c.subjectAttribute, "mail", "displayName", "givenName", "sn",
		"sAMAccountName", "userPrincipalName", "userAccountControl",
		"department", "title", "manager", "telephoneNumber",
		"proxyAddresses", "uSNChanged"}

	return ldap.NewSearchRequest(
		c.searchBaseDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		filter, attrs, []ldap.Control{ldap.NewControlPaging(500)},
	)
}

func (c *Client) userFromEntry(entry *ldap.Entry) (ADUser, bool, error) {
	u := ADUser{
		DN:             entry.DN,
		ObjectGUID:     c.immutableSubject(entry),
		Email:          entry.GetAttributeValue("mail"),
		DisplayName:    entry.GetAttributeValue("displayName"),
		FirstName:      entry.GetAttributeValue("givenName"),
		LastName:       entry.GetAttributeValue("sn"),
		SamAccountName: entry.GetAttributeValue("sAMAccountName"),
		UPN:            entry.GetAttributeValue("userPrincipalName"),
		Department:     entry.GetAttributeValue("department"),
		Title:          entry.GetAttributeValue("title"),
		ManagerDN:      entry.GetAttributeValue("manager"),
		Phone:          entry.GetAttributeValue("telephoneNumber"),
		ProxyAddresses: entry.GetAttributeValues("proxyAddresses"),
	}
	if uac := entry.GetAttributeValue("userAccountControl"); uac != "" {
		var value int
		if _, err := fmt.Sscanf(uac, "%d", &value); err != nil {
			return ADUser{}, false, fmt.Errorf("AD: invalid userAccountControl %q: %w", uac, err)
		}
		u.Disabled = value&2 != 0
	}
	if usn := entry.GetAttributeValue("uSNChanged"); usn != "" {
		if _, err := fmt.Sscanf(usn, "%d", &u.USNChanged); err != nil {
			return ADUser{}, false, nil
		}
	}
	return u, true, nil
}

const managerLookupChunkSize = 100

// resolveManagerSubjects converts manager DNs to the same immutable anchor
// used by provision links. Delta searches often omit an unchanged manager, so
// a page-local DN map is not authoritative enough for an authorization
// relationship.
func (c *Client) resolveManagerSubjects(ctx context.Context, conn *ldap.Conn, users []ADUser) error {
	subjectByDN, missing := knownManagerSubjects(users)

	for start := 0; start < len(missing); start += managerLookupChunkSize {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("AD manager anchor lookup canceled: %w", err)
		}
		end := min(start+managerLookupChunkSize, len(missing))
		res, err := conn.Search(c.managerSearchRequest(missing[start:end]))
		if err != nil {
			return fmt.Errorf("AD manager anchor lookup: %w", err)
		}
		for _, entry := range res.Entries {
			if subject := c.immutableSubject(entry); subject != "" {
				subjectByDN[ldaputil.NormalizeDN(entry.DN)] = subject
			}
		}
	}
	applyManagerSubjects(users, subjectByDN)
	return nil
}

func knownManagerSubjects(users []ADUser) (map[string]string, []string) {
	subjectByDN := make(map[string]string, len(users))
	for i := range users {
		if users[i].DN != "" && users[i].ObjectGUID != "" {
			subjectByDN[ldaputil.NormalizeDN(users[i].DN)] = users[i].ObjectGUID
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
		c.searchBaseDN(),
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false,
		"(|"+strings.Join(parts, "")+")",
		[]string{c.subjectAttribute},
		nil,
	)
}

func applyManagerSubjects(users []ADUser, subjectByDN map[string]string) {
	for i := range users {
		if users[i].ManagerSubject == "" {
			users[i].ManagerSubject = subjectByDN[ldaputil.NormalizeDN(users[i].ManagerDN)]
		}
	}
}

func (c *Client) searchBaseDN() string {
	if c.baseDN != "" {
		return c.baseDN
	}
	return ldaputil.DomainToBaseDN(c.domain)
}

func (c *Client) immutableSubject(entry *ldap.Entry) string {
	raw := entry.GetRawAttributeValue(c.subjectAttribute)
	switch c.subjectAttribute {
	case "objectGUID":
		return guidToString(raw)
	case "msDS-ConsistencyGuid":
		if len(raw) == 0 {
			return ""
		}
		return base64.StdEncoding.EncodeToString(raw)
	default:
		return ""
	}
}

func guidToString(guid []byte) string {
	if len(guid) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		int(guid[3])<<24|int(guid[2])<<16|int(guid[1])<<8|int(guid[0]),
		int(guid[5])<<8|int(guid[4]),
		int(guid[7])<<8|int(guid[6]),
		guid[8:10],
		guid[10:16])
}
