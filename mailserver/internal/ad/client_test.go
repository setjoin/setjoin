package ad

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"setjoin.com/mailserver/internal/ldaputil"
)

func TestGuidToString(t *testing.T) {
	tests := []struct {
		name     string
		guid     []byte
		expected string
	}{
		{
			name:     "valid 16-byte GUID",
			guid:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
			expected: "04030201-0605-0807-090a-0b0c0d0e0f10",
		},
		{
			name:     "empty GUID",
			guid:     []byte{},
			expected: "",
		},
		{
			name:     "short GUID",
			guid:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: "",
		},
		{
			name:     "long GUID",
			guid:     []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := guidToString(tt.guid)
			if got != tt.expected {
				t.Errorf("guidToString() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestBindRefusesPlaintextConnectionBeforeCredentials(t *testing.T) {
	t.Parallel()
	server, peer := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = peer.Close()
	})
	conn := ldap.NewConn(server, false)
	client := &Client{bindDN: "cn=sync", password: "must-not-leak"}
	if err := client.Bind(conn); err == nil {
		t.Fatal("plaintext AD bind was accepted")
	}
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var one [1]byte
	if _, err := peer.Read(one[:]); err == nil {
		t.Fatal("AD bind wrote credential bytes before TLS")
	}
}

func TestADUserDisabled(t *testing.T) {
	// userAccountControl & 2 != 0 means disabled
	u := ADUser{Disabled: true}
	if !u.Disabled {
		t.Error("expected user to be disabled")
	}

	u2 := ADUser{Disabled: false}
	if u2.Disabled {
		t.Error("expected user to be enabled")
	}
}

func TestNewConfiguredClientHonorsEndpointBaseAndImmutableAnchor(t *testing.T) {
	t.Parallel()
	client, err := NewConfiguredClient(ClientConfig{
		Host:             "dc.example.test",
		Port:             389,
		Transport:        "starttls",
		BaseDN:           "OU=People,DC=example,DC=test",
		BindDN:           "CN=Sync,DC=example,DC=test",
		Password:         "secret",
		SubjectAttribute: "msDS-ConsistencyGuid",
		UserFilter:       "(objectClass=user)",
	}, nil)
	if err != nil {
		t.Fatalf("NewConfiguredClient: %v", err)
	}
	if got := client.searchBaseDN(); got != "OU=People,DC=example,DC=test" {
		t.Fatalf("search base = %q", got)
	}
	if client.transport != "starttls" || client.serverHosts[0] != "dc.example.test:389" {
		t.Fatalf("configured endpoint not retained: transport=%q host=%q",
			client.transport, client.serverHosts[0])
	}

	raw := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	entry := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name: "msDS-ConsistencyGuid", ByteValues: [][]byte{raw},
	}}}
	if got, want := client.immutableSubject(entry), base64.StdEncoding.EncodeToString(raw); got != want {
		t.Fatalf("consistency GUID = %q, want %q", got, want)
	}
}

func TestNewConfiguredClientRejectsUnsafeRuntimeShape(t *testing.T) {
	t.Parallel()
	valid := ClientConfig{
		Host: "dc.example.test", Port: 636, Transport: "ldaps",
		BaseDN: "DC=example,DC=test", SubjectAttribute: "objectGUID",
	}
	for name, mutate := range map[string]func(*ClientConfig){
		"transport": func(c *ClientConfig) { c.Transport = "auto" },
		"plaintext": func(c *ClientConfig) { c.Transport = "none" },
		"subject":   func(c *ClientConfig) { c.SubjectAttribute = "mail" },
		"filter":    func(c *ClientConfig) { c.UserFilter = ")(objectClass=*" },
		"port":      func(c *ClientConfig) { c.Port = 0 },
		"base":      func(c *ClientConfig) { c.BaseDN = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			if _, err := NewConfiguredClient(cfg, nil); err == nil {
				t.Fatal("invalid normalized AD runtime config was accepted")
			}
		})
	}
}

func TestResolveManagerSubjectsUsesImmutableAnchorFromSameBatch(t *testing.T) {
	client := &Client{subjectAttribute: "objectGUID"}
	users := []ADUser{
		{
			DN:         "CN=Manager,OU=People,DC=example,DC=test",
			ObjectGUID: "manager-anchor",
		},
		{
			DN:         "CN=Report,OU=People,DC=example,DC=test",
			ObjectGUID: "report-anchor",
			ManagerDN:  " cn=manager,ou=people,dc=example,dc=test ",
		},
		{
			DN:         "CN=No Manager,OU=People,DC=example,DC=test",
			ObjectGUID: "independent-anchor",
		},
	}
	if err := client.resolveManagerSubjects(context.Background(), nil, users); err != nil {
		t.Fatal(err)
	}
	if users[1].ManagerSubject != "manager-anchor" {
		t.Fatalf("manager subject=%q, want batch anchor", users[1].ManagerSubject)
	}
	if users[2].ManagerSubject != "" {
		t.Fatalf("managerless user resolved subject %q", users[2].ManagerSubject)
	}
}

func TestImmutableSubjectModesAndUnsupportedConnect(t *testing.T) {
	objectGUID := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name: "objectGUID",
		ByteValues: [][]byte{{
			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		}},
	}}}
	if got := (&Client{subjectAttribute: "objectGUID"}).immutableSubject(objectGUID); got == "" {
		t.Fatal("objectGUID anchor was not decoded")
	}
	if got := (&Client{subjectAttribute: "msDS-ConsistencyGuid"}).immutableSubject(&ldap.Entry{}); got != "" {
		t.Fatalf("empty consistency GUID=%q, want empty", got)
	}
	if got := (&Client{subjectAttribute: "mail"}).immutableSubject(objectGUID); got != "" {
		t.Fatalf("unsupported anchor mode=%q, want empty", got)
	}

	client := &Client{
		serverHosts: []string{"host-without-port"},
		transport:   "unsupported",
		logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if _, err := client.connect(); err == nil {
		t.Fatal("unsupported AD transport unexpectedly connected")
	}
}

func TestUserFromEntryMapsDirectoryFieldsAndRejectsMalformedControls(t *testing.T) {
	client := &Client{subjectAttribute: "objectGUID"}
	entry := &ldap.Entry{
		DN: "CN=Alice,OU=People,DC=example,DC=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "objectGUID", ByteValues: [][]byte{{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			}}},
			{Name: "mail", Values: []string{"alice@example.test"}},
			{Name: "displayName", Values: []string{"Alice Example"}},
			{Name: "givenName", Values: []string{"Alice"}},
			{Name: "sn", Values: []string{"Example"}},
			{Name: "sAMAccountName", Values: []string{"alice"}},
			{Name: "userPrincipalName", Values: []string{"alice@example.test"}},
			{Name: "department", Values: []string{"Platform"}},
			{Name: "title", Values: []string{"Engineer"}},
			{Name: "manager", Values: []string{"CN=Manager,DC=example,DC=test"}},
			{Name: "telephoneNumber", Values: []string{"100"}},
			{Name: "proxyAddresses", Values: []string{"smtp:alias@example.test"}},
			{Name: "userAccountControl", Values: []string{"514"}},
			{Name: "uSNChanged", Values: []string{"1234"}},
		},
	}
	got, include, err := client.userFromEntry(entry)
	if err != nil || !include {
		t.Fatalf("userFromEntry include=%v err=%v", include, err)
	}
	if got.ObjectGUID == "" || got.Email != "alice@example.test" ||
		got.DisplayName != "Alice Example" || got.FirstName != "Alice" ||
		got.LastName != "Example" || got.SamAccountName != "alice" ||
		got.UPN != "alice@example.test" || got.Department != "Platform" ||
		got.Title != "Engineer" || got.ManagerDN == "" || got.Phone != "100" ||
		len(got.ProxyAddresses) != 1 || !got.Disabled || got.USNChanged != 1234 {
		t.Fatalf("mapped AD user=%+v", got)
	}

	badUAC := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name: "userAccountControl", Values: []string{"not-a-number"},
	}}}
	if _, _, err := client.userFromEntry(badUAC); err == nil {
		t.Fatal("malformed userAccountControl was accepted")
	}
	badUSN := &ldap.Entry{Attributes: []*ldap.EntryAttribute{{
		Name: "uSNChanged", Values: []string{"not-a-number"},
	}}}
	if _, include, err := client.userFromEntry(badUSN); err != nil || include {
		t.Fatalf("malformed uSNChanged include=%v err=%v", include, err)
	}
}

func TestDirectorySearchRequestsPreserveAnchorScopeAndEscapeManagerDNs(t *testing.T) {
	t.Parallel()

	client := &Client{
		domain:           "example.test",
		subjectAttribute: "objectGUID",
		userFilter:       "(employeeType=staff)",
	}
	req := client.userSearchRequest(42)
	if req.BaseDN != "DC=example,DC=test" ||
		req.Filter != "(&(employeeType=staff)(uSNChanged>=42))" ||
		!slices.Contains(req.Attributes, "objectGUID") ||
		len(req.Controls) != 1 {
		t.Fatalf("AD user search request=%+v", req)
	}

	defaultReq := (&Client{
		baseDN:           "OU=People,DC=example,DC=test",
		subjectAttribute: "msDS-ConsistencyGuid",
	}).userSearchRequest(0)
	if defaultReq.BaseDN != "OU=People,DC=example,DC=test" ||
		!strings.Contains(defaultReq.Filter, "(objectClass=user)") ||
		!slices.Contains(defaultReq.Attributes, "msDS-ConsistencyGuid") {
		t.Fatalf("default AD user search request=%+v", defaultReq)
	}

	managerReq := client.managerSearchRequest([]string{
		"CN=Boss*(Primary),OU=People,DC=example,DC=test",
	})
	if managerReq.BaseDN != "DC=example,DC=test" ||
		!strings.Contains(managerReq.Filter, `Boss\2a\28Primary\29`) ||
		!slices.Equal(managerReq.Attributes, []string{"objectGUID"}) {
		t.Fatalf("AD manager search request=%+v", managerReq)
	}
}

func TestKnownManagerSubjectsDeduplicatesRemoteLookupsAndAppliesResults(t *testing.T) {
	t.Parallel()

	users := []ADUser{
		{DN: "CN=Local,DC=example,DC=test", ObjectGUID: "local-anchor"},
		{ManagerDN: " cn=local,dc=example,dc=test "},
		{ManagerDN: "CN=Remote,DC=example,DC=test"},
		{ManagerDN: "cn=remote,dc=example,dc=test"},
		{},
	}
	subjects, missing := knownManagerSubjects(users)
	if users[1].ManagerSubject != "local-anchor" {
		t.Fatalf("same-batch manager=%q", users[1].ManagerSubject)
	}
	if len(missing) != 1 || ldaputil.NormalizeDN(missing[0]) != "cn=remote,dc=example,dc=test" {
		t.Fatalf("remote manager lookups=%v", missing)
	}
	subjects["cn=remote,dc=example,dc=test"] = "remote-anchor"
	applyManagerSubjects(users, subjects)
	if users[2].ManagerSubject != "remote-anchor" || users[3].ManagerSubject != "remote-anchor" {
		t.Fatalf("resolved remote managers=%+v", users)
	}
}
