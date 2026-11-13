package ldapsync

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"setjoin.com/mailserver/internal/ldaputil"
)

// TestEntryDisabled covers disabled-user detection across all four advertised
// directory types. Regression: detection previously honored only nsAccountLock
// (FreeIPA / 389 DS), so a user disabled in OpenLDAP (pwdAccountLockedTime) or
// Samba/AD (userAccountControl ACCOUNTDISABLE bit) was never deprovisioned.
func TestEntryDisabled(t *testing.T) {
	tests := []struct {
		name            string
		nsLock, ppolicy string
		uac             string
		want            bool
	}{
		{"active: all empty", "", "", "", false},
		{"freeipa locked", "TRUE", "", "", true},
		{"freeipa active (FALSE)", "FALSE", "", "", false},
		{"openldap ppolicy locked", "", "000001010000Z", "", true},
		{"openldap ppolicy any value", "", "20240101000000Z", "", true},
		{"samba/ad disabled (0x2 set)", "", "", "514", true}, // 0x202
		{"samba/ad normal account (0x2 clear)", "", "", "512", false},
		{"samba/ad disabled + other bits", "", "", "66050", true}, // 0x10202
		{"samba/ad non-numeric uac ignored", "", "", "garbage", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := entryDisabled(tc.nsLock, tc.ppolicy, tc.uac); got != tc.want {
				t.Errorf("entryDisabled(%q,%q,%q) = %v, want %v",
					tc.nsLock, tc.ppolicy, tc.uac, got, tc.want)
			}
		})
	}
}

func TestBuildLDAPSyncAttrs(t *testing.T) {
	u := LDAPUser{
		Email:       "test@corp.local",
		DisplayName: "Test User",
		FirstName:   "Test",
		LastName:    "User",
		Title:       "Engineer",
		Phone:       "1234",
		UPN:         "test@corp.local",
	}

	attrs := buildLDAPSyncAttrs(u)
	if attrs["email"] != u.Email {
		t.Errorf("email = %q, want %q", attrs["email"], u.Email)
	}
	if _, ok := attrs["department"]; ok {
		t.Error("attrs must not contain 'department' column (use department_id via FK)")
	}
	if attrs["job_title"] != u.Title {
		t.Errorf("job_title = %q, want %q", attrs["job_title"], u.Title)
	}
}

func TestSubjectAttributeFailClosedAndValidated(t *testing.T) {
	t.Parallel()
	client := NewClient("ldap.example.test", 636, true, "", "", "dc=example,dc=test")
	if client.SubjectAttribute() != "" {
		t.Fatal("LDAP must not infer DN or mail as an immutable subject")
	}
	for _, bad := range []string{"entry UUID", "mail)", "1uuid", "x/y", "x\nuid"} {
		if err := client.SetSubjectAttribute(bad); err == nil {
			t.Errorf("accepted invalid attribute %q", bad)
		}
	}
	if err := client.SetSubjectAttribute("entryUUID"); err != nil {
		t.Fatalf("entryUUID: %v", err)
	}
	if client.SubjectAttribute() != "entryUUID" {
		t.Fatalf("subject attribute = %q", client.SubjectAttribute())
	}
}

func TestNewClientWithTransportHasExactModes(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"ldaps", "starttls"} {
		t.Run(mode, func(t *testing.T) {
			client, err := NewClientWithTransport(
				"ldap.example.test", 389, mode, "cn=sync", "secret", "dc=example,dc=test",
			)
			if err != nil {
				t.Fatalf("NewClientWithTransport(%s): %v", mode, err)
			}
			if client.transport != mode {
				t.Fatalf("transport = %q, want %q", client.transport, mode)
			}
		})
	}
	for name, tc := range map[string]struct {
		host   string
		port   int
		mode   string
		baseDN string
	}{
		"host":      {"", 389, "starttls", "dc=example,dc=test"},
		"port":      {"ldap.example.test", 0, "starttls", "dc=example,dc=test"},
		"mode":      {"ldap.example.test", 389, "auto", "dc=example,dc=test"},
		"plaintext": {"ldap.example.test", 389, "none", "dc=example,dc=test"},
		"base":      {"ldap.example.test", 389, "starttls", ""},
	} {
		t.Run("reject "+name, func(t *testing.T) {
			if _, err := NewClientWithTransport(
				tc.host, tc.port, tc.mode, "", "secret", tc.baseDN,
			); err == nil {
				t.Fatal("invalid normalized LDAP runtime config was accepted")
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
		t.Fatal("plaintext LDAP bind was accepted")
	}
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	var one [1]byte
	if _, err := peer.Read(one[:]); err == nil {
		t.Fatal("LDAP bind wrote credential bytes before TLS")
	}
}

func TestSyncWorkerSetFilterValidatesLDAPSyntax(t *testing.T) {
	t.Parallel()
	worker := &SyncWorker{}
	if err := worker.SetFilter("(objectClass=inetOrgPerson)"); err != nil {
		t.Fatalf("valid LDAP filter rejected: %v", err)
	}
	if worker.filter != "(objectClass=inetOrgPerson)" {
		t.Fatalf("filter = %q", worker.filter)
	}
	if err := worker.SetFilter(")(objectClass=*"); err == nil {
		t.Fatal("invalid LDAP filter was accepted")
	}
	if worker.filter != "(objectClass=inetOrgPerson)" {
		t.Fatal("invalid filter replaced the last valid runtime filter")
	}
}

func TestResolveManagerSubjectsUsesImmutableAnchorFromSameBatch(t *testing.T) {
	withoutAnchor := &Client{}
	if err := withoutAnchor.resolveManagerSubjects(nil, []LDAPUser{{
		DN: "uid=user,dc=example,dc=test",
	}}); err != nil {
		t.Fatal(err)
	}

	client := &Client{subjectAttribute: "entryUUID"}
	users := []LDAPUser{
		{
			DN:               "uid=manager,ou=people,dc=example,dc=test",
			ImmutableSubject: "manager-anchor",
		},
		{
			DN:               "uid=report,ou=people,dc=example,dc=test",
			ManagerDN:        " UID=MANAGER,OU=PEOPLE,DC=EXAMPLE,DC=TEST ",
			ImmutableSubject: "report-anchor",
		},
		{
			DN:               "uid=independent,ou=people,dc=example,dc=test",
			ImmutableSubject: "independent-anchor",
		},
	}
	if err := client.resolveManagerSubjects(nil, users); err != nil {
		t.Fatal(err)
	}
	if users[1].ManagerSubject != "manager-anchor" {
		t.Fatalf("manager subject=%q, want batch anchor", users[1].ManagerSubject)
	}
	if users[2].ManagerSubject != "" {
		t.Fatalf("managerless user resolved subject %q", users[2].ManagerSubject)
	}
}

func TestConnectRejectsUnsupportedRuntimeTransport(t *testing.T) {
	client := &Client{
		host: "ldap.example.test", port: 389, transport: "unsupported",
	}
	if _, err := client.Connect(); err == nil {
		t.Fatal("unsupported LDAP runtime transport unexpectedly connected")
	}
}

func TestUserFromEntryMapsAllConfiguredAttributes(t *testing.T) {
	client := &Client{subjectAttribute: "entryUUID"}
	entry := &ldap.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "entryUUID", Values: []string{"immutable-alice"}},
			{Name: "manager", Values: []string{"uid=manager,dc=example,dc=test"}},
			{Name: "mail", Values: []string{"alice@example.test"}},
			{Name: "displayName", Values: []string{"Alice Example"}},
			{Name: "givenName", Values: []string{"Alice"}},
			{Name: "sn", Values: []string{"Example"}},
			{Name: "title", Values: []string{"Engineer"}},
			{Name: "telephoneNumber", Values: []string{"100"}},
			{Name: "department", Values: []string{"Platform"}},
			{Name: "userPrincipalName", Values: []string{"alice@example.test"}},
			{Name: "modifyTimestamp", Values: []string{"20260728010000Z"}},
			{Name: "pwdAccountLockedTime", Values: []string{"000001010000Z"}},
		},
	}
	got := client.userFromEntry(entry)
	if got.DN != entry.DN || got.ImmutableSubject != "immutable-alice" ||
		got.ManagerDN == "" || got.Email != "alice@example.test" ||
		got.DisplayName != "Alice Example" || got.FirstName != "Alice" ||
		got.LastName != "Example" || got.Title != "Engineer" ||
		got.Phone != "100" || got.Department != "Platform" ||
		got.UPN != "alice@example.test" || got.ModifyStamp != "20260728010000Z" ||
		!got.Disabled {
		t.Fatalf("mapped LDAP user=%+v", got)
	}
}

func TestDirectorySearchRequestsUseSafeDefaultsAndConfiguredAnchor(t *testing.T) {
	t.Parallel()

	client := &Client{
		baseDN:           "ou=people,dc=example,dc=test",
		subjectAttribute: "entryUUID",
	}
	req, pageSize := client.userSearchRequest("", 0)
	if req.BaseDN != client.baseDN || req.Filter != "(objectClass=person)" ||
		pageSize != 500 || !slices.Contains(req.Attributes, "entryUUID") ||
		!slices.Contains(req.Attributes, "manager") {
		t.Fatalf("default LDAP user search request=%+v pageSize=%d", req, pageSize)
	}
	customReq, customPageSize := client.userSearchRequest("(uid=alice)", 25)
	if customReq.Filter != "(uid=alice)" || customPageSize != 25 {
		t.Fatalf("custom LDAP user search request=%+v pageSize=%d", customReq, customPageSize)
	}

	managerReq := client.managerSearchRequest([]string{
		"uid=boss*(primary),ou=people,dc=example,dc=test",
	})
	if managerReq.BaseDN != client.baseDN ||
		!strings.Contains(managerReq.Filter, `boss\2a\28primary\29`) ||
		!slices.Equal(managerReq.Attributes, []string{"entryUUID"}) {
		t.Fatalf("LDAP manager search request=%+v", managerReq)
	}
}

func TestKnownManagerSubjectsDeduplicatesRemoteLookupsAndAppliesResults(t *testing.T) {
	t.Parallel()

	users := []LDAPUser{
		{DN: "uid=local,dc=example,dc=test", ImmutableSubject: "local-anchor"},
		{ManagerDN: " UID=LOCAL,DC=EXAMPLE,DC=TEST "},
		{ManagerDN: "uid=remote,dc=example,dc=test"},
		{ManagerDN: "UID=REMOTE,DC=EXAMPLE,DC=TEST"},
		{},
	}
	subjects, missing := knownManagerSubjects(users)
	if users[1].ManagerSubject != "local-anchor" {
		t.Fatalf("same-batch manager=%q", users[1].ManagerSubject)
	}
	if len(missing) != 1 || ldaputil.NormalizeDN(missing[0]) != "uid=remote,dc=example,dc=test" {
		t.Fatalf("remote manager lookups=%v", missing)
	}
	subjects["uid=remote,dc=example,dc=test"] = "remote-anchor"
	applyManagerSubjects(users, subjects)
	if users[2].ManagerSubject != "remote-anchor" || users[3].ManagerSubject != "remote-anchor" {
		t.Fatalf("resolved remote managers=%+v", users)
	}
}
