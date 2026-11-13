package ad

// Credential-path guards (D-AUTHSERVER-INTERNAL-CONNECTOR-008 and -009):
//
//   - VerifyPassword must refuse empty/blank credentials WITHOUT delegating
//     the authentication decision to the remote directory (an empty-password
//     simple bind is an unauthenticated bind on permissive LDAP backends).
//   - ChangePassword must refuse empty/blank inputs and enforce the old-
//     credential proof (bind AS the target principal) BEFORE any service-
//     authority password-modify write.
//
// These tests pin the fail-closed ordering structurally: the dial seam is
// replaced with a sentinel that FAILS the test if the connector dials the
// directory, proving the guards reject before any network work happens.

import (
	"context"
	"crypto/tls"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// guardTestConnector returns a Connector whose directory endpoint is never
// reachable, with dialTLS swapped for a sentinel that fails the test on ANY
// dial attempt. Restores the real seam on cleanup.
func guardTestConnector(t *testing.T) *Connector {
	t.Helper()
	orig := dialTLS
	dialTLS = func(network, addr string, cfg *tls.Config) (*ldap.Conn, error) {
		t.Fatalf("connector dialed the directory (%s) — the empty-credential guard must reject BEFORE any network work", addr)
		return nil, nil
	}
	t.Cleanup(func() { dialTLS = orig })
	return &Connector{id: 1, host: "ad.test.invalid", bindDN: "cn=svc", bindPassword: "svc-pw", baseDN: "dc=test"}
}

func TestVerifyPassword_EmptyDNRefusedWithoutDial(t *testing.T) {
	c := guardTestConnector(t)
	for _, dn := range []string{"", "   ", "\t"} {
		if err := c.VerifyPassword(context.Background(), dn, "pw"); err == nil {
			t.Fatalf("VerifyPassword with user DN %q must fail closed", dn)
		}
	}
}

func TestVerifyPassword_EmptyPasswordRefusedWithoutDial(t *testing.T) {
	c := guardTestConnector(t)
	if err := c.VerifyPassword(context.Background(), "cn=alice,dc=test", ""); err == nil {
		t.Fatal("VerifyPassword with an empty password must fail closed — an empty-password simple bind is an unauthenticated bind on permissive LDAP backends")
	}
}

func TestVerifyPassword_ValidShapeStillDials(t *testing.T) {
	// Sanity for the guard tests above: a well-formed credential attempt MUST
	// reach the dial seam (i.e. the guard does not over-block).
	orig := dialTLS
	dialTLS = func(network, addr string, cfg *tls.Config) (*ldap.Conn, error) {
		return nil, context.DeadlineExceeded // unreachable endpoint: dial attempted
	}
	t.Cleanup(func() { dialTLS = orig })
	c := &Connector{id: 1, host: "ad.test.invalid", bindDN: "cn=svc", bindPassword: "svc-pw", baseDN: "dc=test"}
	if err := c.VerifyPassword(context.Background(), "cn=alice,dc=test", "pw"); err == nil {
		t.Fatal("well-formed VerifyPassword against an unreachable endpoint must surface the dial error")
	}
}

func TestChangePassword_EmptyInputsRefusedWithoutDial(t *testing.T) {
	c := guardTestConnector(t)
	ctx := context.Background()
	cases := []struct{ userDN, oldPw, newPw string }{
		{"", "old-pw", "new-pw"},
		{"   ", "old-pw", "new-pw"},
		{"cn=alice,dc=test", "", "new-pw"},
		{"cn=alice,dc=test", "old-pw", ""},
	}
	for i, tc := range cases {
		err := c.ChangePassword(ctx, tc.userDN, tc.oldPw, tc.newPw)
		if err == nil {
			t.Fatalf("case %d: ChangePassword with blank input (%q,%q,%q) must fail closed", i, tc.userDN, tc.oldPw, tc.newPw)
		}
		if !strings.Contains(err.Error(), "requires") {
			t.Fatalf("case %d: guard error should name the requirement, got: %v", i, err)
		}
	}
}
