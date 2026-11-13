package ldapsync

// L2-C3 (r2-C3-2): the real LDAP map builder pinned to the writer's accepted
// input keys — builder drift fails this test instead of the writer erroring on
// live traffic (or silently accepting a new key). buildLDAPSyncAttrs delegates
// to ldaputil.SyncAttrs, so this also pins SyncAttrs on the LDAP side.

import (
	"testing"

	"setjoin.com/mailserver/internal/ldaputil"
)

func TestBuildLDAPSyncAttrsKeysWithinWriterAllowlist(t *testing.T) {
	u := LDAPUser{
		Email:       "u@corp.example",
		DisplayName: "U",
		FirstName:   "F",
		LastName:    "L",
		Title:       "T",
		Phone:       "P",
		UPN:         "u@CORP.EXAMPLE",
	}
	attrs := buildLDAPSyncAttrs(u)
	accepted := ldaputil.AcceptedSyncAttrsKeys()
	if len(attrs) != len(accepted) {
		t.Errorf("buildLDAPSyncAttrs produced %d keys, want the fixed table of %d", len(attrs), len(accepted))
	}
	for k := range attrs {
		if !accepted[k] {
			t.Errorf("buildLDAPSyncAttrs key %q is outside the writer's accepted input keys", k)
		}
	}
	for k := range accepted {
		if _, ok := attrs[k]; !ok {
			t.Errorf("buildLDAPSyncAttrs dropped accepted input key %q", k)
		}
	}
}
