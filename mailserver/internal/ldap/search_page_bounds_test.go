package ldap

import (
	"encoding/json"
	"testing"
)

// Tests for the server-wide search-size cap (er5-s15, sealed anchor
// ldap-paging-cap-bypass): BOTH client-owned size inputs — the search request's
// SizeLimit field and the RFC 2696 SimplePagedResultsControl's pageSize — must
// resolve through the same effectivePageSize cap, so no client-controlled
// field can lift the enforced maxLDAPSearchSizeLimit entries per search. The
// pre-fix handler copied the control's raw int32 pageSize into the effective
// limit, letting a single control value turn every capped search into a
// full-directory scan; the paging cookie's negative-offset leg is bounded too
// (it would otherwise reach SQL as a failing bound-OFFSET parameter).

func TestEffectivePageSize_ClampsClientInputs(t *testing.T) {
	cases := []struct {
		name      string
		requested int
		want      int
	}{
		{"at cap stays", maxLDAPSearchSizeLimit, maxLDAPSearchSizeLimit},
		{"below cap honored", 250, 250},
		{"one is honored", 1, 1},
		{"one over cap clamped", maxLDAPSearchSizeLimit + 1, maxLDAPSearchSizeLimit},
		{"attacker int32 max clamped", int(int32(^uint32(0) >> 1)), maxLDAPSearchSizeLimit},
		{"zero clamped", 0, maxLDAPSearchSizeLimit},
		{"negative clamped", -7, maxLDAPSearchSizeLimit},
		{"int32 min clamped", int(-2147483648), maxLDAPSearchSizeLimit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectivePageSize(tc.requested); got != tc.want {
				t.Fatalf("effectivePageSize(%d) = %d, want %d", tc.requested, got, tc.want)
			}
		})
	}
}

// TestEffectivePageSize_PagedControlCannotExceedSearchCap is the wire-shape
// regression for the sealed bypass: the exact int32 pageSize a hostile control
// carries (2^31-1) resolves to the server cap, not to itself.
func TestEffectivePageSize_PagedControlCannotExceedSearchCap(t *testing.T) {
	const hostilePageSize = int32(1<<31 - 1)
	if got := effectivePageSize(int(hostilePageSize)); got != maxLDAPSearchSizeLimit {
		t.Fatalf("paged control pageSize %d resolved to %d; want the %d-entry server cap",
			hostilePageSize, got, maxLDAPSearchSizeLimit)
	}
}

func TestSanitizePagingCookie_NegativeOffsetClamped(t *testing.T) {
	raw, err := json.Marshal(pagingCookie{Offset: -42, LastDN: "cn=x"})
	if err != nil {
		t.Fatal(err)
	}
	got := sanitizePagingCookie(decodeCookie(raw))
	if got.Offset != 0 {
		t.Fatalf("negative cookie offset = %d, want 0 (clamped)", got.Offset)
	}
	if got.LastDN != "cn=x" {
		t.Fatalf("LastDN must survive sanitation; got %q", got.LastDN)
	}

	// A well-formed cookie passes through untouched.
	keep := sanitizePagingCookie(pagingCookie{Offset: 300})
	if keep.Offset != 300 {
		t.Fatalf("non-negative offset rewritten: %d", keep.Offset)
	}
}
