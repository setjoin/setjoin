package ldapsync

import (
	"errors"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

type fakeImmutableAttributeSearcher struct {
	request *ldap.SearchRequest
	size    uint32
	result  *ldap.SearchResult
	err     error
}

func (s *fakeImmutableAttributeSearcher) SearchWithPaging(
	request *ldap.SearchRequest,
	size uint32,
) (*ldap.SearchResult, error) {
	s.request = request
	s.size = size
	return s.result, s.err
}

func TestDiscoverImmutableAttributesBoundsQueriesAndAggregatesOnlyCounts(t *testing.T) {
	t.Parallel()
	client, err := NewClientWithTransport(
		"directory.example.test", 636, "ldaps", "cn=service",
		"secret", "dc=example,dc=test",
	)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidates := range map[string][]string{
		"empty":     nil,
		"oversized": make([]string, maxDiscoveryAttributes+1),
		"invalid":   {"entry UUID"},
		"duplicate": {"entryUUID", "entryUUID"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.discoverImmutableAttributes(
				&fakeImmutableAttributeSearcher{}, "", candidates,
			); err == nil {
				t.Fatalf("%s discovery candidates were accepted", name)
			}
		})
	}

	searcher := &fakeImmutableAttributeSearcher{
		result: &ldap.SearchResult{Entries: []*ldap.Entry{
			ldap.NewEntry("uid=one,dc=example,dc=test", map[string][]string{
				"entryUUID": {"uuid-1"}, "uidNumber": {"1001"},
			}),
			ldap.NewEntry("uid=two,dc=example,dc=test", map[string][]string{
				"entryUUID": {"uuid-2"}, "uidNumber": {"1001"},
			}),
			ldap.NewEntry("uid=three,dc=example,dc=test", map[string][]string{
				"entryUUID": {"uuid-3"},
			}),
		}},
	}
	facts, err := client.discoverImmutableAttributes(
		searcher, "", []string{"entryUUID", "uidNumber"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if searcher.request == nil ||
		searcher.request.Filter != "(objectClass=person)" ||
		searcher.request.BaseDN != "dc=example,dc=test" ||
		searcher.size != 500 {
		t.Fatalf("bounded discovery request = %+v page=%d", searcher.request, searcher.size)
	}
	if len(facts) != 2 ||
		facts[0] != (AnchorDiscovery{
			Attribute: "entryUUID", Entries: 3, Present: 3,
			Unique: 3, Duplicates: 0, Ready: true,
		}) ||
		facts[1] != (AnchorDiscovery{
			Attribute: "uidNumber", Entries: 3, Present: 2,
			Unique: 1, Duplicates: 2, Ready: false,
		}) {
		t.Fatalf("anchor discovery facts = %+v", facts)
	}

	expected := errors.New("directory unavailable")
	_, err = client.discoverImmutableAttributes(
		&fakeImmutableAttributeSearcher{err: expected},
		"(objectClass=inetOrgPerson)",
		[]string{"entryUUID"},
	)
	if !errors.Is(err, expected) ||
		!strings.Contains(err.Error(), "immutable-anchor discovery") {
		t.Fatalf("directory discovery error = %v", err)
	}
}
