package ldapsync

import (
	"fmt"

	ldap "github.com/go-ldap/ldap/v3"
)

const maxDiscoveryAttributes = 16

type AnchorDiscovery struct {
	Attribute  string `json:"attribute"`
	Entries    int    `json:"entries"`
	Present    int    `json:"present"`
	Unique     int    `json:"unique"`
	Duplicates int    `json:"duplicates"`
	Ready      bool   `json:"ready"`
}

type immutableAttributeSearcher interface {
	SearchWithPaging(*ldap.SearchRequest, uint32) (*ldap.SearchResult, error)
}

// DiscoverImmutableAttributes reads only operator-supplied attribute names and
// returns aggregate uniqueness evidence. Raw subjects never leave this method.
// An attribute is ready only when every matching entry has one nonempty unique
// value.
func (c *Client) DiscoverImmutableAttributes(conn *ldap.Conn, filter string, candidates []string) ([]AnchorDiscovery, error) {
	return c.discoverImmutableAttributes(conn, filter, candidates)
}

func (c *Client) discoverImmutableAttributes(
	searcher immutableAttributeSearcher,
	filter string,
	candidates []string,
) ([]AnchorDiscovery, error) {
	if len(candidates) == 0 || len(candidates) > maxDiscoveryAttributes {
		return nil, fmt.Errorf("LDAP anchor discovery requires 1..%d attributes", maxDiscoveryAttributes)
	}
	seenNames := make(map[string]struct{}, len(candidates))
	for _, attribute := range candidates {
		if !ldapAttributeName.MatchString(attribute) {
			return nil, fmt.Errorf("invalid LDAP subject attribute %q", attribute)
		}
		if _, duplicate := seenNames[attribute]; duplicate {
			return nil, fmt.Errorf("duplicate LDAP subject attribute %q", attribute)
		}
		seenNames[attribute] = struct{}{}
	}
	if filter == "" {
		filter = "(objectClass=person)"
	}
	req := ldap.NewSearchRequest(
		c.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, candidates, nil,
	)
	result, err := searcher.SearchWithPaging(req, 500)
	if err != nil {
		return nil, fmt.Errorf("LDAP immutable-anchor discovery: %w", err)
	}

	out := make([]AnchorDiscovery, 0, len(candidates))
	for _, attribute := range candidates {
		fact := AnchorDiscovery{Attribute: attribute, Entries: len(result.Entries)}
		values := make(map[string]int, len(result.Entries))
		for _, entry := range result.Entries {
			value := entry.GetAttributeValue(attribute)
			if value == "" {
				continue
			}
			fact.Present++
			values[value]++
		}
		fact.Unique = len(values)
		for _, count := range values {
			if count > 1 {
				fact.Duplicates += count
			}
		}
		fact.Ready = fact.Entries > 0 &&
			fact.Present == fact.Entries &&
			fact.Unique == fact.Entries &&
			fact.Duplicates == 0
		out = append(out, fact)
	}
	return out, nil
}
