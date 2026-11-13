package smtp

import (
	"testing"
)

func TestTLSPolicy_EnforceListMatch(t *testing.T) {
	enforce := []string{"fda.gov", "bank.gov", "partner.com"}
	skip := []string{}
	global := false

	require, skipTLS := resolveTLSPolicy("fda.gov", enforce, skip, global)
	if !require {
		t.Error("fda.gov in enforce list: requireTLS should be true")
	}
	if skipTLS {
		t.Error("fda.gov in enforce list: skipTLS should be false")
	}
}

func TestTLSPolicy_SkipListMatch(t *testing.T) {
	enforce := []string{}
	skip := []string{"old-server.local", "legacy.example.com"}
	global := false

	require, skipTLS := resolveTLSPolicy("old-server.local", enforce, skip, global)
	if require {
		t.Error("old-server.local in skip list: requireTLS should be false")
	}
	if !skipTLS {
		t.Error("old-server.local in skip list: skipTLS should be true")
	}
}

func TestTLSPolicy_DefaultOpportunistic(t *testing.T) {
	_, skipTLS := resolveTLSPolicy("example.com", nil, nil, false)
	if skipTLS {
		t.Error("default: skipTLS should be false (opportunistic)")
	}
	// requireTLS should also be false by default
	require, _ := resolveTLSPolicy("example.com", nil, nil, false)
	if require {
		t.Error("default: requireTLS should be false (opportunistic)")
	}
}

func TestTLSPolicy_GlobalEnforce(t *testing.T) {
	require, _ := resolveTLSPolicy("example.com", nil, nil, true)
	if !require {
		t.Error("global enforce: requireTLS should be true")
	}
}

func TestTLSPolicy_GlobalEnforceButSkipList(t *testing.T) {
	// Skip list overrides global enforce (for broken servers)
	require, skipTLS := resolveTLSPolicy("old-server.local", nil, []string{"old-server.local"}, true)
	if require {
		t.Error("old-server.local in skip list: requireTLS should be false even with global enforce")
	}
	if !skipTLS {
		t.Error("old-server.local in skip list: skipTLS should be true")
	}
}

func TestTLSPolicy_EnforceWinsOverSkip(t *testing.T) {
	// If domain is in BOTH lists, enforce wins
	require, skipTLS := resolveTLSPolicy("partner.com", []string{"partner.com"}, []string{"partner.com"}, false)
	if !require {
		t.Error("partner.com in both lists: requireTLS should win")
	}
	if skipTLS {
		t.Error("partner.com in both lists: skipTLS should be false (enforce wins)")
	}
}

func TestTLSPolicy_CaseInsensitive(t *testing.T) {
	require, _ := resolveTLSPolicy("FDA.GOV", []string{"fda.gov"}, nil, false)
	if !require {
		t.Error("FDA.GOV should match fda.gov (case-insensitive)")
	}
}

func TestTLSPolicy_SubdomainDoesNotMatch(t *testing.T) {
	require, _ := resolveTLSPolicy("mail.fda.gov", []string{"fda.gov"}, nil, false)
	if require {
		t.Error("mail.fda.gov should NOT match fda.gov (exact domain match only — subdomains are separate)")
	}
}
