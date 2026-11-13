package notify

import "testing"

func TestSubstituteWelcomePlaceholders(t *testing.T) {
	vals := map[string]string{
		"DisplayName": "Alice Example",
		"Email":       "alice@corp.test",
		"Username":    "alice",
		"OrgName":     "corp.test",
		"WebmailURL":  "https://corp.test",
	}
	cases := []struct{ in, want string }{
		{"Hi {{DisplayName}}", "Hi Alice Example"},
		{"{{Email}} / {{Username}}", "alice@corp.test / alice"},
		{"Open {{WebmailURL}} at {{OrgName}}", "Open https://corp.test at corp.test"},
		{"no tokens here", "no tokens here"},
		{"{{Unknown}} stays", "{{Unknown}} stays"},                         // unknown left literal
		{"{{DisplayName}} {{DisplayName}}", "Alice Example Alice Example"}, // repeated
	}
	for _, c := range cases {
		if got := substituteWelcomePlaceholders(c.in, vals); got != c.want {
			t.Errorf("substitute(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSubstituteWelcomePlaceholders_MissingValueLeftLiteral(t *testing.T) {
	// A whitelisted key with no provided value must be left literal, not blanked.
	got := substituteWelcomePlaceholders("Hi {{DisplayName}}", map[string]string{})
	if got != "Hi {{DisplayName}}" {
		t.Errorf("missing value should stay literal, got %q", got)
	}
}
