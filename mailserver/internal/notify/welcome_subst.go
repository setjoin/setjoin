package notify

import "strings"

// welcomePlaceholderKeys is the fixed, case-sensitive personalization whitelist
// (spec §5). No template engine: each token is a literal string replace.
var welcomePlaceholderKeys = []string{"DisplayName", "Email", "Username", "OrgName", "WebmailURL"}

// substituteWelcomePlaceholders replaces each "{{Key}}" for a whitelisted Key
// that has a provided value. Whitelisted keys with no value, and any token not
// in the whitelist, are left literal (no blanking, no execution).
func substituteWelcomePlaceholders(s string, vals map[string]string) string {
	for _, key := range welcomePlaceholderKeys {
		v, ok := vals[key]
		if !ok {
			continue
		}
		s = strings.ReplaceAll(s, "{{"+key+"}}", v)
	}
	return s
}
