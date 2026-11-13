package ldap

import (
	"fmt"
	"strings"
)

// buildBaseDN constructs the root DN from a domain like "company.com".
func buildBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	var comps []string
	for _, p := range parts {
		comps = append(comps, fmt.Sprintf("dc=%s", p))
	}
	return strings.Join(comps, ",")
}

// userToDN builds an LDAP DN for a user under the People OU.
func userToDN(userID int64, email, deptPath, baseDN string) string {
	local := strings.Split(email, "@")[0]
	if deptPath != "" {
		return fmt.Sprintf("cn=%s,ou=%s,ou=People,%s", escapeRDN(local), escapeOU(deptPath), baseDN)
	}
	return fmt.Sprintf("cn=%s,ou=People,%s", escapeRDN(local), baseDN)
}

// contactToDN builds an LDAP DN for an external contact.
func contactToDN(contactID int64, displayName, baseDN string) string {
	return fmt.Sprintf("cn=%s,ou=Contacts,%s", escapeRDN(displayName), baseDN)
}

func groupToDN(groupID int64, name, baseDN string) string {
	return fmt.Sprintf("cn=%s,ou=Groups,%s", escapeRDN(name), baseDN)
}

func resourceToDN(mailboxID int64, name, baseDN string) string {
	return fmt.Sprintf("cn=%s,ou=Resources,%s", escapeRDN(name), baseDN)
}

// dnToFilter extracts the base scope from a DN.
func dnToFilter(dn, baseDN string) (ou string, id int64) {
	dn = strings.ToLower(dn)
	baseDN = strings.ToLower(baseDN)
	dn = strings.TrimSuffix(dn, ","+baseDN)

	if dn == "ou=people" || strings.Contains(dn, ",ou=people") {
		return "people", 0
	}
	if dn == "ou=groups" || strings.Contains(dn, ",ou=groups") {
		return "groups", 0
	}
	if dn == "ou=resources" || strings.Contains(dn, ",ou=resources") {
		return "resources", 0
	}
	if dn == "ou=contacts" || strings.Contains(dn, ",ou=contacts") {
		return "contacts", 0
	}
	if dn == "" {
		return "root", 0
	}
	return "", 0
}

func escapeOU(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s,
		"\\", "\\5c"),
		"/", "\\2f")
}

// escapeRDN escapes special characters in RDN attribute values per RFC 4514 §2.4.
var rdnReplacer = strings.NewReplacer(
	"\\", "\\5C",
	",", "\\2C",
	"+", "\\2B",
	"\"", "\\22",
	"<", "\\3C",
	">", "\\3E",
	";", "\\3B",
)

func escapeRDN(s string) string {
	s = rdnReplacer.Replace(s)
	if len(s) > 0 && s[0] == '#' {
		s = "\\23" + s[1:]
	}
	if len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1] + "\\20"
	}
	return s
}

// extractRDNValue extracts the value of an RDN attribute from a DN string.
func extractRDNValue(dn, attr string) string {
	dn = strings.ToLower(dn)
	attr = strings.ToLower(attr)
	prefix := attr + "="
	for _, part := range strings.Split(dn, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return ""
}

// extractDeptPath extracts the department path from a DN for subtree scoping.
// e.g. dn="ou=Backend,ou=Engineering,ou=People,dc=company,dc=com" → "Engineering/Backend"
// Returns empty string if the DN is directly under ou=People (no sub-department).
func extractDeptPath(dn, baseDN, topOU string) string {
	dn = strings.ToLower(dn)
	baseDN = strings.ToLower(baseDN)
	dn = strings.TrimSuffix(dn, ","+baseDN)

	topPrefix := "ou=" + topOU
	idx := strings.Index(dn, topPrefix)
	if idx < 0 {
		return ""
	}

	// Everything before the top OU prefix is the sub-path
	subPath := strings.TrimSuffix(dn[:idx], ",")
	if subPath == "" || subPath == dn {
		return ""
	}

	// Reverse the order: "ou=backend,ou=engineering" → "engineering/backend"
	var parts []string
	for _, part := range strings.Split(subPath, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "ou=") {
			parts = append(parts, strings.TrimPrefix(part, "ou="))
		}
	}
	// Reverse to get natural hierarchy order
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, "/")
}
