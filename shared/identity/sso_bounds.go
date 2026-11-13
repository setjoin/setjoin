package identity

import (
	"fmt"
	"strings"
	"unicode"
)

// SSO group bounds cap login-time work and the persisted mapping document.
// They are shared by the authserver claim readers and mailserver admin writer
// so an accepted configuration cannot exceed the runtime reconciliation cap.
const (
	MaxSSOGroupClaims    = 1000
	MaxSSOGroupMappings  = 100
	MaxSSOGroupNameBytes = 1024
)

// ValidateSSOGroupClaims validates the untrusted membership list supplied by an
// IdP. Empty entries are harmless and tolerated because mappings cannot target
// an empty group. Errors name only the index, never the potentially sensitive
// group value.
func ValidateSSOGroupClaims(groups []string) error {
	if len(groups) > MaxSSOGroupClaims {
		return fmt.Errorf("SSO group claim has %d entries; maximum is %d", len(groups), MaxSSOGroupClaims)
	}
	for i, group := range groups {
		if len(group) > MaxSSOGroupNameBytes {
			return fmt.Errorf("SSO group claim entry %d exceeds %d bytes", i, MaxSSOGroupNameBytes)
		}
		if hasControlRune(group) {
			return fmt.Errorf("SSO group claim entry %d contains a control character", i)
		}
	}
	return nil
}

// ValidateSSOGroupMappings validates the admin-owned mapping keys. A mapping
// must name a real IdP group and the whole document must stay bounded.
func ValidateSSOGroupMappings(groups []string) error {
	if len(groups) > MaxSSOGroupMappings {
		return fmt.Errorf("SSO group mapping has %d entries; maximum is %d", len(groups), MaxSSOGroupMappings)
	}
	for i, group := range groups {
		if strings.TrimSpace(group) == "" {
			return fmt.Errorf("SSO group mapping entry %d has an empty IdP group", i)
		}
		if len(group) > MaxSSOGroupNameBytes {
			return fmt.Errorf("SSO group mapping entry %d exceeds %d bytes", i, MaxSSOGroupNameBytes)
		}
		if hasControlRune(group) {
			return fmt.Errorf("SSO group mapping entry %d contains a control character", i)
		}
	}
	return nil
}

func hasControlRune(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
