package spam

import "strings"

// SpamtrapStore maintains a set of deliberately planted email addresses that
// should never receive legitimate mail. Any message sent to a spamtrap address
// is high-signal spam with zero false positives — these addresses are never
// published, never used for signup, and never send outbound mail.
//
// When autoTrain is true, every message hitting a spamtrap is automatically
// fed to the FTRL classifier as positive spam training data.
type SpamtrapStore struct {
	addresses map[string]bool
	autoTrain bool
}

// NewSpamtrapStore creates a spamtrap store from a list of known spamtrap
// addresses. Addresses are normalized to lowercase with whitespace trimmed.
// autoTrain controls whether messages to spamtraps are auto-fed to training.
func NewSpamtrapStore(addresses []string, autoTrain bool) *SpamtrapStore {
	s := &SpamtrapStore{
		addresses: make(map[string]bool, len(addresses)),
		autoTrain: autoTrain,
	}
	for _, a := range addresses {
		normalized := strings.ToLower(strings.TrimSpace(a))
		if normalized != "" {
			s.addresses[normalized] = true
		}
	}
	return s
}

// IsSpamtrap returns true if the recipient address is a known spamtrap.
// The lookup is case-insensitive and whitespace-trimmed.
func (s *SpamtrapStore) IsSpamtrap(rcpt string) bool {
	return s.addresses[strings.ToLower(strings.TrimSpace(rcpt))]
}

// ShouldAutoTrain returns true if messages to spamtraps should automatically
// be used as positive spam training examples.
func (s *SpamtrapStore) ShouldAutoTrain() bool {
	return s.autoTrain
}

// Count returns the number of spamtrap addresses in the store.
func (s *SpamtrapStore) Count() int {
	return len(s.addresses)
}

// List returns a normalized slice of all spamtrap addresses.
func (s *SpamtrapStore) List() []string {
	result := make([]string, 0, len(s.addresses))
	for addr := range s.addresses {
		result = append(result, addr)
	}
	return result
}
