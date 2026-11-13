package notify

import "testing"

// NOTIFY-001 (notification-channel-authorization): the dispatcher must refuse
// channels outside the reducer/ws NOTIFY universe, and accept every channel
// the session topology actually subscribes to.
func TestValidPgChannel(t *testing.T) {
	valid := []string{
		"tag:1", "tag:42", "calendar:7", "contact:123456789",
		"task:9", "session_revoke", "drive-alarm",
		"drive-watch:5", "chat:5", "meet:5",
	}
	for _, ch := range valid {
		if !validPgChannel(ch) {
			t.Errorf("validPgChannel(%q) = false, want true", ch)
		}
	}
	invalid := []string{
		"", "tag:", "tag:0", "tag:-1", "tag:abc", "tag:1;drop",
		"tag:1 extra", "evil:1", "session-revoke", "drive_alarm",
		"drive-watch:", "chat:x", "meet:1 OR 1=1", "TAG:1",
		"session_revoke\n", "drive-alarm\rpayload",
	}
	for _, ch := range invalid {
		if validPgChannel(ch) {
			t.Errorf("validPgChannel(%q) = true, want false", ch)
		}
	}
}
