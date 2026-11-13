package main

import (
	"os"
	"strings"
)

// listenerEnabled reports whether Go still serves the named public listener.
// `GO_LISTENERS_OFF` is a comma list of exact, case-sensitive names: `imap`
// (STARTTLS and implicit-TLS sockets, #345), `smtp` (inbound :25 and the
// implicit-TLS variant, #501) and `submission` (MSA :587, #501). A listener the
// Rust gateway has taken over via systemd socket activation must be listed here
// first: two processes cannot serve one port, and Go must not keep answering
// behind the swap. Unknown or empty entries do nothing.
func listenerEnabled(name string) bool {
	for _, off := range strings.Split(os.Getenv("GO_LISTENERS_OFF"), ",") {
		if name != "" && strings.TrimSpace(off) == name {
			return false
		}
	}
	return true
}
