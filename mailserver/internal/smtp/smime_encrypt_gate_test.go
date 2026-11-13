package smtp

import (
	"os"
	"strings"
	"testing"
)

// SP1 Phase 3 Task 3.5: the outbound worker NO LONGER encrypts. Encryption is
// re-homed to the EmailSubmission/set Go handler (the single fail-closed gate):
// by the time a blob reaches the worker it is already the final (signed and/or
// encrypted) wire artifact, which the worker relays VERBATIM. The prior
// worker-side encryptSMIME pass (gate query + recipient-cert lookup + smime.Encrypt
// + bounce-on-no-cert) is retired.
//
// This is a source-level regression guard (a machine guard, not a manual sweep):
// the worker source must contain no encryptSMIME method, no smime.Encrypt call,
// and no messages.smime_encrypt gate — so encryption can never silently move back
// to delivery time and split from the submission-time fail-closed contract.
func TestOutboundWorker_DoesNotEncrypt(t *testing.T) {
	src, err := os.ReadFile("outbound.go")
	if err != nil {
		t.Fatalf("read outbound.go: %v", err)
	}
	s := string(src)

	forbidden := []string{
		"encryptSMIME",  // the retired method + its call site
		"smime.Encrypt", // the worker must not encrypt
		"smime_encrypt", // the messages.smime_encrypt gate query
	}
	for _, f := range forbidden {
		if strings.Contains(s, f) {
			t.Errorf("outbound.go still references %q — the worker must not encrypt "+
				"(encryption is re-homed to EmailSubmission/set, SP1 Phase 3)", f)
		}
	}
}
