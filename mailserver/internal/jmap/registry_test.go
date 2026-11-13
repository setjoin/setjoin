package jmap

import (
	"os"
	"sort"
	"strings"
	"testing"

	"setjoin.com/shared/pgxutil"
)

// registryDump renders the method registry as sorted
// "method\tcapability\tapp\tgate" lines — the ONE golden artifact (c4) that
// pins every method × capability × app × delegate-gate row. Regenerate with:
//
//	UPDATE_GOLDEN=1 go test ./internal/jmap/ -run TestMethodRegistryGolden
//
// and update the webmail capability table (client.ts usingFor + its vitest,
// which reads this same golden file) in the SAME commit. (The webmail parser
// destructures columns 0–1 only, so the gate column is additive.)
func registryDump(h *JMAPHandler) string {
	lines := make([]string, 0, len(h.methods))
	for name, e := range h.methods {
		lines = append(lines, name+"\t"+e.capability+"\t"+e.app+"\t"+e.gate.String())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

// TestMethodRegistryGolden fails when a method is added, removed, or moved to
// a different capability/app without the golden file (and the webmail table)
// being updated deliberately.
func TestMethodRegistryGolden(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	got := registryDump(h)

	const golden = "testdata/methods.golden"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (regenerate with UPDATE_GOLDEN=1): %v", err)
	}
	if got != string(want) {
		gotLines := strings.Split(got, "\n")
		wantLines := strings.Split(string(want), "\n")
		gotSet := map[string]bool{}
		for _, l := range gotLines {
			gotSet[l] = true
		}
		wantSet := map[string]bool{}
		for _, l := range wantLines {
			wantSet[l] = true
		}
		for _, l := range wantLines {
			if !gotSet[l] {
				t.Errorf("missing from registry: %q", l)
			}
		}
		for _, l := range gotLines {
			if !wantSet[l] {
				t.Errorf("not in golden file:    %q", l)
			}
		}
		t.Fatalf("method registry drifted from %s — if intentional, regenerate with UPDATE_GOLDEN=1 and update webmail client.ts usingFor in the same commit", golden)
	}
}

// TestRegistryCapabilitiesAdvertised pins that every capability a method
// requires is one the Session handler advertises (the literal `capabilities`
// map in Session, handler.go). Adding a method under a NEW capability means
// updating the Session block AND this set — deliberately, together.
func TestRegistryCapabilitiesAdvertised(t *testing.T) {
	advertised := map[string]bool{ // mirrors the Session `capabilities` keys
		capCore:          true,
		capMail:          true,
		capSubmission:    true,
		capCalendars:     true,
		capContacts:      true,
		capTasks:         true,
		capReminders:     true,
		capBlob:          true,
		VendorCapability: true,
	}
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	for name, e := range h.methods {
		if !advertised[e.capability] {
			t.Errorf("%s requires capability %q which the Session block does not advertise", name, e.capability)
		}
	}
}

// TestCapabilityGateRejections pins the c4 capability re-buckets on the wire:
// Identity/* moved core → submission (RFC 8621 §6) and the vendor surfaces
// (QuickStep/SavedSearch/EmailTemplate) moved core → the vendor URN. A `using`
// carrying only core must now be rejected for these methods, and the correct
// capability must be accepted.
func TestCapabilityGateRejections(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	cases := []struct {
		method string
		cap    string
	}{
		{"Identity/get", capSubmission},
		{"Identity/changes", capSubmission},
		{"Identity/set", capSubmission},
		{"QuickStep/get", VendorCapability},
		{"QuickStep/set", VendorCapability},
		{"QuickStep/apply", VendorCapability},
		{"SavedSearch/list", VendorCapability},
		{"SavedSearch/set", VendorCapability},
		{"SavedSearch/delete", VendorCapability},
		{"EmailTemplate/list", VendorCapability},
		{"EmailTemplate/set", VendorCapability},
		{"EmailTemplate/delete", VendorCapability},
	}
	for _, c := range cases {
		if h.HasCapability([]string{capCore}, c.method) {
			t.Errorf("%s must be rejected when using=[core] only", c.method)
		}
		if !h.HasCapability([]string{c.cap}, c.method) {
			t.Errorf("%s must be accepted when using=[%s]", c.method, c.cap)
		}
	}
	// Unknown methods keep the pre-registry default (core) so they reach
	// Dispatch's method-level unknownMethod error.
	if got := h.capabilityForMethod("No/such"); got != capCore {
		t.Errorf("capabilityForMethod(unknown) = %q, want core", got)
	}
}

// TestGateClassInvariants is the tripwire for future registry rows (#13):
// a method that mutates by name must never be delegate-readable, gateSubmit
// belongs to EmailSubmission/* only, and only the mail+submission families
// may be delegate-accessible at all (every other family is personal —
// delegated accountIds fail closed).
func TestGateClassInvariants(t *testing.T) {
	h := NewJMAPHandler(nil, pgxutil.WorkerPool{}, "localhost", nil, "test-bucket", 10_000_000, nil)
	mutatingSuffixes := []string{"/set", "/apply", "/purge", "/recover", "/merge", "/delete",
		"/dismiss", "/snooze", "/import", "/cancel", "/rsvp", "/counter", "/setOccurrence", "/sendUpdate"}
	for name, e := range h.methods {
		if e.gate == gateRead {
			for _, s := range mutatingSuffixes {
				if strings.HasSuffix(name, s) {
					t.Errorf("%s is classed gateRead but its name says it mutates — a read-only delegate could call it", name)
				}
			}
		}
		if e.gate == gateSubmit && !strings.HasPrefix(name, "EmailSubmission/") {
			t.Errorf("%s is classed gateSubmit — that class is for EmailSubmission/* only", name)
		}
		if e.gate != gatePersonal && e.capability != capMail && e.capability != capSubmission {
			t.Errorf("%s (capability %s) is delegate-accessible — only the mail+submission families may be", name, e.capability)
		}
	}
}
