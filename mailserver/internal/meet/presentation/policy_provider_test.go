package presentation

import (
	"strings"
	"testing"

	"setjoin.com/shared/toggle"
)

// TestMeetPresentationFlagsDefaultOFF is the M0 inertness gate: the three
// MEET-plan flags ship OFF in the compiled registry, so every new code path
// M2+ wires behind them stays inert until separately enabled. A regression
// here would silently admit presentation/recording behavior.
func TestMeetPresentationFlagsDefaultOFF(t *testing.T) {
	for _, key := range []string{
		toggle.FeatureMeetDocumentPresentation,
		toggle.FeatureMeetSemanticRecording,
		toggle.FeatureMeetLocalRecording,
	} {
		definition, ok := toggle.Lookup(key)
		if !ok {
			t.Fatalf("%s is not registered in the compiled toggle registry", key)
		}
		if definition.Default {
			t.Fatalf("%s defaults ON; the MEET plan requires default-OFF production posture", key)
		}
		// A missing DB row must resolve to the same OFF default (overrides →
		// rows → registry default), never to the historical unknown=>true.
		f := toggle.NewTestFlags(nil)
		if f.IsEnabled(key) {
			t.Fatalf("%s resolved enabled with no row; unseeded deployments must stay OFF", key)
		}
	}
}

func TestRecordingPolicyMatrix(t *testing.T) {
	cases := []struct {
		policy     PolicyMode
		surface    Surface
		capability bool
		want       bool
	}{
		{PolicyLocalPreferred, SurfaceElectron, false, true},
		{PolicyLocalPreferred, SurfaceBrowser, false, false}, // probe must pass
		{PolicyLocalPreferred, SurfaceBrowser, true, true},
		{PolicyLocalPreferred, SurfaceServer, false, true},
		{PolicyLocalPreferred, SurfaceSemantic, false, true},
		{PolicyServerOnly, SurfaceElectron, true, false}, // no local target
		{PolicyServerOnly, SurfaceBrowser, true, false},
		{PolicyServerOnly, SurfaceServer, false, true},
		{PolicyServerOnly, SurfaceSemantic, false, true},
		{PolicyLocalOnly, SurfaceElectron, true, true}, // managed-capable only
		{PolicyLocalOnly, SurfaceElectron, false, false},
		{PolicyLocalOnly, SurfaceBrowser, true, false}, // hidden
		{PolicyLocalOnly, SurfaceServer, true, false},  // disabled
		{PolicyLocalOnly, SurfaceSemantic, true, false},
		{PolicyDisabled, SurfaceElectron, true, false},
		{PolicyDisabled, SurfaceBrowser, true, false},
		{PolicyDisabled, SurfaceServer, true, false},
		{PolicyDisabled, SurfaceSemantic, true, false},
	}
	for _, c := range cases {
		if got := AllowsCapture(c.policy, c.surface, c.capability); got != c.want {
			t.Errorf("AllowsCapture(%s, %s, capability=%v) = %v, want %v", c.policy, c.surface, c.capability, got, c.want)
		}
	}
	if !AllowsLocalRegistration(PolicyLocalOnly) {
		t.Fatal("local_only permits truthful local registration")
	}
	if AllowsLocalRegistration(PolicyServerOnly) || AllowsLocalRegistration(PolicyDisabled) {
		t.Fatal("local registration must stay local_only-scoped")
	}
}

func TestFailureRegistryIsClosedAndComplete(t *testing.T) {
	// Every code named by the plan's error/rescue registry is present, and
	// each maps to exactly one owning layer.
	want := map[FailureCode]bool{
		FailSourceVersionGone:          true,
		FailUnsupportedDocument:        true,
		FailDocumentProtected:          true,
		FailRendererTimeout:            true,
		FailPresentationAccessRevoked:  true,
		FailStalePresenterGeneration:   true,
		FailPresentationSequenceGap:    true,
		FailCheckpointRefreshThrottled: true,
		FailLocalCaptureUnavailable:    true,
		FailCaptureLeaseExpired:        true,
		FailTimelineGap:                true,
		FailIntegrityMismatch:          true,
		FailExportCompositionFailed:    true,
		FailHistoryProjectionStale:     true,
	}
	if len(want) != len(FailureRegistry) {
		t.Fatalf("registry has %d codes, plan names %d", len(FailureRegistry), len(want))
	}
	for code := range want {
		if _, ok := FailureRegistry[code]; !ok {
			t.Errorf("code %q missing from the registry", code)
		}
	}
	// Codes are camelCase wire slugs, never free text.
	for code := range FailureRegistry {
		if strings.ContainsAny(string(code), " _") || string(code) != uncapitalize(string(code)) {
			t.Errorf("code %q is not a stable camelCase slug", code)
		}
	}
}

func uncapitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

func TestProviderIdentityAdmissionFailsClosed(t *testing.T) {
	qualified := ProviderIdentity{
		RendererID:           "soffice",
		RendererVersion:      "qualified",
		FontPackDigest:       strings.Repeat("ab", 32),
		LocaleProfile:        "zh-CN",
		OutputProfileVersion: RenditionProfileVersion,
		SupportedOSArch:      "linux/amd64",
		ArtifactFormat:       "tar+zst",
		ArtifactSHA256:       strings.Repeat("cd", 32),
		LicenseSPDX:          "MPL-2.0",
		ProvenanceRef:        "reproducible-build/evidence-1",
		SandboxPolicy:        "bubblewrap-namespace",
		HealthProtocol:       "healthprobe/v1",
		EvidenceRef:          "qualification/run-42",
	}
	if err := AdmitProviderIdentity(qualified); err != nil {
		t.Fatalf("fully-evidenced identity rejected: %v", err)
	}
	// Identities come from qualification, never invented: every evidence or
	// identity field removed independently must fail admission.
	fields := map[string]func(*ProviderIdentity){
		"renderer id":            func(p *ProviderIdentity) { p.RendererID = "" },
		"renderer version":       func(p *ProviderIdentity) { p.RendererVersion = "" },
		"font pack digest":       func(p *ProviderIdentity) { p.FontPackDigest = "deadbeef" },
		"locale profile":         func(p *ProviderIdentity) { p.LocaleProfile = "" },
		"output profile":         func(p *ProviderIdentity) { p.OutputProfileVersion = "meet-pages-v2" },
		"OS/arch":                func(p *ProviderIdentity) { p.SupportedOSArch = "" },
		"artifact format":        func(p *ProviderIdentity) { p.ArtifactFormat = "" },
		"artifact sha256":        func(p *ProviderIdentity) { p.ArtifactSHA256 = "" },
		"license":                func(p *ProviderIdentity) { p.LicenseSPDX = "" },
		"provenance":             func(p *ProviderIdentity) { p.ProvenanceRef = "" },
		"qualification evidence": func(p *ProviderIdentity) { p.EvidenceRef = "" },
		"sandbox policy":         func(p *ProviderIdentity) { p.SandboxPolicy = "" },
		"health protocol":        func(p *ProviderIdentity) { p.HealthProtocol = "" },
	}
	for name, mutate := range fields {
		candidate := qualified
		mutate(&candidate)
		if err := AdmitProviderIdentity(candidate); err == nil {
			t.Errorf("identity missing %s was admitted", name)
		}
	}
}

func TestPinnedSessionsNeverSilentlySwapProviders(t *testing.T) {
	pinned := ProviderIdentity{RendererID: "soffice", RendererVersion: "r1", FontPackDigest: "ff", LocaleProfile: "zh-CN", OutputProfileVersion: RenditionProfileVersion, SupportedOSArch: "linux/amd64", ArtifactFormat: "tar", ArtifactSHA256: "aa", LicenseSPDX: "MPL-2.0", ProvenanceRef: "p", SandboxPolicy: "s", HealthProtocol: "h", EvidenceRef: "e"}
	same := pinned
	if EvaluateRebind(pinned, same) != RebindUnchanged {
		t.Fatal("an identical candidate must not force a rebind")
	}
	swapped := pinned
	swapped.RendererVersion = "r2" // provider upgrade mid-fleet
	if EvaluateRebind(pinned, swapped) != RebindRequired {
		t.Fatal("a provider version change requires explicit requalification/rebind")
	}
	font := pinned
	font.FontPackDigest = "ee"
	if EvaluateRebind(pinned, font) != RebindRequired {
		t.Fatal("a font-pack digest change requires explicit rebind")
	}
}

func TestStaleSubscriptionCleanup(t *testing.T) {
	live := Subscription{ID: "s1", Kind: SubscriptionContinuity, MeetingID: "m1", PresentationID: "p-1", AuthorizationGeneration: 4}

	if _, stale := ClassifyStale(live, AuthorityState{MeetingActive: true, CurrentGeneration: 4}); stale {
		t.Fatal("a live subscription at the current generation is not stale")
	}
	for _, tc := range []struct {
		name      string
		sub       Subscription
		authority AuthorityState
		want      StaleReason
	}{
		{"ended meeting", live, AuthorityState{MeetingEnded: true, CurrentGeneration: 4}, StaleMeetingEnded},
		{"inactive meeting", live, AuthorityState{MeetingActive: false, CurrentGeneration: 4}, StaleMeetingEnded},
		{"stale generation", live, AuthorityState{MeetingActive: true, CurrentGeneration: 5}, StaleGeneration},
		{"revoked grant", live, AuthorityState{MeetingActive: true, CurrentGeneration: 4, GrantRevoked: true}, StaleGrantRevoked},
	} {
		reason, stale := ClassifyStale(tc.sub, tc.authority)
		if !stale || reason != tc.want {
			t.Errorf("%s: got (%q,%v), want (%q,true)", tc.name, reason, stale, tc.want)
		}
		// The owning authority reaps it with the single bounded scope.
		scope, _, err := Reap(tc.sub, tc.authority)
		if err != nil {
			t.Errorf("%s: reap refused a stale subscription: %v", tc.name, err)
		}
		if scope != ReapScopeSubscriptionOnly {
			t.Errorf("%s: reap scope %q is not the subscription-only boundary", tc.name, scope)
		}
	}

	// A LIVE authorization is never reaped.
	if _, _, err := Reap(live, AuthorityState{MeetingActive: true, CurrentGeneration: 4}); err == nil {
		t.Fatal("reap accepted a live subscription; cleanup must never resurrect or cancel live grants")
	}
}

// TestStalePresentationWhileMeetingActive is the regression for the M0/M1
// review finding: ClassifyStale could not represent an ended or replaced
// presentation while the meeting remains active — such subscriptions
// classified as live and were never reaped. Presentation scope follows the
// subscription's PresentationID; the M1(b) boundary (subscription-only
// reaping) is unchanged.
func TestStalePresentationWhileMeetingActive(t *testing.T) {
	live := Subscription{ID: "s2", Kind: SubscriptionPresentation, MeetingID: "m1", PresentationID: "p-1", AuthorizationGeneration: 4}
	activeMeeting := AuthorityState{MeetingActive: true, CurrentGeneration: 4}

	if _, stale := ClassifyStale(live, activeMeeting); stale {
		t.Fatal("a live subscription following the meeting's current presentation is not stale")
	}

	ended := activeMeeting
	ended.PresentationEnded = true
	reason, stale := ClassifyStale(live, ended)
	if !stale || reason != StalePresentationEnded {
		t.Fatalf("ended presentation: got (%q,%v), want (%q,true)", reason, stale, StalePresentationEnded)
	}

	replaced := activeMeeting
	replaced.CurrentPresentationID = "p-2"
	reason, stale = ClassifyStale(live, replaced)
	if !stale || reason != StalePresentationEnded {
		t.Fatalf("replaced presentation: got (%q,%v), want (%q,true)", reason, stale, StalePresentationEnded)
	}

	// A meeting-scoped continuity subscription without a presentation id is
	// not presentation-stale: the authority's presentation state cannot
	// identify it, and only its own scope may reap it.
	bare := Subscription{ID: "s3", Kind: SubscriptionContinuity, MeetingID: "m1", AuthorizationGeneration: 4}
	if _, stale := ClassifyStale(bare, ended); stale {
		t.Fatal("a subscription with no presentation scope must not classify via presentation truth")
	}

	// Reaping stays subscription-only: the presentation-ended scope can
	// never reach admitted recordings or rendition references.
	scope, got, err := Reap(live, ended)
	if err != nil {
		t.Fatalf("reap refused the presentation-stale subscription: %v", err)
	}
	if scope != ReapScopeSubscriptionOnly || got != StalePresentationEnded {
		t.Fatalf("reap gave (%q,%q), want (%q,%q)", scope, got, ReapScopeSubscriptionOnly, StalePresentationEnded)
	}
}

func TestPageCapabilitiesAreViewOnlyAndBounded(t *testing.T) {
	capability := NewPageCapability("p-1", "m-1", "page-0", strings.Repeat("aa", 32), 1_800_000_000_000)
	if err := capability.Validate(); err != nil {
		t.Fatalf("valid capability rejected: %v", err)
	}
	// The type cannot express original/notes/search/future-version grants:
	// compile-time, proven here by the constructor being the only path and
	// forcing view-only.
	if !capability.ViewOnly {
		t.Fatal("page capabilities are view-only by construction")
	}
	zero := PageCapability{}
	if err := zero.Validate(); err == nil {
		t.Fatal("a zero-value capability (ViewOnly=false) must fail validation")
	}
	noExpiry := NewPageCapability("p-1", "m-1", "page-0", strings.Repeat("aa", 32), 0)
	if err := noExpiry.Validate(); err == nil {
		t.Fatal("a capability without expiry must fail; capabilities expire at end/revocation")
	}
}

func TestSourceRefPinsImmutableDriveIdentity(t *testing.T) {
	good := SourceRef{DriveNodeID: 5, DriveVersionID: 42, SourceSHA256: strings.Repeat("ab", 32)}
	if err := good.Validate(); err != nil {
		t.Fatalf("valid source ref rejected: %v", err)
	}
	for _, bad := range []SourceRef{
		{DriveNodeID: 0, DriveVersionID: 42, SourceSHA256: strings.Repeat("ab", 32)},
		{DriveNodeID: 5, DriveVersionID: 0, SourceSHA256: strings.Repeat("ab", 32)},
		{DriveNodeID: 5, DriveVersionID: 42, SourceSHA256: "short"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("incomplete source ref %+v accepted", bad)
		}
	}
	if ErrMeetNeverWopiHost == nil || !strings.Contains(ErrMeetNeverWopiHost.Error(), "WOPI") {
		t.Fatal("the Meet-never-WOPI-host sentinel drifted")
	}
}
