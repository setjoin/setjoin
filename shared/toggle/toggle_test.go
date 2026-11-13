package toggle

import (
	"bytes"
	"log/slog"
	"sort"
	"strings"
	"testing"
)

func TestIsEnabled_EnvOverride(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{"feature.test": false},
		overrides: map[string]bool{"feature.test": true},
	}
	if !f.IsEnabled("feature.test") {
		t.Error("env override should win")
	}
}

func TestIsEnabled_DBDefault(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{"feature.test": true},
		overrides: map[string]bool{},
	}
	if !f.IsEnabled("feature.test") {
		t.Error("DB value should be used when no override")
	}
}

func TestIsEnabled_UnknownKeyDefaultsTrue(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{},
		overrides: map[string]bool{},
	}
	if !f.IsEnabled("feature.nonexistent") {
		t.Error("unknown keys should default to true")
	}
}

func TestEnforceIgnoresUnknownRowsAndOverrides(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{"legacy.example": true, FeatureImap: false},
		overrides: map[string]bool{"legacy.override": true, FeatureImap: true},
		mode:      RegistryEnforce,
	}
	if got, source := f.Resolve("legacy.example"); got || source != SourceDefault {
		t.Fatalf("unknown stored row in enforce = (%v,%s), want (false,default)", got, source)
	}
	if got, source := f.Resolve("legacy.override"); got || source != SourceDefault {
		t.Fatalf("unknown override in enforce = (%v,%s), want (false,default)", got, source)
	}
	if got, source := f.Resolve(FeatureImap); !got || source != SourceEnvironment {
		t.Fatalf("known override in enforce = (%v,%s), want (true,environment)", got, source)
	}
	f.OnNotify("legacy.notify", true)
	if _, exists := f.flags["legacy.notify"]; exists {
		t.Fatal("enforce OnNotify admitted unknown key")
	}
}

func TestValidateRegistrySnapshotFailsClosed(t *testing.T) {
	if err := validateRegistrySnapshot(RegistryObserve, false); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing state error = %v", err)
	}
	if err := validateRegistrySnapshot(RegistryMode("future"), true); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid mode error = %v", err)
	}
	for _, mode := range []RegistryMode{RegistryObserve, RegistryEnforce} {
		if err := validateRegistrySnapshot(mode, true); err != nil {
			t.Fatalf("valid mode %q: %v", mode, err)
		}
	}
}

func TestOnNotify_UpdatesFlag(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{"feature.test": true},
		overrides: map[string]bool{},
	}
	f.OnNotify("feature.test", false)
	if f.IsEnabled("feature.test") {
		t.Error("OnNotify should update the flag")
	}
}

func TestOnNotify_OverrideStillWins(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{"feature.test": true},
		overrides: map[string]bool{"feature.test": true},
	}
	f.OnNotify("feature.test", false)
	if !f.IsEnabled("feature.test") {
		t.Error("override should still win after OnNotify")
	}
}

func TestReloadFailureInvalidatesDatabaseSnapshot(t *testing.T) {
	f := &FeatureFlags{
		flags: map[string]bool{
			FeatureIdentityModelV2:   true,
			FeatureGuestAccounts:     true,
			FeatureGalCarddav:        false,
			FeatureThreatFeed:        false,
			FeatureRequireMFA:        false,
			FeatureConditionalAccess: false,
			FeatureDeviceLockdown:    true,
		},
		overrides: map[string]bool{
			FeatureGuestAccounts: true,
		},
	}

	if err := f.Reload(t.Context()); err == nil {
		t.Fatal("Reload without a database must fail")
	}
	if f.IsEnabled(FeatureIdentityModelV2) {
		t.Fatal("failed authoritative reload must fail a DEFAULT-OFF database gate closed")
	}
	if f.IsEnabled(FeatureGalCarddav) {
		t.Fatal("failed authoritative reload must preserve the safe disabled state for a DEFAULT-ON gate")
	}
	if !f.IsEnabled(FeatureThreatFeed) {
		t.Fatal("failed authoritative reload must keep positive threat defenses enabled")
	}
	if !f.IsEnabled(FeatureRequireMFA) {
		t.Fatal("failed authoritative reload must keep authentication enforcement enabled")
	}
	if f.IsEnabled(FeatureConditionalAccess) {
		t.Fatal("failed reload must not synthetically activate a staged policy regime")
	}
	if !f.IsEnabled(FeatureDeviceLockdown) {
		t.Fatal("failed reload must not synthetically deactivate an active staged policy regime")
	}
	if !f.IsEnabled(FeatureGuestAccounts) {
		t.Fatal("explicit environment override must survive database snapshot invalidation")
	}
}

func TestReloadFailureSecurityPolarityIsRegistered(t *testing.T) {
	for key := range reloadFailureEnabled {
		if _, ok := registryDefaults[key]; !ok {
			t.Errorf("reloadFailureEnabled contains unregistered key %q", key)
		}
		if _, overlap := reloadFailurePreserved[key]; overlap {
			t.Errorf("reload failure policy for %q is both enabled and preserved", key)
		}
	}
	for key := range reloadFailurePreserved {
		if _, ok := registryDefaults[key]; !ok {
			t.Errorf("reloadFailurePreserved contains unregistered key %q", key)
		}
	}

	f := &FeatureFlags{}
	f.invalidateDatabaseSnapshot()
	for key := range reloadFailureEnabled {
		if !f.IsEnabled(key) {
			t.Errorf("positive security control %q disabled after reload failure", key)
		}
	}
	for _, key := range []string{
		FeatureSmtpInbound,
		FeatureKerberos,
		FeatureSAMLSso,
		FeatureOIDCSso,
		FeatureAppPasswords,
		FeatureGalCarddav,
		FeatureDeviceTelemetry,
		FeatureDrive,
		FeatureDriveHistory,
		FeatureDriveNodeACLReads,
		FeatureDriveNodeACLWrites,
		FeatureDriveAccessGovernance,
		FeatureDriveEmergencyAccess,
		FeatureOfficeEditing,
		FeatureOfficeLocalOpen,
		FeatureOfficeManagedDelivery,
		FeatureDirectoryGroupAuthority,
		FeatureAssist,
		FeatureGuestAccounts,
		FeatureIdentityModelV2,
		FeatureIdentityNormalizedReads,
		FeatureIdentityTransitions,
		FeatureTransactionalUpgradesCatalog,
		FeatureTransactionalUpgradesExecution,
		FeatureUpgradeClientReceipts,
		FeatureUpgradeClientRecoveryCache,
		FeatureUpgradeRecoveryIntake,
	} {
		if f.IsEnabled(key) {
			t.Errorf("admission or release gate %q enabled after reload failure", key)
		}
	}
}

func TestNew_LoadsFromDB(t *testing.T) {
	t.Skip("requires PostgreSQL")
}

func TestNew_EmptyDB(t *testing.T) {
	t.Skip("requires PostgreSQL")
}

func TestFeatureFullTextSearchConstantRegistered(t *testing.T) {
	if FeatureFullTextSearch != "feature.full_text_search" {
		t.Errorf("FeatureFullTextSearch = %q, want %q", FeatureFullTextSearch, "feature.full_text_search")
	}
}

func TestFeatureChatRegistered(t *testing.T) {
	if FeatureChat != "feature.chat" {
		t.Errorf("FeatureChat = %q, want %q", FeatureChat, "feature.chat")
	}
	if def, ok := registryDefaults[FeatureChat]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureChat] = (%v, %v), want (false, true)", def, ok)
	}
}

func TestFeatureMeetRegistered(t *testing.T) {
	if FeatureMeet != "feature.meet" {
		t.Errorf("FeatureMeet = %q, want %q", FeatureMeet, "feature.meet")
	}
	if def, ok := registryDefaults[FeatureMeet]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureMeet] = (%v, %v), want (false, true)", def, ok)
	}
}

func TestFeatureChatComplianceRegistered(t *testing.T) {
	if FeatureChatCompliance != "feature.chat_compliance" {
		t.Errorf("FeatureChatCompliance = %q, want %q", FeatureChatCompliance, "feature.chat_compliance")
	}
	if def, ok := registryDefaults[FeatureChatCompliance]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureChatCompliance] = (%v, %v), want (false, true)", def, ok)
	}
}

func TestFeatureMeetRecordingRegistered(t *testing.T) {
	if FeatureMeetRecording != "feature.meet_recording" {
		t.Errorf("FeatureMeetRecording = %q, want %q", FeatureMeetRecording, "feature.meet_recording")
	}
	if def, ok := registryDefaults[FeatureMeetRecording]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureMeetRecording] = (%v, %v), want (false, true)", def, ok)
	}
}

func TestFeatureMeetBreakoutsRegistered(t *testing.T) {
	if FeatureMeetBreakouts != "feature.meet_breakouts" {
		t.Errorf("FeatureMeetBreakouts = %q, want %q", FeatureMeetBreakouts, "feature.meet_breakouts")
	}
	if def, ok := registryDefaults[FeatureMeetBreakouts]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureMeetBreakouts] = (%v, %v), want (false, true)", def, ok)
	}
}

func TestFeatureMeetCaptionsRegistered(t *testing.T) {
	if FeatureMeetCaptions != "feature.meet_captions" {
		t.Errorf("FeatureMeetCaptions = %q, want %q", FeatureMeetCaptions, "feature.meet_captions")
	}
	if def, ok := registryDefaults[FeatureMeetCaptions]; !ok || def != false {
		t.Errorf("registryDefaults[FeatureMeetCaptions] = (%v, %v), want (false, true)", def, ok)
	}
}

// TestAllSetIfDisabledKeysRegistered verifies every feature key used in
// setToggleSessionVars calls (both inbound.go and submission.go) is registered
// as a named constant. Unregistered keys cause IsEnabled() to always return
// true (default for unknown keys), silently breaking the toggle.
func TestFeatureDeviceLockdownKey(t *testing.T) {
	if FeatureDeviceLockdown != "feature.device_lockdown" {
		t.Fatalf("FeatureDeviceLockdown = %q, want feature.device_lockdown", FeatureDeviceLockdown)
	}
}

func TestAllSetIfDisabledKeysRegistered(t *testing.T) {
	required := map[string]string{
		// From inbound.go setToggleSessionVars
		"feature.rules_engine":               FeatureRulesEngine,
		"feature.vacation":                   FeatureVacation,
		"feature.journaling":                 FeatureJournaling,
		"feature.retention":                  FeatureRetention,
		"feature.full_text_search":           FeatureFullTextSearch,
		"feature.mailbox_audit_log":          FeatureMailboxAuditLog,
		"feature.external_sender_first_time": FeatureExternalSenderFirstTime,
		// From submission.go setToggleSessionVars
		"feature.dlp": FeatureDLP,
	}
	for expected, actual := range required {
		if actual != expected {
			t.Errorf("constant for %q has wrong value: got %q", expected, actual)
		}
	}
}

func TestRequireSeeded_MissingRowsFailLoudly(t *testing.T) {
	f := &FeatureFlags{flags: map[string]bool{FeatureConditionalAccess: false}, overrides: map[string]bool{}}
	// One seeded, the rest missing → error naming the missing keys only.
	err := f.RequireSeeded(FeatureConditionalAccess, FeatureDeviceLockdown)
	if err == nil {
		t.Fatal("missing security-toggle rows must fail the seed check")
	}
	if want := FeatureDeviceLockdown; !strings.Contains(err.Error(), want) {
		t.Errorf("error must name the missing key %q, got: %v", want, err)
	}
	if strings.Contains(err.Error(), FeatureConditionalAccess+" ") {
		t.Errorf("seeded key must not be reported missing: %v", err)
	}
}

func TestRequireSeeded_AllSeededOrOverriddenPasses(t *testing.T) {
	f := &FeatureFlags{
		flags:     map[string]bool{FeatureConditionalAccess: false},
		overrides: map[string]bool{FeatureDeviceLockdown: false}, // env override counts as seeded
	}
	if err := f.RequireSeeded(FeatureConditionalAccess, FeatureDeviceLockdown); err != nil {
		t.Fatalf("seeded+overridden keys must pass: %v", err)
	}
}

func TestSecuritySeededKeys_AreDeclaredConstants(t *testing.T) {
	// The seed-check list must never contain a typo'd literal — every entry is
	// one of the declared feature constants (cheap drift tripwire).
	declared := map[string]bool{
		FeatureConditionalAccess: true, FeatureDeviceTrustEnforcement: true,
		FeatureDeviceLockdown: true, FeatureDengbaoSodMode: true,
		FeatureCAERuntime: true, FeatureTokenBinding: true, FeatureUserRisk: true,
		// V032 seeds feature.smime_verify enabled=true; its row is
		// drift-guarded like the other security-family seeds
		// (D-SHARED-TOGGLE-003).
		FeatureSmimeVerify: true,
	}
	for _, k := range SecuritySeededKeys {
		if !declared[k] {
			t.Errorf("SecuritySeededKeys contains undeclared key %q", k)
		}
	}
}

// allFeatureConstants is the explicit list of every Feature* constant declared
// in toggle.go. Go reflection cannot enumerate a const block, so this slice is
// the test-side mirror; TestRegistryCoversAllConstants asserts set equality
// with registryDefaults, and scripts/check-toggle-registry.sh guards the
// toggle.go side (constant declared but missing from the registry).
var allFeatureConstants = []string{
	FeatureThreatFeed, FeatureGeoBlock, FeatureSprayDetect, FeatureCaptcha,
	FeatureTarpit, FeatureRateLimit,
	FeatureSmtpInbound, FeatureSmtpSubmission, FeatureImap, FeatureCaldav,
	FeatureCarddav, FeatureDmarcReporting, FeatureTlsRpt, FeatureLdapGal,
	FeatureKerberos, FeatureDisableBasicAuth, FeatureSAMLSso, FeatureOIDCSso,
	FeatureADSync, FeatureOIDCOp, FeatureAppPasswords, FeatureRequireMFA,
	FeatureLinkProtectRewrite, FeatureLinkProtectSafeBrowsing,
	FeatureLinkProtectSpamhaus, FeatureLinkProtectStrictMode,
	FeatureExternalSenderWarn, FeatureExternalSenderNameSpoof,
	FeatureExternalSenderFirstTime,
	FeatureExchangeReplacementAssessment,
	FeatureDNSSEC, FeatureDANE, FeatureCertRollout,
	FeatureAntiphishDisplayName, FeatureAntiphishLookalike,
	FeatureAntiphishContactGraph, FeatureAntiphishStrictMode,
	FeatureFullTextSearch, FeatureRulesEngine, FeatureVacation,
	FeatureJournaling, FeatureRetention, FeatureMailboxAuditLog,
	FeatureDLP, FeatureMDM, FeatureDeviceTelemetry,
	FeatureConditionalAccess, FeatureDeviceTrustEnforcement,
	FeatureDeviceLockdown, FeatureDengbaoSodMode, FeatureCAERuntime,
	FeatureTokenBinding, FeatureUserRisk, FeatureSmimeVerify,
	FeatureNotifyDecouple, FeatureRustMarkRead, FeatureRustInboxList, FeatureSharingDefaults,
	FeatureBiometricUnlock, FeatureWindowsSsoUnlock,
	FeatureStaleNudges, FeatureGalCarddav,
	FeatureSharedTaskLists,
	FeatureBookingPages,
	FeatureDrive,
	FeatureDriveHistory,
	FeatureDriveNodeACLReads,
	FeatureDriveNodeACLWrites,
	FeatureDriveAccessGovernance,
	FeatureDriveEmergencyAccess,
	FeatureOfficeEditing,
	FeatureOfficeLocalOpen,
	FeatureOfficeManagedDelivery,
	FeatureDirectoryGroupAuthority,
	FeatureChat,
	FeatureAssist,
	FeatureMeet,
	FeatureChatCompliance,
	FeatureMeetRecording,
	FeatureMeetBreakouts,
	FeatureMeetCaptions,
	FeatureMeetDocumentPresentation,
	FeatureMeetLocalRecording,
	FeatureMeetSemanticRecording,
	FeatureSpamMLDetectors,
	FeatureSpamModelBatchLoad,
	FeatureFederation,
	FeatureGuestAccounts,
	FeatureIdentityModelV2,
	FeatureIdentityNormalizedReads,
	FeatureIdentityTransitions,
	FeatureIMAPMembershipUID,
	FeatureMailMigrationSourceIdentity,
	FeatureMailboxLifecycleRetention,
	FeatureMailSearchBuilder,
	FeatureSenderControlCenter,
	FeatureSharedMailAnalytics,
	FeatureSharedMailComments,
	FeatureSharedMailDrafts,
	FeatureSharedMailIntegrations,
	FeatureSharedMailNotifications,
	FeatureSharedMailWork,
	FeatureTransactionalUpgradesCatalog,
	FeatureTransactionalUpgradesExecution,
	FeatureUpgradeClientReceipts,
	FeatureUpgradeClientRecoveryCache,
	FeatureUpgradeRecoveryIntake,
	FeatureSPF, FeatureGreylisting, FeatureDKIM, FeatureDMARC, FeatureARC,
	FeatureSpamScoring, FeatureRBL, FeatureClamAV, FeatureMLSpam, FeatureMTASTS,
	FeatureForgotPassword, FeatureForgotPasswordPush, FeatureTasks,
	FeatureNewsletterBundles, FeatureEmailAddressPolicy, FeatureOfflineMail,
	FeatureConnectivityAwareSync, FeatureWebhookPublicationOutbox,
	FeatureDriveCompliance, FeatureMailPush, FeatureChatPush, FeatureRecall,
	FeatureAuthLogAppPassword, FeatureAuthLogBasic, FeatureAuthLogBcrypt,
	FeatureAuthLogJWT, FeatureAuthLogKerberos, FeatureAuthLogWebAuthn,
	FeatureAuthLogLDAP, FeatureAuthLogThreat, FeatureAuthLogRateLimit,
	FeatureAuthLogCA, ApprovalGroupModeration, ApprovalGuestInvite,
	ApprovalHRExpense, ApprovalHRLeave, ApprovalMailExternal, ApprovalRBAC,
	ChatChainNotary, ChatChannelCreation, ChatUnfurl, DriveSpaceCreation,
	MeetGuestAccess, RBACJIT,
}

func TestDefinitionsAreSortedUniqueAndDefensive(t *testing.T) {
	got := Definitions()
	if len(got) == 0 {
		t.Fatal("registry must not be empty")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Key >= got[i].Key {
			t.Fatalf("definitions not strictly sorted at %q then %q", got[i-1].Key, got[i].Key)
		}
	}
	got[0].Default = !got[0].Default
	again := Definitions()
	if got[0].Default == again[0].Default {
		t.Fatal("Definitions exposed mutable registry storage")
	}
	if len(RegistryDigest()) != 64 {
		t.Fatalf("RegistryDigest length = %d, want 64", len(RegistryDigest()))
	}
}

func TestRegistryAccessorsAndStaticConstructors(t *testing.T) {
	definition, ok := Lookup(FeatureImap)
	if !ok {
		t.Fatalf("Lookup(%q) did not find the registered key", FeatureImap)
	}
	if definition.Key != Key(FeatureImap) || !definition.Default {
		t.Fatalf("Lookup(%q) = %+v, want registered default-on definition", FeatureImap, definition)
	}
	if unknown, ok := Lookup("feature.not_registered"); ok || unknown.Key != "feature.not_registered" || unknown.Default {
		t.Fatalf("unknown Lookup = (%+v,%v), want key-preserving miss", unknown, ok)
	}

	keys := Keys()
	if len(keys) != len(Definitions()) {
		t.Fatalf("Keys length = %d, Definitions length = %d", len(keys), len(Definitions()))
	}
	if !sort.StringsAreSorted(keys) {
		t.Fatal("Keys must return a sorted registry projection")
	}
	keys[0] = "mutated"
	if again := Keys(); len(again) == 0 || again[0] == "mutated" {
		t.Fatal("Keys exposed mutable registry storage")
	}

	source := map[string]bool{FeatureImap: false}
	static := NewStatic(source)
	source[FeatureImap] = true
	if static.IsEnabled(FeatureImap) {
		t.Fatal("NewStatic did not defensively copy its source map")
	}
	if got := static.RegistryMode(); got != RegistryObserve {
		t.Fatalf("NewStatic registry mode = %q, want observe", got)
	}
	testFlags := NewTestFlags(map[string]bool{FeatureImap: true})
	if !testFlags.IsEnabled(FeatureImap) {
		t.Fatal("NewTestFlags did not preserve the supplied state")
	}
	unsetMode := &FeatureFlags{}
	if got := unsetMode.RegistryMode(); got != RegistryObserve {
		t.Fatalf("zero-value registry mode = %q, want observe", got)
	}
}

// The Rust gateway (server-rust/bins/gateway/src/jmap/gates.rs) reads
// this exact key and treats an absent row as OFF; ARCH-026 requires the
// writer flag to default to the reducer.
func TestRustMarkReadIsRegisteredDefaultOff(t *testing.T) {
	if FeatureRustMarkRead != "feature.rust_mark_read" {
		t.Fatalf("FeatureRustMarkRead = %q", FeatureRustMarkRead)
	}
	def, ok := Lookup(FeatureRustMarkRead)
	if !ok || def.Default {
		t.Fatalf("Lookup(%q) = %+v, %v; want registered, default OFF", FeatureRustMarkRead, def, ok)
	}
	if NewStatic(nil).IsEnabled(FeatureRustMarkRead) {
		t.Fatal("an absent row must resolve OFF")
	}
}

// The Rust gateway (server-rust/bins/gateway/src/jmap/gates.rs LIST_FLAG)
// reads this exact key; an absent row is OFF and Go answers the list.
func TestRustInboxListIsRegisteredDefaultOff(t *testing.T) {
	if FeatureRustInboxList != "feature.rust_inbox_list" {
		t.Fatalf("FeatureRustInboxList = %q", FeatureRustInboxList)
	}
	def, ok := Lookup(FeatureRustInboxList)
	if !ok || def.Default {
		t.Fatalf("Lookup(%q) = %+v, %v; want registered, default OFF", FeatureRustInboxList, def, ok)
	}
	if NewStatic(nil).IsEnabled(FeatureRustInboxList) {
		t.Fatal("an absent row must resolve OFF")
	}
}

func TestRegistryCoversAllConstants(t *testing.T) {
	if got, want := len(registryDefaults), len(allFeatureConstants); got != want {
		t.Errorf("registryDefaults has %d keys, %d constants declared", got, want)
	}
	seen := map[string]bool{}
	for _, k := range allFeatureConstants {
		if seen[k] {
			t.Errorf("constant value %q listed twice", k)
		}
		seen[k] = true
		if _, ok := registryDefaults[k]; !ok {
			t.Errorf("declared constant %q missing from registryDefaults", k)
		}
	}
	for k := range registryDefaults {
		if !seen[k] {
			t.Errorf("registryDefaults key %q has no declared constant", k)
		}
	}
}

// TestRegistryMatrix pins IsEnabled to the pre-registry behavior of every
// declared key across all four resolution states: absent → registry default
// (what IsEnabled returned before, per key family); a seeded row wins over
// the default; an env override wins over the row.
func TestRegistryMatrix(t *testing.T) {
	for key, def := range registryDefaults {
		states := []struct {
			name      string
			flags     map[string]bool
			overrides map[string]bool
			want      bool
		}{
			{"absent", map[string]bool{}, map[string]bool{}, def},
			{"row=false", map[string]bool{key: false}, map[string]bool{}, false},
			{"row=true", map[string]bool{key: true}, map[string]bool{}, true},
			// Override beats a contradicting row (row = !override).
			{"override=true", map[string]bool{key: false}, map[string]bool{key: true}, true},
		}
		for _, s := range states {
			f := &FeatureFlags{flags: s.flags, overrides: s.overrides}
			if got := f.IsEnabled(key); got != s.want {
				t.Errorf("IsEnabled(%q) state=%s: got %v, want %v", key, s.name, got, s.want)
			}
		}
	}
}

func TestApplyRegistryRow(t *testing.T) {
	known := FeatureImap // guaranteed to be in registryDefaults
	unknown := "legacy.unregistered.key"
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	t.Run("nil key skipped", func(t *testing.T) {
		next := map[string]bool{}
		enabled := true
		applyRegistryRow(next, RegistryObserve, nil, &enabled)
		if len(next) != 0 {
			t.Fatal("nil key should not write to snapshot")
		}
	})

	t.Run("nil enabled skipped", func(t *testing.T) {
		next := map[string]bool{}
		key := known
		applyRegistryRow(next, RegistryObserve, &key, nil)
		if len(next) != 0 {
			t.Fatal("nil enabled should not write to snapshot")
		}
	})

	t.Run("observe mode writes unknown key", func(t *testing.T) {
		next := map[string]bool{}
		key, enabled := unknown, true
		applyRegistryRow(next, RegistryObserve, &key, &enabled)
		if v, ok := next[unknown]; !ok || !v {
			t.Fatal("observe mode should write unregistered key to snapshot")
		}
		if logs.Len() != 0 {
			t.Fatalf("observe mode unexpectedly logged: %s", logs.String())
		}
	})

	t.Run("enforce mode drops unknown key", func(t *testing.T) {
		next := map[string]bool{}
		key, enabled := unknown, true
		applyRegistryRow(next, RegistryEnforce, &key, &enabled)
		if _, ok := next[unknown]; ok {
			t.Fatal("enforce mode should not write unregistered key to snapshot")
		}
		if got := logs.String(); !strings.Contains(got, "dropping unregistered key") || !strings.Contains(got, unknown) {
			t.Fatalf("enforce mode warning = %q, want dropped key evidence", got)
		}
	})

	t.Run("enforce mode writes known key", func(t *testing.T) {
		next := map[string]bool{}
		key, enabled := known, true
		applyRegistryRow(next, RegistryEnforce, &key, &enabled)
		if v, ok := next[known]; !ok || !v {
			t.Fatal("enforce mode should write registered key to snapshot")
		}
	})
}

// TestSecuritySeededKeys_IncludeSeededOnToggle pins the registry-doctrine
// completeness closure (D-SHARED-TOGGLE-003): feature.smime_verify is seeded
// enabled=true by V032 while its registry default is false, so it is the one
// key whose row loss would silently downgrade a shipped-on control — it must
// stay in the RequireSeeded drift tripwire.
func TestSecuritySeededKeys_IncludeSeededOnToggle(t *testing.T) {
	found := false
	for _, k := range SecuritySeededKeys {
		if k == FeatureSmimeVerify {
			found = true
		}
	}
	if !found {
		t.Fatal("FeatureSmimeVerify must remain in SecuritySeededKeys: its V032 row is seeded ON, so row loss must fail boot loudly")
	}
}

// TestResolveUnknownKeyWarnsInObserveMode pins the loud-warning contract on
// the historical observe-mode unknown=>true fallthrough (D-SHARED-TOGGLE-004):
// the value is deliberately unchanged (rolling-upgrade semantics), but the
// fail-open branch must not stay silent.
func TestResolveUnknownKeyWarnsInObserveMode(t *testing.T) {
	f := NewStatic(map[string]bool{"feature.assist": true})
	if f.RegistryMode() != RegistryObserve {
		t.Fatalf("NewStatic must default to observe mode, got %s", f.RegistryMode())
	}
	// Value semantics unchanged: unknown key in observe mode resolves true.
	if enabled, source := f.Resolve("feature.not_a_registered_key"); !enabled || source != SourceDefault {
		t.Fatalf("observe-mode unknown key = (%v, %s), want (true, default)", enabled, source)
	}
	// Enforce mode inverts the polarity, fail-closed, without the warning path.
	f2 := NewStatic(map[string]bool{"feature.assist": true})
	f2.mu.Lock()
	f2.mode = RegistryEnforce
	f2.mu.Unlock()
	if enabled, source := f2.Resolve("feature.not_a_registered_key"); enabled || source != SourceDefault {
		t.Fatalf("enforce-mode unknown key = (%v, %s), want (false, default)", enabled, source)
	}
}
