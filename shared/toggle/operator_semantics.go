package toggle

import "fmt"

// ChangeMode describes how a running process observes a toggle change. It is
// operator-facing metadata, not runtime behavior and is deliberately excluded
// from RegistryDigest and generated database classification.
type ChangeMode string

const (
	ChangeLive       ChangeMode = "live"
	ChangeDisconnect ChangeMode = "disconnect-live-clients"
)

// DisableBehavior distinguishes admission gates from already-accepted work.
type DisableBehavior string

const (
	DisableImmediate DisableBehavior = "immediate"
	DisableDrain     DisableBehavior = "stop-admission-drain-existing"
)

// OperatorSemantics is the additive operator projection for one registered
// feature. Zero values mean no special warning, dependency, or confirmation.
type OperatorSemantics struct {
	Key                  Key             `json:"key"`
	ChangeMode           ChangeMode      `json:"changeMode"`
	DisableBehavior      DisableBehavior `json:"disableBehavior"`
	Dependencies         []Key           `json:"dependencies,omitempty"`
	ConfirmationRequired bool            `json:"confirmationRequired"`
}

var operatorSemantics = map[Key]OperatorSemantics{
	Key(FeatureImap):           {Key: Key(FeatureImap), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},
	Key(FeatureSmtpInbound):    {Key: Key(FeatureSmtpInbound), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},
	Key(FeatureSmtpSubmission): {Key: Key(FeatureSmtpSubmission), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},
	Key(FeatureLdapGal):        {Key: Key(FeatureLdapGal), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},
	Key(FeatureCaldav):         {Key: Key(FeatureCaldav), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},
	Key(FeatureCarddav):        {Key: Key(FeatureCarddav), ChangeMode: ChangeDisconnect, DisableBehavior: DisableImmediate},

	Key(FeatureConditionalAccess):      {Key: Key(FeatureConditionalAccess), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureDeviceTrustEnforcement): {Key: Key(FeatureDeviceTrustEnforcement), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureCAERuntime):             {Key: Key(FeatureCAERuntime), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureDeviceLockdown):         {Key: Key(FeatureDeviceLockdown), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureRequireMFA):             {Key: Key(FeatureRequireMFA), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureDisableBasicAuth):       {Key: Key(FeatureDisableBasicAuth), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureTokenBinding):           {Key: Key(FeatureTokenBinding), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},
	Key(FeatureUserRisk):               {Key: Key(FeatureUserRisk), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate, ConfirmationRequired: true},

	// Meet recording/captions and the document-presentation family (MEET
	// plan "Rollout and rollback"): disabling a start path must drain/
	// finalize accepted renditions, presentations, recordings, exports,
	// cleanup and retention work — never strand them. Presentation
	// additionally depends on Drive: its sources are Drive versions, never
	// a second Meet file store.
	Key(FeatureMeetRecording):            {Key: Key(FeatureMeetRecording), ChangeMode: ChangeLive, DisableBehavior: DisableDrain, Dependencies: []Key{Key(FeatureMeet)}},
	Key(FeatureMeetCaptions):             {Key: Key(FeatureMeetCaptions), ChangeMode: ChangeLive, DisableBehavior: DisableDrain, Dependencies: []Key{Key(FeatureMeet)}},
	Key(FeatureMeetDocumentPresentation): {Key: Key(FeatureMeetDocumentPresentation), ChangeMode: ChangeLive, DisableBehavior: DisableDrain, Dependencies: []Key{Key(FeatureMeet), Key(FeatureDrive)}},
	Key(FeatureMeetSemanticRecording):    {Key: Key(FeatureMeetSemanticRecording), ChangeMode: ChangeLive, DisableBehavior: DisableDrain, Dependencies: []Key{Key(FeatureMeet)}},
	Key(FeatureMeetLocalRecording):       {Key: Key(FeatureMeetLocalRecording), ChangeMode: ChangeLive, DisableBehavior: DisableDrain, Dependencies: []Key{Key(FeatureMeet)}},
	Key(FeatureWebhookPublicationOutbox): {Key: Key(FeatureWebhookPublicationOutbox), ChangeMode: ChangeLive, DisableBehavior: DisableDrain},
}

// LookupOperatorSemantics returns a defensive copy. Metadata remains separate
// from Definition so behavior/release registry digests stay byte-compatible.
func LookupOperatorSemantics(key string) (OperatorSemantics, bool) {
	semantics, ok := operatorSemantics[Key(key)]
	if !ok {
		return OperatorSemantics{}, false
	}
	semantics.Dependencies = append([]Key(nil), semantics.Dependencies...)
	return semantics, true
}

// ValidateOperatorSemantics proves that metadata and dependencies reference
// the finite behavior registry and use supported dimensions.
func ValidateOperatorSemantics() error {
	return validateOperatorSemantics(operatorSemantics)
}

func validateOperatorSemantics(catalog map[Key]OperatorSemantics) error {
	for key, semantics := range catalog {
		if !isRegistered(string(key)) || semantics.Key != key {
			return fmt.Errorf("operator semantics key %q is not a matching registered feature", key)
		}
		if semantics.ChangeMode != ChangeLive && semantics.ChangeMode != ChangeDisconnect {
			return fmt.Errorf("operator semantics key %q has invalid change mode %q", key, semantics.ChangeMode)
		}
		if semantics.DisableBehavior != DisableImmediate && semantics.DisableBehavior != DisableDrain {
			return fmt.Errorf("operator semantics key %q has invalid disable behavior %q", key, semantics.DisableBehavior)
		}
		for _, dependency := range semantics.Dependencies {
			if !isRegistered(string(dependency)) {
				return fmt.Errorf("operator semantics key %q references unknown dependency %q", key, dependency)
			}
			if dependency == key {
				return fmt.Errorf("operator semantics key %q depends on itself", key)
			}
		}
	}
	return nil
}
