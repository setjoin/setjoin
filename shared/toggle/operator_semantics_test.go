package toggle

import (
	"reflect"
	"testing"
)

func TestOperatorSemanticsAreValidAndDoNotChangeBehaviorDigest(t *testing.T) {
	before := RegistryDigest()
	if err := ValidateOperatorSemantics(); err != nil {
		t.Fatal(err)
	}
	original := operatorSemantics[Key(FeatureImap)]
	operatorSemantics[Key(FeatureImap)] = OperatorSemantics{
		Key: Key(FeatureImap), ChangeMode: ChangeLive, DisableBehavior: DisableDrain,
	}
	t.Cleanup(func() { operatorSemantics[Key(FeatureImap)] = original })
	after := RegistryDigest()
	if before != after {
		t.Fatalf("operator metadata changed behavior digest: %s -> %s", before, after)
	}
}

func TestOperatorSemanticsOwnListenerSecurityAndDrainProjection(t *testing.T) {
	for _, key := range []string{FeatureImap, FeatureSmtpInbound, FeatureSmtpSubmission, FeatureLdapGal, FeatureCaldav, FeatureCarddav} {
		semantics, ok := LookupOperatorSemantics(key)
		if !ok || semantics.ChangeMode != ChangeDisconnect {
			t.Fatalf("%s listener semantics = %+v, %v", key, semantics, ok)
		}
	}
	for _, key := range []string{FeatureConditionalAccess, FeatureDeviceTrustEnforcement, FeatureCAERuntime, FeatureDeviceLockdown, FeatureRequireMFA, FeatureDisableBasicAuth, FeatureTokenBinding, FeatureUserRisk} {
		semantics, ok := LookupOperatorSemantics(key)
		if !ok || !semantics.ConfirmationRequired {
			t.Fatalf("%s confirmation semantics = %+v, %v", key, semantics, ok)
		}
	}
	for _, key := range []string{FeatureMeetRecording, FeatureMeetCaptions, FeatureWebhookPublicationOutbox} {
		semantics, ok := LookupOperatorSemantics(key)
		if !ok || semantics.DisableBehavior != DisableDrain {
			t.Fatalf("%s drain semantics = %+v, %v", key, semantics, ok)
		}
	}
	for _, key := range []string{FeatureMeetRecording, FeatureMeetCaptions} {
		semantics, _ := LookupOperatorSemantics(key)
		if !reflect.DeepEqual(semantics.Dependencies, []Key{Key(FeatureMeet)}) {
			t.Fatalf("%s dependencies = %+v", key, semantics.Dependencies)
		}
	}
	first, _ := LookupOperatorSemantics(FeatureMeetRecording)
	first.Dependencies[0] = Key("mutated")
	second, _ := LookupOperatorSemantics(FeatureMeetRecording)
	if second.Dependencies[0] != Key(FeatureMeet) {
		t.Fatal("lookup did not return defensive dependency copy")
	}
	if semantics, ok := LookupOperatorSemantics("feature.no_metadata"); ok || !reflect.DeepEqual(semantics, OperatorSemantics{}) {
		t.Fatalf("unknown metadata lookup = %+v, %v", semantics, ok)
	}
}

func TestValidateOperatorSemanticsRejectsPlantedMutants(t *testing.T) {
	for name, mutant := range map[string]OperatorSemantics{
		"unknown key": {
			Key: Key("feature.not_registered"), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate,
		},
		"unknown dependency": {
			Key: Key(FeatureImap), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate,
			Dependencies: []Key{Key("feature.not_registered")},
		},
		"self dependency": {
			Key: Key(FeatureImap), ChangeMode: ChangeLive, DisableBehavior: DisableImmediate,
			Dependencies: []Key{Key(FeatureImap)},
		},
		"invalid change mode": {
			Key: Key(FeatureImap), ChangeMode: ChangeMode("restart-maybe"), DisableBehavior: DisableImmediate,
		},
		"invalid disable behavior": {
			Key: Key(FeatureImap), ChangeMode: ChangeLive, DisableBehavior: DisableBehavior("drop-residue"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			catalog := map[Key]OperatorSemantics{mutant.Key: mutant}
			if err := validateOperatorSemantics(catalog); err == nil {
				t.Fatal("planted invalid operator metadata was accepted")
			}
		})
	}
}
