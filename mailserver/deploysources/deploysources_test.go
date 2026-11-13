package deploysources

import "testing"

func TestPublicReadOnlyProjectionAliases(t *testing.T) {
	resolved, err := ResolveCollabora(ProfileInput{Profile: string(ProfileGlobal)})
	if err != nil || resolved.Repository == "" {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	posture := ProjectExternalProviders(ExternalProviderInput{})
	if len(posture) == 0 {
		t.Fatal("external provider posture is empty")
	}
	inventory := InspectUbuntu(t.TempDir())
	if inventory.Architecture == "" {
		t.Fatalf("inventory=%+v", inventory)
	}
}
