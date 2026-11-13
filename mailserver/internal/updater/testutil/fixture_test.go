package testutil

import (
	"testing"
	"time"

	"setjoin.com/shared/release"
)

func TestFixtureTrustIsDeterministicAndProductionRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	first, key, err := SignedManifest(now, release.ChannelCommunity)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := SignedManifest(now, release.ChannelCommunity)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("fixture manifest is not byte-deterministic")
	}
	if _, err := release.NewTrustStore([]release.TrustedKey{key}, false); err == nil {
		t.Fatal("production trust policy accepted fixture root")
	}
	store, err := release.NewTrustStore([]release.TrustedKey{key}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyManifest(first, release.VerifyManifestOptions{Now: now,
		Channel: release.ChannelCommunity, CurrentVersion: "2.0.5",
		Platform: "linux", Architecture: "amd64"}); err != nil {
		t.Fatal(err)
	}
}
