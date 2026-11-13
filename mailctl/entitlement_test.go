package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"setjoin.com/shared/release"
)

func writeEntitlementFixture(t *testing.T, dir, installationID string) (source, destination string) {
	t.Helper()
	seed := bytes.Repeat([]byte{0x33}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	entitlement := &release.Entitlement{
		SchemaVersion: release.EntitlementSchemaV1, EntitlementID: "ent-2026", InstallationID: installationID, CustomerID: "customer-a",
		Channels: []release.Channel{release.ChannelEnterprise}, VersionRanges: []string{">=2.0.0 <3.0.0"},
		IssuedAt: "2026-08-01T00:00:00Z", ValidFrom: "2026-08-01T00:00:00Z", ValidUntil: "2026-08-31T00:00:00Z", GraceUntil: "2026-09-07T00:00:00Z",
		NonProductionRights: []string{"dr", "staging"}, KeyID: "entitlement-a",
	}
	if err := release.SignEntitlement(entitlement, release.Ed25519Signer{ID: "entitlement-a", PrivateKey: private}); err != nil {
		t.Fatal(err)
	}
	raw, err := release.MarshalEntitlement(entitlement)
	if err != nil {
		t.Fatal(err)
	}
	source = filepath.Join(dir, "candidate.json")
	if err := os.WriteFile(source, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	trust := release.TrustRootDocument{SchemaVersion: 1, Purpose: release.PurposeEntitlement, Keys: []release.TrustRootWire{{ID: "entitlement-a", Algorithm: "ed25519", PublicKey: base64.RawStdEncoding.EncodeToString(public)}}}
	trustRaw, _ := json.Marshal(trust)
	trustPath := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, trustRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	installPath := filepath.Join(dir, "installation-id")
	if err := os.WriteFile(installPath, []byte("install-a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	channelPath := filepath.Join(dir, "update-channel")
	if err := os.WriteFile(channelPath, []byte("enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destination = filepath.Join(dir, "installed.json")
	t.Setenv("SETJOIN_ENTITLEMENT_PATH", destination)
	t.Setenv("SETJOIN_ENTITLEMENT_TRUST_ROOTS", trustPath)
	t.Setenv("SETJOIN_INSTALLATION_ID_FILE", installPath)
	t.Setenv("SETJOIN_UPDATE_CHANNEL_FILE", channelPath)
	return source, destination
}

func withEntitlementClock(t *testing.T) {
	t.Helper()
	prior := entitlementNow
	entitlementNow = func() time.Time { return time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { entitlementNow = prior })
}

func TestEntitlementImportAndShowAreVerifiedAtomicAndSanitized(t *testing.T) {
	withEntitlementClock(t)
	source, destination := writeEntitlementFixture(t, t.TempDir(), "install-a")
	out := captureStdout(t, func() {
		if err := runEntitlement(&cmdCtx{}, "import", []string{source, "--json"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"state": "valid"`) || strings.Contains(out, "signature") || strings.Contains(out, "public_key") {
		t.Fatalf("sanitized JSON=%s", out)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
	show := captureStdout(t, func() {
		if err := runEntitlement(&cmdCtx{}, "show", nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(show, "Entitlement installed: ent-2026") || !strings.Contains(show, "Channel:             enterprise") {
		t.Fatalf("show=%s", show)
	}
}

func TestEntitlementImportRejectsScopeAndPreservesInstalledFileOnReplaceFailure(t *testing.T) {
	withEntitlementClock(t)
	source, destination := writeEntitlementFixture(t, t.TempDir(), "wrong-installation")
	if err := runEntitlement(&cmdCtx{}, "import", []string{source}); err == nil || !strings.Contains(err.Error(), "installation scope mismatch") {
		t.Fatalf("scope error=%v", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("destination changed after rejected import: %v", err)
	}

	source, destination = writeEntitlementFixture(t, t.TempDir(), "install-a")
	if err := os.WriteFile(destination, []byte("old-entitlement"), 0o600); err != nil {
		t.Fatal(err)
	}
	prior := entitlementAtomicReplace
	entitlementAtomicReplace = func(string, []byte) error { return errors.New("simulated fsync failure") }
	t.Cleanup(func() { entitlementAtomicReplace = prior })
	if err := runEntitlement(&cmdCtx{}, "import", []string{source}); err == nil || !strings.Contains(err.Error(), "simulated fsync failure") {
		t.Fatalf("replace error=%v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old-entitlement" {
		t.Fatalf("installed document changed: %q", got)
	}
}

func TestEntitlementImportBoundsAndFlags(t *testing.T) {
	withEntitlementClock(t)
	_, _ = writeEntitlementFixture(t, t.TempDir(), "install-a")
	oversized := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte("x"), release.MaxDocumentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runEntitlement(&cmdCtx{}, "import", []string{oversized}); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error=%v", err)
	}
	if err := runEntitlement(&cmdCtx{}, "show", []string{"--secret"}); err == nil || !strings.Contains(err.Error(), "unknown entitlement flag") {
		t.Fatalf("flag error=%v", err)
	}
}

func TestEntitlementCommandAndLocalScopeBoundaries(t *testing.T) {
	withEntitlementClock(t)
	source, _ := writeEntitlementFixture(t, t.TempDir(), "install-a")
	for _, tc := range []struct {
		action string
		args   []string
	}{
		{"import", nil}, {"import", []string{source, source}},
		{"show", []string{"unexpected"}}, {"future", nil},
	} {
		if err := runEntitlement(&cmdCtx{}, tc.action, tc.args); err == nil {
			t.Fatalf("%s %v accepted", tc.action, tc.args)
		}
	}
	channelPath := updateChannelPath()
	if err := os.WriteFile(channelPath, []byte("community\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "enterprise channel") {
		t.Fatalf("community import error=%v", err)
	}
	if err := os.WriteFile(channelPath, []byte("enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installationIDPath(), []byte("bad/id\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "installation id") {
		t.Fatalf("invalid installation error=%v", err)
	}
}

func TestEntitlementVerificationInputFailures(t *testing.T) {
	withEntitlementClock(t)
	dir := t.TempDir()
	source, _ := writeEntitlementFixture(t, dir, "install-a")
	trustPath := entitlementTrustRootsPath()
	installPath := installationIDPath()
	channelPath := updateChannelPath()
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "read entitlement") {
		t.Fatalf("missing source=%v", err)
	}
	source, _ = writeEntitlementFixture(t, dir, "install-a")
	if err := os.Remove(trustPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "trust roots") {
		t.Fatalf("missing trust=%v", err)
	}
	_, _ = writeEntitlementFixture(t, dir, "install-a")
	if err := os.WriteFile(trustPath, []byte(`{"schema_version":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil {
		t.Fatal("malformed trust roots accepted")
	}
	_, _ = writeEntitlementFixture(t, dir, "install-a")
	if err := os.Remove(installPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "installation id") {
		t.Fatalf("missing installation=%v", err)
	}
	_, _ = writeEntitlementFixture(t, dir, "install-a")
	if err := os.Remove(channelPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil || !strings.Contains(err.Error(), "update channel") {
		t.Fatalf("missing channel=%v", err)
	}
	_, _ = writeEntitlementFixture(t, dir, "install-a")
	if err := os.WriteFile(source, []byte(`{"bad":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyEntitlementFile(source); err == nil {
		t.Fatal("invalid entitlement accepted")
	}
}

func TestEntitlementFileHelpersAreBoundedAndAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "value")
	if got := envOr("SETJOIN_MISSING_FIXTURE", "fallback"); got != "fallback" {
		t.Fatalf("fallback=%q", got)
	}
	t.Setenv("SETJOIN_PRESENT_FIXTURE", "configured")
	if got := envOr("SETJOIN_PRESENT_FIXTURE", "fallback"); got != "configured" {
		t.Fatalf("configured=%q", got)
	}
	if _, err := readBoundedFile(filepath.Join(dir, "missing"), 1); err == nil {
		t.Fatal("missing file accepted")
	}
	if err := os.WriteFile(path, []byte("abcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(path, 3); err == nil {
		t.Fatal("oversized file accepted")
	}
	for _, value := range []string{"", "bad/id", strings.Repeat("x", 129), "two words", "line\nbreak"} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBoundedText(path); err == nil {
			t.Fatalf("identifier %q accepted", value)
		}
	}
	if !identifierText("valid_ID-1.example") || identifierText("bad/id") {
		t.Fatal("identifier classifier drift")
	}
	destination := filepath.Join(dir, "entitlement.json")
	if err := atomicReplaceEntitlement(destination, []byte("signed")); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(destination); err != nil || string(raw) != "signed" {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	if info, err := os.Stat(destination); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%v err=%v", info.Mode().Perm(), err)
	}
	if err := atomicReplaceEntitlement(filepath.Join(dir, "missing", "entitlement.json"), []byte("x")); err == nil {
		t.Fatal("missing destination directory accepted")
	}
}
