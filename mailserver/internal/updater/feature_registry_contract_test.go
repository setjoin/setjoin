package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"setjoin.com/shared/release"
	"setjoin.com/shared/toggle"
)

func registryManifest(schema int, digest string, modes, rollbackDigests []string) *release.Manifest {
	manifest := &release.Manifest{SchemaFrom: schema, SchemaTo: schema}
	if digest != "" {
		manifest.FeatureRegistry = &release.FeatureRegistryContract{
			CatalogDigest: digest, CompatibleModes: modes,
			CompatibleRollbackDigests: rollbackDigests,
		}
	}
	return manifest
}

func TestPGFeatureRegistryStateReadsInstalledV183(t *testing.T) {
	dsn := os.Getenv("DB_OWNER_DSN")
	if dsn == "" {
		dsn = os.Getenv("DB_DSN")
	}
	if dsn == "" {
		t.Skip("DB_OWNER_DSN/DB_DSN not set")
	}
	connection, err := OpenPGMigrationConnection(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	state, err := connection.FeatureRegistryState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !state.Present || state.Mode != "observe" || state.CatalogDigest != toggle.RegistryDigest() || state.UnknownRows < 0 {
		t.Fatalf("registry state=%#v want present observe digest=%s", state, toggle.RegistryDigest())
	}
}

func TestFeatureRegistryContractPreflightPostCommitAndRollback(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	observe := FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestA, UnknownRows: 2}
	enforce := FeatureRegistryState{Present: true, Mode: "enforce", CatalogDigest: digestA}
	current := registryManifest(183, digestA, []string{"enforce", "observe"}, []string{digestA})
	rollback := registryManifest(183, digestA, []string{"enforce", "observe"}, []string{digestA})

	if err := checkFeatureRegistryContract(current, rollback, observe, featureRegistryPreflight); err != nil {
		t.Fatalf("observe preflight: %v", err)
	}
	if err := checkFeatureRegistryContract(current, rollback, enforce, featureRegistryPreflight); err != nil {
		t.Fatalf("enforce preflight: %v", err)
	}
	if err := checkFeatureRegistryContract(current, rollback, enforce, featureRegistryPostCommit); err != nil {
		t.Fatalf("enforce post-commit: %v", err)
	}

	changed := registryManifest(184, digestB, []string{"enforce", "observe"}, []string{digestA, digestB})
	if err := checkFeatureRegistryContract(changed, rollback, observe, featureRegistryPreflight); err != nil {
		t.Fatalf("observe digest migration preflight: %v", err)
	}
	if err := checkFeatureRegistryContract(changed, rollback, enforce, featureRegistryPreflight); err == nil {
		t.Fatal("enforce digest migration was accepted")
	}
	if err := checkFeatureRegistryContract(changed, rollback, observe, featureRegistryPostCommit); err == nil {
		t.Fatal("post-commit digest mismatch was accepted")
	}
	postChanged := FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestB}
	if err := checkFeatureRegistryContract(changed, rollback, postChanged, featureRegistryPostCommit); err != nil {
		t.Fatalf("post-commit target digest: %v", err)
	}

	unknownEnforce := enforce
	unknownEnforce.UnknownRows = 1
	if err := checkFeatureRegistryContract(current, rollback, unknownEnforce, featureRegistryPostCommit); err == nil {
		t.Fatal("enforce with unknown rows was accepted")
	}
	if err := checkFeatureRegistryContract(current, nil, enforce, featureRegistryPreflight); err == nil {
		t.Fatal("enforce without rollback cohort was accepted")
	}
	if err := checkFeatureRegistryContract(registryManifest(182, "", nil, nil), current,
		FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestA}, featureRegistryRollback); err != nil {
		t.Fatalf("observe rollback to pre-V183 cohort: %v", err)
	}
	if err := checkFeatureRegistryContract(registryManifest(182, "", nil, nil), current,
		enforce, featureRegistryRollback); err == nil {
		t.Fatal("enforce rollback to pre-V183 cohort was accepted")
	}
	initial := registryManifest(183, digestA, []string{"observe"}, []string{digestA})
	initial.SchemaFrom = 182
	if err := checkFeatureRegistryContract(initial, nil, FeatureRegistryState{}, featureRegistryPreflight); err != nil {
		t.Fatalf("initial V183 observe expansion: %v", err)
	}
}

func TestFeatureRegistryContractRejectsEveryIncompatibleBoundary(t *testing.T) {
	digestA := strings.Repeat("a", 64)
	digestB := strings.Repeat("b", 64)
	observe := FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestA}
	enforce := FeatureRegistryState{Present: true, Mode: "enforce", CatalogDigest: digestA}
	compatible := registryManifest(183, digestA, []string{"enforce", "observe"}, []string{digestA})
	rollback := registryManifest(183, digestA, []string{"enforce", "observe"}, []string{digestA})

	tests := []struct {
		name     string
		target   *release.Manifest
		rollback *release.Manifest
		state    FeatureRegistryState
		phase    featureRegistryPhase
		wantErr  bool
	}{
		{"nil target", nil, nil, observe, featureRegistryPreflight, true},
		{"missing state", compatible, rollback, FeatureRegistryState{}, featureRegistryPostCommit, true},
		{"legacy absent state", registryManifest(182, "", nil, nil), nil, FeatureRegistryState{}, featureRegistryPreflight, false},
		{"bad mode", compatible, rollback, FeatureRegistryState{Present: true, Mode: "bad", CatalogDigest: digestA}, featureRegistryPreflight, true},
		{"missing contract", registryManifest(182, "", nil, nil), rollback, observe, featureRegistryPreflight, true},
		{"legacy rollback observe", registryManifest(182, "", nil, nil), rollback, observe, featureRegistryRollback, false},
		{"mode unsupported", registryManifest(183, digestA, []string{"observe"}, []string{digestA}), rollback, enforce, featureRegistryPreflight, true},
		{"negative unknown rows", compatible, rollback, FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestA, UnknownRows: -1}, featureRegistryPreflight, true},
		{"live digest undeclared", compatible, rollback, FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digestB}, featureRegistryPreflight, true},
		{"rollback digest undeclared", compatible, registryManifest(183, digestB, []string{"observe"}, []string{digestB}), observe, featureRegistryPreflight, true},
		{"enforce changed digest", registryManifest(184, digestB, []string{"enforce", "observe"}, []string{digestA, digestB}), rollback, enforce, featureRegistryPreflight, true},
		{"enforce rollback unsupported", compatible, registryManifest(183, digestA, []string{"observe"}, []string{digestA}), enforce, featureRegistryPreflight, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFeatureRegistryContract(tc.target, tc.rollback, tc.state, tc.phase)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func writeInstalledRegistryManifest(t *testing.T, root, link, releaseID string) string {
	t.Helper()
	manifest := minimalManifest()
	manifest.ReleaseID = releaseID
	manifest.SchemaFrom, manifest.SchemaTo = 183, 183
	digest := strings.Repeat("a", 64)
	manifest.FeatureRegistry = &release.FeatureRegistryContract{
		CatalogDigest: digest, CompatibleModes: []string{"enforce", "observe"},
		CompatibleRollbackDigests: []string{digest},
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "releases", releaseID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("releases", releaseID), filepath.Join(root, link)); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadInstalledManifestAcceptsImmutableFileAndRejectsBoundaries(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		root := t.TempDir()
		writeInstalledRegistryManifest(t, root, "current", "release-a")
		manifest, err := readInstalledManifest(root, "current")
		if err != nil || manifest == nil || manifest.ReleaseID != "release-a" {
			t.Fatalf("manifest=%#v err=%v", manifest, err)
		}
	})
	t.Run("manifest absent", func(t *testing.T) {
		root := t.TempDir()
		dir := filepath.Join(root, "releases", "release-a")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("releases", "release-a"), filepath.Join(root, "current")); err != nil {
			t.Fatal(err)
		}
		manifest, err := readInstalledManifest(root, "current")
		if err != nil || manifest != nil {
			t.Fatalf("manifest=%#v err=%v", manifest, err)
		}
	})
	t.Run("missing link", func(t *testing.T) {
		if _, err := readInstalledManifest(t.TempDir(), "current"); err == nil {
			t.Fatal("missing current link accepted")
		}
	})
	t.Run("insecure mode", func(t *testing.T) {
		root := t.TempDir()
		path := writeInstalledRegistryManifest(t, root, "current", "release-a")
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		if _, err := readInstalledManifest(root, "current"); !errors.Is(err, ErrFeatureRegistryContract) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("invalid document", func(t *testing.T) {
		root := t.TempDir()
		path := writeInstalledRegistryManifest(t, root, "current", "release-a")
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readInstalledManifest(root, "current"); !errors.Is(err, ErrFeatureRegistryContract) {
			t.Fatalf("error=%v", err)
		}
	})
	t.Run("identity mismatch", func(t *testing.T) {
		root := t.TempDir()
		path := writeInstalledRegistryManifest(t, root, "current", "release-a")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var manifest release.Manifest
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.ReleaseID = "release-b"
		raw, err = json.Marshal(&manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readInstalledManifest(root, "current"); !errors.Is(err, ErrFeatureRegistryContract) {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestVerifyFeatureRegistryCompatibilityBranches(t *testing.T) {
	legacy := registryManifest(182, "", nil, nil)
	adapter := &U2Adapter{}
	state, err := adapter.verifyFeatureRegistryCompatibility(t.Context(), legacy, "previous", featureRegistryPreflight)
	if err != nil || state.Present {
		t.Fatalf("legacy state=%#v err=%v", state, err)
	}
	digest := strings.Repeat("a", 64)
	target := registryManifest(183, digest, []string{"enforce", "observe"}, []string{digest})
	if _, err := adapter.verifyFeatureRegistryCompatibility(t.Context(), target, "previous", featureRegistryPreflight); !errors.Is(err, ErrFeatureRegistryContract) {
		t.Fatalf("missing reader error=%v", err)
	}
	adapter.FeatureRegistry = fixedRegistryReader{err: errors.New("reader failed")}
	if _, err := adapter.verifyFeatureRegistryCompatibility(t.Context(), target, "previous", featureRegistryPreflight); err == nil || err.Error() != "reader failed" {
		t.Fatalf("reader error=%v", err)
	}
	adapter.FeatureRegistry = fixedRegistryReader{state: FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digest}}
	adapter.InstallRoot = t.TempDir()
	if _, err := adapter.verifyFeatureRegistryCompatibility(t.Context(), target, "previous", featureRegistryPreflight); err == nil {
		t.Fatal("missing rollback slot accepted")
	}
	root := t.TempDir()
	writeInstalledRegistryManifest(t, root, "previous", "release-a")
	adapter.InstallRoot = root
	state, err = adapter.verifyFeatureRegistryCompatibility(t.Context(), target, "previous", featureRegistryPreflight)
	if err != nil || !state.Present || state.CatalogDigest != digest {
		t.Fatalf("state=%#v err=%v", state, err)
	}
	adapter.FeatureRegistry = fixedRegistryReader{state: FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: strings.Repeat("b", 64)}}
	if _, err := adapter.verifyFeatureRegistryCompatibility(t.Context(), target, "previous", featureRegistryPreflight); !errors.Is(err, ErrFeatureRegistryContract) {
		t.Fatalf("incompatible state error=%v", err)
	}
}

func TestRollbackVerifiesFeatureRegistryCohorts(t *testing.T) {
	root := t.TempDir()
	writeInstalledRegistryManifest(t, root, "current", "release-a")
	writeInstalledRegistryManifest(t, root, "previous", "release-b")
	digest := strings.Repeat("a", 64)
	host := &fakeHostOperations{}
	adapter := &U2Adapter{
		InstallRoot: root,
		Host:        host,
		FeatureRegistry: fixedRegistryReader{state: FeatureRegistryState{
			Present: true, Mode: "observe", CatalogDigest: digest,
		}},
	}
	evidence, err := adapter.Rollback(t.Context(), Transaction{ReleaseID: "failed-release"}, Event{}, Step{Name: "commit_checks"}, errors.New("failed"))
	if err != nil || !json.Valid(evidence) || !strings.Contains(string(evidence), `"feature_registry"`) {
		t.Fatalf("evidence=%s err=%v", evidence, err)
	}
	if got := strings.Join(host.calls, ","); got != "start,readiness,data,post_commit" {
		t.Fatalf("host calls=%s", got)
	}
	adapter.FeatureRegistry = fixedRegistryReader{err: errors.New("registry read failed")}
	if _, err := adapter.Rollback(t.Context(), Transaction{ReleaseID: "failed-release"}, Event{}, Step{Name: "commit_checks"}, errors.New("failed")); err == nil || err.Error() != "registry read failed" {
		t.Fatalf("reader error=%v", err)
	}
}

func TestFeatureRegistryStepAndRollbackFailuresRemainFailClosed(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: '0', data: "ok"})
	storeRoot, releaseID, _, manifest := writeStageFixture(t, archive)
	digest := strings.Repeat("a", 64)
	manifest.SchemaFrom, manifest.SchemaTo = 183, 183
	manifest.Migrations = nil
	manifest.FeatureRegistry = &release.FeatureRegistryContract{
		CatalogDigest: digest, CompatibleModes: []string{"enforce", "observe"},
		CompatibleRollbackDigests: []string{digest},
	}
	manifestDigest := rewriteStageManifest(t, storeRoot, releaseID, manifest)
	store, err := OpenReleaseStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeHostOperations{}
	adapter := &U2Adapter{
		Store: store, InstallRoot: t.TempDir(),
		Migration: MigrationRunner{DB: &fakeMigrationDB{}}, Host: host,
		FeatureRegistry: fixedRegistryReader{err: errors.New("registry unavailable")},
	}
	steps, err := adapter.Steps()
	if err != nil {
		t.Fatal(err)
	}
	stepByName := func(name string) Step {
		t.Helper()
		for _, step := range steps {
			if step.Name == name {
				return step
			}
		}
		t.Fatalf("step %q not found", name)
		return Step{}
	}
	badTransaction := Transaction{ReleaseID: releaseID, ManifestDigest: strings.Repeat("0", 64)}
	if _, err := stepByName("preflight").Run(t.Context(), badTransaction); err == nil {
		t.Fatal("preflight accepted a release with the wrong manifest digest")
	}
	if _, err := stepByName("commit_checks").Run(t.Context(), badTransaction); err == nil {
		t.Fatal("commit checks accepted a release with the wrong manifest digest")
	}
	validTransaction := Transaction{ReleaseID: releaseID, ManifestDigest: manifestDigest}
	if _, err := stepByName("commit_checks").Run(t.Context(), validTransaction); err == nil || err.Error() != "registry unavailable" {
		t.Fatalf("commit registry read error=%v", err)
	}

	state := fixedRegistryReader{state: FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: digest}}
	for _, test := range []struct {
		name          string
		invalidSlot   string
		registryState fixedRegistryReader
	}{
		{name: "invalid current manifest", invalidSlot: "current", registryState: state},
		{name: "invalid previous manifest", invalidSlot: "previous", registryState: state},
		{name: "incompatible cohort", registryState: fixedRegistryReader{state: FeatureRegistryState{Present: true, Mode: "observe", CatalogDigest: strings.Repeat("b", 64)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			for _, slot := range []string{"current", "previous"} {
				releaseID := "release-" + slot
				manifestPath := writeInstalledRegistryManifest(t, root, slot, releaseID)
				if slot == test.invalidSlot {
					if err := os.Chmod(manifestPath, 0o666); err != nil {
						t.Fatal(err)
					}
				}
			}
			rollback := &U2Adapter{InstallRoot: root, Host: &fakeHostOperations{}, FeatureRegistry: test.registryState}
			if _, err := rollback.Rollback(t.Context(), Transaction{ReleaseID: "failed-release"}, Event{}, Step{Name: "commit_checks"}, errors.New("failed")); err == nil {
				t.Fatal("rollback accepted an unverifiable registry cohort")
			}
		})
	}
}

type fixedRegistryReader struct {
	state FeatureRegistryState
	err   error
}

func (reader fixedRegistryReader) FeatureRegistryState(context.Context) (FeatureRegistryState, error) {
	return reader.state, reader.err
}

func TestU2PreflightRefusesIncompatibleEnforceBeforeHostAction(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: '0', data: "ok"})
	root, releaseID, _, manifest := writeStageFixture(t, archive)
	digest := strings.Repeat("a", 64)
	manifest.SchemaFrom, manifest.SchemaTo = 183, 183
	manifest.Migrations = nil
	manifest.FeatureRegistry = &release.FeatureRegistryContract{
		CatalogDigest: digest, CompatibleModes: []string{"enforce", "observe"},
		CompatibleRollbackDigests: []string{digest},
	}
	manifestDigest := rewriteStageManifest(t, root, releaseID, manifest)
	store, err := OpenReleaseStore(root)
	if err != nil {
		t.Fatal(err)
	}
	adoption := flatFixture(t)
	if _, err := AdoptCurrentLayout(adoption); err != nil {
		t.Fatal(err)
	}
	host := &fakeHostOperations{}
	adapter := &U2Adapter{
		Store: store, InstallRoot: adoption.InstallRoot,
		Migration: MigrationRunner{DB: &fakeMigrationDB{current: 183, evidence: map[int]MigrationEvidence{}}},
		FeatureRegistry: fixedRegistryReader{state: FeatureRegistryState{
			Present: true, Mode: "enforce", CatalogDigest: digest,
		}},
		Host: host,
	}
	steps, err := adapter.Steps()
	if err != nil {
		t.Fatal(err)
	}
	_, err = steps[0].Run(context.Background(), Transaction{ReleaseID: releaseID, ManifestDigest: manifestDigest})
	if !errors.Is(err, ErrFeatureRegistryContract) {
		t.Fatalf("preflight error=%v", err)
	}
	if len(host.calls) != 0 {
		t.Fatalf("host preflight ran before registry refusal: %v", host.calls)
	}
}
