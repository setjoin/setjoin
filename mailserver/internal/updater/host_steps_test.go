package updater

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHostOperations struct {
	calls           []string
	readiness       error
	startUpdaterErr error
	errors          map[string]error
}

type fakeRecoveryPoint struct {
	evidence RecoveryPointEvidence
	err      error
}

type fakeApplicationContractProbe struct {
	calls  []string
	errors map[string]error
}

func (probe *fakeApplicationContractProbe) DataContract(context.Context) error {
	probe.calls = append(probe.calls, "data")
	return probe.errors["data"]
}

func (probe *fakeApplicationContractProbe) PostCommit(context.Context) error {
	probe.calls = append(probe.calls, "post_commit")
	return probe.errors["post_commit"]
}

func (provider fakeRecoveryPoint) RequireFresh(context.Context, Transaction) (RecoveryPointEvidence, error) {
	return provider.evidence, provider.err
}

func (host *fakeHostOperations) call(name string) error {
	host.calls = append(host.calls, name)
	if host.errors != nil {
		if err := host.errors[name]; err != nil {
			return err
		}
	}
	if name == "readiness" {
		return host.readiness
	}
	if name == "start_updater" {
		return host.startUpdaterErr
	}
	return nil
}
func (host *fakeHostOperations) Preflight(context.Context) error    { return host.call("preflight") }
func (host *fakeHostOperations) StopCore(context.Context) error     { return host.call("stop") }
func (host *fakeHostOperations) StartCore(context.Context) error    { return host.call("start") }
func (host *fakeHostOperations) Readiness(context.Context) error    { return host.call("readiness") }
func (host *fakeHostOperations) DataContract(context.Context) error { return host.call("data") }
func (host *fakeHostOperations) PostCommit(context.Context) error   { return host.call("post_commit") }
func (host *fakeHostOperations) StopUpdater(context.Context) error  { return host.call("stop_updater") }
func (host *fakeHostOperations) StartUpdater(context.Context) error {
	return host.call("start_updater")
}

func TestU2AdapterDisposableFixtureStagesSwitchesAndRollsBack(t *testing.T) {
	archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: '0', data: "ok"})
	storeRoot, releaseID, digest, _ := writeStageFixture(t, archive)
	store, err := OpenReleaseStore(storeRoot)
	if err != nil {
		t.Fatal(err)
	}
	adoption := flatFixture(t)
	baseline, err := AdoptCurrentLayout(adoption)
	if err != nil {
		t.Fatal(err)
	}
	db := &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}
	host := &fakeHostOperations{}
	recoverySetID := "11111111-1111-4111-8111-111111111111"
	recoveryDigest := strings.Repeat("a", 64)
	adapter := &U2Adapter{Store: store, InstallRoot: adoption.InstallRoot,
		StagePolicy: StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }},
		Migration:   MigrationRunner{DB: db}, Host: host,
		RecoveryPoint: fakeRecoveryPoint{evidence: RecoveryPointEvidence{
			RecoverySetID: recoverySetID, ManifestSHA256: recoveryDigest,
			CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
		}}}
	steps, err := adapter.Steps()
	if err != nil {
		t.Fatal(err)
	}
	tx := Transaction{ReleaseID: releaseID, ManifestDigest: digest,
		RecoverySetID: recoverySetID, RecoverySetDigest: recoveryDigest}
	state := StateClaimed
	for _, step := range steps {
		if err := ValidateTransition(state, step.To); err != nil {
			t.Fatal(err)
		}
		evidence, err := step.Run(context.Background(), tx)
		if err != nil || !json.Valid(evidence) {
			t.Fatalf("step %s evidence=%s err=%v", step.Name, evidence, err)
		}
		state = step.To
	}
	current, _ := activeReleaseID(adoption.InstallRoot, "current")
	previous, _ := activeReleaseID(adoption.InstallRoot, "previous")
	if current != releaseID || previous != baseline.ReleaseID {
		t.Fatalf("current=%q previous=%q", current, previous)
	}
	evidence, err := adapter.Rollback(context.Background(), tx, Event{}, steps[len(steps)-1], os.ErrInvalid)
	if err != nil || !json.Valid(evidence) {
		t.Fatalf("rollback evidence=%s err=%v", evidence, err)
	}
	current, _ = activeReleaseID(adoption.InstallRoot, "current")
	previous, _ = activeReleaseID(adoption.InstallRoot, "previous")
	if current != baseline.ReleaseID || previous != releaseID {
		t.Fatalf("rollback current=%q previous=%q", current, previous)
	}
	if _, err := os.Stat(filepath.Join(adoption.InstallRoot, "releases", releaseID, "share", "docs", "UPGRADE_RECOVERY.md")); err != nil {
		t.Fatalf("release lacks manifest-hashed recovery guide: %v", err)
	}
}

func TestU2AdapterBlocksRetainedHostBeforeRecoveryPoint(t *testing.T) {
	adapter := &U2Adapter{Store: &ReleaseStore{}, InstallRoot: "/opt/setjoin", Migration: MigrationRunner{DB: &fakeMigrationDB{}}, Host: &fakeHostOperations{}}
	steps, err := adapter.Steps()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := steps[1].Run(context.Background(), Transaction{}); err != ErrRecoveryPointUnavailable {
		t.Fatalf("retained host recovery point error=%v", err)
	}
}

func TestU3AdapterRequiresVerifiedRecoveryPointOnRetainedHost(t *testing.T) {
	adapter := &U2Adapter{
		Store: &ReleaseStore{}, InstallRoot: "/opt/setjoin",
		Migration: MigrationRunner{DB: &fakeMigrationDB{}}, Host: &fakeHostOperations{},
		RecoveryPoint: fakeRecoveryPoint{evidence: RecoveryPointEvidence{
			RecoverySetID:  "11111111-1111-4111-8111-111111111111",
			ManifestSHA256: strings.Repeat("a", 64), CreatedAt: time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(time.Hour),
		}},
	}
	steps, err := adapter.Steps()
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := steps[1].Run(context.Background(), Transaction{
		ReleaseID: "release-179", RecoverySetID: "11111111-1111-4111-8111-111111111111",
		RecoverySetDigest: strings.Repeat("a", 64),
	})
	if err != nil || !strings.Contains(string(evidence), "recovery_set_id") {
		t.Fatalf("evidence=%s err=%v", evidence, err)
	}
	adapter.RecoveryPoint = fakeRecoveryPoint{err: errors.New("stale")}
	steps, _ = adapter.Steps()
	if _, err := steps[1].Run(context.Background(), Transaction{
		RecoverySetID:     "11111111-1111-4111-8111-111111111111",
		RecoverySetDigest: strings.Repeat("a", 64),
	}); err == nil {
		t.Fatal("stale recovery point accepted")
	}
	adapter.RecoveryPoint = fakeRecoveryPoint{evidence: RecoveryPointEvidence{
		RecoverySetID: "22222222-2222-4222-8222-222222222222", ManifestSHA256: strings.Repeat("a", 64),
		CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
	}}
	steps, _ = adapter.Steps()
	if _, err := steps[1].Run(context.Background(), Transaction{
		RecoverySetID: "11111111-1111-4111-8111-111111111111", RecoverySetDigest: strings.Repeat("a", 64),
	}); !errors.Is(err, ErrRecoveryPointUnavailable) {
		t.Fatalf("mismatched recovery evidence error=%v", err)
	}
	for name, tx := range map[string]Transaction{
		"non_uuid_set":     {RecoverySetID: "not-a-uuid", RecoverySetDigest: strings.Repeat("a", 64)},
		"uppercase_digest": {RecoverySetID: "11111111-1111-4111-8111-111111111111", RecoverySetDigest: strings.Repeat("A", 64)},
		"non_hex_digest":   {RecoverySetID: "11111111-1111-4111-8111-111111111111", RecoverySetDigest: strings.Repeat("g", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			adapter.RecoveryPoint = fakeRecoveryPoint{evidence: RecoveryPointEvidence{
				RecoverySetID: tx.RecoverySetID, ManifestSHA256: tx.RecoverySetDigest,
				CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
			}}
			steps, stepErr := adapter.Steps()
			if stepErr != nil {
				t.Fatal(stepErr)
			}
			if _, err := steps[1].Run(context.Background(), tx); !errors.Is(err, ErrRecoveryPointUnavailable) {
				t.Fatalf("invalid recovery identity error=%v", err)
			}
		})
	}
}

func TestU2AdapterDependencyAndHostFailureBoundaries(t *testing.T) {
	for _, adapter := range []*U2Adapter{
		{},
		{Store: &ReleaseStore{}, InstallRoot: "relative", Migration: MigrationRunner{DB: &fakeMigrationDB{}}, Host: &fakeHostOperations{}},
		{Store: &ReleaseStore{}, InstallRoot: "/opt/setjoin", Host: &fakeHostOperations{}},
		{Store: &ReleaseStore{}, InstallRoot: "/opt/setjoin", Migration: MigrationRunner{DB: &fakeMigrationDB{}}},
	} {
		if _, err := adapter.Steps(); err == nil {
			t.Fatal("incomplete adapter accepted")
		}
	}
	for _, failure := range []string{"preflight", "stop", "start", "readiness", "data", "post_commit"} {
		t.Run(failure, func(t *testing.T) {
			archive := webmailArchive(t, webmailEntry{name: "index.html", typeflag: '0', data: "ok"})
			storeRoot, releaseID, digest, _ := writeStageFixture(t, archive)
			store, err := OpenReleaseStore(storeRoot)
			if err != nil {
				t.Fatal(err)
			}
			adoption := flatFixture(t)
			if _, err := AdoptCurrentLayout(adoption); err != nil {
				t.Fatal(err)
			}
			host := &fakeHostOperations{errors: map[string]error{failure: errors.New("injected host failure")}}
			recoverySetID := "11111111-1111-4111-8111-111111111111"
			recoveryDigest := strings.Repeat("a", 64)
			adapter := &U2Adapter{Store: store, InstallRoot: adoption.InstallRoot,
				StagePolicy: StagePolicy{Platform: "linux", Architecture: "amd64", FreeBytes: func(string) (uint64, error) { return 1 << 40, nil }},
				Migration:   MigrationRunner{DB: &fakeMigrationDB{current: 178, evidence: map[int]MigrationEvidence{}}}, Host: host,
				RecoveryPoint: fakeRecoveryPoint{evidence: RecoveryPointEvidence{
					RecoverySetID: recoverySetID, ManifestSHA256: recoveryDigest,
					CreatedAt: time.Now().Add(-time.Minute), ExpiresAt: time.Now().Add(time.Hour),
				}}}
			steps, err := adapter.Steps()
			if err != nil {
				t.Fatal(err)
			}
			tx := Transaction{ReleaseID: releaseID, ManifestDigest: digest,
				RecoverySetID: recoverySetID, RecoverySetDigest: recoveryDigest}
			failed := false
			for _, step := range steps {
				if _, err := step.Run(context.Background(), tx); err != nil {
					failed = true
					break
				}
			}
			if !failed {
				t.Fatal("injected host failure did not stop catalog")
			}
		})
	}
}

func TestU2RollbackReportsLayoutAndHostFailures(t *testing.T) {
	base := t.TempDir()
	adapter := &U2Adapter{InstallRoot: base, Host: &fakeHostOperations{}}
	if _, err := adapter.Rollback(context.Background(), Transaction{ReleaseID: "release"}, Event{}, Step{Name: "step"}, errors.New("cause")); err == nil {
		t.Fatal("missing layout accepted")
	}
	adoption := flatFixture(t)
	evidence, err := AdoptCurrentLayout(adoption)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"start", "readiness"} {
		host := &fakeHostOperations{errors: map[string]error{failure: errors.New("injected")}}
		adapter = &U2Adapter{InstallRoot: adoption.InstallRoot, Host: host}
		if _, err := adapter.Rollback(context.Background(), Transaction{ReleaseID: "other"}, Event{}, Step{Name: "step"}, errors.New("cause")); err == nil {
			t.Fatalf("%s failure hidden", failure)
		}
	}
	_ = evidence
}

func TestSystemdHostUsesOnlyFixedCommandsAndBoundsErrors(t *testing.T) {
	priorExec := execCommandContext
	priorUnits := systemdCoreUnitPaths
	priorTimeout, priorRetry := systemdReadinessTimeout, systemdReadinessRetry
	t.Cleanup(func() {
		execCommandContext = priorExec
		systemdCoreUnitPaths = priorUnits
		systemdReadinessTimeout, systemdReadinessRetry = priorTimeout, priorRetry
	})
	unitDir := t.TempDir()
	units := []string{filepath.Join(unitDir, "setjoin.service"), filepath.Join(unitDir, "setjoin-auth.service")}
	for _, path := range units {
		if err := os.WriteFile(path, []byte("unit"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	systemdCoreUnitPaths = units
	var calls []string
	failCommands := false
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if failCommands {
			return exec.CommandContext(ctx, "/bin/sh", "-c", "head -c 5000 /dev/zero | tr '\\0' x; exit 9")
		}
		return exec.CommandContext(ctx, "/usr/bin/true")
	}
	probe := &fakeApplicationContractProbe{errors: map[string]error{}}
	host := SystemdHost{Probe: probe}
	ctx := context.Background()
	for name, action := range map[string]func(context.Context) error{
		"preflight": host.Preflight, "stop": host.StopCore, "start": host.StartCore,
		"stop updater": host.StopUpdater, "start updater": host.StartUpdater, "readiness": host.Readiness,
	} {
		if err := action(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	joined := strings.Join(calls, "\n")
	for _, expected := range []string{"systemctl is-enabled setjoin-gateway setjoin setjoin-auth", "systemctl stop setjoin-gateway setjoin setjoin-auth", "systemctl start setjoin-auth setjoin setjoin-gateway", "systemctl stop setjoin-updater", "systemctl start setjoin-updater", "curl --insecure", "curl --fail"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing fixed command %q in %s", expected, joined)
		}
	}
	if !strings.Contains(joined, "http://127.0.0.1:8443/health") || strings.Contains(joined, "127.0.0.1:8081") {
		t.Fatalf("auth readiness probe is not pinned to the installer port: %s", joined)
	}
	if err := host.DataContract(ctx); err != nil {
		t.Fatalf("data contract probe: %v", err)
	}
	if err := host.PostCommit(ctx); err != nil {
		t.Fatalf("post-commit probe: %v", err)
	}
	if strings.Join(probe.calls, ",") != "data,post_commit" {
		t.Fatalf("application probe calls=%v", probe.calls)
	}

	failCommands = true
	if err := runFixed(ctx, "fixed", "arg"); err == nil || len(err.Error()) > 4200 {
		t.Fatalf("bounded fixed error=%v", err)
	}
	systemdReadinessTimeout, systemdReadinessRetry = time.Nanosecond, time.Nanosecond
	if err := host.Readiness(ctx); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("readiness timeout=%v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	systemdReadinessTimeout = time.Hour
	if err := host.Readiness(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled readiness=%v", err)
	}
}

func TestSystemdHostFailsClosedWithoutOrOnFailedApplicationProbe(t *testing.T) {
	host := SystemdHost{}
	if err := host.DataContract(context.Background()); err == nil {
		t.Fatal("missing data-contract probe accepted")
	}
	if err := host.PostCommit(context.Background()); err == nil {
		t.Fatal("missing post-commit probe accepted")
	}
	probe := &fakeApplicationContractProbe{errors: map[string]error{
		"data": errors.New("login failed"), "post_commit": errors.New("mail round-trip failed"),
	}}
	host.Probe = probe
	if err := host.DataContract(context.Background()); err == nil || !strings.Contains(err.Error(), "login") {
		t.Fatalf("data probe error=%v", err)
	}
	if err := host.PostCommit(context.Background()); err == nil || !strings.Contains(err.Error(), "mail") {
		t.Fatalf("post-commit probe error=%v", err)
	}
}

func TestSystemdPreflightRejectsMissingSymlinkAndInsecureUnit(t *testing.T) {
	prior := systemdCoreUnitPaths
	t.Cleanup(func() { systemdCoreUnitPaths = prior })
	systemdCoreUnitPaths = []string{filepath.Join(t.TempDir(), "missing.service")}
	if err := (SystemdHost{}).Preflight(context.Background()); err == nil {
		t.Fatal("missing unit accepted")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unit"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	systemdCoreUnitPaths = []string{link}
	if err := (SystemdHost{}).Preflight(context.Background()); err == nil {
		t.Fatal("symlink unit accepted")
	}
}
