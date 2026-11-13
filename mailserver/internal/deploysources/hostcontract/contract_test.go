package hostcontract

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	deploysources "setjoin.com/mailserver/internal/deploysources"
)

// Fixture cases bound to the owning plan's Verification/exit registers:
// retired-docs:superpowers/plans/2026-08-24-managed-host-package-sources.md
// (D4_APPLY_PREIMAGE_DRIFT, D4_ROLLBACK_POSTIMAGE_DRIFT,
// D4_SYMLINK_SWAP_ZERO_WRITE, D4_ENROLLMENT_REVOKED_RECOVERY_ONLY,
// D4_OPERATOR_TEMPLATE_INJECTION, D4_RECOVERY_REQUIRED_SURFACED,
// OAR4_COMPONENT_OWNERSHIP_NOT_ENROLLMENT, OAR4_EXTERNAL_RESOURCE_NO_WRITE).

var baseTime = time.Date(2026, 9, 23, 8, 0, 0, 0, time.UTC)

const (
	aptPath    = "/etc/apt/sources.list.d/setjoin.list"
	dockerPath = "/etc/docker/daemon.json"
	vendorPath = "/etc/apt/sources.list.d/vendor.list"
)

func fixtureEnrollment() EnrollmentRecord {
	return EnrollmentRecord{
		Generation:   7,
		HostIdentity: "installation-42",
		Platform:     "linux/amd64",
		Baseline:     "ubuntu-24.04",
		Authorizer:   "owner-product-gate",
		State:        EnrollmentActive,
		IssuedAt:     baseTime.Add(-time.Hour),
	}
}

func fixtureHost() *FixtureHost {
	return NewFixtureHost(map[string]FixtureFile{
		aptPath:    {Data: []byte("deb https://archive.ubuntu.com/ubuntu noble main\n"), Owner: "setjoin", Mode: 0o644},
		dockerPath: {Data: []byte(`{"registry-mirrors":["https://mirror.example.test"]}`), Owner: "root", Mode: 0o644},
		vendorPath: {Data: []byte("deb https://vendor.example.test/repo stable main\n"), Owner: "vendor", Mode: 0o644},
	})
}

func fixtureDesired() map[string][]byte {
	return map[string][]byte{
		aptPath:    []byte("deb https://approved.mirror.test/ubuntu noble main\n"),
		dockerPath: []byte(`{"registry-mirrors":["https://approved.mirror.test/v2"]}`),
	}
}

func wantRefusal(t *testing.T, err error, code ProblemCode) Problem {
	t.Helper()
	if err == nil {
		t.Fatal("expected refusal")
	}
	refused, ok := err.(*Refusal)
	if !ok {
		t.Fatalf("error %T is not a *Refusal: %v", err, err)
	}
	if refused.Problem.Code != code {
		t.Fatalf("problem code = %q want %q (detail %q)", refused.Problem.Code, code, refused.Problem.Detail)
	}
	return refused.Problem
}

func TestInspectAndPlanAreReadOnlyWithDeterministicReceipts(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	enrollment := fixtureEnrollment()
	before := host.Snapshot()

	inspected := InspectFixture(host)
	if len(inspected) != 3 {
		t.Fatalf("inspect = %d objects, want 3", len(inspected))
	}
	inspected[aptPath] = FixtureFile{Data: []byte("tampered")}
	if got, _ := host.Get(aptPath); string(got.Data) == "tampered" {
		t.Fatal("inspect result aliases fixture host memory")
	}

	plan, err := PlanFixture(enrollment, host, 3, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	again, err := PlanFixture(enrollment, host, 3, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	if plan.PlanID == "" || plan.PlanID != again.PlanID {
		t.Fatalf("plan ID not deterministic: %q vs %q", plan.PlanID, again.PlanID)
	}
	revised, err := PlanFixture(enrollment, host, 4, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	if revised.PlanID == plan.PlanID {
		t.Fatal("plan revision change did not change the plan ID")
	}
	if plan.EnrollmentGeneration != enrollment.Generation || plan.HostIdentity != enrollment.HostIdentity {
		t.Fatalf("plan not bound to enrollment identity: %+v", plan)
	}
	if len(plan.Preimages) != 2 || plan.Preimages[0].Path != aptPath || plan.Preimages[0].Owner != "setjoin" {
		t.Fatalf("preimages = %+v", plan.Preimages)
	}
	if plan.Preimages[0].SHA256 == plan.Preimages[1].SHA256 {
		t.Fatal("distinct objects produced identical preimage digests")
	}
	if host.Snapshot() != before {
		t.Fatal("inspect or plan mutated the fixture host")
	}
}

func TestPlanRefusalTaxonomy(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	before := host.Snapshot()

	// OAR4_COMPONENT_OWNERSHIP_NOT_ENROLLMENT: a setjoin-owned file is an
	// inspection fact only; without an enrollment record nothing plans.
	ownershipOnly := EnrollmentRecord{HostIdentity: "installation-42", State: EnrollmentUnenrolled}
	_, err := PlanFixture(ownershipOnly, host, 1, []string{aptPath})
	if err == nil {
		t.Fatal("component ownership manufactured a plan without enrollment")
	}
	wantRefusal(t, err, ProblemEnrollmentRequired)

	revoked := fixtureEnrollment().Revoke(baseTime)
	_, err = PlanFixture(revoked, host, 1, []string{aptPath})
	wantRefusal(t, err, ProblemEnrollmentRevoked)

	unsupported := fixtureEnrollment()
	unsupported.Baseline = "debian-12"
	_, err = PlanFixture(unsupported, host, 1, []string{aptPath})
	wantRefusal(t, err, ProblemUnsupported)

	_, err = PlanFixture(fixtureEnrollment(), host, 1, nil)
	wantRefusal(t, err, ProblemPreimageMissing)

	_, err = PlanFixture(fixtureEnrollment(), host, 1, []string{aptPath, aptPath})
	wantRefusal(t, err, ProblemPreimageMissing)

	_, err = PlanFixture(fixtureEnrollment(), host, 1, []string{"/etc/absent.list"})
	wantRefusal(t, err, ProblemPreimageMissing)

	symlinked := fixtureHost()
	file, _ := symlinked.Get(aptPath)
	symlinked.replace(aptPath, FixtureFile{Owner: file.Owner, Mode: file.Mode, Symlink: "/etc/foreign.list"})
	_, err = PlanFixture(fixtureEnrollment(), symlinked, 1, []string{aptPath})
	wantRefusal(t, err, ProblemSymlinkTarget)

	if host.Snapshot() != before {
		t.Fatal("a refused plan mutated the fixture host")
	}
}

func TestD4_APPLY_PREIMAGE_DRIFT(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	plan, err := PlanFixture(fixtureEnrollment(), host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	file, _ := host.Get(dockerPath)
	host.replace(dockerPath, file.with([]byte(`{"registry-mirrors":["https://operator-edited.test"]}`)))
	drifted := host.Snapshot()

	journal := NewFixtureJournal()
	receipt, err := ApplyFixture(plan, host, journal, fixtureDesired(), baseTime)
	wantRefusal(t, err, ProblemPreimageDrift)
	if receipt.State != OperationRefused || len(receipt.Journal) != 0 || receipt.CompletedSteps != 0 {
		t.Fatalf("refused apply receipt = %+v", receipt)
	}
	if receipt.Problem == nil || receipt.Problem.Code != ProblemPreimageDrift {
		t.Fatalf("refused receipt problem = %+v", receipt.Problem)
	}
	if host.Snapshot() != drifted {
		t.Fatal("apply-time preimage drift was not zero-write")
	}
	if _, ok := journal.Receipt(receipt.OperationID); ok {
		t.Fatal("refusal created durable operation state")
	}
}

func TestD4_SYMLINK_SWAP_ZERO_WRITE(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	plan, err := PlanFixture(fixtureEnrollment(), host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	host.replace(aptPath, FixtureFile{Owner: "setjoin", Mode: 0o644, Symlink: "/etc/attacker.list"})
	substituted := host.Snapshot()

	journal := NewFixtureJournal()
	receipt, err := ApplyFixture(plan, host, journal, fixtureDesired(), baseTime)
	wantRefusal(t, err, ProblemPreimageDrift)
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("substitution detail lost: %v", err)
	}
	if host.Snapshot() != substituted {
		t.Fatal("symlink substitution was not zero-write")
	}
	if receipt.State != OperationRefused || len(receipt.Journal) != 0 {
		t.Fatalf("symlink swap receipt = %+v", receipt)
	}
}

func TestApplyJournalsBeforeAdvancingAndReplaysExactly(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	plan, err := PlanFixture(fixtureEnrollment(), host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewFixtureJournal()
	receipt, err := ApplyFixture(plan, host, journal, fixtureDesired(), baseTime)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != OperationApplied || receipt.CompletedSteps != 2 {
		t.Fatalf("apply receipt = %+v", receipt)
	}
	if len(receipt.Journal) != 2 {
		t.Fatalf("journal = %+v", receipt.Journal)
	}
	first := receipt.Journal[0]
	if first.Seq != 1 || first.Path != aptPath || first.Owner != "setjoin" {
		t.Fatalf("journal entry 1 = %+v", first)
	}
	pre, _ := host.Get(aptPath)
	if pre.digest() != first.PostimageSHA256 {
		t.Fatal("journal postimage digest does not match applied bytes")
	}
	original, _ := host.Get(aptPath)
	if string(original.Data) != string(fixtureDesired()[aptPath]) {
		t.Fatal("apply did not write the desired bytes")
	}

	// Exact replay: same plan returns the same receipt with no duplicate effect.
	replay, err := ApplyFixture(plan, host, journal, fixtureDesired(), baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay, receipt) {
		t.Fatalf("replay receipt differs: %+v vs %+v", replay, receipt)
	}
	after, _ := host.Get(aptPath)
	if !reflect.DeepEqual(after, original) {
		t.Fatal("replay mutated applied bytes")
	}
}

func TestCrashResumeCompletesWithoutReapplyingSteps(t *testing.T) {
	t.Parallel()
	enrollment := fixtureEnrollment()
	desired := fixtureDesired()

	// Crash after the journal entry: the step is journaled but unwritten, so
	// resume must redo it exactly once.
	host := fixtureHost()
	plan, err := PlanFixture(enrollment, host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewFixtureJournal()
	receipt, err := ApplyFixtureWithFailure(plan, host, journal, desired, Failure{AtStep: 2, Mode: FailureCrashAfterJournal}, baseTime)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != OperationApplying || len(receipt.Journal) != 2 {
		t.Fatalf("crash receipt = %+v", receipt)
	}
	if file, _ := host.Get(dockerPath); string(file.Data) == string(desired[dockerPath]) {
		t.Fatal("crash_after_journal unexpectedly wrote the host")
	}
	resumed, err := ResumeFixture(plan, host, journal, desired, enrollment, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resumed.State != OperationApplied || len(resumed.Journal) != 2 {
		t.Fatalf("resume receipt = %+v", resumed)
	}
	if file, _ := host.Get(dockerPath); string(file.Data) != string(desired[dockerPath]) {
		t.Fatal("resume did not redo the journaled-but-unwritten step")
	}

	// Crash after the write: the step is journaled and written, so resume must
	// skip it and complete only the remaining step.
	host2 := fixtureHost()
	plan2, err := PlanFixture(enrollment, host2, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal2 := NewFixtureJournal()
	receipt2, err := ApplyFixtureWithFailure(plan2, host2, journal2, desired, Failure{AtStep: 1, Mode: FailureCrashAfterWrite}, baseTime)
	if err != nil {
		t.Fatal(err)
	}
	if receipt2.State != OperationApplying || receipt2.CompletedSteps != 1 {
		t.Fatalf("crash receipt = %+v", receipt2)
	}
	resumed2, err := ResumeFixture(plan2, host2, journal2, desired, enrollment, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resumed2.State != OperationApplied || len(resumed2.Journal) != 2 {
		t.Fatalf("resume receipt = %+v", resumed2)
	}
	if file, _ := host2.Get(aptPath); string(file.Data) != string(desired[aptPath]) {
		t.Fatal("applied step bytes disturbed by resume")
	}

	// An object matching neither its preimage nor postimage is runtime
	// uncertain and enters recovery_required; the drifted bytes stay untouched.
	host3 := fixtureHost()
	plan3, err := PlanFixture(enrollment, host3, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal3 := NewFixtureJournal()
	if _, err := ApplyFixtureWithFailure(plan3, host3, journal3, desired, Failure{AtStep: 2, Mode: FailureCrashAfterJournal}, baseTime); err != nil {
		t.Fatal(err)
	}
	file, _ := host3.Get(dockerPath)
	host3.replace(dockerPath, file.with([]byte(`{}`)))
	resumed3, err := ResumeFixture(plan3, host3, journal3, desired, enrollment, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resumed3.State != OperationRecoveryRequired || resumed3.Problem.Code != ProblemRuntimeUncertain {
		t.Fatalf("uncertain resume receipt = %+v", resumed3)
	}
	if resumed3.Recovery == nil || resumed3.Recovery.FailedCheckpoint != 2 || resumed3.Recovery.ReceiptRef != resumed3.OperationID {
		t.Fatalf("recovery guidance = %+v", resumed3.Recovery)
	}
	if file, _ := host3.Get(dockerPath); string(file.Data) != "{}" {
		t.Fatal("recovery overwrote drifted bytes")
	}
}

func TestD4_ROLLBACK_POSTIMAGE_DRIFT(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	enrollment := fixtureEnrollment()
	desired := fixtureDesired()
	plan, err := PlanFixture(enrollment, host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewFixtureJournal()
	before := host.Snapshot()
	if _, err := ApplyFixture(plan, host, journal, desired, baseTime); err != nil {
		t.Fatal(err)
	}

	// The operator edits a completed step between apply and rollback.
	file, _ := host.Get(dockerPath)
	operatorBytes := []byte(`{"registry-mirrors":["https://operator.choice.test"]}`)
	host.replace(dockerPath, file.with(operatorBytes))

	receipt, err := RollbackFixture(plan, host, journal, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	// D4_RECOVERY_REQUIRED_SURFACED: honest state plus actionable guidance.
	if receipt.State != OperationRecoveryRequired {
		t.Fatalf("rollback state = %q, want recovery_required", receipt.State)
	}
	if receipt.Problem == nil || receipt.Problem.Code != ProblemPostimageDrift {
		t.Fatalf("rollback problem = %+v", receipt.Problem)
	}
	guidance := receipt.Recovery
	if guidance == nil {
		t.Fatal("recovery_required receipt carries no guidance")
	}
	if guidance.FailedCheckpoint != 2 || guidance.ReceiptRef != receipt.OperationID {
		t.Fatalf("guidance = %+v", guidance)
	}
	if !reflect.DeepEqual(guidance.ObservedDrift, []string{dockerPath}) || guidance.SafeNextStep == "" {
		t.Fatalf("guidance = %+v", guidance)
	}
	// The drifted object is never overwritten and the untouched step is not
	// falsely claimed rolled back.
	if got, _ := host.Get(dockerPath); string(got.Data) != string(operatorBytes) {
		t.Fatal("rollback overwrote operator drift")
	}
	if got, _ := host.Get(aptPath); string(got.Data) != string(desired[aptPath]) {
		t.Fatal("rollback continued past the failed checkpoint")
	}
	if host.Snapshot() == before {
		t.Fatal("rollback claimed success without restoring anything")
	}

	// Clean rollback restores every step byte-for-byte.
	host2 := fixtureHost()
	plan2, err := PlanFixture(enrollment, host2, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal2 := NewFixtureJournal()
	if _, err := ApplyFixture(plan2, host2, journal2, desired, baseTime); err != nil {
		t.Fatal(err)
	}
	clean, err := RollbackFixture(plan2, host2, journal2, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if clean.State != OperationRolledBack {
		t.Fatalf("clean rollback state = %q", clean.State)
	}
	if host2.Snapshot() != before {
		t.Fatal("clean rollback is not byte-for-byte")
	}
	replay, err := RollbackFixture(plan2, host2, journal2, baseTime.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(replay, clean) {
		t.Fatal("rollback replay changed the receipt")
	}
}

func TestD4_ENROLLMENT_REVOKED_RECOVERY_ONLY(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	enrollment := fixtureEnrollment()
	desired := fixtureDesired()
	plan, err := PlanFixture(enrollment, host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	journal := NewFixtureJournal()
	before := host.Snapshot()
	if _, err := ApplyFixtureWithFailure(plan, host, journal, desired, Failure{AtStep: 1, Mode: FailureCrashAfterWrite}, baseTime); err != nil {
		t.Fatal(err)
	}

	revoked := enrollment.Revoke(baseTime)

	// Continuation of new desired changes is refused and writes nothing.
	_, err = ResumeFixture(plan, host, journal, desired, revoked, baseTime.Add(time.Minute))
	wantRefusal(t, err, ProblemEnrollmentRevoked)
	snapshotAtRefusal := host.Snapshot()
	_, err = ResumeFixture(plan, host, journal, desired, revoked, baseTime.Add(time.Minute))
	wantRefusal(t, err, ProblemEnrollmentRevoked)
	if host.Snapshot() != snapshotAtRefusal {
		t.Fatal("refused resume mutated the host")
	}

	// A revoked enrollment cannot plan new operations either.
	if _, err := PlanFixture(revoked, host, 2, []string{aptPath}); err == nil {
		t.Fatal("revoked enrollment planned a new operation")
	}

	// Already authorized safe recovery remains permitted.
	receipt, err := RollbackFixture(plan, host, journal, baseTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != OperationRolledBack {
		t.Fatalf("safe recovery state = %q", receipt.State)
	}
	if host.Snapshot() != before {
		t.Fatal("safe recovery did not restore the pre-apply bytes")
	}
}

func TestD4_OPERATOR_TEMPLATE_INJECTION(t *testing.T) {
	t.Parallel()
	malicious := "noble'; rm -rf /etc/apt/sources.list.d; echo '"
	out := OperatorInstruction("apt-add-repository {source} && apt-get update", map[string]string{
		"source": malicious,
	})
	want := "apt-add-repository 'noble'\\''; rm -rf /etc/apt/sources.list.d; echo '\\''' && apt-get update"
	if out != want {
		t.Fatalf("instruction = %q want %q", out, want)
	}
	if strings.Count(out, "'")%2 != 0 {
		t.Fatal("unbalanced quoting lets inspected text become shell syntax")
	}
}

func TestOAR4_EXTERNAL_RESOURCE_NO_WRITE(t *testing.T) {
	t.Parallel()
	host := fixtureHost()
	before, _ := host.Get(vendorPath)
	inspectSnapshot := host.Snapshot()

	plan, err := PlanFixture(fixtureEnrollment(), host, 1, []string{aptPath, dockerPath})
	if err != nil {
		t.Fatal(err)
	}
	if host.Snapshot() != inspectSnapshot {
		t.Fatal("plan mutated the host before apply")
	}
	journal := NewFixtureJournal()
	if _, err := ApplyFixture(plan, host, journal, fixtureDesired(), baseTime); err != nil {
		t.Fatal(err)
	}

	after, _ := host.Get(vendorPath)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("external resource changed: %+v -> %+v", before, after)
	}
	// The vendor path never appears in the plan's owned goal.
	for _, pre := range plan.Preimages {
		if pre.Path == vendorPath {
			t.Fatal("external resource entered the owned plan")
		}
	}
}

// TestProductionReadOnlySliceBoundary pins the excluded-production boundary:
// the only implemented production host contact is the read-only InspectUbuntu
// inventory whose plan never mutates the host, while the transactional plan
// bit exists only inside this fixture model pending the owner gate.
func TestProductionReadOnlySliceBoundary(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/apt/sources.list.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"etc/os-release":                         "ID=ubuntu\nVERSION_ID=24.04\n",
		"etc/apt/sources.list.d/setjoin.list":    "deb https://archive.ubuntu.com/ubuntu noble main\n",
		"etc/apt/sources.list.d/setjoin.sources": "Types: deb\nURIs: https://approved.mirror.test/ubuntu\nSuites: noble\n",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	inventory := deploysources.InspectUbuntu(root)
	if !inventory.Supported {
		t.Fatalf("production inventory = %+v", inventory)
	}
	if err := inventory.ValidateNoWritePlan(); err != nil {
		t.Fatal(err)
	}
	if inventory.Plan.MutatesHost {
		t.Fatal("production read-only plan claims host mutation")
	}
	for _, row := range inventory.Sources {
		if row.Ownership != "setjoin_managed" && row.Ownership != "external" {
			t.Fatalf("unclassified ownership: %+v", row)
		}
	}

	plan, err := PlanFixture(fixtureEnrollment(), fixtureHost(), 1, []string{aptPath})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.MutatesHost {
		t.Fatal("fixture transactional plan lost its mutation bit")
	}
}
