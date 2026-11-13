package appmarket

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type dockerStep struct {
	args   []string
	output string
	err    error
}

type dockerScript struct {
	t     *testing.T
	steps []dockerStep
	seen  [][]string
}

func (s *dockerScript) run(_ context.Context, args ...string) ([]byte, error) {
	s.t.Helper()
	s.seen = append(s.seen, append([]string(nil), args...))
	if len(s.steps) == 0 {
		s.t.Fatalf("unexpected Docker command: %q", args)
	}
	step := s.steps[0]
	s.steps = s.steps[1:]
	if !reflect.DeepEqual(args, step.args) {
		s.t.Fatalf("Docker command:\n got %#v\nwant %#v", args, step.args)
	}
	return []byte(step.output), step.err
}

func (s *dockerScript) done() {
	s.t.Helper()
	if len(s.steps) != 0 {
		s.t.Fatalf("%d expected Docker commands were not run; next=%#v", len(s.steps), s.steps[0].args)
	}
}

func executionManifest() Manifest {
	return testManifest().WithExecution("installation-01", "operation-01")
}

func resourceJSON(t *testing.T, kind string, plan RuntimePlan, mutate func(map[string]string)) string {
	t.Helper()
	labels := plan.labels()
	if mutate != nil {
		mutate(labels)
	}
	pairs := make([]string, 0, len(labels))
	for _, key := range []string{managedOwnerLabel, managedInstallationLabel, managedAppLabel, managedPlanLabel, managedOperationLabel} {
		pairs = append(pairs, fmt.Sprintf("%q:%q", key, labels[key]))
	}
	labelsJSON := "{" + strings.Join(pairs, ",") + "}"
	switch kind {
	case "container":
		return fmt.Sprintf(`{"Config":{"Image":%q,"Labels":%s}}`, plan.Image, labelsJSON)
	case "network":
		return fmt.Sprintf(`{"Driver":"bridge","Labels":%s}`, labelsJSON)
	case "volume":
		return fmt.Sprintf(`{"Labels":%s}`, labelsJSON)
	default:
		t.Fatalf("unknown resource kind %s", kind)
		return ""
	}
}

func inspectStep(kind, name, output string, err error) dockerStep {
	return dockerStep{args: []string{kind, "inspect", name, "--format", "{{json .}}"}, output: output, err: err}
}

func missing(kind, name string) error {
	return &DockerObjectNotFoundError{Kind: kind, Name: name}
}

func TestDockerVerifyBindsIndexAndEffectivePlatformDigest(t *testing.T) {
	m := executionManifest()
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		t.Fatal(err)
	}
	script := &dockerScript{t: t, steps: []dockerStep{
		{args: []string{"info", "--format", "{{json .}}"}, output: `{"OSType":"linux","Architecture":"x86_64"}`},
		{args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"},
			output: fmt.Sprintf(`{"Architecture":"amd64","RepoDigests":[%q]}`, "collabora/code@"+m.Digest)},
		{args: []string{"manifest", "inspect", "--verbose", plan.Image},
			output: fmt.Sprintf(`[{"Descriptor":{"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}}]`, plan.PlatformDigests.LinuxAMD64)},
	}}
	if err := (DockerRuntime{run: script.run}).Verify(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	script.done()
}

func TestDockerVerifyRejectsDifferentEffectivePlatformDigest(t *testing.T) {
	m := executionManifest()
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		t.Fatal(err)
	}
	script := &dockerScript{t: t, steps: []dockerStep{
		{args: []string{"info", "--format", "{{json .}}"}, output: `{"OSType":"linux","Architecture":"amd64"}`},
		{args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"},
			output: fmt.Sprintf(`{"Architecture":"amd64","RepoDigests":[%q]}`, "collabora/code@"+m.Digest)},
		{args: []string{"manifest", "inspect", "--verbose", plan.Image},
			output: fmt.Sprintf(`[{"Descriptor":{"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}}]`, "sha256:"+strings.Repeat("0", 64))},
	}}
	if err := (DockerRuntime{run: script.run}).Verify(context.Background(), m); err == nil || !strings.Contains(err.Error(), "approved linux/amd64 digest") {
		t.Fatalf("Verify error=%v", err)
	}
	script.done()
}

func TestDockerStageEnsuresMissingResourcesWithExactLabels(t *testing.T) {
	m := executionManifest()
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		t.Fatal(err)
	}
	labels := labelArgs(plan)
	networkCreate := append([]string{"network", "create", "--driver", "bridge"}, labels...)
	networkCreate = append(networkCreate, plan.NetworkName)
	volumeCreate := append([]string{"volume", "create"}, labels...)
	volumeCreate = append(volumeCreate, plan.ConfigVolume)
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("network", plan.NetworkName, "", missing("network", plan.NetworkName)),
		inspectStep("volume", plan.ConfigVolume, "", missing("volume", plan.ConfigVolume)),
		inspectStep("container", plan.ContainerName, "", missing("container", plan.ContainerName)),
		{args: networkCreate, output: plan.NetworkName},
		{args: volumeCreate, output: plan.ConfigVolume},
	}}
	if err := (DockerRuntime{run: script.run}).Stage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	script.done()
}

func TestDockerStageReconcilesExactExistingResources(t *testing.T) {
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("network", plan.NetworkName, resourceJSON(t, "network", plan, nil), nil),
		inspectStep("volume", plan.ConfigVolume, resourceJSON(t, "volume", plan, nil), nil),
		inspectStep("container", plan.ContainerName, resourceJSON(t, "container", plan, nil), nil),
	}}
	if err := (DockerRuntime{run: script.run}).Stage(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	script.done()
}

func TestDockerStageDoesNotTreatInspectFailureAsAbsence(t *testing.T) {
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("network", plan.NetworkName, "permission denied", errors.New("exit status 1")),
	}}
	if err := (DockerRuntime{run: script.run}).Stage(context.Background(), m); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("Stage error=%v", err)
	}
	script.done()
}

func TestDockerInspectClassifiesOnlyRealAbsence(t *testing.T) {
	context := context.Background()
	missingScript := &dockerScript{t: t, steps: []dockerStep{{
		args:   []string{"network", "inspect", "setjoin-office", "--format", "{{json .}}"},
		output: "Error response from daemon: network setjoin-office not found", err: errors.New("exit status 1"),
	}}}
	_, err := (DockerRuntime{run: missingScript.run}).inspect(context, "network", "setjoin-office")
	var notFound *DockerObjectNotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("inspect error %T %v is not typed absence", err, err)
	}
	missingScript.done()

	deniedScript := &dockerScript{t: t, steps: []dockerStep{{
		args:   []string{"network", "inspect", "setjoin-office", "--format", "{{json .}}"},
		output: "permission denied", err: errors.New("exit status 1"),
	}}}
	_, err = (DockerRuntime{run: deniedScript.run}).inspect(context, "network", "setjoin-office")
	if errors.As(err, &notFound) {
		t.Fatalf("permission error misclassified as absence: %v", err)
	}
	deniedScript.done()
}

func TestDockerRollbackForeignResourceMakesZeroDeletes(t *testing.T) {
	for _, foreignKind := range []string{"container", "network", "volume"} {
		t.Run(foreignKind, func(t *testing.T) {
			m := executionManifest()
			plan, _ := CompileRuntimePlan(m)
			targets := []struct {
				kind string
				name string
			}{
				{kind: "container", name: plan.ContainerName},
				{kind: "network", name: plan.NetworkName},
				{kind: "volume", name: plan.ConfigVolume},
			}
			steps := make([]dockerStep, 0, len(targets))
			for _, target := range targets {
				mutate := func(map[string]string) {}
				if target.kind == foreignKind {
					mutate = func(labels map[string]string) {
						labels[managedOperationLabel] = "another-operation"
					}
				}
				steps = append(steps, inspectStep(target.kind, target.name, resourceJSON(t, target.kind, plan, mutate), nil))
				if target.kind == foreignKind {
					break
				}
			}
			script := &dockerScript{t: t, steps: steps}
			if err := (DockerRuntime{run: script.run}).Rollback(context.Background(), m); err == nil || !strings.Contains(err.Error(), "resource left untouched") {
				t.Fatalf("Rollback error=%v", err)
			}
			for _, args := range script.seen {
				if slicesContain(args, "rm") {
					t.Fatalf("foreign resource caused delete command: %#v", args)
				}
			}
			script.done()
		})
	}
}

func TestDockerRollbackReinspectsBeforeFirstDelete(t *testing.T) {
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	changed := resourceJSON(t, "container", plan, func(labels map[string]string) {
		labels[managedPlanLabel] = "sha256:" + strings.Repeat("f", 64)
	})
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("container", plan.ContainerName, resourceJSON(t, "container", plan, nil), nil),
		inspectStep("network", plan.NetworkName, resourceJSON(t, "network", plan, nil), nil),
		inspectStep("volume", plan.ConfigVolume, resourceJSON(t, "volume", plan, nil), nil),
		inspectStep("container", plan.ContainerName, changed, nil),
	}}
	if err := (DockerRuntime{run: script.run}).Rollback(context.Background(), m); err == nil {
		t.Fatal("rollback accepted a container whose fence changed after inventory")
	}
	for _, args := range script.seen {
		if slicesContain(args, "rm") {
			t.Fatalf("changed resource caused delete command: %#v", args)
		}
	}
	script.done()
}

func TestDockerRollbackReinspectsEveryExactResourceBeforeDelete(t *testing.T) {
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	container := resourceJSON(t, "container", plan, nil)
	network := resourceJSON(t, "network", plan, nil)
	volume := resourceJSON(t, "volume", plan, nil)
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("container", plan.ContainerName, container, nil),
		inspectStep("network", plan.NetworkName, network, nil),
		inspectStep("volume", plan.ConfigVolume, volume, nil),
		inspectStep("container", plan.ContainerName, container, nil),
		{args: []string{"container", "rm", "--force", plan.ContainerName}},
		inspectStep("network", plan.NetworkName, network, nil),
		{args: []string{"network", "rm", plan.NetworkName}},
		inspectStep("volume", plan.ConfigVolume, volume, nil),
		{args: []string{"volume", "rm", plan.ConfigVolume}},
	}}
	if err := (DockerRuntime{run: script.run}).Rollback(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	script.done()
}

func TestDockerStartTranscriptUsesCompiledPlanAndLabels(t *testing.T) {
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	want := []string{"run", "--detach", "--name", plan.ContainerName,
		"--network", plan.NetworkName, "--publish", "127.0.0.1:9980:9980"}
	want = append(want, labelArgs(plan)...)
	want = append(want, "--cap-drop", "ALL")
	for _, capability := range plan.Capabilities {
		want = append(want, "--cap-add", capability)
	}
	want = append(want, "--read-only")
	for _, tmpfs := range plan.Tmpfs {
		want = append(want, "--tmpfs", tmpfs)
	}
	want = append(want,
		"--pids-limit", "1024", "--memory", "4g", "--cpus", "4",
		"--restart", "unless-stopped", "--log-opt", "max-size=20m", "--log-opt", "max-file=5",
		"--volume", plan.ConfigVolume+":/etc/coolwsd")
	for _, environment := range plan.Environment {
		want = append(want, "--env", environment)
	}
	want = append(want, plan.Image)
	script := &dockerScript{t: t, steps: []dockerStep{
		inspectStep("container", plan.ContainerName, "", missing("container", plan.ContainerName)),
		{args: want, output: "container-id"},
	}}
	if err := (DockerRuntime{run: script.run}).Start(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	script.done()
}

func TestDockerRuntimePlatformAndCommandFailures(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		output string
		err    error
		want   string
	}{
		{"command", "denied", errors.New("exit status 1"), "docker info"},
		{"json", "{", nil, "decode Docker facts"},
		{"os", `{"OSType":"windows","Architecture":"amd64"}`, nil, "Linux container runtime"},
		{"arch", `{"OSType":"linux","Architecture":"mips"}`, nil, "unsupported Docker architecture"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime := DockerRuntime{run: func(context.Context, ...string) ([]byte, error) {
				return []byte(tc.output), tc.err
			}}
			if _, err := runtime.runtimePlatform(ctx); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("runtimePlatform error=%v", err)
			}
		})
	}
	for _, architecture := range []string{"aarch64", "arm64"} {
		runtime := DockerRuntime{run: func(context.Context, ...string) ([]byte, error) {
			return []byte(fmt.Sprintf(`{"OSType":"docker-desktop","Architecture":%q}`, architecture)), nil
		}}
		if got, err := runtime.runtimePlatform(ctx); err != nil || got != "linux/arm64" {
			t.Fatalf("runtimePlatform(%s)=%q,%v", architecture, got, err)
		}
	}
	if got := (&DockerObjectNotFoundError{Kind: "volume", Name: "x"}).Error(); !strings.Contains(got, "volume") {
		t.Fatalf("not-found error=%q", got)
	}
	for _, tc := range []struct {
		kind, output string
		want         bool
	}{
		{"container", "No such container: x", true}, {"network", "network x not found", true},
		{"volume", "No such volume: x", true}, {"image", "not found", false}, {"network", "denied", false},
	} {
		if got := dockerReportsNotFound(tc.kind, "x", []byte(tc.output)); got != tc.want {
			t.Fatalf("dockerReportsNotFound(%q,%q)=%v", tc.kind, tc.output, got)
		}
	}
	if _, _, ok := inspectTarget([]string{"image", "inspect", "x"}); ok {
		t.Fatal("image unexpectedly accepted as managed inspect target")
	}
}

func TestDockerPreflightPullAndVerifyFailureMatrix(t *testing.T) {
	ctx := context.Background()
	invalid := Manifest{}
	for name, fn := range map[string]func() error{
		"preflight": func() error { return (DockerRuntime{}).Preflight(ctx, invalid) },
		"pull":      func() error { return (DockerRuntime{}).Pull(ctx, invalid) },
		"verify":    func() error { return (DockerRuntime{}).Verify(ctx, invalid) },
		"stage":     func() error { return (DockerRuntime{}).Stage(ctx, invalid) },
		"start":     func() error { return (DockerRuntime{}).Start(ctx, invalid) },
		"healthy":   func() error { return (DockerRuntime{}).Healthy(ctx, invalid) },
		"rollback":  func() error { return (DockerRuntime{}).Rollback(ctx, invalid) },
	} {
		if err := fn(); err == nil {
			t.Fatalf("%s accepted invalid manifest", name)
		}
	}
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	preflight := &dockerScript{t: t, steps: []dockerStep{{args: []string{"info", "--format", "{{json .}}"}, output: `{"OSType":"linux","Architecture":"amd64"}`}}}
	if err := (DockerRuntime{run: preflight.run}).Preflight(ctx, m); err != nil {
		t.Fatal(err)
	}
	preflight.done()
	pull := &dockerScript{t: t, steps: []dockerStep{
		{args: []string{"info", "--format", "{{json .}}"}, output: `{"OSType":"linux","Architecture":"amd64"}`},
		{args: []string{"pull", "--platform", "linux/amd64", plan.Image}},
	}}
	if err := (DockerRuntime{run: pull.run}).Pull(ctx, m); err != nil {
		t.Fatal(err)
	}
	pull.done()

	baseInfo := dockerStep{args: []string{"info", "--format", "{{json .}}"}, output: `{"OSType":"linux","Architecture":"amd64"}`}
	for _, tc := range []struct {
		name  string
		steps []dockerStep
		want  string
	}{
		{"image-json", []dockerStep{baseInfo, {args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"}, output: "{"}}, "decode Docker image"},
		{"architecture", []dockerStep{baseInfo, {args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"}, output: fmt.Sprintf(`{"Architecture":"arm64","RepoDigests":[%q]}`, "x@"+m.Digest)}}, "architecture"},
		{"index", []dockerStep{baseInfo, {args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"}, output: `{"Architecture":"amd64","RepoDigests":[]}`}}, "index digest"},
		{"manifest-json", []dockerStep{baseInfo, {args: []string{"image", "inspect", plan.Image, "--format", "{{json .}}"}, output: fmt.Sprintf(`{"Architecture":"amd64","RepoDigests":[%q]}`, "x@"+m.Digest)}, {args: []string{"manifest", "inspect", "--verbose", plan.Image}, output: "{"}}, "decode Docker platform manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &dockerScript{t: t, steps: tc.steps}
			if err := (DockerRuntime{run: s.run}).Verify(ctx, m); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify error=%v", err)
			}
			s.done()
		})
	}
	single := fmt.Sprintf(`{"Descriptor":{"digest":%q,"platform":{"architecture":"amd64","os":"linux"}}}`, plan.PlatformDigests.LinuxAMD64)
	if got, err := decodeManifestDescriptors([]byte(single)); err != nil || len(got) != 1 {
		t.Fatalf("single descriptor=%v,%v", got, err)
	}
}

func TestDockerInspectStageStartAndRollbackFailures(t *testing.T) {
	ctx := context.Background()
	m := executionManifest()
	plan, _ := CompileRuntimePlan(m)
	for _, kind := range []string{"container", "network", "volume"} {
		s := &dockerScript{t: t, steps: []dockerStep{inspectStep(kind, "x", "{", nil)}}
		if _, err := (DockerRuntime{run: s.run}).inspect(ctx, kind, "x"); err == nil || !strings.Contains(err.Error(), "decode Docker") {
			t.Fatalf("inspect %s error=%v", kind, err)
		}
		s.done()
	}
	unsupported := DockerRuntime{run: func(context.Context, ...string) ([]byte, error) { return []byte(`{}`), nil }}
	if _, err := unsupported.inspect(ctx, "image", "x"); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unsupported inspect=%v", err)
	}
	for _, tc := range []struct{ kind, field string }{{"network", "driver"}, {"container", "image"}} {
		resource := inspectedResource{kind: tc.kind, name: "x", labels: plan.labels(), driver: "host", image: "wrong"}
		if err := validateOwnedResource(&resource, plan); err == nil || !strings.Contains(err.Error(), tc.field) {
			t.Fatalf("validate %s=%v", tc.kind, err)
		}
	}

	for _, failKind := range []string{"network", "volume", "container"} {
		steps := []dockerStep{}
		for _, target := range []struct{ kind, name string }{{"network", plan.NetworkName}, {"volume", plan.ConfigVolume}, {"container", plan.ContainerName}} {
			if target.kind == failKind {
				steps = append(steps, inspectStep(target.kind, target.name, "denied", errors.New("boom")))
				break
			}
			steps = append(steps, inspectStep(target.kind, target.name, resourceJSON(t, target.kind, plan, nil), nil))
		}
		s := &dockerScript{t: t, steps: steps}
		if err := (DockerRuntime{run: s.run}).Stage(ctx, m); err == nil {
			t.Fatalf("Stage accepted %s inspect failure", failKind)
		}
		s.done()
	}
	for _, failCreate := range []string{"network", "volume"} {
		steps := []dockerStep{
			inspectStep("network", plan.NetworkName, "", missing("network", plan.NetworkName)),
			inspectStep("volume", plan.ConfigVolume, "", missing("volume", plan.ConfigVolume)),
			inspectStep("container", plan.ContainerName, "", missing("container", plan.ContainerName)),
		}
		networkArgs := append([]string{"network", "create", "--driver", "bridge"}, labelArgs(plan)...)
		networkArgs = append(networkArgs, plan.NetworkName)
		volumeArgs := append([]string{"volume", "create"}, labelArgs(plan)...)
		volumeArgs = append(volumeArgs, plan.ConfigVolume)
		steps = append(steps, dockerStep{args: networkArgs, err: map[bool]error{true: errors.New("boom")}[failCreate == "network"]})
		if failCreate == "volume" {
			steps = append(steps, dockerStep{args: volumeArgs, err: errors.New("boom")})
		}
		s := &dockerScript{t: t, steps: steps}
		if err := (DockerRuntime{run: s.run}).Stage(ctx, m); err == nil {
			t.Fatalf("Stage accepted %s create failure", failCreate)
		}
		s.done()
	}

	existing := &dockerScript{t: t, steps: []dockerStep{inspectStep("container", plan.ContainerName, resourceJSON(t, "container", plan, nil), nil)}}
	if err := (DockerRuntime{run: existing.run}).Start(ctx, m); err != nil {
		t.Fatal(err)
	}
	existing.done()
	startFail := &dockerScript{t: t, steps: []dockerStep{inspectStep("container", plan.ContainerName, "denied", errors.New("boom"))}}
	if err := (DockerRuntime{run: startFail.run}).Start(ctx, m); err == nil {
		t.Fatal("Start accepted inspect failure")
	}
	startFail.done()

	rollback := &dockerScript{t: t, steps: []dockerStep{inspectStep("container", plan.ContainerName, "denied", errors.New("boom"))}}
	if err := (DockerRuntime{run: rollback.run}).Rollback(ctx, m); err == nil {
		t.Fatal("Rollback accepted inspect failure")
	}
	rollback.done()
}

func TestDockerHealthySuccessExhaustionAndCancellation(t *testing.T) {
	m := executionManifest()
	client := func(fn roundTripFunc) *http.Client { return &http.Client{Transport: fn} }
	ok := DockerRuntime{healthAttempts: 1, healthDelay: time.Nanosecond, healthClient: client(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Path, "/hosting/discovery") {
			t.Fatalf("path=%s", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("ok"))}, nil
	})}
	if err := ok.Healthy(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	bad := DockerRuntime{healthAttempts: 1, healthDelay: time.Nanosecond, healthClient: client(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader("no"))}, nil
	})}
	if err := bad.Healthy(context.Background(), m); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("bad health=%v", err)
	}
	transportErr := DockerRuntime{healthAttempts: 1, healthDelay: time.Nanosecond, healthClient: client(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	if err := transportErr.Healthy(context.Background(), m); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("transport health=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (DockerRuntime{healthAttempts: 2, healthDelay: time.Hour, healthClient: transportErr.healthClient}).Healthy(ctx, m); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel health=%v", err)
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
