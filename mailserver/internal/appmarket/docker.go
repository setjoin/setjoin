package appmarket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Runtime interface {
	Preflight(context.Context, Manifest) error
	Pull(context.Context, Manifest) error
	Verify(context.Context, Manifest) error
	Stage(context.Context, Manifest) error
	Start(context.Context, Manifest) error
	Healthy(context.Context, Manifest) error
	Rollback(context.Context, Manifest) error
}

// DockerObjectNotFoundError distinguishes an absent object from daemon,
// permission, transport, and malformed-response failures. Only this error grants
// ensure/reconcile permission to create or skip a resource.
type DockerObjectNotFoundError struct {
	Kind string
	Name string
}

func (e *DockerObjectNotFoundError) Error() string {
	return fmt.Sprintf("Docker %s %q does not exist", e.Kind, e.Name)
}

type dockerCommand func(context.Context, ...string) ([]byte, error)

type DockerRuntime struct {
	Binary string
	run    dockerCommand
	// The health-probe controls are package-private test seams. Production uses
	// the bounded defaults below; tests can exercise success and exhaustion
	// without sleeping or binding the fixed managed-app port.
	healthClient   *http.Client
	healthAttempts int
	healthDelay    time.Duration
}

type dockerInfo struct {
	OSType       string `json:"OSType"`
	Architecture string `json:"Architecture"`
}

type inspectedResource struct {
	kind   string
	name   string
	labels map[string]string
	driver string
	image  string
}

func (d DockerRuntime) command(ctx context.Context, args ...string) ([]byte, error) {
	if d.run != nil {
		return d.run(ctx, args...)
	}
	binary := d.Binary
	if binary == "" {
		binary = "docker"
	}
	// Binary and arguments are compiled from the root-controlled closed
	// Collabora plan; no request field reaches this command boundary.
	return exec.CommandContext(ctx, binary, args...).CombinedOutput() //nolint:gosec
}

func (d DockerRuntime) docker(ctx context.Context, args ...string) ([]byte, error) {
	output, err := d.command(ctx, args...)
	if err == nil {
		return output, nil
	}
	var notFound *DockerObjectNotFoundError
	if errors.As(err, &notFound) {
		return nil, err
	}
	if kind, name, ok := inspectTarget(args); ok && dockerReportsNotFound(kind, name, output) {
		return nil, &DockerObjectNotFoundError{Kind: kind, Name: name}
	}
	verb := "command"
	if len(args) > 0 {
		verb = args[0]
	}
	return nil, fmt.Errorf("docker %s: %w: %s", verb, err, strings.TrimSpace(string(output)))
}

func inspectTarget(args []string) (string, string, bool) {
	if len(args) < 3 || args[1] != "inspect" {
		return "", "", false
	}
	switch args[0] {
	case "container", "network", "volume":
		return args[0], args[2], true
	default:
		return "", "", false
	}
}

func dockerReportsNotFound(kind, name string, output []byte) bool {
	message := strings.ToLower(string(output))
	name = strings.ToLower(name)
	switch kind {
	case "container":
		return strings.Contains(message, "no such container")
	case "network":
		return strings.Contains(message, "no such network") ||
			strings.Contains(message, "network "+name+" not found")
	case "volume":
		return strings.Contains(message, "no such volume") ||
			strings.Contains(message, "volume "+name+" not found")
	default:
		return false
	}
}

func (d DockerRuntime) runtimePlatform(ctx context.Context) (string, error) {
	output, err := d.docker(ctx, "info", "--format", "{{json .}}")
	if err != nil {
		return "", err
	}
	var info dockerInfo
	if err := json.Unmarshal(output, &info); err != nil {
		return "", fmt.Errorf("decode Docker facts: %w", err)
	}
	if info.OSType != "linux" && info.OSType != "docker-desktop" {
		return "", fmt.Errorf("managed CODE requires a Linux container runtime, got %q", info.OSType)
	}
	architecture := info.Architecture
	switch architecture {
	case "x86_64":
		architecture = "amd64"
	case "aarch64":
		architecture = "arm64"
	}
	if !slices.Contains([]string{"amd64", "arm64"}, architecture) {
		return "", fmt.Errorf("unsupported Docker architecture %q", info.Architecture)
	}
	return "linux/" + architecture, nil
}

func (d DockerRuntime) Preflight(ctx context.Context, m Manifest) error {
	if _, err := CompileRuntimePlan(m); err != nil {
		return err
	}
	_, err := d.runtimePlatform(ctx)
	return err
}

func (d DockerRuntime) Pull(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	platform, err := d.runtimePlatform(ctx)
	if err != nil {
		return err
	}
	_, err = d.docker(ctx, "pull", "--platform", platform, plan.Image)
	return err
}

type inspectedImage struct {
	Architecture string   `json:"Architecture"`
	RepoDigests  []string `json:"RepoDigests"`
}

type manifestDescriptor struct {
	Descriptor struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"Descriptor"`
}

func (d DockerRuntime) Verify(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	platform, err := d.runtimePlatform(ctx)
	if err != nil {
		return err
	}
	wantPlatformDigest, ok := plan.platformDigest(platform)
	if !ok {
		return fmt.Errorf("managed CODE has no approved digest for %s", platform)
	}
	output, err := d.docker(ctx, "image", "inspect", plan.Image, "--format", "{{json .}}")
	if err != nil {
		return err
	}
	var image inspectedImage
	if err := json.Unmarshal(output, &image); err != nil {
		return fmt.Errorf("decode Docker image facts: %w", err)
	}
	wantArchitecture := strings.TrimPrefix(platform, "linux/")
	if image.Architecture != wantArchitecture {
		return fmt.Errorf("pulled Collabora image architecture %q does not match %s", image.Architecture, platform)
	}
	indexFound := false
	for _, digest := range image.RepoDigests {
		if strings.HasSuffix(digest, "@"+m.Digest) {
			indexFound = true
			break
		}
	}
	if !indexFound {
		return errors.New("pulled Collabora image does not expose the accepted index digest")
	}
	manifestOutput, err := d.docker(ctx, "manifest", "inspect", "--verbose", plan.Image)
	if err != nil {
		return err
	}
	descriptors, err := decodeManifestDescriptors(manifestOutput)
	if err != nil {
		return err
	}
	for _, descriptor := range descriptors {
		if descriptor.Descriptor.Platform.OS+"/"+descriptor.Descriptor.Platform.Architecture == platform &&
			descriptor.Descriptor.Digest == wantPlatformDigest {
			return nil
		}
	}
	return fmt.Errorf("Collabora index does not expose approved %s digest %s", platform, wantPlatformDigest)
}

func decodeManifestDescriptors(raw []byte) ([]manifestDescriptor, error) {
	var descriptors []manifestDescriptor
	if err := json.Unmarshal(raw, &descriptors); err == nil {
		return descriptors, nil
	}
	var descriptor manifestDescriptor
	if err := json.Unmarshal(raw, &descriptor); err != nil {
		return nil, fmt.Errorf("decode Docker platform manifest: %w", err)
	}
	return []manifestDescriptor{descriptor}, nil
}

func (d DockerRuntime) inspect(ctx context.Context, kind, name string) (inspectedResource, error) {
	output, err := d.docker(ctx, kind, "inspect", name, "--format", "{{json .}}")
	if err != nil {
		return inspectedResource{}, err
	}
	resource := inspectedResource{kind: kind, name: name}
	switch kind {
	case "container":
		var value struct {
			Config struct {
				Image  string            `json:"Image"`
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}
		if err := json.Unmarshal(output, &value); err != nil {
			return inspectedResource{}, fmt.Errorf("decode Docker container %q: %w", name, err)
		}
		resource.labels, resource.image = value.Config.Labels, value.Config.Image
	case "network":
		var value struct {
			Driver string            `json:"Driver"`
			Labels map[string]string `json:"Labels"`
		}
		if err := json.Unmarshal(output, &value); err != nil {
			return inspectedResource{}, fmt.Errorf("decode Docker network %q: %w", name, err)
		}
		resource.labels, resource.driver = value.Labels, value.Driver
	case "volume":
		var value struct {
			Labels map[string]string `json:"Labels"`
		}
		if err := json.Unmarshal(output, &value); err != nil {
			return inspectedResource{}, fmt.Errorf("decode Docker volume %q: %w", name, err)
		}
		resource.labels = value.Labels
	default:
		return inspectedResource{}, fmt.Errorf("unsupported Docker resource kind %q", kind)
	}
	return resource, nil
}

func (d DockerRuntime) inspectOptional(ctx context.Context, kind, name string) (*inspectedResource, error) {
	resource, err := d.inspect(ctx, kind, name)
	if err == nil {
		return &resource, nil
	}
	var notFound *DockerObjectNotFoundError
	if errors.As(err, &notFound) {
		return nil, nil
	}
	return nil, err
}

func validateOwnedResource(resource *inspectedResource, plan RuntimePlan) error {
	if resource == nil {
		return nil
	}
	for key, want := range plan.labels() {
		if resource.labels[key] != want {
			return fmt.Errorf("Docker %s %q ownership fence %s=%q, want %q; resource left untouched",
				resource.kind, resource.name, key, resource.labels[key], want)
		}
	}
	if resource.kind == "network" && resource.driver != "bridge" {
		return fmt.Errorf("Docker network %q driver %q does not match managed plan; resource left untouched", resource.name, resource.driver)
	}
	if resource.kind == "container" && resource.image != plan.Image {
		return fmt.Errorf("Docker container %q image %q does not match managed plan; resource left untouched", resource.name, resource.image)
	}
	return nil
}

func labelArgs(plan RuntimePlan) []string {
	labels := plan.labels()
	keys := []string{managedOwnerLabel, managedInstallationLabel, managedAppLabel, managedPlanLabel, managedOperationLabel}
	args := make([]string, 0, len(keys)*2)
	for _, key := range keys {
		args = append(args, "--label", key+"="+labels[key])
	}
	return args
}

func (d DockerRuntime) Stage(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	network, err := d.inspectOptional(ctx, "network", plan.NetworkName)
	if err != nil {
		return err
	}
	volume, err := d.inspectOptional(ctx, "volume", plan.ConfigVolume)
	if err != nil {
		return err
	}
	container, err := d.inspectOptional(ctx, "container", plan.ContainerName)
	if err != nil {
		return err
	}
	for _, resource := range []*inspectedResource{network, volume, container} {
		if err := validateOwnedResource(resource, plan); err != nil {
			return err
		}
	}
	if network == nil {
		args := append([]string{"network", "create", "--driver", "bridge"}, labelArgs(plan)...)
		args = append(args, plan.NetworkName)
		if _, err := d.docker(ctx, args...); err != nil {
			return err
		}
	}
	if volume == nil {
		args := append([]string{"volume", "create"}, labelArgs(plan)...)
		args = append(args, plan.ConfigVolume)
		if _, err := d.docker(ctx, args...); err != nil {
			return err
		}
	}
	return nil
}

func (d DockerRuntime) Start(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	container, err := d.inspectOptional(ctx, "container", plan.ContainerName)
	if err != nil {
		return err
	}
	if container != nil {
		return validateOwnedResource(container, plan)
	}
	port := fmt.Sprintf("%s:%d:9980", plan.ListenAddress, plan.ListenPort)
	args := []string{"run", "--detach", "--name", plan.ContainerName,
		"--network", plan.NetworkName, "--publish", port}
	for _, host := range plan.ExtraHosts {
		args = append(args, "--add-host", host)
	}
	args = append(args, labelArgs(plan)...)
	args = append(args, "--cap-drop", "ALL")
	for _, capability := range plan.Capabilities {
		args = append(args, "--cap-add", capability)
	}
	args = append(args, "--read-only")
	for _, tmpfs := range plan.Tmpfs {
		args = append(args, "--tmpfs", tmpfs)
	}
	args = append(args,
		"--pids-limit", strconv.Itoa(plan.PIDsLimit), "--memory", plan.Memory, "--cpus", plan.CPUs,
		"--restart", plan.Restart, "--log-opt", "max-size="+plan.LogMaxSize,
		"--log-opt", "max-file="+strconv.Itoa(plan.LogMaxFiles),
		"--volume", plan.ConfigVolume+":/etc/coolwsd")
	for _, environment := range plan.Environment {
		args = append(args, "--env", environment)
	}
	args = append(args, plan.Image)
	_, err = d.docker(ctx, args...)
	return err
}

func (d DockerRuntime) Healthy(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	client := d.healthClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	attempts := d.healthAttempts
	if attempts == 0 {
		attempts = 30
	}
	delay := d.healthDelay
	if delay == 0 {
		delay = 2 * time.Second
	}
	url := fmt.Sprintf("http://%s:%d/hosting/discovery", plan.ListenAddress, plan.ListenPort)
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, requestErr := client.Do(req)
		if requestErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
		} else {
			last = requestErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("Collabora discovery did not become healthy: %w", last)
}

// Rollback removes only resources carrying the exact current execution fence.
// It is the single cleanup path for BOTH the live rollback window and the
// reclaimed/recovered rollback completion (a crashed executor's rolling_back
// row, or an admin-authorized retry after ROLLBACK_FAILED): idempotent over
// already-absent targets, and it never deletes a foreign or mismatched
// object, so a failed cleanup always leaves the ownership fence intact.
func (d DockerRuntime) Rollback(ctx context.Context, m Manifest) error {
	return d.RemoveTestRuntime(ctx, m)
}

// RemoveTestRuntime first inventories every fixed target, then reinspects each
// immediately before removal. Any initial foreign or mismatched object produces
// zero remove calls. Drive files and database state are outside these targets.
func (d DockerRuntime) RemoveTestRuntime(ctx context.Context, m Manifest) error {
	plan, err := CompileRuntimePlan(m)
	if err != nil {
		return err
	}
	targets := []struct {
		kind string
		name string
		args []string
	}{
		{kind: "container", name: plan.ContainerName, args: []string{"container", "rm", "--force", plan.ContainerName}},
		{kind: "network", name: plan.NetworkName, args: []string{"network", "rm", plan.NetworkName}},
		{kind: "volume", name: plan.ConfigVolume, args: []string{"volume", "rm", plan.ConfigVolume}},
	}
	for _, target := range targets {
		resource, inspectErr := d.inspectOptional(ctx, target.kind, target.name)
		if inspectErr != nil {
			return inspectErr
		}
		if err := validateOwnedResource(resource, plan); err != nil {
			return err
		}
	}
	for _, target := range targets {
		resource, inspectErr := d.inspectOptional(ctx, target.kind, target.name)
		if inspectErr != nil {
			return inspectErr
		}
		if resource == nil {
			continue
		}
		if err := validateOwnedResource(resource, plan); err != nil {
			return err
		}
		if _, err := d.docker(ctx, target.args...); err != nil {
			return err
		}
	}
	return nil
}
