package appmarket

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveDockerCollaboraInstall(t *testing.T) {
	if os.Getenv("SETJOIN_LIVE_COLLABORA") != "1" {
		t.Skip("set SETJOIN_LIVE_COLLABORA=1 for the retained Docker installation lane")
	}
	manifest, err := ReadManifest(filepath.Join("..", "..", "..", "config", "office-managed-app-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest = manifest.WithExecution("live-test-installation", "live-test-operation")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()
	runtime := DockerRuntime{}
	if err := runtime.RemoveTestRuntime(ctx, manifest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Minute)
		defer stop()
		if err := runtime.RemoveTestRuntime(cleanup, manifest); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	steps := []struct {
		name string
		run  func(context.Context, Manifest) error
	}{{"preflight", runtime.Preflight}, {"pull", runtime.Pull}, {"verify", runtime.Verify},
		{"stage", runtime.Stage}, {"start", runtime.Start}, {"health", runtime.Healthy}}
	for _, step := range steps {
		if err := step.run(ctx, manifest); err != nil {
			if logs, logErr := runtime.docker(ctx, "logs", "--tail", "120", manifest.ContainerName); logErr == nil {
				t.Logf("container logs:\n%s", logs)
			}
			t.Fatalf("%s: %v", step.name, err)
		}
	}
}
